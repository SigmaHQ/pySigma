from collections import defaultdict
from dataclasses import dataclass, field
from functools import partial
from typing import (
    FrozenSet,
    List,
    Literal,
    Mapping,
    Set,
    Any,
    Callable,
    Iterable,
    Dict,
    Tuple,
    Optional,
    Type,
    Union,
)

from sigma.correlations import SigmaCorrelationRule
from sigma.processing.condition_expressions import ConditionExpression, parse_condition_expression
from sigma.processing.finalization import Finalizer, finalizers
from sigma.processing.tracking import FieldMappingTracking
from sigma.rule import SigmaDetectionItem, SigmaRule
from sigma.processing.transformations import transformations, Transformation
from sigma.processing.postprocessing import query_postprocessing_transformations
from sigma.processing.conditions import (
    rule_conditions,
    RuleProcessingCondition,
    detection_item_conditions,
    DetectionItemProcessingCondition,
    field_name_conditions,
    FieldNameProcessingCondition,
)
from sigma.exceptions import (
    SigmaConfigurationError,
    SigmaPipelineConditionError,
    SigmaTypeError,
    SigmaPipelineParsingError,
)
import yaml

from sigma.types import SigmaFieldReference, SigmaType


@dataclass
class ProcessingItemBase:
    transformation: Transformation
    rule_condition_linking: Optional[Callable[[Iterable[bool]], bool]] = None  # any or all
    rule_condition_negation: bool = False
    rule_conditions: Union[List[RuleProcessingCondition], Dict[str, RuleProcessingCondition]] = (
        field(default_factory=list)
    )
    rule_condition_expression: Optional[ConditionExpression] = (
        None  # Full rule condition expression mutually exclusive to linking
    )

    identifier: Optional[str] = None

    @classmethod
    def _base_args_from_dict(
        cls, d: dict, transformations: Dict[str, Type[Transformation]]
    ) -> dict:
        """Return class instantiation parameters for attributes contained in base class for further
        usage in similar methods of classes inherited from this class."""
        rule_conds = cls._parse_conditions(rule_conditions, d.get("rule_conditions", list()))
        rule_cond_expr_str = d.get("rule_cond_expr", None)
        if rule_cond_expr_str is not None:
            rule_cond_expr = parse_condition_expression(rule_cond_expr_str, rule_conds)
        else:
            rule_cond_expr = None
        return {
            "identifier": d.get("id", None),
            "rule_conditions": rule_conds,
            "rule_condition_expression": rule_cond_expr,
            "rule_condition_linking": cls._parse_condition_linking(d, "rule_cond_op"),
            "rule_condition_negation": d.get("rule_cond_not", False),
            "transformation": cls._instantiate_transformation(d, transformations),
        }

    def _check_conditions(
        self, expression_attr, linking_attr, conditions_attr, expected_condition_class, name
    ):
        """
        This method conducts various checks of the conditions provided to the processing item:

        * That the condition expressions are mutually exclusive to the linking attribute.
        * That the conditions are provided as a list or dict.
        * That the conditions are of the expected condition class.

        In addition to the checks it sets the linking attribute to `all` if no logic value is provided.
        """
        expr = self.__getattribute__(expression_attr)
        conditions = self.__getattribute__(conditions_attr)
        # Check if logic is mutually exclusive to linking and conditions are provided as dict if
        # condition logic expression is given.
        if expr is not None:
            if self.__getattribute__(linking_attr) is not None:
                raise SigmaConfigurationError(
                    f"{name} expression is mutually exclusive to linking."
                )
            if not isinstance(conditions, dict):
                raise SigmaConfigurationError(
                    f"{name}s must be provided as mapping from identifiers to conditions if condition expression is provided."
                )
        else:  # In case no expression is provided, set linking to all if not provided and simplify condition dict to list.
            if self.__getattribute__(linking_attr) is None:
                self.__setattr__(linking_attr, all)
            if isinstance(conditions, dict):
                self.__setattr__(conditions_attr, list(conditions.values()))

        if not isinstance(conditions, (list, dict)):
            raise SigmaTypeError(f"{name}s must be provided as list or dict")
        if isinstance(conditions, dict):
            conditions_list = conditions.values()
        else:
            conditions_list = conditions
        for condition in conditions_list:
            if not isinstance(condition, expected_condition_class):
                raise SigmaTypeError(
                    f"{name} '{str(condition)}' is not a {expected_condition_class.__name__}"
                )

    def __post_init__(self):
        self._check_conditions(
            "rule_condition_expression",
            "rule_condition_linking",
            "rule_conditions",
            RuleProcessingCondition,
            "Rule condition",
        )
        self.transformation.set_processing_item(
            self
        )  # set processing item in transformation object after it is instantiated
        self._resolve_condition_expression(
            self.rule_condition_expression, self.rule_conditions, "Rule condition"
        )

    def _resolve_condition_expression(
        self,
        expr: Optional[ConditionExpression],
        conditions: Dict[str, RuleProcessingCondition],
        name: str,
    ) -> None:
        if expr is not None:
            refids = expr.resolve(conditions)
            if len(refids) < len(conditions):
                raise SigmaPipelineConditionError(
                    expr.expression,
                    expr.location,
                    f"{name} contains unreferenced condition items: {', '.join(set(conditions.keys()) - refids)}",
                )

    @classmethod
    def _parse_condition(cls, condition_class_mapping, cond_def, ref):
        try:
            cond_type = cond_def["type"]
        except KeyError:
            raise SigmaConfigurationError(f"Missing condition type defined in condition { ref }")

        try:
            cond_class = condition_class_mapping[cond_type]
        except KeyError:
            raise SigmaConfigurationError(
                f"Unknown condition type '{ cond_type }' in condition { ref }"
            )

        cond_params = {k: v for k, v in cond_def.items() if k != "type"}
        try:
            return cond_class(**cond_params)
        except (SigmaConfigurationError, TypeError) as e:
            raise SigmaConfigurationError(f"Error in condition { ref }: { str(e) }") from e

    @classmethod
    def _parse_conditions(
        self,
        condition_class_mapping: Dict[
            str,
            Union[
                Type[RuleProcessingCondition],
                Type[DetectionItemProcessingCondition],
                Type[FieldNameProcessingCondition],
            ],
        ],
        cond_defs: Dict[str, Dict],
    ) -> Union[
        List[RuleProcessingCondition],
        Dict[str, RuleProcessingCondition],
        List[DetectionItemProcessingCondition],
        Dict[str, DetectionItemProcessingCondition],
        List[FieldNameProcessingCondition],
        Dict[str, FieldNameProcessingCondition],
    ]:
        """Parse dict of conditions into list or dict of condition object instances.

        :param condition_class_mapping: Mapping between condition type identifiers and condition classes.
        :type condition_class_mapping: Dict[str, Union[Type[RuleProcessingCondition], Type[DetectionItemProcessingCondition], Type[FieldNameProcessingCondition]]]
        :param cond_defs: Definition of conditions for the pipeline.
        :type cond_defs: Dict[str, Dict]
        :return: List or dict of condition classes as defined in dict.
        :rtype: Union[List[RuleProcessingCondition], Dict[str, RuleProcessingCondition], List[DetectionItemProcessingCondition], Dict[str, DetectionItemProcessingCondition], List[FieldNameProcessingCondition], Dict[str, FieldNameProcessingCondition]]
        """
        if isinstance(cond_defs, dict):
            return {
                k: self._parse_condition(condition_class_mapping, v, k)
                for k, v in cond_defs.items()
            }
        elif isinstance(cond_defs, list):
            return [
                self._parse_condition(condition_class_mapping, cond_def, str(i + 1))
                for i, cond_def in enumerate(cond_defs)
            ]
        else:
            raise SigmaTypeError("Conditions must be provided as list or dict")

    @classmethod
    def _parse_condition_linking(
        cls, d: dict, op_name: str
    ) -> Optional[Callable[[Iterable[bool]], bool]]:
        condition_linking = {
            "or": any,
            "and": all,
            None: None,
        }
        return condition_linking.get(d.get(op_name, None))

    @classmethod
    def _instantiate_transformation(cls, d: dict, transformations: Dict[str, Type[Transformation]]):
        try:
            transformation_class_name = d["type"]
        except KeyError:
            raise SigmaConfigurationError("Missing transformation type")

        try:
            transformation_class = transformations[transformation_class_name]
        except KeyError:
            raise SigmaConfigurationError(
                f"Unknown transformation type '{ transformation_class_name }'"
            )

        params = {
            k: v
            for k, v in d.items()
            if k
            not in {
                "rule_conditions",
                "rule_cond_expr",
                "rule_cond_op",
                "rule_cond_not",
                "detection_item_conditions",
                "detection_item_cond_expr",
                "detection_item_cond_op",
                "detection_item_cond_not",
                "field_name_conditions",
                "field_name_cond_expr",
                "field_name_cond_op",
                "field_name_cond_not",
                "type",
                "id",
            }
        }
        try:
            return transformation_class(**params)
        except (SigmaConfigurationError, TypeError) as e:
            raise SigmaConfigurationError("Error in transformation: " + str(e)) from e

    def _match_condition_expression(
        self, condition_type: Literal["rule", "detection_item", "field_name"]
    ) -> bool:
        expression = self.__getattribute__(f"{condition_type}_cond_expr")
        conditions = self.__getattribute__(f"{condition_type}_conditions")

    def match_rule_conditions(
        self, pipeline: "ProcessingPipeline", rule: Union[SigmaRule, SigmaCorrelationRule]
    ):
        if self.rule_condition_expression is not None:  # rule condition expression
            cond_result = self.rule_condition_expression.match(rule)
        else:  # simplified conditional linking of conditions
            cond_result = self.rule_condition_linking(
                [condition.match(pipeline, rule) for condition in self.rule_conditions]
            )
        if self.rule_condition_negation:
            cond_result = not cond_result
        return not self.rule_conditions or cond_result


@dataclass
class ProcessingItem(ProcessingItemBase):
    """
    A processing item consists of an optional condition and a transformation that is applied in the case that
    the condition evaluates to true against the given Sigma rule or if the condition is not present.

    Processing items are instantiated by the processing pipeline for a whole collection that is about to be
    converted by a backend.
    """

    detection_item_condition_linking: Optional[Callable[[Iterable[bool]], bool]] = (
        None  # any or all
    )
    detection_item_condition_negation: bool = False
    detection_item_conditions: Union[
        List[DetectionItemProcessingCondition], Dict[str, DetectionItemProcessingCondition]
    ] = field(default_factory=list)
    detection_item_condition_expression: Optional[str] = None
    field_name_condition_linking: Optional[Callable[[Iterable[bool]], bool]] = None  # any or all
    field_name_condition_negation: bool = False
    field_name_conditions: Union[
        List[FieldNameProcessingCondition], Dict[str, FieldNameProcessingCondition]
    ] = field(default_factory=list)
    field_name_condition_expression: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict):
        """Instantiate processing item from parsed definition and variables."""
        kwargs = super()._base_args_from_dict(d, transformations)

        detection_item_conds = cls._parse_conditions(
            detection_item_conditions, d.get("detection_item_conditions", list())
        )
        detection_item_cond_expr_str = d.get("detection_item_cond_expr", None)
        if detection_item_cond_expr_str is not None:
            detection_item_cond_expr = parse_condition_expression(
                detection_item_cond_expr_str, detection_item_conds
            )
        else:
            detection_item_cond_expr = None

        field_name_conds = cls._parse_conditions(
            field_name_conditions, d.get("field_name_conditions", list())
        )
        field_name_cond_expr_str = d.get("field_name_cond_expr", None)
        if field_name_cond_expr_str is not None:
            field_name_cond_expr = parse_condition_expression(
                field_name_cond_expr_str, field_name_conds
            )
        else:
            field_name_cond_expr = None

        kwargs.update(
            {
                "detection_item_conditions": detection_item_conds,
                "detection_item_condition_expression": detection_item_cond_expr,
                "detection_item_condition_linking": cls._parse_condition_linking(
                    d, "detection_item_cond_op"
                ),
                "detection_item_condition_negation": d.get("detection_item_cond_not", False),
                "field_name_conditions": field_name_conds,
                "field_name_condition_expression": field_name_cond_expr,
                "field_name_condition_linking": cls._parse_condition_linking(
                    d, "field_name_cond_op"
                ),
                "field_name_condition_negation": d.get("field_name_cond_not", False),
            }
        )

        return cls(**kwargs)

    def __post_init__(self):
        super().__post_init__()
        self._check_conditions(
            "detection_item_condition_expression",
            "detection_item_condition_linking",
            "detection_item_conditions",
            DetectionItemProcessingCondition,
            "Detection item condition",
        )
        self._resolve_condition_expression(
            self.detection_item_condition_expression,
            self.detection_item_conditions,
            "Detection item condition",
        )
        self._check_conditions(
            "field_name_condition_expression",
            "field_name_condition_linking",
            "field_name_conditions",
            FieldNameProcessingCondition,
            "Field name condition",
        )
        self._resolve_condition_expression(
            self.field_name_condition_expression,
            self.field_name_conditions,
            "Field name condition",
        )

    def apply(
        self, pipeline: "ProcessingPipeline", rule: Union[SigmaRule, SigmaCorrelationRule]
    ) -> bool:
        """
        Matches condition against rule and performs transformation if condition is true or not present.
        Returns Sigma rule and bool if transformation was applied.
        """
        if self.match_rule_conditions(
            pipeline, rule
        ):  # apply transformation if conditions match or no condition defined
            self.transformation.apply(pipeline, rule)
            return True
        else:  # just pass rule through
            return False

    def match_detection_item(
        self, pipeline: "ProcessingPipeline", detection_item: SigmaDetectionItem
    ) -> bool:
        """
        Evalutates detection item and field name conditions from processing item to detection item
        and returns result.
        """
        if (
            self.detection_item_condition_expression is not None
        ):  # detection item condition expression
            detection_item_cond_result = self.detection_item_condition_expression.match(
                detection_item
            )
        else:  # simplified detection item condition
            detection_item_cond_result = self.detection_item_condition_linking(
                [
                    condition.match(pipeline, detection_item)
                    for condition in self.detection_item_conditions
                ]
            )
        if self.detection_item_condition_negation:
            detection_item_cond_result = not detection_item_cond_result

        field_name_cond_result = self.field_name_condition_linking(
            [
                condition.match_detection_item(pipeline, detection_item)
                for condition in self.field_name_conditions
            ]
        )
        if self.field_name_condition_negation:
            field_name_cond_result = not field_name_cond_result

        return detection_item_cond_result and field_name_cond_result

    def match_field_name(self, pipeline: "ProcessingPipeline", field: Optional[str]) -> bool:
        """
        Evaluate field name conditions on field names and return result.
        """
        if self.field_name_condition_expression is not None:  # field name condition expression
            field_name_cond_result = self.field_name_condition_expression.match_field_name(field)
        else:  # simplified field name condition
            field_name_cond_result = self.field_name_condition_linking(
                [
                    condition.match_field_name(pipeline, field)
                    for condition in self.field_name_conditions
                ]
            )
        if self.field_name_condition_negation:
            field_name_cond_result = not field_name_cond_result

        return field_name_cond_result

    def match_field_in_value(self, pipeline: "ProcessingPipeline", value: SigmaType) -> bool:
        """
        Evaluate field name conditions in field reference values and return result.
        """
        if isinstance(value, SigmaFieldReference):
            field_name_cond_result = self.field_name_condition_linking(
                [condition.match_value(pipeline, value) for condition in self.field_name_conditions]
            )
            if self.field_name_condition_negation:
                field_name_cond_result = not field_name_cond_result

            return field_name_cond_result
        else:
            return False


@dataclass
class QueryPostprocessingItem(ProcessingItemBase):
    """
    A query post-processing item consists of an optional rule condition and a post-processing
    transformation that operates on the queries that were emitted by a backend for a given rule
    in the case that a transformation that is applied the condition evaluates to true against the
    given Sigma rule or if the condition is not present.

    These items are instantiated by the processing pipeline for a whole collection that was
    converted by a backend.
    """

    @classmethod
    def from_dict(cls, d: dict):
        """Instantiate processing item from parsed definition and variables."""
        kwargs = super()._base_args_from_dict(d, query_postprocessing_transformations)
        return cls(**kwargs)

    def apply(
        self,
        pipeline: "ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
        query: str,
    ) -> Tuple[str, bool]:
        """
        Matches condition against rule and performs transformation of query if condition is true or not present.
        Returns query and bool if transformation was applied.
        """
        if self.match_rule_conditions(
            pipeline, rule
        ):  # apply transformation if conditions match or no condition defined
            result = self.transformation.apply(pipeline, rule, query)
            return (result, True)
        else:  # just pass rule through
            return (query, False)


@dataclass
class ProcessingPipeline:
    """
    A processing pipeline is configured with the transformation steps that are applied on Sigma rules and
    are configured by:

    * a backend to apply a set of base preprocessing of Sigma rules (e.g. renaming of fields).
    * the user in one or multiple configurations to conduct further rule transformation to adapt the rule
      to the environment.

    A processing pipeline is instantiated once for a rule collection. Rules are processed in order of their
    appearance in a rule file or include order. Further, processing pipelines can be chained and contain
    variables that can be used from processing items.
    """

    items: List[ProcessingItem] = field(default_factory=list)
    postprocessing_items: List[QueryPostprocessingItem] = field(default_factory=list)
    finalizers: List[Finalizer] = field(default_factory=list)
    vars: Dict[str, Any] = field(default_factory=dict)
    priority: int = field(default=0)
    name: Optional[str] = field(default=None)
    allowed_backends: FrozenSet[str] = field(
        default_factory=frozenset
    )  # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
    # The following items are reset for each invocation of apply().
    # TODO: move this to parameters or return values of apply().
    applied: List[bool] = field(
        init=False, compare=False, default_factory=list
    )  # list of applied items as booleans. If True, the corresponding item at the same position was applied
    applied_ids: Set[str] = field(
        init=False, compare=False, default_factory=set
    )  # set of identifiers of applied items, doesn't contains items without identifier
    field_name_applied_ids: Dict[str, Set[str]] = field(
        init=False, compare=False, default_factory=partial(defaultdict, set)
    )  # Mapping of field names from rule fields list to set of applied processing items
    field_mappings: FieldMappingTracking = field(
        init=False, compare=False, default_factory=FieldMappingTracking
    )  # Mapping between initial field names and finally mapped field name.
    state: Mapping[str, Any] = field(
        init=False, compare=False, default_factory=dict
    )  # pipeline state: allows to set variables that can be used in conversion (e.g. indices, data model names etc.)

    def __post_init__(self):
        if not all((isinstance(item, ProcessingItem) for item in self.items)):
            raise TypeError(
                "Each item in a processing pipeline must be a ProcessingItem - don't use processing classes directly!"
            )
        if not all(
            (isinstance(item, QueryPostprocessingItem) for item in self.postprocessing_items)
        ):
            raise TypeError(
                "Each item in a postprocessing pipeline must be a QueryPostprocessingItem - don't use processing classes directly!"
            )
        if not all((isinstance(finalizer, Finalizer) for finalizer in self.finalizers)):
            raise TypeError("Each item in a finalizer pipeline must be a Finalizer")

    @classmethod
    def from_dict(cls, d: dict) -> "ProcessingPipeline":
        """Instantiate processing pipeline from a parsed processing item description."""
        vars = d.get("vars", dict())  # default: no variables

        items = d.get("transformations", list())  # default: no transformation
        processing_items = list()
        for i, item in enumerate(items):
            try:
                processing_items.append(ProcessingItem.from_dict(item))
            except SigmaConfigurationError as e:
                raise SigmaConfigurationError(
                    f"Error in processing rule { i + 1 }: { str(e) }"
                ) from e

        items = d.get("postprocessing", list())  # default: no transformation
        postprocessing_items = list()
        for i, item in enumerate(items):
            try:
                postprocessing_items.append(QueryPostprocessingItem.from_dict(item))
            except SigmaConfigurationError as e:
                raise SigmaConfigurationError(
                    f"Error in processing rule { i + 1 }: { str(e) }"
                ) from e

        fds = d.get("finalizers", list())  # no default transformation
        fs = list()
        for fd in fds:
            try:
                finalizer_type = fd.pop("type")
            except KeyError:
                raise SigmaConfigurationError(
                    "Finalizer type must be specified in 'type' attribute"
                )

            try:
                fs.append(finalizers[finalizer_type].from_dict(fd))
            except KeyError:
                raise SigmaConfigurationError(f"Finalizer '{finalizer_type}' is unknown")

        priority = d.get("priority", 0)
        name = d.get("name", None)
        allowed_backends = frozenset(d.get("allowed_backends", frozenset()))

        return cls(
            processing_items,
            postprocessing_items,
            fs,
            vars,
            priority,
            name,
            allowed_backends,
        )

    @classmethod
    def from_yaml(cls, processing_pipeline: str) -> "ProcessingPipeline":
        """Convert YAML input string into processing pipeline."""
        try:
            parsed_pipeline = yaml.safe_load(processing_pipeline)
        except yaml.parser.ParserError as e:
            raise SigmaPipelineParsingError(f"Error in parsing of a Sigma processing pipeline")
        return cls.from_dict(parsed_pipeline)

    def apply(
        self, rule: Union[SigmaRule, SigmaCorrelationRule]
    ) -> Union[SigmaRule, SigmaCorrelationRule]:
        """Apply processing pipeline on Sigma rule."""
        self.applied = list()
        self.applied_ids = set()
        self.field_name_applied_ids = defaultdict(set)
        self.field_mappings = FieldMappingTracking()
        self.state = dict()
        for item in self.items:
            applied = item.apply(self, rule)
            self.applied.append(applied)
            if applied and (itid := item.identifier):
                self.applied_ids.add(itid)
        return rule

    def postprocess_query(self, rule: Union[SigmaRule, SigmaCorrelationRule], query: Any) -> Any:
        """Post-process queries with postprocessing_items."""
        for item in self.postprocessing_items:
            query, applied = item.apply(self, rule, query)
            if applied and (itid := item.identifier):
                self.applied_ids.add(itid)
        return query

    def finalize(self, output: Any) -> Any:
        for finalizer in self.finalizers:
            output = finalizer.apply(self, output)
        return output

    def track_field_processing_items(
        self, src_field: str, dest_field: List[str], processing_item_id: Optional[str]
    ) -> None:
        """
        Track processing items that were applied to field names. This adds the processing_item_id to
        the set of applied processing items from src_field and assigns a copy of this set ass
        tracking set to all fields in dest_field.
        """
        if [src_field] != dest_field:  # Only add if source field was mapped to something different.
            applied_identifiers: Set = self.field_name_applied_ids[src_field]
            if processing_item_id is not None:
                applied_identifiers.add(processing_item_id)
            del self.field_name_applied_ids[src_field]
            for field in dest_field:
                self.field_name_applied_ids[field] = applied_identifiers.copy()

    def field_was_processed_by(self, field: Optional[str], processing_item_id: str) -> bool:
        """
        Check if field name was processed by a particular processing item.
        """
        if field is None:
            return False
        return processing_item_id in self.field_name_applied_ids[field]

    def __add__(self, other: Optional["ProcessingPipeline"]) -> "ProcessingPipeline":
        """Concatenate two processing pipelines and merge their variables."""
        if other is None:
            return self
        if not isinstance(other, self.__class__):
            raise TypeError("Processing pipeline must be merged with another one.")

        return self.__class__(
            items=self.items + other.items,
            postprocessing_items=self.postprocessing_items + other.postprocessing_items,
            finalizers=self.finalizers + other.finalizers,
            vars={**self.vars, **other.vars},
        )

    def __radd__(self, other: Literal[0]) -> "ProcessingPipeline":
        """Ignore integer 0 on addition to make sum of list of ProcessingPipelines working."""
        if other == 0:
            return self
        else:
            return NotImplemented
