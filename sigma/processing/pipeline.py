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
from sigma.processing.finalization import Finalizer, finalizers
from sigma.processing.postprocessing import QueryPostprocessingTransformation
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
from sigma.exceptions import SigmaConfigurationError, SigmaTypeError
import yaml

from sigma.types import SigmaFieldReference, SigmaType


@dataclass
class ProcessingItemBase:
    transformation: Transformation
    rule_condition_linking: Callable[[Iterable[bool]], bool] = all  # any or all
    rule_condition_negation: bool = False
    rule_conditions: List[RuleProcessingCondition] = field(default_factory=list)
    identifier: Optional[str] = None

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
        cond_defs: Dict,
    ) -> Union[
        List[RuleProcessingCondition],
        List[DetectionItemProcessingCondition],
        List[FieldNameProcessingCondition],
    ]:
        """Parse dict of conditions into list of condition object instances.

        :param condition_class_mapping: Mapping between condition type identifiers and condition classes.
        :type condition_class_mapping: Dict[str, Union[Type[RuleProcessingCondition], Type[DetectionItemProcessingCondition], Type[FieldNameProcessingCondition]]]
        :param cond_defs: Definition of conditions for the pipeline.
        :type cond_defs: Dict
        :return: List of condition classes as defined in dict.
        :rtype: Union[List[RuleProcessingCondition], List[DetectionItemProcessingCondition], List[FieldNameProcessingCondition]]
        """
        conds = list()
        for i, cond_def in enumerate(cond_defs):
            try:
                cond_type = cond_def["type"]
            except KeyError:
                raise SigmaConfigurationError(
                    f"Missing condition type defined in condition { i + 1 }"
                )

            try:
                cond_class = condition_class_mapping[cond_type]
            except KeyError:
                raise SigmaConfigurationError(
                    f"Unknown condition type '{ cond_type }' in condition { i + 1 }"
                )

            cond_params = {k: v for k, v in cond_def.items() if k != "type"}
            try:
                conds.append(cond_class(**cond_params))
            except (SigmaConfigurationError, TypeError) as e:
                raise SigmaConfigurationError(f"Error in condition { i + 1 }: { str(e) }") from e
        return conds

    @classmethod
    def _instantiate_transformation(cls, d: dict, transformations: Dict[str, Type[Transformation]]):
        try:
            transformation_class_name = d["type"]
        except KeyError:
            raise SigmaConfigurationError("Missing transformation type")

        try:
            return transformations[transformation_class_name]
        except KeyError:
            raise SigmaConfigurationError(
                f"Unknown transformation type '{ transformation_class_name }'"
            )

    def match_rule_conditions(self, pipeline: "ProcessingPipeline", rule: SigmaRule):
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

    detection_item_condition_linking: Callable[[Iterable[bool]], bool] = all  # any or all
    detection_item_condition_negation: bool = False
    detection_item_conditions: List[DetectionItemProcessingCondition] = field(default_factory=list)
    field_name_condition_linking: Callable[[Iterable[bool]], bool] = all  # any or all
    field_name_condition_negation: bool = False
    field_name_conditions: List[FieldNameProcessingCondition] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict):
        """Instantiate processing item from parsed definition and variables."""
        # Identifier
        identifier = d.get("id", None)

        # Parse conditions
        rule_conds = cls._parse_conditions(rule_conditions, d.get("rule_conditions", list()))
        detection_item_conds = cls._parse_conditions(
            detection_item_conditions, d.get("detection_item_conditions", list())
        )
        field_name_conds = cls._parse_conditions(
            field_name_conditions, d.get("field_name_conditions", list())
        )

        condition_linking = {
            "or": any,
            "and": all,
        }
        rule_condition_linking = condition_linking[
            d.get("rule_cond_op", "and")
        ]  # default: conditions are linked with and operator
        detection_item_condition_linking = condition_linking[
            d.get("detection_item_cond_op", "and")
        ]  # same for detection item conditions
        field_name_condition_linking = condition_linking[
            d.get("field_name_cond_op", "and")
        ]  # same for field name conditions

        rule_condition_negation = d.get("rule_cond_not", False)
        detection_item_condition_negation = d.get("detection_item_cond_not", False)
        field_name_condition_negation = d.get("field_name_cond_not", False)

        # Transformation
        transformation_class = cls._instantiate_transformation(d, transformations)

        params = {
            k: v
            for k, v in d.items()
            if k
            not in {
                "rule_conditions",
                "rule_cond_op",
                "rule_cond_not",
                "detection_item_conditions",
                "detection_item_cond_op",
                "detection_item_cond_not",
                "field_name_conditions",
                "field_name_cond_op",
                "field_name_cond_not",
                "type",
                "id",
            }
        }
        try:
            transformation = transformation_class(**params)
        except (SigmaConfigurationError, TypeError) as e:
            raise SigmaConfigurationError("Error in transformation: " + str(e)) from e

        return cls(
            transformation,
            rule_condition_linking,
            rule_condition_negation,
            rule_conds,
            identifier,
            detection_item_condition_linking,
            detection_item_condition_negation,
            detection_item_conds,
            field_name_condition_linking,
            field_name_condition_negation,
            field_name_conds,
        )

    def __post_init__(self):
        self.transformation.set_processing_item(
            self
        )  # set processing item in transformation object after it is instantiated
        if not isinstance(self.rule_conditions, list):
            raise SigmaTypeError("Rule processing conditions must be provided as list")
        for rule_condition in self.rule_conditions:
            if not isinstance(rule_condition, RuleProcessingCondition):
                raise SigmaTypeError(
                    f"Rule processing condition '{str(rule_condition)}' is not a RuleProcessingCondition"
                )
        if not isinstance(self.detection_item_conditions, list):
            raise SigmaTypeError("Detection item processing conditions must be provided as list")
        for detection_item_condition in self.detection_item_conditions:
            if not isinstance(detection_item_condition, DetectionItemProcessingCondition):
                raise SigmaTypeError(
                    f"Detection item processing condition '{str(detection_item_condition)}' is not a DetectionItemProcessingCondition"
                )
        if not isinstance(self.field_name_conditions, list):
            raise SigmaTypeError("Field name processing conditions must be provided as list")
        for field_name_condition in self.field_name_conditions:
            if not isinstance(field_name_condition, FieldNameProcessingCondition):
                raise SigmaTypeError(
                    f"Detection item processing condition '{str(field_name_condition)}' is not a FieldNameProcessingCondition"
                )

    def apply(self, pipeline: "ProcessingPipeline", rule: SigmaRule) -> bool:
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
        # Identifier
        identifier = d.get("id", None)

        # Parse conditions
        condition_linking = {
            "or": any,
            "and": all,
        }
        rule_conds = cls._parse_conditions(rule_conditions, d.get("rule_conditions", list()))
        rule_condition_linking = condition_linking[
            d.get("rule_cond_op", "and")
        ]  # default: conditions are linked with and operator
        rule_condition_negation = d.get("rule_cond_not", False)

        # Transformation
        transformation_class = cls._instantiate_transformation(
            d, query_postprocessing_transformations
        )

        params = {
            k: v
            for k, v in d.items()
            if k not in {"rule_conditions", "rule_cond_op", "rule_cond_not", "type", "id"}
        }
        try:
            transformation = transformation_class(**params)
        except (SigmaConfigurationError, TypeError) as e:
            raise SigmaConfigurationError("Error in transformation: " + str(e)) from e

        return cls(
            transformation, rule_condition_linking, rule_condition_negation, rule_conds, identifier
        )

    def __post_init__(self):
        self.transformation.set_processing_item(
            self
        )  # set processing item in transformation object after it is instantiated
        if not isinstance(self.rule_conditions, list):
            raise SigmaTypeError("Rule processing conditions must be provided as list")
        for rule_condition in self.rule_conditions:
            if not isinstance(rule_condition, RuleProcessingCondition):
                raise SigmaTypeError(
                    f"Rule processing condition '{str(rule_condition)}' is not a RuleProcessingCondition"
                )

    def apply(
        self, pipeline: "ProcessingPipeline", rule: SigmaRule, query: str
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
    postprocessing_items: List[QueryPostprocessingTransformation] = field(default_factory=list)
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
        parsed_pipeline = yaml.safe_load(processing_pipeline)
        return cls.from_dict(parsed_pipeline)

    def apply(self, rule: SigmaRule) -> SigmaRule:
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

    def postprocess_query(self, rule: SigmaRule, query: Any) -> Any:
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
