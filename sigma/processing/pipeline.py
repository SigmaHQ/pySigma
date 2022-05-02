from dataclasses import dataclass, field
from typing import List, Literal, Mapping, Set, Any, Callable, Iterable, Dict, Tuple, Optional
from sigma.rule import SigmaDetectionItem, SigmaRule
from sigma.processing.transformations import transformations, Transformation
from sigma.processing.conditions import rule_conditions, RuleProcessingCondition, detection_item_conditions, DetectionItemProcessingCondition
from sigma.exceptions import SigmaConfigurationError
import yaml

@dataclass
class ProcessingItem:
    """
    A processing item consists of an optional condition and a transformation that is applied in the case that
    the condition evaluates to true against the given Sigma rule or if the condition is not present.

    Processing items are instantiated by the processing pipeline for a whole collection that is about to be
    converted by a backend.
    """
    transformation : Transformation
    rule_condition_linking : Callable[[ Iterable[bool] ], bool] = all    # any or all
    rule_condition_negation : bool = False
    rule_conditions : List[RuleProcessingCondition] = field(default_factory=list)
    detection_item_condition_linking : Callable[[ Iterable[bool] ], bool] = all    # any or all
    detection_item_condition_negation : bool = False
    detection_item_conditions : List[DetectionItemProcessingCondition] = field(default_factory=list)
    identifier : Optional[str] = None

    @classmethod
    def from_dict(cls, d : dict):
        """Instantiate processing item from parsed definition and variables."""
        # Identifier
        identifier = d.get("id", None)

        # Rule and detection item conditions
        # Do the same initialization for rule and detection item conditions
        for condition_class_mapping, cond_defs, conds in (
            (                                       # Condition item processing items are defined as follows:
                rule_conditions,                    # Dict containing mapping between names used in configuration and classes.
                d.get("rule_conditions", list()),   # List of conditions in configuration dict
                rule_conds := list(),               # List where condition classes for ProcessingItem initialization are collected
            ),
            (
                detection_item_conditions,
                d.get("detection_item_conditions", list()),
                detection_item_conds := list()
            ),
        ):
            for i, cond_def in enumerate(cond_defs):
                try:
                    cond_type = cond_def["type"]
                except KeyError:
                    raise SigmaConfigurationError(f"Missing condition type defined in condition { i + 1 }")

                try:
                    cond_class = condition_class_mapping[cond_type]
                except KeyError:
                    raise SigmaConfigurationError(f"Unknown condition type '{ cond_type }' in condition { i + 1 }")

                cond_params = {
                    k: v
                    for k, v in cond_def.items()
                    if k != "type"
                }
                try:
                    conds.append(cond_class(**cond_params))
                except (SigmaConfigurationError, TypeError) as e:
                    raise SigmaConfigurationError(f"Error in condition { i + 1 }: { str(e) }") from e

        condition_linking = {
            "or": any,
            "and": all,
        }
        rule_condition_linking = condition_linking[d.get("rule_cond_op", "and")]   # default: conditions are linked with and operator
        detection_item_condition_linking = condition_linking[d.get("detection_item_cond_op", "and")]   # same for detection item conditions

        rule_condition_negation = d.get("rule_cond_not", False)
        detection_item_condition_negation = d.get("detection_item_cond_not", False)

        # Transformation
        try:
            transformation_class_name = d["type"]
        except KeyError:
            raise SigmaConfigurationError("Missing transformation type")

        try:
            transformation_class = transformations[transformation_class_name]
        except KeyError:
            raise SigmaConfigurationError(f"Unknown transformation type '{ transformation_class_name }'")

        params = {
            k: v
            for k, v in d.items()
            if k not in {"rule_conditions", "rule_cond_op", "rule_cond_not", "detection_item_conditions", "detection_item_cond_op", "detection_item_cond_not", "type", "id"}
        }
        try:
            transformation = transformation_class(**params)
        except (SigmaConfigurationError, TypeError) as e:
            raise SigmaConfigurationError("Error in transformation: " + str(e)) from e

        return cls(transformation, rule_condition_linking, rule_condition_negation, rule_conds, detection_item_condition_linking, detection_item_condition_negation, detection_item_conds, identifier)

    def __post_init__(self):
        self.transformation.set_processing_item(self)   # set processing item in transformation object after it is instantiated

    def apply(self, pipeline : "ProcessingPipeline", rule : SigmaRule) -> Tuple[SigmaRule, bool]:
        """
        Matches condition against rule and performs transformation if condition is true or not present.
        Returns Sigma rule and bool if transformation was applied.
        """
        cond_result = self.rule_condition_linking([
            condition.match(pipeline, rule)
            for condition in self.rule_conditions
        ])
        if self.rule_condition_negation:
            cond_result = not cond_result
        if not self.rule_conditions or cond_result:     # apply transformation if conditions match or no condition defined
            self.transformation.apply(pipeline, rule)
            return True
        else:       # just pass rule through
            return False

    def match_detection_item(self, pipeline : "ProcessingPipeline", detection_item : SigmaDetectionItem) -> bool:
        """Evalutates detection item conditions from processing item to detection item and returns
        result."""
        cond_result = self.detection_item_condition_linking([
            condition.match(pipeline, detection_item)
            for condition in self.detection_item_conditions
        ])
        if self.detection_item_condition_negation:
            cond_result = not cond_result
        return not self.detection_item_conditions or cond_result

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
    items : List[ProcessingItem] = field(default_factory=list)
    vars  : Dict[str, Any] = field(default_factory=dict)
    priority : int = field(default=0)
    name : Optional[str] = field(default=None)
    # The following items are reset for each invocation of apply().
    # TODO: move this to parameters or return values of apply().
    applied : List[bool] = field(init=False, compare=False)     # list of applied items as booleans. If True, the corresponding item at the same position was applied
    applied_ids : Set[str] = field(init=False, compare=False)   # set of identifiers of applied items, doesn't contains items without identifier
    state : Mapping[str, Any] = field(init=False, compare=False)    # pipeline state: allows to set variables that can be used in conversion (e.g. indices, data model names etc.)

    def __post_init__(self):
        if not all((isinstance(item, ProcessingItem) for item in self.items)):
            raise TypeError("Each item in a processing pipeline must be a ProcessingItem - don't use processing classes directly!")
        self.applied = list()
        self.applied_ids = set()
        self.state = dict()

    @classmethod
    def from_dict(cls, d : dict) -> "ProcessingPipeline":
        """Instantiate processing pipeline from a parsed processing item description."""
        vars = d.get("vars", dict())        # default: no variables
        items = d.get("transformations", list())      # default: no transformation
        processing_items = list()
        for i, item in enumerate(items):
            try:
                processing_items.append(ProcessingItem.from_dict(item))
            except SigmaConfigurationError as e:
                raise SigmaConfigurationError(f"Error in processing rule { i + 1 }: { str(e) }") from e
        priority = d.get("priority", 0)
        name = d.get("name", None)

        return cls(processing_items, vars, priority, name)

    @classmethod
    def from_yaml(cls, processing_pipeline : str) -> "ProcessingPipeline":
        """Convert YAML input string into processing pipeline."""
        parsed_pipeline = yaml.safe_load(processing_pipeline)
        return cls.from_dict(parsed_pipeline)

    def apply(self, rule : SigmaRule) -> SigmaRule:
        """Apply processing pipeline on Sigma rule."""
        self.applied = list()
        self.applied_ids = set()
        self.state = dict()
        for item in self.items:
            applied = item.apply(self, rule)
            self.applied.append(applied)
            if applied and (itid := item.identifier):
                self.applied_ids.add(itid)
        return rule

    def __add__(self, other : Optional["ProcessingPipeline"]) -> "ProcessingPipeline":
        """Concatenate two processing pipelines and merge their variables."""
        if other is None:
            return self
        if not isinstance(other, self.__class__):
            raise TypeError("Processing pipeline must be merged with another one.")
        return self.__class__(
            items=self.items + other.items,
            vars = { **self.vars, **other.vars }
        )

    def __radd__(self, other : Literal[0]) -> "ProcessingPipeline":
        """Ignore integer 0 on addition to make sum of list of ProcessingPipelines working."""
        if other == 0:
            return self
        else:
            return NotImplemented