from dataclasses import dataclass, field
from typing import List, Any, Callable, Iterable, Dict, Tuple, Optional
from sigma.rule import SigmaRule
from sigma.processing.transformations import transformations, Transformation
from sigma.processing.conditions import conditions, ProcessingCondition
from sigma.exceptions import SigmaConfigurationError

@dataclass
class ProcessingItem:
    """
    A processing item consists of an optional condition and a transformation that is applied in the case that
    the condition evaluates to true against the given Sigma rule or if the condition is not present.

    Processing items are instantiated by the processing pipeline for a whole collection that is about to be
    converted by a backend.
    """
    transformation : Transformation
    condition_linking : Callable[[ Iterable[bool] ], bool] = all    # any or all
    conditions : List[ProcessingCondition] = field(default_factory=list)
    identifier : Optional[str] = None

    @classmethod
    def from_dict(cls, d : dict):
        """Instantiate processing item from parsed definition and variables."""
        # Identifier
        identifier = d.get("id")
        # Condition
        conds = list()
        cond_defs = d.get("conditions", list())
        for i, cond_def in enumerate(cond_defs):
            try:
                cond_type = cond_def["type"]
            except KeyError:
                raise SigmaConfigurationError(f"Missing condition type defined in condition { i + 1 }")

            try:
                cond_class = conditions[cond_type]
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
        }[d.get("cond_op", "and")]   # default: conditions are linked with and operator

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
            if k not in {"conditions", "cond_op", "type", "id"}
        }
        try:
            transformation = transformation_class(**params)
        except (SigmaConfigurationError, TypeError) as e:
            raise SigmaConfigurationError("Error in transformation: " + str(e)) from e

        return cls(transformation, condition_linking, conds, identifier)

    def apply(self, pipeline : "ProcessingPipeline", rule : SigmaRule) -> Tuple[SigmaRule, bool]:
        """
        Matches condition against rule and performs transformation if condition is true or not present.
        Returns Sigma rule and bool if transformation was applied.
        """
        if not self.conditions or \
            self.condition_linking([
                condition.match(pipeline, rule)
                for condition in self.conditions
            ]):     # apply transformation if conditions match or no condition defined
            return self.transformation.apply(pipeline, rule), True
        else:       # just pass rule through
            return rule, False

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
    items : List[ProcessingItem]
    vars  : Dict[str, Any] = field(default_factory=dict)

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

        return cls(processing_items, vars)

    def apply(self, rule : SigmaRule) -> SigmaRule:
        """Apply processing pipeline on Sigma rule."""
        self.applied = list()
        self.applied_ids = set()
        for item in self.items:
            rule, applied = item.apply(self, rule)
            self.applied.append(applied)
            if applied and (itid := item.identifier):
                self.applied_ids.add(itid)
        return rule