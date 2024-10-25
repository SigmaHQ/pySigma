from abc import abstractmethod
from sigma.conditions import SigmaCondition
from typing import (
    Any,
    List,
    Dict,
    Optional,
    Union,
)
from dataclasses import dataclass, field
import random
import string
import sigma
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.transformations.base import (
    ConditionTransformation,
    DetectionItemTransformation,
    Transformation,
)
from sigma.rule import SigmaLogSource, SigmaRule, SigmaDetection, SigmaDetectionItem
from sigma.exceptions import (
    SigmaTransformationError,
    SigmaConfigurationError,
)


@dataclass
class AddConditionTransformation(ConditionTransformation):
    """
    Add a condition expression to rule conditions.

    If template is set to True the condition values are interpreted as string templates and the
    following placeholders are replaced:

    * $category, $product and $service: with the corresponding values of the Sigma rule log source.
    """

    conditions: Dict[str, Union[str, List[str]]] = field(default_factory=dict)
    name: Optional[str] = field(default=None, compare=False)
    template: bool = False
    negated: bool = False

    def __post_init__(self):
        if self.name is None:  # generate random detection item name if none is given
            self.name = "_cond_" + ("".join(random.choices(string.ascii_lowercase, k=10)))

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> None:
        if isinstance(rule, SigmaRule):
            if self.template:
                conditions = {
                    field: (
                        [
                            string.Template(item).safe_substitute(
                                category=rule.logsource.category,
                                product=rule.logsource.product,
                                service=rule.logsource.service,
                            )
                            for item in value
                        ]
                        if isinstance(value, list)
                        else string.Template(value).safe_substitute(
                            category=rule.logsource.category,
                            product=rule.logsource.product,
                            service=rule.logsource.service,
                        )
                    )
                    for field, value in self.conditions.items()
                }
            else:
                conditions = self.conditions

            rule.detection.detections[self.name] = SigmaDetection.from_definition(conditions)
            self.processing_item_applied(rule.detection.detections[self.name])
            super().apply(pipeline, rule)

    def apply_condition(self, cond: SigmaCondition) -> None:
        cond.condition = ("not " if self.negated else "") + f"{self.name} and ({cond.condition})"


@dataclass
class ChangeLogsourceTransformation(Transformation):
    """Replace log source as defined in transformation parameters."""

    category: Optional[str] = field(default=None)
    product: Optional[str] = field(default=None)
    service: Optional[str] = field(default=None)

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> None:
        super().apply(pipeline, rule)
        logsource = SigmaLogSource(self.category, self.product, self.service)
        rule.logsource = logsource


@dataclass
class SetStateTransformation(Transformation):
    """Set pipeline state key to value."""

    key: str
    val: Any

    def apply(self, pipeline: "sigma.processing.pipeline.Proces", rule: SigmaRule) -> None:
        super().apply(pipeline, rule)
        pipeline.state[self.key] = self.val


@dataclass
class RuleFailureTransformation(Transformation):
    """
    Raise a SigmaTransformationError with the provided message. This enables transformation
    pipelines to signalize that a certain situation can't be handled, e.g. only a subset of values
    is allowed because the target data model doesn't offers all possibilities.
    """

    message: str

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> None:
        raise SigmaTransformationError(self.message)


@dataclass
class DetectionItemFailureTransformation(DetectionItemTransformation):
    """
    Raise a SigmaTransformationError with the provided message. This enables transformation
    pipelines to signalize that a certain situation can't be handled, e.g. only a subset of values
    is allowed because the target data model doesn't offers all possibilities.
    """

    message: str

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        raise SigmaTransformationError(self.message)


@dataclass
class SetCustomAttributeTransformation(Transformation):
    """
    Sets an arbitrary custom attribute on a rule, that can be used by a backend during processing.
    """

    attribute: str
    value: Any

    def apply(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> None:
        super().apply(pipeline, rule)
        rule.custom_attributes[self.attribute] = self.value


@dataclass
class NestedProcessingTransformation(Transformation):
    """Executes a nested processing pipeline as transformation. Main purpose is to apply a
    whole set of transformations that match the given conditions of the enclosng processing item.
    """

    items: List["sigma.processing.pipeline.ProcessingItem"]
    _nested_pipeline: "sigma.processing.pipeline.ProcessingPipeline" = field(
        init=False, compare=False, repr=False
    )

    def __post_init__(self):
        from sigma.processing.pipeline import (
            ProcessingPipeline,
        )  # TODO: move to top-level after restructuring code

        self._nested_pipeline = ProcessingPipeline(items=self.items)

    @classmethod
    def from_dict(cls, d: Dict) -> "NestedProcessingTransformation":
        from sigma.processing.pipeline import (
            ProcessingItem,
        )  # TODO: move to top-level after restructuring code

        try:
            return cls(items=[ProcessingItem.from_dict(item) for item in d["items"]])
        except KeyError:
            raise SigmaConfigurationError(
                "Nested processing transformation requires an 'items' key."
            )

    def apply(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> None:
        super().apply(pipeline, rule)
        self._nested_pipeline.apply(rule)
        pipeline.applied.extend(self._nested_pipeline.applied)
        pipeline.applied_ids.update(self._nested_pipeline.applied_ids)
        pipeline.field_name_applied_ids.update(self._nested_pipeline.field_name_applied_ids)
        pipeline.field_mappings.merge(self._nested_pipeline.field_mappings)
        pipeline.state.update(self._nested_pipeline.state)
