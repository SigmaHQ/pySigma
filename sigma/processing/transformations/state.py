from typing import (
    Any,
    List,
    Dict,
    Union,
)
from dataclasses import dataclass, field
import sigma
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.transformations.base import (
    DetectionItemTransformation,
    Transformation,
)
from sigma.rule import SigmaRule, SigmaDetectionItem
from sigma.exceptions import (
    SigmaTransformationError,
    SigmaConfigurationError,
)


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
