from typing import (
    Any,
    Union,
    TYPE_CHECKING,
)
from dataclasses import InitVar, dataclass, field
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.transformations.base import PreprocessingTransformation
from sigma.rule import SigmaRule
from sigma.exceptions import SigmaConfigurationError

if TYPE_CHECKING:
    from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem


@dataclass
class NestedProcessingTransformation(PreprocessingTransformation):
    """Executes a nested processing pipeline as transformation. Main purpose is to apply a
    whole set of transformations that match the given conditions of the enclosng processing item.
    """

    items: InitVar[list[Union[dict[str, Any], "ProcessingItem"]]]
    _nested_pipeline: "ProcessingPipeline" = field(init=False, compare=False, repr=False)

    def __post_init__(self, items: list[Union[dict[str, Any], "ProcessingItem"]]) -> None:
        from sigma.processing.pipeline import (
            ProcessingPipeline,
            ProcessingItem,
        )  # TODO: move to top-level after restructuring code

        clean_items = [
            i if isinstance(i, ProcessingItem) else ProcessingItem.from_dict(i) for i in items
        ]
        self._nested_pipeline = ProcessingPipeline(items=clean_items)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "NestedProcessingTransformation":
        from sigma.processing.pipeline import (
            ProcessingItem,
        )  # TODO: move to top-level after restructuring code

        try:
            return cls(items=[ProcessingItem.from_dict(item) for item in d["items"]])
        except KeyError:
            raise SigmaConfigurationError(
                "Nested processing transformation requires an 'items' key."
            )

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
        super().apply(rule)
        self._nested_pipeline.apply(rule)
        if self._pipeline is None:
            raise SigmaConfigurationError("Nested pipeline has not enclosing pipeline.")
        self._pipeline.applied.extend(self._nested_pipeline.applied)
        self._pipeline.applied_ids.update(self._nested_pipeline.applied_ids)
        self._pipeline.field_name_applied_ids.update(self._nested_pipeline.field_name_applied_ids)
        self._pipeline.field_mappings.merge(self._nested_pipeline.field_mappings)
        self._pipeline.state.update(self._nested_pipeline.state)
