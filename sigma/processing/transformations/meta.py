from typing import (
    List,
    Dict,
    Union,
)
from dataclasses import dataclass, field
import sigma
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.transformations.base import Transformation
from sigma.rule import SigmaRule
from sigma.exceptions import SigmaConfigurationError


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

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
        super().apply(rule)
        self._nested_pipeline.apply(rule)
        self._pipeline.applied.extend(self._nested_pipeline.applied)
        self._pipeline.applied_ids.update(self._nested_pipeline.applied_ids)
        self._pipeline.field_name_applied_ids.update(self._nested_pipeline.field_name_applied_ids)
        self._pipeline.field_mappings.merge(self._nested_pipeline.field_mappings)
        self._pipeline.state.update(self._nested_pipeline.state)
