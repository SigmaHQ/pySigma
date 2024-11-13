from typing import (
    List,
    Dict,
    Union,
)
from dataclasses import dataclass, field
import sigma
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.exceptions import (
    SigmaConfigurationError,
)


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
            ProcessingItem,
        )  # TODO: move to top-level after restructuring code

        self.items = [
            i if isinstance(i, ProcessingItem) else ProcessingItem.from_dict(i) for i in self.items
        ]
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
