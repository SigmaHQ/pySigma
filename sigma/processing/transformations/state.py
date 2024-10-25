from typing import Any
from dataclasses import dataclass
import sigma
from sigma.processing.transformations.base import Transformation
from sigma.rule import SigmaRule


@dataclass
class SetStateTransformation(Transformation):
    """Set pipeline state key to value."""

    key: str
    val: Any

    def apply(self, pipeline: "sigma.processing.pipeline.Proces", rule: SigmaRule) -> None:
        super().apply(pipeline, rule)
        pipeline.state[self.key] = self.val
