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

    def apply(self, rule: SigmaRule) -> None:
        super().apply(rule)
        self._pipeline.state[self.key] = self.val
