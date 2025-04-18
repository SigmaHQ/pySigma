from typing import Any
from dataclasses import dataclass
from sigma.processing.transformations.base import PreprocessingTransformation
from sigma.rule import SigmaRule


@dataclass
class SetStateTransformation(PreprocessingTransformation):
    """Set pipeline state key to value."""

    key: str
    val: Any

    def apply(self, rule: SigmaRule) -> None:
        super().apply(rule)
        self._pipeline.state[self.key] = self.val
