from typing import Any, Union
from dataclasses import dataclass
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.transformations.base import PreprocessingTransformation
from sigma.rule import SigmaRule


@dataclass
class SetStateTransformation(PreprocessingTransformation):
    """Set pipeline state key to value."""

    key: str
    val: Any

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
        super().apply(rule)
        if self._pipeline is not None:
            self._pipeline.state[self.key] = self.val
