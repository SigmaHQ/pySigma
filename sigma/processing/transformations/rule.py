from typing import (
    Any,
    Optional,
    Union,
)
from dataclasses import dataclass, field
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.transformations.base import (
    PreprocessingTransformation,
)
from sigma.rule import SigmaLogSource, SigmaRule


@dataclass
class ChangeLogsourceTransformation(PreprocessingTransformation):
    """Replace log source as defined in transformation parameters."""

    category: Optional[str] = field(default=None)
    product: Optional[str] = field(default=None)
    service: Optional[str] = field(default=None)

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
        super().apply(rule)
        if isinstance(rule, SigmaRule):
            logsource = SigmaLogSource(self.category, self.product, self.service)
            rule.logsource = logsource


@dataclass
class SetCustomAttributeTransformation(PreprocessingTransformation):
    """
    Sets an arbitrary custom attribute on a rule, that can be used by a backend during processing.
    """

    attribute: str
    value: Any

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
        super().apply(rule)
        rule.custom_attributes[self.attribute] = self.value
