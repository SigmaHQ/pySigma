from abc import abstractmethod
from typing import (
    Any,
    List,
    Dict,
    Optional,
    Union,
)
from dataclasses import dataclass, field
import sigma
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.transformations.base import (
    Transformation,
)
from sigma.rule import SigmaLogSource, SigmaRule


@dataclass
class ChangeLogsourceTransformation(Transformation):
    """Replace log source as defined in transformation parameters."""

    category: Optional[str] = field(default=None)
    product: Optional[str] = field(default=None)
    service: Optional[str] = field(default=None)

    def apply(self, rule: SigmaRule) -> None:
        super().apply(rule)
        logsource = SigmaLogSource(self.category, self.product, self.service)
        rule.logsource = logsource


@dataclass
class SetCustomAttributeTransformation(Transformation):
    """
    Sets an arbitrary custom attribute on a rule, that can be used by a backend during processing.
    """

    attribute: str
    value: Any

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
        super().apply(rule)
        rule.custom_attributes[self.attribute] = self.value
