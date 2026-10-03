from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from sigma.policy.regex_engine import RegexPattern
from sigma.processing.conditions.base import (
    ValueProcessingCondition,
)
from sigma.types import SigmaNull, SigmaString, SigmaType
from sigma.exceptions import SigmaRegularExpressionError

if TYPE_CHECKING:
    from sigma.policy.regex_engine import RegexEngine


@dataclass
class MatchStringCondition(ValueProcessingCondition):
    """
    Match string values with a regular expression 'pattern'. The parameter 'cond' determines for detection items with multiple
    values if any or all strings must match. Generally, values which aren't strings are skipped in any mode or result in a
    false result in all match mode.
    """

    pattern: str
    negate: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()
        engine = self.resolve_regex_engine()
        try:
            self.compile_regex(self.pattern)
        except engine.error as e:
            raise SigmaRegularExpressionError(
                f"Regular expression '{self.pattern}' is invalid: {str(e)}"
            ) from e

    def match_value(self, value: SigmaType) -> bool:
        if isinstance(value, SigmaString):
            result = bool(self.regex_match(self.pattern, str(value)))
        else:
            result = False

        if self.negate:
            return not result
        else:
            return result


@dataclass
class MatchValueCondition(ValueProcessingCondition):
    """
    Exact match of a value with an arbitrary Sigma type.
    """

    value: str | int | float | bool

    def match_value(self, value: SigmaType) -> bool:
        try:
            return value == self.value
        except NotImplementedError:
            return False


class ContainsWildcardCondition(ValueProcessingCondition):
    """
    Evaluates to True if the value contains a wildcard character.
    """

    def match_value(self, value: SigmaType) -> bool:
        if isinstance(value, SigmaString):
            return value.contains_special()
        else:
            return False


@dataclass
class IsNullCondition(ValueProcessingCondition):
    """
    Match null values. The parameter 'cond' determines for detection items with multiple
    values if any or all strings must match. Generally, values which aren't strings are skipped in any mode or result in a
    false result in all match mode.
    """

    def match_value(self, value: SigmaType) -> bool:
        return isinstance(value, SigmaNull)
