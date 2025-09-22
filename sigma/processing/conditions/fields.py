from dataclasses import dataclass, field

from sigma.processing.conditions.base import FieldNameProcessingCondition
from typing import Pattern, Literal, Optional
import re
from sigma.rule import SigmaDetectionItem
from sigma.exceptions import SigmaConfigurationError


@dataclass
class IncludeFieldCondition(FieldNameProcessingCondition):
    """
    Matches on field name if it is contained in fields list. The parameter 'mode' determines if field names are matched as
    plain string ("plain") or regular expressions ("re").
    """

    fields: list[str]
    mode: Literal["plain", "re"] = field(default="plain")
    patterns: list[Pattern[str]] = field(init=False, repr=False, default_factory=list)

    def __post_init__(self) -> None:
        """
        Check if format is known and pre-compile regular expressions.
        """
        if self.mode == "plain":
            pass
        elif self.mode == "re":
            self.patterns = [re.compile(field) for field in self.fields]
        else:
            raise SigmaConfigurationError(
                f"Invalid field name matching mode '{self.mode}', supported types are 'plain' or 're'."
            )

    def match_field_name(
        self,
        field: Optional[str],
    ) -> bool:
        if field is None:
            return False
        elif self.mode == "plain":
            return field in self.fields
        else:  # regular expression matching
            try:
                return any((pattern.match(field) for pattern in self.patterns))
            except Exception as e:
                msg = f" (while processing field '{field}'"
                if len(e.args) > 1:
                    e.args = (e.args[0] + msg,) + e.args[1:]
                else:
                    e.args = (e.args[0] + msg,)
                raise


@dataclass
class ExcludeFieldCondition(IncludeFieldCondition):
    """Matches on field name if it is not contained in fields list."""

    def match_field_name(
        self,
        field: Optional[str],
    ) -> bool:
        return not super().match_field_name(field)
