from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sigma.matching.compiler import CompiledMatcher, MatchCompiler
from sigma.matching.event import Event
from sigma.matching.match import SigmaMatch

if TYPE_CHECKING:
    from sigma.rule.rule import SigmaRule


class SigmaRuleMatcher:
    """Evaluates a single SigmaRule against events using a precompiled matcher."""

    def __init__(self, rule: SigmaRule, compiler: MatchCompiler) -> None:
        self.rule = rule
        self._matcher: CompiledMatcher = compiler.compile_rule(rule)

    def matches(self, event: Event) -> SigmaMatch | None:
        """Return a SigmaMatch if the event matches this rule, else None."""
        raw = event.get_raw()
        if self._matcher(event.data, raw):
            return SigmaMatch(
                rule=self.rule,
                events=[event],
                timestamp=event.timestamp,
            )
        return None
