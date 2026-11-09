from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sigma.matching.event import Event
    from sigma.rule.base import SigmaRuleBase


@dataclass
class SigmaMatch:
    """Result of a successful Sigma rule match against one or more events."""

    rule: SigmaRuleBase
    events: list[Event]
    timestamp: datetime
    group_values: dict[str, Any] | None = None
