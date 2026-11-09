from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class EventLogSource:
    """Lightweight logsource descriptor for events."""

    category: str | None = None
    product: str | None = None
    service: str | None = None

    def as_tuple(self) -> tuple[str | None, str | None, str | None]:
        return (self.category, self.product, self.service)


@dataclass
class Event:
    """A parsed log event to be matched against Sigma rules."""

    timestamp: datetime
    logsource: EventLogSource
    data: dict[str, Any]
    raw: str | None = None
    _raw_cache: str | None = field(init=False, default=None, repr=False, compare=False)

    def get_raw(self) -> str:
        """Return raw log representation, falling back to JSON-serialized data."""
        if self.raw is not None:
            return self.raw
        if self._raw_cache is None:
            self._raw_cache = json.dumps(self.data)
        return self._raw_cache
