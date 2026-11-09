from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any

from sigma.matching.match import SigmaMatch


class SlidingWindowState:
    """Manages sliding time window state for correlation rules."""

    def __init__(self, window_seconds: int, max_entries: int | None = None) -> None:
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        # group_key -> deque of (timestamp, match)
        self._state: dict[tuple[Any, ...], deque[tuple[datetime, SigmaMatch]]] = defaultdict(deque)

    def add(self, group_key: tuple[Any, ...], match: SigmaMatch) -> None:
        """Add a match to the state for the given group key."""
        entries = self._state[group_key]
        entries.append((match.timestamp, match))
        if self.max_entries is not None and len(entries) > self.max_entries:
            entries.popleft()

    def get_window(self, group_key: tuple[Any, ...], now: datetime) -> list[SigmaMatch]:
        """Get all matches within the time window for the given group key."""
        self._evict_group(group_key, now)
        return [match for _, match in self._state[group_key]]

    def _evict_group(self, group_key: tuple[Any, ...], now: datetime) -> None:
        """Remove entries outside the time window."""
        entries = self._state[group_key]
        cutoff = now - timedelta(seconds=self.window_seconds)
        while entries and entries[0][0] < cutoff:
            entries.popleft()

    def evict(self) -> None:
        """Remove empty groups."""
        empty_keys = [k for k, v in self._state.items() if not v]
        for k in empty_keys:
            del self._state[k]
