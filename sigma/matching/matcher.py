from __future__ import annotations

import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Iterable

from typing_extensions import Self

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.matching.compiler import MatchCompiler
from sigma.matching.correlation_matcher import SigmaCorrelationRuleMatcher
from sigma.matching.event import Event, EventLogSource
from sigma.matching.match import SigmaMatch
from sigma.matching.rule_matcher import SigmaRuleMatcher
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule.logsource import SigmaLogSource
from sigma.rule.rule import SigmaRule


class SigmaMatcher:
    """
    Orchestrator that matches events against a collection of Sigma rules.

    Manages logsource dispatch, threading, and correlation.
    """

    def __init__(
        self,
        collection: SigmaCollection,
        pipeline: ProcessingPipeline | None = None,
        max_workers: int | None = None,
        max_events_per_match: int | None = 100,
        max_correlation_state: int | None = None,
    ) -> None:
        self._compiler = MatchCompiler()
        self._max_workers = max_workers or os.cpu_count() or 4
        self._executor = ThreadPoolExecutor(max_workers=self._max_workers)

        # Apply pipeline if provided
        if pipeline is not None:
            pipeline.apply(collection)

        # Build dispatch table and correlation matchers
        self._dispatch: dict[tuple[str | None, str | None, str | None], list[SigmaRuleMatcher]] = (
            defaultdict(list)
        )
        self._all_rule_matchers: list[SigmaRuleMatcher] = []
        # Map rule name -> list of correlation matchers that reference it
        self._correlation_map: dict[str, list[SigmaCorrelationRuleMatcher]] = defaultdict(list)
        self._correlation_matchers: list[SigmaCorrelationRuleMatcher] = []

        for rule in collection.rules:
            if isinstance(rule, SigmaRule):
                rm = SigmaRuleMatcher(rule, self._compiler)
                self._all_rule_matchers.append(rm)
                key = (
                    rule.logsource.category,
                    rule.logsource.product,
                    rule.logsource.service,
                )
                self._dispatch[key].append(rm)
            elif isinstance(rule, SigmaCorrelationRule):
                cm = SigmaCorrelationRuleMatcher(
                    rule,
                    max_state=max_correlation_state,
                    max_events_per_match=max_events_per_match,
                )
                self._correlation_matchers.append(cm)
                if rule.rules:
                    for ref in rule.rules:
                        self._correlation_map[ref.reference].append(cm)

    def match(self, event: Event) -> list[SigmaMatch]:
        """Match a single event against all relevant rules. Returns list of matches."""
        matchers = self._get_matchers(event.logsource)
        matches: list[SigmaMatch] = []

        for rm in matchers:
            result = rm.matches(event)
            if result is not None:
                matches.append(result)

        # Route matches to correlation matchers
        correlation_matches: list[SigmaMatch] = []
        for m in matches:
            rule_name = getattr(m.rule, "name", None)
            if rule_name and rule_name in self._correlation_map:
                for cm in self._correlation_map[rule_name]:
                    correlation_matches.extend(cm.receive_match(m, rule_name))

        matches.extend(correlation_matches)
        return matches

    def bulk_match(self, events: Iterable[Event]) -> list[SigmaMatch]:
        """Match multiple events, returning all matches. Processes sequentially for ordering."""
        all_matches: list[SigmaMatch] = []
        for event in events:
            all_matches.extend(self.match(event))
        return all_matches

    def _get_matchers(self, logsource: EventLogSource) -> list[SigmaRuleMatcher]:
        """Get all rule matchers whose logsource contains the event's logsource."""
        result: list[SigmaRuleMatcher] = []
        event_ls = SigmaLogSource(
            category=logsource.category,
            product=logsource.product,
            service=logsource.service,
        )
        for key, matchers in self._dispatch.items():
            rule_ls = SigmaLogSource(
                category=key[0],
                product=key[1],
                service=key[2],
            )
            if event_ls in rule_ls:
                result.extend(matchers)
        return result

    def close(self) -> None:
        """Shut down the thread pool."""
        self._executor.shutdown(wait=False)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
