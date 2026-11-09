"""Tests for the sigma.matching module."""

from datetime import datetime, timedelta, timezone

import pytest

from sigma.collection import SigmaCollection
from sigma.matching import Event, EventLogSource, SigmaMatch, SigmaMatcher


@pytest.fixture
def simple_rule_yaml():
    return """
title: Test Rule
name: test_rule
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "mimikatz"
    condition: selection
"""


@pytest.fixture
def simple_collection(simple_rule_yaml):
    return SigmaCollection.from_yaml(simple_rule_yaml)


class TestEvent:
    def test_event_creation(self):
        event = Event(
            timestamp=datetime.now(tz=timezone.utc),
            logsource=EventLogSource(category="process_creation", product="windows"),
            data={"CommandLine": "mimikatz.exe"},
        )
        assert event.data["CommandLine"] == "mimikatz.exe"

    def test_event_get_raw_with_raw(self):
        event = Event(
            timestamp=datetime.now(tz=timezone.utc),
            logsource=EventLogSource(),
            data={"key": "val"},
            raw="raw log line",
        )
        assert event.get_raw() == "raw log line"

    def test_event_get_raw_without_raw(self):
        event = Event(
            timestamp=datetime.now(tz=timezone.utc),
            logsource=EventLogSource(),
            data={"key": "val"},
        )
        assert '"key"' in event.get_raw()


class TestSigmaMatcher:
    def test_basic_match(self, simple_collection):
        with SigmaMatcher(simple_collection) as matcher:
            event = Event(
                timestamp=datetime.now(tz=timezone.utc),
                logsource=EventLogSource(category="process_creation", product="windows"),
                data={"CommandLine": "C:\\tools\\mimikatz.exe"},
            )
            matches = matcher.match(event)
            assert len(matches) == 1
            assert matches[0].rule.name == "test_rule"

    def test_no_match(self, simple_collection):
        with SigmaMatcher(simple_collection) as matcher:
            event = Event(
                timestamp=datetime.now(tz=timezone.utc),
                logsource=EventLogSource(category="process_creation", product="windows"),
                data={"CommandLine": "notepad.exe"},
            )
            matches = matcher.match(event)
            assert len(matches) == 0

    def test_logsource_mismatch(self, simple_collection):
        with SigmaMatcher(simple_collection) as matcher:
            event = Event(
                timestamp=datetime.now(tz=timezone.utc),
                logsource=EventLogSource(category="network_connection", product="windows"),
                data={"CommandLine": "mimikatz.exe"},
            )
            matches = matcher.match(event)
            assert len(matches) == 0

    def test_bulk_match(self, simple_collection):
        with SigmaMatcher(simple_collection) as matcher:
            events = [
                Event(
                    timestamp=datetime.now(tz=timezone.utc),
                    logsource=EventLogSource(category="process_creation", product="windows"),
                    data={"CommandLine": "mimikatz.exe"},
                ),
                Event(
                    timestamp=datetime.now(tz=timezone.utc),
                    logsource=EventLogSource(category="process_creation", product="windows"),
                    data={"CommandLine": "notepad.exe"},
                ),
            ]
            matches = matcher.bulk_match(events)
            assert len(matches) == 1


class TestCompilerTypes:
    """Test various Sigma types compile correctly."""

    def _match(self, yaml_str: str, data: dict, logsource: EventLogSource | None = None):
        collection = SigmaCollection.from_yaml(yaml_str)
        ls = logsource or EventLogSource(category="test", product="test")
        with SigmaMatcher(collection) as matcher:
            event = Event(
                timestamp=datetime.now(tz=timezone.utc),
                logsource=ls,
                data=data,
            )
            return matcher.match(event)

    def test_plain_string(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field: "value"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "value"})) == 1
        assert len(self._match(yaml_str, {"field": "VALUE"})) == 1  # case insensitive
        assert len(self._match(yaml_str, {"field": "other"})) == 0

    def test_wildcard(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|contains: "test"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "this is a test string"})) == 1
        assert len(self._match(yaml_str, {"field": "no match here"})) == 0

    def test_number(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field: 42
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": 42})) == 1
        assert len(self._match(yaml_str, {"field": 43})) == 0

    def test_null(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field: null
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": None})) == 1
        assert len(self._match(yaml_str, {"other": "val"})) == 1  # field not present = None
        assert len(self._match(yaml_str, {"field": "something"})) == 0

    def test_boolean(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field: true
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": True})) == 1
        assert len(self._match(yaml_str, {"field": False})) == 0

    def test_regex(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|re: "^test\\\\d+"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "test123"})) == 1
        assert len(self._match(yaml_str, {"field": "notest"})) == 0

    def test_cidr(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|cidr: "192.168.1.0/24"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "192.168.1.50"})) == 1
        assert len(self._match(yaml_str, {"field": "10.0.0.1"})) == 0

    def test_compare_gt(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|gt: 10
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": 15})) == 1
        assert len(self._match(yaml_str, {"field": 5})) == 0

    def test_condition_and(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    sel1:
        field1: "a"
    sel2:
        field2: "b"
    condition: sel1 and sel2
"""
        assert len(self._match(yaml_str, {"field1": "a", "field2": "b"})) == 1
        assert len(self._match(yaml_str, {"field1": "a", "field2": "c"})) == 0

    def test_condition_or(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    sel1:
        field1: "a"
    sel2:
        field2: "b"
    condition: sel1 or sel2
"""
        assert len(self._match(yaml_str, {"field1": "a"})) == 1
        assert len(self._match(yaml_str, {"field2": "b"})) == 1
        assert len(self._match(yaml_str, {"field3": "c"})) == 0

    def test_condition_not(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    sel:
        field: "a"
    condition: not sel
"""
        assert len(self._match(yaml_str, {"field": "b"})) == 1
        assert len(self._match(yaml_str, {"field": "a"})) == 0

    def test_keyword(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    keywords:
        - "suspicious"
    condition: keywords
"""
        assert len(self._match(yaml_str, {"msg": "this is suspicious activity"})) == 1
        assert len(self._match(yaml_str, {"msg": "normal activity"})) == 0


class TestCorrelation:
    def test_event_count(self):
        yaml_str = """
title: Base Rule
name: base_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field: "trigger"
    condition: selection
---
title: Correlation
name: correlation_rule
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - src_ip
    timespan: 5m
    condition:
        gte: 3
"""
        collection = SigmaCollection.from_yaml(yaml_str)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            ls = EventLogSource(category="test", product="test")

            # First two events - no correlation match yet
            for i in range(2):
                matches = matcher.match(
                    Event(
                        timestamp=now, logsource=ls, data={"field": "trigger", "src_ip": "1.2.3.4"}
                    )
                )
                # Should have base rule match but no correlation yet
                assert any(m.rule.name == "base_rule" for m in matches)
                assert not any(m.rule.name == "correlation_rule" for m in matches)

            # Third event triggers correlation
            matches = matcher.match(
                Event(timestamp=now, logsource=ls, data={"field": "trigger", "src_ip": "1.2.3.4"})
            )
            assert any(m.rule.name == "correlation_rule" for m in matches)

    def test_value_count(self):
        yaml_str = """
title: Base Rule
name: base_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: "login"
    condition: selection
---
title: Value Count Correlation
name: vc_corr
status: test
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - src_ip
    timespan: 5m
    condition:
        gte: 3
        field: user
"""
        collection = SigmaCollection.from_yaml(yaml_str)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            ls = EventLogSource(category="test", product="test")

            # Two distinct users – no correlation yet
            for user in ("alice", "bob"):
                matches = matcher.match(
                    Event(
                        timestamp=now,
                        logsource=ls,
                        data={"event": "login", "src_ip": "1.2.3.4", "user": user},
                    )
                )
                assert any(m.rule.name == "base_rule" for m in matches)
                assert not any(m.rule.name == "vc_corr" for m in matches)

            # Duplicate user does not increase distinct count
            matches = matcher.match(
                Event(
                    timestamp=now,
                    logsource=ls,
                    data={"event": "login", "src_ip": "1.2.3.4", "user": "alice"},
                )
            )
            assert not any(m.rule.name == "vc_corr" for m in matches)

            # Third distinct user triggers correlation
            matches = matcher.match(
                Event(
                    timestamp=now,
                    logsource=ls,
                    data={"event": "login", "src_ip": "1.2.3.4", "user": "charlie"},
                )
            )
            assert any(m.rule.name == "vc_corr" for m in matches)

    def test_temporal(self):
        yaml_str = """
title: Login Rule
name: login_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: "login"
    condition: selection
---
title: Access Rule
name: access_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: "access"
    condition: selection
---
title: Temporal Correlation
name: temporal_corr
status: test
correlation:
    type: temporal
    rules:
        - login_rule
        - access_rule
    group-by:
        - user
    timespan: 5m
"""
        collection = SigmaCollection.from_yaml(yaml_str)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            ls = EventLogSource(category="test", product="test")

            # Only login fires for bob – no temporal match
            matches = matcher.match(
                Event(timestamp=now, logsource=ls, data={"event": "login", "user": "bob"})
            )
            assert any(m.rule.name == "login_rule" for m in matches)
            assert not any(m.rule.name == "temporal_corr" for m in matches)

            # Both rules fire for alice within the window – temporal match fires
            matcher.match(
                Event(timestamp=now, logsource=ls, data={"event": "login", "user": "alice"})
            )
            matches = matcher.match(
                Event(timestamp=now, logsource=ls, data={"event": "access", "user": "alice"})
            )
            assert any(m.rule.name == "access_rule" for m in matches)
            assert any(m.rule.name == "temporal_corr" for m in matches)

    def test_temporal_ordered(self):
        yaml_str = """
title: Login Rule
name: login_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: "login"
    condition: selection
---
title: Access Rule
name: access_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: "access"
    condition: selection
---
title: Ordered Temporal Correlation
name: ordered_corr
status: test
correlation:
    type: temporal_ordered
    rules:
        - login_rule
        - access_rule
    group-by:
        - user
    timespan: 5m
"""
        collection = SigmaCollection.from_yaml(yaml_str)
        t1 = datetime.now(tz=timezone.utc)
        t2 = t1 + timedelta(seconds=30)
        ls = EventLogSource(category="test", product="test")

        with SigmaMatcher(collection) as matcher:
            # Correct order for alice: login then access
            matcher.match(
                Event(timestamp=t1, logsource=ls, data={"event": "login", "user": "alice"})
            )
            matches = matcher.match(
                Event(timestamp=t2, logsource=ls, data={"event": "access", "user": "alice"})
            )
            assert any(m.rule.name == "ordered_corr" for m in matches)

        with SigmaMatcher(collection) as matcher:
            # Wrong order for bob: access then login – should not fire
            matcher.match(
                Event(timestamp=t1, logsource=ls, data={"event": "access", "user": "bob"})
            )
            matches = matcher.match(
                Event(timestamp=t2, logsource=ls, data={"event": "login", "user": "bob"})
            )
            assert not any(m.rule.name == "ordered_corr" for m in matches)

    def test_value_sum(self):
        yaml_str = """
title: Base Rule
name: base_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: "transfer"
    condition: selection
---
title: Value Sum Correlation
name: vs_corr
status: test
correlation:
    type: value_sum
    rules:
        - base_rule
    group-by:
        - src_ip
    timespan: 5m
    condition:
        gte: 100
        field: bytes
"""
        collection = SigmaCollection.from_yaml(yaml_str)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            ls = EventLogSource(category="test", product="test")

            for bytes_val in (40, 40):
                matches = matcher.match(
                    Event(
                        timestamp=now,
                        logsource=ls,
                        data={"event": "transfer", "src_ip": "1.2.3.4", "bytes": bytes_val},
                    )
                )
                assert not any(m.rule.name == "vs_corr" for m in matches)

            # Sum reaches 110 >= 100
            matches = matcher.match(
                Event(
                    timestamp=now,
                    logsource=ls,
                    data={"event": "transfer", "src_ip": "1.2.3.4", "bytes": 30},
                )
            )
            assert any(m.rule.name == "vs_corr" for m in matches)

    def test_value_avg(self):
        yaml_str = """
title: Base Rule
name: base_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: "metric"
    condition: selection
---
title: Value Avg Correlation
name: avg_corr
status: test
correlation:
    type: value_avg
    rules:
        - base_rule
    group-by:
        - host
    timespan: 5m
    condition:
        gte: 20
        field: value
"""
        collection = SigmaCollection.from_yaml(yaml_str)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            ls = EventLogSource(category="test", product="test")

            for val in (5, 5):
                matches = matcher.match(
                    Event(
                        timestamp=now,
                        logsource=ls,
                        data={"event": "metric", "host": "srv1", "value": val},
                    )
                )
                assert not any(m.rule.name == "avg_corr" for m in matches)

            # Average becomes (5+5+50)/3 = 20 >= 20
            matches = matcher.match(
                Event(
                    timestamp=now,
                    logsource=ls,
                    data={"event": "metric", "host": "srv1", "value": 50},
                )
            )
            assert any(m.rule.name == "avg_corr" for m in matches)

    def test_value_median(self):
        yaml_str = """
title: Base Rule
name: base_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: "metric"
    condition: selection
---
title: Value Median Correlation
name: med_corr
status: test
correlation:
    type: value_median
    rules:
        - base_rule
    group-by:
        - host
    timespan: 5m
    condition:
        gte: 30
        field: value
"""
        collection = SigmaCollection.from_yaml(yaml_str)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            ls = EventLogSource(category="test", product="test")

            for val in (10, 40):
                matches = matcher.match(
                    Event(
                        timestamp=now,
                        logsource=ls,
                        data={"event": "metric", "host": "srv1", "value": val},
                    )
                )
                assert not any(m.rule.name == "med_corr" for m in matches)

            # Median of [10, 30, 40] = 30 >= 30
            matches = matcher.match(
                Event(
                    timestamp=now,
                    logsource=ls,
                    data={"event": "metric", "host": "srv1", "value": 30},
                )
            )
            assert any(m.rule.name == "med_corr" for m in matches)

    def test_value_percentile(self):
        yaml_str = """
title: Base Rule
name: base_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: "metric"
    condition: selection
---
title: Value Percentile Correlation
name: pct_corr
status: test
correlation:
    type: value_percentile
    rules:
        - base_rule
    group-by:
        - host
    timespan: 5m
    condition:
        gte: 40
        field: value
        percentile: 90
"""
        collection = SigmaCollection.from_yaml(yaml_str)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            ls = EventLogSource(category="test", product="test")

            for val in (10, 20, 30):
                matches = matcher.match(
                    Event(
                        timestamp=now,
                        logsource=ls,
                        data={"event": "metric", "host": "srv1", "value": val},
                    )
                )
                assert not any(m.rule.name == "pct_corr" for m in matches)

            # 90th percentile of [10,20,30,40]: idx=int(4*0.9)=3, val=40 >= 40
            matches = matcher.match(
                Event(
                    timestamp=now,
                    logsource=ls,
                    data={"event": "metric", "host": "srv1", "value": 40},
                )
            )
            assert any(m.rule.name == "pct_corr" for m in matches)


class TestExtendedCorrelation:
    """Test extended correlation conditions with boolean expressions."""

    _BASE_RULES = """
title: Failed Logon
name: failed_logon
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: "failed_logon"
    condition: selection
---
title: Successful Logon
name: successful_logon
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: "successful_logon"
    condition: selection
---
title: Suspicious Activity
name: suspicious_activity
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: "suspicious"
    condition: selection
"""

    def _make_collection(self, correlation_yaml: str) -> SigmaCollection:
        return SigmaCollection.from_yaml(self._BASE_RULES + "---\n" + correlation_yaml)

    def _fire(
        self,
        matcher: SigmaMatcher,
        event_type: str,
        user: str = "alice",
        ts: datetime | None = None,
    ) -> list[SigmaMatch]:
        return matcher.match(
            Event(
                timestamp=ts or datetime.now(tz=timezone.utc),
                logsource=EventLogSource(category="test", product="test"),
                data={"event": event_type, "user": user},
            )
        )

    def test_and_both_fire(self):
        """Extended AND: both rules must fire to produce a correlation match."""
        yaml = """
title: Extended AND Correlation
name: ext_and_corr
status: test
correlation:
    type: temporal
    condition: failed_logon and successful_logon
    timespan: 5m
    group-by:
        - user
"""
        collection = self._make_collection(yaml)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            self._fire(matcher, "failed_logon", ts=now)
            matches = self._fire(matcher, "successful_logon", ts=now)
            assert any(m.rule.name == "ext_and_corr" for m in matches)

    def test_and_only_one_fires(self):
        """Extended AND: only one rule fires — no correlation match."""
        yaml = """
title: Extended AND Correlation
name: ext_and_corr
status: test
correlation:
    type: temporal
    condition: failed_logon and successful_logon
    timespan: 5m
    group-by:
        - user
"""
        collection = self._make_collection(yaml)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            matches = self._fire(matcher, "failed_logon", ts=now)
            assert not any(m.rule.name == "ext_and_corr" for m in matches)

    def test_or_first_fires(self):
        """Extended OR: firing any referenced rule triggers a correlation match."""
        yaml = """
title: Extended OR Correlation
name: ext_or_corr
status: test
correlation:
    type: temporal
    condition: failed_logon or suspicious_activity
    timespan: 5m
    group-by:
        - user
"""
        collection = self._make_collection(yaml)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            matches = self._fire(matcher, "failed_logon", ts=now)
            assert any(m.rule.name == "ext_or_corr" for m in matches)

    def test_or_second_fires(self):
        """Extended OR: the second alternative also triggers a match."""
        yaml = """
title: Extended OR Correlation
name: ext_or_corr
status: test
correlation:
    type: temporal
    condition: failed_logon or suspicious_activity
    timespan: 5m
    group-by:
        - user
"""
        collection = self._make_collection(yaml)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            matches = self._fire(matcher, "suspicious", ts=now)
            assert any(m.rule.name == "ext_or_corr" for m in matches)

    def test_or_neither_fires(self):
        """Extended OR: no matching event → no correlation match."""
        yaml = """
title: Extended OR Correlation
name: ext_or_corr
status: test
correlation:
    type: temporal
    condition: failed_logon or suspicious_activity
    timespan: 5m
    group-by:
        - user
"""
        collection = self._make_collection(yaml)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            matches = self._fire(matcher, "successful_logon", ts=now)
            assert not any(m.rule.name == "ext_or_corr" for m in matches)

    def test_not_excluded_rule_absent(self):
        """Extended NOT: trigger rule fires without the excluded rule → match."""
        yaml = """
title: Extended NOT Correlation
name: ext_not_corr
status: test
correlation:
    type: temporal
    condition: failed_logon and not successful_logon
    timespan: 5m
    group-by:
        - user
"""
        collection = self._make_collection(yaml)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            matches = self._fire(matcher, "failed_logon", ts=now)
            assert any(m.rule.name == "ext_not_corr" for m in matches)

    def test_not_excluded_rule_present(self):
        """Extended NOT: excluded rule fires within window → no match."""
        yaml = """
title: Extended NOT Correlation
name: ext_not_corr
status: test
correlation:
    type: temporal
    condition: failed_logon and not successful_logon
    timespan: 5m
    group-by:
        - user
"""
        collection = self._make_collection(yaml)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            self._fire(matcher, "failed_logon", ts=now)
            matches = self._fire(matcher, "successful_logon", ts=now)
            assert not any(m.rule.name == "ext_not_corr" for m in matches)

    def test_ordered_correct_order(self):
        """Extended temporal_ordered AND: rules in correct order → match."""
        yaml = """
title: Extended Ordered Correlation
name: ext_ordered_corr
status: test
correlation:
    type: temporal_ordered
    condition: failed_logon and successful_logon
    timespan: 5m
    group-by:
        - user
"""
        collection = self._make_collection(yaml)
        t1 = datetime.now(tz=timezone.utc)
        t2 = t1 + timedelta(seconds=30)
        with SigmaMatcher(collection) as matcher:
            self._fire(matcher, "failed_logon", ts=t1)
            matches = self._fire(matcher, "successful_logon", ts=t2)
            assert any(m.rule.name == "ext_ordered_corr" for m in matches)

    def test_ordered_wrong_order(self):
        """Extended temporal_ordered AND: rules in wrong order → no match."""
        yaml = """
title: Extended Ordered Correlation
name: ext_ordered_corr
status: test
correlation:
    type: temporal_ordered
    condition: failed_logon and successful_logon
    timespan: 5m
    group-by:
        - user
"""
        collection = self._make_collection(yaml)
        t1 = datetime.now(tz=timezone.utc)
        t2 = t1 + timedelta(seconds=30)
        with SigmaMatcher(collection) as matcher:
            self._fire(matcher, "successful_logon", ts=t1)
            matches = self._fire(matcher, "failed_logon", ts=t2)
            assert not any(m.rule.name == "ext_ordered_corr" for m in matches)

    def test_ordered_three_rules_correct_order(self):
        """Extended temporal_ordered: three rules all fire in correct sequence."""
        yaml = """
title: Extended Ordered 3 Correlation
name: ext_ordered3_corr
status: test
correlation:
    type: temporal_ordered
    condition: failed_logon and successful_logon and suspicious_activity
    timespan: 5m
    group-by:
        - user
"""
        collection = self._make_collection(yaml)
        t1 = datetime.now(tz=timezone.utc)
        t2 = t1 + timedelta(seconds=10)
        t3 = t2 + timedelta(seconds=10)
        with SigmaMatcher(collection) as matcher:
            self._fire(matcher, "failed_logon", ts=t1)
            self._fire(matcher, "successful_logon", ts=t2)
            matches = self._fire(matcher, "suspicious", ts=t3)
            assert any(m.rule.name == "ext_ordered3_corr" for m in matches)

    def test_ordered_three_rules_wrong_order(self):
        """Extended temporal_ordered: middle rule fires last → no match."""
        yaml = """
title: Extended Ordered 3 Correlation
name: ext_ordered3_corr
status: test
correlation:
    type: temporal_ordered
    condition: failed_logon and successful_logon and suspicious_activity
    timespan: 5m
    group-by:
        - user
"""
        collection = self._make_collection(yaml)
        t1 = datetime.now(tz=timezone.utc)
        t2 = t1 + timedelta(seconds=10)
        t3 = t2 + timedelta(seconds=10)
        with SigmaMatcher(collection) as matcher:
            self._fire(matcher, "failed_logon", ts=t1)
            self._fire(matcher, "suspicious", ts=t2)
            matches = self._fire(matcher, "successful_logon", ts=t3)
            assert not any(m.rule.name == "ext_ordered3_corr" for m in matches)

    def test_group_by_isolation(self):
        """Extended AND: group-by keeps user windows separate."""
        yaml = """
title: Extended AND Correlation
name: ext_and_corr
status: test
correlation:
    type: temporal
    condition: failed_logon and successful_logon
    timespan: 5m
    group-by:
        - user
"""
        collection = self._make_collection(yaml)
        with SigmaMatcher(collection) as matcher:
            now = datetime.now(tz=timezone.utc)
            # failed_logon for alice, successful_logon for bob — different groups
            self._fire(matcher, "failed_logon", user="alice", ts=now)
            matches = self._fire(matcher, "successful_logon", user="bob", ts=now)
            assert not any(m.rule.name == "ext_and_corr" for m in matches)


class TestModifiers:
    """Test that all Sigma modifiers produce correct matching behavior end-to-end."""

    def _match(self, yaml_str: str, data: dict, logsource: EventLogSource | None = None):
        collection = SigmaCollection.from_yaml(yaml_str)
        ls = logsource or EventLogSource(category="test", product="test")
        with SigmaMatcher(collection) as matcher:
            event = Event(
                timestamp=datetime.now(tz=timezone.utc),
                logsource=ls,
                data=data,
            )
            return matcher.match(event)

    def test_startswith(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|startswith: "cmd"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "cmd.exe /c dir"})) == 1
        assert len(self._match(yaml_str, {"field": "CMD.exe"})) == 1  # case-insensitive
        assert len(self._match(yaml_str, {"field": "not cmd"})) == 0

    def test_endswith(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|endswith: ".exe"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "cmd.exe"})) == 1
        assert len(self._match(yaml_str, {"field": "CMD.EXE"})) == 1  # case-insensitive
        assert len(self._match(yaml_str, {"field": "cmd.bat"})) == 0

    def test_base64(self):
        # base64("foobar") == "Zm9vYmFy"
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|base64: "foobar"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "Zm9vYmFy"})) == 1
        assert len(self._match(yaml_str, {"field": "zm9vymfy"})) == 1  # case-insensitive
        assert len(self._match(yaml_str, {"field": "foobar"})) == 0  # raw value does not match
        assert len(self._match(yaml_str, {"field": "other"})) == 0

    def test_base64offset(self):
        # base64offset("foobar") == ["Zm9vYmFy", "Zvb2Jhc", "mb29iYX"]
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|base64offset: "foobar"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "Zm9vYmFy"})) == 1  # offset 0
        assert len(self._match(yaml_str, {"field": "Zvb2Jhc"})) == 1  # offset 1
        assert len(self._match(yaml_str, {"field": "mb29iYX"})) == 1  # offset 2
        assert len(self._match(yaml_str, {"field": "foobar"})) == 0
        assert len(self._match(yaml_str, {"field": "other"})) == 0

    def test_wide(self):
        # wide("cmd") encodes each ASCII char as two bytes (UTF-16LE), resulting in "c\x00m\x00d\x00"
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|wide: "cmd"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "c\x00m\x00d\x00"})) == 1
        assert len(self._match(yaml_str, {"field": "cmd"})) == 0  # not wide-encoded
        assert len(self._match(yaml_str, {"field": "other"})) == 0

    def test_utf16be(self):
        # utf16be("ab") == "\x00a\x00b" (big-endian null-prefixed pairs)
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|utf16be: "ab"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "\x00a\x00b"})) == 1
        assert len(self._match(yaml_str, {"field": "ab"})) == 0
        assert len(self._match(yaml_str, {"field": "other"})) == 0

    def test_utf16(self):
        # utf16("ab") == "\ufeffa\x00b\x00" (BOM + UTF-16LE pairs)
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|utf16: "ab"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "\ufeffa\x00b\x00"})) == 1
        assert len(self._match(yaml_str, {"field": "ab"})) == 0
        assert len(self._match(yaml_str, {"field": "other"})) == 0

    def test_windash(self):
        # windash expands the leading "-" to "-", "/", en-dash, em-dash, horizontal bar
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|windash: "-cmd"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "-cmd"})) == 1
        assert len(self._match(yaml_str, {"field": "/cmd"})) == 1  # slash variant
        assert len(self._match(yaml_str, {"field": "\u2013cmd"})) == 1  # en-dash variant
        assert len(self._match(yaml_str, {"field": "other"})) == 0

    def test_all_modifier(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|contains|all:
            - "word1"
            - "word2"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "word1 and word2 here"})) == 1
        assert len(self._match(yaml_str, {"field": "only word1"})) == 0
        assert len(self._match(yaml_str, {"field": "only word2"})) == 0
        assert len(self._match(yaml_str, {"field": "neither"})) == 0

    def test_negate_modifier(self):
        # |neq wraps the detection item in NOT
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|neq: "blocked"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "allowed"})) == 1
        assert len(self._match(yaml_str, {"field": "blocked"})) == 0

    def test_compare_lt(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|lt: 10
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": 5})) == 1
        assert len(self._match(yaml_str, {"field": 10})) == 0
        assert len(self._match(yaml_str, {"field": 15})) == 0

    def test_compare_lte(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|lte: 10
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": 5})) == 1
        assert len(self._match(yaml_str, {"field": 10})) == 1
        assert len(self._match(yaml_str, {"field": 15})) == 0

    def test_compare_gte(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|gte: 10
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": 15})) == 1
        assert len(self._match(yaml_str, {"field": 10})) == 1
        assert len(self._match(yaml_str, {"field": 5})) == 0

    def test_cased(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|cased: "CasedValue"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "CasedValue"})) == 1
        assert len(self._match(yaml_str, {"field": "casedvalue"})) == 0  # case-sensitive mismatch
        assert len(self._match(yaml_str, {"field": "CASEDVALUE"})) == 0

    def test_exists_true(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|exists: true
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "anything"})) == 1
        assert len(self._match(yaml_str, {"field": None})) == 1  # key present, value null
        assert len(self._match(yaml_str, {"other": "val"})) == 0  # key absent

    def test_exists_false(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|exists: false
    condition: selection
"""
        assert len(self._match(yaml_str, {"other": "val"})) == 1  # field absent
        assert len(self._match(yaml_str, {"field": "anything"})) == 0  # field present

    def test_fieldref(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field1|fieldref: "field2"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field1": "abc", "field2": "abc"})) == 1
        assert len(self._match(yaml_str, {"field1": "abc", "field2": "def"})) == 0

    def test_fieldref_contains(self):
        # field1 must contain the value of field2
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field1|fieldref|contains: "field2"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field1": "abcdef", "field2": "abc"})) == 1
        assert len(self._match(yaml_str, {"field1": "abc", "field2": "abcdef"})) == 0

    def test_re_ignorecase(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|re|i: "^pattern$"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "pattern"})) == 1
        assert len(self._match(yaml_str, {"field": "PATTERN"})) == 1  # case-insensitive
        assert len(self._match(yaml_str, {"field": "other"})) == 0

    def test_re_multiline(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|re|m: "^test$"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "prefix\ntest\nsuffix"})) == 1
        assert len(self._match(yaml_str, {"field": "prefix\nsuffix"})) == 0

    def test_re_dotall(self):
        yaml_str = """
title: Test
name: test
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        field|re|s: "test.data"
    condition: selection
"""
        assert len(self._match(yaml_str, {"field": "test\ndata"})) == 1  # dot matches newline
        assert len(self._match(yaml_str, {"field": "testXdata"})) == 1
        assert len(self._match(yaml_str, {"field": "no match"})) == 0
