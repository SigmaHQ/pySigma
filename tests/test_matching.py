"""Tests for the sigma.matching module."""

from datetime import datetime, timezone

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
