import pytest
from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from .test_conversion_base import test_backend


@pytest.fixture
def event_count_correlation_rule():
    return SigmaCollection.from_yaml(
        """
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons for a single user (possible brute force attack)
status: test
correlation:
    type: event_count
    rules:
        - failed_logon
    group-by:
        - TargetUserName
        - TargetDomainName
    timespan: 5m
    condition:
        gte: 10
            """
    )


def test_event_count_correlation_single_rule_with_grouping(
    test_backend, event_count_correlation_rule
):
    assert test_backend.convert(event_count_correlation_rule) == [
        """EventID=4625
| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName
| where event_count >= 10"""
    ]


@pytest.fixture
def value_count_correlation_rule():
    return SigmaCollection.from_yaml(
        """
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons for diffrerent users (possible password spraying attack)
status: test
correlation:
    type: value_count
    rules:
        - failed_logon
    timespan: 5m
    condition:
        gte: 100
        field: TargetUserName
            """
    )


def test_value_count_correlation_single_rule_without_grouping(
    test_backend, value_count_correlation_rule
):
    assert test_backend.convert(value_count_correlation_rule) == [
        """EventID=4625
| aggregate window=5min value_count(TargetUserName) as value_count
| where value_count >= 100"""
    ]


def test_temporal_correlation_multi_rule_without_condition(test_backend):
    rule_collection = SigmaCollection.from_yaml(
        """
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Successful logon
name: successful_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
---
title: Failed and successful logons for a single user
status: test
correlation:
    type: temporal
    rules:
        - failed_logon
        - successful_logon
    timespan: 5m
    group-by:
        - TargetUserName
        - TargetDomainName
            """
    )
    assert test_backend.convert(rule_collection) == [
        """subsearch { EventID=4625 | set event_type="failed_logon" }
subsearch { EventID=4624 | set event_type="successful_logon" }

| temporal window=5min eventtypes=failed_logon,successful_logon by TargetUserName, TargetDomainName

| where eventtype_count >= 2"""
    ]


def test_temporal_ordered_correlation_multi_rule_with_condition_and_field_normalization(
    test_backend,
):
    rule_collection = SigmaCollection.from_yaml(
        """
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Successful logon
name: successful_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
    condition: selection
---
title: Discovery activity
name: discovery_activity
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - whoami
            - dsquery
            - net group
    condition: selection
---
title: Failed and successful logons for a single user
status: test
correlation:
    type: temporal_ordered
    rules:
        - failed_logon
        - successful_logon
        - discovery_activity
    timespan: 1h
    aliases:
        user:
            failed_logon: TargetUserName
            successful_logon: TargetUserName
            discovery_activity: User
        domain:
            failed_logon: TargetDomainName
            successful_logon: TargetDomainName
            discovery_activity: Domain
    group-by:
        - user
        - domain
    condition:
        gte: 2
            """
    )
    assert test_backend.convert(rule_collection) == [
        """subsearch { EventID=4625 | set event_type="failed_logon" | set user=TargetUserName | set domain=TargetDomainName }
subsearch { EventID=4624 | set event_type="successful_logon" | set user=TargetUserName | set domain=TargetDomainName }
subsearch { CommandLine in ("*whoami*", "*dsquery*", "*net group*") | set event_type="discovery_activity" | set user=User | set domain=Domain }
| temporal ordered=true window=1h eventtypes=failed_logon,successful_logon,discovery_activity by user, domain
| where eventtype_count >= 2 and eventtype_order=failed_logon,successful_logon,discovery_activity"""
    ]


def test_correlation_timespan_in_seconds(monkeypatch, test_backend, event_count_correlation_rule):
    monkeypatch.setattr(test_backend, "timespan_seconds", True)
    assert test_backend.convert(event_count_correlation_rule) == [
        """EventID=4625
| aggregate window=300 count() as event_count by TargetUserName, TargetDomainName
| where event_count >= 10"""
    ]


def test_correlation_no_aggregation_expression(
    monkeypatch, test_backend, value_count_correlation_rule
):
    monkeypatch.setattr(test_backend, "groupby_expression_nofield", {"test": " by nothing"})
    assert test_backend.convert(value_count_correlation_rule) == [
        """EventID=4625
| aggregate window=5min value_count(TargetUserName) as value_count by nothing
| where value_count >= 100"""
    ]


def test_correlation_generate_rule(test_backend):
    rule_collection = SigmaCollection.from_yaml(
        """
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons for a single user (possible brute force attack)
status: test
correlation:
    type: event_count
    rules:
        - failed_logon
    generate: true
    group-by:
        - TargetUserName
        - TargetDomainName
    timespan: 5m
    condition:
        gte: 10
            """
    )
    assert test_backend.convert(rule_collection) == [
        "EventID=4625",
        """EventID=4625
| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName
| where event_count >= 10""",
    ]
