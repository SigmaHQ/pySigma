"""Tests for extended correlation condition conversion to target query language."""

import pytest
from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection


@pytest.fixture
def test_backend():
    return TextQueryTestBackend()


@pytest.fixture
def extended_temporal_correlation_simple_and():
    return SigmaCollection.from_yaml("""
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
    condition: failed_logon and successful_logon
    timespan: 5m
    group-by:
        - TargetUserName
        """)


@pytest.fixture
def extended_temporal_correlation_simple_or():
    return SigmaCollection.from_yaml("""
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
title: Suspicious logon
name: suspicious_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4648
    condition: selection
---
title: Either failed or suspicious logon for a single user
status: test
correlation:
    type: temporal
    condition: failed_logon or suspicious_logon
    timespan: 5m
    group-by:
        - TargetUserName
        """)


@pytest.fixture
def extended_temporal_correlation_simple_not():
    return SigmaCollection.from_yaml("""
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
title: Failed logon but not successful
status: test
correlation:
    type: temporal
    condition: failed_logon and not successful_logon
    timespan: 5m
    group-by:
        - TargetUserName
        """)


@pytest.fixture
def extended_temporal_correlation_complex():
    return SigmaCollection.from_yaml("""
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
title: Suspicious logon
name: suspicious_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4648
    condition: selection
---
title: Account lockout
name: account_lockout
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4740
    condition: selection
---
title: Complex correlation condition
status: test
correlation:
    type: temporal
    condition: (failed_logon or suspicious_logon) and not (successful_logon or account_lockout)
    timespan: 5m
    group-by:
        - TargetUserName
        """)


@pytest.fixture
def extended_temporal_ordered_correlation():
    return SigmaCollection.from_yaml("""
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
title: Administrative action
name: admin_action
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4672
    condition: selection
---
title: Failed then successful logon then admin action
status: test
correlation:
    type: temporal_ordered
    condition: failed_logon and successful_logon and admin_action
    timespan: 10m
    group-by:
        - TargetUserName
        """)


def test_extended_temporal_correlation_simple_and(
    test_backend, extended_temporal_correlation_simple_and
):
    """Test conversion of simple AND condition in extended temporal correlation."""
    result = test_backend.convert(extended_temporal_correlation_simple_and)
    assert result == ["""subsearch { EventID=4625 | set event_type="failed_logon" }
subsearch { EventID=4624 | set event_type="successful_logon" }

| temporal extended=true window=5min by TargetUserName

| where matched_rules="failed_logon" and matched_rules="successful_logon\""""]


def test_extended_temporal_correlation_simple_or(
    test_backend, extended_temporal_correlation_simple_or
):
    """Test conversion of simple OR condition in extended temporal correlation."""
    result = test_backend.convert(extended_temporal_correlation_simple_or)
    assert result == ["""subsearch { EventID=4625 | set event_type="failed_logon" }
subsearch { EventID=4648 | set event_type="suspicious_logon" }

| temporal extended=true window=5min by TargetUserName

| where matched_rules="failed_logon" or matched_rules="suspicious_logon\""""]


def test_extended_temporal_correlation_simple_not(
    test_backend, extended_temporal_correlation_simple_not
):
    """Test conversion of simple NOT condition in extended temporal correlation."""
    result = test_backend.convert(extended_temporal_correlation_simple_not)
    assert result == ["""subsearch { EventID=4625 | set event_type="failed_logon" }
subsearch { EventID=4624 | set event_type="successful_logon" }

| temporal extended=true window=5min by TargetUserName

| where matched_rules="failed_logon" and not matched_rules="successful_logon\""""]


def test_extended_temporal_correlation_complex(test_backend, extended_temporal_correlation_complex):
    """Test conversion of complex nested condition in extended temporal correlation."""
    result = test_backend.convert(extended_temporal_correlation_complex)
    assert result == [
        """subsearch { EventID=4625 | set event_type="failed_logon" }
subsearch { EventID=4648 | set event_type="suspicious_logon" }
subsearch { EventID=4624 | set event_type="successful_logon" }
subsearch { EventID=4740 | set event_type="account_lockout" }

| temporal extended=true window=5min by TargetUserName

| where (matched_rules="failed_logon" or matched_rules="suspicious_logon") and not (matched_rules="successful_logon" or matched_rules="account_lockout")"""
    ]


def test_extended_temporal_ordered_correlation(test_backend, extended_temporal_ordered_correlation):
    """Test conversion of extended temporal ordered correlation."""
    result = test_backend.convert(extended_temporal_ordered_correlation)
    assert result == [
        """subsearch { EventID=4625 | set event_type="failed_logon" }
subsearch { EventID=4624 | set event_type="successful_logon" }
subsearch { EventID=4672 | set event_type="admin_action" }

| temporal ordered=true extended=true window=10min by TargetUserName

| where matched_rules="failed_logon" and matched_rules="successful_logon" and matched_rules="admin_action\""""
    ]


def test_extended_temporal_correlation_precedence_and_or(test_backend):
    """Test that AND has higher precedence than OR."""
    collection = SigmaCollection.from_yaml("""
title: Rule A
name: rule_a
status: test
logsource:
    product: test
detection:
    selection:
        field: a
    condition: selection
---
title: Rule B
name: rule_b
status: test
logsource:
    product: test
detection:
    selection:
        field: b
    condition: selection
---
title: Rule C
name: rule_c
status: test
logsource:
    product: test
detection:
    selection:
        field: c
    condition: selection
---
title: Precedence test
status: test
correlation:
    type: temporal
    condition: rule_a or rule_b and rule_c
    timespan: 5m
        """)
    result = test_backend.convert(collection)
    # Should be: rule_a or (rule_b and rule_c)
    # Note: Parentheses are not needed because AND has higher precedence than OR
    assert result == ["""subsearch { field="a" | set event_type="rule_a" }
subsearch { field="b" | set event_type="rule_b" }
subsearch { field="c" | set event_type="rule_c" }

| temporal extended=true window=5min

| where matched_rules="rule_a" or matched_rules="rule_b" and matched_rules="rule_c\""""]


def test_extended_temporal_correlation_precedence_parentheses(test_backend):
    """Test that parentheses override precedence."""
    collection = SigmaCollection.from_yaml("""
title: Rule A
name: rule_a
status: test
logsource:
    product: test
detection:
    selection:
        field: a
    condition: selection
---
title: Rule B
name: rule_b
status: test
logsource:
    product: test
detection:
    selection:
        field: b
    condition: selection
---
title: Rule C
name: rule_c
status: test
logsource:
    product: test
detection:
    selection:
        field: c
    condition: selection
---
title: Parentheses test
status: test
correlation:
    type: temporal
    condition: (rule_a or rule_b) and rule_c
    timespan: 5m
        """)
    result = test_backend.convert(collection)
    # Should be: (rule_a or rule_b) and rule_c
    assert result == ["""subsearch { field="a" | set event_type="rule_a" }
subsearch { field="b" | set event_type="rule_b" }
subsearch { field="c" | set event_type="rule_c" }

| temporal extended=true window=5min

| where (matched_rules="rule_a" or matched_rules="rule_b") and matched_rules="rule_c\""""]


def test_extended_temporal_correlation_multiple_not(test_backend):
    """Test multiple consecutive NOT operators."""
    collection = SigmaCollection.from_yaml("""
title: Rule A
name: rule_a
status: test
logsource:
    product: test
detection:
    selection:
        field: a
    condition: selection
---
title: Double negation test
status: test
correlation:
    type: temporal
    condition: not not rule_a
    timespan: 5m
        """)
    result = test_backend.convert(collection)
    # Should be: not not rule_a
    # Note: Single rule doesn't use subsearch wrapper, and NOTs are grouped
    assert result == ["""field="a"

| temporal extended=true window=5min

| where not (not matched_rules="rule_a")"""]
