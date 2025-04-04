import pytest
from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaBackendError, SigmaConversionError
from sigma.processing.pipeline import ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.postprocessing import EmbedQueryTransformation
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
        - fieldB
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
| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName, mappedB
| where event_count >= 10"""
    ]


def test_correlation_without_normalization_support(
    monkeypatch, test_backend, event_count_correlation_rule
):
    monkeypatch.setattr(test_backend, "correlation_search_field_normalization_expression", None)
    assert test_backend.convert(event_count_correlation_rule) == [
        """EventID=4625
| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName, mappedB
| where event_count >= 10"""
    ]


def test_generate_query_without_referenced_rules_expression(
    monkeypatch, test_backend, event_count_correlation_rule
):
    monkeypatch.setattr(test_backend, "referenced_rules_expression", None)
    monkeypatch.setattr(test_backend, "referenced_rules_expression_joiner", None)
    assert test_backend.convert(event_count_correlation_rule) == [
        """EventID=4625
| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName, mappedB
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


@pytest.fixture
def temporal_correlation_rule():
    temporal_correlation_rule = SigmaCollection.from_yaml(
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

    return temporal_correlation_rule


def test_temporal_correlation_multi_rule_without_condition(test_backend, temporal_correlation_rule):
    assert test_backend.convert(temporal_correlation_rule) == [
        """subsearch { EventID=4625 | set event_type="failed_logon" }
subsearch { EventID=4624 | set event_type="successful_logon" }

| temporal window=5min eventtypes=failed_logon,successful_logon by TargetUserName, TargetDomainName

| where eventtype_count >= 2"""
    ]


def test_temporal_correlation_multi_rule_with_typing_expression(
    monkeypatch, test_backend, temporal_correlation_rule
):
    monkeypatch.setattr(
        test_backend,
        "temporal_correlation_query",
        {"test": "{search}\n{typing}\n\n{aggregate}\n\n{condition}"},
    )
    monkeypatch.setattr(
        test_backend, "correlation_search_multi_rule_query_expression", "( {query} )"
    )
    monkeypatch.setattr(
        test_backend, "correlation_search_multi_rule_query_expression_joiner", " or "
    )
    monkeypatch.setattr(test_backend, "typing_expression", "| eval event_type=case({queries})")
    monkeypatch.setattr(test_backend, "typing_rule_query_expression_joiner", ", ")
    monkeypatch.setattr(test_backend, "typing_rule_query_expression", '{query}, "{ruleid}"')
    assert test_backend.convert(temporal_correlation_rule) == [
        """( EventID=4625 ) or ( EventID=4624 )
| eval event_type=case(EventID=4625, "failed_logon", EventID=4624, "successful_logon")

| temporal window=5min eventtypes=failed_logon,successful_logon by TargetUserName, TargetDomainName

| where eventtype_count >= 2"""
    ]


def test_referenced_rule_expression_used_but_not_defined(
    monkeypatch, test_backend, temporal_correlation_rule
):
    monkeypatch.setattr(test_backend, "referenced_rules_expression", None)
    monkeypatch.setattr(test_backend, "referenced_rules_expression_joiner", None)
    with pytest.raises(SigmaBackendError, match="referenced rule expression"):
        test_backend.convert(temporal_correlation_rule)


@pytest.fixture
def temporal_ordered_correlation_rule():
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
        mapped:
            failed_logon: fieldB
            successful_logon: fieldC
            discovery_activity: fieldD
    group-by:
        - user
        - domain
        - mapped
    condition:
        gte: 2
            """
    )


def test_temporal_ordered_correlation_multi_rule_with_condition_and_field_normalization(
    test_backend, temporal_ordered_correlation_rule
):
    assert test_backend.convert(temporal_ordered_correlation_rule) == [
        """subsearch { EventID=4625 | set event_type="failed_logon" | set user=TargetUserName | set domain=TargetDomainName | set mapped=mappedB }
subsearch { EventID=4624 | set event_type="successful_logon" | set user=TargetUserName | set domain=TargetDomainName | set mapped=fieldC }
subsearch { CommandLine in ("*whoami*", "*dsquery*", "*net group*") | set event_type="discovery_activity" | set user=User | set domain=Domain | set mapped=fieldD }
| temporal ordered=true window=1h eventtypes=failed_logon,successful_logon,discovery_activity by user, domain, mapped
| where eventtype_count >= 2 and eventtype_order=failed_logon,successful_logon,discovery_activity"""
    ]


def test_correlation_timespan_in_seconds(monkeypatch, test_backend, event_count_correlation_rule):
    monkeypatch.setattr(test_backend, "timespan_seconds", True)
    assert test_backend.convert(event_count_correlation_rule) == [
        """EventID=4625
| aggregate window=300 count() as event_count by TargetUserName, TargetDomainName, mappedB
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


def test_correlation_generate_chained_rule(test_backend):
    rule_collection = SigmaCollection.from_yaml(
        """
title: Successful login
name: successful_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 528
            - 4624
    condition: selection
---
title: Single failed login
name: failed_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 529
            - 4625
    condition: selection
---
title: Multiple failed logons
name: multiple_failed_login
correlation:
    type: event_count
    rules:
        - failed_login
    generate: true
    group-by:
        - User
    timespan: 10m
    condition:
        gte: 10
---
title: Multiple Failed Logins Followed by Successful Login
status: test
correlation:
    type: temporal_ordered
    rules:
        - multiple_failed_login
        - successful_login
    generate: true
    group-by:
        - User
    timespan: 10m
            """
    )

    assert test_backend.convert(rule_collection) == [
        """EventID in (528, 4624)""",
        """EventID in (529, 4625)""",
        """EventID in (529, 4625)
| aggregate window=10min count() as event_count by User
| where event_count >= 10""",
        """subsearch { EventID in (529, 4625)\n| aggregate window=10min count() as event_count by User\n| where event_count >= 10 | set event_type="multiple_failed_login" }
subsearch { EventID in (528, 4624) | set event_type="successful_login" }
| temporal ordered=true window=10min eventtypes=multiple_failed_login,successful_login by User
| where eventtype_count >= 2 and eventtype_order=multiple_failed_login,successful_login""",
    ]


def test_correlation_not_supported(monkeypatch, test_backend, event_count_correlation_rule):
    monkeypatch.setattr(test_backend, "correlation_methods", None)
    with pytest.raises(NotImplementedError, match="Backend does not support correlation"):
        test_backend.convert(event_count_correlation_rule)


def test_correlation_method_not_supported(test_backend, event_count_correlation_rule):
    with pytest.raises(SigmaConversionError, match="Correlation method 'invalid' is not supported"):
        test_backend.convert(event_count_correlation_rule, correlation_method="invalid")


def test_correlation_method_no_supported_for_correlation_type(
    monkeypatch, test_backend, event_count_correlation_rule
):
    monkeypatch.setattr(
        test_backend,
        "correlation_methods",
        {"test": "Test correlation method", "another": "Another correlation method"},
    )
    with pytest.raises(
        SigmaConversionError,
        match="Correlation method 'another' is not supported by backend for correlation type 'event_count'",
    ):
        test_backend.convert(event_count_correlation_rule, correlation_method="another")


def test_correlation_type_not_supported(monkeypatch, test_backend, event_count_correlation_rule):
    monkeypatch.setattr(test_backend, "default_correlation_query", None)
    with pytest.raises(
        NotImplementedError, match="Correlation rule type 'event_count' is not supported"
    ):
        test_backend.convert(event_count_correlation_rule)


def test_correlation_normalization_not_supported(
    monkeypatch, test_backend, temporal_ordered_correlation_rule
):
    monkeypatch.setattr(test_backend, "correlation_search_field_normalization_expression", None)
    monkeypatch.setattr(
        test_backend, "correlation_search_field_normalization_expression_joiner", None
    )
    with pytest.raises(
        NotImplementedError, match="Correlation field normalization is not supported"
    ):
        test_backend.convert(temporal_ordered_correlation_rule)


def test_correlation_query_postprocessing(event_count_correlation_rule):
    test_backend = TextQueryTestBackend(
        ProcessingPipeline(
            postprocessing_items=[
                QueryPostprocessingItem(EmbedQueryTransformation(prefix="[ ", suffix=" ]"))
            ]
        )
    )
    assert test_backend.convert(event_count_correlation_rule) == [
        """[ [ EventID=4625 ]
| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName, fieldB
| where event_count >= 10 ]"""
    ]
