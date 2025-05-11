import pytest
from sigma.collection import SigmaCollection
from sigma.correlations import (
    SigmaCorrelationCondition,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationFieldAliases,
    SigmaCorrelationRule,
    SigmaCorrelationTimespan,
    SigmaCorrelationType,
    SigmaRuleReference,
)
from sigma.exceptions import (
    SigmaCorrelationConditionError,
    SigmaCorrelationRuleError,
    SigmaCorrelationTypeError,
    SigmaRuleNotFoundError,
    SigmaTimespanError,
)


@pytest.fixture
def rule_collection():
    return SigmaCollection.from_yaml(
        """
title: Failed login
name: failed_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
        """
    )


@pytest.fixture
def correlation_rule():
    return SigmaCorrelationRule.from_dict(
        {
            "title": "Valid correlation",
            "correlation": {
                "type": "event_count",
                "rules": "failed_login",
                "group-by": "user",
                "timespan": "10m",
                "condition": {"gte": 10},
            },
        }
    )


def test_correlation_valid_1(correlation_rule):
    rule = correlation_rule
    assert isinstance(rule, SigmaCorrelationRule)
    assert rule.title == "Valid correlation"
    assert rule.type == SigmaCorrelationType.EVENT_COUNT
    assert rule.rules == [SigmaRuleReference("failed_login")]
    assert rule.generate == False
    assert rule.group_by == ["user"]
    assert rule.timespan == SigmaCorrelationTimespan("10m")
    assert rule.condition == SigmaCorrelationCondition(
        op=SigmaCorrelationConditionOperator.GTE, count=10
    )


def test_correlation_valid_2():
    rule = SigmaCorrelationRule.from_dict(
        {
            "title": "Valid correlation",
            "correlation": {
                "type": "temporal",
                "rules": ["event_a", "event_b"],
                "group-by": ["source", "user"],
                "timespan": "1h",
                "aliases": {
                    "source": {
                        "event_a": "source_ip",
                        "event_b": "source_address",
                    },
                    "user": {
                        "event_a": "username",
                        "event_b": "user_name",
                    },
                },
            },
        }
    )
    assert isinstance(rule, SigmaCorrelationRule)
    assert rule.title == "Valid correlation"
    assert rule.type == SigmaCorrelationType.TEMPORAL
    assert rule.rules == [
        SigmaRuleReference("event_a"),
        SigmaRuleReference("event_b"),
    ]
    assert rule.group_by == ["source", "user"]
    assert rule.timespan == SigmaCorrelationTimespan("1h")
    assert rule.condition == SigmaCorrelationCondition(SigmaCorrelationConditionOperator.GTE, 2)
    assert len(rule.aliases.aliases) == 2
    assert rule.aliases.aliases["source"].mapping == {
        SigmaRuleReference("event_a"): "source_ip",
        SigmaRuleReference("event_b"): "source_address",
    }
    assert rule.aliases.aliases["user"].mapping == {
        SigmaRuleReference("event_a"): "username",
        SigmaRuleReference("event_b"): "user_name",
    }


def test_correlation_valid_1_from_yaml():
    rule = SigmaCorrelationRule.from_yaml(
        """
title: Valid correlation
correlation:
    type: event_count
    rules: failed_login
    group-by: user
    timespan: 10m
    condition:
        gte: 10
"""
    )
    assert isinstance(rule, SigmaCorrelationRule)
    assert rule.title == "Valid correlation"
    assert rule.type == SigmaCorrelationType.EVENT_COUNT
    assert rule.rules == [SigmaRuleReference("failed_login")]
    assert rule.group_by == ["user"]
    assert rule.timespan == SigmaCorrelationTimespan("10m")
    assert rule.condition == SigmaCorrelationCondition(
        op=SigmaCorrelationConditionOperator.GTE, count=10
    )


def test_correlation_valid_2_from_yaml():
    rule = SigmaCorrelationRule.from_yaml(
        """
title: Valid correlation
correlation:
    type: temporal
    rules:
        - event_a
        - event_b
    group-by:
        - source
        - user
    aliases:
        source:
            event_a: source_ip
            event_b: source_address
        user:
            event_a: username
            event_b: user_name
    timespan: 1h
"""
    )
    assert isinstance(rule, SigmaCorrelationRule)
    assert rule.title == "Valid correlation"
    assert rule.type == SigmaCorrelationType.TEMPORAL
    assert rule.rules == [SigmaRuleReference("event_a"), SigmaRuleReference("event_b")]
    assert rule.group_by == ["source", "user"]
    assert rule.timespan == SigmaCorrelationTimespan("1h")
    assert rule.condition == SigmaCorrelationCondition(SigmaCorrelationConditionOperator.GTE, 2)
    assert len(rule.aliases.aliases) == 2
    assert rule.aliases.aliases["source"].mapping == {
        SigmaRuleReference("event_a"): "source_ip",
        SigmaRuleReference("event_b"): "source_address",
    }
    assert rule.aliases.aliases["user"].mapping == {
        SigmaRuleReference("event_a"): "username",
        SigmaRuleReference("event_b"): "user_name",
    }


def test_correlation_wrong_type():
    with pytest.raises(
        SigmaCorrelationTypeError, match="'test' is no valid Sigma correlation type"
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Invalid correlation type",
                "correlation": {
                    "type": "test",
                    "rules": "failed_login",
                    "group-by": ["user"],
                    "timespan": "10m",
                    "condition": {"gte": 10},
                },
            }
        )


def test_correlation_without_type():
    with pytest.raises(SigmaCorrelationTypeError, match="Sigma correlation rule without type"):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Invalid correlation type",
                "correlation": {
                    "rules": "failed_login",
                    "group-by": ["user"],
                    "timespan": "10m",
                    "condition": {"gte": 10},
                },
            }
        )


def test_correlation_invalid_rule_reference():
    with pytest.raises(
        SigmaCorrelationRuleError, match="Rule reference must be plain string or list."
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Invalid rule reference",
                "correlation": {
                    "type": "event_count",
                    "rules": {"test": "test"},
                    "group-by": ["user"],
                    "timespan": "10m",
                    "condition": {"gte": 10},
                },
            }
        )


def test_correlation_without_rule_reference():
    with pytest.raises(
        SigmaCorrelationRuleError, match="Sigma correlation rule without rule references"
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Invalid rule reference",
                "correlation": {
                    "type": "event_count",
                    "group-by": ["user"],
                    "timespan": "10m",
                    "condition": {"gte": 10},
                },
            }
        )


def test_correlation_invalid_group_by():
    with pytest.raises(
        SigmaCorrelationRuleError,
        match="Sigma correlation group-by definition must be string or list",
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Invalid group-by",
                "correlation": {
                    "type": "event_count",
                    "rules": "failed_login",
                    "group-by": {"test": "test"},
                    "timespan": "10m",
                    "condition": {"gte": 10},
                },
            }
        )


def test_correlation_invalid_timespan():
    with pytest.raises(SigmaTimespanError, match="Timespan '10' is invalid."):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Invalid time span",
                "correlation": {
                    "type": "event_count",
                    "rules": "failed_login",
                    "group-by": ["user"],
                    "timespan": "10",
                    "condition": {"gte": 10},
                },
            }
        )


def test_correlation_timespan():
    timespan = SigmaCorrelationTimespan("10m")
    assert isinstance(timespan, SigmaCorrelationTimespan)
    assert timespan.count == 10
    assert timespan.unit == "m"
    assert timespan.seconds == 600


def test_correlation_without_timespan():
    with pytest.raises(SigmaCorrelationRuleError, match="Sigma correlation rule without timespan"):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Invalid time span",
                "correlation": {
                    "type": "event_count",
                    "rules": "failed_login",
                    "group-by": ["user"],
                    "condition": {"gte": 10},
                },
            }
        )


def test_correlation_invalid_condition():
    with pytest.raises(
        SigmaCorrelationRuleError, match="Sigma correlation condition definition must be a dict"
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Invalid condition",
                "correlation": {
                    "type": "event_count",
                    "rules": "failed_login",
                    "group-by": ["user"],
                    "timespan": "10m",
                    "condition": "test",
                },
            }
        )


def test_correlation_without_condition():
    with pytest.raises(SigmaCorrelationRuleError, match="Sigma correlation rule without condition"):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Invalid condition",
                "correlation": {
                    "type": "event_count",
                    "rules": "failed_login",
                    "group-by": ["user"],
                    "timespan": "10m",
                },
            }
        )


def test_correlation_without_condition_post_init_check():
    with pytest.raises(SigmaCorrelationRuleError, match="Sigma correlation rule without condition"):
        SigmaCorrelationRule(
            type=SigmaCorrelationType.EVENT_COUNT,
            rules=[SigmaRuleReference("failed_login")],
            timespan=600,
            group_by=["user"],
            condition=None,
        )


def test_value_count_correlation_without_condition_field():
    with pytest.raises(
        SigmaCorrelationRuleError, match="Value count correlation rule without field reference"
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Missing field in condition",
                "correlation": {
                    "type": "value_count",
                    "rules": "failed_login",
                    "group-by": ["user"],
                    "timespan": "10m",
                    "condition": {"gte": 10},
                },
            }
        )


def test_correlation_to_dict():
    rule = SigmaCorrelationRule.from_dict(
        {
            "title": "Valid correlation",
            "correlation": {
                "type": "event_count",
                "rules": "failed_login",
                "group-by": "user",
                "timespan": "10m",
                "aliases": {"user": {"failed_login": "username"}},
                "condition": {"gte": 10},
            },
        }
    )
    assert rule.to_dict() == {
        "title": "Valid correlation",
        "correlation": {
            "type": "event_count",
            "rules": ["failed_login"],
            "group-by": ["user"],
            "timespan": "10m",
            "aliases": {"user": {"failed_login": "username"}},
            "condition": {"gte": 10},
        },
    }


def test_correlation_invalid_alias():
    with pytest.raises(
        SigmaCorrelationRuleError, match="Sigma correlation aliases definition must be a dict"
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Invalid alias",
                "correlation": {
                    "type": "event_count",
                    "rules": "failed_login",
                    "group-by": ["user"],
                    "timespan": "10m",
                    "aliases": "test",
                    "condition": {"gte": 10},
                },
            }
        )


def test_correlation_alias_invalid_mapping():
    with pytest.raises(
        SigmaCorrelationRuleError, match="Sigma correlation field alias mapping must be a dict"
    ):
        SigmaCorrelationFieldAliases.from_dict(
            {"test": "test"},
        )


def test_correlation_condition():
    cond = SigmaCorrelationCondition.from_dict({"gte": 10})
    assert isinstance(cond, SigmaCorrelationCondition)
    assert cond.op == SigmaCorrelationConditionOperator.GTE
    assert cond.count == 10


def test_correlation_neq_condition():
    cond = SigmaCorrelationCondition.from_dict({"neq": 10})
    assert isinstance(cond, SigmaCorrelationCondition)
    assert cond.op == SigmaCorrelationConditionOperator.NEQ
    assert cond.count == 10


def test_correlation_condition_with_field():
    cond = SigmaCorrelationCondition.from_dict({"field": "test", "gte": 10})
    assert isinstance(cond, SigmaCorrelationCondition)
    assert cond.op == SigmaCorrelationConditionOperator.GTE
    assert cond.count == 10
    assert cond.fieldref == "test"


def test_correlation_condition_with_field_to_dict():
    assert SigmaCorrelationCondition(
        op=SigmaCorrelationConditionOperator.GTE, count=10, fieldref="test"
    ).to_dict() == {"field": "test", "gte": 10}


def test_correlation_condition_invalid_multicond():
    with pytest.raises(
        SigmaCorrelationConditionError,
        match="Sigma correlation condition must have exactly one condition item",
    ):
        SigmaCorrelationCondition.from_dict({"gte": 10, "lte": 20})


def test_correlation_condition_invalid_item():
    with pytest.raises(
        SigmaCorrelationConditionError,
        match="Sigma correlation condition contains invalid items: test.*",
    ):
        SigmaCorrelationCondition.from_dict({"gte": 10, "test1": 20, "test2": 30})


def test_correlation_condition_invalid_count():
    with pytest.raises(
        SigmaCorrelationConditionError,
        match="'test' is no valid Sigma correlation condition count",
    ):
        SigmaCorrelationCondition.from_dict({"gte": "test"})


def test_correlation_condition_to_dict():
    cond = SigmaCorrelationCondition.from_dict({"gte": 10})
    assert cond.to_dict() == {"gte": 10}


def test_correlation_resolve_rule_references(rule_collection, correlation_rule):
    correlation_rule.resolve_rule_references(rule_collection)
    rule = rule_collection["failed_login"]
    assert correlation_rule.rules[0].rule == rule
    assert rule.referenced_by(correlation_rule)


def test_correlation_resolve_rule_references_invalid_reference(correlation_rule):
    with pytest.raises(
        SigmaRuleNotFoundError, match="Rule 'failed_login' not found in rule collection"
    ):
        correlation_rule.resolve_rule_references(SigmaCollection([]))


def test_correlation_valid_multidocuments_from_yaml():
    rules = """
title: Correlation - Multiple Failed Logins Followed by Successful Login
id: b180ead8-d58f-40b2-ae54-c8940995b9b6
status: experimental
description: Detects multiple failed logins by a single user followed by a successful login of that user
references:
    - https://reference.com
author: Florian Roth (Nextron Systems)
date: 2023-06-16
correlation:
    type: temporal_ordered
    rules:
        - multiple_failed_login
        - failed_login
        - successful_login
    group-by:
        - User
    timespan: 10m
falsepositives:
    - Unlikely
level: high
---
title: Multiple failed logons
id: a8418a5a-5fc4-46b5-b23b-6c73beb19d41
description: Detects multiple failed logins within a certain amount of time
name: multiple_failed_login
correlation:
    type: event_count
    rules:
        - event_a
        - failed_login
    group-by:
        - User
    timespan: 10m
    condition:
        gte: 10
---
title: Valid nested correlations
name: nested_correlations
correlation:
    type: temporal
    rules:
        - event_a
        - event_b
        - failed_login
    group-by:
        - source
        - user
    aliases:
        source:
            event_a: source_ip
            event_b: source_address
        user:
            event_a: username
            event_b: user_name
    timespan: 1h
""".split(
        "---"
    )

    head, *tail = list(map(SigmaCorrelationRule.from_yaml, rules))
    result = head.flatten_rules(tail)

    assert set(result) == set(["failed_login", "event_a", "event_b", "successful_login"])
    assert result["failed_login"]["count"] == 3
    assert result["event_a"]["count"] == 2
    assert result["event_b"]["count"] == 1


def test_correlation_rule_generate():
    assert (
        SigmaCorrelationRule.from_dict(
            {
                "title": "Valid correlation",
                "correlation": {
                    "type": "event_count",
                    "rules": "failed_login",
                    "generate": True,
                    "group-by": "user",
                    "timespan": "10m",
                    "condition": {"gte": 10},
                },
            }
        ).generate
        == True
    )


def test_correlation_invalid_generate():
    with pytest.raises(
        SigmaCorrelationRuleError, match="Sigma correlation generate definition must be a boolean"
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Valid correlation",
                "correlation": {
                    "type": "event_count",
                    "rules": "failed_login",
                    "generate": "test",
                    "group-by": "user",
                    "timespan": "10m",
                    "condition": {"gte": 10},
                },
            }
        )
