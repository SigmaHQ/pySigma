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
    assert rule.group_by == ["user"]
    assert rule.timespan == SigmaCorrelationTimespan("10m")
    assert rule.condition == SigmaCorrelationCondition(
        op=SigmaCorrelationConditionOperator.GTE, count=10
    )
    assert rule.ordered == False


def test_correlation_valid_2():
    rule = SigmaCorrelationRule.from_dict(
        {
            "title": "Valid correlation",
            "correlation": {
                "type": "temporal",
                "rules": ["event_a", "event_b"],
                "group-by": ["source", "user"],
                "timespan": "1h",
                "ordered": True,
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
    assert rule.ordered is True
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
    assert rule.ordered == False


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
    ordered: true
"""
    )
    assert isinstance(rule, SigmaCorrelationRule)
    assert rule.title == "Valid correlation"
    assert rule.type == SigmaCorrelationType.TEMPORAL
    assert rule.rules == [SigmaRuleReference("event_a"), SigmaRuleReference("event_b")]
    assert rule.group_by == ["source", "user"]
    assert rule.timespan == SigmaCorrelationTimespan("1h")
    assert rule.condition == SigmaCorrelationCondition(SigmaCorrelationConditionOperator.GTE, 2)
    assert rule.ordered == True
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
                "name": "Invalid correlation type",
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
                "name": "Invalid correlation type",
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
                "name": "Invalid rule reference",
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
                "name": "Invalid rule reference",
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
                "name": "Invalid group-by",
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
                "name": "Invalid time span",
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
                "name": "Invalid time span",
                "correlation": {
                    "type": "event_count",
                    "rules": "failed_login",
                    "group-by": ["user"],
                    "condition": {"gte": 10},
                },
            }
        )


def test_correlation_invalid_ordered():
    with pytest.raises(
        SigmaCorrelationRuleError, match="Sigma correlation ordered definition must be boolean"
    ):
        SigmaCorrelationRule.from_dict(
            {
                "name": "Invalid ordered",
                "correlation": {
                    "type": "event_count",
                    "rules": "failed_login",
                    "group-by": ["user"],
                    "timespan": "10m",
                    "ordered": "test",
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
                "name": "Invalid condition",
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
                "name": "Invalid condition",
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
            ordered=False,
            condition=None,
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
            "ordered": False,
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
                "name": "Invalid alias",
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


def test_correlation_condition_multiple_items():
    with pytest.raises(
        SigmaCorrelationConditionError,
        match="Sigma correlation condition must have exactly one item",
    ):
        SigmaCorrelationCondition.from_dict({"gte": 10, "lte": 20})


def test_correlation_condition_invalid_operator():
    with pytest.raises(
        SigmaCorrelationConditionError,
        match="Sigma correlation condition operator 'test' is invalid",
    ):
        SigmaCorrelationCondition.from_dict({"test": 10})


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
