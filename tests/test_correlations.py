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


@pytest.fixture
def nested_correlation_rule():
    rules = """
title: Top level correlation
id: fab710f8-8b2a-4d7a-a8ec-4cd46d728f12
name: test_correlation
status: experimental
correlation:
    type: temporal_ordered
    rules:
        - rule_a
        - rule_b
        - nested_correlation
    group-by:
        - User
    timespan: 10m
---
title: Nested correlation
id: fda46cab-e5fe-4287-96d2-238433ad8ed7
name: nested_correlation
correlation:
    type: event_count
    rules:
        - rule_c
        - rule_d
    group-by:
        - User
    timespan: 10m
    condition:
        gte: 10
---
title: Rule A
id: 2d0179f5-8e57-4875-8888-7b18b4458af1
name: rule_a
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 1
    condition: selection
---
title: Rule B
id: e15bb313-747c-4c9f-aa26-20980b5494cc
name: rule_b
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 2
    condition: selection
---
title: Rule C
id: d5a68ab4-3d4e-4a54-a82f-d89f600cedff
name: rule_c
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 3
    condition: selection
---
title: Rule D
id: 906bab7a-9dd4-48df-8fea-449dbc74979c
name: rule_d
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4
    condition: selection
"""
    return SigmaCollection.from_yaml(rules)


def test_correlation_reference_flattening(nested_correlation_rule):
    nested_correlation_rule.resolve_rule_references()
    flattened_rule_ids = [
        rule.name for rule in nested_correlation_rule["test_correlation"].flatten_rules()
    ]
    assert flattened_rule_ids == ["rule_a", "rule_b", "nested_correlation", "rule_c", "rule_d"]


def test_correlation_reference_flattening_without_correlations(nested_correlation_rule):
    nested_correlation_rule.resolve_rule_references()
    flattened_rule_ids = [
        rule.name
        for rule in nested_correlation_rule["test_correlation"].flatten_rules(
            include_correlations=False
        )
    ]
    assert flattened_rule_ids == ["rule_a", "rule_b", "rule_c", "rule_d"]
