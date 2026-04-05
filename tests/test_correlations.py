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


def test_correlation_without_rules_requires_extended_condition():
    """Test that rules=None requires an extended correlation condition."""
    with pytest.raises(
        SigmaCorrelationRuleError,
        match="Sigma correlation rule without rules list requires an extended correlation condition",
    ):
        SigmaCorrelationRule(
            title="Invalid correlation",
            type=SigmaCorrelationType.EVENT_COUNT,
            rules=None,
            timespan=SigmaCorrelationTimespan("10m"),
            condition=SigmaCorrelationCondition(SigmaCorrelationConditionOperator.GTE, 10),
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
        SigmaCorrelationRuleError,
        match="Extended conditions \\(string\\) can only be used with temporal",
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
    flattened_rule_ids = [
        rule.name for rule in nested_correlation_rule["test_correlation"].flatten_rules()
    ]
    assert flattened_rule_ids == ["rule_a", "rule_b", "nested_correlation", "rule_c", "rule_d"]


def test_correlation_reference_flattening_without_correlations(nested_correlation_rule):
    flattened_rule_ids = [
        rule.name
        for rule in nested_correlation_rule["test_correlation"].flatten_rules(
            include_correlations=False
        )
    ]
    assert flattened_rule_ids == ["rule_a", "rule_b", "rule_c", "rule_d"]


# Tests for new correlation types field validation
def test_value_sum_without_field_reference():
    with pytest.raises(
        SigmaCorrelationRuleError, match="Value sum correlation rule without field reference"
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Test",
                "correlation": {
                    "type": "value_sum",
                    "rules": "test_rule",
                    "timespan": "10m",
                    "condition": {"gte": 1000},  # Missing field
                },
            }
        )


def test_value_avg_without_field_reference():
    with pytest.raises(
        SigmaCorrelationRuleError, match="Value avg correlation rule without field reference"
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Test",
                "correlation": {
                    "type": "value_avg",
                    "rules": "test_rule",
                    "timespan": "10m",
                    "condition": {"gte": 100},  # Missing field
                },
            }
        )


def test_value_percentile_without_field_reference():
    with pytest.raises(
        SigmaCorrelationRuleError, match="Value percentile correlation rule without field reference"
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Test",
                "correlation": {
                    "type": "value_percentile",
                    "rules": "test_rule",
                    "timespan": "10m",
                    "condition": {"gte": 95},  # Missing field
                },
            }
        )


def test_temporal_correlation_with_extended_condition():
    """Test that temporal correlation can use an extended condition (string)."""
    rule = SigmaCorrelationRule.from_dict(
        {
            "title": "Temporal with extended condition",
            "correlation": {
                "type": "temporal",
                "rules": ["rule_a", "rule_b"],
                "group-by": ["user"],
                "timespan": "5m",
                "condition": "rule_a and not rule_b",
            },
        }
    )
    assert rule.type == SigmaCorrelationType.TEMPORAL
    from sigma.correlations import SigmaExtendedCorrelationCondition

    assert isinstance(rule.condition, SigmaExtendedCorrelationCondition)
    assert rule.condition.expression == "rule_a and not rule_b"


def test_temporal_ordered_correlation_with_extended_condition():
    """Test that temporal_ordered correlation can use an extended condition (string)."""
    rule = SigmaCorrelationRule.from_dict(
        {
            "title": "Temporal ordered with extended condition",
            "correlation": {
                "type": "temporal_ordered",
                "rules": ["rule_a", "rule_b", "rule_c"],
                "group-by": ["user"],
                "timespan": "30s",
                "condition": "rule_a and not rule_b and rule_c",
            },
        }
    )
    assert rule.type == SigmaCorrelationType.TEMPORAL_ORDERED
    from sigma.correlations import SigmaExtendedCorrelationCondition

    assert isinstance(rule.condition, SigmaExtendedCorrelationCondition)
    assert rule.condition.expression == "rule_a and not rule_b and rule_c"


def test_extended_condition_requires_temporal_type():
    """Test that extended conditions (string) can only be used with temporal types."""
    with pytest.raises(
        SigmaCorrelationRuleError,
        match="Extended conditions \\(string\\) can only be used with temporal",
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Invalid extended condition",
                "correlation": {
                    "type": "event_count",
                    "rules": ["rule_a", "rule_b"],
                    "group-by": ["user"],
                    "timespan": "5m",
                    "condition": "rule_a and rule_b",
                },
            }
        )


def test_temporal_correlation_with_basic_condition():
    """Test that temporal correlation still works with basic dict condition."""
    rule = SigmaCorrelationRule.from_dict(
        {
            "title": "Temporal with basic condition",
            "correlation": {
                "type": "temporal",
                "rules": ["rule_a", "rule_b"],
                "group-by": ["user"],
                "timespan": "5m",
                "condition": {"gte": 1},
            },
        }
    )
    from sigma.correlations import SigmaCorrelationCondition

    assert isinstance(rule.condition, SigmaCorrelationCondition)
    assert rule.type == SigmaCorrelationType.TEMPORAL
    assert rule.condition.op == SigmaCorrelationConditionOperator.GTE
    assert rule.condition.count == 1


def test_extended_condition_serialization():
    """Test that extended condition is properly serialized to dict."""
    rule = SigmaCorrelationRule.from_dict(
        {
            "title": "Extended condition serialization test",
            "correlation": {
                "type": "temporal",
                "rules": ["rule_a", "rule_b"],
                "group-by": ["user"],
                "timespan": "5m",
                "condition": "rule_a and not rule_b",
            },
        }
    )

    rule_dict = rule.to_dict()
    assert rule_dict["correlation"]["condition"] == "rule_a and not rule_b"
    assert isinstance(rule_dict["correlation"]["condition"], str)


def test_basic_condition_serialization():
    """Test that basic dict conditions are still properly serialized."""
    rule = SigmaCorrelationRule.from_dict(
        {
            "title": "Event Count Correlation",
            "correlation": {
                "type": "event_count",
                "rules": ["rule_a", "rule_b"],
                "group-by": ["user"],
                "timespan": "5m",
                "condition": {"gte": 2},
            },
        }
    )
    rule_dict = rule.to_dict()
    assert rule_dict["correlation"]["condition"] == {"gte": 2}
    assert isinstance(rule_dict["correlation"]["condition"], dict)


def test_extended_condition_complex():
    """Test complex extended condition with multiple operators."""
    rule = SigmaCorrelationRule.from_dict(
        {
            "title": "Complex Extended Condition",
            "correlation": {
                "type": "temporal",
                "rules": ["rule_a", "rule_b", "rule_c", "rule_d"],
                "group-by": ["user", "host"],
                "timespan": "10m",
                "condition": "(rule_a or rule_b) and not (rule_c or rule_d)",
            },
        }
    )
    from sigma.correlations import SigmaExtendedCorrelationCondition

    assert isinstance(rule.condition, SigmaExtendedCorrelationCondition)
    assert rule.condition.expression == "(rule_a or rule_b) and not (rule_c or rule_d)"


def test_extended_condition_unreferenced_rule():
    """Test that unreferenced rules in extended condition raise an error."""
    with pytest.raises(
        SigmaCorrelationConditionError,
        match="Rules defined but not referenced in extended condition: rule_c",
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Unreferenced rule",
                "correlation": {
                    "type": "temporal",
                    "rules": ["rule_a", "rule_b", "rule_c"],
                    "group-by": ["user"],
                    "timespan": "5m",
                    "condition": "rule_a and rule_b",
                },
            }
        )


def test_extended_condition_invalid_syntax():
    """Test that invalid syntax in extended condition raises an error."""
    with pytest.raises(
        SigmaCorrelationConditionError,
        match="Failed to parse extended condition expression",
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Invalid syntax",
                "correlation": {
                    "type": "temporal",
                    "rules": ["rule_a", "rule_b"],
                    "group-by": ["user"],
                    "timespan": "5m",
                    "condition": "rule_a and and rule_b",  # Invalid syntax
                },
            }
        )


def test_extended_condition_multiple_unreferenced_rules():
    """Test error message when multiple rules are not referenced."""
    with pytest.raises(
        SigmaCorrelationConditionError,
        match="Rules defined but not referenced in extended condition: rule_c, rule_d",
    ):
        SigmaCorrelationRule.from_dict(
            {
                "title": "Multiple missing rule references",
                "correlation": {
                    "type": "temporal",
                    "rules": ["rule_a", "rule_b", "rule_c", "rule_d"],
                    "group-by": ["user"],
                    "timespan": "5m",
                    "condition": "rule_a and rule_b",  # rule_c and rule_d are missing
                },
            }
        )


def test_extended_condition_undefined_rule_direct_constructor():
    """Test that rules referenced in condition but not in rules list raise an error when using constructor directly."""
    from sigma.correlations import SigmaExtendedCorrelationCondition

    with pytest.raises(
        SigmaCorrelationConditionError,
        match="Rules referenced in extended condition but not defined in rules list: rule_c",
    ):
        SigmaCorrelationRule(
            title="Undefined rule in condition",
            type=SigmaCorrelationType.TEMPORAL,
            rules=[SigmaRuleReference("rule_a"), SigmaRuleReference("rule_b")],
            timespan=SigmaCorrelationTimespan("5m"),
            group_by=["user"],
            condition=SigmaExtendedCorrelationCondition("rule_a and rule_b and rule_c"),
        )


def test_extended_condition_multiple_undefined_rules_direct_constructor():
    """Test error message when multiple rules referenced in condition are not defined using constructor."""
    from sigma.correlations import SigmaExtendedCorrelationCondition

    with pytest.raises(
        SigmaCorrelationConditionError,
        match="Rules referenced in extended condition but not defined in rules list: rule_c, rule_d",
    ):
        SigmaCorrelationRule(
            title="Multiple undefined rules in condition",
            type=SigmaCorrelationType.TEMPORAL,
            rules=[SigmaRuleReference("rule_a"), SigmaRuleReference("rule_b")],
            timespan=SigmaCorrelationTimespan("5m"),
            group_by=["user"],
            condition=SigmaExtendedCorrelationCondition("rule_a and (rule_b or rule_c) and rule_d"),
        )


def test_extended_condition_rules_match():
    """Test successful case where rules list matches extended condition references."""
    rule = SigmaCorrelationRule.from_dict(
        {
            "title": "Matching rules",
            "correlation": {
                "type": "temporal",
                "rules": ["rule_a", "rule_b", "rule_c"],
                "group-by": ["user"],
                "timespan": "5m",
                "condition": "rule_a and (rule_b or rule_c)",
            },
        }
    )
    from sigma.correlations import SigmaExtendedCorrelationCondition

    assert isinstance(rule.condition, SigmaExtendedCorrelationCondition)
    assert rule.condition.expression == "rule_a and (rule_b or rule_c)"
    assert len(rule.rules) == 3
    assert set(r.reference for r in rule.rules) == {"rule_a", "rule_b", "rule_c"}


# Tests for SigmaExtendedCorrelationCondition parsing
def test_extended_condition_parse_simple_identifier():
    """Test parsing a simple rule identifier."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        SigmaRuleReference,
    )

    cond = SigmaExtendedCorrelationCondition(expression="rule_a")
    assert cond.expression == "rule_a"
    assert cond._parsed is not None
    # Simple identifier should be a SigmaRuleReference
    assert isinstance(cond._parsed, SigmaRuleReference)
    assert cond._parsed.reference == "rule_a"
    assert set(cond.get_referenced_rules()) == {"rule_a"}


def test_extended_condition_parse_basic_and():
    """Test parsing basic AND expression."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionAND,
        SigmaRuleReference,
    )

    cond = SigmaExtendedCorrelationCondition(expression="rule_a and rule_b")
    assert cond.expression == "rule_a and rule_b"
    assert cond._parsed is not None
    # Binary AND should be a CorrelationConditionAND object
    assert isinstance(cond._parsed, CorrelationConditionAND)
    assert len(cond._parsed.args) == 2
    assert isinstance(cond._parsed.args[0], SigmaRuleReference)
    assert cond._parsed.args[0].reference == "rule_a"
    assert isinstance(cond._parsed.args[1], SigmaRuleReference)
    assert cond._parsed.args[1].reference == "rule_b"
    assert set(cond.get_referenced_rules()) == {"rule_a", "rule_b"}


def test_extended_condition_parse_basic_or():
    """Test parsing basic OR expression."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionOR,
        SigmaRuleReference,
    )

    cond = SigmaExtendedCorrelationCondition(expression="rule_a or rule_b")
    assert cond.expression == "rule_a or rule_b"
    assert cond._parsed is not None
    # Binary OR should be a CorrelationConditionOR object
    assert isinstance(cond._parsed, CorrelationConditionOR)
    assert len(cond._parsed.args) == 2
    assert isinstance(cond._parsed.args[0], SigmaRuleReference)
    assert cond._parsed.args[0].reference == "rule_a"
    assert isinstance(cond._parsed.args[1], SigmaRuleReference)
    assert cond._parsed.args[1].reference == "rule_b"
    assert set(cond.get_referenced_rules()) == {"rule_a", "rule_b"}


def test_extended_condition_parse_basic_not():
    """Test parsing basic NOT expression."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionNOT,
        SigmaRuleReference,
    )

    cond = SigmaExtendedCorrelationCondition(expression="not rule_a")
    assert cond.expression == "not rule_a"
    assert cond._parsed is not None
    # Unary NOT should be a CorrelationConditionNOT object
    assert isinstance(cond._parsed, CorrelationConditionNOT)
    assert len(cond._parsed.args) == 1
    assert isinstance(cond._parsed.args[0], SigmaRuleReference)
    assert cond._parsed.args[0].reference == "rule_a"
    assert set(cond.get_referenced_rules()) == {"rule_a"}


def test_extended_condition_parse_multiple_and():
    """Test parsing multiple AND operations."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionAND,
        SigmaRuleReference,
    )

    cond = SigmaExtendedCorrelationCondition(expression="rule_a and rule_b and rule_c")
    assert cond.expression == "rule_a and rule_b and rule_c"
    assert cond._parsed is not None
    # Left-associative AND with 3 operands: all args in flat list
    assert isinstance(cond._parsed, CorrelationConditionAND)
    assert len(cond._parsed.args) == 3
    assert all(isinstance(arg, SigmaRuleReference) for arg in cond._parsed.args)
    assert cond._parsed.args[0].reference == "rule_a"
    assert cond._parsed.args[1].reference == "rule_b"
    assert cond._parsed.args[2].reference == "rule_c"
    assert set(cond.get_referenced_rules()) == {"rule_a", "rule_b", "rule_c"}


def test_extended_condition_parse_multiple_or():
    """Test parsing multiple OR operations."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionOR,
        SigmaRuleReference,
    )

    cond = SigmaExtendedCorrelationCondition(expression="rule_a or rule_b or rule_c")
    assert cond.expression == "rule_a or rule_b or rule_c"
    assert cond._parsed is not None
    # Left-associative OR with 3 operands: all args in flat list
    assert isinstance(cond._parsed, CorrelationConditionOR)
    assert len(cond._parsed.args) == 3
    assert all(isinstance(arg, SigmaRuleReference) for arg in cond._parsed.args)
    assert cond._parsed.args[0].reference == "rule_a"
    assert cond._parsed.args[1].reference == "rule_b"
    assert cond._parsed.args[2].reference == "rule_c"
    assert set(cond.get_referenced_rules()) == {"rule_a", "rule_b", "rule_c"}


def test_extended_condition_parse_precedence_and_or():
    """Test that AND has higher precedence than OR (rule_a and rule_b or rule_c = (rule_a and rule_b) or rule_c)."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionOR,
        CorrelationConditionAND,
        SigmaRuleReference,
    )

    cond = SigmaExtendedCorrelationCondition(expression="rule_a and rule_b or rule_c")
    assert cond.expression == "rule_a and rule_b or rule_c"
    assert cond._parsed is not None
    # AND binds tighter than OR: OR(AND(rule_a, rule_b), rule_c)
    assert isinstance(cond._parsed, CorrelationConditionOR)
    assert len(cond._parsed.args) == 2
    # First arg should be AND
    assert isinstance(cond._parsed.args[0], CorrelationConditionAND)
    assert len(cond._parsed.args[0].args) == 2
    assert cond._parsed.args[0].args[0].reference == "rule_a"
    assert cond._parsed.args[0].args[1].reference == "rule_b"
    # Second arg is rule_c
    assert isinstance(cond._parsed.args[1], SigmaRuleReference)
    assert cond._parsed.args[1].reference == "rule_c"
    assert set(cond.get_referenced_rules()) == {"rule_a", "rule_b", "rule_c"}


def test_extended_condition_parse_precedence_or_and():
    """Test that AND has higher precedence than OR (rule_a or rule_b and rule_c = rule_a or (rule_b and rule_c))."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionOR,
        CorrelationConditionAND,
        SigmaRuleReference,
    )

    cond = SigmaExtendedCorrelationCondition(expression="rule_a or rule_b and rule_c")
    assert cond.expression == "rule_a or rule_b and rule_c"
    assert cond._parsed is not None
    # AND binds tighter than OR: OR(rule_a, AND(rule_b, rule_c))
    assert isinstance(cond._parsed, CorrelationConditionOR)
    assert len(cond._parsed.args) == 2
    # First arg is rule_a
    assert isinstance(cond._parsed.args[0], SigmaRuleReference)
    assert cond._parsed.args[0].reference == "rule_a"
    # Second arg should be AND
    assert isinstance(cond._parsed.args[1], CorrelationConditionAND)
    assert len(cond._parsed.args[1].args) == 2
    assert cond._parsed.args[1].args[0].reference == "rule_b"
    assert cond._parsed.args[1].args[1].reference == "rule_c"
    assert set(cond.get_referenced_rules()) == {"rule_a", "rule_b", "rule_c"}


def test_extended_condition_parse_precedence_not_and():
    """Test that NOT has higher precedence than AND (not rule_a and rule_b = (not rule_a) and rule_b)."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionAND,
        CorrelationConditionNOT,
        SigmaRuleReference,
    )

    cond = SigmaExtendedCorrelationCondition(expression="not rule_a and rule_b")
    assert cond.expression == "not rule_a and rule_b"
    assert cond._parsed is not None
    # NOT binds tighter than AND: AND(NOT(rule_a), rule_b)
    assert isinstance(cond._parsed, CorrelationConditionAND)
    assert len(cond._parsed.args) == 2
    # First arg should be NOT
    assert isinstance(cond._parsed.args[0], CorrelationConditionNOT)
    assert len(cond._parsed.args[0].args) == 1
    assert isinstance(cond._parsed.args[0].args[0], SigmaRuleReference)
    assert cond._parsed.args[0].args[0].reference == "rule_a"
    # Second arg is rule_b
    assert isinstance(cond._parsed.args[1], SigmaRuleReference)
    assert cond._parsed.args[1].reference == "rule_b"
    assert set(cond.get_referenced_rules()) == {"rule_a", "rule_b"}


def test_extended_condition_parse_parentheses_or_and():
    """Test explicit grouping with parentheses overrides default precedence."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionAND,
        CorrelationConditionOR,
        SigmaRuleReference,
    )

    cond = SigmaExtendedCorrelationCondition(expression="(rule_a or rule_b) and rule_c")
    assert cond.expression == "(rule_a or rule_b) and rule_c"
    assert cond._parsed is not None
    # Parentheses force OR to bind first: AND(OR(rule_a, rule_b), rule_c)
    assert isinstance(cond._parsed, CorrelationConditionAND)
    assert len(cond._parsed.args) == 2
    # First arg should be OR (grouped by parentheses)
    assert isinstance(cond._parsed.args[0], CorrelationConditionOR)
    assert len(cond._parsed.args[0].args) == 2
    assert cond._parsed.args[0].args[0].reference == "rule_a"
    assert cond._parsed.args[0].args[1].reference == "rule_b"
    # Second arg is rule_c
    assert isinstance(cond._parsed.args[1], SigmaRuleReference)
    assert cond._parsed.args[1].reference == "rule_c"
    assert set(cond.get_referenced_rules()) == {"rule_a", "rule_b", "rule_c"}


def test_extended_condition_parse_parentheses_not():
    """Test parentheses with NOT operator."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionNOT,
        CorrelationConditionOR,
        SigmaRuleReference,
    )

    cond = SigmaExtendedCorrelationCondition(expression="not (rule_a or rule_b)")
    assert cond.expression == "not (rule_a or rule_b)"
    assert cond._parsed is not None
    # NOT of grouped OR: NOT(OR(rule_a, rule_b))
    assert isinstance(cond._parsed, CorrelationConditionNOT)
    assert len(cond._parsed.args) == 1
    # Arg should be OR
    assert isinstance(cond._parsed.args[0], CorrelationConditionOR)
    assert len(cond._parsed.args[0].args) == 2
    assert cond._parsed.args[0].args[0].reference == "rule_a"
    assert cond._parsed.args[0].args[1].reference == "rule_b"
    assert set(cond.get_referenced_rules()) == {"rule_a", "rule_b"}


def test_extended_condition_parse_complex_nested():
    """Test complex nested expression with multiple operators and grouping."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionAND,
        CorrelationConditionOR,
        CorrelationConditionNOT,
        SigmaRuleReference,
    )

    cond = SigmaExtendedCorrelationCondition(
        expression="(rule_a or rule_b) and not (rule_c or rule_d)"
    )
    assert cond.expression == "(rule_a or rule_b) and not (rule_c or rule_d)"
    assert cond._parsed is not None
    # Complex: AND(OR(rule_a, rule_b), NOT(OR(rule_c, rule_d)))
    assert isinstance(cond._parsed, CorrelationConditionAND)
    assert len(cond._parsed.args) == 2
    # First arg: OR(rule_a, rule_b)
    assert isinstance(cond._parsed.args[0], CorrelationConditionOR)
    assert len(cond._parsed.args[0].args) == 2
    assert cond._parsed.args[0].args[0].reference == "rule_a"
    assert cond._parsed.args[0].args[1].reference == "rule_b"
    # Second arg: NOT(OR(rule_c, rule_d))
    assert isinstance(cond._parsed.args[1], CorrelationConditionNOT)
    assert len(cond._parsed.args[1].args) == 1
    assert isinstance(cond._parsed.args[1].args[0], CorrelationConditionOR)
    assert len(cond._parsed.args[1].args[0].args) == 2
    assert cond._parsed.args[1].args[0].args[0].reference == "rule_c"
    assert cond._parsed.args[1].args[0].args[1].reference == "rule_d"
    assert set(cond.get_referenced_rules()) == {"rule_a", "rule_b", "rule_c", "rule_d"}


def test_extended_condition_parse_complex_mixed():
    """Test complex mixed expression with all operators."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionAND,
        CorrelationConditionItem,
    )

    cond = SigmaExtendedCorrelationCondition(
        expression="rule_a and (rule_b or not rule_c) and rule_d"
    )
    assert cond.expression == "rule_a and (rule_b or not rule_c) and rule_d"
    assert cond._parsed is not None
    # Complex mixed expression should parse into proper tree structure
    assert isinstance(cond._parsed, CorrelationConditionItem)
    assert set(cond.get_referenced_rules()) == {"rule_a", "rule_b", "rule_c", "rule_d"}


def test_extended_condition_parse_underscore_identifiers():
    """Test parsing rule identifiers with underscores."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionItem,
    )

    cond = SigmaExtendedCorrelationCondition(expression="rule_a_1 and rule_b_2 or not rule_c_3")
    assert cond.expression == "rule_a_1 and rule_b_2 or not rule_c_3"
    assert cond._parsed is not None
    # Should parse into proper tree structure with underscore identifiers
    assert isinstance(cond._parsed, CorrelationConditionItem)
    assert set(cond.get_referenced_rules()) == {"rule_a_1", "rule_b_2", "rule_c_3"}


def test_extended_condition_parse_multiple_nots():
    """Test multiple NOT operators in sequence."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionAND,
        CorrelationConditionNOT,
        SigmaRuleReference,
    )

    cond = SigmaExtendedCorrelationCondition(expression="not rule_a and not rule_b")
    assert cond.expression == "not rule_a and not rule_b"
    assert cond._parsed is not None
    # Multiple NOTs: AND(NOT(rule_a), NOT(rule_b))
    assert isinstance(cond._parsed, CorrelationConditionAND)
    assert len(cond._parsed.args) == 2
    # First arg: NOT(rule_a)
    assert isinstance(cond._parsed.args[0], CorrelationConditionNOT)
    assert len(cond._parsed.args[0].args) == 1
    assert isinstance(cond._parsed.args[0].args[0], SigmaRuleReference)
    assert cond._parsed.args[0].args[0].reference == "rule_a"
    # Second arg: NOT(rule_b)
    assert isinstance(cond._parsed.args[1], CorrelationConditionNOT)
    assert len(cond._parsed.args[1].args) == 1
    assert isinstance(cond._parsed.args[1].args[0], SigmaRuleReference)
    assert cond._parsed.args[1].args[0].reference == "rule_b"
    assert set(cond.get_referenced_rules()) == {"rule_a", "rule_b"}


def test_extended_condition_parse_deeply_nested():
    """Test deeply nested expression with multiple levels of grouping."""
    from sigma.correlations import (
        SigmaExtendedCorrelationCondition,
        CorrelationConditionItem,
    )

    cond = SigmaExtendedCorrelationCondition(
        expression="((rule_a and rule_b) or (rule_c and rule_d)) and not (rule_e or rule_f)"
    )
    assert (
        cond.expression == "((rule_a and rule_b) or (rule_c and rule_d)) and not (rule_e or rule_f)"
    )
    assert cond._parsed is not None
    # Should parse into proper nested tree structure
    assert isinstance(cond._parsed, CorrelationConditionItem)
    assert set(cond.get_referenced_rules()) == {
        "rule_a",
        "rule_b",
        "rule_c",
        "rule_d",
        "rule_e",
        "rule_f",
    }


# --- Tests for uncovered code paths ---


def test_correlation_condition_invalid_percentile():
    """Test that invalid percentile value raises error."""
    with pytest.raises(SigmaCorrelationConditionError, match="no valid.*percentile"):
        SigmaCorrelationCondition.from_dict(
            {"gte": 10, "field": "testfield", "percentile": "not_a_number"}
        )


def test_correlation_condition_to_dict_with_percentile():
    """Test condition to_dict includes percentile when set."""
    cond = SigmaCorrelationCondition(
        op=SigmaCorrelationConditionOperator.GTE, count=10, fieldref="field1", percentile=95
    )
    d = cond.to_dict()
    assert d["percentile"] == 95
    assert d["field"] == "field1"
    assert d["gte"] == 10


def test_correlation_condition_non_dict_non_string():
    """Test that correlation with non-dict/non-string condition raises error."""
    with pytest.raises(SigmaCorrelationRuleError, match="must be a dict or string"):
        SigmaCorrelationRule.from_yaml(
            """
title: Test correlation
status: test
correlation:
    type: event_count
    rules:
        - test_rule
    timespan: 5m
    condition:
        - invalid
        - list_condition
        """
        )
