from pathlib import Path
from uuid import UUID
import pytest
from sigma.collection import SigmaCollection, deep_dict_update
from sigma.correlations import (
    SigmaCorrelationRule,
    SigmaCorrelationTimespan,
    SigmaCorrelationType,
    SigmaRuleReference,
)
from sigma.rule import SigmaRule, SigmaLogSource
from sigma.types import SigmaString
from sigma.exceptions import (
    SigmaCollectionError,
    SigmaModifierError,
    SigmaRuleLocation,
    SigmaError,
    SigmaRuleNotFoundError,
)


def test_single_rule():
    rule = {
        "title": "Test",
        "logsource": {"category": "test"},
        "detection": {
            "test": {"field": "value"},
            "condition": "test",
        },
    }

    assert SigmaCollection.from_dicts([rule]) == SigmaCollection([SigmaRule.from_dict(rule)])


def test_merge():
    rules = [
        {
            "title": "Test " + i,
            "logsource": {"category": "test"},
            "detection": {
                "test": {"field" + i: "value" + i},
                "condition": "test",
            },
        }
        for i in ["1", "2"]
    ]

    collection_1 = SigmaCollection.from_dicts([rules[0]])
    collection_1.errors = [SigmaError("Test Error 1")]
    collection_2 = SigmaCollection.from_dicts([rules[1]])
    collection_2.errors = [SigmaError("Test Error 2")]
    assert SigmaCollection.merge(
        [
            collection_1,
            collection_2,
        ]
    ) == SigmaCollection(
        [
            SigmaRule.from_dict(rules[0]),
            SigmaRule.from_dict(rules[1]),
        ],
        errors=[
            SigmaError("Test Error 1"),
            SigmaError("Test Error 2"),
        ],
    )


def test_deep_dict_update_disjunct():
    assert deep_dict_update(
        {
            "key1": "val1",
        },
        {
            "key2": "val2",
        },
    ) == {
        "key1": "val1",
        "key2": "val2",
    }


def test_deep_dict_update_overwrite():
    assert deep_dict_update(
        {
            "key": "val1",
        },
        {
            "key": "val2",
        },
    ) == {
        "key": "val2",
    }


def test_deep_dict_update_subdict():
    assert deep_dict_update(
        {
            "dict": {"key1": "val1"},
        },
        {
            "dict": {"key2": "val2"},
        },
    ) == {
        "dict": {
            "key1": "val1",
            "key2": "val2",
        }
    }


def test_action_global():
    c = SigmaCollection.from_dicts(
        [
            {
                "action": "global",
                "title": "Test",
                "detection": {
                    "test": {"field": "value"},
                    "condition": "test",
                },
            },
            {
                "logsource": {"category": "test-1"},
            },
            {
                "logsource": {"category": "test-2"},
            },
        ]
    )
    assert (
        len(c) == 2
        and [r.title for r in c] == ["Test", "Test"]
        and c[0].detection == c[1].detection
        and [r.logsource.category for r in c] == ["test-1", "test-2"]
    )


def test_action_reset():
    c = SigmaCollection.from_dicts(
        [
            {
                "title": "Reset Test",
                "action": "global",
                "logsource": {"category": "testcat"},
            },
            {"action": "reset"},
            {
                "title": "Test",
                "logsource": {"service": "testsvc"},
                "detection": {
                    "test": {"field": "value"},
                    "condition": "test",
                },
            },
        ]
    )
    assert (
        len(c) == 1 and c[0].title == "Test" and c[0].logsource == SigmaLogSource(service="testsvc")
    )


def test_action_repeat():
    c = SigmaCollection.from_dicts(
        [
            {
                "title": "Test",
                "logsource": {"category": "testcat", "service": "svc-1"},
                "detection": {
                    "test": {"field": "value"},
                    "condition": "test",
                },
            },
            {
                "action": "repeat",
                "logsource": {"service": "svc-2"},
            },
        ]
    )
    assert (
        len(c) == 2
        and [r.title for r in c] == ["Test", "Test"]
        and c[0].detection == c[1].detection
        and [r.logsource for r in c]
        == [
            SigmaLogSource(category="testcat", service="svc-1"),
            SigmaLogSource(category="testcat", service="svc-2"),
        ]
    )


def test_action_repeat_global():
    c = SigmaCollection.from_dicts(
        [
            {
                "action": "global",
                "title": "Test",
                "logsource": {"category": "testcat", "service": "svc-1"},
                "detection": {
                    "test": {"field": "value"},
                    "condition": "test",
                },
            },
            {
                "action": "repeat",
                "logsource": {"service": "svc-2"},
            },
        ]
    )
    assert (
        len(c) == 1
        and c[0].title == "Test"
        and c[0].logsource == SigmaLogSource(category="testcat", service="svc-2")
    )


def test_action_unknown():
    with pytest.raises(SigmaCollectionError, match="Unknown.*test.yml"):
        SigmaCollection.from_dicts(
            [
                {
                    "action": "invalid",
                }
            ],
            source=SigmaRuleLocation("test.yml"),
        )


def test_action_unknown_collect_errors():
    assert (
        len(
            SigmaCollection.from_dicts(
                [
                    {
                        "action": "invalid",
                    }
                ],
                collect_errors=True,
            ).errors
        )
        > 0
    )


@pytest.fixture
def ruleset():
    return SigmaCollection.load_ruleset(["tests/files/ruleset"])


def test_load_ruleset(ruleset):
    assert len(ruleset.rules) == 2


def test_load_ruleset_path():
    assert (
        SigmaCollection.load_ruleset([Path("tests/files/ruleset")]).rules
        == SigmaCollection.load_ruleset(["tests/files/ruleset"]).rules
    )


def test_load_ruleset_with_error():
    with pytest.raises(SigmaModifierError, match="Unknown modifier.*test_rule_with_error.yml"):
        SigmaCollection.load_ruleset([Path("tests/files/ruleset_with_errors")])


def test_load_ruleset_nolist():
    with pytest.raises(TypeError, match="must be list"):
        SigmaCollection.load_ruleset("tests/files/ruleset")


def test_load_ruleset_onbeforeload():
    def onbeforeload(p):
        if "2" in str(p):
            return None
        else:
            return p

    assert (
        len(SigmaCollection.load_ruleset(["tests/files/ruleset"], on_beforeload=onbeforeload).rules)
        == 1
    )


def test_load_ruleset_onload():
    def onload(p, sc):
        if "2" in str(p):
            return None
        else:
            sc.rules[0].title = "changed"
            return sc

    sigma_collection = SigmaCollection.load_ruleset(["tests/files/ruleset"], on_load=onload)
    assert len(sigma_collection.rules) == 1 and sigma_collection.rules[0].title == "changed"


def test_index_rule_by_position(ruleset):
    assert isinstance(ruleset[0], SigmaRule)


def test_index_rule_by_position_not_existing(ruleset):
    with pytest.raises(
        SigmaRuleNotFoundError, match="Rule at position 2 not found in rule collection"
    ):
        ruleset[2]


def test_index_rule_by_id(ruleset):
    rule_id = "240dbc26-8b19-4f5f-8972-fc3841f4185f"
    assert ruleset[rule_id].id == UUID(rule_id)
    assert ruleset[UUID(rule_id)].id == UUID(rule_id)


def test_index_rule_by_name(ruleset):
    assert ruleset["test_rule"].name == "test_rule"


def test_index_rule_by_name_not_existing(ruleset):
    with pytest.raises(
        SigmaRuleNotFoundError, match="Rule 'test_rule_not_existing' not found in rule collection"
    ):
        ruleset["test_rule_not_existing"]


@pytest.fixture
def rules_with_correlation():
    return SigmaCollection.from_yaml(
        """
title: Rule 1
name: rule-1
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ImageFile|endswith: '\\\\a.exe'
    condition: selection
---
title: Rule 2
name: rule-2
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ImageFile|endswith: '\\\\b.exe'
    condition: selection
---
title: Correlating 1+2
name: corr-1-2
correlation:
    type: temporal
    rules:
        - rule-1
        - rule-2
    group-by: user
    timespan: 5m
"""
    )


def test_load_ruleset_with_correlation(rules_with_correlation):
    assert len(rules_with_correlation.rules) == 3
    correlation_rule = rules_with_correlation.rules[2]
    assert correlation_rule == SigmaCorrelationRule(
        title="Correlating 1+2",
        name="corr-1-2",
        type=SigmaCorrelationType.TEMPORAL,
        rules=[SigmaRuleReference("rule-1"), SigmaRuleReference("rule-2")],
        group_by=["user"],
        timespan=SigmaCorrelationTimespan("5m"),
    )
    assert correlation_rule.rules[0].rule == rules_with_correlation.rules[0]


def test_load_ruleset_with_correlation_referencing_nonexistent_rule():
    with pytest.raises(SigmaRuleNotFoundError, match="Rule 'rule-2' not found in rule collection"):
        SigmaCollection.from_yaml(
            """
title: Rule 1
name: rule-1
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ImageFile|endswith: '\\\\a.exe'
    condition: selection
---
title: Correlating 1+2
name: corr-1-2
correlation:
    type: temporal
    rules:
        - rule-1
        - rule-2
    group-by: user
    timespan: 5m
"""
        )
