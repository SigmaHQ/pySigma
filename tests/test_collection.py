from pathlib import Path
from uuid import UUID
import pytest
from sigma.collection import SigmaCollection, deep_dict_update
from sigma.rule import SigmaRule, SigmaLogSource
from sigma.types import SigmaString
from sigma.exceptions import SigmaCollectionError, SigmaModifierError, SigmaRuleLocation

def test_single_rule():
    rule = {
        "title": "Test",
        "logsource": {
            "category": "test"
        },
        "detection": {
            "test": {
                "field": "value"
            },
            "condition": "test",
        }
    }

    assert SigmaCollection.from_dicts([ rule ]) == SigmaCollection([ SigmaRule.from_dict(rule) ])

def test_merge():
    rules = [
        {
            "title": "Test " + i,
            "logsource": {
                "category": "test"
            },
            "detection": {
                "test": {
                    "field" + i: "value" + i
                },
                "condition": "test",
            }
        }
        for i in ["1", "2"]
    ]

    assert SigmaCollection.merge([
        SigmaCollection.from_dicts([ rules[0] ]),
        SigmaCollection.from_dicts([ rules[1] ]),
    ]) == SigmaCollection([
        SigmaRule.from_dict(rules[0]),
        SigmaRule.from_dict(rules[1]),
    ])

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
            "dict": {
                "key1": "val1"
            },
        },
        {
            "dict": {
                "key2": "val2"
            },
        },
    ) == {
        "dict": {
            "key1": "val1",
            "key2": "val2",
        }
    }

def test_action_global():
    c = SigmaCollection.from_dicts([
        {
            "action": "global",
            "title": "Test",
            "detection": {
                "test": {
                    "field": "value"
                },
                "condition": "test",
            }
        },
        {
            "logsource": {
                "category": "test-1"
            },
        },
        {
            "logsource": {
                "category": "test-2"
            },
        },
    ])
    assert len(c) == 2 \
        and [ r.title for r in c ] == [ "Test", "Test" ] \
        and c[0].detection == c[1].detection \
        and [ r.logsource.category for r in c] == [ "test-1", "test-2" ]

def test_action_reset():
    c = SigmaCollection.from_dicts([
        {
            "title": "Reset Test",
            "action": "global",
            "logsource": {
                "category": "testcat"
            },
        },
        {
            "action": "reset"
        },
        {
            "title": "Test",
            "logsource": {
                "service": "testsvc"
            },
            "detection": {
                "test": {
                    "field": "value"
                },
                "condition": "test",
            }
        },
    ])
    assert len(c) == 1 \
        and c[0].title == "Test" \
        and c[0].logsource == SigmaLogSource(service="testsvc")

def test_action_repeat():
    c = SigmaCollection.from_dicts([
        {
            "title": "Test",
            "logsource": {
                "category": "testcat",
                "service": "svc-1"
            },
            "detection": {
                "test": {
                    "field": "value"
                },
                "condition": "test",
            }
        },
        {
            "action": "repeat",
            "logsource": {
                "service": "svc-2"
            },
        },
    ])
    assert len(c) == 2 \
        and [ r.title for r in c ] == [ "Test", "Test" ] \
        and c[0].detection == c[1].detection \
        and [ r.logsource for r in c] == [ SigmaLogSource(category="testcat", service="svc-1"), SigmaLogSource(category="testcat", service="svc-2") ]

def test_action_repeat_global():
    c = SigmaCollection.from_dicts([
        {
            "action": "global",
            "title": "Test",
            "logsource": {
                "category": "testcat",
                "service": "svc-1"
            },
            "detection": {
                "test": {
                    "field": "value"
                },
                "condition": "test",
            }
        },
        {
            "action": "repeat",
            "logsource": {
                "service": "svc-2"
            },
        },
    ])
    assert len(c) == 1 \
        and c[0].title == "Test" \
        and c[0].logsource == SigmaLogSource(category="testcat", service="svc-2")

def test_action_unknown():
    with pytest.raises(SigmaCollectionError, match="Unknown.*test.yml"):
        SigmaCollection.from_dicts([
            {
                "action": "invalid",
            }
        ], source=SigmaRuleLocation("test.yml"))

def test_action_unknown_collect_errors():
    assert len(SigmaCollection.from_dicts([
        {
            "action": "invalid",
        }
    ], collect_errors=True).errors) > 0

@pytest.fixture
def ruleset():
    return SigmaCollection.load_ruleset([ "tests/files/ruleset" ])

def test_load_ruleset(ruleset):
    assert len(ruleset.rules) == 2

def test_load_ruleset_path():
    assert SigmaCollection.load_ruleset([ Path("tests/files/ruleset") ]).rules == SigmaCollection.load_ruleset([ "tests/files/ruleset" ]).rules

def test_load_ruleset_with_error():
    with pytest.raises(SigmaModifierError, match="Unknown modifier.*test_rule_with_error.yml"):
        SigmaCollection.load_ruleset([ Path("tests/files/ruleset_with_errors") ])

def test_load_ruleset_nolist():
    with pytest.raises(TypeError, match="must be list"):
        SigmaCollection.load_ruleset("tests/files/ruleset")

def test_load_ruleset_onbeforeload():
    def onbeforeload(p):
        if "2" in str(p):
            return None
        else:
            return p
    assert len(SigmaCollection.load_ruleset([ "tests/files/ruleset" ], on_beforeload=onbeforeload).rules) == 1

def test_load_ruleset_onload():
    def onload(p, sc):
        if "2" in str(p):
            return None
        else:
            sc.rules[0].title = "changed"
            return sc
    sigma_collection = SigmaCollection.load_ruleset([ "tests/files/ruleset" ], on_load=onload)
    assert len(sigma_collection.rules) == 1 and sigma_collection.rules[0].title == "changed"

def test_index_rule_by_position(ruleset):
    assert isinstance(ruleset[0], SigmaRule)

def test_index_rule_by_id(ruleset):
    rule_id = "240dbc26-8b19-4f5f-8972-fc3841f4185f"
    assert ruleset[rule_id].id == UUID(rule_id)