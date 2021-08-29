import pytest
from sigma.collection import SigmaCollection, deep_dict_update
from sigma.rule import SigmaRule, SigmaLogSource
from sigma.types import SigmaString
from sigma.exceptions import SigmaCollectionError

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
    with pytest.raises(SigmaCollectionError, match="Unknown"):
        SigmaCollection.from_dicts([
            {
                "action": "invalid",
            }
        ])