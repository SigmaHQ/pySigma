import pytest

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaCollectionError, SigmaDetectionError, SigmaError
from sigma.rule import SigmaRule
from sigma.rule.base import check_alias_expansion


def alias_chain_rule(levels: int) -> str:
    lines = ["title: t", "logsource: {product: x}", "detection:", "  l0: &l0 [{f: v}]"]
    lines += [f"  l{i}: &l{i} [*l{i-1}, *l{i-1}]" for i in range(1, levels + 1)]
    lines.append("  condition: l0")
    return "\n".join(lines)


def test_rule_alias_bomb_rejected():
    # 2^40 detections if expanded - must be rejected before from_definition walks it.
    with pytest.raises(SigmaDetectionError, match="YAML aliases expand"):
        SigmaRule.from_yaml(alias_chain_rule(40))


def test_rule_alias_bomb_collect_errors():
    rule = SigmaRule.from_yaml(alias_chain_rule(40), collect_errors=True)
    assert any(isinstance(e, SigmaDetectionError) for e in rule.errors)


def test_collection_global_alias_bomb_rejected():
    lines = ["action: global", "x:", "  d0: &d0 {a: 1, b: 2}"]
    lines += [f"  d{i}: &d{i} {{a: *d{i-1}, b: *d{i-1}}}" for i in range(1, 41)]
    lines += ["---", "title: t", "logsource: {product: x}", "detection: {s: {f: v}, condition: s}"]
    yaml_str = "\n".join(lines)
    with pytest.raises(SigmaCollectionError, match="YAML aliases expand"):
        SigmaCollection.from_yaml(yaml_str)
    collection = SigmaCollection.from_yaml(yaml_str, collect_errors=True)
    assert any(isinstance(e, SigmaCollectionError) for e in collection.errors)


def test_recursive_structure_rejected():
    recursive: list = []
    recursive.append(recursive)
    with pytest.raises(SigmaError, match="Recursive"):
        check_alias_expansion({"a": recursive})


def test_large_structure_without_aliases_accepted():
    check_alias_expansion({"sel": {"field": [str(i) for i in range(100000)]}})


def test_moderate_alias_reuse_accepted():
    rule = SigmaRule.from_yaml("""
title: t
logsource: {product: x}
detection:
    sel1:
        a: &values [v1, v2, v3]
    sel2:
        b: *values
    condition: sel1 and sel2
""")
    assert len(rule.detection.detections) == 2
    assert [str(v) for v in rule.detection["sel2"].detection_items[0].value] == ["v1", "v2", "v3"]


def test_expansion_limit_configurable():
    shared = list(range(10))
    obj = [shared] * 5  # 40 extra nodes over the unique structure
    check_alias_expansion(obj, max_expansion=100)
    with pytest.raises(SigmaError, match="YAML aliases expand"):
        check_alias_expansion(obj, max_expansion=10)
