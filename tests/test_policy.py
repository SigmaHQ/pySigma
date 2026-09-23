"""Tests for the SigmaPolicy / regex engine infrastructure."""

from __future__ import annotations

import re
import time
import pytest

import sigma
from sigma.policy import SigmaPolicy
from sigma.policy.profiles import SafePolicy, TrustedPolicy
from sigma.policy.regex_engine import PythonRegexEngine, RE2RegexEngine
from sigma.exceptions import SigmaPolicyError

def test_python_engine_compile_and_match() -> None:
    engine = PythonRegexEngine()
    pat = engine.compile(r"foo.*bar")
    assert pat.search("fooXbar")
    assert not pat.search("bazqux")


def test_python_engine_error_type() -> None:
    engine = PythonRegexEngine()
    assert engine.error is re.error


def test_re2_engine_compile_and_match() -> None:
    engine = RE2RegexEngine()
    pat = engine.compile(r"foo.*bar")
    assert pat.search("fooXbar")
    assert not pat.search("bazqux")


def test_re2_engine_fullmatch() -> None:
    engine = RE2RegexEngine()
    pat = engine.compile(r"selection_.*")
    assert pat.fullmatch("selection_main")
    assert not pat.fullmatch("filter_main")


def test_re2_engine_sub() -> None:
    engine = RE2RegexEngine()
    pat = engine.compile(r"ERROR")
    assert pat.sub("WARN", "ERROR in log") == "WARN in log"


def test_redos_poc_completes_instantly_with_safe_policy() -> None:
    """A catastrophically-backtracking pattern must complete in << 1 s under RE2."""
    engine = RE2RegexEngine()
    # 10 stars separated by 'a': 'aa*a*a*a*a*a*a*a*a*a*b' → re2 compiles & matches fine
    pattern = "a" + "a*" * 9 + "b"
    identifier = "a" * 40  # no trailing 'b' — worst case for Python re backtracking
    pat = engine.compile(pattern)
    start = time.monotonic()
    result = pat.fullmatch(identifier)
    elapsed = time.monotonic() - start
    assert result is None  # does not match
    assert elapsed < 0.5, f"RE2 took too long ({elapsed:.3f}s) — ReDoS not mitigated"


def test_default_policy_is_safe_policy() -> None:
    assert sigma.default_policy is SafePolicy


def test_default_policy_uses_re2_engine() -> None:
    assert isinstance(sigma.default_policy.regex_engine, RE2RegexEngine)


def test_set_default_policy_to_trusted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sigma, "default_policy", TrustedPolicy)
    assert sigma.default_policy is TrustedPolicy
    assert isinstance(sigma.default_policy.regex_engine, PythonRegexEngine)


def test_processing_pipeline_stores_policy() -> None:
    from sigma.processing.pipeline import ProcessingPipeline

    p = ProcessingPipeline(policy=TrustedPolicy)
    assert p.policy is TrustedPolicy


def test_processing_pipeline_default_policy_is_none() -> None:
    from sigma.processing.pipeline import ProcessingPipeline

    p = ProcessingPipeline()
    assert p.policy is None


def test_processing_pipeline_from_yaml_accepts_policy() -> None:
    from sigma.processing.pipeline import ProcessingPipeline

    yaml_str = """
name: test
transformations: []
"""
    p = ProcessingPipeline.from_yaml(yaml_str, policy=TrustedPolicy)
    assert p.policy is TrustedPolicy


def test_processing_pipeline_add_preserves_policy() -> None:
    from sigma.processing.pipeline import ProcessingPipeline

    p1 = ProcessingPipeline(policy=TrustedPolicy)
    p2 = ProcessingPipeline()
    merged = p1 + p2
    assert merged.policy is TrustedPolicy


def test_processing_pipeline_add_raises_on_policy_mismatch() -> None:
    from sigma.processing.pipeline import ProcessingPipeline

    p1 = ProcessingPipeline(policy=TrustedPolicy)
    p2 = ProcessingPipeline(policy=SafePolicy)
    with pytest.raises(SigmaPolicyError):
        _ = p1 + p2


def test_match_string_condition_uses_pipeline_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """MatchStringCondition must compile with pipeline's policy engine, not the global."""
    from sigma.processing.conditions.values import MatchStringCondition
    from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
    from sigma.processing.transformations.state import SetStateTransformation

    # Build a processing item with TrustedPolicy so the compiled _re uses Python re
    item = ProcessingItem(
        transformation=SetStateTransformation(key="x", val="y"),
        policy=TrustedPolicy,
    )
    cond = MatchStringCondition(cond="any", pattern=r"foo.*")
    cond.set_pipeline(
        ProcessingPipeline(
            items=[item],
            policy=TrustedPolicy,
        )
    )
    compiled = cond.compile_regex(cond.pattern)
    # Python re patterns have a specific type
    assert isinstance(compiled, re.Pattern)


SIMPLE_RULE = """
title: Test
status: test
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"""


def test_sigma_rule_from_yaml_accepts_policy() -> None:
    from sigma.rule import SigmaRule

    rule = SigmaRule.from_yaml(SIMPLE_RULE, policy=TrustedPolicy)
    assert rule.policy is TrustedPolicy


def test_sigma_rule_policy_propagates_to_detections() -> None:
    from sigma.rule import SigmaRule

    rule = SigmaRule.from_yaml(SIMPLE_RULE, policy=TrustedPolicy)
    assert rule.detection.policy is TrustedPolicy


def test_sigma_collection_from_yaml_accepts_policy() -> None:
    from sigma.collection import SigmaCollection

    coll = SigmaCollection.from_yaml(SIMPLE_RULE, policy=TrustedPolicy)
    assert coll.rules[0].policy is TrustedPolicy  # type: ignore[union-attr]


def test_condition_selector_uses_detections_policy() -> None:
    """ConditionSelector.resolve_referenced_detections should use the detections' policy."""
    from sigma.conditions import ConditionSelector
    from sigma.rule import SigmaRule

    rule_yaml = """
title: Test
status: test
logsource:
    category: test
detection:
    selection_a:
        field: value1
    selection_b:
        field: value2
    condition: 1 of selection_*
"""
    rule = SigmaRule.from_yaml(rule_yaml, policy=TrustedPolicy)
    # Parse the condition — this will call resolve_referenced_detections
    parsed = rule.detection.parsed_condition[0].parse()
    assert parsed is not None
