import pytest
from sigma.exceptions import SigmaPipelineConditionError
from sigma.processing.condition_expressions import (
    ConditionOR,
    ConditionAND,
    ConditionIdentifier,
    ConditionNOT,
    parse_condition_expression,
)
from tests.test_processing_pipeline import (
    RuleConditionFalse,
    RuleConditionTrue,
    DetectionItemConditionFalse,
    DetectionItemConditionTrue,
    FieldNameConditionFalse,
    FieldNameConditionTrue,
)
from tests.test_rule import sigma_rule, detection_item


def test_pipeline_condition_expression_identifier(sigma_rule):
    conditions = {
        "cond1": RuleConditionTrue(dummy="test-true"),
    }
    condition_expression = "cond1"
    result = parse_condition_expression(condition_expression, conditions)
    assert result == ConditionIdentifier(0, "cond1")
    assert result.match(sigma_rule)


def test_pipeline_condition_expression_identifier_not_found():
    conditions = {
        "cond1": RuleConditionTrue(dummy="test-true"),
    }
    condition_expression = "cond2"
    with pytest.raises(SigmaPipelineConditionError, match="cond2.*not found"):
        parse_condition_expression(condition_expression, conditions)


def test_pipeline_condition_expression_and(sigma_rule):
    conditions = {
        "cond1": RuleConditionTrue(dummy="test-true"),
        "cond2": RuleConditionFalse(dummy="test-false"),
    }
    condition_expression = "cond1 and cond2"
    result = parse_condition_expression(condition_expression, conditions)
    assert result == ConditionAND(
        0, ConditionIdentifier(0, "cond1"), ConditionIdentifier(10, "cond2")
    )
    assert not result.match(sigma_rule)


def test_pipeline_condition_expression_or(sigma_rule):
    conditions = {
        "cond1": RuleConditionTrue(dummy="test-true"),
        "cond2": RuleConditionFalse(dummy="test-false"),
    }
    condition_expression = "cond1 or cond2"
    result = parse_condition_expression(condition_expression, conditions)
    assert result == ConditionOR(
        0, ConditionIdentifier(0, "cond1"), ConditionIdentifier(9, "cond2")
    )
    assert result.match(sigma_rule)


def test_pipeline_condition_expression_not(sigma_rule):
    conditions = {
        "cond1": RuleConditionFalse(dummy="test-false"),
    }
    condition_expression = "not cond1"
    result = parse_condition_expression(condition_expression, conditions)
    assert result == ConditionNOT(0, ConditionIdentifier(4, "cond1"))
    assert result.match(sigma_rule)


def test_pipeline_condition_expression_precedence(sigma_rule):
    conditions = {
        "cond1": RuleConditionTrue(dummy="test-true"),
        "cond2": RuleConditionFalse(dummy="test-false"),
        "cond3": RuleConditionTrue(dummy="test-false"),
    }
    condition_expression = "cond1 and not cond2 or cond3"
    result = parse_condition_expression(condition_expression, conditions)
    assert result == ConditionOR(
        0,
        ConditionAND(
            0, ConditionIdentifier(0, "cond1"), ConditionNOT(10, ConditionIdentifier(14, "cond2"))
        ),
        ConditionIdentifier(23, "cond3"),
    )
    assert result.match(sigma_rule)


def test_pipeline_condition_expression_match_detection_item(detection_item):
    conditions = {
        "cond1": DetectionItemConditionTrue(dummy="test-true"),
        "cond2": DetectionItemConditionFalse(dummy="test-false"),
        "cond3": DetectionItemConditionTrue(dummy="test-false"),
    }
    condition_expression = "cond1 and not cond2 or cond3"
    result = parse_condition_expression(condition_expression, conditions)
    assert result.match(detection_item)


def test_pipeline_condition_expression_match_field_name(detection_item):
    conditions = {
        "cond1": FieldNameConditionTrue(dummy="test-true"),
        "cond2": FieldNameConditionFalse(dummy="test-false"),
        "cond3": FieldNameConditionTrue(dummy="test-false"),
    }
    condition_expression = "cond1 and not cond2 or cond3"
    result = parse_condition_expression(condition_expression, conditions)
    assert result.match_detection_item(detection_item)
    assert result.match_field_name("test")


def test_pipeline_condition_expression_invalid():
    with pytest.raises(SigmaPipelineConditionError, match="Error parsing"):
        parse_condition_expression("cond1 and", {})


def test_pipeline_condition_expression_unreferenced(sigma_rule):
    conditions = {
        "cond1": RuleConditionTrue(dummy="test-true"),
        "cond2": RuleConditionFalse(dummy="test-false"),
        "cond3": RuleConditionTrue(dummy="test-false"),
    }
    with pytest.raises(SigmaPipelineConditionError, match="unreferenced"):
        parse_condition_expression("cond1 and cond2", conditions)
