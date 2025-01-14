import inspect
from typing import cast
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.types import SigmaNull, SigmaNumber, SigmaString
from sigma import processing
from sigma.exceptions import SigmaConfigurationError, SigmaRegularExpressionError
import pytest
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.conditions import (
    ContainsWildcardCondition,
    DetectionItemProcessingCondition,
    DetectionItemProcessingItemAppliedCondition,
    DetectionItemProcessingStateCondition,
    FieldNameProcessingCondition,
    FieldNameProcessingItemAppliedCondition,
    FieldNameProcessingStateCondition,
    IsNullCondition,
    IsSigmaCorrelationRuleCondition,
    IsSigmaRuleCondition,
    LogsourceCondition,
    IncludeFieldCondition,
    ExcludeFieldCondition,
    MatchStringCondition,
    ProcessingCondition,
    RuleContainsDetectionItemCondition,
    RuleContainsFieldCondition,
    RuleProcessingCondition,
    RuleProcessingItemAppliedCondition,
    RuleAttributeCondition,
    RuleProcessingStateCondition,
    RuleTagCondition,
)
from sigma.rule import SigmaDetectionItem, SigmaLogSource, SigmaRule
from tests.test_processing_pipeline import processing_item
from tests.test_processing_transformations import sigma_correlation_rule
from sigma.processing.conditions import (
    rule_conditions,
    detection_item_conditions,
    field_name_conditions,
)


@pytest.fixture
def dummy_processing_pipeline():
    return ProcessingPipeline()


@pytest.fixture
def detection_item():
    return SigmaDetectionItem("field", [], [SigmaString("value")])


@pytest.fixture
def detection_item_null_value():
    return SigmaDetectionItem("field", [], [SigmaNull()])


@pytest.fixture
def detection_item_nofield():
    return SigmaDetectionItem(None, [], [SigmaString("value")])


@pytest.fixture
def sigma_rule():
    return SigmaRule.from_yaml(
        """
        title: Test
        id: 809718e3-f7f5-46f1-931e-d036f0ffb0af
        related:
        - id: 08fbc97d-0a2f-491c-ae21-8ffcfd3174e9
          type: derived
        status: test
        taxonomy: test
        date: 2022-02-22
        logsource:
            category: test_category
            product: test_product
        detection:
            sel:
                fieldA:
                    - value
                    - 123
            condition: sel
        tags:
            - test.tag
        level: medium
        custom: 123
    """
    )


def test_logsource_match(dummy_processing_pipeline, sigma_rule):
    assert LogsourceCondition(category="test_category").match(
        dummy_processing_pipeline,
        sigma_rule,
    )


def test_logsource_no_match(dummy_processing_pipeline, sigma_rule):
    assert not LogsourceCondition(category="test_category", product="other_product").match(
        dummy_processing_pipeline,
        sigma_rule,
    )


def test_logsource_match_correlation_rule_cat(dummy_processing_pipeline, sigma_correlated_rules):
    sigma_correlated_rules.resolve_rule_references()
    assert LogsourceCondition(category="test_category").match(
        dummy_processing_pipeline,
        cast(SigmaCorrelationRule, sigma_correlated_rules.rules[-1]),
    )


def test_logsource_match_correlation_rule_prod(dummy_processing_pipeline, sigma_correlated_rules):
    sigma_correlated_rules.resolve_rule_references()
    assert LogsourceCondition(product="test_product").match(
        dummy_processing_pipeline,
        cast(SigmaCorrelationRule, sigma_correlated_rules.rules[-1]),
    )


def test_logsource_no_match_correlation_rule_both(
    dummy_processing_pipeline, sigma_correlated_rules
):
    sigma_correlated_rules.resolve_rule_references()
    assert not LogsourceCondition(category="test_category", product="test_product").match(
        dummy_processing_pipeline,
        cast(SigmaCorrelationRule, sigma_correlated_rules.rules[-1]),
    )


def test_logsource_no_match_correlation_rule(dummy_processing_pipeline, sigma_correlated_rules):
    sigma_correlated_rules.resolve_rule_references()
    assert not LogsourceCondition(service="test_service").match(
        dummy_processing_pipeline,
        cast(SigmaCorrelationRule, sigma_correlated_rules.rules[-1]),
    )


def test_logsource_no_rule_correlation_rule(dummy_processing_pipeline, sigma_correlation_rule):
    assert not LogsourceCondition(category="test_category", product="other_product").match(
        dummy_processing_pipeline,
        sigma_correlation_rule,
    )


from tests.test_processing_pipeline import processing_item


def test_rule_processing_item_applied(
    dummy_processing_pipeline, processing_item, sigma_rule: SigmaRule
):
    sigma_rule.add_applied_processing_item(processing_item)
    assert RuleProcessingItemAppliedCondition(processing_item_id="test").match(
        dummy_processing_pipeline,
        sigma_rule,
    )


def test_rule_processing_item_not_applied(dummy_processing_pipeline, sigma_rule: SigmaRule):
    assert not RuleProcessingItemAppliedCondition(processing_item_id="test").match(
        dummy_processing_pipeline,
        sigma_rule,
    )


def test_rule_state_match(dummy_processing_pipeline, sigma_rule):
    dummy_processing_pipeline.state["key"] = "value"
    dummy_processing_pipeline.state["number"] = 123
    assert RuleProcessingStateCondition("key", "value").match(dummy_processing_pipeline, sigma_rule)
    assert RuleProcessingStateCondition("key", "other_value", "ne").match(
        dummy_processing_pipeline, sigma_rule
    )
    assert RuleProcessingStateCondition("number", 123, "gte").match(
        dummy_processing_pipeline, sigma_rule
    )
    assert RuleProcessingStateCondition("number", 123, "lte").match(
        dummy_processing_pipeline, sigma_rule
    )
    assert RuleProcessingStateCondition("number", 122, "gt").match(
        dummy_processing_pipeline, sigma_rule
    )
    assert RuleProcessingStateCondition("number", 124, "lt").match(
        dummy_processing_pipeline, sigma_rule
    )


def test_rule_state_nomatch(dummy_processing_pipeline, sigma_rule):
    dummy_processing_pipeline.state["key"] = "value"
    assert not RuleProcessingStateCondition("key", "other_value").match(
        dummy_processing_pipeline, sigma_rule
    )


def test_rule_processing_item_applied_correlation_rule(
    dummy_processing_pipeline, processing_item, sigma_correlation_rule
):
    assert not RuleProcessingItemAppliedCondition(processing_item_id="test").match(
        dummy_processing_pipeline,
        sigma_correlation_rule,
    )
    sigma_correlation_rule.add_applied_processing_item(processing_item)
    assert RuleProcessingItemAppliedCondition(processing_item_id="test").match(
        dummy_processing_pipeline,
        sigma_correlation_rule,
    )


def test_rule_contains_detection_item_match(sigma_rule, dummy_processing_pipeline):
    assert RuleContainsDetectionItemCondition(field="fieldA", value="value").match(
        dummy_processing_pipeline, sigma_rule
    )


def test_rule_contains_detection_item_nomatch_field(sigma_rule, dummy_processing_pipeline):
    assert not RuleContainsDetectionItemCondition(field="fieldB", value="value").match(
        dummy_processing_pipeline, sigma_rule
    )


def test_rule_contains_detection_item_nomatch_value(sigma_rule, dummy_processing_pipeline):
    assert not RuleContainsDetectionItemCondition(field="fieldA", value="valuex").match(
        dummy_processing_pipeline, sigma_rule
    )


def test_rule_contains_detection_item_correlation_rule(
    sigma_correlation_rule, dummy_processing_pipeline
):
    assert not RuleContainsDetectionItemCondition(field="fieldA", value="value").match(
        dummy_processing_pipeline, sigma_correlation_rule
    )


def test_rule_contains_field_match(dummy_processing_pipeline, sigma_rule):
    assert RuleContainsFieldCondition("fieldA").match(dummy_processing_pipeline, sigma_rule)


def test_rule_contains_field_nomatch(dummy_processing_pipeline, sigma_rule):
    assert not RuleContainsFieldCondition("non_existing").match(
        dummy_processing_pipeline, sigma_rule
    )


def test_rule_contains_field_correlation_rule(dummy_processing_pipeline, sigma_correlation_rule):
    assert not RuleContainsFieldCondition("fieldA").match(
        dummy_processing_pipeline, sigma_correlation_rule
    )


def test_is_sigma_rule_with_rule(dummy_processing_pipeline, sigma_rule):
    assert IsSigmaRuleCondition().match(dummy_processing_pipeline, sigma_rule)


def test_is_sigma_rule_with_correlation_rule(dummy_processing_pipeline, sigma_correlation_rule):
    assert not IsSigmaRuleCondition().match(dummy_processing_pipeline, sigma_correlation_rule)


def test_is_sigma_correlation_rule_with_correlation_rule(
    dummy_processing_pipeline, sigma_correlation_rule
):
    assert IsSigmaCorrelationRuleCondition().match(
        dummy_processing_pipeline, sigma_correlation_rule
    )


def test_is_sigma_correlation_rule_with_rule(dummy_processing_pipeline, sigma_rule):
    assert not IsSigmaCorrelationRuleCondition().match(dummy_processing_pipeline, sigma_rule)


def test_rule_attribute_condition_str_match(dummy_processing_pipeline, sigma_rule):
    assert RuleAttributeCondition("taxonomy", "test").match(dummy_processing_pipeline, sigma_rule)


def test_rule_attribute_condition_invalid_str_op(dummy_processing_pipeline, sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="Invalid operation.*for string"):
        RuleAttributeCondition("taxonomy", "test", "gte").match(
            dummy_processing_pipeline, sigma_rule
        )


def test_rule_attribute_condition_invalid_op(dummy_processing_pipeline, sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="Invalid operation"):
        RuleAttributeCondition("custom", "123.4", "invalid")


def test_rule_attribute_condition_uuid_match(dummy_processing_pipeline, sigma_rule):
    assert RuleAttributeCondition("id", "809718e3-f7f5-46f1-931e-d036f0ffb0af").match(
        dummy_processing_pipeline, sigma_rule
    )


def test_rule_attribute_condition_custom_field_numeric_match(dummy_processing_pipeline, sigma_rule):
    assert RuleAttributeCondition("custom", "123.4", "lte").match(
        dummy_processing_pipeline, sigma_rule
    )


def test_rule_attribute_condition_invalid_numeric_value(dummy_processing_pipeline, sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="Invalid number"):
        RuleAttributeCondition("custom", "something", "lte").match(
            dummy_processing_pipeline, sigma_rule
        )


def test_rule_attribute_condition_date_match(dummy_processing_pipeline, sigma_rule):
    assert RuleAttributeCondition("date", "2022-02-23", "lt").match(
        dummy_processing_pipeline, sigma_rule
    )


def test_rule_attribute_condition_invalid_date(dummy_processing_pipeline, sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="Invalid date"):
        RuleAttributeCondition("date", "2022-02-23T00:00:00", "lt").match(
            dummy_processing_pipeline, sigma_rule
        )


def test_rule_attribute_condition_sigmalevel_match(dummy_processing_pipeline, sigma_rule):
    assert RuleAttributeCondition("level", "high", "lt").match(
        dummy_processing_pipeline, sigma_rule
    )


def test_rule_attribute_condition_invalid_sigmalevel(dummy_processing_pipeline, sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="Invalid Sigma severity level"):
        RuleAttributeCondition("level", "invalid", "lt").match(
            dummy_processing_pipeline, sigma_rule
        )


def test_rule_attribute_condition_sigmastatus_match(dummy_processing_pipeline, sigma_rule):
    assert RuleAttributeCondition("status", "stable", "lt").match(
        dummy_processing_pipeline, sigma_rule
    )


def test_rule_attribute_condition_invalid_sigmastatus(dummy_processing_pipeline, sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="Invalid Sigma status"):
        RuleAttributeCondition("status", "invalid", "lt").match(
            dummy_processing_pipeline, sigma_rule
        )


def test_rule_attribute_condition_invalid_rule_field_type(dummy_processing_pipeline, sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="Unsupported type"):
        RuleAttributeCondition("related", "08fbc97d-0a2f-491c-ae21-8ffcfd3174e9").match(
            dummy_processing_pipeline, sigma_rule
        )


def test_rule_tag_condition_match(dummy_processing_pipeline, sigma_rule):
    assert RuleTagCondition("test.tag").match(dummy_processing_pipeline, sigma_rule)


def test_rule_tag_condition_nomatch(dummy_processing_pipeline, sigma_rule):
    assert not RuleTagCondition("test.notag").match(dummy_processing_pipeline, sigma_rule)


def test_include_field_condition_match(dummy_processing_pipeline, detection_item):
    assert IncludeFieldCondition(["field", "otherfield"]).match_field_name(
        dummy_processing_pipeline, "field"
    )


def test_include_field_condition_match_nofield(dummy_processing_pipeline, detection_item_nofield):
    assert not IncludeFieldCondition(["field", "otherfield"]).match_field_name(
        dummy_processing_pipeline, None
    )


def test_include_field_condition_nomatch(dummy_processing_pipeline, detection_item):
    assert not IncludeFieldCondition(["testfield", "otherfield"]).match_field_name(
        dummy_processing_pipeline, "field"
    )


def test_include_field_condition_re_match(dummy_processing_pipeline, detection_item):
    assert IncludeFieldCondition(["o[0-9]+", "f.*"], "re").match_field_name(
        dummy_processing_pipeline, "field"
    )


def test_include_field_condition_re_match_nofield(
    dummy_processing_pipeline, detection_item_nofield
):
    assert not IncludeFieldCondition(["o[0-9]+", "f.*"], "re").match_field_name(
        dummy_processing_pipeline, None
    )


def test_include_field_condition_re_nomatch(dummy_processing_pipeline, detection_item):
    assert not IncludeFieldCondition(["o[0-9]+", "x.*"], "re").match_field_name(
        dummy_processing_pipeline, "field"
    )


def test_include_field_condition_wrong_type(dummy_processing_pipeline, detection_item):
    with pytest.raises(SigmaConfigurationError, match="Invalid.*type"):
        IncludeFieldCondition(["field", "otherfield"], "invalid")


def test_exclude_field_condition_match(dummy_processing_pipeline, detection_item):
    assert (
        ExcludeFieldCondition(["field", "otherfield"]).match_field_name(
            dummy_processing_pipeline, "field"
        )
        == False
    )


def test_exclude_field_condition_nomatch(dummy_processing_pipeline, detection_item):
    assert (
        ExcludeFieldCondition(["testfield", "otherfield"]).match_field_name(
            dummy_processing_pipeline, "field"
        )
        == True
    )


def test_exclude_field_condition_re_match(dummy_processing_pipeline, detection_item):
    assert (
        ExcludeFieldCondition(["o[0-9]+", "f.*"], "re").match_field_name(
            dummy_processing_pipeline, "field"
        )
        == False
    )


def test_exclude_field_condition_re_nomatch(dummy_processing_pipeline, detection_item):
    assert (
        ExcludeFieldCondition(["o[0-9]+", "x.*"], "re").match_field_name(
            dummy_processing_pipeline, "field"
        )
        == True
    )


def test_field_state_condition_match(dummy_processing_pipeline):
    dummy_processing_pipeline.state["field"] = "value"
    assert FieldNameProcessingStateCondition("field", "value").match_field_name(
        dummy_processing_pipeline, "field"
    )


@pytest.fixture
def multivalued_detection_item():
    return SigmaDetectionItem("field", [], [SigmaString("value"), SigmaNumber(123)])


def test_match_string_condition_any(
    dummy_processing_pipeline, multivalued_detection_item: SigmaDetectionItem
):
    assert (
        MatchStringCondition(pattern="^val.*", cond="any").match(
            dummy_processing_pipeline, multivalued_detection_item
        )
        == True
    )


def test_match_string_condition_all(
    dummy_processing_pipeline, multivalued_detection_item: SigmaDetectionItem
):
    assert (
        MatchStringCondition(pattern="^val.*", cond="all").match(
            dummy_processing_pipeline, multivalued_detection_item
        )
        == False
    )


def test_match_string_condition_all_sametype(dummy_processing_pipeline):
    assert (
        MatchStringCondition(pattern="^val.*", cond="all").match(
            dummy_processing_pipeline,
            SigmaDetectionItem("field", [], [SigmaString("val1"), SigmaString("val2")]),
        )
        == True
    )


def test_match_string_condition_all_negated(dummy_processing_pipeline):
    assert (
        MatchStringCondition(pattern="^val.*", cond="all", negate=True).match(
            dummy_processing_pipeline,
            SigmaDetectionItem("field", [], [SigmaString("val1"), SigmaString("val2")]),
        )
        == False
    )


def test_match_string_condition_error_mode():
    with pytest.raises(SigmaConfigurationError, match="parameter is invalid"):
        MatchStringCondition(pattern="x", cond="test")


def test_match_string_condition_error_mode():
    with pytest.raises(SigmaRegularExpressionError, match="is invalid"):
        MatchStringCondition(pattern="*", cond="any")


def test_contains_wildcard_condition_match(dummy_processing_pipeline):
    assert ContainsWildcardCondition(cond="any").match(
        dummy_processing_pipeline, SigmaDetectionItem("field", [], [SigmaString("*")])
    )


def test_contains_wildcard_condition_nomatch(dummy_processing_pipeline):
    assert not ContainsWildcardCondition(cond="any").match(
        dummy_processing_pipeline, SigmaDetectionItem("field", [], [SigmaString("value")])
    )


def test_contains_wildcard_condition_nostring(dummy_processing_pipeline):
    assert not ContainsWildcardCondition(cond="any").match(
        dummy_processing_pipeline, SigmaDetectionItem("field", [], [SigmaNumber(123)])
    )


def test_isnull_condition_match(dummy_processing_pipeline, detection_item_null_value):
    assert IsNullCondition(cond="all").match(dummy_processing_pipeline, detection_item_null_value)


def test_isnull_condition_nomatch(dummy_processing_pipeline, detection_item):
    assert not IsNullCondition(cond="all").match(dummy_processing_pipeline, detection_item)


def test_value_processing_invalid_cond():
    with pytest.raises(SigmaConfigurationError, match="The value.*cond"):
        MatchStringCondition(pattern="^val.*", cond="invalid")


def test_detection_item_processing_item_applied(
    dummy_processing_pipeline, processing_item, detection_item: SigmaDetectionItem
):
    detection_item.add_applied_processing_item(processing_item)
    assert DetectionItemProcessingItemAppliedCondition(processing_item_id="test").match(
        dummy_processing_pipeline,
        detection_item,
    )


def test_detection_item_processing_item_not_applied(
    dummy_processing_pipeline, processing_item, detection_item: SigmaDetectionItem
):
    assert not DetectionItemProcessingItemAppliedCondition(processing_item_id="test").match(
        dummy_processing_pipeline,
        detection_item,
    )


@pytest.fixture
def pipeline_field_tracking():
    pipeline = ProcessingPipeline()
    pipeline.track_field_processing_items("field1", ["fieldA", "fieldB"], "processing_item")
    return pipeline


def test_field_name_processing_item_applied(pipeline_field_tracking):
    assert FieldNameProcessingItemAppliedCondition(
        processing_item_id="processing_item"
    ).match_field_name(pipeline_field_tracking, "fieldA")


def test_field_name_processing_item_not_applied(pipeline_field_tracking):
    assert not FieldNameProcessingItemAppliedCondition(
        processing_item_id="processing_item"
    ).match_field_name(pipeline_field_tracking, "fieldC")


def test_detection_item_state_match(dummy_processing_pipeline, detection_item):
    dummy_processing_pipeline.state["field"] = "value"
    assert DetectionItemProcessingStateCondition("field", "value").match(
        dummy_processing_pipeline, detection_item
    )


def test_condition_identifiers_completeness():
    rule_condition_classes = rule_conditions.values()
    detection_item_condition_classes = detection_item_conditions.values()
    field_name_condition_classes = field_name_conditions.values()

    def condition_class_filter(c):
        return (
            inspect.isclass(c)
            and not inspect.isabstract(c)
            and issubclass(c, ProcessingCondition)
            and not c
            in (
                ProcessingCondition,
                RuleProcessingCondition,
                DetectionItemProcessingCondition,
                FieldNameProcessingCondition,
            )
        )

    for name, cls in inspect.getmembers(processing.conditions, condition_class_filter):
        if issubclass(cls, RuleProcessingCondition):
            assert cls in rule_condition_classes
        elif issubclass(cls, DetectionItemProcessingCondition):
            assert cls in detection_item_condition_classes
        elif issubclass(cls, FieldNameProcessingCondition):
            assert cls in field_name_condition_classes
        else:
            raise AssertionError(
                f"Class {name} is not a rule, detection item or field name condition"
            )


@pytest.fixture
def sigma_correlated_rules():
    return SigmaCollection.from_dicts(
        [
            {
                "title": "Test 1",
                "name": "testrule_1",
                "logsource": {"category": "test_category"},
                "detection": {
                    "test": [
                        {
                            "field1": "value1",
                            "field2": "value2",
                            "field3": "value3",
                        }
                    ],
                    "condition": "test",
                },
                "fields": [
                    "otherfield1",
                    "field1",
                    "field2",
                    "field3",
                    "otherfield2",
                ],
            },
            {
                "title": "Test 2",
                "name": "testrule_2",
                "logsource": {"product": "test_product"},
                "detection": {
                    "test": [
                        {
                            "field1": "value1",
                            "field2": "value2",
                            "field3": "value3",
                        }
                    ],
                    "condition": "test",
                },
                "fields": [
                    "otherfield1",
                    "field1",
                    "field2",
                    "field3",
                    "otherfield2",
                ],
            },
            {
                "title": "Test",
                "status": "test",
                "correlation": {
                    "type": "value_count",
                    "rules": [
                        "testrule_1",
                        "testrule_2",
                    ],
                    "timespan": "5m",
                    "group-by": [
                        "testalias",
                        "field2",
                        "field3",
                    ],
                    "condition": {
                        "gte": 10,
                        "field": "field1",
                    },
                    "aliases": {
                        "testalias": {
                            "testrule_1": "field1",
                            "testrule_2": "field2",
                        },
                    },
                },
            },
        ]
    )
