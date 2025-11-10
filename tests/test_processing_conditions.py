import inspect
from typing import cast
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions.values import MatchValueCondition
from sigma.types import SigmaBool, SigmaNull, SigmaNumber, SigmaString
from sigma import processing
from sigma.exceptions import (
    SigmaConfigurationError,
    SigmaProcessingItemError,
    SigmaRegularExpressionError,
)
import pytest
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.conditions import *
from sigma.processing.conditions import (
    ProcessingCondition,
    DetectionItemProcessingCondition,
    FieldNameProcessingCondition,
    RuleProcessingCondition,
    __all__ as conditions_all,
    rule_conditions,
    detection_item_conditions,
    field_name_conditions,
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


def test_processing_condition_multiple_pipelines_set(dummy_processing_pipeline):
    condition = IsSigmaRuleCondition()
    condition.set_pipeline(dummy_processing_pipeline)
    with pytest.raises(SigmaProcessingItemError, match="Pipeline.*was already set"):
        condition.set_pipeline(dummy_processing_pipeline)


def test_logsource_match(sigma_rule):
    assert LogsourceCondition(category="test_category").match(
        sigma_rule,
    )


def test_logsource_no_match(sigma_rule):
    assert not LogsourceCondition(category="test_category", product="other_product").match(
        sigma_rule,
    )


def test_logsource_match_correlation_rule_cat(sigma_correlated_rules):
    assert LogsourceCondition(category="test_category").match(
        cast(SigmaCorrelationRule, sigma_correlated_rules.rules[-1]),
    )


def test_logsource_match_correlation_rule_prod(sigma_correlated_rules):
    assert LogsourceCondition(product="test_product").match(
        cast(SigmaCorrelationRule, sigma_correlated_rules.rules[-1]),
    )


def test_logsource_no_match_correlation_rule_both(sigma_correlated_rules):
    assert not LogsourceCondition(category="test_category", product="test_product").match(
        cast(SigmaCorrelationRule, sigma_correlated_rules.rules[-1]),
    )


def test_logsource_no_match_correlation_rule(sigma_correlated_rules):
    assert not LogsourceCondition(service="test_service").match(
        cast(SigmaCorrelationRule, sigma_correlated_rules.rules[-1]),
    )


def test_logsource_no_rule_correlation_rule(sigma_correlation_rule):
    assert not LogsourceCondition(category="test_category", product="other_product").match(
        sigma_correlation_rule,
    )


from tests.test_processing_pipeline import processing_item


def test_rule_processing_item_applied(processing_item, sigma_rule: SigmaRule):
    sigma_rule.add_applied_processing_item(processing_item)
    assert RuleProcessingItemAppliedCondition(processing_item_id="test").match(
        sigma_rule,
    )


def test_rule_processing_item_not_applied(sigma_rule: SigmaRule):
    assert not RuleProcessingItemAppliedCondition(processing_item_id="test").match(
        sigma_rule,
    )


def test_rule_state_match(dummy_processing_pipeline, sigma_rule):
    dummy_processing_pipeline.state["key"] = "value"
    dummy_processing_pipeline.state["number"] = 123

    condition = RuleProcessingStateCondition("key", "value")
    condition.set_pipeline(dummy_processing_pipeline)
    assert condition.match(sigma_rule)

    condition = RuleProcessingStateCondition("key", "other_value", "ne")
    condition.set_pipeline(dummy_processing_pipeline)
    assert condition.match(sigma_rule)

    condition = RuleProcessingStateCondition("number", 123, "gte")
    condition.set_pipeline(dummy_processing_pipeline)
    assert condition.match(sigma_rule)

    condition = RuleProcessingStateCondition("number", 123, "lte")
    condition.set_pipeline(dummy_processing_pipeline)
    assert condition.match(sigma_rule)

    condition = RuleProcessingStateCondition("number", 122, "gt")
    condition.set_pipeline(dummy_processing_pipeline)
    assert condition.match(sigma_rule)

    condition = RuleProcessingStateCondition("number", 124, "lt")
    condition.set_pipeline(dummy_processing_pipeline)
    assert condition.match(sigma_rule)


def test_rule_state_nomatch(sigma_rule, dummy_processing_pipeline):
    dummy_processing_pipeline.state["key"] = "value"
    condition = RuleProcessingStateCondition("key", "other_value")
    condition.set_pipeline(dummy_processing_pipeline)
    assert not condition.match(sigma_rule)


def test_rule_processing_item_applied_correlation_rule(processing_item, sigma_correlation_rule):
    assert not RuleProcessingItemAppliedCondition(processing_item_id="test").match(
        sigma_correlation_rule,
    )
    sigma_correlation_rule.add_applied_processing_item(processing_item)
    assert RuleProcessingItemAppliedCondition(processing_item_id="test").match(
        sigma_correlation_rule,
    )


def test_rule_contains_detection_item_match(sigma_rule):
    assert RuleContainsDetectionItemCondition(field="fieldA", value="value").match(sigma_rule)


def test_rule_contains_detection_item_nomatch_field(sigma_rule):
    assert not RuleContainsDetectionItemCondition(field="fieldB", value="value").match(sigma_rule)


def test_rule_contains_detection_item_nomatch_value(sigma_rule):
    assert not RuleContainsDetectionItemCondition(field="fieldA", value="valuex").match(sigma_rule)


def test_rule_contains_detection_item_correlation_rule(sigma_correlation_rule):
    assert not RuleContainsDetectionItemCondition(field="fieldA", value="value").match(
        sigma_correlation_rule
    )


def test_rule_contains_field_match(sigma_rule):
    assert RuleContainsFieldCondition("fieldA").match(sigma_rule)


def test_rule_contains_field_nomatch(sigma_rule):
    assert not RuleContainsFieldCondition("non_existing").match(sigma_rule)


def test_rule_contains_field_correlation_rule(sigma_correlation_rule):
    assert not RuleContainsFieldCondition("fieldA").match(sigma_correlation_rule)


def test_is_sigma_rule_with_rule(sigma_rule):
    assert IsSigmaRuleCondition().match(sigma_rule)


def test_is_sigma_rule_with_correlation_rule(sigma_correlation_rule):
    assert not IsSigmaRuleCondition().match(sigma_correlation_rule)


def test_is_sigma_correlation_rule_with_correlation_rule(sigma_correlation_rule):
    assert IsSigmaCorrelationRuleCondition().match(sigma_correlation_rule)


def test_is_sigma_correlation_rule_with_rule(sigma_rule):
    assert not IsSigmaCorrelationRuleCondition().match(sigma_rule)


def test_rule_attribute_condition_str_match(sigma_rule):
    assert RuleAttributeCondition("taxonomy", "test").match(sigma_rule)


def test_rule_attribute_condition_invalid_str_op(sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="Invalid operation.*for string"):
        RuleAttributeCondition("taxonomy", "test", "gte").match(sigma_rule)


def test_rule_attribute_condition_invalid_op(sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="Invalid operation"):
        RuleAttributeCondition("custom", "123.4", "invalid")


def test_rule_attribute_condition_uuid_match(sigma_rule):
    assert RuleAttributeCondition("id", "809718e3-f7f5-46f1-931e-d036f0ffb0af").match(sigma_rule)


def test_rule_attribute_condition_custom_field_numeric_match(sigma_rule):
    assert RuleAttributeCondition("custom", "123.4", "lte").match(sigma_rule)


def test_rule_attribute_condition_invalid_numeric_value(sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="Invalid number"):
        RuleAttributeCondition("custom", "something", "lte").match(sigma_rule)


def test_rule_attribute_condition_date_match(sigma_rule):
    assert RuleAttributeCondition("date", "2022-02-23", "lt").match(sigma_rule)


def test_rule_attribute_condition_invalid_date(sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="Invalid date"):
        RuleAttributeCondition("date", "2022-02-23T00:00:00", "lt").match(sigma_rule)


def test_rule_attribute_condition_sigmalevel_match(sigma_rule):
    assert RuleAttributeCondition("level", "high", "lt").match(sigma_rule)


def test_rule_attribute_condition_invalid_sigmalevel(sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="Invalid Sigma severity level"):
        RuleAttributeCondition("level", "invalid", "lt").match(sigma_rule)


def test_rule_attribute_condition_sigmastatus_match(sigma_rule):
    assert RuleAttributeCondition("status", "stable", "lt").match(sigma_rule)


def test_rule_attribute_condition_invalid_sigmastatus(sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="Invalid Sigma status"):
        RuleAttributeCondition("status", "invalid", "lt").match(sigma_rule)


def test_rule_attribute_condition_invalid_rule_field_type(sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="Unsupported type"):
        RuleAttributeCondition("related", "08fbc97d-0a2f-491c-ae21-8ffcfd3174e9").match(sigma_rule)


@pytest.fixture
def sigma_rule_with_list_attribute():
    return SigmaRule.from_yaml(
        """
        title: Test
        status: test
        logsource:
            category: test_category
        detection:
            sel:
                fieldA: value
            condition: sel
        level: low
        custom:
            - valueA
            - valueB
    """
    )


def test_rule_attribute_condition_list_eq_match(sigma_rule_with_list_attribute):
    assert RuleAttributeCondition("custom", "valueA", "in").match(sigma_rule_with_list_attribute)


def test_rule_attribute_condition_list_eq_nomatch(sigma_rule_with_list_attribute):
    assert not RuleAttributeCondition("custom", "valueC", "in").match(
        sigma_rule_with_list_attribute
    )


def test_rule_attribute_condition_list_ne_match(sigma_rule_with_list_attribute):
    assert RuleAttributeCondition("custom", "valueC", "not_in").match(
        sigma_rule_with_list_attribute
    )


def test_rule_attribute_condition_list_ne_nomatch(sigma_rule_with_list_attribute):
    assert not RuleAttributeCondition("custom", "valueA", "not_in").match(
        sigma_rule_with_list_attribute
    )


def test_rule_attribute_condition_list_invalid_op(sigma_rule_with_list_attribute):
    with pytest.raises(SigmaConfigurationError, match="Invalid operation.*for list comparison"):
        RuleAttributeCondition("custom", "valueA", "gte").match(sigma_rule_with_list_attribute)


def test_rule_tag_condition_match(sigma_rule):
    assert RuleTagCondition("test.tag").match(sigma_rule)


def test_rule_tag_condition_nomatch(sigma_rule):
    assert not RuleTagCondition("test.notag").match(sigma_rule)


def test_include_field_condition_match():
    assert IncludeFieldCondition(["field", "otherfield"]).match_field_name("field")


def test_include_field_condition_match_nofield():
    assert not IncludeFieldCondition(["field", "otherfield"]).match_field_name(None)


def test_include_field_condition_nomatch():
    assert not IncludeFieldCondition(["testfield", "otherfield"]).match_field_name("field")


def test_include_field_condition_re_match():
    assert IncludeFieldCondition(["o[0-9]+", "f.*"], "re").match_field_name("field")


def test_include_field_condition_re_match_nofield():
    assert not IncludeFieldCondition(["o[0-9]+", "f.*"], "re").match_field_name(None)


def test_include_field_condition_re_nomatch():
    assert not IncludeFieldCondition(["o[0-9]+", "x.*"], "re").match_field_name("field")


def test_include_field_condition_wrong_type():
    with pytest.raises(SigmaConfigurationError, match="Invalid.*matching mode"):
        IncludeFieldCondition(["field", "otherfield"], "invalid")


def test_exclude_field_condition_match():
    assert ExcludeFieldCondition(["field", "otherfield"]).match_field_name("field") == False


def test_exclude_field_condition_nomatch():
    assert ExcludeFieldCondition(["testfield", "otherfield"]).match_field_name("field") == True


def test_exclude_field_condition_re_match():
    assert ExcludeFieldCondition(["o[0-9]+", "f.*"], "re").match_field_name("field") == False


def test_exclude_field_condition_re_nomatch():
    assert ExcludeFieldCondition(["o[0-9]+", "x.*"], "re").match_field_name("field") == True


def test_field_state_condition_match(dummy_processing_pipeline):
    dummy_processing_pipeline.state["field"] = "value"
    condition = FieldNameProcessingStateCondition("field", "value")
    condition.set_pipeline(dummy_processing_pipeline)
    assert condition.match_field_name("field")


@pytest.fixture
def multivalued_detection_item():
    return SigmaDetectionItem("field", [], [SigmaString("value"), SigmaNumber(123)])


def test_match_string_condition_any(multivalued_detection_item: SigmaDetectionItem):
    assert (
        MatchStringCondition(pattern="^val.*", cond="any").match(multivalued_detection_item) == True
    )


def test_match_string_condition_all(multivalued_detection_item: SigmaDetectionItem):
    assert (
        MatchStringCondition(pattern="^val.*", cond="all").match(multivalued_detection_item)
        == False
    )


def test_match_string_condition_all_sametype():
    assert (
        MatchStringCondition(pattern="^val.*", cond="all").match(
            SigmaDetectionItem("field", [], [SigmaString("val1"), SigmaString("val2")]),
        )
        == True
    )


def test_match_string_condition_all_negated():
    assert (
        MatchStringCondition(pattern="^val.*", cond="all", negate=True).match(
            SigmaDetectionItem("field", [], [SigmaString("val1"), SigmaString("val2")]),
        )
        == False
    )


def test_match_string_condition_error_mode():
    with pytest.raises(SigmaConfigurationError, match="parameter is invalid"):
        MatchStringCondition(pattern="x", cond="test")


def test_match_string_condition_error_pattern():
    with pytest.raises(SigmaRegularExpressionError, match="is invalid"):
        MatchStringCondition(pattern="*", cond="any")


def test_match_value_condition_str():
    assert MatchValueCondition(value="test", cond="any").match(
        SigmaDetectionItem("field", [], [SigmaString("test")])
    )


def test_match_value_condition_str_nomatch():
    assert not MatchValueCondition(value="test", cond="any").match(
        SigmaDetectionItem("field", [], [SigmaString("other")])
    )


def test_match_value_condition_number():
    assert MatchValueCondition(value=123, cond="any").match(
        SigmaDetectionItem("field", [], [SigmaNumber(123)])
    )


def test_match_value_condition_number_nomatch():
    assert not MatchValueCondition(value=123, cond="any").match(
        SigmaDetectionItem("field", [], [SigmaNumber(124)])
    )


def test_match_value_condition_bool():
    assert MatchValueCondition(value=True, cond="any").match(
        SigmaDetectionItem("field", [], [SigmaBool(True)])
    )


def test_match_value_condition_bool_nomatch():
    assert not MatchValueCondition(value=True, cond="any").match(
        SigmaDetectionItem("field", [], [SigmaBool(False)])
    )


def test_match_value_condition_incompatible_type():
    assert not MatchValueCondition(value=123, cond="any").match(
        SigmaDetectionItem("field", [], [SigmaString("123")])
    )


def test_contains_wildcard_condition_match():
    assert ContainsWildcardCondition(cond="any").match(
        SigmaDetectionItem("field", [], [SigmaString("*")])
    )


def test_contains_wildcard_condition_nomatch():
    assert not ContainsWildcardCondition(cond="any").match(
        SigmaDetectionItem("field", [], [SigmaString("value")])
    )


def test_contains_wildcard_condition_nostring():
    assert not ContainsWildcardCondition(cond="any").match(
        SigmaDetectionItem("field", [], [SigmaNumber(123)])
    )


def test_isnull_condition_match(detection_item_null_value):
    assert IsNullCondition(cond="all").match(detection_item_null_value)


def test_isnull_condition_nomatch(detection_item):
    assert not IsNullCondition(cond="all").match(detection_item)


def test_value_processing_invalid_cond():
    with pytest.raises(SigmaConfigurationError, match="The value.*cond"):
        MatchStringCondition(pattern="^val.*", cond="invalid")


def test_detection_item_processing_item_applied(
    processing_item, detection_item: SigmaDetectionItem
):
    detection_item.add_applied_processing_item(processing_item)
    assert DetectionItemProcessingItemAppliedCondition(processing_item_id="test").match(
        detection_item,
    )


def test_detection_item_processing_item_not_applied(detection_item: SigmaDetectionItem):
    assert not DetectionItemProcessingItemAppliedCondition(processing_item_id="test").match(
        detection_item,
    )


@pytest.fixture
def pipeline_field_tracking():
    pipeline = ProcessingPipeline()
    pipeline.track_field_processing_items("field1", ["fieldA", "fieldB"], "processing_item")
    return pipeline


def test_field_name_processing_item_applied(pipeline_field_tracking):
    condition = FieldNameProcessingItemAppliedCondition(processing_item_id="processing_item")
    condition.set_pipeline(pipeline_field_tracking)
    assert condition.match_field_name("fieldA")


def test_field_name_processing_item_not_applied(pipeline_field_tracking):
    condition = FieldNameProcessingItemAppliedCondition(processing_item_id="processing_item")
    condition.set_pipeline(pipeline_field_tracking)
    assert not condition.match_field_name("fieldC")


def test_detection_item_state_match(detection_item, dummy_processing_pipeline):
    dummy_processing_pipeline.state["field"] = "value"
    condition = DetectionItemProcessingStateCondition("field", "value")
    condition.set_pipeline(dummy_processing_pipeline)
    assert condition.match(detection_item)


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


def test_condition_export_completeness():
    condition_classes = {
        condition_class.__name__
        for condition_class in list(rule_conditions.values())
        + list(detection_item_conditions.values())
        + list(field_name_conditions.values())
    }

    conditions_all_set = set(conditions_all)
    assert conditions_all_set.issuperset(
        condition_classes
    ), "Not all conditions are exported, missing: " + ", ".join(
        condition_classes.difference(conditions_all_set)
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


def test_rule_attribute_condition_invalid_date_type(sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="must be a string value with a valid date"):
        RuleAttributeCondition("date", 20220223, "lt").match(sigma_rule)


def test_rule_attribute_condition_invalid_sigmalevel_type(sigma_rule):
    with pytest.raises(
        SigmaConfigurationError, match="must be a string value with a valid severity level"
    ):
        RuleAttributeCondition("level", 123, "lt").match(sigma_rule)


def test_rule_attribute_condition_invalid_sigmastatus_type(sigma_rule):
    with pytest.raises(SigmaConfigurationError, match="must be a string value with a valid status"):
        RuleAttributeCondition("status", 123, "lt").match(sigma_rule)


def test_rule_processing_state_condition_no_pipeline(sigma_rule):
    condition = RuleProcessingStateCondition("key", "value")
    with pytest.raises(
        SigmaProcessingItemError, match="Processing pipeline must be set before matching condition"
    ):
        condition.match(sigma_rule)


def test_field_name_processing_state_condition_no_pipeline():
    condition = FieldNameProcessingStateCondition("field", "value")
    with pytest.raises(
        SigmaProcessingItemError, match="Processing pipeline must be set before matching condition"
    ):
        condition.match_field_name("field")


def test_detection_item_processing_state_condition_no_pipeline(detection_item):
    condition = DetectionItemProcessingStateCondition("field", "value")
    with pytest.raises(
        SigmaProcessingItemError, match="Processing pipeline must be set before matching condition"
    ):
        condition.match(detection_item)


def test_field_name_processing_item_applied_no_pipeline():
    condition = FieldNameProcessingItemAppliedCondition(processing_item_id="processing_item")
    with pytest.raises(
        SigmaProcessingItemError, match="Processing pipeline must be set before matching condition"
    ):
        condition.match_field_name("fieldA")
