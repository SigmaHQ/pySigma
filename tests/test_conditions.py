import pytest
from sigma.conditions import ConditionItem, SigmaCondition, ConditionAND, ConditionOR, ConditionNOT, ConditionIdentifier, ConditionSelector, ConditionFieldEqualsValueExpression, ConditionValueExpression
from sigma.rule import SigmaDetections, SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.types import SigmaString, SigmaNumber, SigmaNull, SigmaRegularExpression
from sigma.exceptions import SigmaConditionError

@pytest.fixture
def sigma_simple_detections():
    return SigmaDetections({
        "detection1": SigmaDetection([
            SigmaDetectionItem(None, [], [SigmaString("val1")]),
        ]),
        "detection2": SigmaDetection([
            SigmaDetectionItem(None, [], [SigmaString("val2")]),
        ]),
        "detection3": SigmaDetection([
            SigmaDetectionItem(None, [], [SigmaString("val3")]),
        ]),
        "detection_4": SigmaDetection([
            SigmaDetectionItem(None, [], [SigmaString("val4")]),
        ]),
        "other": SigmaDetection([
            SigmaDetectionItem(None, [], [SigmaString("other")]),
        ]),
    }, list())

@pytest.fixture
def sigma_detections():
    return SigmaDetections({
        "keywords": SigmaDetection([        # expected result: OR across values
            SigmaDetectionItem(None, [], [
                SigmaString("keyword1"),
                SigmaNumber(123),
            ]),
        ]),
        "keyword-list": SigmaDetection([    # expected result: OR across values inside a detection item, AND of detection items
            SigmaDetectionItem(None, [], [
                SigmaString("keyword1"),
                SigmaString("keyword2"),
            ]),
            SigmaDetectionItem(None, [], [
                SigmaString("keyword3"),
                SigmaString("keyword4"),
            ]),
        ]),
        "field-value": SigmaDetection([     # expected result: AND of key=value pairs
            SigmaDetectionItem("field1", [], [ SigmaString("value1") ]),
            SigmaDetectionItem("field2", [], [ SigmaNumber(123) ]),
            SigmaDetectionItem("field3", [], [ SigmaNull() ]),
        ]),
        "field-valuelist": SigmaDetection([    # expected result: each key results in "in" expression (or expanded to OR on demand), AND of key-expressions
            SigmaDetectionItem("field1", [], [
                SigmaString("value1-1"),
                SigmaNumber(123),
            ]),
            SigmaDetectionItem("field2", [], [
                SigmaString("value2-1"),
                SigmaNumber(234),
            ]),
        ]),
        "field-valuelist-wildcards": SigmaDetection([    # expected result: ORed key=value expressions, no "in" expression
            SigmaDetectionItem("field", [], [
                SigmaString("simple-value"),
                SigmaString("*wildcards*"),
            ]),
        ]),
        "field-valuelist-regex": SigmaDetection([    # expected result: ORed key=value expressions, no "in" expression
            SigmaDetectionItem("field", [], [
                SigmaString("simple-value"),
                SigmaRegularExpression("reg.*ex"),
            ]),
        ]),
        "empty-field": SigmaDetection([              # expected result: field match against null value
            SigmaDetectionItem("field", [], [])
        ])
    }, list())

@pytest.fixture
def sigma_invalid_detections():
    return SigmaDetections({
        "null-keyword": SigmaDetection([
            SigmaDetectionItem(None, [], []),
        ]),
    }, list())

def test_or(sigma_simple_detections):
    assert SigmaCondition("detection1 or detection2", sigma_simple_detections).parsed == ConditionOR([
        ConditionValueExpression(SigmaString("val1")),
        ConditionValueExpression(SigmaString("val2")),
    ])

def test_and(sigma_simple_detections):
    assert SigmaCondition("detection1 and detection2", sigma_simple_detections).parsed == ConditionAND([
        ConditionValueExpression(SigmaString("val1")),
        ConditionValueExpression(SigmaString("val2")),
    ])

def test_not(sigma_simple_detections):
    assert SigmaCondition("not detection1", sigma_simple_detections).parsed == ConditionNOT([ConditionValueExpression(SigmaString("val1"))])

def test_3or(sigma_simple_detections):
    assert SigmaCondition("detection1 or detection2 or detection3", sigma_simple_detections).parsed == ConditionOR([
        ConditionValueExpression(SigmaString("val1")),
        ConditionValueExpression(SigmaString("val2")),
        ConditionValueExpression(SigmaString("val3")),
    ])

def test_precedence(sigma_simple_detections):
    assert SigmaCondition("detection1 and not detection2 or not detection3 and detection_4", sigma_simple_detections).parsed == ConditionOR([
        ConditionAND([
            ConditionValueExpression(SigmaString("val1")),
            ConditionNOT([ConditionValueExpression(SigmaString("val2"))]),
        ]),
        ConditionAND([
            ConditionNOT([ConditionValueExpression(SigmaString("val3"))]),
            ConditionValueExpression(SigmaString("val4")),
        ])
    ])

def test_precedence_parent_chain_condition_classes(sigma_simple_detections):
    parsed : ConditionItem = SigmaCondition("detection1 and not detection2 or not detection3 and detection_4", sigma_simple_detections).parsed
    assert (
        parsed.args[0].args[0].parent_chain_condition_classes() == [ConditionAND, ConditionOR] and                               # detection1
        parsed.args[0].args[1].args[0].parent_chain_condition_classes() == [ConditionNOT, ConditionAND, ConditionOR] and         # detection2
        parsed.args[1].args[0].args[0].parent_chain_condition_classes() == [ConditionNOT, ConditionAND, ConditionOR] and         # detection3
        parsed.args[1].args[1].parent_chain_condition_classes() == [ConditionAND, ConditionOR]                                   # detection_4
    )

def test_precedence_parent_chain_condition_classes_contains(sigma_simple_detections):
    assert SigmaCondition("detection1 and not detection2 or not detection3 and detection_4", sigma_simple_detections) \
        .parsed.args[0].args[0].parent_condition_chain_contains(ConditionOR)

def test_precedence_parent_chain_condition_classes_not_contains(sigma_simple_detections):
    assert not SigmaCondition("detection1 and not detection2 or not detection3 and detection_4", sigma_simple_detections) \
        .parsed.args[0].args[0].parent_condition_chain_contains(ConditionNOT)

def test_precedence_parenthesis(sigma_simple_detections):
    assert SigmaCondition("(detection1 or not detection2) and not (detection3 or detection_4)", sigma_simple_detections).parsed == ConditionAND([
        ConditionOR([
            ConditionValueExpression(SigmaString("val1")),
            ConditionNOT([ConditionValueExpression(SigmaString("val2"))]),
        ]),
        ConditionNOT([
            ConditionOR([
                ConditionValueExpression(SigmaString("val3")),
                ConditionValueExpression(SigmaString("val4")),
            ])
        ])
    ])

def test_precedence_parenthesis_parent_chain_condition_classes(sigma_simple_detections):
    assert SigmaCondition("(detection1 or not detection2) and not (detection3 or detection_4)", sigma_simple_detections) \
        .parsed.args[1].args[0].args[0].parent_chain_condition_classes() == [ConditionOR, ConditionNOT, ConditionAND]

def test_selector_1(sigma_simple_detections):
    assert SigmaCondition("1 of detection*", sigma_simple_detections).parsed == ConditionOR([
        ConditionValueExpression(SigmaString("val1")),
        ConditionValueExpression(SigmaString("val2")),
        ConditionValueExpression(SigmaString("val3")),
        ConditionValueExpression(SigmaString("val4")),
    ])

def test_selector_1_parent_chain_classes(sigma_simple_detections):
    assert SigmaCondition("1 of detection*", sigma_simple_detections) \
        .parsed.args[0].parent_chain_classes() == [SigmaDetectionItem, SigmaDetection, ConditionIdentifier, ConditionOR]

def test_selector_1_of_them(sigma_simple_detections):
    assert SigmaCondition("1 of them", sigma_simple_detections).parsed == ConditionOR([
        ConditionValueExpression(SigmaString("val1")),
        ConditionValueExpression(SigmaString("val2")),
        ConditionValueExpression(SigmaString("val3")),
        ConditionValueExpression(SigmaString("val4")),
        ConditionValueExpression(SigmaString("other")),
    ])

def test_selector_any(sigma_simple_detections):
    assert SigmaCondition("any of detection*", sigma_simple_detections).parsed == ConditionOR([
        ConditionValueExpression(SigmaString("val1")),
        ConditionValueExpression(SigmaString("val2")),
        ConditionValueExpression(SigmaString("val3")),
        ConditionValueExpression(SigmaString("val4")),
    ])

def test_selector_any_of_them(sigma_simple_detections):
    assert SigmaCondition("any of them", sigma_simple_detections).parsed == ConditionOR([
        ConditionValueExpression(SigmaString("val1")),
        ConditionValueExpression(SigmaString("val2")),
        ConditionValueExpression(SigmaString("val3")),
        ConditionValueExpression(SigmaString("val4")),
        ConditionValueExpression(SigmaString("other")),
    ])

def test_selector_all(sigma_simple_detections):
    assert SigmaCondition("all of detection*", sigma_simple_detections).parsed == ConditionAND([
        ConditionValueExpression(SigmaString("val1")),
        ConditionValueExpression(SigmaString("val2")),
        ConditionValueExpression(SigmaString("val3")),
        ConditionValueExpression(SigmaString("val4")),
    ])

def test_selector_all_of_them(sigma_simple_detections):
    assert SigmaCondition("all of them", sigma_simple_detections).parsed == ConditionAND([
        ConditionValueExpression(SigmaString("val1")),
        ConditionValueExpression(SigmaString("val2")),
        ConditionValueExpression(SigmaString("val3")),
        ConditionValueExpression(SigmaString("val4")),
        ConditionValueExpression(SigmaString("other")),
    ])

def test_keyword_detection(sigma_detections):
    assert SigmaCondition("keywords", sigma_detections).parsed == ConditionOR([
        ConditionValueExpression(SigmaString("keyword1")),
        ConditionValueExpression(SigmaNumber(123)),
    ])

def test_multiple_keyword_detection(sigma_detections):
    assert SigmaCondition("keyword-list", sigma_detections).parsed == ConditionAND([
        ConditionOR([
            ConditionValueExpression(SigmaString("keyword1")),
            ConditionValueExpression(SigmaString("keyword2")),
        ]),
        ConditionOR([
            ConditionValueExpression(SigmaString("keyword3")),
            ConditionValueExpression(SigmaString("keyword4")),
        ]),
    ])

def test_field_value_detection(sigma_detections):
    assert SigmaCondition("field-value", sigma_detections).parsed == ConditionAND([
        ConditionFieldEqualsValueExpression("field1", SigmaString("value1")),
        ConditionFieldEqualsValueExpression("field2", SigmaNumber(123)),
        ConditionFieldEqualsValueExpression("field3", SigmaNull()),
    ])

def test_field_valuelist_with_wildcards_detection(sigma_detections):
    assert SigmaCondition("field-valuelist-wildcards", sigma_detections).parsed == ConditionOR([
        ConditionFieldEqualsValueExpression("field", SigmaString("simple-value")),
        ConditionFieldEqualsValueExpression("field", SigmaString("*wildcards*")),
    ])

def test_field_valuelist_with_regex_detection(sigma_detections):
    assert SigmaCondition("field-valuelist-regex", sigma_detections).parsed == ConditionOR([
        ConditionFieldEqualsValueExpression("field", SigmaString("simple-value")),
        ConditionFieldEqualsValueExpression("field", SigmaRegularExpression("reg.*ex")),
    ])

def test_field_valuelist_with_regex_detection_parent_condition_chain(sigma_detections):
    assert SigmaCondition("field-valuelist-regex", sigma_detections). \
        parsed.args[0].parent_chain_classes() == [ConditionOR, SigmaDetection, ConditionIdentifier]

def test_empty_field_detection(sigma_detections):
    assert SigmaCondition("empty-field", sigma_detections).parsed == ConditionFieldEqualsValueExpression("field", SigmaNull())

def test_undefined_identifier(sigma_simple_detections):
    with pytest.raises(SigmaConditionError):
        SigmaCondition("detection", sigma_simple_detections).parsed

def test_null_keyword(sigma_invalid_detections):
    with pytest.raises(SigmaConditionError):
        SigmaCondition("null-keyword", sigma_invalid_detections).parsed


@pytest.mark.parametrize("condition", [
    "detection1 and",
    "detection1 and (detection2 OR detection3)",
    "detection1 and not (detection2 OR detection3)",
])
def test_invalid_conditions(condition, sigma_simple_detections):
    with pytest.raises(SigmaConditionError):
        SigmaCondition(condition, sigma_simple_detections).parsed

def test_deprecated_pipe_syntax(sigma_simple_detections):
    with pytest.raises(SigmaConditionError, match="deprecated"):
        SigmaCondition("detection | count() by src_ip > 50", sigma_simple_detections).parsed


def test_and_condition_has_parent(sigma_simple_detections):
    """
    Non-regression test related to issue #64
    """
    rule = SigmaRule.from_yaml("""
title: rule
id: cafecafe-0499-4d3f-9670-55cfc950e2dc
status: stable
level: critical
description: rule
logsource:
  product: Windows
detection:
  selection:
    Somefield: 'Somevalue'
    Someotherfield: 'someothervalue'
  selection2:
    Thirdfield: 'thirdvalue'
  condition: selection or selection2
""")
    or_condition = rule.detection.parsed_condition[0].parsed
    assert or_condition.args[0].parent != None
    assert or_condition.args[0].parent.parent == or_condition
