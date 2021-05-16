import pytest
from sigma.processing.transformations import FieldMappingTransformation, AddFieldnameSuffixTransformation, WildcardPlaceholderTransformation
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem
from sigma.types import Placeholder, SigmaString, SpecialChars
from sigma.modifiers import SigmaExpandModifier
from sigma.exceptions import SigmaConfigurationError, SigmaValueError

@pytest.fixture
def dummy_pipeline():
    return ProcessingPipeline([], {})

@pytest.fixture
def sigma_rule():
    return SigmaRule.from_dict({
        "title": "Test",
        "logsource": {
            "category": "test"
        },
        "detection": {
            "test": [{
                "field1": "value1",
                "field2": "value2",
                "field3": "value3",
            }],
            "condition": "test",
        }
    })

@pytest.fixture
def sigma_rule_placeholders():
    return SigmaRule.from_dict({
        "title": "Test",
        "logsource": {
            "category": "test"
        },
        "detection": {
            "test": [{
                "field1|expand": "value%var1%test",
                "field2|expand": "value%var2%test%var3%",
                "field3|expand": "value%var1%test%var2%test%var3%test",
            }],
            "condition": "test",
        }
    })

def test_field_mapping_from_dict():
    mapping = {
        "single": "single_mapping",
        "multiple": [
            "multi_mapping_1",
            "multi_mapping_2",
        ]
    }
    assert FieldMappingTransformation.from_dict({
        "mapping": mapping
    }) == FieldMappingTransformation(mapping)

def test_field_mapping(dummy_pipeline, sigma_rule):
    transformation = FieldMappingTransformation({
        "field1": "fieldA",
        "field3": [ "fieldC", "fieldD" ],
    })
    transformation.apply(dummy_pipeline, sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection([
        SigmaDetection([
            SigmaDetectionItem("fieldA", [], [ SigmaString("value1") ]),
            SigmaDetectionItem("field2", [], [ SigmaString("value2") ]),
            SigmaDetection([
                SigmaDetectionItem("fieldC", [], [ SigmaString("value3") ]),
                SigmaDetectionItem("fieldD", [], [ SigmaString("value3") ]),
            ])
        ])
    ])

def test_add_fieldname_suffix_plain(dummy_pipeline, sigma_rule):
    transformation = AddFieldnameSuffixTransformation.from_dict({
        "type": "plain",
        "suffix": ".test",
        "fields": "field1",
    })
    transformation.apply(dummy_pipeline, sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection([
        SigmaDetection([
            SigmaDetectionItem("field1.test", [], [ SigmaString("value1") ]),
            SigmaDetectionItem("field2", [], [ SigmaString("value2") ]),
            SigmaDetectionItem("field3", [], [ SigmaString("value3") ]),
        ])
    ])

def test_add_fieldname_suffix_re_default(dummy_pipeline, sigma_rule):
    transformation = AddFieldnameSuffixTransformation.from_dict({
        "suffix": ".test",
    })
    transformation.apply(dummy_pipeline, sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection([
        SigmaDetection([
            SigmaDetectionItem("field1.test", [], [ SigmaString("value1") ]),
            SigmaDetectionItem("field2.test", [], [ SigmaString("value2") ]),
            SigmaDetectionItem("field3.test", [], [ SigmaString("value3") ]),
        ])
    ])

def test_add_fieldname_suffix_invalid_type():
    with pytest.raises(SigmaValueError, match="Transformation expects"):
        AddFieldnameSuffixTransformation.from_dict({"type": "invalid"})

def test_wildcard_placeholders(dummy_pipeline, sigma_rule_placeholders : SigmaRule):
    transformation = WildcardPlaceholderTransformation()
    transformation.apply(dummy_pipeline, sigma_rule_placeholders)
    assert sigma_rule_placeholders.detection.detections["test"] == SigmaDetection([
        SigmaDetection([
            SigmaDetectionItem("field1", [SigmaExpandModifier], [ SigmaString("value*test") ]),
            SigmaDetectionItem("field2", [SigmaExpandModifier], [ SigmaString("value*test*") ]),
            SigmaDetectionItem("field3", [SigmaExpandModifier], [ SigmaString("value*test*test*test") ]),
        ])
    ])

def test_wildcard_placeholder_include_and_exclude_error():
    with pytest.raises(SigmaConfigurationError, match="exclusively"):
        WildcardPlaceholderTransformation(include=["included_field"], exclude=["excluded_field"])

def test_wildcard_placeholders_included(dummy_pipeline, sigma_rule_placeholders : SigmaRule):
    transformation = WildcardPlaceholderTransformation(include=["var1"])
    transformation.apply(dummy_pipeline, sigma_rule_placeholders)
    detection_items = sigma_rule_placeholders.detection.detections["test"].detection_items[0].detection_items
    assert detection_items[0].value[0] == SigmaString("value*test") and \
        detection_items[1].value[0].s == ("value", Placeholder("var2"), "test", Placeholder("var3")) and \
        detection_items[2].value[0].s == ("value", SpecialChars.WILDCARD_MULTI, "test", Placeholder("var2"), "test", Placeholder("var3"), "test")

def test_wildcard_placeholders_excluded(dummy_pipeline, sigma_rule_placeholders : SigmaRule):
    transformation = WildcardPlaceholderTransformation(exclude=["var2", "var3"])
    transformation.apply(dummy_pipeline, sigma_rule_placeholders)
    detection_items = sigma_rule_placeholders.detection.detections["test"].detection_items[0].detection_items
    assert detection_items[0].value[0] == SigmaString("value*test") and \
        detection_items[1].value[0].s == ("value", Placeholder("var2"), "test", Placeholder("var3")) and \
        detection_items[2].value[0].s == ("value", SpecialChars.WILDCARD_MULTI, "test", Placeholder("var2"), "test", Placeholder("var3"), "test")

def test_wildcard_placeholders_without_placeholders(dummy_pipeline, sigma_rule : SigmaRule):
    transformation = WildcardPlaceholderTransformation()
    transformation.apply(dummy_pipeline, sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection([
        SigmaDetection([
            SigmaDetectionItem("field1", [], [ SigmaString("value1") ]),
            SigmaDetectionItem("field2", [], [ SigmaString("value2") ]),
            SigmaDetectionItem("field3", [], [ SigmaString("value3") ]),
        ])
    ])
