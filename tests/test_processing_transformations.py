import pytest
from sigma.processing.transformations import FieldMappingTransformation, AddFieldnameSuffixTransformation
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem
from sigma.types import SigmaString
from sigma.exceptions import SigmaValueError

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