import pytest
from sigma.processing.transformations import FieldMappingTransformation
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem
from sigma.types import SigmaString

@pytest.fixture
def dummy_pipeline():
    return ProcessingPipeline([], {})

def test_field_mapping(dummy_pipeline):
    sigma_rule = SigmaRule.from_dict({
        "title": "Test",
        "logsource": {
            "category": "test"
        },
        "detection": {
            "test": {
                "field1": "value1",
                "field2": "value2",
                "field3": "value3",
            },
            "condition": "test",
        }
    })
    transformation = FieldMappingTransformation({
        "field1": "fieldA",
        "field3": [ "fieldC", "fieldD" ],
    })
    transformation.apply(dummy_pipeline, sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection([
        SigmaDetectionItem("fieldA", [], [ SigmaString("value1") ]),
        SigmaDetectionItem("field2", [], [ SigmaString("value2") ]),
        SigmaDetection([
            SigmaDetectionItem("fieldC", [], [ SigmaString("value3") ]),
            SigmaDetectionItem("fieldD", [], [ SigmaString("value3") ]),
        ])
    ])
