import pytest
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.conditions import IncludeFieldCondition, ExcludeFieldCondition
from sigma.rule import SigmaDetectionItem

@pytest.fixture
def dummy_processing_pipeline():
    return ProcessingPipeline()

@pytest.fixture
def detection_item():
    return SigmaDetectionItem("field", [], "value")

def test_include_field_condition_match(dummy_processing_pipeline, detection_item):
    assert IncludeFieldCondition(["field", "otherfield"]).match(dummy_processing_pipeline, detection_item) == True

def test_include_field_condition_nomatch(dummy_processing_pipeline, detection_item):
    assert IncludeFieldCondition(["testfield", "otherfield"]).match(dummy_processing_pipeline, detection_item) == False

def test_exclude_field_condition_match(dummy_processing_pipeline, detection_item):
    assert ExcludeFieldCondition(["field", "otherfield"]).match(dummy_processing_pipeline, detection_item) == False

def test_exclude_field_condition_nomatch(dummy_processing_pipeline, detection_item):
    assert ExcludeFieldCondition(["testfield", "otherfield"]).match(dummy_processing_pipeline, detection_item) == True