from sigma.types import SigmaNumber, SigmaString
from sigma import processing
from sigma.exceptions import SigmaConfigurationError, SigmaRegularExpressionError
import pytest
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, MatchStringCondition
from sigma.rule import SigmaDetectionItem, SigmaLogSource, SigmaRule

@pytest.fixture
def dummy_processing_pipeline():
    return ProcessingPipeline()

@pytest.fixture
def detection_item():
    return SigmaDetectionItem("field", [], [ SigmaString("value") ])

def test_logsource_match(dummy_processing_pipeline, detection_item):
    assert LogsourceCondition(category="test_category").match(
        dummy_processing_pipeline,
        SigmaRule.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value
                condition: sel
        """
        )
    )

def test_logsource_no_match(dummy_processing_pipeline, detection_item):
    assert not LogsourceCondition(category="test_category", product="other_product").match(
        dummy_processing_pipeline,
        SigmaRule.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value
                condition: sel
        """
        )
    )

def test_include_field_condition_match(dummy_processing_pipeline, detection_item):
    assert IncludeFieldCondition(["field", "otherfield"]).match(dummy_processing_pipeline, detection_item) == True

def test_include_field_condition_nomatch(dummy_processing_pipeline, detection_item):
    assert IncludeFieldCondition(["testfield", "otherfield"]).match(dummy_processing_pipeline, detection_item) == False

def test_include_field_condition_re_match(dummy_processing_pipeline, detection_item):
    assert IncludeFieldCondition(["o[0-9]+", "f.*"], "re").match(dummy_processing_pipeline, detection_item) == True

def test_include_field_condition_re_nomatch(dummy_processing_pipeline, detection_item):
    assert IncludeFieldCondition(["o[0-9]+", "x.*"], "re").match(dummy_processing_pipeline, detection_item) == False

def test_include_field_condition_wrong_type(dummy_processing_pipeline, detection_item):
    with pytest.raises(SigmaConfigurationError, match="Invalid.*type"):
        IncludeFieldCondition(["field", "otherfield"], "invalid")

def test_exclude_field_condition_match(dummy_processing_pipeline, detection_item):
    assert ExcludeFieldCondition(["field", "otherfield"]).match(dummy_processing_pipeline, detection_item) == False

def test_exclude_field_condition_nomatch(dummy_processing_pipeline, detection_item):
    assert ExcludeFieldCondition(["testfield", "otherfield"]).match(dummy_processing_pipeline, detection_item) == True

def test_exclude_field_condition_re_match(dummy_processing_pipeline, detection_item):
    assert ExcludeFieldCondition(["o[0-9]+", "f.*"], "re").match(dummy_processing_pipeline, detection_item) == False

def test_exclude_field_condition_re_nomatch(dummy_processing_pipeline, detection_item):
    assert ExcludeFieldCondition(["o[0-9]+", "x.*"], "re").match(dummy_processing_pipeline, detection_item) == True

@pytest.fixture
def multivalued_detection_item():
    return SigmaDetectionItem("field", [], [SigmaString("value"), SigmaNumber(123)])

def test_match_string_condition_any(dummy_processing_pipeline, multivalued_detection_item : SigmaDetectionItem):
    assert MatchStringCondition(pattern="^val.*", cond="any").match(dummy_processing_pipeline, multivalued_detection_item) == True

def test_match_string_condition_all(dummy_processing_pipeline, multivalued_detection_item : SigmaDetectionItem):
    assert MatchStringCondition(pattern="^val.*", cond="all").match(dummy_processing_pipeline, multivalued_detection_item) == False

def test_match_string_condition_all_sametype(dummy_processing_pipeline):
    assert MatchStringCondition(pattern="^val.*", cond="all").match(dummy_processing_pipeline, SigmaDetectionItem("field", [], [SigmaString("val1"), SigmaString("val2")])) == True

def test_match_string_condition_all_negated(dummy_processing_pipeline):
    assert MatchStringCondition(pattern="^val.*", cond="all", negate=True).match(dummy_processing_pipeline, SigmaDetectionItem("field", [], [SigmaString("val1"), SigmaString("val2")])) == False

def test_match_string_condition_error_mode():
    with pytest.raises(SigmaConfigurationError, match="parameter is invalid"):
        MatchStringCondition(pattern="x", cond="test")

def test_match_string_condition_error_mode():
    with pytest.raises(SigmaRegularExpressionError, match="is invalid"):
        MatchStringCondition(pattern="*", cond="any")