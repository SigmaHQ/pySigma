import pytest
from dataclasses import dataclass
import re
from textwrap import dedent
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.conditions import rule_conditions, RuleProcessingCondition, detection_item_conditions, DetectionItemProcessingCondition
from sigma.processing.transformations import transformations, Transformation
from sigma.rule import SigmaRule, SigmaDetectionItem
from sigma.exceptions import SigmaConfigurationError

@dataclass
class RuleConditionTrue(RuleProcessingCondition):
    dummy : str

    def match(self, pipeline : ProcessingPipeline, rule : SigmaRule) -> bool:
        return True

@dataclass
class RuleConditionFalse(RuleProcessingCondition):
    dummy : str

    def match(self, pipeline : ProcessingPipeline, rule : SigmaRule) -> bool:
        return False

@dataclass
class DetectionItemConditionTrue(DetectionItemProcessingCondition):
    dummy : str

    def match(self, pipeline : ProcessingPipeline, detection_item : SigmaDetectionItem) -> bool:
        return True

@dataclass
class DetectionItemConditionFalse(DetectionItemProcessingCondition):
    dummy : str

    def match(self, pipeline : ProcessingPipeline, detection_item : SigmaDetectionItem) -> bool:
        return False

@dataclass
class TransformationPrepend(Transformation):
    s : str

    def apply(self, pipeline : ProcessingPipeline, rule : SigmaRule) -> SigmaRule:
        rule.title = self.s + rule.title
        return rule

@dataclass
class TransformationAppend(Transformation):
    s : str

    def apply(self, pipeline : ProcessingPipeline, rule : SigmaRule) -> SigmaRule:
        rule.title += self.s
        return rule

@pytest.fixture(autouse=True)
def inject_test_classes(monkeypatch):
    monkeypatch.setitem(rule_conditions, "true", RuleConditionTrue)
    monkeypatch.setitem(rule_conditions, "false", RuleConditionFalse)
    monkeypatch.setitem(detection_item_conditions, "true", DetectionItemConditionTrue)
    monkeypatch.setitem(detection_item_conditions, "false", DetectionItemConditionFalse)
    monkeypatch.setitem(transformations, "prepend", TransformationPrepend)
    monkeypatch.setitem(transformations, "append", TransformationAppend)

@pytest.fixture
def sigma_rule():
    return SigmaRule.from_dict({
        "title": "Test",
        "logsource": {
            "category": "test"
        },
        "detection": {
            "test": {
                "field": "value"
            },
            "condition": "test",
        }
    })

@pytest.fixture
def detection_item():
    return SigmaDetectionItem("field", [], "value")

@pytest.fixture
def processing_item_dict():
    return {
        "id": "test",
        "rule_conditions": [
            {
                "type": "true",
                "dummy": "test-true"
            },
            {
                "type": "false",
                "dummy": "test-false"
            },
        ],
        "rule_cond_op": "or",
        "detection_item_conditions": [
            {
                "type": "true",
                "dummy": "test-true"
            },
            {
                "type": "false",
                "dummy": "test-false"
            },
        ],
        "detection_item_cond_op": "or",
        "type": "append",
        "s": "Test",
    }

@pytest.fixture
def processing_item_dict_with_error():
    return {
        "id": "test",
        "rule_conditions": [
            {
                "type": "true",
                "dummy": "test-true"
            },
            {
                "dummy": "test-false"
            },
        ],
        "rule_cond_op": "or",
        "type": "append",
        "s": "Test",
    }

@pytest.fixture
def processing_item():
    return ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        rule_condition_linking=any,
        rule_conditions=[
            RuleConditionTrue(dummy="test-true"),
            RuleConditionFalse(dummy="test-false"),
        ],
        detection_item_condition_linking=any,
        detection_item_conditions=[
            DetectionItemConditionTrue(dummy="test-true"),
            DetectionItemConditionFalse(dummy="test-false"),
        ],
        identifier="test",
    )

@pytest.fixture
def processing_pipeline_vars():
    return {
        "test_string": "abc",
        "test_number": 123,
    }

@pytest.fixture
def dummy_processing_pipeline():
    return ProcessingPipeline(items=[], vars=dict())

def test_processingitem_fromdict(processing_item_dict, processing_item):
    assert ProcessingItem.from_dict(processing_item_dict) == processing_item

def test_processingitem_fromdict_missing_condition_type():
    with pytest.raises(SigmaConfigurationError, match="Missing condition type.*2"):
        ProcessingItem.from_dict({
            "id": "test",
            "rule_conditions": [
                {
                    "type": "true",
                    "dummy": "test-true"
                },
                {
                    "dummy": "test-missing"
                },
            ],
            "rule_cond_op": "or",
            "type": "append",
            "s": "Test",
        })

def test_processingitem_fromdict_unknown_condition_type():
    with pytest.raises(SigmaConfigurationError, match="Unknown condition type.*2"):
        ProcessingItem.from_dict({
            "id": "test",
            "rule_conditions": [
                {
                    "type": "true",
                    "dummy": "test-true"
                },
                {
                    "type": "unknown",
                    "dummy": "test-false"
                },
            ],
            "rule_cond_op": "or",
            "type": "append",
            "s": "Test",
        })

def test_processingitem_fromdict_unknown_parameter():
    with pytest.raises(SigmaConfigurationError, match="Error in condition.*2"):
        ProcessingItem.from_dict({
            "id": "test",
            "rule_conditions": [
                {
                    "type": "true",
                    "dummy": "test-true"
                },
                {
                    "type": "false",
                    "unknown": "test-false"
                },
            ],
            "rule_cond_op": "or",
            "type": "append",
            "s": "Test",
        }) == ProcessingItem(
            rule_conditions=[
                RuleConditionTrue(dummy="test-true"),
                RuleConditionFalse(dummy="test-false"),
            ],
            rule_condition_linking=any,
            transformation=TransformationAppend(s="Test")
        )

def test_processingitem_fromdict_missing_transformation_type():
    with pytest.raises(SigmaConfigurationError, match="Missing transformation type"):
        ProcessingItem.from_dict({
            "id": "test",
            "rule_conditions": [
                {
                    "type": "true",
                    "dummy": "test-true"
                },
                {
                    "type": "false",
                    "dummy": "test-false"
                },
            ],
            "rule_cond_op": "or",
            "s": "Test",
        })

def test_processingitem_fromdict_unknown_transformation_type():
    with pytest.raises(SigmaConfigurationError, match="Unknown transformation type"):
        ProcessingItem.from_dict({
            "id": "test",
            "rule_conditions": [
                {
                    "type": "true",
                    "dummy": "test-true"
                },
                {
                    "type": "false",
                    "dummy": "test-false"
                },
            ],
            "rule_cond_op": "or",
            "type": "unknown",
            "s": "Test",
        })

def test_processingitem_fromdict_unknown_transformation_parameter():
    with pytest.raises(SigmaConfigurationError, match="Error in transformation"):
        ProcessingItem.from_dict({
            "id": "test",
            "rule_conditions": [
                {
                    "type": "true",
                    "dummy": "test-true"
                },
                {
                    "type": "false",
                    "dummy": "test-false"
                },
            ],
            "rule_cond_op": "or",
            "type": "append",
            "unknown": "Test",
        })

def test_processingitem_apply(processing_item, dummy_processing_pipeline, sigma_rule):
    applied = processing_item.apply(dummy_processing_pipeline, sigma_rule)
    assert applied and sigma_rule.title == "TestTest"

def test_processingitem_apply_notapplied_all_with_false(dummy_processing_pipeline, sigma_rule):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        rule_condition_linking=all,
        rule_conditions=[
            RuleConditionTrue(dummy="test-true"),
            RuleConditionFalse(dummy="test-false"),
        ],
    )
    applied = processing_item.apply(dummy_processing_pipeline, sigma_rule)
    assert not applied and sigma_rule.title == "Test"

def test_processingitem_apply_notapplied_any_without_true(dummy_processing_pipeline, sigma_rule):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        rule_condition_linking=any,
        rule_conditions=[
            RuleConditionFalse(dummy="test-true"),
            RuleConditionFalse(dummy="test-false"),
        ],
    )
    applied = processing_item.apply(dummy_processing_pipeline, sigma_rule)
    assert not applied and sigma_rule.title == "Test"

def test_processingitem_match_detection_item(dummy_processing_pipeline, detection_item):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        detection_item_condition_linking=any,
        detection_item_conditions=[
            DetectionItemConditionTrue(dummy="test-true"),
            DetectionItemConditionFalse(dummy="test-false"),
        ],
    )
    assert processing_item.match_detection_item(dummy_processing_pipeline, detection_item) == True

def test_processingitem_match_detection_item_all_with_false(dummy_processing_pipeline, detection_item):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        detection_item_condition_linking=all,
        detection_item_conditions=[
            DetectionItemConditionTrue(dummy="test-true"),
            DetectionItemConditionFalse(dummy="test-false"),
        ],
    )
    assert processing_item.match_detection_item(dummy_processing_pipeline, detection_item) == False

def test_processingitem_match_detection_item_any_without_true(dummy_processing_pipeline, detection_item):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        detection_item_condition_linking=any,
        detection_item_conditions=[
            DetectionItemConditionFalse(dummy="test-true"),
            DetectionItemConditionFalse(dummy="test-false"),
        ],
    )
    assert processing_item.match_detection_item(dummy_processing_pipeline, detection_item) == False

def test_processingpipeline_fromdict(processing_item_dict, processing_item, processing_pipeline_vars):
    assert ProcessingPipeline.from_dict({
        "transformations": [ processing_item_dict ],
        "vars": processing_pipeline_vars,
    }) == ProcessingPipeline(
        items=[ processing_item ],
        vars=processing_pipeline_vars,
    )

def test_processingpipeline_fromyaml(processing_item_dict, processing_item, processing_pipeline_vars):
    assert ProcessingPipeline.from_yaml("""
        transformations:
            - id: test
              rule_conditions:
                  - type: "true"
                    dummy: test-true
                  - type: "false"
                    dummy: test-false
              rule_cond_op: or
              detection_item_conditions:
                  - type: "true"
                    dummy: test-true
                  - type: "false"
                    dummy: test-false
              detection_item_cond_op: or
              type: append
              s: Test
        vars:
            test_string: abc
            test_number: 123
    """) == ProcessingPipeline(
        items=[ processing_item ],
        vars=processing_pipeline_vars,
    )

def test_processingpipeline_fromdict_error(processing_item_dict_with_error):
    with pytest.raises(SigmaConfigurationError, match="Error in processing rule 1:.*2"):
        ProcessingPipeline.from_dict({ "transformations": [ processing_item_dict_with_error ], })

def test_processingpipeline_error_direct_transofrmations(sigma_rule):
    """Common error: passing transformations directly instead wrapped in ProcessingItem objects. This should raise an error."""
    with pytest.raises(TypeError, match="must be a ProcessingItem"):
        ProcessingPipeline(
            items=[
                TransformationPrepend(s="Pre"),
                TransformationAppend(s="Appended"),
            ]
        )

def test_processingpipeline_apply(sigma_rule):
    pipeline = ProcessingPipeline(
        items=[
            ProcessingItem(transformation=TransformationPrepend(s="Pre"), identifier="pre"),
            ProcessingItem(transformation=TransformationAppend(s="Appended"), identifier="append"),
        ]
    )
    result_rule = pipeline.apply(sigma_rule)
    assert result_rule.title == "PreTestAppended" \
        and pipeline.applied == [True, True] \
        and pipeline.applied_ids == { "pre", "append" }

def test_processingpipeline_apply_partial(sigma_rule):
    pipeline = ProcessingPipeline(
        items=[
            ProcessingItem(
                transformation=TransformationPrepend(s="Pre"),
                rule_conditions=[RuleConditionFalse(dummy="test")],
                identifier="pre"
                ),
            ProcessingItem(transformation=TransformationAppend(s="Appended"), identifier="append"),
        ]
    )
    result_rule = pipeline.apply(sigma_rule)
    assert result_rule.title == "TestAppended" \
        and pipeline.applied == [False, True] \
        and pipeline.applied_ids == { "append" }

def test_processingpipeline_concatenation():
    p1 = ProcessingPipeline(
        items=[
            ProcessingItem(
                transformation=TransformationPrepend(s="Pre"),
                identifier="pre",
            ),
        ],
        vars={
            "a": 1,
            "b": 2,
        }
    )
    p2 = ProcessingPipeline(
        items=[
            ProcessingItem(
                transformation=TransformationAppend(s="Append"),
                identifier="append",
            ),
        ],
        vars={
            "b": 3,
            "c": 4,
        }
    )
    assert p1 + p2 == ProcessingPipeline(
        items=[
            ProcessingItem(
                transformation=TransformationPrepend(s="Pre"),
                identifier="pre",
            ),
            ProcessingItem(
                transformation=TransformationAppend(s="Append"),
                identifier="append",
            ),
        ],
        vars={
            "a": 1,
            "b": 3,
            "c": 4,
        }
    )

def test_processingpipeline_invalid_concatenation():
    with pytest.raises(TypeError):
        ProcessingPipeline(
            items=[
                ProcessingItem(
                    transformation=TransformationAppend(s="Append"),
                    identifier="append",
                ),
            ],
        ) + 3
