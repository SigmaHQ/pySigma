import pytest
from dataclasses import dataclass
import re
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.conditions import conditions, ProcessingCondition
from sigma.processing.transformations import transformations, Transformation
from sigma.rule import SigmaRule
from sigma.exceptions import SigmaConfigurationError

@dataclass
class ConditionTrue(ProcessingCondition):
    dummy : str

    def match(self, pipeline : ProcessingPipeline, rule : SigmaRule) -> bool:
        return True

@dataclass
class ConditionFalse(ProcessingCondition):
    dummy : str

    def match(self, pipeline : ProcessingPipeline, rule : SigmaRule) -> bool:
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
    monkeypatch.setitem(conditions, "true", ConditionTrue)
    monkeypatch.setitem(conditions, "false", ConditionFalse)
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
def processing_item_dict():
    return {
        "id": "test",
        "conditions": [
            {
                "type": "true",
                "dummy": "test-true"
            },
            {
                "type": "false",
                "dummy": "test-false"
            },
        ],
        "cond_op": "or",
        "type": "append",
        "s": "Test",
    }

@pytest.fixture
def processing_item_dict_with_error():
    return {
        "id": "test",
        "conditions": [
            {
                "type": "true",
                "dummy": "test-true"
            },
            {
                "dummy": "test-false"
            },
        ],
        "cond_op": "or",
        "type": "append",
        "s": "Test",
    }

@pytest.fixture
def processing_item():
    return ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        condition_linking=any,
        conditions=[
            ConditionTrue(dummy="test-true"),
            ConditionFalse(dummy="test-false"),
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
            "conditions": [
                {
                    "type": "true",
                    "dummy": "test-true"
                },
                {
                    "dummy": "test-missing"
                },
            ],
            "cond_op": "or",
            "type": "append",
            "s": "Test",
        })

def test_processingitem_fromdict_unknown_condition_type():
    with pytest.raises(SigmaConfigurationError, match="Unknown condition type.*2"):
        ProcessingItem.from_dict({
            "id": "test",
            "conditions": [
                {
                    "type": "true",
                    "dummy": "test-true"
                },
                {
                    "type": "unknown",
                    "dummy": "test-false"
                },
            ],
            "cond_op": "or",
            "type": "append",
            "s": "Test",
        })

def test_processingitem_fromdict_unknown_parameter():
    with pytest.raises(SigmaConfigurationError, match="Error in condition.*2"):
        ProcessingItem.from_dict({
            "id": "test",
            "conditions": [
                {
                    "type": "true",
                    "dummy": "test-true"
                },
                {
                    "type": "false",
                    "unknown": "test-false"
                },
            ],
            "cond_op": "or",
            "type": "append",
            "s": "Test",
        }) == ProcessingItem(
            conditions=[
                ConditionTrue(dummy="test-true"),
                ConditionFalse(dummy="test-false"),
            ],
            condition_linking=any,
            transformation=TransformationAppend(s="Test")
        )

def test_processingitem_fromdict_missing_transformation_type():
    with pytest.raises(SigmaConfigurationError, match="Missing transformation type"):
        ProcessingItem.from_dict({
            "id": "test",
            "conditions": [
                {
                    "type": "true",
                    "dummy": "test-true"
                },
                {
                    "type": "false",
                    "dummy": "test-false"
                },
            ],
            "cond_op": "or",
            "s": "Test",
        })

def test_processingitem_fromdict_unknown_transformation_type():
    with pytest.raises(SigmaConfigurationError, match="Unknown transformation type"):
        ProcessingItem.from_dict({
            "id": "test",
            "conditions": [
                {
                    "type": "true",
                    "dummy": "test-true"
                },
                {
                    "type": "false",
                    "dummy": "test-false"
                },
            ],
            "cond_op": "or",
            "type": "unknown",
            "s": "Test",
        })

def test_processingitem_fromdict_unknown_transformation_parameter():
    with pytest.raises(SigmaConfigurationError, match="Error in transformation"):
        ProcessingItem.from_dict({
            "id": "test",
            "conditions": [
                {
                    "type": "true",
                    "dummy": "test-true"
                },
                {
                    "type": "false",
                    "dummy": "test-false"
                },
            ],
            "cond_op": "or",
            "type": "append",
            "unknown": "Test",
        })

def test_processingitem_apply(processing_item, dummy_processing_pipeline, sigma_rule):
    result_rule, applied = processing_item.apply(dummy_processing_pipeline, sigma_rule)
    assert applied and result_rule.title == "TestTest"

def test_processingitem_apply_notapplied_all_with_false(dummy_processing_pipeline, sigma_rule):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        condition_linking=all,
        conditions=[
            ConditionTrue(dummy="test-true"),
            ConditionFalse(dummy="test-false"),
        ],
    )
    result_rule, applied = processing_item.apply(dummy_processing_pipeline, sigma_rule)
    assert not applied and result_rule.title == "Test"

def test_processingitem_apply_notapplied_any_without_true(dummy_processing_pipeline, sigma_rule):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        condition_linking=any,
        conditions=[
            ConditionFalse(dummy="test-true"),
            ConditionFalse(dummy="test-false"),
        ],
    )
    result_rule, applied = processing_item.apply(dummy_processing_pipeline, sigma_rule)
    assert not applied and result_rule.title == "Test"

def test_processingpipeline_fromdict(processing_item_dict, processing_item, processing_pipeline_vars):
    assert ProcessingPipeline.from_dict({
        "transformations": [ processing_item_dict ],
        "vars": processing_pipeline_vars,
    }) == ProcessingPipeline(
        items=[ processing_item ],
        vars=processing_pipeline_vars,
    )

def test_processingpipeline_fromdict_error(processing_item_dict_with_error):
    with pytest.raises(SigmaConfigurationError, match="Error in processing rule 1:.*2"):
        ProcessingPipeline.from_dict({ "transformations": [ processing_item_dict_with_error ], })

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
                conditions=[ConditionFalse(dummy="test")],
                identifier="pre"
                ),
            ProcessingItem(transformation=TransformationAppend(s="Appended"), identifier="append"),
        ]
    )
    result_rule = pipeline.apply(sigma_rule)
    assert result_rule.title == "TestAppended" \
        and pipeline.applied == [False, True] \
        and pipeline.applied_ids == { "append" }