import pytest
from dataclasses import dataclass
import re
from textwrap import dedent
from sigma.processing.condition_expressions import ConditionAND, ConditionIdentifier, ConditionNOT
from sigma.processing.finalization import ConcatenateQueriesFinalizer, JSONFinalizer
from sigma.processing.pipeline import (
    ProcessingPipeline,
    ProcessingItem,
    QueryPostprocessingItem,
    SigmaPipelineParsingError,
)
from sigma.processing.transformations import transformations
from sigma.processing.conditions import (
    DetectionItemProcessingItemAppliedCondition,
    FieldNameProcessingCondition,
    field_name_conditions,
    IncludeFieldCondition,
    LogsourceCondition,
    rule_conditions,
    RuleProcessingCondition,
    detection_item_conditions,
    DetectionItemProcessingCondition,
    FieldNameProcessingItemAppliedCondition,
)
from sigma.processing.postprocessing import EmbedQueryTransformation
from sigma.processing.transformations import (
    SetStateTransformation,
    Transformation,
    FieldMappingTransformation,
    AddFieldnamePrefixTransformation,
    FieldFunctionTransformation,
)
from sigma.rule import SigmaRule, SigmaDetectionItem
from sigma.exceptions import SigmaConfigurationError, SigmaPipelineConditionError, SigmaTypeError
from sigma.types import SigmaString


@dataclass
class RuleConditionTrue(RuleProcessingCondition):
    dummy: str

    def match(self, rule: SigmaRule) -> bool:
        return True


@dataclass
class RuleConditionFalse(RuleProcessingCondition):
    dummy: str

    def match(self, rule: SigmaRule) -> bool:
        return False


@dataclass
class DetectionItemConditionTrue(DetectionItemProcessingCondition):
    dummy: str

    def match(self, detection_item: SigmaDetectionItem) -> bool:
        return True


@dataclass
class DetectionItemConditionFalse(DetectionItemProcessingCondition):
    dummy: str

    def match(self, detection_item: SigmaDetectionItem) -> bool:
        return False


@dataclass
class FieldNameConditionTrue(FieldNameProcessingCondition):
    dummy: str

    def match_field_name(self, field_name: str) -> bool:
        return True


@dataclass
class FieldNameConditionFalse(FieldNameProcessingCondition):
    dummy: str

    def match_field_name(self, field_name: str) -> bool:
        return False


@dataclass
class FieldNameConditionTrue(FieldNameProcessingCondition):
    dummy: str

    def match_field_name(self, field_name: str) -> bool:
        return True


@dataclass
class FieldNameConditionFalse(FieldNameProcessingCondition):
    dummy: str

    def match_field_name(self, field_name: str) -> bool:
        return False


@dataclass
class TransformationPrepend(Transformation):
    s: str

    def apply(self, rule: SigmaRule) -> SigmaRule:
        super().apply(rule)
        rule.title = self.s + rule.title
        return rule


@dataclass
class TransformationAppend(Transformation):
    s: str

    def apply(self, rule: SigmaRule) -> SigmaRule:
        super().apply(rule)
        rule.title += self.s
        return rule


@pytest.fixture(autouse=True)
def inject_test_classes(monkeypatch):
    monkeypatch.setitem(rule_conditions, "true", RuleConditionTrue)
    monkeypatch.setitem(rule_conditions, "false", RuleConditionFalse)
    monkeypatch.setitem(detection_item_conditions, "true", DetectionItemConditionTrue)
    monkeypatch.setitem(detection_item_conditions, "false", DetectionItemConditionFalse)
    monkeypatch.setitem(field_name_conditions, "true", FieldNameConditionTrue)
    monkeypatch.setitem(field_name_conditions, "false", FieldNameConditionFalse)
    monkeypatch.setitem(transformations, "prepend", TransformationPrepend)
    monkeypatch.setitem(transformations, "append", TransformationAppend)


@pytest.fixture
def sigma_rule():
    return SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "test": {"field": "value"},
                "condition": "test",
            },
        }
    )


@pytest.fixture
def detection_item():
    return SigmaDetectionItem("field", [], [SigmaString("value")])


@pytest.fixture
def processing_item_dict():
    return {
        "id": "test",
        "rule_conditions": [
            {"type": "true", "dummy": "test-true"},
            {"type": "false", "dummy": "test-false"},
        ],
        "rule_cond_op": "or",
        "detection_item_conditions": [
            {"type": "true", "dummy": "test-true"},
            {"type": "false", "dummy": "test-false"},
        ],
        "detection_item_cond_op": "or",
        "field_name_conditions": [
            {"type": "true", "dummy": "test-true"},
            {"type": "false", "dummy": "test-false"},
        ],
        "field_name_cond_op": "or",
        "type": "append",
        "s": "Test",
    }


@pytest.fixture
def processing_item_with_condition_expr_dict():
    return {
        "id": "test",
        "rule_conditions": {
            "cond1": {"type": "true", "dummy": "test-true"},
            "cond2": {"type": "false", "dummy": "test-false"},
        },
        "rule_cond_expr": "cond1 and not cond2",
        "detection_item_conditions": {
            "cond1": {"type": "true", "dummy": "test-true"},
            "cond2": {"type": "false", "dummy": "test-false"},
        },
        "detection_item_cond_expr": "cond1 and not cond2",
        "field_name_conditions": {
            "cond1": {"type": "true", "dummy": "test-true"},
            "cond2": {"type": "false", "dummy": "test-false"},
        },
        "field_name_cond_expr": "cond1 and not cond2",
        "type": "append",
        "s": "Test",
    }


@pytest.fixture
def processing_item_dict_with_error():
    return {
        "id": "test",
        "rule_conditions": [
            {"type": "true", "dummy": "test-true"},
            {"dummy": "test-false"},
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
        field_name_condition_linking=any,
        field_name_conditions=[
            FieldNameConditionTrue(dummy="test-true"),
            FieldNameConditionFalse(dummy="test-false"),
        ],
        identifier="test",
    )


@pytest.fixture
def processing_item_with_condition_expr():
    return ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        rule_conditions={
            "cond1": RuleConditionTrue(dummy="test-true"),
            "cond2": RuleConditionFalse(dummy="test-false"),
        },
        rule_condition_expression=ConditionAND(
            0, ConditionIdentifier(0, "cond1"), ConditionNOT(10, ConditionIdentifier(14, "cond2"))
        ),
        detection_item_conditions={
            "cond1": DetectionItemConditionTrue(dummy="test-true"),
            "cond2": DetectionItemConditionFalse(dummy="test-false"),
        },
        detection_item_condition_expression=ConditionAND(
            0, ConditionIdentifier(0, "cond1"), ConditionNOT(10, ConditionIdentifier(14, "cond2"))
        ),
        field_name_conditions={
            "cond1": FieldNameConditionTrue(dummy="test-true"),
            "cond2": FieldNameConditionFalse(dummy="test-false"),
        },
        field_name_condition_expression=ConditionAND(
            0, ConditionIdentifier(0, "cond1"), ConditionNOT(10, ConditionIdentifier(14, "cond2"))
        ),
        identifier="test",
    )


@pytest.fixture
def postprocessing_item_dict():
    return {
        "id": "test",
        "rule_conditions": [
            {"type": "true", "dummy": "test-true"},
            {"type": "false", "dummy": "test-false"},
        ],
        "rule_cond_op": "or",
        "type": "embed",
        "prefix": "[ ",
        "suffix": " ]",
    }


@pytest.fixture
def postprocessing_item():
    return QueryPostprocessingItem(
        transformation=EmbedQueryTransformation(prefix="[ ", suffix=" ]"),
        rule_condition_linking=any,
        rule_conditions=[
            RuleConditionTrue(dummy="test-true"),
            RuleConditionFalse(dummy="test-false"),
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


def test_processingitem_fromdict_with_condition_expr(
    processing_item_with_condition_expr_dict, processing_item_with_condition_expr, sigma_rule
):
    assert (
        ProcessingItem.from_dict(processing_item_with_condition_expr_dict)
        == processing_item_with_condition_expr
    )


def test_processingitem_condition_expr_unreferenced_rule_condition():
    with pytest.raises(SigmaPipelineConditionError, match="Rule condition.*contains unreferenced"):
        ProcessingItem(
            transformation=TransformationAppend(s="Test"),
            rule_conditions={
                "cond1": RuleConditionTrue(dummy="test-true"),
                "cond2": RuleConditionFalse(dummy="test-false"),
                "cond3": RuleConditionTrue(dummy="test-unreferenced"),
            },
            rule_condition_expression=ConditionAND(
                0,
                ConditionIdentifier(0, "cond1"),
                ConditionNOT(10, ConditionIdentifier(14, "cond2")),
            ),
            identifier="test",
        )


def test_processingitem_condition_expr_unreferenced_detection_item_condition():
    with pytest.raises(
        SigmaPipelineConditionError, match="Detection item condition.*contains unreferenced"
    ):
        ProcessingItem(
            transformation=TransformationAppend(s="Test"),
            detection_item_conditions={
                "cond1": DetectionItemConditionTrue(dummy="test-true"),
                "cond2": DetectionItemConditionFalse(dummy="test-false"),
                "cond3": DetectionItemConditionTrue(dummy="test-unreferenced"),
            },
            detection_item_condition_expression=ConditionAND(
                0,
                ConditionIdentifier(0, "cond1"),
                ConditionNOT(10, ConditionIdentifier(14, "cond2")),
            ),
            identifier="test",
        )


def test_processingitem_condition_expr_unreferenced_field_name_condition():
    with pytest.raises(
        SigmaPipelineConditionError, match="Field name condition.*contains unreferenced"
    ):
        ProcessingItem(
            transformation=TransformationAppend(s="Test"),
            field_name_conditions={
                "cond1": FieldNameConditionTrue(dummy="test-true"),
                "cond2": FieldNameConditionFalse(dummy="test-false"),
                "cond3": FieldNameConditionTrue(dummy="test-unreferenced"),
            },
            field_name_condition_expression=ConditionAND(
                0,
                ConditionIdentifier(0, "cond1"),
                ConditionNOT(10, ConditionIdentifier(14, "cond2")),
            ),
            identifier="test",
        )


def test_processingitem_default_linking():
    processing_item = ProcessingItem(transformation=TransformationAppend(s="Test"))
    assert processing_item.rule_condition_linking == all
    assert processing_item.detection_item_condition_linking == all
    assert processing_item.field_name_condition_linking == all


def test_processingitem_fromdict_without_id(processing_item_dict, processing_item):
    del processing_item_dict["id"]
    item1 = ProcessingItem.from_dict(processing_item_dict)
    item2 = ProcessingItem.from_dict(processing_item_dict)

    # Should generate deterministic identifiers when no ID is provided
    assert item1.identifier is not None
    assert item2.identifier is not None
    assert item1.identifier == item2.identifier
    assert len(item1.identifier) == 16  # SHA256 hash truncated to 16 chars


def test_processingitem_fromdict_missing_condition_type():
    with pytest.raises(SigmaConfigurationError, match="Missing condition type.*2"):
        ProcessingItem.from_dict(
            {
                "id": "test",
                "rule_conditions": [
                    {"type": "true", "dummy": "test-true"},
                    {"dummy": "test-missing"},
                ],
                "rule_cond_op": "or",
                "type": "append",
                "s": "Test",
            }
        )


def test_processingitem_fromdict_unknown_condition_type():
    with pytest.raises(SigmaConfigurationError, match="Unknown condition type.*2"):
        ProcessingItem.from_dict(
            {
                "id": "test",
                "rule_conditions": [
                    {"type": "true", "dummy": "test-true"},
                    {"type": "unknown", "dummy": "test-false"},
                ],
                "rule_cond_op": "or",
                "type": "append",
                "s": "Test",
            }
        )


def test_processingitem_fromdict_unknown_parameter():
    with pytest.raises(SigmaConfigurationError, match="Error in condition.*2"):
        ProcessingItem.from_dict(
            {
                "id": "test",
                "rule_conditions": [
                    {"type": "true", "dummy": "test-true"},
                    {"type": "false", "unknown": "test-false"},
                ],
                "rule_cond_op": "or",
                "type": "append",
                "s": "Test",
            }
        ) == ProcessingItem(
            rule_conditions=[
                RuleConditionTrue(dummy="test-true"),
                RuleConditionFalse(dummy="test-false"),
            ],
            rule_condition_linking=any,
            transformation=TransformationAppend(s="Test"),
        )


def test_processingitem_fromdict_missing_transformation_type():
    with pytest.raises(SigmaConfigurationError, match="Missing transformation type"):
        ProcessingItem.from_dict(
            {
                "id": "test",
                "rule_conditions": [
                    {"type": "true", "dummy": "test-true"},
                    {"type": "false", "dummy": "test-false"},
                ],
                "rule_cond_op": "or",
                "s": "Test",
            }
        )


def test_processingitem_fromdict_unknown_transformation_type():
    with pytest.raises(SigmaConfigurationError, match="Unknown transformation type"):
        ProcessingItem.from_dict(
            {
                "id": "test",
                "rule_conditions": [
                    {"type": "true", "dummy": "test-true"},
                    {"type": "false", "dummy": "test-false"},
                ],
                "rule_cond_op": "or",
                "type": "unknown",
                "s": "Test",
            }
        )


def test_processingitem_fromdict_unknown_transformation_parameter():
    with pytest.raises(SigmaConfigurationError, match="Error in transformation"):
        ProcessingItem.from_dict(
            {
                "id": "test",
                "rule_conditions": [
                    {"type": "true", "dummy": "test-true"},
                    {"type": "false", "dummy": "test-false"},
                ],
                "rule_cond_op": "or",
                "type": "append",
                "unknown": "Test",
            }
        )


def test_processingitem_apply(processing_item, sigma_rule):
    applied = processing_item.apply(sigma_rule)
    assert applied and sigma_rule.title == "TestTest"


def test_processingitem_apply_condition_expr(processing_item_with_condition_expr, sigma_rule):
    applied = processing_item_with_condition_expr.apply(sigma_rule)
    assert applied and sigma_rule.title == "TestTest"


def test_processingitem_apply_condition_expr(processing_item_with_condition_expr, sigma_rule):
    applied = processing_item_with_condition_expr.apply(sigma_rule)
    assert applied and sigma_rule.title == "TestTest"


def test_processingitem_apply_notapplied_all_with_false(sigma_rule):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        rule_condition_linking=all,
        rule_conditions=[
            RuleConditionTrue(dummy="test-true"),
            RuleConditionFalse(dummy="test-false"),
        ],
    )
    applied = processing_item.apply(sigma_rule)
    assert not applied and sigma_rule.title == "Test"


def test_processingitem_apply_negated_true(sigma_rule):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        rule_condition_negation=True,
        rule_conditions=[
            RuleConditionTrue(dummy="test-true"),
        ],
    )
    applied = processing_item.apply(sigma_rule)
    assert not applied and sigma_rule.title == "Test"


def test_processingitem_apply_negated_false(sigma_rule):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        rule_condition_negation=True,
        rule_conditions=[
            RuleConditionFalse(dummy="test-false"),
        ],
    )
    applied = processing_item.apply(sigma_rule)
    assert applied and sigma_rule.title == "TestTest"


def test_processingitem_apply_notapplied_all_with_false(sigma_rule):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        rule_condition_linking=all,
        rule_conditions=[
            RuleConditionTrue(dummy="test-true"),
            RuleConditionFalse(dummy="test-false"),
        ],
    )
    applied = processing_item.apply(sigma_rule)
    assert not applied and sigma_rule.title == "Test"


def test_processingitem_match_detection_item(detection_item):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        detection_item_condition_linking=any,
        detection_item_conditions=[
            DetectionItemConditionTrue(dummy="test-true"),
            DetectionItemConditionFalse(dummy="test-false"),
        ],
    )
    assert processing_item.match_detection_item(detection_item) == True


def test_processingitem_match_detection_item_dict_detections(detection_item):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        detection_item_conditions={
            "cond1": DetectionItemConditionTrue(dummy="test-true"),
            "cond2": DetectionItemConditionFalse(dummy="test-false"),
        },
        detection_item_condition_linking=any,
    )
    assert processing_item.match_detection_item(detection_item) == True


def test_processingitem_match_detection_item_dict_detections(detection_item):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        detection_item_conditions={
            "cond1": DetectionItemConditionTrue(dummy="test-true"),
            "cond2": DetectionItemConditionFalse(dummy="test-false"),
        },
        detection_item_condition_linking=any,
    )
    assert processing_item.match_detection_item(detection_item) == True


def test_processingitem_match_detection_item_all_with_false(detection_item):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        detection_item_condition_linking=all,
        detection_item_conditions=[
            DetectionItemConditionTrue(dummy="test-true"),
            DetectionItemConditionFalse(dummy="test-false"),
        ],
    )
    assert processing_item.match_detection_item(detection_item) == False


def test_processingitem_match_detection_item_any_without_true(detection_item):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        detection_item_condition_linking=any,
        detection_item_conditions=[
            DetectionItemConditionFalse(dummy="test-true"),
            DetectionItemConditionFalse(dummy="test-false"),
        ],
    )
    assert processing_item.match_detection_item(detection_item) == False


def test_processingitem_match_detection_item_negated_true(detection_item):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        detection_item_condition_negation=True,
        detection_item_conditions=[
            DetectionItemConditionTrue(dummy="test-true"),
        ],
    )
    assert processing_item.match_detection_item(detection_item) == False


def test_processingitem_match_detection_item_negated_false(detection_item):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        detection_item_condition_negation=True,
        detection_item_conditions=[
            DetectionItemConditionFalse(dummy="test-false"),
        ],
    )
    assert processing_item.match_detection_item(detection_item)


def test_processingitem_match_detection_item_with_expression_false(detection_item):
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        detection_item_conditions={
            "cond1": DetectionItemConditionTrue(dummy="test-true"),
            "cond2": DetectionItemConditionTrue(dummy="test-false"),
        },
        detection_item_condition_expression=ConditionAND(
            0, ConditionIdentifier(0, "cond1"), ConditionNOT(10, ConditionIdentifier(14, "cond2"))
        ),
    )
    assert not processing_item.match_detection_item(detection_item)


def test_processingitem_match_field_name():
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        field_name_conditions=[
            FieldNameConditionTrue(dummy="test-true"),
            FieldNameConditionFalse(dummy="test-false"),
        ],
        field_name_condition_linking=any,
    )
    assert processing_item.match_field_name("field") == True


def test_processingitem_match_field_name_dict_fields():
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        field_name_conditions={
            "cond1": FieldNameConditionTrue(dummy="test-true"),
            "cond2": FieldNameConditionFalse(dummy="test-false"),
        },
        field_name_condition_linking=any,
    )
    assert processing_item.match_field_name("field") == True


def test_processingitem_match_field_name_with_expression():
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        field_name_conditions={
            "cond1": FieldNameConditionTrue(dummy="test-true"),
            "cond2": FieldNameConditionFalse(dummy="test-false"),
        },
        field_name_condition_expression=ConditionAND(
            0, ConditionIdentifier(0, "cond1"), ConditionNOT(10, ConditionIdentifier(14, "cond2"))
        ),
    )
    assert processing_item.match_field_name("field") == True


def test_processingitem_match_field_name_with_expression_false():
    processing_item = ProcessingItem(
        transformation=TransformationAppend(s="Test"),
        field_name_conditions={
            "cond1": FieldNameConditionTrue(dummy="test-true"),
            "cond2": FieldNameConditionTrue(dummy="test-false"),
        },
        field_name_condition_expression=ConditionAND(
            0, ConditionIdentifier(0, "cond1"), ConditionNOT(10, ConditionIdentifier(14, "cond2"))
        ),
    )
    assert not processing_item.match_field_name("field")


def test_processingitem_rule_condition_no_list_or_dict():
    with pytest.raises(SigmaTypeError, match="Rule conditions"):
        ProcessingItem(
            rule_conditions=LogsourceCondition(category="test"),
            transformation=SetStateTransformation("test", True),
        )


def test_processingitem_detection_item_condition_no_list_or_dict():
    with pytest.raises(SigmaTypeError, match="Detection item conditions"):
        ProcessingItem(
            detection_item_conditions=DetectionItemProcessingItemAppliedCondition("test"),
            transformation=SetStateTransformation("test", True),
        )


def test_processingitem_field_name_condition_no_list_or_dict():
    with pytest.raises(SigmaTypeError, match="Field name conditions"):
        ProcessingItem(
            field_name_conditions=IncludeFieldCondition(fields=["test"]),
            transformation=SetStateTransformation("test", True),
        )


def test_processingitem_wrong_rule_condition():
    with pytest.raises(SigmaTypeError, match="RuleProcessingCondition"):
        ProcessingItem(
            rule_conditions=[IncludeFieldCondition(fields=["testfield"])],
            transformation=SetStateTransformation("test", True),
        )


def test_processingitem_wrong_rule_condition_dict():
    with pytest.raises(SigmaTypeError, match="RuleProcessingCondition"):
        ProcessingItem(
            rule_conditions={"cond": IncludeFieldCondition(fields=["testfield"])},
            transformation=SetStateTransformation("test", True),
        )


def test_processingitem_rule_condition_linking_with_expr():
    with pytest.raises(
        SigmaConfigurationError, match="Rule condition expression is mutually exclusive"
    ):
        ProcessingItem(
            rule_condition_linking=any,
            rule_conditions=[
                RuleConditionTrue(dummy="test-true"),
                RuleConditionFalse(dummy="test-false"),
            ],
            rule_condition_expression="cond1 or cond2",
            transformation=SetStateTransformation("test", True),
        )


def test_processingitem_detection_item_condition_linking_with_expr():
    with pytest.raises(
        SigmaConfigurationError, match="Detection item condition expression is mutually exclusive"
    ):
        ProcessingItem(
            detection_item_condition_linking=any,
            detection_item_conditions=[
                DetectionItemConditionTrue(dummy="test-true"),
                DetectionItemConditionFalse(dummy="test-false"),
            ],
            detection_item_condition_expression="cond1 or cond2",
            transformation=SetStateTransformation("test", True),
        )


def test_processingitem_field_name_condition_linking_with_expr():
    with pytest.raises(SigmaConfigurationError, match="must be provided as mapping"):
        ProcessingItem(
            field_name_condition_linking=any,
            field_name_conditions=[
                FieldNameProcessingItemAppliedCondition("test"),
                FieldNameProcessingItemAppliedCondition("test"),
            ],
            detection_item_condition_expression="cond1 or cond2",
            transformation=SetStateTransformation("test", True),
        )


def test_processingitem_rule_condition_expr_with_list():
    with pytest.raises(SigmaConfigurationError, match="mapping from identifiers to conditions"):
        ProcessingItem(
            rule_conditions=[
                RuleConditionTrue(dummy="test-true"),
                RuleConditionFalse(dummy="test-false"),
            ],
            rule_condition_expression="cond1 or cond2",
            transformation=SetStateTransformation("test", True),
        )


def test_processingitem_detecton_item_condition_expr_with_list():
    with pytest.raises(SigmaConfigurationError, match="mapping from identifiers to conditions"):
        ProcessingItem(
            detection_item_conditions=[
                DetectionItemConditionTrue(dummy="test-true"),
                DetectionItemConditionFalse(dummy="test-false"),
            ],
            detection_item_condition_expression="cond1 or cond2",
            transformation=SetStateTransformation("test", True),
        )


def test_processingitem_wrong_detection_item_condition():
    with pytest.raises(SigmaTypeError, match="DetectionItemProcessingCondition"):
        ProcessingItem(
            detection_item_conditions=[IncludeFieldCondition(fields=["testfield"])],
            transformation=SetStateTransformation("test", True),
        )


def test_processingitem_wrong_detection_item_condition_dict():
    with pytest.raises(SigmaTypeError, match="DetectionItemProcessingCondition"):
        ProcessingItem(
            detection_item_conditions={"cond": IncludeFieldCondition(fields=["testfield"])},
            transformation=SetStateTransformation("test", True),
        )


def test_processingitem_wrong_field_name_condition():
    with pytest.raises(SigmaTypeError, match="FieldNameProcessingCondition"):
        ProcessingItem(
            field_name_conditions=[LogsourceCondition(category="test")],
            transformation=SetStateTransformation("test", True),
        )


def test_processingitem_wrong_field_name_condition_dict():
    with pytest.raises(SigmaTypeError, match="FieldNameProcessingCondition"):
        ProcessingItem(
            field_name_conditions={"cond": LogsourceCondition(category="test")},
            transformation=SetStateTransformation("test", True),
        )


def test_postprocessingitem_fromdict(postprocessing_item_dict, postprocessing_item):
    assert QueryPostprocessingItem.from_dict(postprocessing_item_dict) == postprocessing_item


def test_postprocessingitem_apply(postprocessing_item: QueryPostprocessingItem, sigma_rule):
    postprocessing_item.apply(sigma_rule, "field=value") == "[ field=value ]"


def test_postprocessingitem_apply_false_condition(
    postprocessing_item: QueryPostprocessingItem, sigma_rule, monkeypatch
):
    monkeypatch.setattr(postprocessing_item, "rule_conditions", [RuleConditionFalse(dummy="test")])
    assert postprocessing_item.apply(sigma_rule, "field=value") == (
        "field=value",
        False,
    )


def test_postprocessingitem_condition_not_list():
    with pytest.raises(SigmaTypeError, match="must be provided as list"):
        QueryPostprocessingItem(
            transformation=EmbedQueryTransformation(prefix="[ ", suffix=" ]"),
            rule_conditions=RuleConditionTrue(dummy="test-true"),
            identifier="test",
        )


def test_postprocessingitem_wrong_condition_type():
    with pytest.raises(SigmaTypeError, match="is not a RuleProcessingCondition"):
        QueryPostprocessingItem(
            transformation=EmbedQueryTransformation(prefix="[ ", suffix=" ]"),
            rule_conditions=[DetectionItemConditionTrue(dummy="test-true")],
            identifier="test",
        )


def test_processingpipeline_fromdict(
    processing_item_dict,
    processing_item,
    postprocessing_item_dict,
    postprocessing_item,
    processing_pipeline_vars,
):
    assert ProcessingPipeline.from_dict(
        {
            "name": "Test",
            "priority": 10,
            "transformations": [processing_item_dict],
            "postprocessing": [postprocessing_item_dict],
            "finalizers": [
                {
                    "type": "concat",
                    "prefix": "('",
                    "separator": "', '",
                    "suffix": "')",
                }
            ],
            "vars": processing_pipeline_vars,
        }
    ) == ProcessingPipeline(
        name="Test",
        priority=10,
        items=[processing_item],
        postprocessing_items=[postprocessing_item],
        finalizers=[ConcatenateQueriesFinalizer(prefix="('", separator="', '", suffix="')")],
        vars=processing_pipeline_vars,
    )


def test_processingpipeline_fromyaml(
    processing_item_dict, processing_item, postprocessing_item, processing_pipeline_vars
):
    assert (
        ProcessingPipeline.from_yaml(
            """
        name: Test
        priority: 10
        allowed_backends:
            - test-a
            - test-b
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
              field_name_conditions:
                  - type: "true"
                    dummy: test-true
                  - type: "false"
                    dummy: test-false
              field_name_cond_op: or
              type: append
              s: Test
        postprocessing:
            - id: test
              type: embed
              prefix: "[ "
              suffix: " ]"
              rule_conditions:
                  - type: "true"
                    dummy: test-true
                  - type: "false"
                    dummy: test-false
              rule_cond_op: or
        finalizers:
            - type: concat
              prefix: "('"
              separator: "', '"
              suffix: "')"
        vars:
            test_string: abc
            test_number: 123
    """
        )
        == ProcessingPipeline(
            name="Test",
            priority=10,
            items=[processing_item],
            postprocessing_items=[postprocessing_item],
            finalizers=[ConcatenateQueriesFinalizer(prefix="('", separator="', '", suffix="')")],
            vars=processing_pipeline_vars,
            allowed_backends={"test-a", "test-b"},
        )
    )


def test_processingpipeline_fromyaml_invalid(
    processing_item_dict, processing_item, postprocessing_item, processing_pipeline_vars
):
    with pytest.raises(
        SigmaPipelineParsingError, match="Error in parsing of a Sigma processing pipeline"
    ):
        ProcessingPipeline.from_yaml(
            """
                {not a yaml
            """
        )


def test_processingpipeline_fromyaml_unknown(
    processing_item_dict, processing_item, postprocessing_item, processing_pipeline_vars
):
    with pytest.raises(SigmaConfigurationError, match="Unkown keys \['transformation'\]"):
        ProcessingPipeline.from_yaml(
            """
        name: unknown
        priority: 10
        transformation:
        - id: test
          type: test
          method: test
            """
        )


def test_processingpipeline_fromdict_error(processing_item_dict_with_error):
    with pytest.raises(SigmaConfigurationError, match="Error in processing rule 1:.*2"):
        ProcessingPipeline.from_dict(
            {
                "transformations": [processing_item_dict_with_error],
            }
        )


def test_processingpipeline_error_direct_transformations(sigma_rule):
    """Common error: passing transformations directly instead wrapped in ProcessingItem objects. This should raise an error."""
    with pytest.raises(TypeError, match="must be a ProcessingItem"):
        ProcessingPipeline(
            items=[
                TransformationPrepend(s="Pre"),
                TransformationAppend(s="Appended"),
            ]
        )


def test_processingpipeline_error_direct_postprocessing(sigma_rule):
    """Common error: passing transformations directly instead wrapped in QueryPostprocessingItem objects. This should raise an error."""
    with pytest.raises(TypeError, match="must be a QueryPostprocessingItem"):
        ProcessingPipeline(
            postprocessing_items=[
                EmbedQueryTransformation(prefix="[ "),
                EmbedQueryTransformation(suffix=" ]"),
            ]
        )


def test_processingpipeline_wrong_finalizer(sigma_rule):
    with pytest.raises(TypeError, match="must be a Finalizer"):
        ProcessingPipeline(
            finalizers=[
                EmbedQueryTransformation(prefix="[ "),
                EmbedQueryTransformation(suffix=" ]"),
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
    assert (
        result_rule.title == "PreTestAppended"
        and pipeline.applied == [True, True]
        and pipeline.applied_ids == {"pre", "append"}
    )


def test_processingpipeline_apply_partial(sigma_rule):
    pipeline = ProcessingPipeline(
        items=[
            ProcessingItem(
                transformation=TransformationPrepend(s="Pre"),
                rule_conditions=[RuleConditionFalse(dummy="test")],
                identifier="pre",
            ),
            ProcessingItem(transformation=TransformationAppend(s="Appended"), identifier="append"),
        ]
    )
    result_rule = pipeline.apply(sigma_rule)
    assert (
        result_rule.title == "TestAppended"
        and pipeline.applied == [False, True]
        and pipeline.applied_ids == {"append"}
    )


def test_procesingpipeline_postprocess(sigma_rule):
    pipeline = ProcessingPipeline(
        postprocessing_items=[
            QueryPostprocessingItem(
                transformation=EmbedQueryTransformation(prefix="[ "),
                identifier="add_query_prefix",
            ),
            QueryPostprocessingItem(
                transformation=EmbedQueryTransformation(suffix=" ]"),
                identifier="add_query_suffix",
            ),
        ]
    )
    assert pipeline.postprocess_query(sigma_rule, "field=value") == "[ field=value ]"
    assert pipeline.applied_ids == {"add_query_prefix", "add_query_suffix"}


def test_procesingpipeline_postprocess_partial(sigma_rule):
    pipeline = ProcessingPipeline(
        postprocessing_items=[
            QueryPostprocessingItem(
                transformation=EmbedQueryTransformation(prefix="[ ", suffix=" ]"),
                rule_conditions=[RuleConditionTrue("test")],
                identifier="add_brackets",
            ),
            QueryPostprocessingItem(
                transformation=EmbedQueryTransformation(prefix="query"),
                rule_conditions=[RuleConditionFalse("test")],
                identifier="add_query_keyword",
            ),
        ]
    )
    assert pipeline.postprocess_query(sigma_rule, "field=value") == "[ field=value ]"
    assert pipeline.applied_ids == {"add_brackets"}


def test_processingpipeline_finalize():
    pipeline = ProcessingPipeline(
        finalizers=[
            ConcatenateQueriesFinalizer(separator="', '", prefix="('", suffix="')"),
            JSONFinalizer(),
        ]
    )
    assert (
        pipeline.finalize(['field1="value1"', 'field2="value2"'])
        == """\"('field1=\\"value1\\"', 'field2=\\"value2\\"')\""""
    )


def test_processingpipeline_field_processing_item_tracking():
    pipeline = ProcessingPipeline()
    pipeline.track_field_processing_items("field1", ["fieldA", "fieldB"], "processing_item_1")
    pipeline.track_field_processing_items(
        "fieldA", ["fieldA", "fieldC", "fieldD"], "processing_item_2"
    )
    pipeline.track_field_processing_items("fieldB", ["fieldD", "fieldE"], "processing_item_3")
    pipeline.track_field_processing_items("fieldE", ["fieldF"], None)
    assert pipeline.field_name_applied_ids == {
        "fieldA": {"processing_item_1", "processing_item_2"},
        "fieldC": {"processing_item_1", "processing_item_2"},
        "fieldD": {"processing_item_1", "processing_item_3"},
        "fieldF": {"processing_item_1", "processing_item_3"},
    }
    assert pipeline.field_was_processed_by("fieldF", "processing_item_3") == True
    assert pipeline.field_was_processed_by("fieldF", "processing_item_2") == False
    assert pipeline.field_was_processed_by("nonexistingfield", "processing_item_2") == False
    assert pipeline.field_was_processed_by(None, "processing_item_3") == False


@pytest.fixture(scope="module")
def processing_pipeline_with_field_name_condition():
    return ProcessingPipeline(
        items=[
            ProcessingItem(  # Field mappings
                identifier="field_mapping",
                transformation=FieldMappingTransformation(
                    {
                        "fieldA": "mappedA",
                    }
                ),
            ),
            ProcessingItem(  # Prepend each field that was not processed by previous field mapping transformation with "winlog.event_data."
                identifier="prefix",
                transformation=AddFieldnamePrefixTransformation("prefix."),
                field_name_conditions=[
                    FieldNameProcessingItemAppliedCondition("field_mapping"),
                ],
                field_name_condition_negation=True,
                field_name_condition_linking=any,
            ),
        ]
    )


def test_processingpipeline_field_name_condition_tracking_in_field_list(
    processing_pipeline_with_field_name_condition,
):
    rule = processing_pipeline_with_field_name_condition.apply(
        SigmaRule.from_yaml(
            f"""
            title: Test
            status: test
            logsource:
                category: test
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
            fields:
                - fieldA
                - fieldB
        """
        )
    )
    assert rule.fields == ["mappedA", "prefix.fieldB"]


def test_processingpipeline_field_name_condition_tracking_in_detection_item(
    processing_pipeline_with_field_name_condition,
):
    rule = processing_pipeline_with_field_name_condition.apply(
        SigmaRule.from_yaml(
            f"""
            title: Test
            status: test
            logsource:
                category: test
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
        )
    )
    detection_items = rule.detection.detections["sel"].detection_items
    detection_item_fields = [detection_item.field for detection_item in detection_items]
    assert detection_item_fields == ["mappedA", "prefix.fieldB"]


def test_processingpipeline_concatenation():
    p1 = ProcessingPipeline(
        items=[
            ProcessingItem(
                transformation=TransformationPrepend(s="Pre"),
                identifier="pre",
            ),
        ],
        postprocessing_items=[
            QueryPostprocessingItem(
                EmbedQueryTransformation(prefix="[ "),
            )
        ],
        finalizers=[ConcatenateQueriesFinalizer()],
        vars={
            "a": 1,
            "b": 2,
        },
    )
    p2 = ProcessingPipeline(
        items=[
            ProcessingItem(
                transformation=TransformationAppend(s="Append"),
                identifier="append",
            ),
        ],
        postprocessing_items=[
            QueryPostprocessingItem(
                EmbedQueryTransformation(suffix=" ]"),
            ),
        ],
        finalizers=[JSONFinalizer()],
        vars={
            "b": 3,
            "c": 4,
        },
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
        postprocessing_items=[
            QueryPostprocessingItem(EmbedQueryTransformation(prefix="[ ")),
            QueryPostprocessingItem(EmbedQueryTransformation(suffix=" ]")),
        ],
        finalizers=[
            ConcatenateQueriesFinalizer(),
            JSONFinalizer(),
        ],
        vars={
            "a": 1,
            "b": 3,
            "c": 4,
        },
    )


def test_processingpipeline_sum():
    ps = [
        ProcessingPipeline(
            items=[
                ProcessingItem(
                    transformation=TransformationPrepend(s="Pre"),
                    identifier="pre",
                ),
            ],
            postprocessing_items=[
                QueryPostprocessingItem(EmbedQueryTransformation(prefix="[ ")),
            ],
            finalizers=[
                ConcatenateQueriesFinalizer(),
            ],
            vars={
                "a": 1,
                "b": 2,
            },
        ),
        ProcessingPipeline(
            items=[
                ProcessingItem(
                    transformation=TransformationAppend(s="Append"),
                    identifier="append",
                ),
            ],
            finalizers=[
                JSONFinalizer(),
            ],
            vars={
                "b": 3,
                "c": 4,
            },
        ),
        ProcessingPipeline(
            items=[
                ProcessingItem(
                    transformation=TransformationAppend(s="AppendAnother"),
                    identifier="append_another",
                ),
            ],
            postprocessing_items=[
                QueryPostprocessingItem(EmbedQueryTransformation(suffix=" ]")),
            ],
            vars={"c": 5, "d": 6},
        ),
    ]
    assert sum(ps) == ProcessingPipeline(
        items=[
            ProcessingItem(
                transformation=TransformationPrepend(s="Pre"),
                identifier="pre",
            ),
            ProcessingItem(
                transformation=TransformationAppend(s="Append"),
                identifier="append",
            ),
            ProcessingItem(
                transformation=TransformationAppend(s="AppendAnother"),
                identifier="append_another",
            ),
        ],
        postprocessing_items=[
            QueryPostprocessingItem(EmbedQueryTransformation(prefix="[ ")),
            QueryPostprocessingItem(EmbedQueryTransformation(suffix=" ]")),
        ],
        finalizers=[
            ConcatenateQueriesFinalizer(),
            JSONFinalizer(),
        ],
        vars={
            "a": 1,
            "b": 3,
            "c": 5,
            "d": 6,
        },
    )


def test_processingpipeline_null_concatenation():
    p = ProcessingPipeline(
        items=[
            ProcessingItem(
                transformation=TransformationPrepend(s="Pre"),
                identifier="pre",
            ),
        ],
        vars={
            "a": 1,
            "b": 2,
        },
    )
    assert p + None == p


def test_processingpipeline_invalid_concatenation():
    with pytest.raises(TypeError):
        (
            ProcessingPipeline(
                items=[
                    ProcessingItem(
                        transformation=TransformationAppend(s="Append"),
                        identifier="append",
                    ),
                ],
            )
            + 3
        )


def test_processingpipeline_invalid_concatenation_left():
    with pytest.raises(TypeError):
        3 + ProcessingPipeline(
            items=[
                ProcessingItem(
                    transformation=TransformationAppend(s="Append"),
                    identifier="append",
                ),
            ],
        )


@pytest.fixture(scope="module")
def processing_pipeline_with_field_func_transform():
    return ProcessingPipeline(
        items=[
            ProcessingItem(  # Field mappings
                identifier="field_transform",
                transformation=FieldFunctionTransformation(
                    transform_func=lambda f: f.upper(),
                    mapping={
                        "fieldA": "mappedA",
                    },
                ),
            ),
        ]
    )


def test_processingpipeline_field_name_transformation_in_field_list(
    processing_pipeline_with_field_func_transform,
):
    rule = processing_pipeline_with_field_func_transform.apply(
        SigmaRule.from_yaml(
            f"""
            title: Test
            status: test
            logsource:
                category: test
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
            fields:
                - fieldA
                - fieldB
        """
        )
    )
    assert rule.fields == ["mappedA", "FIELDB"]
