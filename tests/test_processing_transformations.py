import inspect
from copy import deepcopy
from dataclasses import dataclass

import pytest

import sigma.processing.transformations as transformations_module
from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.conditions import ConditionOR, SigmaCondition
from sigma.correlations import (
    SigmaCorrelationFieldAlias,
    SigmaCorrelationFieldAliases,
    SigmaCorrelationRule,
    SigmaRuleReference,
)
from sigma.exceptions import (
    SigmaConfigurationError,
    SigmaRegularExpressionError,
    SigmaTransformationError,
    SigmaValueError,
    SigmaTypeError,
)
from sigma.modifiers import SigmaExpandModifier, SigmaRegularExpressionModifier
from sigma.processing.conditions import (
    FieldNameProcessingItemAppliedCondition,
    IncludeFieldCondition,
    RuleContainsDetectionItemCondition,
    RuleProcessingItemAppliedCondition,
    rule_conditions,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import *
from sigma.processing.transformations import (
    Transformation,
    transformations,
    __all__ as transformations_all,
    StrictFieldMappingFailure,
)
from sigma.processing.transformations.base import ConditionTransformation
from sigma.rule.detection import SigmaDetection, SigmaDetectionItem
from sigma.rule.logsource import SigmaLogSource
from sigma.rule.rule import SigmaRule
from sigma.types import (
    Placeholder,
    SigmaBool,
    SigmaExpansion,
    SigmaNull,
    SigmaNumber,
    SigmaQueryExpression,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)
from tests.test_processing_pipeline import (
    RuleConditionFalse,
    RuleConditionTrue,
    TransformationAppend,
)


@pytest.fixture
def dummy_pipeline():
    return ProcessingPipeline([], {})


@pytest.fixture
def sigma_rule():
    return SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
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
        }
    )


@pytest.fixture
def sigma_correlation_rule():
    return SigmaCorrelationRule.from_dict(
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
        }
    )


@pytest.fixture
def keyword_sigma_rule():
    return SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "test": [
                    "value1",
                    "value2",
                    "value3",
                ],
                "condition": "test",
            },
        }
    )


@pytest.fixture
def sigma_rule_placeholders():
    return SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "test": [
                    {
                        "field1|expand": "value%var1%test",
                        "field2|expand": "value%var2%test%var3%",
                        "field3|expand": "value%var1%test%var2%test%var3%test",
                    }
                ],
                "condition": "test",
            },
        }
    )


@pytest.fixture
def sigma_rule_placeholders_simple():
    return SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "test": [
                    {
                        "field|expand": "value%var1%test%var2%end",
                    }
                ],
                "condition": "test",
            },
        }
    )


@pytest.fixture
def sigma_rule_placeholders_simple_re():
    return SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "test": [
                    {
                        "field|re|expand": "value%var1%test%var2%end",
                    }
                ],
                "condition": "test",
            },
        }
    )


@pytest.fixture
def sigma_rule_placeholders_only():
    return SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "test": [
                    {
                        "field1|expand": "%var1%",
                        "field2|expand": "%var2%",
                        "field3|expand": "%var3%",
                    }
                ],
                "condition": "test",
            },
        }
    )


def test_transformaion_multiple_pipelines_set(dummy_pipeline):
    transformation = DropDetectionItemTransformation()
    transformation.set_pipeline(dummy_pipeline)
    with pytest.raises(SigmaTransformationError, match="Pipeline.*was already set"):
        transformation.set_pipeline(dummy_pipeline)


def test_field_mapping_from_dict():
    mapping = {
        "single": "single_mapping",
        "multiple": [
            "multi_mapping_1",
            "multi_mapping_2",
        ],
    }
    assert FieldMappingTransformation.from_dict({"mapping": mapping}) == FieldMappingTransformation(
        mapping
    )


@pytest.fixture
def field_mapping_transformation():
    return FieldMappingTransformation(
        {
            "field1": "fieldA",
            "field3": ["fieldC", "fieldD"],
            "testalias": "something_different",
        }
    )


@pytest.fixture
def field_mapping_transformation_sigma_rule(
    dummy_pipeline, sigma_rule, field_mapping_transformation
):
    field_mapping_transformation.set_processing_item(
        ProcessingItem(
            field_mapping_transformation,
            identifier="test",
        )
    )
    field_mapping_transformation.set_pipeline(dummy_pipeline)
    field_mapping_transformation.apply(sigma_rule)
    return (field_mapping_transformation, sigma_rule)


def test_field_mapping(field_mapping_transformation_sigma_rule):
    transformation, sigma_rule = field_mapping_transformation_sigma_rule
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("fieldA", [], [SigmaString("value1")]),
                    SigmaDetectionItem("field2", [], [SigmaString("value2")]),
                    SigmaDetection(
                        [
                            SigmaDetectionItem("fieldC", [], [SigmaString("value3")]),
                            SigmaDetectionItem("fieldD", [], [SigmaString("value3")]),
                        ],
                        item_linking=ConditionOR,
                    ),
                ]
            )
        ]
    )
    assert sigma_rule.fields == [
        "otherfield1",
        "fieldA",
        "field2",
        "fieldC",
        "fieldD",
        "otherfield2",
    ]


def test_field_mapping_correlation_rule(
    dummy_pipeline, sigma_correlation_rule, field_mapping_transformation
):
    field_mapping_transformation.set_pipeline(dummy_pipeline)
    field_mapping_transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule.group_by == ["testalias", "field2", "fieldC", "fieldD"]
    assert sigma_correlation_rule.aliases.aliases["testalias"] == SigmaCorrelationFieldAlias(
        alias="testalias",
        mapping={
            SigmaRuleReference("testrule_1"): "fieldA",
            SigmaRuleReference("testrule_2"): "field2",
        },
    )
    assert sigma_correlation_rule.condition.fieldref == "fieldA"


def test_field_mapping_correlation_rule_no_condition_fieldref(
    monkeypatch, dummy_pipeline, sigma_correlation_rule, field_mapping_transformation
):
    monkeypatch.setattr(sigma_correlation_rule.condition, "fieldref", None)
    field_mapping_transformation.set_pipeline(dummy_pipeline)
    field_mapping_transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule.group_by == ["testalias", "field2", "fieldC", "fieldD"]
    assert sigma_correlation_rule.aliases.aliases["testalias"] == SigmaCorrelationFieldAlias(
        alias="testalias",
        mapping={
            SigmaRuleReference("testrule_1"): "fieldA",
            SigmaRuleReference("testrule_2"): "field2",
        },
    )
    assert sigma_correlation_rule.condition.fieldref is None


def test_field_mapping_correlation_rule_no_condition(
    monkeypatch, dummy_pipeline, sigma_correlation_rule, field_mapping_transformation
):
    monkeypatch.setattr(sigma_correlation_rule, "condition", None)
    field_mapping_transformation.set_pipeline(dummy_pipeline)
    field_mapping_transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule.group_by == ["testalias", "field2", "fieldC", "fieldD"]
    assert sigma_correlation_rule.aliases.aliases["testalias"] == SigmaCorrelationFieldAlias(
        alias="testalias",
        mapping={
            SigmaRuleReference("testrule_1"): "fieldA",
            SigmaRuleReference("testrule_2"): "field2",
        },
    )
    assert sigma_correlation_rule.condition is None


def test_field_mapping_correlation_rule_no_groupby(
    monkeypatch, dummy_pipeline, sigma_correlation_rule, field_mapping_transformation
):
    monkeypatch.setattr(sigma_correlation_rule, "group_by", None)
    monkeypatch.setattr(sigma_correlation_rule, "aliases", SigmaCorrelationFieldAliases())
    field_mapping_transformation.set_pipeline(dummy_pipeline)
    field_mapping_transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule.group_by is None
    assert sigma_correlation_rule.aliases == SigmaCorrelationFieldAliases()
    assert sigma_correlation_rule.condition.fieldref == "fieldA"


def test_field_mapping_correlation_rule_no_alias(
    monkeypatch, dummy_pipeline, sigma_correlation_rule, field_mapping_transformation
):
    monkeypatch.setattr(sigma_correlation_rule, "aliases", SigmaCorrelationFieldAliases())
    field_mapping_transformation.set_pipeline(dummy_pipeline)
    field_mapping_transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule.group_by == ["something_different", "field2", "fieldC", "fieldD"]
    assert sigma_correlation_rule.aliases == SigmaCorrelationFieldAliases()
    assert sigma_correlation_rule.condition.fieldref == "fieldA"


def test_field_mapping_correlation_rule_multiple_alias_mappings(
    monkeypatch, dummy_pipeline, sigma_correlation_rule, field_mapping_transformation
):
    monkeypatch.setitem(
        sigma_correlation_rule.aliases.aliases["testalias"].mapping,
        SigmaRuleReference("testrule_1"),
        "field3",
    )
    with pytest.raises(SigmaConfigurationError, match="rule alias mapping.*multiple field names"):
        field_mapping_transformation.set_pipeline(dummy_pipeline)
        field_mapping_transformation.apply(sigma_correlation_rule)


def test_field_mapping_correlation_rule_multiple_condition_mappings(
    monkeypatch, dummy_pipeline, sigma_correlation_rule, field_mapping_transformation
):
    monkeypatch.setattr(sigma_correlation_rule.condition, "fieldref", "field3")
    with pytest.raises(SigmaConfigurationError, match="rule condition field.*multiple field names"):
        field_mapping_transformation.set_pipeline(dummy_pipeline)
        field_mapping_transformation.apply(sigma_correlation_rule)


def test_field_mapping_tracking(field_mapping_transformation_sigma_rule):
    transformation, sigma_rule = field_mapping_transformation_sigma_rule
    detection_items = sigma_rule.detection.detections["test"].detection_items[0].detection_items
    updated_detection_items = {
        detection_item.field: detection_item.was_processed_by("test")
        for detection_item in detection_items
        if isinstance(detection_item, SigmaDetectionItem)
    }
    updated_detection_items.update(
        {
            detection_item.field: detection_item.was_processed_by("test")
            for detection in detection_items
            if isinstance(detection, SigmaDetection)
            for detection_item in detection.detection_items
        }
    )
    assert updated_detection_items == {
        "fieldA": True,
        "field2": False,
        "fieldC": True,
        "fieldD": True,
    }
    assert sigma_rule.was_processed_by("test")
    assert transformation._pipeline.field_mappings == {
        "field1": {"fieldA"},
        "field3": {"fieldC", "fieldD"},
    }


def test_field_mapping_none_to_field_adds_wildcards(dummy_pipeline):
    """Test that mapping None (keyword) to a field adds wildcards to preserve keyword semantics."""
    rule = SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "keywords": ["a", "b", "c"],
                "condition": "keywords",
            },
        }
    )

    transformation = FieldMappingTransformation(mapping={None: "my_field"})
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(rule)

    detection_item = rule.detection.detections["keywords"].detection_items[0]
    assert detection_item.field == "my_field"

    # Check that wildcards were added
    for value in detection_item.value:
        assert isinstance(value, SigmaString)
        assert value.contains_special()
        value_str = str(value)
        assert value_str.startswith("*")
        assert value_str.endswith("*")


def test_field_mapping_none_to_multiple_fields_adds_wildcards(dummy_pipeline):
    """Test that mapping None to multiple fields adds wildcards."""
    rule = SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "keywords": ["test"],
                "condition": "keywords",
            },
        }
    )

    transformation = FieldMappingTransformation(mapping={None: ["field1", "field2"]})
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(rule)

    # Should create a SigmaDetection with multiple SigmaDetectionItems
    detection = rule.detection.detections["keywords"].detection_items[0]
    assert isinstance(detection, SigmaDetection)

    # Check each detection item has wildcards
    for item in detection.detection_items:
        assert isinstance(item, SigmaDetectionItem)
        for value in item.value:
            assert isinstance(value, SigmaString)
            assert value.contains_special()
            value_str = str(value)
            assert value_str.startswith("*")
            assert value_str.endswith("*")


def test_field_mapping_field_to_field_no_wildcards(dummy_pipeline):
    """Test that mapping a regular field to another field does NOT add wildcards."""
    rule = SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "selection": {"field1": "value"},
                "condition": "selection",
            },
        }
    )

    transformation = FieldMappingTransformation(mapping={"field1": "field2"})
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(rule)

    detection_item = rule.detection.detections["selection"].detection_items[0]
    assert detection_item.field == "field2"

    # Values should NOT have wildcards
    for value in detection_item.value:
        assert isinstance(value, SigmaString)
        assert not value.contains_special()


def test_field_mapping_none_preserves_existing_wildcards(dummy_pipeline):
    """Test that mapping None to field doesn't duplicate existing wildcards."""
    rule = SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "keywords": ["*already*", "*partial", "other*"],
                "condition": "keywords",
            },
        }
    )

    transformation = FieldMappingTransformation(mapping={None: "my_field"})
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(rule)

    detection_item = rule.detection.detections["keywords"].detection_items[0]
    values_str = [str(v) for v in detection_item.value]

    assert "*already*" in values_str
    assert "*partial*" in values_str
    assert "*other*" in values_str


@pytest.fixture
def field_function_transformation():
    return FieldFunctionTransformation(
        transform_func=lambda field: f"transformed_{field}",
        mapping={"field1": "mapped_field1", "field2": "mapped_field2"},
    )


def test_field_function_transformation(dummy_pipeline, field_function_transformation):
    sigma_rule = SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
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
                "field1",
                "field2",
                "field3",
            ],
        }
    )
    field_function_transformation.set_pipeline(dummy_pipeline)
    field_function_transformation.set_processing_item(
        ProcessingItem(
            field_function_transformation,
            identifier="test",
        )
    )
    field_function_transformation.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("mapped_field1", [], [SigmaString("value1")]),
                    SigmaDetectionItem("mapped_field2", [], [SigmaString("value2")]),
                    SigmaDetectionItem("transformed_field3", [], [SigmaString("value3")]),
                ]
            )
        ]
    )
    assert sigma_rule.fields == [
        "mapped_field1",
        "mapped_field2",
        "transformed_field3",
    ]
    assert sigma_rule.was_processed_by("test")
    assert field_function_transformation._pipeline.field_mappings == {
        "field1": {"mapped_field1"},
        "field2": {"mapped_field2"},
        "field3": {"transformed_field3"},
    }


def test_field_function_transformation_keyword_detection(
    dummy_pipeline, keyword_sigma_rule, field_function_transformation
):
    field_function_transformation.set_pipeline(dummy_pipeline)
    field_function_transformation.apply(keyword_sigma_rule)
    assert keyword_sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetectionItem(
                None,
                [],
                [
                    SigmaString("value1"),
                    SigmaString("value2"),
                    SigmaString("value3"),
                ],
            ),
        ]
    )


def test_field_function_transformation_keyword_detection_with_none(
    monkeypatch, dummy_pipeline, keyword_sigma_rule, field_function_transformation
):
    monkeypatch.setattr(field_function_transformation, "apply_keyword", True)
    field_function_transformation.set_pipeline(dummy_pipeline)
    field_function_transformation.apply(keyword_sigma_rule)
    # When mapping None (keyword) to a field, wildcards are added to preserve keyword semantics
    assert keyword_sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetectionItem(
                "transformed_None",
                [],
                [
                    SigmaString("*value1*"),
                    SigmaString("*value2*"),
                    SigmaString("*value3*"),
                ],
            ),
        ]
    )


def test_field_function_transformation_correlation_rule(
    dummy_pipeline, sigma_correlation_rule, field_function_transformation
):
    sigma_correlation_rule = SigmaCorrelationRule.from_dict(
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
                    "field1",
                    "field2",
                    "field3",
                ],
                "condition": {
                    "gte": 10,
                    "field": "field1",
                },
                "aliases": {
                    "alias1": {
                        "testrule_1": "field1",
                        "testrule_2": "field2",
                    },
                },
            },
        }
    )
    field_function_transformation.set_pipeline(dummy_pipeline)
    field_function_transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule.group_by == [
        "mapped_field1",
        "mapped_field2",
        "transformed_field3",
    ]
    assert sigma_correlation_rule.aliases.aliases["alias1"] == SigmaCorrelationFieldAlias(
        alias="alias1",
        mapping={
            SigmaRuleReference("testrule_1"): "mapped_field1",
            SigmaRuleReference("testrule_2"): "mapped_field2",
        },
    )
    assert sigma_correlation_rule.condition.fieldref == "mapped_field1"


@pytest.fixture
def field_prefix_mapping_transformation():
    transformation = FieldPrefixMappingTransformation(
        {
            "test1.": "mapped1.",
            "test2.": ["mapped2a.", "mapped2b."],
        }
    )
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )

    return transformation


def test_field_prefix_mapping(dummy_pipeline, field_prefix_mapping_transformation):
    sigma_rule = SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "test": [
                    {
                        "test1.field": "value1",
                        "test2.field": "value2",
                        "otherfield": "value3",
                    }
                ],
                "condition": "test",
            },
            "fields": [
                "otherfield1",
                "test1.field",
                "test2.field",
                "otherfield2",
            ],
        }
    )
    field_prefix_mapping_transformation.set_pipeline(dummy_pipeline)
    field_prefix_mapping_transformation.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("mapped1.field", [], [SigmaString("value1")]),
                    SigmaDetection(
                        [
                            SigmaDetectionItem("mapped2a.field", [], [SigmaString("value2")]),
                            SigmaDetectionItem("mapped2b.field", [], [SigmaString("value2")]),
                        ],
                        item_linking=ConditionOR,
                    ),
                    SigmaDetectionItem("otherfield", [], [SigmaString("value3")]),
                ]
            )
        ]
    )
    assert sigma_rule.fields == [
        "otherfield1",
        "mapped1.field",
        "mapped2a.field",
        "mapped2b.field",
        "otherfield2",
    ]
    assert sigma_rule.was_processed_by("test")
    assert field_prefix_mapping_transformation._pipeline.field_mappings == {
        "test1.field": {"mapped1.field"},
        "test2.field": {
            "mapped2a.field",
            "mapped2b.field",
        },
    }


def test_field_prefix_mapping_keyword_detection(
    dummy_pipeline, keyword_sigma_rule, field_prefix_mapping_transformation
):
    field_prefix_mapping_transformation.set_pipeline(dummy_pipeline)
    field_prefix_mapping_transformation.apply(keyword_sigma_rule)
    assert keyword_sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetectionItem(
                None,
                [],
                [
                    SigmaString("value1"),
                    SigmaString("value2"),
                    SigmaString("value3"),
                ],
            ),
        ]
    )


def test_field_prefix_mapping_correlation_rule(
    dummy_pipeline, sigma_correlation_rule, field_prefix_mapping_transformation
):
    sigma_correlation_rule = SigmaCorrelationRule.from_dict(
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
                    "test1.field",
                    "test.field",
                    "test2.field",
                ],
                "condition": {
                    "gte": 10,
                    "field": "test1.field",
                },
                "aliases": {
                    "testalias": {
                        "testrule_1": "test1.field",
                        "testrule_2": "test3.field",
                    },
                },
            },
        }
    )
    field_prefix_mapping_transformation.set_pipeline(dummy_pipeline)
    field_prefix_mapping_transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule.group_by == [
        "testalias",
        "mapped1.field",
        "test.field",
        "mapped2a.field",
        "mapped2b.field",
    ]
    assert sigma_correlation_rule.aliases.aliases["testalias"] == SigmaCorrelationFieldAlias(
        alias="testalias",
        mapping={
            SigmaRuleReference("testrule_1"): "mapped1.field",
            SigmaRuleReference("testrule_2"): "test3.field",
        },
    )
    assert sigma_correlation_rule.condition.fieldref == "mapped1.field"


def test_field_prefix_mapping_correlation_rule_with_multiple_fields(
    dummy_pipeline, sigma_correlation_rule, field_prefix_mapping_transformation
):
    sigma_correlation_rule = SigmaCorrelationRule.from_dict(
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
                    "test1.field",
                    "test.field",
                    "test2.field",
                ],
                "condition": {
                    "gte": 10,
                    "field": [
                        "test1.field1",
                        "test1.field2",
                    ],
                },
                "aliases": {
                    "testalias": {
                        "testrule_1": "test1.field",
                        "testrule_2": "test3.field",
                    },
                },
            },
        }
    )
    field_prefix_mapping_transformation.set_pipeline(dummy_pipeline)
    field_prefix_mapping_transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule.condition.fieldref == ["mapped1.field1", "mapped1.field2"]


def test_drop_detection_item_transformation(sigma_rule: SigmaRule, dummy_pipeline):
    transformation = DropDetectionItemTransformation()
    processing_item = ProcessingItem(
        transformation,
        field_name_conditions=[IncludeFieldCondition(fields=["field2"])],
    )
    processing_item.set_pipeline(dummy_pipeline)
    processing_item.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("field1", [], [SigmaString("value1")]),
                    SigmaDetectionItem("field3", [], [SigmaString("value3")]),
                ]
            )
        ]
    )


def test_drop_detection_item_transformation_with_set_state(sigma_rule: SigmaRule):
    pipeline = ProcessingPipeline(
        [
            ProcessingItem(
                identifier="test",
                transformation=SetStateTransformation("state", "test"),
                rule_conditions=[RuleContainsDetectionItemCondition("field2", "value2")],
            ),
            ProcessingItem(
                transformation=DropDetectionItemTransformation(),
                field_name_conditions=[IncludeFieldCondition(fields=["field2"])],
                rule_conditions=[RuleProcessingItemAppliedCondition("test")],
            ),
        ]
    )
    pipeline.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("field1", [], [SigmaString("value1")]),
                    SigmaDetectionItem("field3", [], [SigmaString("value3")]),
                ]
            )
        ]
    )


def test_drop_detection_item_transformation(sigma_rule: SigmaRule, dummy_pipeline):
    transformation = DropDetectionItemTransformation()
    processing_item = ProcessingItem(
        transformation,
        field_name_conditions=[IncludeFieldCondition(fields=["field2"])],
    )
    processing_item.set_pipeline(dummy_pipeline)
    processing_item.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("field1", [], [SigmaString("value1")]),
                    SigmaDetectionItem("field3", [], [SigmaString("value3")]),
                ]
            )
        ]
    )


def test_drop_detection_item_transformation_correlation_rule(
    sigma_correlation_rule, dummy_pipeline
):
    transformation = DropDetectionItemTransformation()
    orig_correlation_rule = deepcopy(sigma_correlation_rule)
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule == orig_correlation_rule


def test_drop_detection_item_transformation_all(sigma_rule: SigmaRule, dummy_pipeline):
    transformation = DropDetectionItemTransformation()
    processing_item = ProcessingItem(
        transformation,
        field_name_conditions=[IncludeFieldCondition(fields=["field1", "field2", "field3"])],
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"].detection_items[0].detection_items == []


@pytest.fixture
def add_fieldname_suffix_transformation():
    return AddFieldnameSuffixTransformation.from_dict(
        {
            "suffix": ".test",
        }
    )


def test_add_fieldname_suffix(dummy_pipeline, sigma_rule, add_fieldname_suffix_transformation):
    add_fieldname_suffix_transformation.set_pipeline(dummy_pipeline)
    add_fieldname_suffix_transformation.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("field1.test", [], [SigmaString("value1")]),
                    SigmaDetectionItem("field2.test", [], [SigmaString("value2")]),
                    SigmaDetectionItem("field3.test", [], [SigmaString("value3")]),
                ]
            )
        ]
    )
    assert sigma_rule.fields == [
        "otherfield1.test",
        "field1.test",
        "field2.test",
        "field3.test",
        "otherfield2.test",
    ]


def test_add_fieldname_suffix_keyword(
    dummy_pipeline, keyword_sigma_rule, add_fieldname_suffix_transformation
):
    add_fieldname_suffix_transformation.set_pipeline(dummy_pipeline)
    add_fieldname_suffix_transformation.apply(keyword_sigma_rule)
    assert keyword_sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetectionItem(
                None,
                [],
                [
                    SigmaString("value1"),
                    SigmaString("value2"),
                    SigmaString("value3"),
                ],
            ),
        ]
    )


def test_add_fieldname_suffix_tracking(
    dummy_pipeline, sigma_rule, add_fieldname_suffix_transformation
):
    processing_item = ProcessingItem(
        add_fieldname_suffix_transformation,
        field_name_conditions=[IncludeFieldCondition("field1")],
        identifier="test",
    )
    processing_item.set_pipeline(dummy_pipeline)
    processing_item.apply(sigma_rule)
    detection_items = sigma_rule.detection.detections["test"].detection_items[0].detection_items
    assert detection_items == [
        SigmaDetectionItem("field1.test", [], [SigmaString("value1")]),
        SigmaDetectionItem("field2", [], [SigmaString("value2")]),
        SigmaDetectionItem("field3", [], [SigmaString("value3")]),
    ]
    assert [detection_item.was_processed_by("test") for detection_item in detection_items] == [
        True,
        False,
        False,
    ]
    assert sigma_rule.was_processed_by("test")
    assert processing_item.transformation._pipeline.field_mappings == {"field1": {"field1.test"}}


def test_add_fieldname_suffix_transformation_correlation_rule(
    sigma_correlation_rule, dummy_pipeline, add_fieldname_suffix_transformation
):
    add_fieldname_suffix_transformation.set_pipeline(dummy_pipeline)
    add_fieldname_suffix_transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule.group_by == ["testalias", "field2.test", "field3.test"]
    assert sigma_correlation_rule.aliases.aliases["testalias"] == SigmaCorrelationFieldAlias(
        alias="testalias",
        mapping={
            SigmaRuleReference("testrule_1"): "field1.test",
            SigmaRuleReference("testrule_2"): "field2.test",
        },
    )
    assert sigma_correlation_rule.condition.fieldref == "field1.test"


@pytest.fixture
def add_fieldname_prefix_transformation():
    return AddFieldnamePrefixTransformation.from_dict(
        {
            "prefix": "test.",
        }
    )


def test_add_fieldname_prefix(dummy_pipeline, sigma_rule, add_fieldname_prefix_transformation):
    add_fieldname_prefix_transformation.set_pipeline(dummy_pipeline)
    add_fieldname_prefix_transformation.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("test.field1", [], [SigmaString("value1")]),
                    SigmaDetectionItem("test.field2", [], [SigmaString("value2")]),
                    SigmaDetectionItem("test.field3", [], [SigmaString("value3")]),
                ]
            )
        ]
    )
    assert sigma_rule.fields == [
        "test.otherfield1",
        "test.field1",
        "test.field2",
        "test.field3",
        "test.otherfield2",
    ]


def test_add_fieldname_prefix_keyword(
    dummy_pipeline, keyword_sigma_rule, add_fieldname_prefix_transformation
):
    add_fieldname_prefix_transformation.set_pipeline(dummy_pipeline)
    add_fieldname_prefix_transformation.apply(keyword_sigma_rule)
    assert keyword_sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetectionItem(
                None,
                [],
                [
                    SigmaString("value1"),
                    SigmaString("value2"),
                    SigmaString("value3"),
                ],
            ),
        ]
    )


def test_add_fieldname_prefix_tracking(
    dummy_pipeline, sigma_rule, add_fieldname_prefix_transformation
):
    processing_item = ProcessingItem(
        add_fieldname_prefix_transformation,
        field_name_conditions=[IncludeFieldCondition("field1")],
        identifier="test",
    )
    processing_item.set_pipeline(dummy_pipeline)
    processing_item.apply(sigma_rule)
    detection_items = sigma_rule.detection.detections["test"].detection_items[0].detection_items
    assert detection_items == [
        SigmaDetectionItem("test.field1", [], [SigmaString("value1")]),
        SigmaDetectionItem("field2", [], [SigmaString("value2")]),
        SigmaDetectionItem("field3", [], [SigmaString("value3")]),
    ]
    assert [detection_item.was_processed_by("test") for detection_item in detection_items] == [
        True,
        False,
        False,
    ]
    assert sigma_rule.was_processed_by("test")
    assert processing_item.transformation._pipeline.field_mappings == {"field1": {"test.field1"}}


def test_add_fieldname_prefix_correlation_rule(
    sigma_correlation_rule, dummy_pipeline, add_fieldname_prefix_transformation
):
    add_fieldname_prefix_transformation.set_pipeline(dummy_pipeline)
    add_fieldname_prefix_transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule.group_by == ["testalias", "test.field2", "test.field3"]
    assert sigma_correlation_rule.aliases.aliases["testalias"] == SigmaCorrelationFieldAlias(
        alias="testalias",
        mapping={
            SigmaRuleReference("testrule_1"): "test.field1",
            SigmaRuleReference("testrule_2"): "test.field2",
        },
    )
    assert sigma_correlation_rule.condition.fieldref == "test.field1"


def test_fields_list_mapping_with_detection_item_condition(sigma_rule: SigmaRule):
    processing_pipeline = ProcessingPipeline(
        [
            ProcessingItem(
                identifier="suffix_some",
                transformation=AddFieldnameSuffixTransformation(".test"),
                field_name_conditions=[
                    IncludeFieldCondition(
                        fields=["^field\\d+"],
                        mode="re",
                    ),
                ],
            ),
            ProcessingItem(
                identifier="prefix_others",
                transformation=AddFieldnamePrefixTransformation("test."),
                field_name_conditions=[
                    FieldNameProcessingItemAppliedCondition("suffix_some"),
                ],
                field_name_condition_negation=True,
            ),
        ]
    )
    processing_pipeline.apply(sigma_rule)
    assert sigma_rule.fields == [
        "test.otherfield1",
        "field1.test",
        "field2.test",
        "field3.test",
        "test.otherfield2",
    ]


def test_wildcard_placeholders(dummy_pipeline, sigma_rule_placeholders: SigmaRule):
    transformation = WildcardPlaceholderTransformation()
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule_placeholders)
    assert sigma_rule_placeholders.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem(
                        "field1", [SigmaExpandModifier], [SigmaString("value*test")]
                    ),
                    SigmaDetectionItem(
                        "field2", [SigmaExpandModifier], [SigmaString("value*test*")]
                    ),
                    SigmaDetectionItem(
                        "field3",
                        [SigmaExpandModifier],
                        [SigmaString("value*test*test*test")],
                    ),
                ]
            )
        ]
    )


def test_wildcard_placeholders_correlation_rule(sigma_correlation_rule, dummy_pipeline):
    orig_correlation_rule = deepcopy(sigma_correlation_rule)
    transformation = WildcardPlaceholderTransformation()
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule == orig_correlation_rule


def test_wildcard_placeholders_include_and_exclude_error():
    with pytest.raises(SigmaConfigurationError, match="exclusively"):
        WildcardPlaceholderTransformation(include=["included_field"], exclude=["excluded_field"])


def test_wildcard_placeholders_included(dummy_pipeline, sigma_rule_placeholders: SigmaRule):
    transformation = WildcardPlaceholderTransformation(include=["var1"])
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule_placeholders)
    detection_items = (
        sigma_rule_placeholders.detection.detections["test"].detection_items[0].detection_items
    )
    assert (
        detection_items[0].value[0] == SigmaString("value*test")
        and detection_items[0].was_processed_by("test") == True
        and detection_items[1].value[0].s
        == ["value", Placeholder("var2"), "test", Placeholder("var3")]
        and detection_items[1].was_processed_by("test") == False
        and detection_items[2].value[0].s
        == [
            "value",
            SpecialChars.WILDCARD_MULTI,
            "test",
            Placeholder("var2"),
            "test",
            Placeholder("var3"),
            "test",
        ]
        and detection_items[2].was_processed_by("test") == True
        and sigma_rule_placeholders.was_processed_by("test")
    )


def test_wildcard_placeholders_excluded(dummy_pipeline, sigma_rule_placeholders: SigmaRule):
    transformation = WildcardPlaceholderTransformation(exclude=["var2", "var3"])
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule_placeholders)
    detection_items = (
        sigma_rule_placeholders.detection.detections["test"].detection_items[0].detection_items
    )
    assert (
        detection_items[0].value[0] == SigmaString("value*test")
        and detection_items[0].was_processed_by("test") == True
        and detection_items[1].value[0].s
        == ["value", Placeholder("var2"), "test", Placeholder("var3")]
        and detection_items[1].was_processed_by("test") == False
        and detection_items[2].value[0].s
        == [
            "value",
            SpecialChars.WILDCARD_MULTI,
            "test",
            Placeholder("var2"),
            "test",
            Placeholder("var3"),
            "test",
        ]
        and detection_items[2].was_processed_by("test") == True
        and sigma_rule_placeholders.was_processed_by("test")
    )


def test_wildcard_placeholders_without_placeholders(dummy_pipeline, sigma_rule: SigmaRule):
    transformation = WildcardPlaceholderTransformation()
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("field1", [], [SigmaString("value1")]),
                    SigmaDetectionItem("field2", [], [SigmaString("value2")]),
                    SigmaDetectionItem("field3", [], [SigmaString("value3")]),
                ]
            )
        ]
    )


def test_valuelist_placeholders(sigma_rule_placeholders_simple: SigmaRule):
    transformation = ValueListPlaceholderTransformation()
    pipeline = ProcessingPipeline(vars={"var1": ["val1", 123], "var2": "val3*"})
    transformation.set_pipeline(pipeline)
    transformation.apply(sigma_rule_placeholders_simple)
    assert sigma_rule_placeholders_simple.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem(
                        "field",
                        [SigmaExpandModifier],
                        [
                            SigmaString("valueval1testval3*end"),
                            SigmaString("value123testval3*end"),
                        ],
                    ),
                ]
            )
        ]
    )


def test_valuelist_placeholders_re(sigma_rule_placeholders_simple_re: SigmaRule):
    transformation = ValueListPlaceholderTransformation()
    pipeline = ProcessingPipeline(vars={"var1": ["val1", 123], "var2": "val3*"})
    transformation.set_pipeline(pipeline)
    transformation.apply(sigma_rule_placeholders_simple_re)
    assert sigma_rule_placeholders_simple_re.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem(
                        "field",
                        [SigmaRegularExpressionModifier, SigmaExpandModifier],
                        [
                            SigmaString("valueval1testval3*end"),
                            SigmaString("value123testval3*end"),
                        ],
                    ),
                ]
            )
        ]
    )


def test_valuelist_placeholders_correlation_rule(sigma_correlation_rule, dummy_pipeline):
    orig_correlation_rule = deepcopy(sigma_correlation_rule)
    transformation = ValueListPlaceholderTransformation()
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule == orig_correlation_rule


def test_valuelist_placeholders_missing(sigma_rule_placeholders_simple: SigmaRule):
    transformation = ValueListPlaceholderTransformation()
    pipeline = ProcessingPipeline([], vars={"var1": "val1"})
    transformation.set_pipeline(pipeline)
    with pytest.raises(SigmaValueError, match="doesn't exist"):
        transformation.apply(sigma_rule_placeholders_simple)


def test_valuelist_placeholders_wrong_type(sigma_rule_placeholders_simple: SigmaRule):
    transformation = ValueListPlaceholderTransformation()
    pipeline = ProcessingPipeline(vars={"var1": None})
    transformation.set_pipeline(pipeline)
    with pytest.raises(SigmaValueError, match="not a string or number"):
        transformation.apply(sigma_rule_placeholders_simple)


def test_queryexpr_placeholders(dummy_pipeline, sigma_rule_placeholders_only: SigmaRule):
    expr = "{field} lookup {id}"
    transformation = QueryExpressionPlaceholderTransformation(
        expression=expr, mapping={"var2": "placeholder2"}
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule_placeholders_only)
    assert sigma_rule_placeholders_only.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem(
                        "field1",
                        [SigmaExpandModifier],
                        [SigmaQueryExpression(expr, "var1")],
                        auto_modifiers=False,
                    ),
                    SigmaDetectionItem(
                        "field2",
                        [SigmaExpandModifier],
                        [SigmaQueryExpression(expr, "placeholder2")],
                        auto_modifiers=False,
                    ),
                    SigmaDetectionItem(
                        "field3",
                        [SigmaExpandModifier],
                        [SigmaQueryExpression(expr, "var3")],
                        auto_modifiers=False,
                    ),
                ]
            )
        ]
    )


def test_queryexpr_placeholders_correlation_rule(sigma_correlation_rule, dummy_pipeline):
    orig_correlation_rule = deepcopy(sigma_correlation_rule)
    transformation = QueryExpressionPlaceholderTransformation(
        expression="{field} lookup {id}", mapping={"var2": "placeholder2"}
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule == orig_correlation_rule


def test_queryexpr_placeholders_without_placeholders(dummy_pipeline, sigma_rule: SigmaRule):
    transformation = QueryExpressionPlaceholderTransformation(
        expression="{field} lookup {id}",
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("field1", [], [SigmaString("value1")]),
                    SigmaDetectionItem("field2", [], [SigmaString("value2")]),
                    SigmaDetectionItem("field3", [], [SigmaString("value3")]),
                ]
            )
        ]
    )


def test_queryexpr_placeholders_mixed_string(dummy_pipeline, sigma_rule_placeholders: SigmaRule):
    transformation = QueryExpressionPlaceholderTransformation(
        expression="{field} lookup {id}",
    )
    with pytest.raises(SigmaValueError, match="only allows placeholder-only strings"):
        transformation.set_pipeline(dummy_pipeline)
        transformation.apply(sigma_rule_placeholders)


def test_queryexpr_placeholders_include_and_exclude_error():
    with pytest.raises(SigmaConfigurationError, match="exclusively"):
        QueryExpressionPlaceholderTransformation(
            expression="{field} lookup {id}",
            mapping={"var1": "placeholder1"},
            include=["included_field"],
            exclude=["excluded_field"],
        )


### ConditionTransformation ###
@dataclass
class DummyConditionTransformation(ConditionTransformation):
    """A condition transformation that does absolutely nothing or appends something to the condition."""

    do_something: bool

    def apply_condition(self, cond: SigmaCondition) -> None:
        if self.do_something:
            cond.condition += " and test"


def test_conditiontransformation_tracking_change(dummy_pipeline, sigma_rule: SigmaRule):
    transformation = DummyConditionTransformation(True)
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.detection.parsed_condition[0].was_processed_by(
        "test"
    ) and sigma_rule.was_processed_by("test")


def test_conditiontransformation_tracking_nochange(dummy_pipeline, sigma_rule: SigmaRule):
    transformation = DummyConditionTransformation(False)
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert not sigma_rule.detection.parsed_condition[0].was_processed_by(
        "test"
    ) and sigma_rule.was_processed_by("test")


### AddConditionTransformation ###
def test_addconditiontransformation(dummy_pipeline, sigma_rule: SigmaRule):
    transformation = AddConditionTransformation(
        {
            "newfield1": "test",
            "newfield2": 123,
            "newfield3": "$category",
            "listfield": ["value1", "value2"],
            "numlistfield": [1, 2, 3],
        },
        "additional",
    )
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert (
        sigma_rule.detection.parsed_condition[0].condition
        == "additional and (test)"  # condition expression was added
        and sigma_rule.detection.detections["additional"]
        == SigmaDetection(
            [  # additional detection item referred by condition
                SigmaDetectionItem("newfield1", [], [SigmaString("test")]),
                SigmaDetectionItem("newfield2", [], [SigmaNumber(123)]),
                SigmaDetectionItem("newfield3", [], [SigmaString("$category")]),
                SigmaDetectionItem("listfield", [], [SigmaString("value1"), SigmaString("value2")]),
                SigmaDetectionItem(
                    "numlistfield", [], [SigmaNumber(1), SigmaNumber(2), SigmaNumber(3)]
                ),
            ]
        )
        and all(  # detection items are marked as processed by processing item
            detection_item.was_processed_by("test")
            for detection_item in sigma_rule.detection.detections["additional"].detection_items
        )
        and sigma_rule.was_processed_by("test")
    )


def test_addconditiontransformation_correlation_rule(sigma_correlation_rule, dummy_pipeline):
    orig_correlation_rule = deepcopy(sigma_correlation_rule)
    transformation = AddConditionTransformation(
        {
            "newfield1": "test",
        },
        "additional",
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule == orig_correlation_rule


def test_addconditiontransformation_template(dummy_pipeline, sigma_rule: SigmaRule):
    transformation = AddConditionTransformation(
        {
            "newfield1": "$category",
            "newfield2": "$something",
            "listfield": ["$category", "value"],
            "numfield": 123,
            "numlistfield": [1, 2, 3],
        },
        "additional",
        template=True,
    )
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert (
        sigma_rule.detection.parsed_condition[0].condition
        == "additional and (test)"  # condition expression was added
        and sigma_rule.detection.detections["additional"]
        == SigmaDetection(
            [  # additional detection item referred by condition
                SigmaDetectionItem("newfield1", [], [SigmaString("test")]),
                SigmaDetectionItem("newfield2", [], [SigmaString("$something")]),
                SigmaDetectionItem("listfield", [], [SigmaString("test"), SigmaString("value")]),
                SigmaDetectionItem("numfield", [], [SigmaNumber(123)]),
                SigmaDetectionItem(
                    "numlistfield", [], [SigmaNumber(1), SigmaNumber(2), SigmaNumber(3)]
                ),
            ]
        )
        and all(  # detection items are marked as processed by processing item
            detection_item.was_processed_by("test")
            for detection_item in sigma_rule.detection.detections["additional"].detection_items
        )
        and sigma_rule.was_processed_by("test")
    )


def test_addconditiontransformation_random_name():
    transformation = AddConditionTransformation({})
    name = transformation.name
    assert len(name) > 6 and name.startswith("_cond_")


def test_addconditiontransformation_negated(dummy_pipeline, sigma_rule: SigmaRule):
    transformation = AddConditionTransformation(
        {
            "newfield1": "test",
            "newfield2": 123,
            "newfield3": "$category",
            "listfield": ["value1", "value2"],
        },
        "additional",
        negated=True,
    )
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert (
        sigma_rule.detection.parsed_condition[0].condition
        == "not additional and (test)"  # negated condition expression was added
    )


### ChangeLogsourceTransformation ###
def test_changelogsource(dummy_pipeline, sigma_rule: SigmaRule):
    processing_item = ProcessingItem(
        ChangeLogsourceTransformation("test_category", "test_product", "test_service"),
        identifier="test",
    )
    processing_item.set_pipeline(dummy_pipeline)
    processing_item.apply(sigma_rule)

    assert sigma_rule.logsource == SigmaLogSource(
        "test_category", "test_product", "test_service"
    ) and sigma_rule.was_processed_by("test")


def test_changelogsource_correlation_rule(sigma_correlation_rule, dummy_pipeline):
    orig_correlation_rule = deepcopy(sigma_correlation_rule)
    transformation = ChangeLogsourceTransformation("test_category", "test_product", "test_service")
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule == orig_correlation_rule


def test_add_fields_transformation_single(dummy_pipeline, sigma_rule):
    transformation = AddFieldTransformation("added_field")
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.fields == [
        "otherfield1",
        "field1",
        "field2",
        "field3",
        "otherfield2",
        "added_field",
    ]


def test_add_fields_transformation_multiple(dummy_pipeline, sigma_rule):
    transformation = AddFieldTransformation(["added_field1", "added_field2"])
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.fields == [
        "otherfield1",
        "field1",
        "field2",
        "field3",
        "otherfield2",
        "added_field1",
        "added_field2",
    ]


def test_remove_fields_transformation_single(dummy_pipeline, sigma_rule):
    transformation = RemoveFieldTransformation("field1")
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.fields == [
        "otherfield1",
        "field2",
        "field3",
        "otherfield2",
    ]


def test_remove_fields_transformation_multiple(dummy_pipeline, sigma_rule):
    transformation = RemoveFieldTransformation(["field1", "field3"])
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.fields == [
        "otherfield1",
        "field2",
        "otherfield2",
    ]


def test_remove_fields_transformation_single_nonexistent(dummy_pipeline, sigma_rule):
    transformation = RemoveFieldTransformation("nonexistent_field")
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.fields == [
        "otherfield1",
        "field1",
        "field2",
        "field3",
        "otherfield2",
    ]


def test_remove_fields_transformation_multiple_nonexistent(dummy_pipeline, sigma_rule):
    transformation = RemoveFieldTransformation(
        ["nonexistent_field1", "field1", "nonexistent_field2"]
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.fields == [
        "otherfield1",
        "field2",
        "field3",
        "otherfield2",
    ]


def test_set_fields_transformation(dummy_pipeline, sigma_rule):
    transformation = SetFieldTransformation(["field1", "field2", "field3"])
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.fields == ["field1", "field2", "field3"]


def test_replace_string_simple(dummy_pipeline, sigma_rule: SigmaRule):
    transformation = ReplaceStringTransformation("value", "test")
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("field1", [], [SigmaString("test1")]),
                    SigmaDetectionItem("field2", [], [SigmaString("test2")]),
                    SigmaDetectionItem("field3", [], [SigmaString("test3")]),
                ]
            )
        ]
    )


def test_replace_string_specials(dummy_pipeline):
    sigma_rule = SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "test": [
                    {
                        "field1": "*\\value",
                        "field2": 123,
                    }
                ],
                "condition": "test",
            },
        }
    )
    transformation = ReplaceStringTransformation("^.*\\\\", "/")
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("field1", [], [SigmaString("/value")]),
                    SigmaDetectionItem("field2", [], [SigmaNumber(123)]),
                ]
            )
        ]
    )


def test_replace_string_placeholder(dummy_pipeline):
    sigma_rule = SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "test": {
                    "field|expand": "foo%var%bar",
                },
                "condition": "test",
            },
        }
    )
    s_before = sigma_rule.detection.detections["test"].detection_items[0].value[0]
    assert s_before == SigmaString("foo%var%bar").insert_placeholders()

    transformation = ReplaceStringTransformation("bar", "test")
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    s = sigma_rule.detection.detections["test"].detection_items[0].value[0]
    assert s == SigmaString("foo%var%test").insert_placeholders()


def test_replace_string_no_placeholder(dummy_pipeline):
    sigma_rule = SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "test": {
                    "field": "foo%var%bar",
                },
                "condition": "test",
            },
        }
    )
    s_before = sigma_rule.detection.detections["test"].detection_items[0].value[0]
    assert s_before == SigmaString("foo%var%bar")

    transformation = ReplaceStringTransformation("bar", "test")
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    s = sigma_rule.detection.detections["test"].detection_items[0].value[0]
    assert s == SigmaString("foo%var%test")


def test_replace_string_skip_specials(dummy_pipeline):
    sigma_rule = SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "test": [
                    {
                        "field1": "*\\value",
                        "field2": 123,
                    }
                ],
                "condition": "test",
            },
        }
    )
    transformation = ReplaceStringTransformation("^.*\\\\", "/?/", True)
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("field1", [], [SigmaString("*/\\?/value")]),
                    SigmaDetectionItem("field2", [], [SigmaNumber(123)]),
                ]
            )
        ]
    )


def test_replace_string_skip_specials_with_interpret_specials(dummy_pipeline):
    sigma_rule = SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "test": [
                    {
                        "field1": "*\\value",
                        "field2": 123,
                    }
                ],
                "condition": "test",
            },
        }
    )
    transformation = ReplaceStringTransformation("^.*\\\\", "/?/", True, True)
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("field1", [], [SigmaString("*/?/value")]),
                    SigmaDetectionItem("field2", [], [SigmaNumber(123)]),
                ]
            )
        ]
    )


def test_replace_string_backslashes(dummy_pipeline):
    sigma_rule = SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "test": [
                    {
                        "field1": r"backslash\\value",
                        "field2": r"backslash\\\\value",
                        "field3": r"plainwildcard\*value",
                    }
                ],
                "condition": "test",
            },
        }
    )
    transformation = ReplaceStringTransformation("value", "test")
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("field1", [], [SigmaString(r"backslash\\test")]),
                    SigmaDetectionItem("field2", [], [SigmaString(r"backslash\\\\test")]),
                    SigmaDetectionItem("field3", [], [SigmaString(r"plainwildcard\*test")]),
                ]
            )
        ]
    )


def test_replace_string_invalid():
    with pytest.raises(SigmaRegularExpressionError, match="Regular expression.*invalid"):
        ReplaceStringTransformation("*", "test")


def test_replace_string_correlation_rule(sigma_correlation_rule, dummy_pipeline):
    orig_correlation_rule = deepcopy(sigma_correlation_rule)
    transformation = ReplaceStringTransformation("value", "test")
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule == orig_correlation_rule


@pytest.fixture
def map_string_transformation():
    return MapStringTransformation(
        {
            "value1": "mapped1",
            "value2": ["mapped2A", "mapped2B"],
        }
    )


def test_map_string_transformation(dummy_pipeline, sigma_rule, map_string_transformation):
    map_string_transformation.set_pipeline(dummy_pipeline)
    map_string_transformation.apply(sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection(
        [
            SigmaDetection(
                [
                    SigmaDetectionItem("field1", [], [SigmaString("mapped1")]),
                    SigmaDetectionItem(
                        "field2", [], [SigmaString("mapped2A"), SigmaString("mapped2B")]
                    ),
                    SigmaDetectionItem("field3", [], [SigmaString("value3")]),
                ]
            )
        ]
    )


def test_map_string_transformation_correlation_rule(
    dummy_pipeline, sigma_correlation_rule, map_string_transformation
):
    orig_correlation_rule = deepcopy(sigma_correlation_rule)
    map_string_transformation.set_pipeline(dummy_pipeline)
    map_string_transformation.apply(sigma_correlation_rule)
    assert sigma_correlation_rule == orig_correlation_rule


def test_regex_transformation_plain_method(dummy_pipeline):
    detection_item = SigmaDetectionItem("field", [], [SigmaString("\\te.st*va?ue")])
    transformation = RegexTransformation(method="plain")
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaRegularExpression("\\\\te\\.st.*va.ue")


def test_regex_transformation_empty_string(dummy_pipeline):
    detection_item = SigmaDetectionItem("field", [], [SigmaString("")])
    transformation = RegexTransformation(method="plain")
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaString("")


def test_regex_transformation_case_insensitive_bracket_method(dummy_pipeline):
    detection_item = SigmaDetectionItem("field", [], [SigmaString("\\tE.sT*val?ue")])
    transformation = RegexTransformation(method="ignore_case_brackets")
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaRegularExpression(
        "\\\\[tT][eE]\\.[sS][tT].*[vV][aA][lL].[uU][eE]"
    )


def test_regex_transformation_case_insensitive_flags_method(dummy_pipeline):
    detection_item = SigmaDetectionItem("field", [], [SigmaString("\\tE.sT*val?ue")])
    transformation = RegexTransformation(method="ignore_case_flag")
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaRegularExpression(
        "\\\\tE\\.sT.*val.ue", {SigmaRegularExpressionFlag.IGNORECASE}
    )


def test_regex_transformation_invalid_method():
    with pytest.raises(SigmaConfigurationError, match="Invalid method"):
        RegexTransformation(method="invalid")


def test_set_value_transformation_string():
    transformation = SetValueTransformation("testvalue")
    detection_item = SigmaDetectionItem("field", [], [SigmaString("test")])
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaString("testvalue")


def test_set_value_transformation_number():
    transformation = SetValueTransformation(123)
    detection_item = SigmaDetectionItem("field", [], [SigmaString("test")])
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaNumber(123)


def test_set_value_transformation_boolean():
    transformation = SetValueTransformation(True)
    detection_item = SigmaDetectionItem("field", [], [SigmaString("test")])
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaBool(True)


def test_set_value_transformation_none():
    transformation = SetValueTransformation(None)
    detection_item = SigmaDetectionItem("field", [], [SigmaString("test")])
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaNull()


def test_set_value_transformation_unsupported_type():
    with pytest.raises(SigmaConfigurationError, match="Unsupported value type"):
        SetValueTransformation(object())


def test_set_value_transformation_force_unsupported_type():
    with pytest.raises(SigmaConfigurationError, match="is only allowed for"):
        SetValueTransformation(None, "num")


def test_set_value_transformation_force_string():
    transformation = SetValueTransformation(123, "str")
    detection_item = SigmaDetectionItem("field", [], [SigmaString("test")])
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaString("123")


def test_set_value_transformation_force_number():
    transformation = SetValueTransformation("123", "num")
    detection_item = SigmaDetectionItem("field", [], [SigmaString("test")])
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaNumber(123)


def test_set_value_transformation_force_number_type_error():
    with pytest.raises(SigmaConfigurationError, match="can't be converted to number"):
        SetValueTransformation("test", "num")


def test_set_value_transformation_invalid_force_type():
    with pytest.raises(SigmaConfigurationError, match="Invalid force_type"):
        SetValueTransformation("test", "invalid")


def test_convert_type_transformation_num_to_str():
    transformation = ConvertTypeTransformation("str")
    detection_item = SigmaDetectionItem("field", [], [SigmaNumber(123)])
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaString("123")


def test_convert_type_transformation_str_to_str():
    transformation = ConvertTypeTransformation("str")
    detection_item = SigmaDetectionItem("field", [], [SigmaString("123")])
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaString("123")


def test_convert_type_transformation_str_to_num():
    transformation = ConvertTypeTransformation("num")
    detection_item = SigmaDetectionItem("field", [], [SigmaString("123")])
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaNumber(123)


def test_convert_type_transformation_num_to_num():
    transformation = ConvertTypeTransformation("num")
    detection_item = SigmaDetectionItem("field", [], [SigmaNumber(123)])
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaNumber(123)


def test_convert_type_transformation_str_to_num_no_number():
    transformation = ConvertTypeTransformation("num")
    detection_item = SigmaDetectionItem("field", [], [SigmaString("abc")])
    with pytest.raises(SigmaValueError, match="can't be converted to number"):
        transformation.apply_detection_item(detection_item)


def test_convert_type_transformation_expansion_num_to_str():
    transformation = ConvertTypeTransformation("str")
    detection_item = SigmaDetectionItem("field", [], [SigmaExpansion(values=[SigmaNumber(123)])])
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaExpansion(values=[SigmaString("123")])


def test_convert_type_transformation_expansion_str_to_num():
    transformation = ConvertTypeTransformation("num")
    detection_item = SigmaDetectionItem("field", [], [SigmaExpansion(values=[SigmaString("123")])])
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaExpansion(values=[SigmaNumber(123)])


def test_convert_type_transformation_expansion_str_to_num_no_number():
    transformation = ConvertTypeTransformation("num")
    detection_item = SigmaDetectionItem("field", [], [SigmaExpansion(values=[SigmaString("abc")])])
    with pytest.raises(SigmaValueError, match="can't be converted to number"):
        transformation.apply_detection_item(detection_item)


def test_set_state(dummy_pipeline, sigma_rule: SigmaRule):
    transformation = SetStateTransformation("testkey", "testvalue")
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert dummy_pipeline.state == {"testkey": "testvalue"}
    assert sigma_rule.was_processed_by("test")


def test_set_state_correlation_rule(sigma_correlation_rule, dummy_pipeline):
    transformation = SetStateTransformation("testkey", "testvalue")
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_correlation_rule)
    assert dummy_pipeline.state == {"testkey": "testvalue"}
    assert sigma_correlation_rule.was_processed_by("test")


def test_rule_failure_transformation(dummy_pipeline, sigma_rule):
    transformation = RuleFailureTransformation("Test")
    with pytest.raises(SigmaTransformationError, match="^Test$"):
        transformation.set_pipeline(dummy_pipeline)
        transformation.apply(sigma_rule)


def test_rule_failure_transformation_correlation_rule(dummy_pipeline, sigma_correlation_rule):
    transformation = RuleFailureTransformation("Test")
    with pytest.raises(SigmaTransformationError, match="^Test$"):
        transformation.set_pipeline(dummy_pipeline)
        transformation.apply(sigma_correlation_rule)


def test_detection_item_failure_transformation(dummy_pipeline, sigma_rule):
    transformation = DetectionItemFailureTransformation("Test")
    with pytest.raises(SigmaTransformationError, match="^Test$"):
        transformation.set_pipeline(dummy_pipeline)
        transformation.apply(sigma_rule)


def test_set_custom_attribute(dummy_pipeline, sigma_rule):
    transformation = SetCustomAttributeTransformation("custom_key", "custom_value")
    transformation.set_processing_item(ProcessingItem(transformation, identifier="test"))

    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_rule)
    assert "custom_key" in sigma_rule.custom_attributes
    assert sigma_rule.custom_attributes["custom_key"] == "custom_value"
    assert sigma_rule.was_processed_by("test")


def test_set_custom_attribute_correlation_rule(dummy_pipeline, sigma_correlation_rule):
    transformation = SetCustomAttributeTransformation("custom_key", "custom_value")
    transformation.set_processing_item(ProcessingItem(transformation, identifier="test"))

    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_correlation_rule)
    assert "custom_key" in sigma_correlation_rule.custom_attributes
    assert sigma_correlation_rule.custom_attributes["custom_key"] == "custom_value"
    assert sigma_correlation_rule.was_processed_by("test")


@pytest.fixture
def nested_pipeline_transformation():
    return NestedProcessingTransformation(
        items=[
            ProcessingItem(
                transformation=TransformationAppend(s="Test"),
                rule_condition_linking=any,
                rule_conditions=[
                    RuleConditionTrue(dummy="test-true"),
                    RuleConditionFalse(dummy="test-false"),
                ],
                identifier="test",
            )
        ],
    )


def test_nested_pipeline_transformation_from_dict(nested_pipeline_transformation, monkeypatch):
    monkeypatch.setitem(transformations, "append", TransformationAppend)
    monkeypatch.setitem(rule_conditions, "true", RuleConditionTrue)
    monkeypatch.setitem(rule_conditions, "false", RuleConditionFalse)
    assert (
        NestedProcessingTransformation.from_dict(
            {
                "items": [
                    {
                        "id": "test",
                        "rule_conditions": [
                            {"type": "true", "dummy": "test-true"},
                            {"type": "false", "dummy": "test-false"},
                        ],
                        "rule_cond_op": "or",
                        "type": "append",
                        "s": "Test",
                    }
                ],
            }
        )
        == nested_pipeline_transformation
    )


def test_nested_pipeline_transformation_from_yaml(nested_pipeline_transformation, monkeypatch):
    monkeypatch.setitem(transformations, "append", TransformationAppend)
    monkeypatch.setitem(rule_conditions, "true", RuleConditionTrue)
    monkeypatch.setitem(rule_conditions, "false", RuleConditionFalse)
    assert (
        ProcessingPipeline.from_yaml(
            """
            name: Test
            priority: 100
            transformations:
                - type: nest
                  items:
                  - id: test
                    type: append
                    s: Test
                    rule_conditions:
                    - type: "true"
                      dummy: test-true
                    - type: "false"
                      dummy: test-false
                    rule_cond_op: or
            """
        )
        == ProcessingPipeline(
            name="Test",
            priority=100,
            items=[ProcessingItem(nested_pipeline_transformation)],
        )
    )


def test_nested_pipeline_transformation_from_dict_apply(
    dummy_pipeline, sigma_rule, nested_pipeline_transformation
):
    nested_pipeline_transformation.set_pipeline(dummy_pipeline)
    nested_pipeline_transformation.apply(sigma_rule)
    assert sigma_rule.title == "TestTest"
    assert sigma_rule.was_processed_by("test")


def test_nested_pipeline_transformation_no_items():
    with pytest.raises(SigmaConfigurationError, match="requires an 'items' key"):
        NestedProcessingTransformation.from_dict({"test": "fails"})


def test_transformation_identifier_completeness():
    import sigma.processing.transformations as transformations_module

    classes_with_identifiers = transformations.values()

    def class_filter(c):
        return (
            inspect.isclass(c)
            and not inspect.isabstract(c)
            and issubclass(c, Transformation)
            and not c is Transformation
        )

    for cls in inspect.getmembers(transformations_module, class_filter):
        assert cls[1] in classes_with_identifiers


def test_transformation_export_completeness():
    assert {transformation.__name__ for transformation in transformations.values()}.issubset(
        transformations_all
    ), "Not all transformations are exported in transformations_all: " + ", ".join(
        set(transformations_all)
        - {transformation.__name__ for transformation in transformations.values()}
    )


@pytest.fixture
def hashes_transformation():
    return HashesFieldsDetectionItemTransformation(
        valid_hash_algos=["MD5", "SHA1", "SHA256", "SHA512"],
        field_prefix="File",
        drop_algo_prefix=False,
    )


def test_hashes_transformation_single_hash(hashes_transformation):
    detection_item = SigmaDetectionItem(
        "Hashes", [], [SigmaString("SHA1=5F1CBC3D99558307BC1250D084FA968521482025")]
    )
    result = hashes_transformation.apply_detection_item(detection_item)
    assert isinstance(result, SigmaDetection)
    assert len(result.detection_items) == 1
    assert result.detection_items[0].field == "FileSHA1"
    assert result.detection_items[0].value == [
        SigmaString("5F1CBC3D99558307BC1250D084FA968521482025")
    ]


def test_hashes_transformation_multiple_hashes(hashes_transformation):
    detection_item = SigmaDetectionItem(
        "Hashes",
        [],
        [
            SigmaString("SHA1=5F1CBC3D99558307BC1250D084FA968521482025"),
            SigmaString("MD5=987B65CD9B9F4E9A1AFD8F8B48CF64A7"),
        ],
    )
    result = hashes_transformation.apply_detection_item(detection_item)
    assert isinstance(result, SigmaDetection)
    assert len(result.detection_items) == 2
    assert result.detection_items[0].field == "FileSHA1"
    assert result.detection_items[0].value == [
        SigmaString("5F1CBC3D99558307BC1250D084FA968521482025")
    ]
    assert result.detection_items[1].field == "FileMD5"
    assert result.detection_items[1].value == [SigmaString("987B65CD9B9F4E9A1AFD8F8B48CF64A7")]
    assert result.item_linking == ConditionOR


def test_hashes_transformation_drop_algo_prefix():
    transformation = HashesFieldsDetectionItemTransformation(
        valid_hash_algos=["MD5", "SHA1", "SHA256", "SHA512"],
        field_prefix="File",
        drop_algo_prefix=True,
    )
    detection_item = SigmaDetectionItem(
        "Hashes", [], [SigmaString("SHA1=5F1CBC3D99558307BC1250D084FA968521482025")]
    )
    result = transformation.apply_detection_item(detection_item)
    assert isinstance(result, SigmaDetection)
    assert len(result.detection_items) == 1
    assert result.detection_items[0].field == "File"
    assert result.detection_items[0].value == [
        SigmaString("5F1CBC3D99558307BC1250D084FA968521482025")
    ]


def test_hashes_transformation_invalid_hash(hashes_transformation):
    detection_item = SigmaDetectionItem("Hashes", [], [SigmaString("INVALID=123456")])
    with pytest.raises(Exception, match="No valid hash algorithm found"):
        hashes_transformation.apply_detection_item(detection_item)


def test_hashes_transformation_mixed_valid_invalid(hashes_transformation):
    detection_item = SigmaDetectionItem(
        "Hashes",
        [],
        [
            SigmaString("SHA1=5F1CBC3D99558307BC1250D084FA968521482025"),
            SigmaString("INVALID=123456"),
            SigmaString("MD5=987B65CD9B9F4E9A1AFD8F8B48CF64A7"),
        ],
    )
    result = hashes_transformation.apply_detection_item(detection_item)
    assert isinstance(result, SigmaDetection)
    assert len(result.detection_items) == 2
    assert result.detection_items[0].field == "FileSHA1"
    assert result.detection_items[0].value == [
        SigmaString("5F1CBC3D99558307BC1250D084FA968521482025")
    ]
    assert result.detection_items[1].field == "FileMD5"
    assert result.detection_items[1].value == [SigmaString("987B65CD9B9F4E9A1AFD8F8B48CF64A7")]


def test_hashes_transformation_auto_detect_hash_type(hashes_transformation):
    detection_item = SigmaDetectionItem(
        "Hashes",
        [],
        [
            SigmaString("5F1CBC3D99558307BC1250D084FA968521482025"),  # SHA1
            SigmaString("987B65CD9B9F4E9A1AFD8F8B48CF64A7"),  # MD5
            SigmaString("A" * 64),  # SHA256
            SigmaString("B" * 128),  # SHA512
        ],
    )
    result = hashes_transformation.apply_detection_item(detection_item)
    assert isinstance(result, SigmaDetection)
    assert len(result.detection_items) == 4
    assert result.detection_items[0].field == "FileSHA1"
    assert result.detection_items[1].field == "FileMD5"
    assert result.detection_items[2].field == "FileSHA256"
    assert result.detection_items[3].field == "FileSHA512"


def test_hashes_transformation_pipe_separator(hashes_transformation):
    detection_item = SigmaDetectionItem(
        "Hashes", [], [SigmaString("SHA1|5F1CBC3D99558307BC1250D084FA968521482025")]
    )
    result = hashes_transformation.apply_detection_item(detection_item)
    assert isinstance(result, SigmaDetection)
    assert len(result.detection_items) == 1
    assert result.detection_items[0].field == "FileSHA1"
    assert result.detection_items[0].value == [
        SigmaString("5F1CBC3D99558307BC1250D084FA968521482025")
    ]


def test_hashes_transformation_no_string_value(hashes_transformation):
    detection_item = SigmaDetectionItem("SomethingElse", [], [SigmaNumber(123456)])
    assert hashes_transformation.apply_detection_item(detection_item) is None


def test_case_transformation_lower(dummy_pipeline):
    detection_item = SigmaDetectionItem("field", [], [SigmaString("AbC")])
    transformation = CaseTransformation(method="lower")
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaString("abc")


def test_case_transformation_upper(dummy_pipeline):
    detection_item = SigmaDetectionItem("field", [], [SigmaString("AbC")])
    transformation = CaseTransformation(method="upper")
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaString("ABC")


def test_case_transformation_special(dummy_pipeline):
    detection_item = SigmaDetectionItem("field", [], [SigmaString("AbC*zer?.123\\")])
    transformation = CaseTransformation(method="upper")
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0].s == [
        "ABC",
        SpecialChars.WILDCARD_MULTI,
        "ZER",
        SpecialChars.WILDCARD_SINGLE,
        ".123\\",
    ]


def test_case_transformation_snake_case_from_camel_case(dummy_pipeline):
    detection_item = SigmaDetectionItem("field", [], [SigmaString("abcDef")])
    transformation = CaseTransformation(method="snake_case")
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaString("abc_def")


def test_case_transformation_snake_case_from_pascal_case(dummy_pipeline):
    detection_item = SigmaDetectionItem("field", [], [SigmaString("AbcDef")])
    transformation = CaseTransformation(method="snake_case")
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaString("abc_def")


def test_case_transformation_snake_case_from_snake_case(dummy_pipeline):
    detection_item = SigmaDetectionItem("field", [], [SigmaString("abc_def")])
    transformation = CaseTransformation(method="snake_case")
    transformation.apply_detection_item(detection_item)
    assert detection_item.value[0] == SigmaString("abc_def")


def test_case_transformation_error():
    with pytest.raises(
        SigmaConfigurationError, match="Invalid method 'SnakeCase' for CaseTransformation."
    ):
        transformation = CaseTransformation(method="SnakeCase")


def test_strict_mapped_fields_throws_exception():
    test_backend = TextQueryTestBackend(
        ProcessingPipeline(
            [
                ProcessingItem(
                    FieldMappingTransformation(
                        {
                            "fieldOne": "mappedField",
                        }
                    )
                ),
                ProcessingItem(StrictFieldMappingFailure()),
            ]
        ),
    )

    with pytest.raises(
        SigmaTransformationError, match="The following fields are not mapped: fieldTwo"
    ):
        a = test_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldOne: "mapped"
                    fieldTwo: "not-mapped"
                condition: sel
                """
            )
        )


def test_strict_mapped_fields_does_not_throw_exception():
    test_backend = TextQueryTestBackend(
        ProcessingPipeline(
            [
                ProcessingItem(
                    FieldMappingTransformation(
                        {
                            "fieldOne": "mappedField",
                            "fieldTwo": "mappedFieldB",
                        }
                    )
                ),
                ProcessingItem(StrictFieldMappingFailure()),
            ]
        ),
    )

    assert (
        test_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldOne: "mapped"
                    fieldTwo: "not-mapped"
                condition: sel
                """
            )
        )
        == ['mappedField="mapped" and mappedFieldB="not-mapped"']
    )


def test_strict_mapped_fields_on_prefixing():
    test_backend = TextQueryTestBackend(
        ProcessingPipeline(
            [
                ProcessingItem(AddFieldnamePrefixTransformation("prefix_")),
                ProcessingItem(StrictFieldMappingFailure()),
            ]
        ),
    )

    assert (
        test_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldOne: "mapped"
                    fieldTwo: "not-mapped"
                condition: sel
                """
            )
        )
        == ['prefix_fieldOne="mapped" and prefix_fieldTwo="not-mapped"']
    )


def test_strict_mapped_fields_on_suffixing():
    test_backend = TextQueryTestBackend(
        ProcessingPipeline(
            [
                ProcessingItem(AddFieldnameSuffixTransformation("_suffix")),
                ProcessingItem(StrictFieldMappingFailure()),
            ]
        ),
    )

    assert (
        test_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldOne: "mapped"
                    fieldTwo: "not-mapped"
                condition: sel
                """
            )
        )
        == ['fieldOne_suffix="mapped" and fieldTwo_suffix="not-mapped"']
    )


def test_strict_mapped_fields_multiple_pipelines():
    test_backend = TextQueryTestBackend(
        ProcessingPipeline(
            [
                ProcessingItem(
                    FieldMappingTransformation(
                        {
                            "fieldOne": "mappedField",
                            "fieldTwo": "mappedFieldB",
                        }
                    )
                ),
            ]
        )
        + ProcessingPipeline(
            [
                ProcessingItem(StrictFieldMappingFailure()),
            ]
        ),
    )

    assert (
        test_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldOne: "mapped"
                    fieldTwo: "not-mapped"
                condition: sel
                """
            )
        )
        == ['mappedField="mapped" and mappedFieldB="not-mapped"']
    )


def test_strict_mapped_fields_multiple_pipelines_error():
    test_backend = TextQueryTestBackend(
        ProcessingPipeline(
            [
                ProcessingItem(
                    FieldMappingTransformation(
                        {
                            "fieldOne": "mappedField",
                        }
                    )
                ),
            ]
        )
        + ProcessingPipeline(
            [
                ProcessingItem(StrictFieldMappingFailure()),
            ]
        ),
    )

    with pytest.raises(
        SigmaTransformationError, match="The following fields are not mapped: fieldTwo"
    ):
        test_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldOne: "mapped"
                    fieldTwo: "not-mapped"
                condition: sel
                """
            )
        )


def test_strict_mapped_fields_correlation_rule(dummy_pipeline, sigma_correlation_rule):
    transformation = StrictFieldMappingFailure()
    transformation.set_pipeline(dummy_pipeline)
    transformation.apply(sigma_correlation_rule)
