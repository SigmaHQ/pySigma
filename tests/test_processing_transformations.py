import inspect
from copy import deepcopy
from dataclasses import dataclass

import pytest

import sigma.processing.transformations as transformations_module
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
)
from sigma.modifiers import SigmaExpandModifier
from sigma.processing.conditions import (
    FieldNameProcessingItemAppliedCondition,
    IncludeFieldCondition,
    RuleContainsDetectionItemCondition,
    RuleProcessingItemAppliedCondition,
    rule_conditions,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    AddFieldnamePrefixTransformation,
    AddFieldnameSuffixTransformation,
    AddFieldTransformation,
    ChangeLogsourceTransformation,
    ConvertTypeTransformation,
    DetectionItemFailureTransformation,
    DropDetectionItemTransformation,
    FieldMappingTransformation,
    FieldPrefixMappingTransformation,
    HashesFieldsDetectionItemTransformation,
    MapStringTransformation,
    NestedProcessingTransformation,
    QueryExpressionPlaceholderTransformation,
    RegexTransformation,
    RemoveFieldTransformation,
    ReplaceStringTransformation,
    RuleFailureTransformation,
    SetCustomAttributeTransformation,
    SetFieldTransformation,
    SetStateTransformation,
    SetValueTransformation,
    Transformation,
    ValueListPlaceholderTransformation,
    WildcardPlaceholderTransformation,
    transformations,
)
from sigma.processing.transformations.base import ConditionTransformation
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaLogSource, SigmaRule
from sigma.types import (
    Placeholder,
    SigmaBool,
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
                        type="re",
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
        == ("value", Placeholder("var2"), "test", Placeholder("var3"))
        and detection_items[1].was_processed_by("test") == False
        and detection_items[2].value[0].s
        == (
            "value",
            SpecialChars.WILDCARD_MULTI,
            "test",
            Placeholder("var2"),
            "test",
            Placeholder("var3"),
            "test",
        )
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
        == ("value", Placeholder("var2"), "test", Placeholder("var3"))
        and detection_items[1].was_processed_by("test") == False
        and detection_items[2].value[0].s
        == (
            "value",
            SpecialChars.WILDCARD_MULTI,
            "test",
            Placeholder("var2"),
            "test",
            Placeholder("var3"),
            "test",
        )
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
    classes_with_identifiers = transformations.values()

    def class_filter(c):
        return inspect.isclass(c) and not inspect.isabstract(c) and issubclass(c, Transformation)

    for cls in inspect.getmembers(transformations_module, class_filter):
        assert cls[1] in classes_with_identifiers


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
    with pytest.raises(Exception, match="No valid hash algo found"):
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
