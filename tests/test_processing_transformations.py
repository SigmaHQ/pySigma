from dataclasses import dataclass
from sigma.conditions import SigmaCondition
from _pytest.fixtures import fixture
import pytest
from sigma.processing import transformations
from sigma.processing.transformations import AddConditionTransformation, ChangeLogsourceTransformation, ConditionTransformation, DetectionItemFailureTransformation, DropDetectionItemTransformation, RuleFailureTransformation, FieldMappingTransformation, AddFieldnameSuffixTransformation, AddFieldnamePrefixTransformation, SetStateTransformation, Transformation, WildcardPlaceholderTransformation, ValueListPlaceholderTransformation, QueryExpressionPlaceholderTransformation, ReplaceStringTransformation
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.conditions import IncludeFieldCondition
from sigma.rule import SigmaLogSource, SigmaRule, SigmaDetection, SigmaDetectionItem
from sigma.types import Placeholder, SigmaNumber, SigmaQueryExpression, SigmaString, SpecialChars
from sigma.modifiers import SigmaExpandModifier
from sigma.exceptions import SigmaConfigurationError, SigmaRegularExpressionError, SigmaTransformationError, SigmaValueError

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
def keyword_sigma_rule():
    return SigmaRule.from_dict({
        "title": "Test",
        "logsource": {
            "category": "test"
        },
        "detection": {
            "test": [
                "value1",
                "value2",
                "value3",
            ],
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

@pytest.fixture
def sigma_rule_placeholders_simple():
    return SigmaRule.from_dict({
        "title": "Test",
        "logsource": {
            "category": "test"
        },
        "detection": {
            "test": [{
                "field|expand": "value%var1%test%var2%end",
            }],
            "condition": "test",
        }
    })

@pytest.fixture
def sigma_rule_placeholders_only():
    return SigmaRule.from_dict({
        "title": "Test",
        "logsource": {
            "category": "test"
        },
        "detection": {
            "test": [{
                "field1|expand": "%var1%",
                "field2|expand": "%var2%",
                "field3|expand": "%var3%",
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

@pytest.fixture
def field_mapping_transformation_sigma_rule(dummy_pipeline, sigma_rule):
    transformation = FieldMappingTransformation({
        "field1": "fieldA",
        "field3": [ "fieldC", "fieldD" ],
    })
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.apply(dummy_pipeline, sigma_rule)
    return sigma_rule

def test_field_mapping(field_mapping_transformation_sigma_rule):
    assert field_mapping_transformation_sigma_rule.detection.detections["test"] == SigmaDetection([
        SigmaDetection([
            SigmaDetectionItem("fieldA", [], [ SigmaString("value1") ]),
            SigmaDetectionItem("field2", [], [ SigmaString("value2") ]),
            SigmaDetection([
                SigmaDetectionItem("fieldC", [], [ SigmaString("value3") ]),
                SigmaDetectionItem("fieldD", [], [ SigmaString("value3") ]),
            ])
        ])
    ])

def test_field_mapping_tracking(field_mapping_transformation_sigma_rule):
    detection_items = field_mapping_transformation_sigma_rule.detection.detections["test"].detection_items[0].detection_items
    updated_detection_items = {
        detection_item.field: detection_item.was_processed_by("test")
        for detection_item in detection_items
        if isinstance(detection_item, SigmaDetectionItem)
    }
    updated_detection_items.update({
        detection_item.field: detection_item.was_processed_by("test")
        for detection in detection_items
        if isinstance(detection, SigmaDetection)
        for detection_item in detection.detection_items
    })
    assert (
        updated_detection_items == {
            "fieldA": True,
            "field2": False,
            "fieldC": True,
            "fieldD": True,
        }
        and field_mapping_transformation_sigma_rule.was_processed_by("test"))

def test_drop_detection_item_transformation(sigma_rule : SigmaRule, dummy_pipeline):
    transformation = DropDetectionItemTransformation()
    processing_item = ProcessingItem(
        transformation,
        detection_item_conditions=[ IncludeFieldCondition(fields=["field2"]) ],
    )
    transformation.apply(dummy_pipeline, sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection([
        SigmaDetection([
            SigmaDetectionItem("field1", [], [ SigmaString("value1") ]),
            SigmaDetectionItem("field3", [], [ SigmaString("value3") ]),
        ])
    ])

def test_drop_detection_item_transformation_all(sigma_rule : SigmaRule, dummy_pipeline):
    transformation = DropDetectionItemTransformation()
    processing_item = ProcessingItem(
        transformation,
        detection_item_conditions=[ IncludeFieldCondition(fields=["field1", "field2", "field3"]) ],
    )
    transformation.apply(dummy_pipeline, sigma_rule)
    assert sigma_rule.detection.detections["test"].detection_items[0].detection_items == []

@pytest.fixture
def add_fieldname_suffix_transformation():
    return AddFieldnameSuffixTransformation.from_dict({
        "suffix": ".test",
    })

def test_add_fieldname_suffix(dummy_pipeline, sigma_rule, add_fieldname_suffix_transformation):
    add_fieldname_suffix_transformation.apply(dummy_pipeline, sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection([
        SigmaDetection([
            SigmaDetectionItem("field1.test", [], [ SigmaString("value1") ]),
            SigmaDetectionItem("field2.test", [], [ SigmaString("value2") ]),
            SigmaDetectionItem("field3.test", [], [ SigmaString("value3") ]),
        ])
    ])

def test_add_fieldname_suffix_keyword(dummy_pipeline, keyword_sigma_rule, add_fieldname_suffix_transformation):
    add_fieldname_suffix_transformation.apply(dummy_pipeline, keyword_sigma_rule)
    assert keyword_sigma_rule.detection.detections["test"] == SigmaDetection([
        SigmaDetectionItem(None, [], [
            SigmaString("value1"),
            SigmaString("value2"),
            SigmaString("value3"),
        ]),
    ])

def test_add_fieldname_suffix_tracking(dummy_pipeline, sigma_rule, add_fieldname_suffix_transformation):
    processing_item = ProcessingItem(
        add_fieldname_suffix_transformation,
        detection_item_conditions=[
            IncludeFieldCondition("field1")
        ],
        identifier="test",
    )
    processing_item.apply(dummy_pipeline, sigma_rule)
    detection_items = sigma_rule.detection.detections["test"].detection_items[0].detection_items
    assert (
        detection_items == [
            SigmaDetectionItem("field1.test", [], [ SigmaString("value1") ]),
            SigmaDetectionItem("field2", [], [ SigmaString("value2") ]),
            SigmaDetectionItem("field3", [], [ SigmaString("value3") ]),
        ]
        and [
            detection_item.was_processed_by("test")
            for detection_item in detection_items
        ] == [ True, False, False ]
        and sigma_rule.was_processed_by("test")
    )

@pytest.fixture
def add_fieldname_prefix_transformation():
    return AddFieldnamePrefixTransformation.from_dict({
        "prefix": "test.",
    })

def test_add_fieldname_prefix(dummy_pipeline, sigma_rule, add_fieldname_prefix_transformation):
    add_fieldname_prefix_transformation.apply(dummy_pipeline, sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection([
        SigmaDetection([
            SigmaDetectionItem("test.field1", [], [ SigmaString("value1") ]),
            SigmaDetectionItem("test.field2", [], [ SigmaString("value2") ]),
            SigmaDetectionItem("test.field3", [], [ SigmaString("value3") ]),
        ])
    ])

def test_add_fieldname_prefix_keyword(dummy_pipeline, keyword_sigma_rule, add_fieldname_prefix_transformation):
    add_fieldname_prefix_transformation.apply(dummy_pipeline, keyword_sigma_rule)
    assert keyword_sigma_rule.detection.detections["test"] == SigmaDetection([
        SigmaDetectionItem(None, [], [
            SigmaString("value1"),
            SigmaString("value2"),
            SigmaString("value3"),
        ]),
    ])

def test_add_fieldname_prefix_tracking(dummy_pipeline, sigma_rule, add_fieldname_prefix_transformation):
    processing_item = ProcessingItem(
        add_fieldname_prefix_transformation,
        detection_item_conditions=[
            IncludeFieldCondition("field1")
        ],
        identifier="test",
    )
    processing_item.apply(dummy_pipeline, sigma_rule)
    detection_items = sigma_rule.detection.detections["test"].detection_items[0].detection_items
    assert (
        detection_items == [
            SigmaDetectionItem("test.field1", [], [ SigmaString("value1") ]),
            SigmaDetectionItem("field2", [], [ SigmaString("value2") ]),
            SigmaDetectionItem("field3", [], [ SigmaString("value3") ]),
        ]
        and [
            detection_item.was_processed_by("test")
            for detection_item in detection_items
        ] == [ True, False, False ]
        and sigma_rule.was_processed_by("test")
    )

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

def test_wildcard_placeholders_include_and_exclude_error():
    with pytest.raises(SigmaConfigurationError, match="exclusively"):
        WildcardPlaceholderTransformation(include=["included_field"], exclude=["excluded_field"])

def test_wildcard_placeholders_included(dummy_pipeline, sigma_rule_placeholders : SigmaRule):
    transformation = WildcardPlaceholderTransformation(include=["var1"])
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.apply(dummy_pipeline, sigma_rule_placeholders)
    detection_items = sigma_rule_placeholders.detection.detections["test"].detection_items[0].detection_items
    assert detection_items[0].value[0] == SigmaString("value*test") and \
        detection_items[0].was_processed_by("test") == True and \
        detection_items[1].value[0].s == ("value", Placeholder("var2"), "test", Placeholder("var3")) and \
        detection_items[1].was_processed_by("test") == False and \
        detection_items[2].value[0].s == ("value", SpecialChars.WILDCARD_MULTI, "test", Placeholder("var2"), "test", Placeholder("var3"), "test") and \
        detection_items[2].was_processed_by("test") == True and \
        sigma_rule_placeholders.was_processed_by("test")

def test_wildcard_placeholders_excluded(dummy_pipeline, sigma_rule_placeholders : SigmaRule):
    transformation = WildcardPlaceholderTransformation(exclude=["var2", "var3"])
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.apply(dummy_pipeline, sigma_rule_placeholders)
    detection_items = sigma_rule_placeholders.detection.detections["test"].detection_items[0].detection_items
    assert detection_items[0].value[0] == SigmaString("value*test") and \
        detection_items[0].was_processed_by("test") == True and \
        detection_items[1].value[0].s == ("value", Placeholder("var2"), "test", Placeholder("var3")) and \
        detection_items[1].was_processed_by("test") == False and \
        detection_items[2].value[0].s == ("value", SpecialChars.WILDCARD_MULTI, "test", Placeholder("var2"), "test", Placeholder("var3"), "test") and \
        detection_items[2].was_processed_by("test") == True and \
        sigma_rule_placeholders.was_processed_by("test")

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

def test_valuelist_placeholders(sigma_rule_placeholders_simple : SigmaRule):
    transformation = ValueListPlaceholderTransformation()
    pipeline = ProcessingPipeline([], { "var1": ["val1", 123], "var2": "val3"})
    transformation.apply(pipeline, sigma_rule_placeholders_simple)
    assert sigma_rule_placeholders_simple.detection.detections["test"] == SigmaDetection([
        SigmaDetection([
            SigmaDetectionItem("field", [SigmaExpandModifier], [
                SigmaString("valueval1testval3end"),
                SigmaString("value123testval3end"),
            ]),
        ])
    ])

def test_valuelist_placeholders_missing(sigma_rule_placeholders_simple : SigmaRule):
    transformation = ValueListPlaceholderTransformation()
    pipeline = ProcessingPipeline([], { "var1": "val1" })
    with pytest.raises(SigmaValueError, match="doesn't exist"):
        transformation.apply(pipeline, sigma_rule_placeholders_simple)

def test_valuelist_placeholders_wrong_type(sigma_rule_placeholders_simple : SigmaRule):
    transformation = ValueListPlaceholderTransformation()
    pipeline = ProcessingPipeline([], { "var1": None })
    with pytest.raises(SigmaValueError, match="not a string or number"):
        transformation.apply(pipeline, sigma_rule_placeholders_simple)

def test_queryexpr_placeholders(dummy_pipeline, sigma_rule_placeholders_only : SigmaRule):
    expr = "{field} lookup {id}"
    transformation = QueryExpressionPlaceholderTransformation(
        expression=expr,
        mapping={
            "var2": "placeholder2"
        }
    )
    transformation.apply(dummy_pipeline, sigma_rule_placeholders_only)
    assert sigma_rule_placeholders_only.detection.detections["test"] == SigmaDetection([
        SigmaDetection([
            SigmaDetectionItem("field1", [SigmaExpandModifier], [ SigmaQueryExpression(expr, "var1") ], auto_modifiers=False),
            SigmaDetectionItem("field2", [SigmaExpandModifier], [ SigmaQueryExpression(expr, "placeholder2") ], auto_modifiers=False),
            SigmaDetectionItem("field3", [SigmaExpandModifier], [ SigmaQueryExpression(expr, "var3") ], auto_modifiers=False),
        ])
    ])

def test_queryexpr_placeholders_without_placeholders(dummy_pipeline, sigma_rule : SigmaRule):
    transformation = QueryExpressionPlaceholderTransformation(
        expression="{field} lookup {id}",
    )
    transformation.apply(dummy_pipeline, sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection([
        SigmaDetection([
            SigmaDetectionItem("field1", [], [ SigmaString("value1") ]),
            SigmaDetectionItem("field2", [], [ SigmaString("value2") ]),
            SigmaDetectionItem("field3", [], [ SigmaString("value3") ]),
        ])
    ])

def test_queryexpr_placeholders_mixed_string(dummy_pipeline, sigma_rule_placeholders : SigmaRule):
    transformation = QueryExpressionPlaceholderTransformation(
        expression="{field} lookup {id}",
    )
    with pytest.raises(SigmaValueError, match="only allows placeholder-only strings"):
        transformation.apply(dummy_pipeline, sigma_rule_placeholders)

### ConditionTransformation ###
@dataclass
class DummyConditionTransformation(ConditionTransformation):
    """A condition transformation that does absolutely nothing or appends something to the condition."""
    do_something : bool

    def apply_condition(self, cond: SigmaCondition) -> None:
        if self.do_something:
            cond.condition += " and test"

def test_conditiontransformation_tracking_change(dummy_pipeline, sigma_rule : SigmaRule):
    transformation = DummyConditionTransformation(True)
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.apply(dummy_pipeline, sigma_rule)
    assert (
        sigma_rule.detection.parsed_condition[0].was_processed_by("test") and
        sigma_rule.was_processed_by("test")
    )

def test_conditiontransformation_tracking_nochange(dummy_pipeline, sigma_rule : SigmaRule):
    transformation = DummyConditionTransformation(False)
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.apply(dummy_pipeline, sigma_rule)
    assert (
        not sigma_rule.detection.parsed_condition[0].was_processed_by("test") and
        sigma_rule.was_processed_by("test")
    )

### AddConditionTransformation ###
def test_addconditiontransformation(dummy_pipeline, sigma_rule : SigmaRule):
    transformation = AddConditionTransformation({
        "newfield1": "test",
        "newfield2": 123,
    }, "additional")
    transformation.set_processing_item(
        ProcessingItem(
            transformation,
            identifier="test",
        )
    )
    transformation.apply(dummy_pipeline, sigma_rule)
    assert (
        sigma_rule.detection.parsed_condition[0].condition == "additional and (test)"       # condition expression was added
        and sigma_rule.detection.detections["additional"] == SigmaDetection([               # additional detection item referred by condition
                SigmaDetectionItem("newfield1", [], [ SigmaString("test") ]),
                SigmaDetectionItem("newfield2", [], [ SigmaNumber(123) ]),
        ])
        and all(                                                                            # detection items are marked as processed by processing item
            detection_item.was_processed_by("test")
            for detection_item in sigma_rule.detection.detections["additional"].detection_items
        )
        and sigma_rule.was_processed_by("test")
    )

def test_addconditiontransformation_random_name():
    transformation = AddConditionTransformation({})
    name = transformation.name
    assert len(name) > 6 and name.startswith("_cond_")

### ChangeLogsourceTransformation ###
def test_changelogsource(dummy_pipeline, sigma_rule : SigmaRule):
    processing_item = ProcessingItem(
        ChangeLogsourceTransformation("test_category", "test_product", "test_service"),
        identifier="test",
    )
    processing_item.apply(dummy_pipeline, sigma_rule)

    assert (sigma_rule.logsource == SigmaLogSource("test_category", "test_product", "test_service")
        and sigma_rule.was_processed_by("test")
        )

def test_replace_string_simple(dummy_pipeline, sigma_rule : SigmaRule):
    transformation = ReplaceStringTransformation("value", "test")
    transformation.apply(dummy_pipeline, sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection([
        SigmaDetection([
            SigmaDetectionItem("field1", [], [ SigmaString("test1") ]),
            SigmaDetectionItem("field2", [], [ SigmaString("test2") ]),
            SigmaDetectionItem("field3", [], [ SigmaString("test3") ]),
        ])
    ])

def test_replace_string_wildcard(dummy_pipeline):
    sigma_rule = SigmaRule.from_dict({
        "title": "Test",
        "logsource": {
            "category": "test"
        },
        "detection": {
            "test": [{
                "field1": "*\\value",
                "field2": 123,
            }],
            "condition": "test",
        }
    })
    transformation = ReplaceStringTransformation("^.*\\\\(.*)$", "\\1")
    transformation.apply(dummy_pipeline, sigma_rule)
    assert sigma_rule.detection.detections["test"] == SigmaDetection([
        SigmaDetection([
            SigmaDetectionItem("field1", [], [ SigmaString("value") ]),
            SigmaDetectionItem("field2", [], [ SigmaNumber(123) ]),
        ])
    ])

def test_replace_string_invalid():
    with pytest.raises(SigmaRegularExpressionError, match="Regular expression.*invalid"):
        ReplaceStringTransformation("*", "test")

def test_set_state(dummy_pipeline, sigma_rule : SigmaRule):
    transformation = SetStateTransformation("testkey", "testvalue")
    transformation.apply(dummy_pipeline, sigma_rule)
    assert dummy_pipeline.state == { "testkey": "testvalue" }

def test_rule_failure_transformation(dummy_pipeline, sigma_rule):
    transformation = RuleFailureTransformation("Test")
    with pytest.raises(SigmaTransformationError, match="^Test$"):
        transformation.apply(dummy_pipeline, sigma_rule)

def test_detection_item_failure_transformation(dummy_pipeline, sigma_rule):
    transformation = DetectionItemFailureTransformation("Test")
    with pytest.raises(SigmaTransformationError, match="^Test$"):
        transformation.apply(dummy_pipeline, sigma_rule)