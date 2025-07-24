import pytest
from datetime import date, datetime
from uuid import UUID
from sigma import conditions
from sigma.rule import (
    SigmaRuleTag,
    SigmaLogSource,
    SigmaDetectionItem,
    SigmaDetection,
    SigmaDetections,
    SigmaStatus,
    SigmaLevel,
    SigmaRule,
)
from sigma.types import (
    SigmaBool,
    SigmaExpansion,
    SigmaString,
    SigmaNumber,
    SigmaNull,
    SigmaRegularExpression,
    SigmaTimestampPart,
    TimestampPart,
)
from sigma.modifiers import (
    SigmaBase64Modifier,
    SigmaBase64OffsetModifier,
    SigmaContainsModifier,
    SigmaRegularExpressionModifier,
    SigmaAllModifier,
)
from sigma.conditions import (
    ConditionFieldEqualsValueExpression,
    ConditionValueExpression,
    SigmaCondition,
    ConditionAND,
    ConditionOR,
)
import sigma.exceptions as sigma_exceptions
from tests.test_processing_conditions import detection_item
from tests.test_processing_pipeline import processing_item
from yaml.error import YAMLError


### SigmaLevel and SigmaStatus tests ###
def test_sigmalevel_str():
    assert str(SigmaLevel.MEDIUM) == "medium"


def test_sigmalevel_comparation():
    assert SigmaLevel.HIGH == SigmaLevel.HIGH
    assert SigmaLevel.HIGH >= SigmaLevel.LOW
    assert SigmaLevel.HIGH > SigmaLevel.LOW
    assert SigmaLevel.HIGH != SigmaLevel.LOW
    assert SigmaLevel.LOW <= SigmaLevel.HIGH
    assert SigmaLevel.LOW < SigmaLevel.HIGH


def test_sigmalevel_comparation_invalid():
    with pytest.raises(sigma_exceptions.SigmaTypeError, match="Must be a SigmaLevel"):
        SigmaLevel.HIGH == "HIGH"
        SigmaLevel.HIGH >= "LOW"
        SigmaLevel.HIGH > "LOW"
        SigmaLevel.HIGH != "LOW"
        SigmaLevel.LOW <= "HIGH"
        SigmaLevel.LOW < "HIGH"


def test_sigmastatus_str():
    assert str(SigmaStatus.STABLE) == "stable"


def test_sigmastatus_comparation():
    assert SigmaStatus.STABLE == SigmaStatus.STABLE
    assert SigmaStatus.STABLE >= SigmaStatus.EXPERIMENTAL
    assert SigmaStatus.STABLE > SigmaStatus.EXPERIMENTAL
    assert SigmaStatus.STABLE != SigmaStatus.EXPERIMENTAL
    assert SigmaStatus.EXPERIMENTAL <= SigmaStatus.STABLE
    assert SigmaStatus.EXPERIMENTAL < SigmaStatus.STABLE


def test_sigmastatus_comparation_invalid():
    with pytest.raises(sigma_exceptions.SigmaTypeError, match="Must be a SigmaStatus"):
        assert SigmaStatus.STABLE == "STABLE"
        assert SigmaStatus.STABLE >= "EXPERIMENTAL"
        assert SigmaStatus.STABLE > "EXPERIMENTAL"
        assert SigmaStatus.STABLE != "EXPERIMENTAL"
        assert SigmaStatus.EXPERIMENTAL <= "STABLE"
        assert SigmaStatus.EXPERIMENTAL < "STABLE"


### SigmaRuleTag tests ###
def test_sigmaruletag_fromstr():
    assert SigmaRuleTag.from_str("namespace.name") == SigmaRuleTag("namespace", "name")


def test_sigmaruletag_fromstr_nodot():
    with pytest.raises(sigma_exceptions.SigmaValueError, match="must start with namespace"):
        SigmaRuleTag.from_str("tag")


def test_sigmaruletag_fromstr_3dots():
    assert SigmaRuleTag.from_str("namespace.subnamespace.tag") == SigmaRuleTag(
        "namespace", "subnamespace.tag"
    )


### SigmaLogSource tests ###


def test_sigmalogsource_fromdict():
    logsource = SigmaLogSource.from_dict(
        {
            "category": "category-id",
            "product": "product-id",
            "service": "service-id",
        }
    )
    assert logsource == SigmaLogSource("category-id", "product-id", "service-id")


def test_sigmalogsource_fromdict_no_category():
    logsource = SigmaLogSource.from_dict(
        {
            "product": "product-id",
            "service": "service-id",
        }
    )
    assert logsource == SigmaLogSource(None, "product-id", "service-id")


def test_sigmalogsource_fromdict_no_product():
    logsource = SigmaLogSource.from_dict(
        {
            "category": "category-id",
            "service": "service-id",
        }
    )
    assert logsource == SigmaLogSource("category-id", None, "service-id")


def test_sigmalogsource_fromdict_no_service():
    logsource = SigmaLogSource.from_dict(
        {
            "category": "category-id",
            "product": "product-id",
        }
    )
    assert logsource == SigmaLogSource("category-id", "product-id", None)


def test_sigmalogsource_fromdict_definition():
    logsource = SigmaLogSource.from_dict(
        {"category": "category-id", "product": "product-id", "definition": "use it"}
    )
    assert logsource == SigmaLogSource("category-id", "product-id", None, "use it")


def test_sigmalogsource_fromdict_category_not_str():
    with pytest.raises(sigma_exceptions.SigmaLogsourceError):
        SigmaLogSource.from_dict({"category": 1234, "product": "product-id"})


def test_sigmalogsource_fromdict_product_not_str():
    with pytest.raises(sigma_exceptions.SigmaLogsourceError):
        SigmaLogSource.from_dict({"category": "category-id", "product": {"a": "b"}})


def test_sigmalogsource_fromdict_service_not_str():
    with pytest.raises(sigma_exceptions.SigmaLogsourceError):
        SigmaLogSource.from_dict({"category": "category-id", "service": ["1", "2", "3"]})


def test_sigmalogsource_empty():
    with pytest.raises(sigma_exceptions.SigmaLogsourceError, match="can't be empty.*test.yml"):
        SigmaLogSource(None, None, None, source=sigma_exceptions.SigmaRuleLocation("test.yml"))


def test_sigmalogsource_fromdict_definition_not_str():
    with pytest.raises(sigma_exceptions.SigmaLogsourceError):
        SigmaLogSource.from_dict(
            {"category": "category-id", "definition": ["sysmon", "edr", "siem"]}
        )


def test_sigmalogsource_str():
    with pytest.raises(
        sigma_exceptions.SigmaLogsourceError,
        match="Sigma logsource must be a valid YAML map.*test.yml",
    ):
        SigmaRule.from_dict(
            {"title": "test", "logsource": "windows"},
            source=sigma_exceptions.SigmaRuleLocation("test.yml"),
        )


def test_sigmalogsource_eq():
    assert SigmaLogSource("category", "product", "service") == SigmaLogSource(
        "category", "product", "service"
    )


def test_sigmalogsource_neq():
    assert SigmaLogSource("category", "product", None) != SigmaLogSource(
        "category", "product", "service"
    )


def test_sigmalogsource_in_eq():
    assert SigmaLogSource("category", "product", "service") in SigmaLogSource(
        "category", "product", "service"
    )


def test_sigmalogsource_in():
    assert SigmaLogSource("category", "product", "service") in SigmaLogSource(
        "category", "product", None
    )


def test_sigmalogsource_not_in():
    assert SigmaLogSource("category", None, "service") not in SigmaLogSource(
        None, "product", "service"
    )


def test_sigmalogsource_in_invalid():
    with pytest.raises(sigma_exceptions.SigmaTypeError):
        assert 123 in SigmaLogSource("category", "product", "service")


# SigmaDetectionItem
def test_sigmadetectionitem_keyword_single():
    """Single keyword detection."""
    assert SigmaDetectionItem.from_mapping(None, "value") == SigmaDetectionItem(
        None, [], [SigmaString("value")]
    )


def test_sigmadetectionitem_value_cleanup_multi():
    """Multiple value cleanup."""
    assert SigmaDetectionItem(None, [], ["value", 123]) == SigmaDetectionItem(
        None, [], [SigmaString("value"), SigmaNumber(123)]
    )


def test_sigmadetectionitem_keyword_single_to_plain():
    """Single keyword detection."""
    assert SigmaDetectionItem(None, [], [SigmaString("value*")]).to_plain() == "value*"


def test_sigmadetectionitem_disabled_to_plain():
    detection_item = SigmaDetectionItem(
        None,
        [],
        [SigmaString("value*")],
        source=sigma_exceptions.SigmaRuleLocation("test.yml"),
    )
    detection_item.disable_conversion_to_plain()
    with pytest.raises(
        sigma_exceptions.SigmaValueError,
        match="can't be converted to plain data type.*test.yml",
    ):
        detection_item.to_plain()


def test_sigmadetectionitem_is_keyword():
    assert SigmaDetectionItem.from_mapping(None, "value").is_keyword() == True


def test_sigmadetectionitem_is_not_keyword():
    assert SigmaDetectionItem.from_mapping("field", "value").is_keyword() == False


def test_sigmadetectionitem_keyword_list():
    """Keyword list detection."""
    assert SigmaDetectionItem.from_mapping(None, ["string", 123]) == SigmaDetectionItem(
        None, [], [SigmaString("string"), SigmaNumber(123)]
    )


def test_sigmadetectionitem_keyword_list_to_plain():
    """Keyword list detection."""
    assert SigmaDetectionItem(None, [], [SigmaString("string"), SigmaNumber(123)]).to_plain() == [
        "string",
        123,
    ]


def test_sigmadetectionitem_keyword_modifiers():
    """Keyword detection with modifier chain."""
    assert SigmaDetectionItem.from_mapping("key|re", "reg.*exp") == SigmaDetectionItem(
        "key",
        [SigmaRegularExpressionModifier],
        [SigmaRegularExpression("reg.*exp")],
        auto_modifiers=False,
    )


def test_sigmadetectionitem_keyword_modifiers_to_plain():
    """Keyword detection with modifier chain."""
    detection_item = SigmaDetectionItem(
        None, [SigmaBase64Modifier, SigmaContainsModifier], [SigmaString("foobar")]
    )
    assert detection_item.to_plain() == {"|base64|contains": "foobar"}


def test_sigmadetectionitem_unknown_modifier():
    """Keyword detection with modifier chain."""
    with pytest.raises(sigma_exceptions.SigmaModifierError, match="Unknown modifier.*test.yml"):
        SigmaDetectionItem.from_mapping(
            "|foobar", "foobar", source=sigma_exceptions.SigmaRuleLocation("test.yml")
        )


def test_sigmadetectionitem_key_value_single_string():
    """Key-value detection with one value."""
    assert SigmaDetectionItem.from_mapping("key", "value") == SigmaDetectionItem(
        "key", [], [SigmaString("value")]
    )


def test_sigmadetectionitem_key_value_single_string_to_plain():
    """Key-value detection with one value."""
    assert SigmaDetectionItem("key", [], [SigmaString("value")]).to_plain() == {"key": "value"}


def test_sigmadetectionitem_key_value_single_string_modifier_to_plain():
    """
    Key-value detection with one value and contains modifier converted to plain. Important: the
    original value should appear instead of the modified.
    """
    detection_item = SigmaDetectionItem("key", [SigmaContainsModifier], [SigmaString("value")])
    detection_item.apply_modifiers()
    assert detection_item.to_plain() == {"key|contains": "value"}


def test_sigmadetectionitem_key_value_single_int():
    """Key-value detection with one integer value."""
    assert SigmaDetectionItem.from_mapping("key", 123) == SigmaDetectionItem(
        "key", [], [SigmaNumber(123)]
    )


def test_sigmadetectionitem_key_value_single_float():
    """Key-value detection with one integer value."""
    assert SigmaDetectionItem.from_mapping("key", 12.34) == SigmaDetectionItem(
        "key", [], [SigmaNumber(12.34)]
    )


def test_sigmadetectionitem_key_value_none():
    """Key-value detection with none value."""
    assert SigmaDetectionItem.from_mapping("key", None) == SigmaDetectionItem(
        "key", [], [SigmaNull()]
    )


def test_sigmadetectionitem_key_value_single_regexp():
    """Key-value detection with one value."""
    assert SigmaDetectionItem.from_mapping("key|re", "reg.*exp") == SigmaDetectionItem(
        "key",
        [SigmaRegularExpressionModifier],
        [SigmaRegularExpression("reg.*exp")],
        auto_modifiers=False,
    )


def test_sigmadetectionitem_key_value_single_regexp_to_plain():
    """Key-value detection with one value."""
    assert SigmaDetectionItem.from_mapping("key|re", "reg.*exp").to_plain() == {
        "key|re": "reg.*exp"
    }


def test_sigmadetectionitem_key_value_single_regexp_trailing_backslashes_to_plain():
    """Key-value detection with one value."""
    assert SigmaDetectionItem.from_mapping("key|re", "reg.*exp\\\\").to_plain() == {
        "key|re": "reg.*exp\\\\"
    }


def test_sigmadetectionitem_key_value_list():
    """Key-value detection with value list."""
    assert SigmaDetectionItem.from_mapping("key", ["string", 123]) == SigmaDetectionItem(
        "key", [], [SigmaString("string"), SigmaNumber(123)]
    )


def test_sigmadetectionitem_key_value_list_to_plain():
    """Key-value detection with value list."""
    assert SigmaDetectionItem.from_mapping("key", ["string", 123]).to_plain() == {
        "key": ["string", 123]
    }


def test_sigmadetectionitem_key_value_modifiers():
    """Key-value detection with modifier chain with first modifier expanding value to multiple values"""
    assert SigmaDetectionItem.from_mapping(
        "key|base64offset|contains|all", "foobar"
    ) == SigmaDetectionItem(
        "key",
        [SigmaBase64OffsetModifier, SigmaContainsModifier, SigmaAllModifier],
        [
            SigmaExpansion(
                [
                    SigmaString("*Zm9vYmFy*"),
                    SigmaString("*Zvb2Jhc*"),
                    SigmaString("*mb29iYX*"),
                ]
            )
        ],
        ConditionAND,
        auto_modifiers=False,
    )


def test_sigmadetectionitem_key_value_modifiers_to_plain():
    """Key-value detection with modifier chain with first modifier expanding value to multiple values"""
    assert SigmaDetectionItem.from_mapping(
        "key|base64offset|contains|all", "foobar"
    ).to_plain() == {"key|base64offset|contains|all": "foobar"}


def test_sigmadetectionitem_key_value_modifiers_invalid_re():
    """Invalid regular expression modifier chain."""
    with pytest.raises(sigma_exceptions.SigmaValueError, match="only applicable.*test.yml"):
        SigmaDetectionItem.from_mapping(
            "key|base64|re",
            "value",
            source=sigma_exceptions.SigmaRuleLocation("test.yml"),
        )


def test_sigmadetectionitem_fromvalue():
    assert SigmaDetectionItem.from_value("test") == SigmaDetectionItem(
        None, [], [SigmaString("test")]
    )


def test_sigmadetectionitem_processing_item_tracking(processing_item):
    """Key-value detection with one value."""
    detection_item = SigmaDetectionItem.from_mapping("key", "value")
    detection_item.add_applied_processing_item(processing_item)
    assert detection_item.was_processed_by("test")


### SigmaDetection tests ###


def test_sigmadetection_items():
    assert (
        SigmaDetection(
            [
                SigmaDetectionItem("key_1", [], [SigmaString("value_1")]),
                SigmaDetectionItem("key_2", [], [SigmaString("value_2")]),
            ]
        ).item_linking
        == ConditionAND
    )


def test_sigmadetection_detections():
    assert (
        SigmaDetection(
            [
                SigmaDetection([SigmaDetectionItem("key_1", [], [SigmaString("value_1")])]),
                SigmaDetection([SigmaDetectionItem("key_2", [], [SigmaString("value_2")])]),
            ]
        ).item_linking
        == ConditionOR
    )


def test_sigmadetection_mixed():
    assert SigmaDetection(
        [
            SigmaDetectionItem("key_1", [], [SigmaString("value_1")]),
            SigmaDetection([SigmaDetectionItem("key_2", [], [SigmaString("value_2")])]),
        ]
    )


def test_sigmadetection_to_plain():
    assert SigmaDetection(
        [
            SigmaDetectionItem("test_str", [], [SigmaString("test")]),
            SigmaDetectionItem("test_num", [], [SigmaNumber(123)]),  # Issue #56
            SigmaDetectionItem("test_bool", [], [SigmaBool(True)]),
            SigmaDetectionItem("test_null", [], [SigmaNull()]),
        ]
    ).to_plain() == {
        "test_str": "test",
        "test_num": 123,
        "test_bool": True,
        "test_null": None,
    }


### SigmaDetections tests ###


def test_sigmadetections_fromdict():
    detections = {
        "keyword_list": [
            "keyword_1",
            "keyword_2",
            3,
        ],
        "test_list_of_maps": [
            {"key1": "value1"},
            {"key2": 2},
        ],
        "test_map": {
            "key1": "value1",
            "key2": 2,
        },
        "single_keyword": "keyword",
    }
    condition = "1 of them"
    sigma_detections = SigmaDetections.from_dict(
        {
            **detections,
            "condition": condition,
        }
    )
    assert sigma_detections == SigmaDetections(
        detections={
            "keyword_list": SigmaDetection(
                [
                    SigmaDetectionItem(
                        None,
                        [],
                        [
                            SigmaString("keyword_1"),
                            SigmaString("keyword_2"),
                            SigmaNumber(3),
                        ],
                    ),
                ]
            ),
            "test_list_of_maps": SigmaDetection(
                [
                    SigmaDetection([SigmaDetectionItem("key1", [], [SigmaString("value1")])]),
                    SigmaDetection([SigmaDetectionItem("key2", [], [SigmaNumber(2)])]),
                ]
            ),
            "test_map": SigmaDetection(
                [
                    SigmaDetectionItem("key1", [], [SigmaString("value1")]),
                    SigmaDetectionItem("key2", [], [SigmaNumber(2)]),
                ]
            ),
            "single_keyword": SigmaDetection(
                [SigmaDetectionItem(None, [], [SigmaString("keyword")])]
            ),
        },
        condition=[condition],
    )
    assert isinstance(sigma_detections.parsed_condition[0], SigmaCondition)


def test_sigmadetections_to_dict_single_condition():
    assert SigmaDetections(
        detections={
            "test": SigmaDetection([SigmaDetectionItem("field", [], [SigmaString("value")])])
        },
        condition=["test"],
    ).to_dict() == {"test": {"field": "value"}, "condition": "test"}


def test_sigmadetections_to_dict_double_condition():
    assert SigmaDetections(
        detections={
            "test": SigmaDetection([SigmaDetectionItem("field", [], [SigmaString("value")])])
        },
        condition=["test", "all of them"],
    ).to_dict() == {"test": {"field": "value"}, "condition": ["test", "all of them"]}


def test_sigmadetections_index():
    assert SigmaDetections(
        detections={
            "foo": SigmaDetection(
                [
                    SigmaDetectionItem(None, [], [SigmaString("keyword_1")]),
                ]
            ),
            "bar": SigmaDetection(
                [
                    SigmaDetectionItem(None, [], [SigmaString("keyword_2")]),
                ]
            ),
        },
        condition=["1 of them"],
    )["foo"] == SigmaDetection(
        [
            SigmaDetectionItem(None, [], [SigmaString("keyword_1")]),
        ]
    )


def test_sigmadetections_fromdict_no_detections():
    with pytest.raises(sigma_exceptions.SigmaDetectionError, match="No detections.*test.yml"):
        SigmaDetections.from_dict(
            {"condition": ["selection"]}, sigma_exceptions.SigmaRuleLocation("test.yml")
        )


def test_sigmadetections_fromdict_no_condition():
    with pytest.raises(
        sigma_exceptions.SigmaConditionError, match="at least one condition.*test.yml"
    ):
        SigmaDetections.from_dict(
            {"selection": {"key": "value"}},
            sigma_exceptions.SigmaRuleLocation("test.yml"),
        )


def test_sigmadetections_empty_condition_list():
    with pytest.raises(
        sigma_exceptions.SigmaConditionError, match="at least one condition.*test.yml"
    ):
        SigmaDetections(
            detections={
                "selection": SigmaDetection([SigmaDetectionItem("key", [], [SigmaString("value")])])
            },
            condition=[],
            source=sigma_exceptions.SigmaRuleLocation("test.yml"),
        )


def test_sigmadetections_none_condition():
    with pytest.raises(
        sigma_exceptions.SigmaConditionError, match="at least one condition.*test.yml"
    ):
        SigmaDetections(
            detections={
                "selection": SigmaDetection([SigmaDetectionItem("key", [], [SigmaString("value")])])
            },
            condition=None,
            source=sigma_exceptions.SigmaRuleLocation("test.yml"),
        )


def test_detectionitem_all_modified_key_plain_values_postprocess():
    """
    Test if postprocessed condition result of an all-modified field-bound value list results in an
    AND condition linking all listed values.
    """
    detections = SigmaDetections.from_dict(
        {"selection": {"field|all": ["val1", "val2", 123]}, "condition": "selection"}
    )
    assert detections.parsed_condition[0].parsed == ConditionAND(
        [
            ConditionFieldEqualsValueExpression("field", SigmaString("val1")),
            ConditionFieldEqualsValueExpression("field", SigmaString("val2")),
            ConditionFieldEqualsValueExpression("field", SigmaNumber(123)),
        ]
    )


def test_detectionitem_all_modified_unbound_plain_values_postprocess():
    """
    Test if postprocessed condition result of an all-modified not field-bound value list results in an
    AND condition linking all listed values.
    """
    detections = SigmaDetections.from_dict(
        {"selection": {"|all": ["val1", "val2", 123]}, "condition": "selection"}
    )
    assert detections.parsed_condition[0].parsed == ConditionAND(
        [
            ConditionValueExpression(SigmaString("val1")),
            ConditionValueExpression(SigmaString("val2")),
            ConditionValueExpression(SigmaNumber(123)),
        ]
    )


def test_detectionitem_all_modified_key_special_values_postprocess():
    """
    Test if postprocessed condition result of an all-modified field-bound value list containing
    strings with wildcards results in an AND condition linking all listed values.
    """
    detections = SigmaDetections.from_dict(
        {"selection": {"field|all": ["val1*", "val2", 123]}, "condition": "selection"}
    )
    assert detections.parsed_condition[0].parsed == ConditionAND(
        [
            ConditionFieldEqualsValueExpression("field", SigmaString("val1*")),
            ConditionFieldEqualsValueExpression("field", SigmaString("val2")),
            ConditionFieldEqualsValueExpression("field", SigmaNumber(123)),
        ]
    )


def test_sigmadetection_from_definition_mapping():
    """Test if SigmaDetection can be created from a definition mapping."""
    definition_mapping = {
        "field1": ["value1", "value2"],
        "field2": "value3",
        "field3|re": "regex.*pattern",
    }
    detection = SigmaDetection.from_definition(definition_mapping)
    assert detection.detection_items == [
        SigmaDetectionItem("field1", [], [SigmaString("value1"), SigmaString("value2")]),
        SigmaDetectionItem("field2", [], [SigmaString("value3")]),
        SigmaDetectionItem(
            "field3",
            [SigmaRegularExpressionModifier],
            [SigmaRegularExpression("regex.*pattern")],
            auto_modifiers=False,
        ),
    ]


def test_sigmadetection_from_definition_plain_value():
    detection = SigmaDetection.from_definition("keyword")
    assert detection.detection_items == [SigmaDetectionItem(None, [], [SigmaString("keyword")])]


def test_sigmadetection_from_definition_list_of_values():
    detection = SigmaDetection.from_definition(["value1", "value2"])
    assert detection.detection_items == [
        SigmaDetectionItem(None, [], [SigmaString("value1"), SigmaString("value2")])
    ]


def test_sigmadetection_from_definition_list_of_dicts():
    detection = SigmaDetection.from_definition(
        [
            {"field1": "value1"},
            {"field2": "value2"},
        ]
    )
    assert detection.detection_items == [
        SigmaDetection([SigmaDetectionItem("field1", [], [SigmaString("value1")])]),
        SigmaDetection([SigmaDetectionItem("field2", [], [SigmaString("value2")])]),
    ]


def test_sigmadetection_from_definition_unsupported_type():
    """Test if an unsupported type raises an error."""
    with pytest.raises(sigma_exceptions.SigmaDetectionError, match="Unsupported.*type"):
        SigmaDetection.from_definition(object())


def test_sigmadetection_processing_item_tracking(processing_item):
    """Key-value detection with one value."""
    detection = SigmaDetection(
        [
            SigmaDetectionItem("field1", [], [SigmaString("value1")]),
            SigmaDetectionItem("field2", [], [SigmaString("value2")]),
            SigmaDetection(
                [
                    SigmaDetectionItem("field3", [], [SigmaString("value3")]),
                    SigmaDetectionItem("field4", [], [SigmaString("value4")]),
                ]
            ),
        ]
    )
    detection.add_applied_processing_item(processing_item)
    assert all(
        [
            (
                detection_item.was_processed_by("test")
                if isinstance(detection_item, SigmaDetectionItem)
                else all(
                    [
                        sub_detection_item.was_processed_by("test")
                        for sub_detection_item in detection_item.detection_items
                    ]
                )
            )
            for detection_item in detection.detection_items
        ]
    )


def test_sigmadetection_single_to_plain():
    assert SigmaDetection(
        detection_items=[SigmaDetectionItem("field", [], [SigmaString("value")])]
    ).to_plain() == {"field": "value"}


def test_sigmadetection_multi_dict_to_plain():
    assert SigmaDetection(
        detection_items=[
            SigmaDetectionItem("field1", [], [SigmaString("value1")]),
            SigmaDetectionItem("field2", [], [SigmaString("value2")]),
        ]
    ).to_plain() == {
        "field1": "value1",
        "field2": "value2",
    }


def test_sigmadetection_multi_dict_to_plain_key_collision():
    """Two field names exist in distinct detection items and have to be merged."""
    assert SigmaDetection(
        detection_items=[
            SigmaDetectionItem("field", [], [SigmaString("value1")]),
            SigmaDetectionItem("field", [], [SigmaString("value2")]),
        ]
    ).to_plain() == {"field|all": ["value1", "value2"]}


def test_sigmadetection_multi_dict_to_plain_all_key_collision():
    """Two field names exist in distinct detection items and have to be merged."""
    assert SigmaDetection(
        detection_items=[
            SigmaDetectionItem("field|all", [], [SigmaString("value1")]),
            SigmaDetectionItem("field|all", [], [SigmaString("value2")]),
        ]
    ).to_plain() == {"field|all": ["value1", "value2"]}


def test_sigmadetection_multi_dict_to_plain_all_key_collision_list_values():
    """Two field names exist in distinct detection items and have to be merged."""
    assert SigmaDetection(
        detection_items=[
            SigmaDetectionItem("field|all", [], [SigmaString("value1"), SigmaString("value2")]),
            SigmaDetectionItem("field|all", [], [SigmaString("value3"), SigmaString("value4")]),
        ]
    ).to_plain() == {"field|all": ["value1", "value2", "value3", "value4"]}


def test_sigmadetection_multi_dict_to_plain_key_collision_all():
    assert SigmaDetection(
        detection_items=[
            SigmaDetectionItem("field", [], [SigmaString("value1")]),
            SigmaDetectionItem("field|all", [], [SigmaString("value2"), SigmaString("value3")]),
        ]
    ).to_plain() == {
        "field": "value1",
        "field|all": ["value2", "value3"],
    }


def test_sigmadetection_multi_dict_to_plain_key_collision_lists():
    """
    Two items with the same field value and multiple values can't be merged, because both items are
    implicitely and-linked, while the list items are or-linked. Merging them would cause a semantic
    change because all items must have the same logical linking.
    """
    with pytest.raises(
        sigma_exceptions.SigmaValueError, match="different logical linking.*test.yml"
    ):
        SigmaDetection(
            detection_items=[
                SigmaDetectionItem("field", [], [SigmaString("value1"), SigmaString("value2")]),
                SigmaDetectionItem("field", [], [SigmaString("value3"), SigmaString("value4")]),
            ],
            source=sigma_exceptions.SigmaRuleLocation("test.yml"),
        ).to_plain()


def test_sigmadetection_multi_dict_to_plain_key_collision_all_2single():
    assert SigmaDetection(
        detection_items=[
            SigmaDetectionItem("field|all", [], [SigmaString("value1"), SigmaString("value2")]),
            SigmaDetectionItem("field", [], [SigmaString("value3")]),
            SigmaDetectionItem("field", [], [SigmaString("value4")]),
        ]
    ).to_plain() == {
        "field|all": [
            SigmaString("value1"),
            SigmaString("value2"),
            SigmaString("value3"),
            SigmaString("value4"),
        ]
    }


def test_sigmadetection_lists_and_plain_to_plain():
    assert SigmaDetection(
        detection_items=[
            SigmaDetectionItem(None, [], [SigmaString("value1")]),
            SigmaDetectionItem(None, [], [SigmaString("value2"), SigmaString("value3")]),
            SigmaDetectionItem(None, [], [SigmaString("value4"), SigmaString("value5")]),
        ]
    ).to_plain() == ["value1", "value2", "value3", "value4", "value5"]


def test_sigmadetection_dict_and_keyword_to_plain():
    with pytest.raises(sigma_exceptions.SigmaValueError, match="Can't convert detection.*test.yml"):
        SigmaDetection(
            detection_items=[
                SigmaDetectionItem("field", [], [SigmaString("value")]),
                SigmaDetectionItem(None, [], [SigmaString("keyword")]),
            ],
            source=sigma_exceptions.SigmaRuleLocation("test.yml"),
        ).to_plain()


### SigmaRule tests ###


def test_sigmarule_fields_not_list():
    with pytest.raises(sigma_exceptions.SigmaFieldsError, match="must be a list.*test.yml"):
        SigmaRule.from_dict(
            {"fields": "test"}, source=sigma_exceptions.SigmaRuleLocation("test.yml")
        )


def test_sigmarule_bad_uuid():
    with pytest.raises(sigma_exceptions.SigmaIdentifierError, match="must be an UUID.*test.yml"):
        SigmaRule.from_dict(
            {"id": "no-uuid"}, source=sigma_exceptions.SigmaRuleLocation("test.yml")
        )


def test_sigmarule_bad_name():
    with pytest.raises(sigma_exceptions.SigmaTypeError, match="must be a string.*test.yml"):
        SigmaRule.from_dict({"name": 123}, source=sigma_exceptions.SigmaRuleLocation("test.yml"))


def test_sigmarule_empty_name():
    with pytest.raises(sigma_exceptions.SigmaNameError, match="must not be empty.*test.yml"):
        SigmaRule.from_dict({"name": ""}, source=sigma_exceptions.SigmaRuleLocation("test.yml"))


def test_sigmarule_bad_description():
    with pytest.raises(sigma_exceptions.SigmaDescriptionError, match="must be a string.*test.yml"):
        SigmaRule.from_dict(
            {"description": ["1", "2"]}, source=sigma_exceptions.SigmaRuleLocation("test.yml")
        )


def test_sigmarule_bad_level():
    with pytest.raises(
        sigma_exceptions.SigmaLevelError, match="not a valid Sigma rule level.*test.yml"
    ):
        SigmaRule.from_dict({"level": "bad"}, source=sigma_exceptions.SigmaRuleLocation("test.yml"))


def test_sigmarule_bad_status():
    with pytest.raises(
        sigma_exceptions.SigmaStatusError, match="not a valid Sigma rule status.*test.yml"
    ):
        SigmaRule.from_dict(
            {"status": "bad"}, source=sigma_exceptions.SigmaRuleLocation("test.yml")
        )


def test_sigmarule_bad_status_type():
    with pytest.raises(
        sigma_exceptions.SigmaStatusError, match="Sigma rule status cannot be a list.*test.yml"
    ):
        SigmaRule.from_dict(
            {"status": ["test"]}, source=sigma_exceptions.SigmaRuleLocation("test.yml")
        )


def test_sigmarule_bad_date():
    """This test uses string data type as date representation in yaml"""
    bad_string_dates = (
        "bad",
        " 2024-11-24",
        "2024-11-24 ",
        "2024 11-24",
        "24-11-24",
        "02-02-02",
        "4000-01-01",
        "10000-01-01",
        "2022-01/01",
        "2022/01-01",
    )
    for test_string in bad_string_dates:
        match_string = f"Rule date '{test_string}' is invalid, use yyyy-mm-dd"
        with pytest.raises(sigma_exceptions.SigmaDateError, match=match_string) as ex:
            SigmaRule.from_yaml(
                f"""
                title: Test
                date: '{test_string}'  # try a string
                logsource:
                    product: foobar
                detection:
                    selection_1:
                        fieldA: valueA
                    condition: selection_1
                """
            )
            assert False, f"Did not throw SigmaDateError on date {test_string}"


def test_sigmarule_bad_modified():
    """
    This test uses yaml ability to recognize dates.
    Therefore, here 4000-01-01 will be interpreted as a correct yaml date.
    """
    bad_dates = (
        "bad",
        "24-11-24",
        "02-02-02",
        "2024-5-5",
        "10000-01-01",
        "2022-01/01",
        "2022/01-01",
        "2022 01/01",
    )
    for test_string in bad_dates:
        match_string = f"Rule modified '{test_string}' is invalid, use yyyy-mm-dd"
        with pytest.raises(sigma_exceptions.SigmaModifiedError, match=match_string) as ex:
            SigmaRule.from_yaml(
                f"""
                title: Test
                modified: {test_string}  # this can be recognized as date by yaml parser
                logsource:
                    product: foobar
                detection:
                    selection_1:
                        fieldA: valueA
                    condition: selection_1
                """
            )
            assert False, f"Did not throw SigmaModifiedError on date {test_string}"


def test_sigmarule_bad_falsepositives():
    with pytest.raises(
        sigma_exceptions.SigmaFalsePositivesError,
        match="Sigma rule falsepositives must be a list.*test.yml",
    ):
        SigmaRule.from_dict(
            {"falsepositives": "bad"}, source=sigma_exceptions.SigmaRuleLocation("test.yml")
        )


def test_sigmarule_bad_references():
    with pytest.raises(
        sigma_exceptions.SigmaReferencesError,
        match="Sigma rule references must be a list.*test.yml",
    ):
        SigmaRule.from_dict(
            {"references": "bad"}, source=sigma_exceptions.SigmaRuleLocation("test.yml")
        )


def test_sigmarule_date():
    expected_date = date(3000, 1, 2)
    rule = SigmaRule.from_yaml(
        """
    title: Test
    id: cafedead-beef-0000-1111-0123456789ab
    level: medium
    status: test
    date: 3000-01-02
    logsource:
        product: foobar
    detection:
        selection_1:
            fieldA: valueA
        condition: selection_1
    """
    )
    assert rule is not None
    assert rule.date == expected_date


def test_modified_date():
    validDates = {
        "3000-12-31": date(3000, 12, 31),  # can appear as a generic date in the future
        "2999-04-04": date(2999, 4, 4),
        "2024-11-22": date(2024, 11, 22),
        "1970-01-01": date(1970, 1, 1),  # can appear as a generic date in the past
        "1900-12-31": date(1900, 12, 31),  # not much useful, but correct
        "2024/11/22": date(2024, 11, 22),  # US-based sigmas have such dates
        "2024/1/2": date(2024, 1, 2),
        "1970/1/1": date(1970, 1, 1),
    }
    for test_string, expected_date in validDates.items():
        rule = SigmaRule.from_yaml(
            f"""
            title: Test
            id: cafedead-beef-0000-1111-0123456789ab
            level: medium
            status: test
            date: {test_string}       # possibly a yaml date
            modified: '{test_string}' # always a string data type converted into date
            logsource:
                product: foobar
            detection:
                selection_1:
                    fieldA: valueA
                condition: selection_1
            """
        )
        assert rule is not None
        assert rule.date == expected_date, f"bad 'date' for '{test_string}'"
        assert rule.modified == expected_date, f"bad 'modified' for '{test_string}'"


def test_sigmarule_datetime():
    expected_date = datetime(3000, 1, 2, 3, 4, 5)
    rule = SigmaRule.from_yaml(
        """
    title: Test
    id: cafedead-beef-0000-1111-123456789abc
    level: medium
    status: test
    date: 3000-01-02T03:04:05
    logsource:
        product: foobar
    detection:
        selection_1:
            fieldA: valueA
        condition: selection_1
    """
    )
    assert rule is not None
    assert rule.date == expected_date


def test_sigmarule_collect_errors():
    rule = SigmaRule.from_yaml(
        """
    title: Test
    id: invalid
    level: invalid
    status: invalid
    date: invalid
    detections:
    detection:
        selection_1:
            Image|test: test.exe
        condition: selection
    """,
        collect_errors=True,
    )
    assert {error.__class__ for error in rule.errors} == {
        sigma_exceptions.SigmaIdentifierError,
        sigma_exceptions.SigmaLevelError,
        sigma_exceptions.SigmaStatusError,
        sigma_exceptions.SigmaDateError,
        sigma_exceptions.SigmaLogsourceError,
        sigma_exceptions.SigmaModifierError,
    }


def test_sigmarule_no_logsource():
    with pytest.raises(
        sigma_exceptions.SigmaLogsourceError, match="must have a log source.*test.yml"
    ):
        SigmaRule.from_dict(
            {"title": "azerty"}, source=sigma_exceptions.SigmaRuleLocation("test.yml")
        )


def test_sigmarule_no_detections():
    with pytest.raises(
        sigma_exceptions.SigmaDetectionError, match="must have a detection.*test.yml"
    ):
        SigmaRule.from_dict(
            {"title": "azerty", "logsource": {"category": "category-id"}},
            source=sigma_exceptions.SigmaRuleLocation("test.yml"),
        )


def test_sigmarule_none_to_list():
    sigma_rule = SigmaRule(
        title="Test",
        logsource=SigmaLogSource(category="test"),
        detection=SigmaDetections(
            detections={
                "selection": SigmaDetection(
                    [
                        SigmaDetectionItem(
                            "CommandLine",
                            [SigmaContainsModifier],
                            [SigmaString("*test.exe*")],
                        )
                    ]
                ),
            },
            condition=["selection"],
        ),
    )
    assert all(
        (
            sigma_rule.__getattribute__(field) == []
            for field in ("references", "tags", "fields", "falsepositives")
        )
    )


@pytest.fixture
def sigma_rule():
    return SigmaRule(
        title="Test",
        id=UUID("9a6cafa7-1481-4e64-89a1-1f69ed08618c"),
        name="test",
        taxonomy="test",
        status=SigmaStatus.TEST,
        description="This is a test",
        references=[
            "ref1",
            "ref2",
        ],
        tags=[
            SigmaRuleTag.from_str("attack.execution"),
            SigmaRuleTag.from_str("attack.t1059"),
        ],
        author="Thomas Patzke",
        date=date(2020, 7, 12),
        logsource=SigmaLogSource(
            category="process_creation",
            product="windows",
            service=None,
        ),
        detection=SigmaDetections(
            detections={
                "selection_1": SigmaDetection(
                    [
                        SigmaDetectionItem(
                            "CommandLine",
                            [SigmaContainsModifier],
                            [SigmaString("test.exe")],
                        )
                    ]
                ),
                "selection_2": SigmaDetection(
                    [
                        SigmaDetection(
                            [
                                SigmaDetectionItem(
                                    "CommandLine",
                                    [SigmaContainsModifier],
                                    [SigmaString("test.exe")],
                                )
                            ]
                        ),
                        SigmaDetection(
                            [
                                SigmaDetectionItem(
                                    "CommandLine", [SigmaContainsModifier], [SigmaString("cmd.exe")]
                                )
                            ]
                        ),
                    ]
                ),
                "selection_3": SigmaDetection(
                    [
                        SigmaDetectionItem(
                            None, [], [SigmaString("keyword_1"), SigmaString("keyword_2")]
                        ),
                    ]
                ),
            },
            condition=["1 of them"],
        ),
        fields=[
            "User",
            "CommandLine",
        ],
        falsepositives=[
            "Everything",
        ],
        level=SigmaLevel.LOW,
    )


def test_sigmarule_fromyaml(sigma_rule):
    sigmarule_from_yaml = SigmaRule.from_yaml(
        """
    title: Test
    id: 9a6cafa7-1481-4e64-89a1-1f69ed08618c
    name: test
    taxonomy: test
    status: test
    description: This is a test
    references:
        - ref1
        - ref2
    tags:
        - attack.execution
        - attack.t1059
    author: Thomas Patzke
    date: 2020-07-12
    logsource:
        category: process_creation
        product: windows
    detection:
        selection_1:
            CommandLine|contains: test.exe
        selection_2:
            - CommandLine|contains: test.exe
            - CommandLine|contains: cmd.exe
        selection_3:
            - keyword_1
            - keyword_2
        condition: 1 of them
    fields:
        - User
        - CommandLine
    falsepositives:
        - Everything
    level: low
    """
    )
    assert sigmarule_from_yaml == sigma_rule


def test_sigmarule_fromyaml_with_custom_attribute(sigma_rule):
    sigmarule_from_yaml = SigmaRule.from_yaml(
        """
    title: Test
    id: 9a6cafa7-1481-4e64-89a1-1f69ed08618c
    name: test
    taxonomy: test
    status: test
    description: This is a test
    references:
        - ref1
        - ref2
    tags:
        - attack.execution
        - attack.t1059
    author: Thomas Patzke
    date: 2020-07-12
    logsource:
        category: process_creation
        product: windows
    detection:
        selection_1:
            CommandLine|contains: test.exe
        selection_2:
            - CommandLine|contains: test.exe
            - CommandLine|contains: cmd.exe
        selection_3:
            - keyword_1
            - keyword_2
        condition: 1 of them
    fields:
        - User
        - CommandLine
    falsepositives:
        - Everything
    level: low
    custom: attribute
    """
    )
    assert sigmarule_from_yaml == sigma_rule
    assert sigmarule_from_yaml.custom_attributes == {"custom": "attribute"}


def test_sigmarule_fromyaml_duplicate_key():
    with pytest.raises(YAMLError, match="Duplicate key"):
        SigmaRule.from_yaml(
            """
        title: Test
        id: 9a6cafa7-1481-4e64-89a1-1f69ed08618c
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine|contains: test.exe
            selection:
                - CommandLine|contains: test.exe
                - CommandLine|contains: cmd.exe
            condition: 1 of them
        level: low
        """
        )


def test_sigmarule_to_dict(sigma_rule: SigmaRule):
    assert sigma_rule.to_dict() == {
        "title": "Test",
        "id": "9a6cafa7-1481-4e64-89a1-1f69ed08618c",
        "name": "test",
        "status": "test",
        "description": "This is a test",
        "references": [
            "ref1",
            "ref2",
        ],
        "tags": [
            "attack.execution",
            "attack.t1059",
        ],
        "author": "Thomas Patzke",
        "date": "2020-07-12",
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection_1": {
                "CommandLine|contains": "test.exe",
            },
            "selection_2": {
                "CommandLine|contains|all": ["test.exe", "cmd.exe"],
            },
            "selection_3": [
                "keyword_1",
                "keyword_2",
            ],
            "condition": "1 of them",
        },
        "fields": ["User", "CommandLine"],
        "falsepositives": [
            "Everything",
        ],
        "level": "low",
    }


def test_empty_detection():
    with pytest.raises(sigma_exceptions.SigmaDetectionError, match="Detection is empty.*test.yml"):
        SigmaDetection([], sigma_exceptions.SigmaRuleLocation("test.yml"))


def test_sigmarule_processing_item_tracking(sigma_rule, processing_item):
    sigma_rule.add_applied_processing_item(processing_item)
    assert sigma_rule.was_processed_by("test")


def test_sigma_rule_overlapping_selections():
    rule = SigmaRule.from_yaml(
        """
    title: test
    logsource:
        category: test
    detection:
        selection1:
            field|contains|all:
                - str1
                - str2
        selection2:
            field|contains|all:
                - str1
                - str2
                - str3
                - str4
        condition: 1 of selection*
    """
    )
    cond = rule.detection.parsed_condition[0].parsed
    assert (
        isinstance(cond, ConditionOR)
        and all((isinstance(arg, ConditionAND) for arg in cond.args))
        and [len(ands.args) for ands in cond.args] == [2, 4]
    )


def test_invalid_related_type():
    with pytest.raises(
        sigma_exceptions.SigmaRelatedError, match="same is not a Sigma related valid type"
    ):
        SigmaRule.from_yaml(
            """
    title: Test
    related:
        - id: 08fbc97d-0a2f-491c-ae21-8ffcfd3174e9
          type: derived
        - id: 929a690e-bef0-4204-a928-ef5e620d6fcc
          type: obsolete
        - id: 929a690e-bef0-4204-a928-ef5e620d6fff
          type: same
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
        )


def test_invalid_related_id():
    with pytest.raises(
        sigma_exceptions.SigmaRelatedError, match="Sigma related identifier must be an UUID"
    ):
        SigmaRule.from_yaml(
            """
    title: Test
    related:
        - id: 08fbc97d-0a2f-491c-ae21-8ffcfd3174e9
          type: derived
        - id: 929a690e-bef0-4204-a928-ef5e620d6fc
          type: obsolete
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
        )


def test_invalid_related_id_subfield():
    with pytest.raises(
        sigma_exceptions.SigmaRelatedError, match="Sigma related must have an id field"
    ):
        SigmaRule.from_yaml(
            """
    title: Test
    related:
        - uuid: 08fbc97d-0a2f-491c-ae21-8ffcfd3174e9
          type: derived
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
        )


def test_invalid_related_type_subfield():
    with pytest.raises(
        sigma_exceptions.SigmaRelatedError, match="Sigma related must have a type field"
    ):
        SigmaRule.from_yaml(
            """
    title: Test
    related:
        - id: 08fbc97d-0a2f-491c-ae21-8ffcfd3174e9
          types: derived
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
        )


def test_invalid_related_list():
    with pytest.raises(
        sigma_exceptions.SigmaRelatedError, match="Sigma rule related must be a list"
    ):
        SigmaRule.from_yaml(
            """
    title: Test
    related:
        id: 08fbc97d-0a2f-491c-ae21-8ffcfd3174e9
        types: derived
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
        )


def test_invalid_author():
    with pytest.raises(
        sigma_exceptions.SigmaAuthorError, match="Sigma rule author must be a string"
    ):
        rule = SigmaRule.from_yaml(
            """
        title: Test
        status: test
        author:
            - abc
            - def
        logsource:
            category: test
        detection:
            sel:
                field: value
            condition: sel
        """
        )


def test_missing_title():
    with pytest.raises(sigma_exceptions.SigmaTitleError, match="Sigma rule must have a title"):
        rule = SigmaRule.from_yaml(
            """
        status: test
        logsource:
            category: test
        detection:
            sel:
                field: value
            condition: sel
        """
        )


def test_invalid_title_type():
    with pytest.raises(sigma_exceptions.SigmaTitleError, match="Sigma rule title must be a string"):
        rule = SigmaRule.from_yaml(
            """
        title:
            - abc
        status: test
        logsource:
            category: test
        detection:
            sel:
                field: value
            condition: sel
        """
        )


def test_invalid_title_length():
    with pytest.raises(
        sigma_exceptions.SigmaTitleError,
        match="Sigma rule title length must not exceed 256 characters",
    ):
        title = "0123456789 " * 26
        rule = SigmaRule.from_yaml(
            f"""
        title: {title}
        status: test
        logsource:
            category: test
        detection:
            sel:
                field: value
            condition: sel
        """
        )


def test_sigma_rule_backreference(sigma_rule):
    sigma_rule_2 = SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {
                "category": "process_creation",
                "product": "windows",
            },
            "detection": {
                "selection": {
                    "CommandLine|endswith": "test.exe",
                },
                "condition": "selection",
            },
        }
    )
    sigma_rule.add_backreference(sigma_rule_2)
    assert sigma_rule.referenced_by(sigma_rule_2)
    assert sigma_rule < sigma_rule_2
    assert not sigma_rule_2.referenced_by(sigma_rule)
    assert not sigma_rule_2 < sigma_rule


def test_sigma_rule_conversion_result(sigma_rule):
    conversion_result = ["test1", "test2"]
    sigma_rule.set_conversion_result(conversion_result)
    assert sigma_rule.get_conversion_result() == conversion_result


def test_sigma_rule_conversion_result_no_result(sigma_rule):
    with pytest.raises(
        sigma_exceptions.SigmaConversionError, match="Conversion result not available.*Test"
    ):
        assert sigma_rule.get_conversion_result()


def test_sigma_rule_disable_output(sigma_rule):
    sigma_rule.disable_output()
    assert sigma_rule._output == False


def test_sigmarule_bad_license():
    with pytest.raises(
        sigma_exceptions.SigmaLicenseError,
        match="Sigma rule license must be a string.*test.yml",
    ):
        SigmaRule.from_dict(
            {"title": "test", "license": 1234},
            source=sigma_exceptions.SigmaRuleLocation("test.yml"),
        )


def test_sigmarule_bad_scope():
    with pytest.raises(
        sigma_exceptions.SigmaScopeError,
        match="Sigma rule scope must be a list.*test.yml",
    ):
        SigmaRule.from_dict(
            {"title": "test", "scope": "windows AD"},
            source=sigma_exceptions.SigmaRuleLocation("test.yml"),
        )


def test_sigmarule_timestamp_modifiers():
    rule = SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {
                "category": "process_creation",
                "product": "windows",
            },
            "detection": {
                "selection": {
                    "timestamp|minute": 1,
                    "timestamp|hour": 2,
                    "timestamp|day": 3,
                    "timestamp|week": 4,
                    "timestamp|month": 5,
                    "timestamp|year": 6,
                },
                "condition": "selection",
            },
        },
        source=sigma_exceptions.SigmaRuleLocation("test.yml"),
    )
    detection_items = rule.detection["selection"].detection_items
    assert detection_items[0].value[0] == SigmaTimestampPart(TimestampPart.MINUTE, 1)
    assert detection_items[1].value[0] == SigmaTimestampPart(TimestampPart.HOUR, 2)
    assert detection_items[2].value[0] == SigmaTimestampPart(TimestampPart.DAY, 3)
    assert detection_items[3].value[0] == SigmaTimestampPart(TimestampPart.WEEK, 4)
    assert detection_items[4].value[0] == SigmaTimestampPart(TimestampPart.MONTH, 5)
    assert detection_items[5].value[0] == SigmaTimestampPart(TimestampPart.YEAR, 6)
