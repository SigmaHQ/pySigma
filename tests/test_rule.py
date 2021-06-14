import pytest
from datetime import date
from uuid import UUID
from sigma.rule import SigmaRuleTag, SigmaLogSource, SigmaDetectionItem, SigmaDetection, SigmaDetections, SigmaStatus, SigmaLevel, SigmaRule
from sigma.types import SigmaString, SigmaNumber, SigmaNull, SigmaRegularExpression
from sigma.modifiers import SigmaBase64Modifier, SigmaBase64OffsetModifier, SigmaContainsModifier, SigmaRegularExpressionModifier, SigmaAllModifier
from sigma.conditions import SigmaCondition, ConditionAND, ConditionOR
import sigma.exceptions as sigma_exceptions

### SigmaRuleTag tests ###
def test_sigmaruletag_fromstr():
    assert SigmaRuleTag.from_str("namespace.name") == SigmaRuleTag("namespace", "name")

def test_sigmaruletag_fromstr_nodot():
    with pytest.raises(ValueError):
        SigmaRuleTag.from_str("tag")

def test_sigmaruletag_fromstr_3dots():
    assert SigmaRuleTag.from_str("namespace.subnamespace.tag") == SigmaRuleTag("namespace", "subnamespace.tag")

### SigmaLogSource tests ###

def test_sigmalogsource_fromdict():
    logsource = SigmaLogSource.from_dict({
        "category": "category-id",
        "product": "product-id",
        "service": "service-id",
        })
    assert logsource == SigmaLogSource("category-id", "product-id", "service-id")

def test_sigmalogsource_fromdict_no_category():
    logsource = SigmaLogSource.from_dict({
        "product": "product-id",
        "service": "service-id",
        })
    assert logsource == SigmaLogSource(None, "product-id", "service-id")

def test_sigmalogsource_fromdict_no_product():
    logsource = SigmaLogSource.from_dict({
        "category": "category-id",
        "service": "service-id",
        })
    assert logsource == SigmaLogSource("category-id", None, "service-id")

def test_sigmalogsource_fromdict_no_service():
    logsource = SigmaLogSource.from_dict({
        "category": "category-id",
        "product": "product-id",
        })
    assert logsource == SigmaLogSource("category-id", "product-id", None)

def test_sigmalogsource_empty():
    with pytest.raises(sigma_exceptions.SigmaLogsourceError):
        SigmaLogSource(None, None, None)

def test_sigmalogsource_eq():
    assert SigmaLogSource("category", "product", "service") == SigmaLogSource("category", "product", "service")

def test_sigmalogsource_neq():
    assert SigmaLogSource("category", "product", None) != SigmaLogSource("category", "product", "service")

def test_sigmalogsource_in_eq():
    assert SigmaLogSource("category", "product", "service") in SigmaLogSource("category", "product", "service")

def test_sigmalogsource_in():
    assert SigmaLogSource("category", "product", "service") in SigmaLogSource("category", "product", None)

def test_sigmalogsource_not_in():
    assert SigmaLogSource("category", None, "service") not in SigmaLogSource(None, "product", "service")

def test_sigmalogsource_in_invalid():
    with pytest.raises(TypeError):
        assert 123 in SigmaLogSource("category", "product", "service")

# SigmaDetectionItem
def test_sigmadetectionitem_keyword_single():
    """Single keyword detection."""
    assert SigmaDetectionItem.from_mapping(None, "value") == SigmaDetectionItem(None, [], [SigmaString("value")])

def test_sigmadetectionitem_keyword_list():
    """Keyword list detection."""
    assert SigmaDetectionItem.from_mapping(None, ["string", 123]) == SigmaDetectionItem(None, [], [SigmaString("string"), SigmaNumber(123)])

def test_sigmadetectionitem_keyword_modifiers():
    """Keyword detection with modifier chain."""
    assert SigmaDetectionItem.from_mapping("|base64|contains", "foobar") == SigmaDetectionItem(None, [SigmaBase64Modifier, SigmaContainsModifier], [SigmaString("*Zm9vYmFy*")])

def test_sigmadetectionitem_unknown_modifier():
    """Keyword detection with modifier chain."""
    with pytest.raises(sigma_exceptions.SigmaModifierError):
        SigmaDetectionItem.from_mapping("|foobar", "foobar")

def test_sigmadetectionitem_key_value_single_string():
    """Key-value detection with one value."""
    assert SigmaDetectionItem.from_mapping("key", "value") == SigmaDetectionItem("key", [], [SigmaString("value")])

def test_sigmadetectionitem_key_value_single_number():
    """Key-value detection with one value."""
    assert SigmaDetectionItem.from_mapping("key", 123) == SigmaDetectionItem("key", [], [SigmaNumber(123)])

def test_sigmadetectionitem_key_value_none():
    """Key-value detection with none value."""
    assert SigmaDetectionItem.from_mapping("key", None) == SigmaDetectionItem("key", [], [SigmaNull()])

def test_sigmadetectionitem_key_value_single_regexp():
    """Key-value detection with one value."""
    assert SigmaDetectionItem.from_mapping("key|re", "reg.*exp") == SigmaDetectionItem("key", [SigmaRegularExpressionModifier], [SigmaRegularExpression("reg.*exp")])

def test_sigmadetectionitem_key_value_list():
    """Key-value detection with value list."""
    assert SigmaDetectionItem.from_mapping("key", ["string", 123]) == SigmaDetectionItem("key", [], [SigmaString("string"), SigmaNumber(123)])

def test_sigmadetectionitem_key_value_modifiers():
    """Key-value detection with modifier chain with first modifier expanding value to multiple values"""
    assert SigmaDetectionItem.from_mapping("key|base64offset|contains|all", "foobar") == SigmaDetectionItem(
        "key",
        [SigmaBase64OffsetModifier, SigmaContainsModifier, SigmaAllModifier],
        [
            SigmaString("*Zm9vYmFy*"),
            SigmaString("*Zvb2Jhc*"),
            SigmaString("*mb29iYX*"),
        ],
        ConditionAND
        )

def test_sigmadetectionitem_key_value_modifiers_invalid_re():
    """Invalid regular expression modifier chain."""
    with pytest.raises(sigma_exceptions.SigmaValueError):
        SigmaDetectionItem.from_mapping("key|base64|re", "value")

def test_sigmadetectionitem_fromvalue():
    SigmaDetectionItem.from_value("test") == SigmaDetectionItem(None, [], [SigmaString("test")])

### SigmaDetection tests ###

def test_sigmadetection_items():
    assert SigmaDetection([
        SigmaDetectionItem("key_1", [], [ SigmaString("value_1") ]),
        SigmaDetectionItem("key_2", [], [ SigmaString("value_2") ]),
    ]).item_linking == ConditionAND

def test_sigmadetection_detections():
    assert SigmaDetection([
        SigmaDetection([ SigmaDetectionItem("key_1", [], [ SigmaString("value_1") ])]),
        SigmaDetection([ SigmaDetectionItem("key_2", [], [ SigmaString("value_2") ])]),
    ]).item_linking == ConditionOR

def test_sigmadetection_mixed():
    assert SigmaDetection([
        SigmaDetectionItem("key_1", [], [ SigmaString("value_1") ]),
        SigmaDetection([ SigmaDetectionItem("key_2", [], [ SigmaString("value_2") ])]),
    ]).item_linking == ConditionAND

### SigmaDetections tests ###

def test_sigmadetections_fromdict():
    detections = {
        "keyword_list": [
            "keyword_1",
            "keyword_2",
            3,
            ],
        "test_list_of_maps": [
                {
                    "key1": "value1"
                },
                {
                    "key2": 2
                },
            ],
        "test_map": {
                "key1": "value1",
                "key2": 2,
            },
        "single_keyword": "keyword",
        }
    condition = "1 of them"
    sigma_detections = SigmaDetections.from_dict({
        **detections,
        "condition": condition,
        })
    assert sigma_detections == SigmaDetections(
            detections = {
                "keyword_list": SigmaDetection([
                    SigmaDetectionItem(None, [], [ SigmaString("keyword_1"), SigmaString("keyword_2"), SigmaNumber(3) ]),
                ]),
                "test_list_of_maps": SigmaDetection([
                    SigmaDetection([SigmaDetectionItem("key1", [], [ SigmaString("value1") ])]),
                    SigmaDetection([SigmaDetectionItem("key2", [], [ SigmaNumber(2) ])]),
                ]),
                "test_map": SigmaDetection([
                    SigmaDetectionItem("key1", [], [ SigmaString("value1") ]),
                    SigmaDetectionItem("key2", [], [ SigmaNumber(2) ]),
                ]),
                "single_keyword": SigmaDetection([
                    SigmaDetectionItem(None, [], [ SigmaString("keyword") ])
                ]),
            },
            condition = [ condition ],
            )
    assert isinstance(sigma_detections.parsed_condition[0], SigmaCondition)

def test_sigmadetections_index():
    assert SigmaDetections(
        detections = {
            "foo": SigmaDetection([
                    SigmaDetectionItem(None, [], [ SigmaString("keyword_1") ]),
            ]),
            "bar": SigmaDetection([
                    SigmaDetectionItem(None, [], [ SigmaString("keyword_2") ]),
            ]),
        },
        condition = [ "1 of them" ]
    )["foo"] == SigmaDetection([
            SigmaDetectionItem(None, [], [ SigmaString("keyword_1") ]),
    ])

def test_sigmadetections_fromdict_no_detections():
    with pytest.raises(sigma_exceptions.SigmaDetectionError):
        SigmaDetections.from_dict({ "condition": [ "selection" ] })

def test_sigmadetections_fromdict_no_condition():
    with pytest.raises(sigma_exceptions.SigmaConditionError):
        SigmaDetections.from_dict({ "selection": { "key": "value" }})

### SigmaRule tests ###

def test_sigmarule_bad_uuid():
    with pytest.raises(sigma_exceptions.SigmaIdentifierError):
        SigmaRule.from_dict({ "id": "no-uuid" })

def test_sigmarule_bad_level():
    with pytest.raises(sigma_exceptions.SigmaLevelError):
        SigmaRule.from_dict({ "level": "bad" })

def test_sigmarule_bad_status():
    with pytest.raises(sigma_exceptions.SigmaStatusError):
        SigmaRule.from_dict({ "status": "bad" })

def test_sigmarule_bad_date():
    with pytest.raises(sigma_exceptions.SigmaDateError):
        SigmaRule.from_dict({ "date": "bad" })

def test_sigmarule_no_logsource():
    with pytest.raises(sigma_exceptions.SigmaLogsourceError):
        SigmaRule.from_dict({})

def test_sigmarule_no_detections():
    with pytest.raises(sigma_exceptions.SigmaDetectionError):
        SigmaRule.from_dict({ "logsource": { "category": "category-id" } })

def test_sigmarule_fromyaml():
    sigmarule_from_yaml = SigmaRule.from_yaml("""
    title: Test
    id: 9a6cafa7-1481-4e64-89a1-1f69ed08618c
    status: test
    description: This is a test
    references:
        - ref1
        - ref2
    tags:
        - attack.execution
        - attack.t1059
    author: Thomas Patzke
    date: 2020/07/12
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
    """)
    sigmarule = SigmaRule(
        title = "Test",
        id = UUID("9a6cafa7-1481-4e64-89a1-1f69ed08618c"),
        status = SigmaStatus.TEST,
        description = "This is a test",
        references = [
            "ref1",
            "ref2",
        ],
        tags = [
            SigmaRuleTag.from_str("attack.execution"),
            SigmaRuleTag.from_str("attack.t1059"),
        ],
        author = "Thomas Patzke",
        date = date(2020, 7, 12),
        logsource = SigmaLogSource(
            category = "process_creation",
            product = "windows",
            service = None,
        ),
        detection = SigmaDetections(
            detections = {
                "selection_1": SigmaDetection([
                        SigmaDetectionItem("CommandLine", [SigmaContainsModifier], [ SigmaString("*test.exe*") ])
                    ]),
                "selection_2": SigmaDetection([
                        SigmaDetection([SigmaDetectionItem("CommandLine", [SigmaContainsModifier], [ "*test.exe*" ])]),
                        SigmaDetection([SigmaDetectionItem("CommandLine", [SigmaContainsModifier], [ "*cmd.exe*" ])]),
                    ]),
                "selection_3": SigmaDetection([
                    SigmaDetectionItem(None, [], [ "keyword_1", "keyword_2" ]),
                ]),
            },
            condition = [ "1 of them" ],
        ),
        fields = [
            "User",
            "CommandLine",
        ],
        falsepositives = [
            "Everything",
        ],
        level = SigmaLevel.LOW,
    )
    assert sigmarule_from_yaml == sigmarule


def test_empty_detection():
    with pytest.raises(sigma_exceptions.SigmaDetectionError):
        SigmaDetection([])