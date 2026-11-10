import pytest
from sigma.rule import SigmaDetectionItem, SigmaLogSource, SigmaRule
from sigma.types import SigmaString
from sigma.validators.core.logsources import (
    SpecificInsteadOfGenericLogsourceValidator,
    SpecificInsteadOfGenericLogsourceIssue,
)
from sigma.validators.core.values import (
    ControlCharacterIssue,
    ControlCharacterValidator,
    DoubleWildcardIssue,
    DoubleWildcardValidator,
    NumberAsStringIssue,
    NumberAsStringValidator,
    WildcardInsteadOfEndswithIssue,
    WildcardInsteadOfStartswithIssue,
    WildcardsInsteadOfContainsModifierIssue,
    WildcardsInsteadOfModifiersValidator,
    EscapedWildcardIssue,
    EscapedWildcardValidator,
    TautologicalValueIssue,
    TautologicalValueValidator,
)
from .test_correlations import correlation_rule


@pytest.fixture
def rule_without_id():
    return SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection:
            field: value
        condition: selection
    """)


@pytest.fixture
def rule_with_id():
    return SigmaRule.from_yaml("""
    title: Test
    id: 19855ce4-00b3-4d07-8e57-f6c6955ce4e7
    status: test
    logsource:
        category: test
    detection:
        selection:
            field: value
        condition: selection
    """)


@pytest.fixture
def rules_with_id_collision():
    return [SigmaRule.from_yaml(f"""
        title: Test {i}
        id: 32532a0b-e56c-47c9-bcbb-3d88bd670c37
        status: test
        logsource:
            category: test
        detection:
            selection:
                field{i}: value{i}
            condition: selection
        """) for i in range(2)]


def test_validator_double_wildcard():
    validator = DoubleWildcardValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field1: te**st
            field2: 123
        condition: sel
    """)
    assert validator.validate(rule) == [DoubleWildcardIssue([rule], SigmaString("te**st"))]


def test_validator_double_wildcard_valid():
    validator = DoubleWildcardValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field1: t*es*t
            field2: 123
        condition: sel
    """)
    assert validator.validate(rule) == []


def test_validator_double_wildcard_correlation_rule(correlation_rule):
    validator = DoubleWildcardValidator()
    assert validator.validate(correlation_rule) == []


def test_validator_number_as_string():
    validator = NumberAsStringValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field1: 123
            field2: "234"
        condition: sel
    """)
    assert validator.validate(rule) == [NumberAsStringIssue([rule], SigmaString("234"))]


def test_validator_number_as_string_valid():
    validator = NumberAsStringValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field1: a
        condition: sel
    """)
    assert validator.validate(rule) == []


def test_validator_number_as_string_correlation_rule(correlation_rule):
    validator = NumberAsStringValidator()
    assert validator.validate(correlation_rule) == []


def test_validator_control_characters():
    validator = ControlCharacterValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field1: "\\temp"
            field2: "\\\\test"
        condition: sel
    """)
    assert validator.validate(rule) == [ControlCharacterIssue([rule], SigmaString("\temp"))]


def test_validator_control_characters_c0_range_boundary():
    # The C0 control range is 0x00-0x1F inclusive, so 0x1F (Unit Separator) must be
    # flagged while 0x20 (space, the first printable character) must not.
    validator = ControlCharacterValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field1: placeholder
        condition: sel
    """)
    detection_item = rule.detection.detections["sel"].detection_items[0]

    # 0x1F is a control character and must be reported.
    us_value = SigmaString("value\x1fend")
    detection_item.value = [us_value]
    assert validator.validate(rule) == [ControlCharacterIssue([rule], us_value)]

    # 0x20 (space) is printable and must not be reported.
    detection_item.value = [SigmaString("value end")]
    assert validator.validate(rule) == []


def test_validator_control_characters_correlation_rule(correlation_rule):
    validator = ControlCharacterValidator()
    assert validator.validate(correlation_rule) == []


def test_validator_wildcards_instead_of_contains():
    validator = WildcardsInsteadOfModifiersValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field:
              - "*val1*"
              - "*val2*"
              - "*val3*"
        condition: sel
    """)
    assert validator.validate(rule) == [
        WildcardsInsteadOfContainsModifierIssue(
            [rule],
            SigmaDetectionItem(
                "field",
                [],
                [
                    SigmaString("*val1*"),
                    SigmaString("*val2*"),
                    SigmaString("*val3*"),
                ],
            ),
        )
    ]


def test_validator_wildcard_instead_of_endswith():
    validator = WildcardsInsteadOfModifiersValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field:
              - "*val1"
              - "*val2"
              - "*val3"
        condition: sel
    """)
    assert validator.validate(rule) == [
        WildcardInsteadOfEndswithIssue(
            [rule],
            SigmaDetectionItem(
                "field",
                [],
                [
                    SigmaString("*val1"),
                    SigmaString("*val2"),
                    SigmaString("*val3"),
                ],
            ),
        )
    ]


def test_validator_wildcard_instead_of_startswith():
    validator = WildcardsInsteadOfModifiersValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field:
              - "val1*"
              - "val2*"
              - "val3*"
        condition: sel
    """)
    assert validator.validate(rule) == [
        WildcardInsteadOfStartswithIssue(
            [rule],
            SigmaDetectionItem(
                "field",
                [],
                [
                    SigmaString("val1*"),
                    SigmaString("val2*"),
                    SigmaString("val3*"),
                ],
            ),
        )
    ]


def test_validator_wildcards_instead_of_modifiers_inconsistent():
    validator = WildcardsInsteadOfModifiersValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field:
              - "*val1*"
              - "*val2"
              - "val3*"
        condition: sel
    """)
    assert validator.validate(rule) == []


def test_validator_wildcards_instead_of_modifiers_none():
    validator = WildcardsInsteadOfModifiersValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: null
              - "val1"
              - null
        condition: sel
    """)
    assert validator.validate(rule) == []


def test_validator_wildcards_instead_of_modifiers_correlation_rule(correlation_rule):
    validator = WildcardsInsteadOfModifiersValidator()
    assert validator.validate(correlation_rule) == []


def test_validator_sysmon_insteadof_generic_logsource():
    validator = SpecificInsteadOfGenericLogsourceValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        product: windows
        service: sysmon
    detection:
        sel:
            EventID:
               - 1
               - 999
               - 7
        condition: sel
    """)
    logsource_sysmon = SigmaLogSource(None, "windows", "sysmon")
    assert validator.validate(rule) == [
        SpecificInsteadOfGenericLogsourceIssue(
            rules=[rule],
            logsource=logsource_sysmon,
            event_id=1,
            generic_logsource=SigmaLogSource("process_creation"),
        ),
        SpecificInsteadOfGenericLogsourceIssue(
            rules=[rule],
            logsource=logsource_sysmon,
            event_id=7,
            generic_logsource=SigmaLogSource("image_load"),
        ),
    ]


def test_validator_sysmon_insteadof_generic_logsource_sysmon_valid():
    validator = SpecificInsteadOfGenericLogsourceValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        product: windows
        service: sysmon
    detection:
        sel:
            field: 999
        condition: sel
    """)
    assert validator.validate(rule) == []


def test_validator_sysmon_insteadof_generic_logsource_other_valid():
    validator = SpecificInsteadOfGenericLogsourceValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        product: windows
        service: generic
    detection:
        sel:
            field: 999
        condition: sel
    """)
    assert validator.validate(rule) == []


def test_validator_specific_insteadof_generic_correlation_rule(correlation_rule):
    validator = SpecificInsteadOfGenericLogsourceValidator()
    assert validator.validate(correlation_rule) == []


def test_validator_escaped_wildcard():
    validator = EscapedWildcardValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """)
    assert validator.validate(rule) == [
        EscapedWildcardIssue([rule], SigmaString(r"path\*something"))
    ]


def test_validator_escaped_wildcard_valid():
    validator = EscapedWildcardValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\\\*something
        condition: sel
    """)
    assert validator.validate(rule) == []


def test_validator_escaped_wildcard_correlation_rule(correlation_rule):
    validator = EscapedWildcardValidator()
    assert validator.validate(correlation_rule) == []


def test_validator_tautological_value_contains_collapsed_backslash():
    validator = TautologicalValueValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field|contains:
                - '\\Users\\'
                - '\\\\'
        condition: sel
    """)
    detection_item = rule.detection.detections["sel"].detection_items[0]
    assert validator.validate(rule) == [TautologicalValueIssue([rule], detection_item)]


def test_validator_tautological_value_contains_empty():
    validator = TautologicalValueValidator()
    rule = SigmaRule.from_yaml("""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field|contains: ''
        condition: sel
    """)
    detection_item = rule.detection.detections["sel"].detection_items[0]
    assert validator.validate(rule) == [TautologicalValueIssue([rule], detection_item)]


@pytest.mark.parametrize(
    "detection",
    [
        "field|contains: '\\\\'",
        "field|startswith: '\\\\'",
        "field|endswith: '\\\\'",
        "field|startswith: '/'",
        "field|endswith: '/'",
    ],
)
def test_validator_tautological_value_single_separator(detection):
    validator = TautologicalValueValidator()
    rule = SigmaRule.from_yaml(f"""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            {detection}
        condition: sel
    """)
    detection_item = rule.detection.detections["sel"].detection_items[0]
    assert validator.validate(rule) == [TautologicalValueIssue([rule], detection_item)]


@pytest.mark.parametrize(
    "detection",
    [
        "field|contains: '\\\\Users\\\\'",
        "field|contains: '\\\\\\\\server\\\\share'",
        "field|contains: '*\\\\'",
        "field|startswith: 'C:\\\\'",
        "field|endswith: '.exe'",
        "field: '\\\\'",
        "field|all|contains:\n                - '\\\\'\n                - 'foo'",
    ],
)
def test_validator_tautological_value_valid(detection):
    validator = TautologicalValueValidator()
    rule = SigmaRule.from_yaml(f"""
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            {detection}
        condition: sel
    """)
    assert validator.validate(rule) == []


def test_validator_tautological_value_correlation_rule(correlation_rule):
    validator = TautologicalValueValidator()
    assert validator.validate(correlation_rule) == []
