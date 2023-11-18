from uuid import UUID
from wsgiref.validate import validator

import pytest
from sigma.exceptions import SigmaValueError

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
)


@pytest.fixture
def rule_without_id():
    return SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection:
            field: value
        condition: selection
    """
    )


@pytest.fixture
def rule_with_id():
    return SigmaRule.from_yaml(
        """
    title: Test
    id: 19855ce4-00b3-4d07-8e57-f6c6955ce4e7
    status: test
    logsource:
        category: test
    detection:
        selection:
            field: value
        condition: selection
    """
    )


@pytest.fixture
def rules_with_id_collision():
    return [
        SigmaRule.from_yaml(
            f"""
        title: Test {i}
        id: 32532a0b-e56c-47c9-bcbb-3d88bd670c37
        status: test
        logsource:
            category: test
        detection:
            selection:
                field{i}: value{i}
            condition: selection
        """
        )
        for i in range(2)
    ]


def test_validator_double_wildcard():
    validator = DoubleWildcardValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field1: te**st
            field2: 123
        condition: sel
    """
    )
    assert validator.validate(rule) == [DoubleWildcardIssue([rule], SigmaString("te**st"))]


def test_validator_double_wildcard_valid():
    validator = DoubleWildcardValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field1: t*es*t
            field2: 123
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_number_as_string():
    validator = NumberAsStringValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field1: 123
            field2: "234"
        condition: sel
    """
    )
    assert validator.validate(rule) == [NumberAsStringIssue([rule], SigmaString("234"))]


def test_validator_control_characters():
    validator = ControlCharacterValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field1: "\\temp"
            field2: "\\\\test"
        condition: sel
    """
    )
    assert validator.validate(rule) == [ControlCharacterIssue([rule], SigmaString("\temp"))]


def test_validator_wildcards_instead_of_contains():
    validator = WildcardsInsteadOfModifiersValidator()
    rule = SigmaRule.from_yaml(
        """
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
    """
    )
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
    rule = SigmaRule.from_yaml(
        """
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
    """
    )
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
    rule = SigmaRule.from_yaml(
        """
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
    """
    )
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
    rule = SigmaRule.from_yaml(
        """
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
    """
    )
    assert validator.validate(rule) == []


def test_validator_sysmon_insteadof_generic_logsource():
    validator = SpecificInsteadOfGenericLogsourceValidator()
    rule = SigmaRule.from_yaml(
        """
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
    """
    )
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


def test_validator_escaped_wildcard():
    validator = EscapedWildcardValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        EscapedWildcardIssue([rule], SigmaString("path\*something"))
    ]


def test_validator_escaped_wildcard_valid():
    validator = EscapedWildcardValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []
