import pytest
from wsgiref.validate import validator

from sigma.rule import SigmaRule


from sigma.validators.core.condition import (
    AllOfThemConditionIssue,
    AllOfThemConditionValidator,
    DanglingDetectionIssue,
    DanglingDetectionValidator,
    ThemConditionWithSingleDetectionIssue,
    ThemConditionWithSingleDetectionValidator,
)


def test_validator_dangling_detection():
    validator = DanglingDetectionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        referenced1:
            field1: val1
        referenced2:
            field2: val2
        referenced3:
            field3: val3
        unreferenced:
            field4: val4
        condition: (referenced1 or referenced2) and referenced3
    """
    )
    assert validator.validate(rule) == [DanglingDetectionIssue([rule], "unreferenced")]


def test_validator_dangling_detection_valid():
    validator = DanglingDetectionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        referenced1:
            field1: val1
        referenced2:
            field2: val2
        referenced3:
            field3: val3
        condition: (referenced1 or referenced2) and referenced3
    """
    )
    assert validator.validate(rule) == []


def test_validator_dangling_detection_valid_x_of_wildcard():
    validator = DanglingDetectionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        referenced1:
            field1: val1
        referenced2:
            field2: val2
        referenced3:
            field3: val3
        condition: 1 of referenced*
    """
    )
    assert validator.validate(rule) == []


def test_validator_dangling_detection_valid_x_of_them():
    validator = DanglingDetectionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        referenced1:
            field1: val1
        referenced2:
            field2: val2
        referenced3:
            field3: val3
        condition: 1 of them
    """
    )
    assert validator.validate(rule) == []


def test_validator_them_condition_with_single_detection():
    validator = ThemConditionWithSingleDetectionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection:
            field1: val1
        condition: 1 of them
    """
    )
    assert validator.validate(rule) == [ThemConditionWithSingleDetectionIssue([rule])]


def test_validator_them_condition_with_multiple_detection():
    validator = ThemConditionWithSingleDetectionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection1:
            field1: val1
        selection2:
            field2: val2
        condition: 1 of them
    """
    )
    assert validator.validate(rule) == []


def test_validator_all_of_them():
    validator = AllOfThemConditionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection1:
            field1: val1
        selection2:
            field2: val2
        condition: all of them
    """
    )
    assert validator.validate(rule) == [AllOfThemConditionIssue([rule])]
