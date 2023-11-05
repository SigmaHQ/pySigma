from uuid import UUID
from wsgiref.validate import validator

import pytest
from sigma.exceptions import SigmaValueError
from sigma.rule import SigmaRule
from sigma.types import SigmaString

from sigma.validators.core.metadata import (
    IdentifierExistenceValidator,
    IdentifierExistenceIssue,
    IdentifierUniquenessValidator,
    IdentifierCollisionIssue,
    TitleLengthIssue,
    TitleLengthValidator,
    DuplicateTitleIssue,
    DuplicateTitleValidator,
    DuplicateReferencesIssue,
    DuplicateReferencesValidator,
    InvalidRelatedTypeValidator,
    InvalidRelatedTypeIssue,
    InvalidRelatedIdValidator,
    InvalidRelatedIdIssue,
    InvalidRelatedSubfieldValidator,
    InvalidRelatedSubfieldIssue,
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


def test_validator_identifier_existence(rule_without_id):
    validator = IdentifierExistenceValidator()
    assert (
        validator.validate(rule_without_id) == [IdentifierExistenceIssue([rule_without_id])]
        and validator.finalize() == []
    )


def test_validator_identifier_existence_valid(rule_with_id):
    validator = IdentifierExistenceValidator()
    assert validator.validate(rule_with_id) == [] and validator.finalize() == []


def test_validator_identifier_uniqueness(rules_with_id_collision):
    validator = IdentifierUniquenessValidator()
    assert [
        issue for rule in rules_with_id_collision for issue in validator.validate(rule)
    ] == [] and validator.finalize() == [
        IdentifierCollisionIssue(
            rules_with_id_collision, UUID("32532a0b-e56c-47c9-bcbb-3d88bd670c37")
        )
    ]


def test_validator_lengthy_title():
    validator = TitleLengthValidator()
    rule = SigmaRule.from_yaml(
        """
    title: ThisIsAVeryLongTitleThisIsAVeryLongTitleThisIsAVeryLongTitleThisIsAVeryLongTitleThisIsAVeryLongTitleT
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [TitleLengthIssue([rule])]


def test_validator_lengthy_title_valid():
    validator = TitleLengthValidator()
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
    assert validator.validate(rule) == []


def test_validator_duplicate_title():
    validator = DuplicateTitleValidator()
    rule1 = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )

    rule2 = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule1) == []
    assert validator.validate(rule2) == []
    assert validator.finalize() == [DuplicateTitleIssue([rule1, rule2], "Test")]


def test_validator_duplicate_title_valid():
    validator = DuplicateTitleValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_duplicate_references():
    validator = DuplicateReferencesValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    references:
        - ref_a
        - ref_b
        - ref_a
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [DuplicateReferencesIssue([rule], "ref_a")]


def test_validator_duplicate_references_valid():
    validator = DuplicateReferencesValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    references:
        - ref_a
        - ref_b
        - ref_c
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_invalid_related_type():
    validator = InvalidRelatedTypeValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    related:
        - id: 08fbc97d-0a2f-491c-ae21-8ffcfd3174e9
          type: derived
        - id: 929a690e-bef0-4204-a928-ef5e620d6fcc
          type: obsoletes
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
    assert validator.validate(rule) == [InvalidRelatedTypeIssue([rule], "same")]


def test_validator_invalid_related_id():
    validator = InvalidRelatedIdValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    related:
        - id: 08fbc97d-0a2f-491c-ae21-8ffcfd3174e9
          type: derived
        - id: 929a690e-bef0-4204-a928-ef5e620d6fc
          type: obsoletes
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        InvalidRelatedIdIssue([rule], "929a690e-bef0-4204-a928-ef5e620d6fc")
    ]


def test_validator_invalid_related_subfield():
    validator = InvalidRelatedSubfieldValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == [InvalidRelatedSubfieldIssue([rule], "uuid")]
