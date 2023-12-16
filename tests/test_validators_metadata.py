from uuid import UUID
from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule
from sigma.types import SigmaString
from sigma.collection import SigmaCollection

from sigma.validators.core.metadata import (
    IdentifierExistenceValidator,
    IdentifierExistenceIssue,
    IdentifierUniquenessValidator,
    IdentifierCollisionIssue,
    TitleLengthSigmaHQIssue,
    TitleLengthSigmaHQValidator,
    DuplicateTitleIssue,
    DuplicateTitleValidator,
    DuplicateReferencesIssue,
    DuplicateReferencesValidator,
    StatusExistenceValidator,
    StatusExistenceIssue,
    StatusUnsupportedValidator,
    StatusUnsupportedIssue,
    DateExistenceValidator,
    DateExistenceIssue,
    DuplicateFilenameValidator,
    DuplicateFilenameIssue,
    FilenameSigmahqValidator,
    FilenameSigmahqIssue,
    FilenameLenghValidator,
    FilenameLenghIssue,
    CustomAttributesValidator,
    CustomAttributesIssue,
    DescriptionExistenceValidator,
    DescriptionExistenceIssue,
    DescriptionLengthValidator,
    DescriptionLengthIssue,
    LevelExistenceValidator,
    LevelExistenceIssue,
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
    validator = TitleLengthSigmaHQValidator()
    rule = SigmaRule.from_yaml(
        """
    title: ThisIsAVeryLongTitleThisIsAVeryLongTitleThisIsAVeryLongTitleThisIsAVeryLongTitleThisIsAVeryLongTitleThisIsAVery
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [TitleLengthSigmaHQIssue([rule])]


def test_validator_lengthy_title_valid():
    validator = TitleLengthSigmaHQValidator()
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


def test_validator_status_existence():
    validator = StatusExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [StatusExistenceIssue([rule])]


def test_validator_status_existence_valid():
    validator = StatusExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: stable
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_status_unsupported():
    validator = StatusUnsupportedValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: unsupported
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [StatusUnsupportedIssue([rule])]


def test_validator_status_unsupported_valid():
    validator = StatusUnsupportedValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: stable
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_date_existence():
    validator = DateExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [DateExistenceIssue([rule])]


def test_validator_date_existence_valid():
    validator = DateExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    date: 2023-12-11
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_duplicate_filename():
    validator = DuplicateFilenameValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/ruleset_duplicate"])
    rule1 = sigma_collection[0]
    rule2 = sigma_collection[1]
    assert validator.validate(rule1) == []
    assert validator.validate(rule2) == []
    assert validator.finalize() == [DuplicateFilenameIssue([rule1, rule2], "test_rule.yml")]


def test_validator_sigmahqfilename():
    validator = FilenameSigmahqValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_filename_errors"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == [FilenameSigmahqIssue([rule], "Name.yml")]


def test_validator_sigmahqfilename_valid():
    validator = FilenameSigmahqValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_valid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == []


def test_validator_filename_lengh():
    validator = FilenameLenghValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_filename_errors"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == [FilenameLenghIssue([rule], "Name.yml")]


def test_validator_filename_lengh_valid():
    validator = FilenameLenghValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_valid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == []


def test_validator_custom_attributes():
    validator = CustomAttributesValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    realted: 
        - id: abc
          type: abc
    """
    )
    assert validator.validate(rule) == [CustomAttributesIssue([rule], "realted")]


def test_validator_custom_attributes_valid():
    validator = CustomAttributesValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_description_existence():
    validator = DescriptionExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [DescriptionExistenceIssue([rule])]


def test_validator_description_existence_valid():
    validator = DescriptionExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: it is a simple description
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_description_length():
    validator = DescriptionLengthValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [DescriptionLengthIssue([rule])]


def test_validator_description_length_valid():
    validator = DescriptionLengthValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: it is a simple description
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_level_existence():
    validator = LevelExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [LevelExistenceIssue([rule])]


def test_validator_level_existence_valid():
    validator = LevelExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    level: medium
    """
    )
    assert validator.validate(rule) == []
