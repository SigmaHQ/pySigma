from uuid import UUID

import pytest
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.validators.metadata import IdentifierCollisionIssue, IdentifierExistenceIssue, IdentifierExistenceValidator, IdentifierUniquenessValidator

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
    id: 32532a0b-e56c-47c9-bcbb-3d88bd670c37
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
    return [
        SigmaRule.from_yaml(f"""
        title: Test {i}
        id: 32532a0b-e56c-47c9-bcbb-3d88bd670c37
        status: test
        logsource:
            category: test
        detection:
            selection:
                field{i}: value{i}
            condition: selection
        """)
        for i in range(2)
    ]

def test_validator_identifier_existence(rule_without_id):
    validator = IdentifierExistenceValidator()
    assert validator.validate(rule_without_id) == [ IdentifierExistenceIssue([rule_without_id]) ] and \
        validator.finalize() == []

def test_validator_identifier_existence_valid(rule_with_id):
    validator = IdentifierExistenceValidator()
    assert validator.validate(rule_with_id) == [] and \
        validator.finalize() == []

def test_validator_identifier_uniqueness(rules_with_id_collision):
    validator = IdentifierUniquenessValidator()
    assert [
        issue
        for rule in rules_with_id_collision
        for issue in validator.validate(rule)
    ] == [] and \
        validator.finalize() == [ IdentifierCollisionIssue(rules_with_id_collision, UUID("32532a0b-e56c-47c9-bcbb-3d88bd670c37")) ]