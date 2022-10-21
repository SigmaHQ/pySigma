from uuid import UUID
import pytest
from sigma.exceptions import SigmaConfigurationError
from sigma.plugins import SigmaPlugins
from sigma.validation import SigmaValidator
from sigma.validators.condition import DanglingDetectionValidator
from sigma.validators.tags import ATTACKTagValidator, TLPv1TagValidator
from sigma.validators.values import NumberAsStringValidator
from tests.test_validators import rule_with_id, rule_without_id, rules_with_id_collision
from sigma.collection import SigmaCollection
from sigma.validators.metadata import IdentifierExistenceValidator, IdentifierUniquenessValidator, IdentifierExistenceIssue, IdentifierCollisionIssue

@pytest.fixture
def validators():
    return SigmaPlugins.autodiscover().validators

def test_sigmavalidator_validate_rules(rule_with_id, rule_without_id, rules_with_id_collision):
    rules = SigmaCollection([rule_with_id, rule_without_id, *rules_with_id_collision])
    validator = SigmaValidator({ IdentifierExistenceValidator, IdentifierUniquenessValidator })
    issues = validator.validate_rules(rules)
    assert issues == [
        IdentifierExistenceIssue([rule_without_id]),
        IdentifierCollisionIssue(rules_with_id_collision, UUID("32532a0b-e56c-47c9-bcbb-3d88bd670c37")),
    ]

def test_sigmavalidator_exclusions(rule_with_id, rule_without_id, rules_with_id_collision):
    rules = SigmaCollection([rule_with_id, rule_without_id, *rules_with_id_collision])
    exclusions = {
        UUID("32532a0b-e56c-47c9-bcbb-3d88bd670c37"): { IdentifierUniquenessValidator },
    }
    validator = SigmaValidator({ IdentifierExistenceValidator, IdentifierUniquenessValidator }, exclusions)
    issues = validator.validate_rules(rules)
    assert issues == [
        IdentifierExistenceIssue([rule_without_id]),
    ]

def test_sigmavalidator_from_dict(validators):
    validator = SigmaValidator.from_dict({
        "validators": [
            "all",
            "-tlptag",
            "-tlpv1_tag",
        ],
        "exclusions": {
            "c702c6c7-1393-40e5-93f8-91469f3445ad": "dangling_detection",
            "bf39335e-e666-4eaf-9416-47f1955b5fb3": [
                "attacktag",
                "number_as_string",
            ]
        }
    }, validators)
    assert DanglingDetectionValidator in (v.__class__ for v in validator.validators)
    assert TLPv1TagValidator not in (v.__class__ for v in validator.validators)
    assert len(validator.validators) >= 10
    assert validator.exclusions == {
        UUID("c702c6c7-1393-40e5-93f8-91469f3445ad"): { DanglingDetectionValidator },
        UUID("bf39335e-e666-4eaf-9416-47f1955b5fb3"): {
            ATTACKTagValidator,
            NumberAsStringValidator,
        }
    }

def test_sigmavalidator_from_yaml(validators):
    validator = SigmaValidator.from_yaml("""
    validators:
        - all
        - -tlptag
        - -tlpv1_tag
    exclusions:
        c702c6c7-1393-40e5-93f8-91469f3445ad: dangling_detection
        bf39335e-e666-4eaf-9416-47f1955b5fb3:
            - attacktag
            - number_as_string
    """, validators)
    assert DanglingDetectionValidator in (v.__class__ for v in validator.validators)
    assert TLPv1TagValidator not in (v.__class__ for v in validator.validators)
    assert len(validator.validators) >= 10
    assert validator.exclusions == {
        UUID("c702c6c7-1393-40e5-93f8-91469f3445ad"): { DanglingDetectionValidator },
        UUID("bf39335e-e666-4eaf-9416-47f1955b5fb3"): {
            ATTACKTagValidator,
            NumberAsStringValidator,
        }
    }

def test_sigmavalidator_fromdict_explicit_validator(validators):
    validator = SigmaValidator.from_dict({
        "validators": [
            "dangling_detection",
            "identifier_existence",
        ],
    }, validators)
    assert { v.__class__ for v in validator.validators } == { DanglingDetectionValidator, IdentifierExistenceValidator }

def test_sigmavalidator_fromdict_remove_nonexisting(validators):
    with pytest.raises(SigmaConfigurationError, match="Attempting to remove.*identifier_existence"):
        SigmaValidator.from_dict({
            "validators": [
                "dangling_detection",
                "-identifier_existence",
            ],
        }, validators)

def test_sigmavalidator_fromdict_unknown_validator_in_validators(validators):
    with pytest.raises(SigmaConfigurationError, match="Unknown validator 'non_existing'"):
        SigmaValidator.from_dict({
            "validators": [
                "non_existing",
            ],
        }, validators)

def test_sigmavalidator_fromdict_unknown_validator_in_exclusions(validators):
    with pytest.raises(SigmaConfigurationError, match="Unknown validator 'non_existing'"):
        SigmaValidator.from_dict({
            "validators": [
                "all",
            ],
            "exclusions": {
                "c702c6c7-1393-40e5-93f8-91469f3445ad": "non_existing",
            }
        }, validators)

def test_issue_string_rendering(rules_with_id_collision):
    assert str(IdentifierCollisionIssue(rules_with_id_collision, UUID("32532a0b-e56c-47c9-bcbb-3d88bd670c37"))) == \
        "issue=IdentifierCollisionIssue severity=high description=\"Rule identifier used by multiple rules\" rules=[32532a0b-e56c-47c9-bcbb-3d88bd670c37, 32532a0b-e56c-47c9-bcbb-3d88bd670c37] identifier=32532a0b-e56c-47c9-bcbb-3d88bd670c37"