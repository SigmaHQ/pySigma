from uuid import UUID
from sigma.validation import SigmaValidator
from tests.test_validators import rule_with_id, rule_without_id, rules_with_id_collision
from sigma.collection import SigmaCollection
from sigma.validators.metadata import IdentifierExistenceValidator, IdentifierUniquenessValidator, IdentifierExistenceIssue, IdentifierCollisionIssue

def test_sigmavalidator_validate_rule_collection(rule_with_id, rule_without_id, rules_with_id_collision):
    rules = SigmaCollection([rule_with_id, rule_without_id, *rules_with_id_collision])
    validator = SigmaValidator([IdentifierExistenceValidator, IdentifierUniquenessValidator])
    issues = validator.validate_rule_collection(rules)
    assert len(issues) == 2 \
        and IdentifierExistenceIssue([rule_without_id]) in issues \
        and IdentifierCollisionIssue(rules_with_id_collision, UUID("32532a0b-e56c-47c9-bcbb-3d88bd670c37"))

def test_issue_string_rendering(rules_with_id_collision):
    assert str(IdentifierCollisionIssue(rules_with_id_collision, UUID("32532a0b-e56c-47c9-bcbb-3d88bd670c37"))) == \
        "issue=IdentifierCollisionIssue severity=high description=\"Rule identifier used by multiple rules\" rules=[32532a0b-e56c-47c9-bcbb-3d88bd670c37, 32532a0b-e56c-47c9-bcbb-3d88bd670c37] identifier=32532a0b-e56c-47c9-bcbb-3d88bd670c37"