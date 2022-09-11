from collections import defaultdict
from dataclasses import dataclass
from typing import ClassVar, Dict, List
from uuid import UUID
from sigma.rule import SigmaRule
from sigma.validators.base import SigmaRuleValidator, SigmaValidationIssue, SigmaValidationIssueSeverity

@dataclass
class IdentifierExistenceIssue(SigmaValidationIssue):
    description = "Rule has no identifier (UUID)"
    severity = SigmaValidationIssueSeverity.MEDIUM

class IdentifierExistenceValidator(SigmaRuleValidator):
    """Checks if rule has identifier."""
    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.id is None:
            return [ IdentifierExistenceIssue([rule]) ]
        else:
            return []

@dataclass
class IdentifierCollisionIssue(SigmaValidationIssue):
    description : ClassVar[str] = "Rule identifier used by multiple rules"
    severity : ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    identifier : UUID

class IdentifierUniquenessValidator(SigmaRuleValidator):
    """Collect all rule identifiers and output rules with same identifier on finalization."""
    ids : Dict[UUID, List[SigmaRule]]

    def __init__(self):
        self.ids = defaultdict(list)

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.id is not None:
            self.ids[rule.id].append(rule)
        return []

    def finalize(self) -> List[SigmaValidationIssue]:
        return [
            IdentifierCollisionIssue(rules, id)
            for id, rules in self.ids.items()
            if len(rules) > 1
        ]