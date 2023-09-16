from collections import defaultdict
from dataclasses import dataclass
from typing import ClassVar, Dict, List
from uuid import UUID
from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


@dataclass
class IdentifierExistenceIssue(SigmaValidationIssue):
    description = "Rule has no identifier (UUID)"
    severity = SigmaValidationIssueSeverity.MEDIUM


class IdentifierExistenceValidator(SigmaRuleValidator):
    """Checks if rule has identifier."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.id is None:
            return [IdentifierExistenceIssue([rule])]
        else:
            return []


@dataclass
class IdentifierCollisionIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule identifier used by multiple rules"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    identifier: UUID


class IdentifierUniquenessValidator(SigmaRuleValidator):
    """Check rule UUID uniqueness."""

    ids: Dict[UUID, List[SigmaRule]]

    def __init__(self):
        self.ids = defaultdict(list)

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.id is not None:
            self.ids[rule.id].append(rule)
        return []

    def finalize(self) -> List[SigmaValidationIssue]:
        return [
            IdentifierCollisionIssue(rules, id) for id, rules in self.ids.items() if len(rules) > 1
        ]


@dataclass
class TitleLengthIssue(SigmaValidationIssue):
    description = "Rule has a title longer than 100 characters"
    severity = SigmaValidationIssueSeverity.MEDIUM


class TitleLengthValidator(SigmaRuleValidator):
    """Checks if rule has a title length longer than 100."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if len(rule.title) > 100:
            return [TitleLengthIssue([rule])]
        else:
            return []


@dataclass
class DuplicateTitleIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule title used by multiple rules"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    title: str


class DuplicateTitleValidator(SigmaRuleValidator):
    """Check rule title uniqueness."""

    titles: Dict[str, List[SigmaRule]]

    def __init__(self):
        self.titles = defaultdict(list)

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.title is not None:
            self.titles[rule.title].append(rule)
        return []

    def finalize(self) -> List[SigmaValidationIssue]:
        return [
            DuplicateTitleIssue(rules, title)
            for title, rules in self.titles.items()
            if len(rules) > 1
        ]
