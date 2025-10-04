from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar
from uuid import UUID

from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

if TYPE_CHECKING:
    from sigma.correlations import SigmaCorrelationRule
    from sigma.rule import SigmaRule


def is_uuid_v4(val: str) -> bool:
    try:
        id = UUID(str(val))
        if id.version == 4:
            return True
        else:
            return False
    except ValueError:
        return False


@dataclass
class IdentifierExistenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has no identifier (UUID)"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class IdentifierExistenceValidator(SigmaRuleValidator):
    """Checks if rule has identifier."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> list[SigmaValidationIssue]:
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

    ids: dict[UUID, list[SigmaRule | SigmaCorrelationRule]]

    def __init__(self) -> None:
        self.ids = defaultdict(list)

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> list[SigmaValidationIssue]:
        if rule.id is not None:
            self.ids[rule.id].append(rule)
        return []

    def finalize(self) -> list[SigmaValidationIssue]:
        return [
            IdentifierCollisionIssue(rules, id) for id, rules in self.ids.items() if len(rules) > 1
        ]


@dataclass
class DuplicateTitleIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule title used by multiple rules"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    title: str


class DuplicateTitleValidator(SigmaRuleValidator):
    """Check rule title uniqueness."""

    titles: dict[str, list[SigmaRule | SigmaCorrelationRule]]

    def __init__(self) -> None:
        self.titles = defaultdict(list)

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> list[SigmaValidationIssue]:
        if rule.title is not None:
            self.titles[rule.title].append(rule)
        return []

    def finalize(self) -> list[SigmaValidationIssue]:
        return [
            DuplicateTitleIssue(rules, title)
            for title, rules in self.titles.items()
            if len(rules) > 1
        ]


@dataclass
class DuplicateReferencesIssue(SigmaValidationIssue):
    description: ClassVar[str] = "The same references appears multiple times"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    reference: str


class DuplicateReferencesValidator(SigmaRuleValidator):
    """Validate rule References uniqueness."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> list[SigmaValidationIssue]:
        references = Counter(rule.references)
        return [
            DuplicateReferencesIssue([rule], reference)
            for reference, count in references.items()
            if count > 1
        ]


@dataclass
class DuplicateFilenameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule filename used by multiple rules"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    filename: str


class DuplicateFilenameValidator(SigmaRuleValidator):
    """Check rule filename uniqueness."""

    filenames_to_rules: dict[str, list[SigmaRule | SigmaCorrelationRule]]
    filenames_to_paths: dict[str, set[str]]

    def __init__(self) -> None:
        self.filenames_to_rules = defaultdict(list)
        self.filenames_to_paths = defaultdict(set)

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> list[SigmaValidationIssue]:
        if rule.source is not None:
            self.filenames_to_rules[rule.source.path.name].append(rule)
            self.filenames_to_paths[rule.source.path.name].add(str(rule.source.path))
        return []

    def finalize(self) -> list[SigmaValidationIssue]:
        return [
            DuplicateFilenameIssue(self.filenames_to_rules[filename], filename)
            for filename, paths in self.filenames_to_paths.items()
            if len(paths) > 1
        ]


@dataclass
class FilenameLengthIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule filename is too short or long"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    filename: str


@dataclass(frozen=True)
class FilenameLengthValidator(SigmaRuleValidator):
    """Check rule filename length"""

    min_size: int = 10
    max_size: int = 90

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> list[SigmaValidationIssue]:
        if rule.source is not None:
            filename = rule.source.path.name
            if len(filename) < self.min_size or len(filename) > self.max_size:
                return [FilenameLengthIssue([rule], filename)]
        return []


@dataclass
class CustomAttributesIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule use optional field name similar to legit"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    fieldname: str


class CustomAttributesValidator(SigmaRuleValidator):
    """Check if field name is similar to legit one"""

    known_custom_attributes: ClassVar[set[str]] = {
        "realted",
        "relatde",
        "relted",
        "rlated",
        "reference",
    }

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> list[SigmaValidationIssue]:
        if rule.custom_attributes is not None:
            for k in rule.custom_attributes.keys():
                if k in self.known_custom_attributes:
                    return [CustomAttributesIssue([rule], k)]
        return []
