import re
from collections import Counter
from collections import defaultdict
from dataclasses import dataclass
from typing import ClassVar, Dict, List, Set
from uuid import UUID

from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


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


@dataclass
class DuplicateReferencesIssue(SigmaValidationIssue):
    description = "The same references appears multiple times"
    severity = SigmaValidationIssueSeverity.MEDIUM
    reference: str


class DuplicateReferencesValidator(SigmaRuleValidator):
    """Validate rule References uniqueness."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        references = Counter(rule.references)
        return [
            DuplicateReferencesIssue([rule], reference)
            for reference, count in references.items()
            if count > 1
        ]


@dataclass
class StatusExistenceIssue(SigmaValidationIssue):
    description = "Rule has no status"
    severity = SigmaValidationIssueSeverity.MEDIUM


class StatusExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a status."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.status is None:
            return [StatusExistenceIssue([rule])]
        else:
            return []


@dataclass
class StatusUnsupportedIssue(SigmaValidationIssue):
    description = "Rule has UNSUPPORTED status"
    severity = SigmaValidationIssueSeverity.MEDIUM


class StatusUnsupportedValidator(SigmaRuleValidator):
    """Checks if rule has a status UNSUPPORTED."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.status and rule.status.name == "UNSUPPORTED":
            return [StatusUnsupportedIssue([rule])]
        else:
            return []


@dataclass
class DateExistenceIssue(SigmaValidationIssue):
    description = "Rule has no date"
    severity = SigmaValidationIssueSeverity.MEDIUM


class DateExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a data."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.date is None:
            return [DateExistenceIssue([rule])]
        else:
            return []


@dataclass
class DuplicateFilenameIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule filemane used by multiple rules"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    filename: str


class DuplicateFilenameValidator(SigmaRuleValidator):
    """Check rule filename uniqueness."""

    filenames: Dict[str, List[SigmaRule]]

    def __init__(self):
        self.filenames = defaultdict(list)

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.source is not None:
            self.filenames[rule.source.path.name].append(rule)
        return []

    def finalize(self) -> List[SigmaValidationIssue]:
        return [
            DuplicateFilenameIssue(rules, filename)
            for filename, rules in self.filenames.items()
            if len(rules) > 1
        ]


@dataclass
class FilenameSigmahqIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule filemane doesn't match SigmaHQ standard"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    filename: str


class FilenameSigmahqValidator(SigmaRuleValidator):
    """Check rule filename match SigmaHQ standard."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        filename_pattern = re.compile(r"[a-z0-9_]{10,90}\.yml")
        if rule.source is not None:
            filename = rule.source.path.name
            if filename_pattern.match(filename) is None or not "_" in filename:
                return [FilenameSigmahqIssue(rule, filename)]
        return []


@dataclass
class FilenameLenghIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule filename is too short or long"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    filename: str


class FilenameLenghValidator(SigmaRuleValidator):
    """Check rule filename lengh"""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.source is not None:
            filename = rule.source.path.name
            if len(filename) < 10 or len(filename) > 90:
                return [FilenameLenghIssue(rule, filename)]
        return []


@dataclass
class CustomAttributesIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule use optional field name similar to legit"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    fieldname: str


class CustomAttributesValidator(SigmaRuleValidator):
    """Check rule filename lengh"""

    known_custom_attributes: Set[str] = {
        "realted",
        "relatde",
        "relted",
        "rlated",
        "reference",
    }

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.custom_attributes is not None:
            for k in rule.custom_attributes.keys():
                if k in self.known_custom_attributes:
                    return [CustomAttributesIssue(rule, k)]
        return []


@dataclass
class DescriptionExistenceIssue(SigmaValidationIssue):
    description = "Rule has no description"
    severity = SigmaValidationIssueSeverity.MEDIUM


class DescriptionExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a description."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.description is None:
            return [DescriptionExistenceIssue([rule])]
        else:
            return []


@dataclass
class DescriptionLengthIssue(SigmaValidationIssue):
    description = "Rule has a too short description"
    severity = SigmaValidationIssueSeverity.MEDIUM


class DescriptionLengthValidator(SigmaRuleValidator):
    """Checks if rule has a description."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.description is not None and len(rule.description) < 16:
            return [DescriptionLengthIssue([rule])]
        else:
            return []


@dataclass
class LevelExistenceIssue(SigmaValidationIssue):
    description = "Rule has no level"
    severity = SigmaValidationIssueSeverity.MEDIUM


class LevelExistenceValidator(SigmaRuleValidator):
    """Checks if rule has a level."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if rule.level is None:
            return [LevelExistenceIssue([rule])]
        else:
            return []
