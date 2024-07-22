from collections import Counter
from dataclasses import dataclass
from typing import ClassVar, List, Set
from sigma.rule import SigmaRule, SigmaRuleTag
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaTagValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)
from sigma.data.mitre_attack import (
    mitre_attack_tactics,
    mitre_attack_techniques,
    mitre_attack_intrusion_sets,
    mitre_attack_software,
)
import re


@dataclass
class InvalidATTACKTagIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Invalid MITRE ATT&CK tagging"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    tag: SigmaRuleTag


class ATTACKTagValidator(SigmaTagValidator):
    """Check for usage of valid MITRE ATT&CK tags."""

    def __init__(self) -> None:
        self.allowed_tags = (
            {tactic.lower().replace("-", "_") for tactic in mitre_attack_tactics.values()}
            .union({technique.lower() for technique in mitre_attack_techniques.keys()})
            .union({intrusion_set.lower() for intrusion_set in mitre_attack_intrusion_sets})
            .union({software.lower() for software in mitre_attack_software})
        )

    def validate_tag(self, tag: SigmaRuleTag) -> List[SigmaValidationIssue]:
        if tag.namespace == "attack" and tag.name not in self.allowed_tags:
            return [InvalidATTACKTagIssue([self.rule], tag)]
        return []


@dataclass
class InvalidTLPTagIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Invalid TLP tagging"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    tag: SigmaRuleTag


class TLPTagValidatorBase(SigmaTagValidator):
    """Base class for TLP tag validation"""

    def validate_tag(self, tag: SigmaRuleTag) -> List[SigmaValidationIssue]:
        if tag.namespace == "tlp" and tag.name not in self.allowed_tags:
            return [InvalidTLPTagIssue([self.rule], tag)]
        return []


class TLPv1TagValidator(TLPTagValidatorBase):
    """Validation of TLP tags according to old version 1 standard."""

    allowed_tags: Set[str] = {
        "white",
        "green",
        "amber",
        "red",
    }


class TLPv2TagValidator(TLPTagValidatorBase):
    """Validation of TLP tags according to version 2 standard."""

    allowed_tags: Set[str] = {
        "clear",
        "green",
        "amber",
        "amber+strict",
        "red",
    }


class TLPTagValidator(TLPTagValidatorBase):
    """Validation of TLP tags from all versions of the TLP standard."""

    allowed_tags: Set[str] = TLPv1TagValidator.allowed_tags.union(TLPv2TagValidator.allowed_tags)


@dataclass
class DuplicateTagIssue(SigmaValidationIssue):
    description: ClassVar[str] = "The same tag appears multiple times"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    tag: SigmaRuleTag


class DuplicateTagValidator(SigmaRuleValidator):
    """Validate rule tag uniqueness."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        tags = Counter(rule.tags)
        return [DuplicateTagIssue([rule], tag) for tag, count in tags.items() if count > 1]


class NamespaceTagValidator(SigmaTagValidator):
    """Validate rule tag name"""

    allowed_namespace = {"attack", "car", "stp", "cve", "tlp", "detection"}

    def validate_tag(self, tag: SigmaRuleTag) -> List[SigmaValidationIssue]:
        if tag.namespace not in self.allowed_namespace:
            return [InvalidNamespaceTagIssue([self.rule], tag)]
        return []


@dataclass
class InvalidPatternTagIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Invalid tag Pattern"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    tag: SigmaRuleTag


class TagPatternValidatorBase(SigmaTagValidator):
    """Base class for tag pattern validation"""

    def validate_tag(self, tag: SigmaRuleTag) -> List[SigmaValidationIssue]:
        tags_pattern = re.compile(self.pattern)
        if tag.namespace == self.namespace and tags_pattern.match(tag.name) is None:
            return [InvalidPatternTagIssue([self.rule], tag)]
        return []


class CARTagValidator(TagPatternValidatorBase):
    """Validate rule CAR tag"""

    namespace = "car"
    pattern = r"\d{4}-\d{2}-\d{3}$"


class CVETagValidator(TagPatternValidatorBase):
    """Validate rule CVE tag"""

    namespace = "cve"
    pattern = r"^\d+\.\d+$"


class STPTagValidator(TagPatternValidatorBase):
    """Validate rule STP tag"""

    namespace = "stp"
    pattern = r"^[1-5]{1}[auk]{0,1}$"


class DetectionTagValidator(TagPatternValidatorBase):
    """Validate rule detection tag"""

    namespace = "detection"
    pattern = r"dfir|emerging_threats|threat_hunting"


@dataclass
class InvalidNamespaceTagIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Invalid tagging name"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    tag: SigmaRuleTag
