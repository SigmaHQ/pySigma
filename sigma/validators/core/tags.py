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
from sigma.data.mitre_d3fend import (
    mitre_d3fend_tactics,
    mitre_d3fend_techniques,
    mitre_d3fend_artifacts,
)
import re


@dataclass
class InvalidTagFormatIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Invalid char in namaspace or name tag"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    tag: SigmaRuleTag


class TagFormatValidator(SigmaTagValidator):
    """Validate rule tag namespace and name allowed char"""

    def validate_tag(self, tag: SigmaRuleTag) -> List[SigmaValidationIssue]:
        tags_pattern = re.compile(r"^[a-z0-9\-\_]+\.[a-z0-9\-\_\.]+$")

        if tags_pattern.match(str(tag)) is None:
            return [InvalidTagFormatIssue([self.rule], tag)]
        return []


@dataclass
class InvalidATTACKTagIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Invalid MITRE ATT&CK tagging"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    tag: SigmaRuleTag


class ATTACKTagValidator(SigmaTagValidator):
    """Check for usage of valid MITRE ATT&CK tags."""

    def __init__(self) -> None:
        self.allowed_tags = (
            {tactic.lower() for tactic in mitre_attack_tactics.values()}
            .union({technique.lower() for technique in mitre_attack_techniques.keys()})
            .union({intrusion_set.lower() for intrusion_set in mitre_attack_intrusion_sets.keys()})
            .union({software.lower() for software in mitre_attack_software.keys()})
        )

    def validate_tag(self, tag: SigmaRuleTag) -> List[SigmaValidationIssue]:
        if tag.namespace == "attack" and tag.name not in self.allowed_tags:
            return [InvalidATTACKTagIssue([self.rule], tag)]
        return []


@dataclass
class InvalidD3FENDagIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Invalid MITRE D3FEND tagging"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    tag: SigmaRuleTag


class D3FENDTagValidator(SigmaTagValidator):
    """Check for usage of valid MITRE D3FEND tags."""

    def __init__(self) -> None:
        self.allowed_tags = (
            {tactic.lower() for tactic in mitre_d3fend_tactics.keys()}
            .union({technique.lower() for technique in mitre_d3fend_techniques.keys()})
            .union({artefact for artefact in mitre_d3fend_artifacts.keys()})
        )

    def validate_tag(self, tag: SigmaRuleTag) -> List[SigmaValidationIssue]:
        if tag.namespace == "d3fend" and tag.name not in self.allowed_tags:
            return [InvalidD3FENDagIssue([self.rule], tag)]
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
        "amber-strict",
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


@dataclass
class InvalidNamespaceTagIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Invalid tagging namespace"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    tag: SigmaRuleTag


class NamespaceTagValidator(SigmaTagValidator):
    """Validate rule tag namespace"""

    allowed_namespace = {
        "attack",
        "car",
        "cve",
        "d3fend",
        "detection",
        "stp",
        "tlp",
    }

    def validate_tag(self, tag: SigmaRuleTag) -> List[SigmaValidationIssue]:
        if tag.namespace not in self.allowed_namespace:
            return [InvalidNamespaceTagIssue([self.rule], tag)]
        return []


@dataclass
class InvalidPatternTagIssue(SigmaValidationIssue):
    description: ClassVar[str] = "The tag is using an invalid pattern"
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
    pattern = r"^\d+-\d+$"


class DetectionTagValidator(TagPatternValidatorBase):
    """Validate rule detection tag"""

    namespace = "detection"
    pattern = r"dfir|emerging-threats|threat-hunting"


class STPTagValidator(TagPatternValidatorBase):
    """Validate rule STP tag"""

    namespace = "stp"
    pattern = r"^[1-5]{1}[auk]{0,1}$"
