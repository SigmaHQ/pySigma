from dataclasses import dataclass
from typing import ClassVar, List, Set
from sigma.rule import SigmaRule, SigmaRuleTag
from sigma.validation import SigmaRuleValidator, SigmaTagValidator, SigmaValidationIssue, SigmaValidationIssueSeverity
from sigma.data.mitre_attack import mitre_attack_tactics, mitre_attack_techniques

@dataclass
class InvalidATTACKTagIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Invalid MITRE ATT&CK tagging"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    tag: SigmaRuleTag

class ATTACKTagValidator(SigmaTagValidator):
    def __init__(self) -> None:
        self.allowed_tags = {
            tactic.lower().replace("-", "_")
            for tactic in mitre_attack_tactics.values()
        }.union({
            technique.lower()
            for technique in mitre_attack_techniques.keys()
        })

    def validate_tag(self, tag: SigmaRuleTag) -> List[SigmaValidationIssue]:
        if tag.namespace == "attack" and tag.name not in self.allowed_tags:
            return [ InvalidATTACKTagIssue([ self.rule ], tag) ]
        return []