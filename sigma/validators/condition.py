from dataclasses import dataclass
from typing import ClassVar, List, Set
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidationIssue, SigmaValidationIssueSeverity, SigmaRuleValidator

@dataclass
class DanglingDetectionIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule defines detection that is not referenced from condition"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    detection_name : str

class DanglingDetectionValidator(SigmaRuleValidator):
    detection_names : Set[str]

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        detection_names = {    # collect detection names
            name
            for name in rule.detection.detections.keys()
        }
        condition_token = {         # collect condition tokens in set
            token
            for condition in rule.detection.condition
            for token in condition.replace("(", " ").replace(")", " ").split(" ")
        }
        return [
            DanglingDetectionIssue([rule], name)
            for name in detection_names - condition_token       # Set difference contains detection names not contained as token in condition.
        ]