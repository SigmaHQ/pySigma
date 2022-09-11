from dataclasses import dataclass
from typing import ClassVar, List, Set
from sigma.conditions import ConditionIdentifier, ConditionItem, ConditionSelector
from sigma.rule import SigmaDetections, SigmaRule
from sigma.validators.base import SigmaValidationIssue, SigmaValidationIssueSeverity, SigmaRuleValidator

@dataclass
class DanglingDetectionIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule defines detection that is not referenced from condition"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    detection_name : str

class DanglingDetectionValidator(SigmaRuleValidator):
    """
    Check for detection definitions not referenced from condition.
    """
    detection_names : Set[str]

    def condition_referenced_ids(self, cond : ConditionItem, detections : SigmaDetections) -> Set[str]:
        """
        Return detection item identifierd referenced by condition.

        :param cond: Condition to analyze.
        :type cond: ConditionItem
        :param detections: Detections referenced from condition.
        :type detections: SigmaDetections
        :return: Set of referenced detection identifiers.
        :rtype: Set[str]
        """
        if isinstance(cond, ConditionIdentifier):       # Only one id referenced.
            return { cond.identifier }
        elif isinstance(cond, ConditionSelector):       # Resolve all referenced ids and return
            return {
                cond.identifier
                for cond in cond.resolve_referenced_detections(detections)
            }
        elif isinstance(cond, ConditionItem):           # Traverse into subconditions
            ids = set()
            for arg in cond.args:
                ids.update(self.condition_referenced_ids(arg, detections))
            return ids
        else:                                           # Fallback if something different is encountered: return empty set.
            return set()

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        detection_names = {    # collect detection names
            name
            for name in rule.detection.detections.keys()
        }
        referenced_ids = set()
        for condition in rule.detection.parsed_condition:
            parsed_condition = condition.parse(False)
            referenced_ids.update(self.condition_referenced_ids(parsed_condition, rule.detection))

        return [
            DanglingDetectionIssue([rule], name)
            for name in detection_names - referenced_ids
        ]