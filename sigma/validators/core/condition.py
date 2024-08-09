from dataclasses import dataclass
from re import Pattern
import re
from typing import ClassVar, List, Set
from sigma.conditions import ConditionIdentifier, ConditionItem, ConditionSelector
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaDetections, SigmaRule
from sigma.validators.base import (
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
    SigmaRuleValidator,
)


@dataclass
class DanglingDetectionIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule defines detection that is not referenced from condition"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    detection_name: str


class DanglingDetectionValidator(SigmaRuleValidator):
    """Check for detection definitions not referenced from condition."""

    detection_names: Set[str]

    def condition_referenced_ids(
        self, cond: ConditionItem, detections: SigmaDetections
    ) -> Set[str]:
        """
        Return detection item identifier referenced by condition.

        :param cond: Condition to analyze.
        :type cond: ConditionItem
        :param detections: Detections referenced from condition.
        :type detections: SigmaDetections
        :return: Set of referenced detection identifiers.
        :rtype: Set[str]
        """
        if isinstance(cond, ConditionIdentifier):  # Only one id referenced.
            return {cond.identifier}
        elif isinstance(cond, ConditionSelector):  # Resolve all referenced ids and return
            return {cond.identifier for cond in cond.resolve_referenced_detections(detections)}
        elif isinstance(cond, ConditionItem):  # Traverse into subconditions
            ids = set()
            for arg in cond.args:
                ids.update(self.condition_referenced_ids(arg, detections))
            return ids
        else:  # Fallback if something different is encountered: return empty set.
            return set()

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []  # Correlation rules do not have detections

        detection_names = {  # collect detection names
            name for name in rule.detection.detections.keys()
        }
        referenced_ids = set()
        for condition in rule.detection.parsed_condition:
            parsed_condition = condition.parse(False)
            referenced_ids.update(self.condition_referenced_ids(parsed_condition, rule.detection))

        return [DanglingDetectionIssue([rule], name) for name in detection_names - referenced_ids]


@dataclass
class DanglingConditionIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule defines a condition that contains references to an unknown detection definition"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    condition_name: str


class DanglingConditionValidator(SigmaRuleValidator):
    """Check for non existing detection definitions referenced from the condition."""

    def condition_unknown_referenced_ids(
        self, cond: ConditionItem, detections: SigmaDetections
    ) -> Set[str]:
        """
        Return set of unknown item identifier referenced by condition.

        :param cond: Condition to analyze.
        :type cond: ConditionItem
        :param detections: Detections referenced from condition.
        :type detections: SigmaDetections
        :return: Set of unknown referenced detection identifiers.
        :rtype: Set[str]
        """
        if isinstance(cond, ConditionSelector):  # Resolve all referenced ids and return
            resolved_detections = {
                cond.identifier for cond in cond.resolve_referenced_detections(detections)
            }
            if (
                resolved_detections == set()
            ):  # If the function returns an empty set, it means that there was no corresponding detection identifier for the condition identifier.
                return {cond.pattern}
            else:
                return {}
        elif isinstance(cond, ConditionItem):  # Traverse into subconditions
            ids = set()
            for arg in cond.args:
                ids.update(self.condition_unknown_referenced_ids(arg, detections))
            return ids
        else:  # Fallback if something different is encountered: return empty set.
            return set()

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []  # Correlation rules do not have detections

        unknown_detection_refs = set()
        for condition in rule.detection.parsed_condition:
            parsed_condition = condition.parse(False)
            unknown_detection_refs.update(
                self.condition_unknown_referenced_ids(parsed_condition, rule.detection)
            )

        return [DanglingConditionIssue([rule], name) for name in unknown_detection_refs]


@dataclass
class ThemConditionWithSingleDetectionIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule refers to 'them' but has only one condition"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW


class ThemConditionWithSingleDetectionValidator(SigmaRuleValidator):
    """Detect conditions referring to 'them' with only one detection."""

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []  # Correlation rules do not have detections

        if (
            any(["them" in condition for condition in rule.detection.condition])
            and len(rule.detection.detections) == 1
        ):
            return [ThemConditionWithSingleDetectionIssue([rule])]
        else:
            return []


@dataclass
class AllOfThemConditionIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule contains discouraged 'all of them' condition, use 'all of selection*' instead."
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class AllOfThemConditionValidator(SigmaRuleValidator):
    """Find occurrences of discouraged 'all of them' conditions."""

    re_all_of_them: ClassVar[Pattern] = re.compile("all\\s+of\\s+them")

    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        if isinstance(rule, SigmaCorrelationRule):
            return []  # Correlation rules do not have detections

        if any([self.re_all_of_them.search(condition) for condition in rule.detection.condition]):
            return [AllOfThemConditionIssue([rule])]
        else:
            return []
