from abc import ABC, abstractmethod
from dataclasses import dataclass, fields
from enum import Enum, auto
from typing import ClassVar, List, Optional, Type
from sigma.collection import SigmaCollection
from sigma.rule import SigmaDetection, SigmaRule

class SigmaValidationIssueSeverity(Enum):
    """
    Severity of a Sigma rule validation issue:

    * Low: minor improvement suggestion that results in better readability or maintainability of the
      rule.
    * Medium: issue can cause problems under certain conditions or the meaning of the rule can be
      different than intended.
    * High: issue will cause problems. It is certain that the intention of the rule author and the
      rule logic deviate.
    """
    LOW           = auto()
    MEDIUM        = auto()
    HIGH          = auto()

@dataclass
class SigmaValidationIssue(ABC):
    """
    Describes an issue of one or multiple Sigma rules. This is a base class that should be
    overridden with specific issue classes. Description should contain some general issue
    information defined statically for the class. Additional issue information should be provided by
    additional fields that are automatically rendered in the representation methods.
    """
    description : ClassVar[str] = "Sigma rule validation issue"
    severity    : ClassVar[SigmaValidationIssueSeverity]
    rules       : List[SigmaRule]

    def __post_init__(self):
        """Ensure that self.rules contains a list, even when a single rule was provided."""
        if isinstance(self.rules, SigmaRule):
            self.rules = [self.rules]

    def __str__(self):
        rules = ", ".join([
            str(rule.source) if rule.source is not None
            else str(rule.id) or rule.title
            for rule in self.rules
        ])
        additional_fields = " ".join([
            f"{field.name}={self.__getattribute__(field.name) or '-'}"
            for field in fields(self)
            if field.name not in ("rules", "severity", "description")
        ])
        return f"issue={self.__class__.__name__} severity={self.severity.name.lower()} description=\"{self.description}\" rules=[{rules}] {additional_fields}"

class SigmaRuleValidator(ABC):
    """
    A rule validator class implements a check for a Sigma rule. It is instantiated once by
    SigmaCollectionValidator and can therefore keep a state across the validation of a whole Sigma
    collection. The validate() method returns results for a specific rule while finalize() is called
    at the end of the validation of multiple rules and can return issues that apply across multiple
    rules, e.g. violation of uniqueness constraints.
    """
    @abstractmethod
    def validate(self, rule : SigmaRule) -> List[SigmaValidationIssue]:
        """Implementation of the rule validation.

        :param rule: Sigma rule that should be validated.
        :type rule: SigmaRule
        :return: List of validation issue objects describing.
        :rtype: List[SigmaValidationIssue]
        """

    def finalize(self) -> List[SigmaValidationIssue]:
        """
        Finalize a validation run and return validation issues that apply to multiple rules.

        :return: List of validation issues.
        :rtype: List[SigmaValidationIssue]
        """
        return []

class SigmaDetectionValidator(SigmaRuleValidator):
    """
    A detection validator class implements a check for detection definitions contained in Sigma
    rules. The method validate_detection() must be implemented and is called for each detection
    definition contained in the Sigma rule. It can perform isolated checks per detection or collect
    state across different detections and then conduct checks across multiple detections in the
    following methods:

    * validate(): all detections across a rule.
    * finalize(): all detections across a rule set.

    The validation state stored in the object should be reset as required to prevent undesired side
    effects in implementations of them methods mentioned above.
    """
    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        """
        Iterate over all detections and call validate_detection() for each.
        """
        return [
            issue
            for name, detection in rule.detection.detections.items()
            for issue in self.validate_detection(name, detection)
        ]

    @abstractmethod
    def validate_detection(self, name : str, detection : SigmaDetection) -> List[SigmaValidationIssue]:
        """Implementation of the detection validation. It is invoked for each detection.

        :param name: Name of the validated detection.
        :type detection: str
        :param detection: detection definition that should be validated.
        :type detection: SigmaDetection
        :return: List of validation issue objects describing.
        :rtype: List[SigmaValidationIssue]
        """

class SigmaDetectionItemValidator(SigmaDetectionValidator):
    """
    A detection item validator iterates over all detection definitions and their detection items and
    calls the method validate_detection_item() for each of them. It can perform isolated checks per
    detection item or collect state across different detection items and then conduct checks across
    multiple of them in the following methods:

    * validate_detection(): all detection items of a detection.
    * validate(): all detection items across a rule.
    * finalize(): all detection items across a rule set.

    The validation state stored in the object should be reset as required to prevent undesired side
    effects in implementations of them methods mentioned above.
    """

class SigmaValidator:
    """
    A SigmaValidator instantiates the given SigmaRuleValidator classes once at instantiation and
    uses them to check Sigma rules and collections. The validators can keep a state across the
    whole lifecycle of the SigmaValidator and can therefore also conduct uniqueness and other checks.
    """
    validators : List[SigmaRuleValidator]

    def __init__(self, validators : List[Type[SigmaRuleValidator]]):
        self.validators = [
            validator()
            for validator in validators
        ]

    def validate_rule(self, rule : SigmaRule) -> List[SigmaValidationIssue]:
        """
        Validate a single rule with all rule validators configured in this SigmaValidator object. A
        rule validator can keep state information across the validation of multiple rules. Therefore
        the validation of a single rule is not necessarily isolated to itself but can also influence
        the result of the validation of other rules or cause that additional issues are emitted on
        finalization of the validator object.

        :param rule: Sigma rule that should be validated.
        :type rule: SigmaRule
        :return: A list of SigmaValidationIssue objects describing potential issues.
        :rtype: List[SigmaValidationIssue]
        """
        issues : List[SigmaValidationIssue] = []
        for validator in self.validators:
            issues.extend(validator.validate(rule))
        return issues

    def finalize(self) -> List[SigmaValidationIssue]:
        """
        Finalize all rule validators, collect their issues and return them as flat list.

        :return: a list of all issues emitted by rule validators on finalization.
        :rtype: List[SigmaValidationIssue]
        """
        return [
            issue
            for validator in self.validators
            for issue in validator.finalize()
        ]

    def validate_rule_collection(self, rule_collection : SigmaCollection) -> List[SigmaValidationIssue]:
        """
        Validate a Sigma rule collection. This method runs all validators on all rules and finalizes
        the validators at the end.

        :param rule_collection: Rule collection that should be validated.
        :type rule_collection: SigmaCollection
        :return: A list of SigmaValidationIssue objects describing potential issues.
        :rtype: List[SigmaValidationIssue]
        """
        return [
            issue
            for rule in rule_collection
            for issue in self.validate_rule(rule)
        ] + self.finalize()