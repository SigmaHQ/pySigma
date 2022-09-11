from abc import ABC, abstractmethod
from dataclasses import dataclass, fields
from enum import Enum, auto
from typing import ClassVar, List, Optional, Set, Type
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule, SigmaRuleTag
from sigma.types import SigmaString, SigmaType

class SigmaValidationIssueSeverity(Enum):
    """
    Severity of a Sigma rule validation issue:

    * Low: minor improvement suggestion that results in better readability or maintainability of the
      rule.
    * Medium: issue can cause problems under certain conditions or the meaning of the rule can be
      different than intended.
    * High: issue will cause problems. It is certain that the intention of the rule author and the
      rule logic deviate or the rule doesn't matches anything.
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
        self.rule = rule

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
        super().validate(rule)
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
    def validate_detection(self, name: Optional[str], detection: SigmaDetection) -> List[SigmaValidationIssue]:
        """
        Iterate over all detection items of a detection definition and call
        validate_detection_item() method on each detection item or this method itself recursively
        for nested detection definitions.
        """
        return [
            issue
            for item in detection.detection_items
            for issue in (
                self.validate_detection_item(item) if isinstance(item, SigmaDetectionItem)
                else self.validate_detection(None, item)
                )
        ]

    @abstractmethod
    def validate_detection_item(self, detection_item: SigmaDetectionItem) -> List[SigmaValidationIssue]:
        """Implementation of the detection item validation. It is invoked for each detection item.

        :param detection_item: detection item that should be validated.
        :type detection: SigmaDetectionItem
        :return: List of validation issue objects describing.
        :rtype: List[SigmaValidationIssue]
        """

class SigmaValueValidator(SigmaDetectionItemValidator):
    """
    A value validator iterates over all values contained in a Sigma rules detection items and calls
    the method validate_value() for each of them if the type is contained in the validated_types
    set. It can perform isolated checks per value or collect state across different values and then
    conduct checks across multiple of them in the following methods:

    * validate_detection_item(): all values of a detection item.
    * validate_detection(): all detection items of a detection.
    * validate(): all detection items across a rule.
    * finalize(): all detection items across a rule set.

    The validation state stored in the object should be reset as required to prevent undesired side
    effects in implementations of them methods mentioned above.
    """
    validated_types : ClassVar[Set[Type[SigmaType]]] = { SigmaType }

    def validate_detection_item(self, detection_item: SigmaDetectionItem) -> List[SigmaValidationIssue]:
        """
        Iterate over all values of a detection item and call validate_value() method for each of
        them if they are contained in the validated_types class attribute.
        """
        return [
            issue
            for value in detection_item.value
            for issue in (
                self.validate_value(value) if any((
                    isinstance(value, t)
                    for t in self.validated_types
                    ))
                else []
            )
        ]

    @abstractmethod
    def validate_value(self, value: SigmaType) -> List[SigmaValidationIssue]:
        """Implementation of the value validation. It is invoked for each value of a type.

        :param detection_item: detection item that should be validated.
        :type detection: SigmaDetectionItem
        :return: List of validation issue objects describing.
        :rtype: List[SigmaValidationIssue]
        """

class SigmaStringValueValidator(SigmaValueValidator):
    """
    A value validator iterates over all values contained in a Sigma rules detection items and calls
    the method validate_value() for all strings. It can perform isolated checks per value or collect
    state across different values and then conduct checks across multiple of them in the following
    methods:

    * validate_detection_item(): all values of a detection item.
    * validate_detection(): all detection items of a detection.
    * validate(): all detection items across a rule.
    * finalize(): all detection items across a rule set.

    The validation state stored in the object should be reset as required to prevent undesired side
    effects in implementations of them methods mentioned above.
    """
    validated_types : ClassVar[Set[Type[SigmaType]]] = { SigmaString }

class SigmaTagValidator(SigmaRuleValidator):
    """
    The tag validator iterates over all tags from the rule and calls the method validate_tag() for
    each tag.
    """
    def validate(self, rule: SigmaRule) -> List[SigmaValidationIssue]:
        super().validate(rule)
        return [
            issue
            for tag in rule.tags
            for issue in self.validate_tag(tag)
        ]

    @abstractmethod
    def validate_tag(self, tag: SigmaRuleTag) -> List[SigmaValidationIssue]:
        """Validates a tag."""