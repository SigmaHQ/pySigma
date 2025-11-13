from dataclasses import dataclass, field
from datetime import date
from uuid import UUID

from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions.base import (
    RuleDetectionItemCondition,
    RuleProcessingCondition,
)
from sigma.types import sigma_type
from typing import ClassVar, Literal, Optional, Union
from sigma.rule import (
    SigmaDetection,
    SigmaLevel,
    SigmaRule,
    SigmaDetectionItem,
    SigmaLogSource,
    SigmaRuleTag,
    SigmaStatus,
)
from sigma.exceptions import SigmaConfigurationError


@dataclass
class LogsourceCondition(RuleProcessingCondition):
    """
    Matches log source on rule. Not specified log source fields are ignored. For Correlation rules,
    the condition returns true if any of the associated rules have the required log source fields.
    """

    category: Optional[str] = field(default=None)
    product: Optional[str] = field(default=None)
    service: Optional[str] = field(default=None)

    def __post_init__(self) -> None:
        self.logsource = SigmaLogSource(self.category, self.product, self.service)

    def match(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        if isinstance(rule, SigmaRule):
            return rule.logsource in self.logsource
        elif isinstance(rule, SigmaCorrelationRule):
            # Will only return true if the rules have been resolved in advance
            for ref in rule.rules:
                if hasattr(ref, "rule") and isinstance(ref.rule, (SigmaRule, SigmaCorrelationRule)):
                    if self.match(ref.rule):
                        return True
            return False


@dataclass
class RuleContainsFieldCondition(RuleDetectionItemCondition):
    """Returns True if rule contains a field that matches the given field name."""

    field: Optional[str]

    def find_detection_item(self, detection: Union[SigmaDetectionItem, SigmaDetection]) -> bool:
        if isinstance(detection, SigmaDetection):
            for detection_item in detection.detection_items:
                if self.find_detection_item(detection_item):
                    return True
        elif isinstance(detection, SigmaDetectionItem):
            if detection.field is not None and detection.field == self.field:
                return True
        else:
            raise TypeError("Parameter of type SigmaDetection or SigmaDetectionItem expected.")

        return False


@dataclass
class RuleContainsDetectionItemCondition(RuleDetectionItemCondition):
    """Returns True if rule contains a detection item that matches the given field name and value."""

    field: Optional[str]
    value: Union[str, int, float, bool]

    def __post_init__(self) -> None:
        self.sigma_value = sigma_type(self.value)

    def find_detection_item(self, detection: Union[SigmaDetectionItem, SigmaDetection]) -> bool:
        if isinstance(detection, SigmaDetection):
            for detection_item in detection.detection_items:
                if self.find_detection_item(detection_item):
                    return True
        elif isinstance(detection, SigmaDetectionItem):
            if (
                detection.field is not None
                and detection.field == self.field
                and self.sigma_value
                in [v for v in detection.value if isinstance(self.sigma_value, type(v))]
            ):
                return True
        else:
            raise TypeError("Parameter of type SigmaDetection or SigmaDetectionItem expected.")

        return False


@dataclass
class IsSigmaRuleCondition(RuleProcessingCondition):
    """
    Checks if rule is a SigmaRule.
    """

    def match(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        return isinstance(rule, SigmaRule)


@dataclass
class IsSigmaCorrelationRuleCondition(RuleProcessingCondition):
    """
    Checks if rule is a SigmaCorrelationRule.
    """

    def match(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        return isinstance(rule, SigmaCorrelationRule)


@dataclass
class RuleAttributeCondition(RuleProcessingCondition):
    """
    Generic match on rule attributes with supported types:

    * strings (exact matches with eq/ne)
    * UUIDs (exact matches with eq/ne)
    * lists (membership checks with in/not_in; eq/gte/gt/lte/lt always return False, ne always returns True)
    * numbers (relations: eq, ne, gte, ge, lte, le)
    * dates (relations: eq, ne, gte, ge, lte, le)
    * Rule severity levels (relations: eq, ne, gte, ge, lte, le)
    * Rule statuses (relations: eq, ne, gte, ge, lte, le)

    Fields that contain maps or other complex data structures are not supported and
    raise a SigmaConfigurationError. If the type of the value doesn't allows a particular relation, the
    condition also raises a SigmaConfigurationError on match.
    """

    attribute: str
    value: Union[str, int, float]
    op: Literal["eq", "ne", "gte", "gt", "lte", "lt", "in", "not_in"] = field(default="eq")
    op_methods: ClassVar[dict[str, str]] = {
        "eq": "__eq__",
        "ne": "__ne__",
        "gte": "__ge__",
        "gt": "__gt__",
        "lte": "__le__",
        "lt": "__lt__",
    }

    def __post_init__(self) -> None:
        if self.op not in self.op_methods and self.op not in ("in", "not_in"):
            raise SigmaConfigurationError(
                f"Invalid operation '{self.op}' in rule attribute condition {str(self)}."
            )

    def match(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        try:  # first try to get built-in attribute
            value = getattr(rule, self.attribute)
        except AttributeError:
            try:
                value = rule.custom_attributes[self.attribute]
            except KeyError:
                return False

        # Finally, value has some comparable type
        compare_value: Union[str, int, float, date, SigmaLevel, SigmaStatus]
        if isinstance(value, list):  # list membership check
            if self.op == "in":
                return self.value in value
            elif self.op == "not_in":
                return self.value not in value
            elif self.op == "eq":
                return False  # A list will never equal a single value
            elif self.op == "ne":
                return True  # A list will never equal a single value
            elif self.op in ("gte", "gt", "lte", "lt"):
                return False  # A list cannot be compared numerically to a single value
            else:
                raise SigmaConfigurationError(
                    f"Invalid operation '{self.op}' for list comparison in rule attribute condition {str(self)}."
                )
        elif isinstance(value, (str, UUID)):  # exact match of strings and UUIDs
            if self.op == "eq":
                return str(value) == self.value
            elif self.op == "ne":
                return str(value) != self.value
            else:
                raise SigmaConfigurationError(
                    f"Invalid operation '{self.op}' for string comparison in rule attribute condition {str(self)}."
                )
        elif isinstance(value, (int, float)):  # numeric comparison
            try:
                compare_value = float(self.value)
            except ValueError:
                raise SigmaConfigurationError(
                    f"Invalid number format '{self.value}' in rule attribute condition {str(self)}."
                )
        elif isinstance(value, date):  # date comparison
            if not isinstance(self.value, str):
                raise SigmaConfigurationError(
                    f"'{self.value}' must be a string value with a valid date but is a {type(self.value)} in rule attribute condition {str(self)}."
                )
            try:
                compare_value = date.fromisoformat(self.value)
            except ValueError:
                raise SigmaConfigurationError(
                    f"Invalid date format '{self.value}' in rule attribute condition {str(self)}."
                )
        elif isinstance(value, SigmaLevel):
            try:
                if not isinstance(self.value, str):
                    raise SigmaConfigurationError(
                        f"'{self.value}' must be a string value with a valid severity level but is a {type(self.value)} in rule attribute condition {str(self)}."
                    )
                compare_value = SigmaLevel[self.value.upper()]
            except KeyError:
                raise SigmaConfigurationError(
                    f"Invalid Sigma severity level '{self.value}' in rule attribute condition {str(self)}."
                )
        elif isinstance(value, SigmaStatus):
            try:
                if not isinstance(self.value, str):
                    raise SigmaConfigurationError(
                        f"'{self.value}' must be a string value with a valid status but is a {type(self.value)} in rule attribute condition {str(self)}."
                    )
                compare_value = SigmaStatus[self.value.upper()]
            except KeyError:
                raise SigmaConfigurationError(
                    f"Invalid Sigma status '{self.value}' in rule attribute condition {str(self)}."
                )
        else:
            raise SigmaConfigurationError(
                f"Unsupported type '{type(value)}' in rule attribute condition {str(self)}."
            )

        try:
            return bool(getattr(value, self.op_methods[self.op])(compare_value))
        # bool(NotImplemented) used to return `True` with Python<3.14
        except TypeError:
            return True
        except AttributeError:  # operation not supported by value type
            return False


@dataclass
class RuleTagCondition(RuleProcessingCondition):
    """
    Matches if rule is tagged with a specific tag.
    """

    tag: str

    def __post_init__(self) -> None:
        self.match_tag = SigmaRuleTag.from_str(self.tag)

    def match(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        return self.match_tag in rule.tags
