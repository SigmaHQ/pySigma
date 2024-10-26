from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import date
from uuid import UUID

import sigma
from sigma.correlations import SigmaCorrelationRule
from sigma.types import SigmaFieldReference, SigmaNull, SigmaString, SigmaType, sigma_type
from typing import ClassVar, Dict, List, Pattern, Literal, Optional, Union
import re
from sigma.rule import (
    SigmaDetection,
    SigmaLevel,
    SigmaRule,
    SigmaDetectionItem,
    SigmaLogSource,
    SigmaRuleTag,
    SigmaStatus,
)
from sigma.exceptions import SigmaConfigurationError, SigmaRegularExpressionError


### Base Classes ###
class ProcessingCondition(ABC):
    """Anchor base class for all processing condition types."""


@dataclass
class RuleProcessingCondition(ProcessingCondition, ABC):
    """
    Base for Sigma rule processing condition classes used in processing pipelines.
    """

    @abstractmethod
    def match(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        """Match condition on Sigma rule."""


class FieldNameProcessingCondition(ProcessingCondition, ABC):
    """
    Base class for conditions on field names in detection items, Sigma rule field lists and other
    use cases that require matching on field names without detection item context.
    """

    @abstractmethod
    def match_field_name(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", field: str
    ) -> bool:
        "The method match is called for each field name and must return a bool result."

    def match_detection_item(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        detection_item: SigmaDetectionItem,
    ) -> bool:
        """
        Field names can be contained in the detection item field as well as in field references in
        detection item values. The detection item matching returns True for both cases, but in
        subsequent processing it has to be verified which part of the detection item has matched and
        should be subject of processing actions (e.g. field name mapping). This can be done with the
        methods

        * `match_detection_item_field` for the field of a detection item
        * `match_detection_item_value` for the whole value list of a detection item and
        * `match_value` for single detection items values.
        """
        return self.match_detection_item_field(
            pipeline, detection_item
        ) or self.match_detection_item_value(pipeline, detection_item)

    def match_detection_item_field(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        detection_item: SigmaDetectionItem,
    ) -> bool:
        """Returns True if the field of the detection item matches the implemented field name condition."""
        return self.match_field_name(pipeline, detection_item.field)

    def match_detection_item_value(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        detection_item: SigmaDetectionItem,
    ) -> bool:
        """Returns True if any value of a detection item contains a field reference to a field name
        matching the implemented field name condition. Processing actions must only be applied to
        matching individual values determined by `match_value`."""
        return any((self.match_value(pipeline, value) for value in detection_item.value))

    def match_value(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", value: SigmaType
    ) -> bool:
        """
        Checks if a detection item value matches the field name condition implemented in
        `match_field_name` if it is a field reference. For all other types the method returns False.
        """
        if isinstance(value, SigmaFieldReference):
            return self.match_field_name(pipeline, value.field)
        else:
            return False


@dataclass
class DetectionItemProcessingCondition(ProcessingCondition, ABC):
    """
    Base for Sigma detection item processing condition classes used in processing pipelines.
    """

    @abstractmethod
    def match(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        detection_item: SigmaDetectionItem,
    ) -> bool:
        """Match condition on Sigma rule."""


@dataclass
class ValueProcessingCondition(DetectionItemProcessingCondition):
    """
    Base class for conditions on values in detection items. The 'cond' parameter determines if any or all
    values of a multivalued detection item must match to result in an overall match.

    The method match_value is called for each value and must return a bool result. It should reject values
    which are incompatible with the condition with a False return value.
    """

    cond: Literal["any", "all"]

    def __post_init__(self):
        if self.cond == "any":
            self.match_func = any
        elif self.cond == "all":
            self.match_func = all
        else:
            raise SigmaConfigurationError(
                f"The value '{self.cond}' for the 'cond' parameter is invalid. It must be 'any' or 'all'."
            )

    def match(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        detection_item: SigmaDetectionItem,
    ) -> bool:
        return self.match_func(
            (self.match_value(pipeline, value) for value in detection_item.value)
        )

    @abstractmethod
    def match_value(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", value: SigmaType
    ) -> bool:
        """Match condition on detection item values."""


### Rule Condition Classes ###
@dataclass
class LogsourceCondition(RuleProcessingCondition):
    """
    Matches log source on rule. Not specified log source fields are ignored. For Correlation rules,
    the condition returns true if any of the associated rules have the required log source fields.
    """

    category: Optional[str] = field(default=None)
    product: Optional[str] = field(default=None)
    service: Optional[str] = field(default=None)

    def __post_init__(self):
        self.logsource = SigmaLogSource(self.category, self.product, self.service)

    def match(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        if isinstance(rule, SigmaRule):
            return rule.logsource in self.logsource
        elif isinstance(rule, SigmaCorrelationRule):
            # Will only return true if the rules have been resolved in advance
            for ref in rule.rules:
                if hasattr(ref, "rule") and isinstance(ref.rule, (SigmaRule, SigmaCorrelationRule)):
                    if self.match(pipeline, ref.rule):
                        return True
            return False


@dataclass
class RuleDetectionItemCondition(RuleProcessingCondition, ABC):
    """Base class for rule conditions that search for a detection item with certain properties."""

    def match(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        if isinstance(rule, SigmaRule):
            for detection in rule.detection.detections.values():
                if self.find_detection_item(detection):
                    return True
            return False
        elif isinstance(rule, SigmaCorrelationRule):
            return False

    @abstractmethod
    def find_detection_item(self, detection: Union[SigmaDetectionItem, SigmaDetection]) -> bool:
        pass


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

    def __post_init__(self):
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
                in [v for v in detection.value if type(self.sigma_value) == type(v)]
            ):
                return True
        else:
            raise TypeError("Parameter of type SigmaDetection or SigmaDetectionItem expected.")

        return False


@dataclass
class RuleProcessingItemAppliedCondition(RuleProcessingCondition):
    """
    Checks if processing item was applied to rule.
    """

    processing_item_id: str

    def match(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        return rule.was_processed_by(self.processing_item_id)


@dataclass
class ProcessingStateConditionBase:
    """
    Base class for processing pipeline state matching. The method match_state can be used by the
    matching method of the derived condition classes to match the state condition.
    """

    key: str
    val: Union[str, int, float, bool]
    op: Literal["eq", "ne", "gte", "gt", "lte", "lt"] = field(default="eq")

    def match_state(self, pipeline: "sigma.processing.pipeline.ProcessingPipeline") -> bool:
        try:
            state_val = pipeline.state[self.key]
        except KeyError:
            return False

        if self.op == "eq":
            return state_val == self.val
        elif self.op == "ne":
            return state_val != self.val
        elif self.op == "gte":
            return state_val >= self.val
        elif self.op == "gt":
            return state_val > self.val
        elif self.op == "lte":
            return state_val <= self.val
        elif self.op == "lt":
            return state_val < self.val
        else:
            raise SigmaConfigurationError(
                f"Invalid operation '{self.op}' in rule state condition {str(self)}."
            )


@dataclass
class RuleProcessingStateCondition(RuleProcessingCondition, ProcessingStateConditionBase):
    """
    Matches on processing pipeline state.
    """

    def match(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        return self.match_state(pipeline)


@dataclass
class IsSigmaRuleCondition(RuleProcessingCondition):
    """
    Checks if rule is a SigmaRule.
    """

    def match(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
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
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        return isinstance(rule, SigmaCorrelationRule)


@dataclass
class RuleAttributeCondition(RuleProcessingCondition):
    """
    Generic match on rule attributes with supported types:

    * strings (exact matches)
    * UUIDs (exact matches)
    * numbers (relations: eq, ne, gte, ge, lte, le)
    * dates (relations: eq, ne, gte, ge, lte, le)
    * Rule severity levels (relations: eq, ne, gte, ge, lte, le)
    * Rule statuses (relations: eq, ne, gte, ge, lte, le)

    Fields that contain lists of values, maps or other complex data structures are not supported and
    raise a SigmaConfigurationError. If the type of the value doesn't allows a particular relation, the
    condition also raises a SigmaConfigurationError on match.
    """

    attribute: str
    value: Union[str, int, float]
    op: Literal["eq", "ne", "gte", "gt", "lte", "lt"] = field(default="eq")
    op_methods: ClassVar[Dict[str, str]] = {
        "eq": "__eq__",
        "ne": "__ne__",
        "gte": "__ge__",
        "gt": "__gt__",
        "lte": "__le__",
        "lt": "__lt__",
    }

    def __post_init__(self):
        if self.op not in self.op_methods:
            raise SigmaConfigurationError(
                f"Invalid operation '{self.op}' in rule attribute condition {str(self)}."
            )

    def match(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
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
        if isinstance(value, (str, UUID)):  # exact match of strings and UUIDs
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
            try:
                compare_value = date.fromisoformat(self.value)
            except ValueError:
                raise SigmaConfigurationError(
                    f"Invalid date format '{self.value}' in rule attribute condition {str(self)}."
                )
        elif isinstance(value, SigmaLevel):
            try:
                compare_value = SigmaLevel[self.value.upper()]
            except KeyError:
                raise SigmaConfigurationError(
                    f"Invalid Sigma severity level '{self.value}' in rule attribute condition {str(self)}."
                )
        elif isinstance(value, SigmaStatus):
            try:
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
            return getattr(value, self.op_methods[self.op])(compare_value)
        except AttributeError:  # operation not supported by value type
            return False


@dataclass
class RuleTagCondition(RuleProcessingCondition):
    """
    Matches if rule is tagged with a specific tag.
    """

    tag: str

    def __post_init__(self):
        self.match_tag = SigmaRuleTag.from_str(self.tag)

    def match(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        return self.match_tag in rule.tags


### Field Name Condition Classes ###
@dataclass
class IncludeFieldCondition(FieldNameProcessingCondition):
    """
    Matches on field name if it is contained in fields list. The parameter 'type' determines if field names are matched as
    plain string ("plain") or regular expressions ("re").
    """

    fields: List[str]
    type: Literal["plain", "re"] = field(default="plain")
    patterns: List[Pattern] = field(init=False, repr=False, default_factory=list)

    def __post_init__(self):
        """
        Check if type is known and pre-compile regular expressions.
        """
        if self.type == "plain":
            pass
        elif self.type == "re":
            self.patterns = [re.compile(field) for field in self.fields]
        else:
            raise SigmaConfigurationError(
                f"Invalid detection item field name condition type '{self.type}', supported types are 'plain' or 're'."
            )

    def match_field_name(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        field: Optional[str],
    ) -> bool:
        if field is None:
            return False
        elif self.type == "plain":
            return field in self.fields
        else:  # regular expression matching
            try:
                return any((pattern.match(field) for pattern in self.patterns))
            except Exception as e:
                msg = f" (while processing field '{field}'"
                if len(e.args) > 1:
                    e.args = (e.args[0] + msg,) + e.args[1:]
                else:
                    e.args = (e.args[0] + msg,)
                raise


@dataclass
class ExcludeFieldCondition(IncludeFieldCondition):
    """Matches on field name if it is not contained in fields list."""

    def match_field_name(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        detection_item: SigmaDetectionItem,
    ) -> bool:
        return not super().match_field_name(pipeline, detection_item)


@dataclass
class FieldNameProcessingStateCondition(FieldNameProcessingCondition, ProcessingStateConditionBase):
    """
    Matches on processing pipeline state in context of a field name condition.
    """

    def match_field_name(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        field: str,
    ) -> bool:
        return self.match_state(pipeline)


### Detection Item Condition Classes ###
@dataclass
class MatchStringCondition(ValueProcessingCondition):
    """
    Match string values with a regular expression 'pattern'. The parameter 'cond' determines for detection items with multiple
    values if any or all strings must match. Generally, values which aren't strings are skipped in any mode or result in a
    false result in all match mode.
    """

    pattern: str
    negate: bool = False

    def __post_init__(self):
        super().__post_init__()
        try:
            self.re = re.compile(self.pattern)
        except re.error as e:
            raise SigmaRegularExpressionError(
                f"Regular expression '{self.pattern}' is invalid: {str(e)}"
            ) from e

    def match_value(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", value: SigmaType
    ) -> bool:
        if isinstance(value, SigmaString):
            result = self.re.match(str(value))
        else:
            result = False

        if self.negate:
            return not result
        else:
            return result


class ContainsWildcardCondition(ValueProcessingCondition):
    """
    Evaluates to True if the value contains a wildcard character.
    """

    def match_value(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", value: SigmaType
    ) -> bool:
        if isinstance(value, SigmaString):
            return value.contains_special()
        else:
            return False


@dataclass
class IsNullCondition(ValueProcessingCondition):
    """
    Match null values. The parameter 'cond' determines for detection items with multiple
    values if any or all strings must match. Generally, values which aren't strings are skipped in any mode or result in a
    false result in all match mode.
    """

    def match_value(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", value: SigmaType
    ) -> bool:
        return isinstance(value, SigmaNull)


@dataclass
class DetectionItemProcessingItemAppliedCondition(DetectionItemProcessingCondition):
    """
    Checks if processing item was applied to detection item.
    """

    processing_item_id: str

    def match(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        detection_item: SigmaDetectionItem,
    ) -> bool:
        return detection_item.was_processed_by(self.processing_item_id)


@dataclass
class DetectionItemProcessingStateCondition(
    DetectionItemProcessingCondition, ProcessingStateConditionBase
):
    """
    Matches on processing pipeline state in context of a detection item condition.
    """

    def match(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        detection_item: SigmaDetectionItem,
    ) -> bool:
        return self.match_state(pipeline)


@dataclass
class FieldNameProcessingItemAppliedCondition(FieldNameProcessingCondition):
    """
    Checks if processing item was applied to a field name.
    """

    processing_item_id: str

    def match_field_name(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", field: str
    ) -> bool:
        return pipeline.field_was_processed_by(field, self.processing_item_id)

    def match_detection_item(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        detection_item: SigmaDetectionItem,
    ):
        return detection_item.was_processed_by(self.processing_item_id)


### Condition mappings between rule identifier and class

rule_conditions: Dict[str, RuleProcessingCondition] = {
    "logsource": LogsourceCondition,
    "contains_detection_item": RuleContainsDetectionItemCondition,
    "contains_field": RuleContainsFieldCondition,
    "processing_item_applied": RuleProcessingItemAppliedCondition,
    "processing_state": RuleProcessingStateCondition,
    "is_sigma_rule": IsSigmaRuleCondition,
    "is_sigma_correlation_rule": IsSigmaCorrelationRuleCondition,
    "rule_attribute": RuleAttributeCondition,
    "tag": RuleTagCondition,
}
detection_item_conditions: Dict[str, DetectionItemProcessingCondition] = {
    "match_string": MatchStringCondition,
    "contains_wildcard": ContainsWildcardCondition,
    "is_null": IsNullCondition,
    "processing_item_applied": DetectionItemProcessingItemAppliedCondition,
    "processing_state": DetectionItemProcessingStateCondition,
}
field_name_conditions: Dict[str, DetectionItemProcessingCondition] = {
    "include_fields": IncludeFieldCondition,
    "exclude_fields": ExcludeFieldCondition,
    "processing_item_applied": FieldNameProcessingItemAppliedCondition,
    "processing_state": FieldNameProcessingStateCondition,
}
