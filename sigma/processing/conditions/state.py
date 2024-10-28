from dataclasses import dataclass, field
from datetime import date
from uuid import UUID

import sigma
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions.base import (
    DetectionItemProcessingCondition,
    FieldNameProcessingCondition,
    RuleDetectionItemCondition,
    RuleProcessingCondition,
    ValueProcessingCondition,
)
from sigma.types import SigmaNull, SigmaString, SigmaType, sigma_type
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
