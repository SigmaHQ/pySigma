from dataclasses import dataclass, field

import sigma
from sigma.processing.conditions.base import (
    DetectionItemProcessingCondition,
    FieldNameProcessingCondition,
    RuleProcessingCondition,
    ValueProcessingCondition,
)
from sigma.types import SigmaNull, SigmaString, SigmaType
from typing import Dict, List, Pattern, Literal, Optional
import re
from sigma.rule import SigmaDetectionItem
from sigma.exceptions import SigmaConfigurationError, SigmaRegularExpressionError


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
