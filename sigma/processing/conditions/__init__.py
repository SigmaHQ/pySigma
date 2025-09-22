from sigma.processing.conditions.base import (
    ProcessingCondition,
    DetectionItemProcessingCondition,
    FieldNameProcessingCondition,
    RuleProcessingCondition,
)
from typing import Mapping, Type

from sigma.processing.conditions.fields import ExcludeFieldCondition, IncludeFieldCondition
from sigma.processing.conditions.rule import (
    IsSigmaCorrelationRuleCondition,
    IsSigmaRuleCondition,
    LogsourceCondition,
    RuleAttributeCondition,
    RuleContainsDetectionItemCondition,
    RuleContainsFieldCondition,
    RuleTagCondition,
)
from sigma.processing.conditions.state import (
    DetectionItemProcessingItemAppliedCondition,
    DetectionItemProcessingStateCondition,
    FieldNameProcessingItemAppliedCondition,
    FieldNameProcessingStateCondition,
    RuleProcessingItemAppliedCondition,
    RuleProcessingStateCondition,
)
from sigma.processing.conditions.values import (
    ContainsWildcardCondition,
    IsNullCondition,
    MatchStringCondition,
    MatchValueCondition,
)


rule_conditions: Mapping[str, Type[RuleProcessingCondition]] = {
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
detection_item_conditions: Mapping[str, Type[DetectionItemProcessingCondition]] = {
    "match_string": MatchStringCondition,
    "match_value": MatchValueCondition,
    "contains_wildcard": ContainsWildcardCondition,
    "is_null": IsNullCondition,
    "processing_item_applied": DetectionItemProcessingItemAppliedCondition,
    "processing_state": DetectionItemProcessingStateCondition,
}
field_name_conditions: Mapping[str, Type[FieldNameProcessingCondition]] = {
    "include_fields": IncludeFieldCondition,
    "exclude_fields": ExcludeFieldCondition,
    "processing_item_applied": FieldNameProcessingItemAppliedCondition,
    "processing_state": FieldNameProcessingStateCondition,
}

__all__ = [
    "ProcessingCondition",
    "DetectionItemProcessingCondition",
    "FieldNameProcessingCondition",
    "RuleProcessingCondition",
    "LogsourceCondition",
    "RuleContainsDetectionItemCondition",
    "RuleContainsFieldCondition",
    "RuleProcessingItemAppliedCondition",
    "RuleProcessingStateCondition",
    "IsSigmaRuleCondition",
    "IsSigmaCorrelationRuleCondition",
    "RuleAttributeCondition",
    "RuleTagCondition",
    "MatchStringCondition",
    "MatchValueCondition",
    "ContainsWildcardCondition",
    "IsNullCondition",
    "DetectionItemProcessingItemAppliedCondition",
    "DetectionItemProcessingStateCondition",
    "IncludeFieldCondition",
    "ExcludeFieldCondition",
    "FieldNameProcessingItemAppliedCondition",
    "FieldNameProcessingStateCondition",
]
