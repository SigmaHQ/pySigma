from dataclasses import dataclass, field

from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions.base import (
    DetectionItemProcessingCondition,
    FieldNameProcessingCondition,
    RuleProcessingCondition,
)
from typing import Literal, Union
from sigma.rule import (
    SigmaRule,
    SigmaDetectionItem,
)
from sigma.exceptions import SigmaConfigurationError, SigmaProcessingItemError


@dataclass
class RuleProcessingItemAppliedCondition(RuleProcessingCondition):
    """
    Checks if processing item was applied to rule.
    """

    processing_item_id: str

    def match(
        self,
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

    def match_state(self) -> bool:
        try:
            state_val = self._pipeline.state[self.key]
        except KeyError:
            return False
        except AttributeError:
            raise SigmaProcessingItemError(
                "No processing pipeline was passed to condition, but required by it"
            )

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
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        return self.match_state()


@dataclass
class FieldNameProcessingStateCondition(FieldNameProcessingCondition, ProcessingStateConditionBase):
    """
    Matches on processing pipeline state in context of a field name condition.
    """

    def match_field_name(
        self,
        field: str,
    ) -> bool:
        return self.match_state()


@dataclass
class DetectionItemProcessingItemAppliedCondition(DetectionItemProcessingCondition):
    """
    Checks if processing item was applied to detection item.
    """

    processing_item_id: str

    def match(
        self,
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
        detection_item: SigmaDetectionItem,
    ) -> bool:
        return self.match_state()


@dataclass
class FieldNameProcessingItemAppliedCondition(FieldNameProcessingCondition):
    """
    Checks if processing item was applied to a field name.
    """

    processing_item_id: str

    def match_field_name(self, field: str) -> bool:
        return self._pipeline.field_was_processed_by(field, self.processing_item_id)

    def match_detection_item(
        self,
        detection_item: SigmaDetectionItem,
    ):
        return detection_item.was_processed_by(self.processing_item_id)
