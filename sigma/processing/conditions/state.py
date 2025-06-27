from dataclasses import dataclass, field

from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions.base import (
    DetectionItemProcessingCondition,
    FieldNameProcessingCondition,
    RuleProcessingCondition,
)
from typing import Literal, Optional, Union, TYPE_CHECKING
from sigma.rule import (
    SigmaRule,
    SigmaDetectionItem,
)
from sigma.exceptions import SigmaConfigurationError, SigmaProcessingItemError

if TYPE_CHECKING:
    from sigma.processing.pipeline import ProcessingPipeline


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

    def match_state(self, processing_pipeline: "ProcessingPipeline") -> bool:
        try:
            state_val = processing_pipeline.state[self.key]
        except KeyError:
            return False

        if self.op == "eq":
            return bool(state_val == self.val)
        elif self.op == "ne":
            return bool(state_val != self.val)
        elif self.op == "gte":
            return bool(state_val >= self.val)
        elif self.op == "gt":
            return bool(state_val > self.val)
        elif self.op == "lte":
            return bool(state_val <= self.val)
        elif self.op == "lt":
            return bool(state_val < self.val)
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
        if self._pipeline is None:
            raise SigmaProcessingItemError(
                f"Processing pipeline must be set before matching condition {str(self)}."
            )
        return self.match_state(self._pipeline)


@dataclass
class FieldNameProcessingStateCondition(FieldNameProcessingCondition, ProcessingStateConditionBase):
    """
    Matches on processing pipeline state in context of a field name condition.
    """

    def match_field_name(
        self,
        field: Optional[str],
    ) -> bool:
        if self._pipeline is None:
            raise SigmaProcessingItemError(
                f"Processing pipeline must be set before matching condition {str(self)}."
            )
        return self.match_state(self._pipeline)


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
        if self._pipeline is None:
            raise SigmaProcessingItemError(
                f"Processing pipeline must be set before matching condition {str(self)}."
            )
        return self.match_state(self._pipeline)


@dataclass
class FieldNameProcessingItemAppliedCondition(FieldNameProcessingCondition):
    """
    Checks if processing item was applied to a field name.
    """

    processing_item_id: str

    def match_field_name(self, field: Optional[str]) -> bool:
        if self._pipeline is None:
            raise SigmaProcessingItemError(
                f"Processing pipeline must be set before matching condition {str(self)}."
            )
        return self._pipeline.field_was_processed_by(field, self.processing_item_id)

    def match_detection_item(
        self,
        detection_item: SigmaDetectionItem,
    ) -> bool:
        return detection_item.was_processed_by(self.processing_item_id)
