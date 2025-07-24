from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal, Optional, Union, TYPE_CHECKING
from sigma.correlations import SigmaCorrelationRule
from sigma.types import SigmaFieldReference, SigmaType
from sigma.rule import (
    SigmaDetection,
    SigmaRule,
    SigmaDetectionItem,
)
from sigma.exceptions import (
    SigmaConfigurationError,
    SigmaProcessingItemError,
)

if TYPE_CHECKING:
    from sigma.processing.pipeline import ProcessingPipeline


@dataclass
class ProcessingCondition(ABC):
    """Anchor base class for all processing condition types."""

    _pipeline: Optional["ProcessingPipeline"] = field(init=False, compare=False, default=None)

    def set_pipeline(self, pipeline: "ProcessingPipeline") -> None:
        if self._pipeline is None:
            self._pipeline = pipeline
        else:
            raise SigmaProcessingItemError("Pipeline for condition was already set.")

    def _clear_pipeline(self) -> None:
        self._pipeline = None


@dataclass
class RuleProcessingCondition(ProcessingCondition, ABC):
    """
    Base for Sigma rule processing condition classes used in processing pipelines.
    """

    @abstractmethod
    def match(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        """Match condition on Sigma rule."""


class FieldNameProcessingCondition(ProcessingCondition, ABC):
    """
    Base class for conditions on field names in detection items, Sigma rule field lists and other
    use cases that require matching on field names without detection item context.
    """

    @abstractmethod
    def match_field_name(self, field: Optional[str]) -> bool:
        "The method match is called for each field name and must return a bool result."

    def match_detection_item(
        self,
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
        return self.match_detection_item_field(detection_item) or self.match_detection_item_value(
            detection_item
        )

    def match_detection_item_field(
        self,
        detection_item: SigmaDetectionItem,
    ) -> bool:
        """Returns True if the field of the detection item matches the implemented field name condition."""
        return self.match_field_name(detection_item.field)

    def match_detection_item_value(
        self,
        detection_item: SigmaDetectionItem,
    ) -> bool:
        """Returns True if any value of a detection item contains a field reference to a field name
        matching the implemented field name condition. Processing actions must only be applied to
        matching individual values determined by `match_value`."""
        return any((self.match_value(value) for value in detection_item.value))

    def match_value(self, value: SigmaType) -> bool:
        """
        Checks if a detection item value matches the field name condition implemented in
        `match_field_name` if it is a field reference. For all other types the method returns False.
        """
        if isinstance(value, SigmaFieldReference):
            return self.match_field_name(value.field)
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

    def __post_init__(self) -> None:
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
        detection_item: SigmaDetectionItem,
    ) -> bool:
        return self.match_func((self.match_value(value) for value in detection_item.value))

    @abstractmethod
    def match_value(self, value: SigmaType) -> bool:
        """Match condition on detection item values."""


@dataclass
class RuleDetectionItemCondition(RuleProcessingCondition, ABC):
    """Base class for rule conditions that search for a detection item with certain properties."""

    def match(
        self,
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
