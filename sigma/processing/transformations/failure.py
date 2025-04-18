from dataclasses import dataclass
from sigma.processing.transformations.base import (
    PreprocessingTransformation,
    DetectionItemTransformation,
)
from sigma.rule import SigmaRule, SigmaDetectionItem
from sigma.exceptions import SigmaTransformationError


@dataclass
class RuleFailureTransformation(PreprocessingTransformation):
    """
    Raise a SigmaTransformationError with the provided message. This enables transformation
    pipelines to signalize that a certain situation can't be handled, e.g. only a subset of values
    is allowed because the target data model doesn't offers all possibilities.

    This is a rule transformation. Detection item and field name conditions are not evaluated if
    this is used.
    """

    message: str

    def apply(self, rule: SigmaRule) -> None:
        raise SigmaTransformationError(self.message, source=rule.source)


@dataclass
class DetectionItemFailureTransformation(DetectionItemTransformation):
    """
    Raise a SigmaTransformationError with the provided message. This enables transformation
    pipelines to signalize that a certain situation can't be handled, e.g. only a subset of values
    is allowed because the target data model doesn't offers all possibilities.

    This is a detection item transformation that should be used if detection item or field name
    conditions are used.
    """

    message: str

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        raise SigmaTransformationError(self.message, source=detection_item.source)
