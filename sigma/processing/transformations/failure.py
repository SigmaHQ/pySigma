from dataclasses import dataclass
from typing import Set, Union
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaTransformationError
from sigma.processing.transformations.base import (
    PreprocessingTransformation,
    DetectionItemTransformation,
)
from sigma.rule import SigmaRule, SigmaDetectionItem, SigmaDetection


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

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
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


@dataclass
class StrictFieldMappingFailure(PreprocessingTransformation):
    message = (
        "The field mapping is not strict. "
        "Please check the field mapping in the configuration file."
    )

    def _get_all_field_names(self, rule: SigmaRule) -> set[str]:
        """Extract all field names from the rule's detection items."""
        field_names = set()

        for detection_name, detection in rule.detection.detections.items():
            field_names.update(self._get_fields_from_detection(detection))

        return field_names

    def _get_fields_from_detection(self, detection: SigmaDetection) -> set[str]:
        """Recursively extract field names from a detection."""
        field_names = set()

        for item in detection.detection_items:
            if isinstance(item, SigmaDetectionItem):
                if item.field is not None:
                    field_names.add(item.field)
            elif isinstance(item, SigmaDetection):
                field_names.update(self._get_fields_from_detection(item))

        return field_names

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
        super().apply(rule)
        if isinstance(rule, SigmaRule):
            pipeline = self._pipeline
            if pipeline is None:
                raise SigmaTransformationError("Pipeline is not set for the transformation.")
            field_mappings = pipeline.field_mappings

            # Get all field names used in the rule (after any transformations have been applied)
            all_fields = self._get_all_field_names(rule)

            # Check which original fields from the rule were not explicitly mapped
            # We need to check the target_fields reverse mapping to see which original fields
            # are represented by the current field names
            unmapped_fields = []

            for field in all_fields:
                # Check if this field is in the target_fields (meaning it was mapped from an original field)
                # or if it's in the field_mappings keys (meaning it was an original field that was mapped)
                is_mapped = field in field_mappings or field in field_mappings.target_fields
                if not is_mapped:
                    unmapped_fields.append(field)

            # Raise error if there are unmapped fields
            if unmapped_fields:
                unmapped_fields_str = ", ".join(
                    unmapped_fields
                )  # Create a comma-separated list of unmapped fields
                raise SigmaTransformationError(
                    f"The following fields are not mapped: {unmapped_fields_str}",
                    source=rule.source,
                )
