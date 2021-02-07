from abc import ABC, abstractmethod
from typing import List, Dict, Union
from dataclasses import dataclass, field
import dataclasses
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem

@dataclass
class Transformation(ABC):
    """Base class for processing steps used in pipelines."""
    @abstractmethod
    def apply(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", rule : SigmaRule) -> SigmaRule:
        """Apply transformation on Sigma rule."""

class DetectionItemTransformation(Transformation):
    """
    Iterates over all detection items of a Sigma rule and calls the apply_detection_item method
    for each of them. It also takes care to recurse into detections nested into detections.

    The apply_detection_item method can directly change the detection or return a replacement
    object, which can be a SigmaDetection, a SigmaDetectionItem or a list of SigmaDetectionItems.
    """
    @abstractmethod
    def apply_detection_item(self, detection_item : SigmaDetectionItem):
        """Apply transformation on detection item."""

    def apply_detection(self, detection : SigmaDetection):
        for i, detection_item in enumerate(detection.detection_items):
            if isinstance(detection_item, SigmaDetection):        # recurse into nested detection items
                self.apply_detection(detection_item)
            else:
                if (r := self.apply_detection_item(detection_item)) is not None:
                    detection.detection_items[i] = r

    def apply(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", rule : SigmaRule) -> SigmaRule:
        for detection in rule.detection.detections.values():
            self.apply_detection(detection)

@dataclass
class FieldMappingTransformation(DetectionItemTransformation):
    """Map a field name to a different one."""
    mapping : Dict[str, Union[str, List[str]]]

    def apply_detection_item(self, detection_item : SigmaDetectionItem):
        if (field_name := detection_item.field) in self.mapping:
            mapping = self.mapping[field_name]
            if isinstance(mapping, str):    # 1:1 mapping, map field name of detection item directly
                detection_item.field = self.mapping[field_name]
            else:
                return SigmaDetection([
                    dataclasses.replace(detection_item, field=field)
                    for field in mapping
                ])

transformations : Dict[str, Transformation] = {
    "field_name_mapping": FieldMappingTransformation,
}
