from abc import ABC, abstractmethod
from typing import List, Dict, Union, Pattern
from dataclasses import dataclass, field
import dataclasses
import re
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem
from sigma.exceptions import SigmaValueError

@dataclass
class Transformation(ABC):
    """Base class for processing steps used in pipelines."""
    @classmethod
    def from_dict(cls, d : dict) -> "Transformation":
        return cls(**d)

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
    """Map a field name to one or multiple different."""
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

@dataclass
class AddFieldnameSuffixTransformation(DetectionItemTransformation):
    """
    Add field name suffix to fields matching one of the given names or regular expressions.
    """
    suffix : str
    fields : List[Union[str, Pattern[str]]]

    @classmethod
    def from_dict(cls, d : dict) -> "AddFieldnameSuffixTransformation":
        """
        Create transform instance from dict with following field semantics:
        * type: plain or re, determines if given values are treated as plain strings or regular expressions.
        * fields: if this is a single value it is converted into a list. All values are converted into strings.
        """
        suffix = d.get("suffix", "")
        pattern_type = d.get("type", "re")
        fields = d.get("fields", [ ".*" ] if pattern_type == "re" else [])
        if isinstance(fields, str):
            fields = [ fields ]

        if pattern_type == "plain":
            return cls(
                suffix=suffix,
                fields=[
                    str(pattern)
                    for pattern in fields
                ],
            )
        elif pattern_type == "re":
            return cls(
                suffix=suffix,
                fields=[
                    re.compile(pattern)
                    for pattern in fields
                ],
            )
        else:
            raise SigmaValueError(f"Transformation expects plain or re as type, not '{ pattern_type }'")

    def apply_detection_item(self, detection_item : SigmaDetectionItem):
        for pattern in self.fields:
            if isinstance(pattern, Pattern) and pattern.match(detection_item.field) or \
               isinstance(pattern, str) and pattern == detection_item.field:
                    detection_item.field += self.suffix
                    continue

transformations : Dict[str, Transformation] = {
    "field_name_mapping": FieldMappingTransformation,
    "field_name_suffix": AddFieldnameSuffixTransformation,
}
