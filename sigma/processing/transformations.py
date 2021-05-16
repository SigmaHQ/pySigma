from abc import ABC, abstractmethod
from typing import Iterable, List, Dict, Optional, Union, Pattern, Iterator
from dataclasses import dataclass, field
import dataclasses
import re
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem
from sigma.exceptions import SigmaValueError, SigmaConfigurationError
from sigma.types import Placeholder, SigmaString, SigmaType, SpecialChars

@dataclass
class Transformation(ABC):
    """Base class for processing steps used in pipelines."""
    @classmethod
    def from_dict(cls, d : dict) -> "Transformation":
        return cls(**d)

    @abstractmethod
    def apply(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", rule : SigmaRule) -> None:
        """Apply transformation on Sigma rule."""
        self.pipeline = pipeline        # make pipeline accessible from all further options in class property

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

    def apply(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", rule : SigmaRule) -> None:
        super().apply(pipeline, rule)
        for detection in rule.detection.detections.values():
            self.apply_detection(detection)

@dataclass
class ValueTransformation(DetectionItemTransformation):
    """
    Iterates over all values in all detection items of a Sigma rule and call apply_value method
    for each of them. The apply_value method can return a single value or a list of values which
    are inserted into the value list or None if the value should be dropped.
    """
    def __post_init__(self):
        argtypes = list(self.apply_value.__annotations__.values())      # get type annotations of apply_value method
        try:        # try to extract type annotation of first argument and derive accepted types
            argtype = argtypes[0]
            if hasattr(argtype, "__origin__") and argtype.__origin__ is Union:      # if annotation is an union the list of types is contained in __args__
                self.value_types = argtype.__args__
            else:
                self.value_types = argtype
        except IndexError:      # No type annotation found
            self.value_types = None

    def apply_detection_item(self, detection_item : SigmaDetectionItem):
        """Call apply_value for each value and integrate results into value list."""
        results = []
        for value in detection_item.value:
            if self.value_types is None or isinstance(value, self.value_types):     # run replacement if no type annotation is defined or matching to type of value
                res = self.apply_value(value)
                if value is None:       # no value returned: drop value
                    pass
                elif isinstance(value, Iterable):
                    results.extend(res)
                else:
                    results.append(res)
            else:       # pass original value if type doesn't matches to apply_value argument type annotation
                results.append(value)
        detection_item.value = results

    @abstractmethod
    def apply_value(self, val : SigmaType) -> Optional[Union[SigmaType, Iterable[SigmaType]]]:
        """
        Perform a value transformation. This method can return:

        * None to drop the value
        * a single SigmaType object which replaces the original value.
        * an iterable of SigmaType objects. These objects are used as replacement for the
          original value.

        The type annotation of the val argument is used to skip incompatible values.
        """

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

@dataclass
class BasePlaceholderTransformation(ValueTransformation):
    """
    Placeholder base transformation. The parameters include and exclude can contain variable names that
    are handled by this transformation. Unhandled placeholders are left as they are and must be handled by
    later transformations.
    """
    include : List[str] = field(default_factory=list)
    exclude : List[str] = field(default_factory=list)

    def __post_init__(self):
        super().__post_init__()
        if len(self.include) > 0 and len(self.exclude) > 0:
            raise SigmaConfigurationError("Placeholder transformation include and exclude lists can only be used exclusively!")

    def apply_value(self, val: SigmaString) -> Union[SigmaString, Iterable[SigmaString]]:
        if val.contains_placeholder():
            return val.replace_placeholders(self.placeholder_replacements_base)
        else:
            return [ val ]

    def placeholder_replacements_base(self, p : Placeholder) -> Iterator[Union[str, SpecialChars, Placeholder]]:
        """
        Base placeholder replacement callback. Calls real callback if placeholder is included or not excluded,
        else it passes the placeholder back to caller.
        """
        if  (len(self.include) == 0 and len(self.exclude) == 0) or \
            (len(self.include) > 0 and p.name in self.include) or \
            (len(self.exclude) > 0 and p.name not in self.exclude):
            yield from self.placeholder_replacements(p)
        else:
            yield p

    @abstractmethod
    def placeholder_replacements(self, p : Placeholder) -> Iterator[Union[str, SpecialChars, Placeholder]]:
        """
        Placeholder replacement callback used by SigmaString.replace_placeholders(). This must return one
        of the following object types:

        * Plain strings
        * SpecialChars instances for insertion of wildcards
        * Placeholder instances, it may even return the same placeholder. These must be handled by following processing
          pipeline items or the backend or the conversion will fail.
        """

@dataclass
class WildcardPlaceholderTransformation(BasePlaceholderTransformation):
    """
    Replaces placeholders with wildcards. This transformation is useful if remaining placeholders should
    be replaced with something meaningful to make conversion of rules possible without defining the
    placeholders content.
    """
    def placeholder_replacements(self, p: Placeholder) -> Iterator[SpecialChars]:
        return [ SpecialChars.WILDCARD_MULTI ]

transformations : Dict[str, Transformation] = {
    "field_name_mapping": FieldMappingTransformation,
    "field_name_suffix": AddFieldnameSuffixTransformation,
    "wildcard_placeholders": WildcardPlaceholderTransformation,
}
