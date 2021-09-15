from abc import ABC, abstractmethod
from sigma.conditions import SigmaCondition
from typing import Iterable, List, Dict, Optional, Union, Pattern, Iterator
from dataclasses import dataclass, field
import dataclasses
import re
import sigma
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem
from sigma.exceptions import SigmaValueError, SigmaConfigurationError
from sigma.types import Placeholder, SigmaString, SigmaType, SpecialChars, SigmaQueryExpression

### Base Classes ###
@dataclass
class Transformation(ABC):
    """Base class for processing steps used in pipelines."""
    processing_item : Optional["sigma.processing.pipeline.ProcessingItem"] = field(init=False, compare=False, default=None)

    @classmethod
    def from_dict(cls, d : dict) -> "Transformation":
        return cls(**d)

    @abstractmethod
    def apply(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", rule : SigmaRule) -> None:
        """Apply transformation on Sigma rule."""
        self.pipeline = pipeline        # make pipeline accessible from all further options in class property

    def set_processing_item(self, processing_item : "sigma.processing.pipeline.ProcessingItem"):
        self.processing_item = processing_item

    def processing_item_applied(self, d : Union[SigmaDetection, SigmaDetectionItem, SigmaCondition]):
        """Mark detection item or detection as applied."""
        d.add_applied_processing_item(self.processing_item)

class DetectionItemTransformation(Transformation):
    """
    Iterates over all detection items of a Sigma rule and calls the apply_detection_item method
    for each of them if the detection item condition associated with the processing item evaluates
    to true. It also takes care to recurse into detections nested into detections.

    The apply_detection_item method can directly change the detection or return a replacement
    object, which can be a SigmaDetection or a SigmaDetectionItem.

    The processing item is automatically added to the applied items of the detection items if a
    replacement value was returned. In the other case the apply_detection_item method must take
    care of this to make conditional decisions in the processing pipeline working. This can be
    done with the detection_item_applied() method.
    """
    @abstractmethod
    def apply_detection_item(self, detection_item : SigmaDetectionItem) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        """Apply transformation on detection item."""

    def apply_detection(self, detection : SigmaDetection):
        for i, detection_item in enumerate(detection.detection_items):
            if isinstance(detection_item, SigmaDetection):        # recurse into nested detection items
                self.apply_detection(detection_item)
            else:
                if (
                    self.processing_item is None or
                    self.processing_item.match_detection_item(self.pipeline, detection_item)
                 ) and (r := self.apply_detection_item(detection_item)) is not None:
                    detection.detection_items[i] = r
                    self.processing_item_applied(r)

    def apply(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", rule : SigmaRule) -> None:
        super().apply(pipeline, rule)
        for detection in rule.detection.detections.values():
            self.apply_detection(detection)

@dataclass
class ValueTransformation(DetectionItemTransformation):
    """
    Iterates over all values in all detection items of a Sigma rule and call apply_value method
    for each of them. The apply_value method can return a single value or a list of values which
    are inserted into the value list or None if the original value should be passed through. An
    empty list should be returned by apply_value to drop the value from the transformed results.
    """
    def __post_init__(self):
        argtypes = list(self.apply_value.__annotations__.values())      # get type annotations of apply_value method
        try:        # try to extract type annotation of first argument and derive accepted types
            argtype = argtypes[1]
            if hasattr(argtype, "__origin__") and argtype.__origin__ is Union:      # if annotation is an union the list of types is contained in __args__
                self.value_types = argtype.__args__
            else:
                self.value_types = argtype
        except IndexError:      # No type annotation found
            self.value_types = None

    def apply_detection_item(self, detection_item : SigmaDetectionItem):
        """Call apply_value for each value and integrate results into value list."""
        results = []
        modified = False
        for value in detection_item.value:
            if self.value_types is None or isinstance(value, self.value_types):     # run replacement if no type annotation is defined or matching to type of value
                res = self.apply_value(detection_item.field, value)
                if res is None:       # no value returned: drop value
                    results.append(value)
                elif isinstance(res, Iterable):
                    results.extend(res)
                    modified = True
                else:
                    results.append(res)
                    modified = True
            else:       # pass original value if type doesn't matches to apply_value argument type annotation
                results.append(value)
        if modified:
            detection_item.value = results
            self.processing_item_applied(detection_item)

    @abstractmethod
    def apply_value(self, field : str, val : SigmaType) -> Optional[Union[SigmaType, Iterable[SigmaType]]]:
        """
        Perform a value transformation. This method can return:

        * None to drop the value
        * a single SigmaType object which replaces the original value.
        * an iterable of SigmaType objects. These objects are used as replacement for the
          original value.

        The type annotation of the val argument is used to skip incompatible values.
        """

class ConditionTransformation(Transformation):
    """
    Iterates over all rule conditions and calls the apply_condition method for each condition. Automatically
    takes care of marking condition as applied by processing item.
    """
    def apply(self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule) -> None:
        super().apply(pipeline, rule)
        for i, condition in enumerate(rule.detection.parsed_condition):
            condition_before = condition.condition
            self.apply_condition(condition)
            if condition.condition != condition_before:               # Condition was changed by transformation,
                self.processing_item_applied(condition)     # mark as processed by processing item containing this transformation

    @abstractmethod
    def apply_condition(self, cond : SigmaCondition) -> None:
        """
        This method is invoked for each condition and can change it.
        """

### Transformations ###
@dataclass
class FieldMappingTransformation(DetectionItemTransformation):
    """Map a field name to one or multiple different."""
    mapping : Dict[str, Union[str, List[str]]]

    def apply_detection_item(self, detection_item : SigmaDetectionItem):
        if (field_name := detection_item.field) in self.mapping:
            mapping = self.mapping[field_name]
            if isinstance(mapping, str):    # 1:1 mapping, map field name of detection item directly
                detection_item.field = self.mapping[field_name]
                self.processing_item_applied(detection_item)
            else:
                return SigmaDetection([
                    dataclasses.replace(detection_item, field=field)
                    for field in mapping
                ])

@dataclass
class AddFieldnameSuffixTransformation(DetectionItemTransformation):
    """
    Add field name suffix.
    """
    suffix : str

    def apply_detection_item(self, detection_item : SigmaDetectionItem):
        detection_item.field += self.suffix
        self.processing_item_applied(detection_item)

@dataclass
class AddFieldnamePrefixTransformation(DetectionItemTransformation):
    """
    Add field name prefix.
    """
    prefix : str

    def apply_detection_item(self, detection_item : SigmaDetectionItem):
        detection_item.field = self.prefix + detection_item.field
        self.processing_item_applied(detection_item)

@dataclass
class PlaceholderIncludeExcludeMixin:
    include : Optional[List[str]] = field(default=None)
    exclude : Optional[List[str]] = field(default=None)

    def __post_init__(self):
        super().__post_init__()
        if self.include is not None and self.exclude is not None:
            raise SigmaConfigurationError("Placeholder transformation include and exclude lists can only be used exclusively!")

    def is_handled_placeholder(self, p : Placeholder) -> bool:
        return (self.include is None and self.exclude is None) or \
            (self.include is not None and p.name in self.include) or \
            (self.exclude is not None and p.name not in self.exclude)

@dataclass
class BasePlaceholderTransformation(PlaceholderIncludeExcludeMixin, ValueTransformation):
    """
    Placeholder base transformation. The parameters include and exclude can contain variable names that
    are handled by this transformation. Unhandled placeholders are left as they are and must be handled by
    later transformations.
    """
    def __post_init__(self):
        super().__post_init__()

    def apply_value(self, field : str, val: SigmaString) -> Union[SigmaString, Iterable[SigmaString]]:
        if val.contains_placeholder(self.include, self.exclude):
            return val.replace_placeholders(self.placeholder_replacements_base)
        else:
            return None

    def placeholder_replacements_base(self, p : Placeholder) -> Iterator[Union[str, SpecialChars, Placeholder]]:
        """
        Base placeholder replacement callback. Calls real callback if placeholder is included or not excluded,
        else it passes the placeholder back to caller.
        """
        if self.is_handled_placeholder(p):
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
    def placeholder_replacements(self, p : Placeholder) -> Iterator[SpecialChars]:
        return [ SpecialChars.WILDCARD_MULTI ]

@dataclass
class ValueListPlaceholderTransformation(BasePlaceholderTransformation):
    """
    Replaces placeholders with values contained in variables defined in the configuration.
    """
    def placeholder_replacements(self, p : Placeholder) -> List[str]:
        try:
            values = self.pipeline.vars[p.name]
        except KeyError:
            raise SigmaValueError(f"Placeholder replacement variable '{ p.name }' doesn't exists.")

        if not isinstance(values, List):
            values = [ values ]

        if { isinstance(item, (str, int, float)) for item in values } != { True }:
            raise SigmaValueError(f"Replacement variable '{ p.name }' contains value which is not a string or number.")

        return [ str(v) for v in values ]

@dataclass
class QueryExpressionPlaceholderTransformation(PlaceholderIncludeExcludeMixin, ValueTransformation):
    """
    Replaces a placeholder with a plain query containing the placeholder or an identifier
    mapped from the placeholder name. The main purpose is the generation of arbitrary
    list lookup expressions which are passed to the resulting query.

    Parameters:
    * expression: string that contains query expression with {field} and {id} placeholder
      where placeholder identifier or a mapped identifier is inserted.
    * mapping: Mapping between placeholders and identifiers that should be used in the expression.
      If no mapping is provided the placeholder name is used.
    """
    expression : str = ""
    mapping : Dict[str, str] = field(default_factory=dict)

    def apply_value(self, field : str, val: SigmaString) -> Union[SigmaString, Iterable[SigmaString]]:
        if val.contains_placeholder():
            if len(val.s) == 1:     # Sigma string must only contain placeholder, nothing else.
                p = val.s[0]
                if self.is_handled_placeholder(p):
                    return SigmaQueryExpression(self.expression.format(field=field, id=self.mapping.get(p.name) or p.name))
            else:       # SigmaString contains placeholder as well as other parts
                raise SigmaValueError(f"Placeholder query expression transformation only allows placeholder-only strings.")
        return None

transformations : Dict[str, Transformation] = {
    "field_name_mapping": FieldMappingTransformation,
    "field_name_suffix": AddFieldnameSuffixTransformation,
    "field_name_prefix": AddFieldnamePrefixTransformation,
    "wildcard_placeholders": WildcardPlaceholderTransformation,
    "value_placeholders": ValueListPlaceholderTransformation,
    "query_expression_placeholders": QueryExpressionPlaceholderTransformation,
}
