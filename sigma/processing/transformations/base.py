from abc import ABC, abstractmethod
from collections import defaultdict
from functools import partial
from sigma.conditions import ConditionOR, SigmaCondition
from typing import (
    Any,
    ClassVar,
    Iterable,
    List,
    Dict,
    Optional,
    Tuple,
    Union,
)
from dataclasses import dataclass, field
import sigma
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem
from sigma.exceptions import (
    SigmaConfigurationError,
)
from sigma.types import (
    SigmaString,
    SigmaType,
    SigmaFieldReference,
)


### Base Classes ###
@dataclass
class Transformation(ABC):
    """
    Base class for processing steps used in pipelines. Override `apply` with transformation that is
    applied to the whole rule.
    """

    processing_item: Optional["sigma.processing.pipeline.ProcessingItem"] = field(
        init=False, compare=False, default=None
    )

    @classmethod
    def from_dict(cls, d: dict) -> "Transformation":
        try:
            return cls(**d)
        except TypeError as e:
            raise SigmaConfigurationError("Error in instantiation of transformation: " + str(e))

    @abstractmethod
    def apply(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> None:
        """Apply transformation on Sigma rule."""
        self._pipeline: "sigma.processing.pipeline.ProcessingPipeline" = (
            pipeline  # make pipeline accessible from all further options in class property
        )
        self.processing_item_applied(rule)

    def set_processing_item(self, processing_item: "sigma.processing.pipeline.ProcessingItem"):
        self.processing_item = processing_item

    def processing_item_applied(
        self,
        d: Union[
            SigmaRule, SigmaDetection, SigmaDetectionItem, SigmaCondition, SigmaCorrelationRule
        ],
    ):
        """Mark detection item or detection as applied."""
        d.add_applied_processing_item(self.processing_item)


@dataclass
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

    A detection item transformation also marks the item as unconvertible to plain data types.
    """

    @abstractmethod
    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        """Apply transformation on detection item."""

    def apply_detection(self, detection: SigmaDetection):
        for i, detection_item in enumerate(detection.detection_items):
            if isinstance(detection_item, SigmaDetection):  # recurse into nested detection items
                self.apply_detection(detection_item)
            else:
                if (
                    self.processing_item is None
                    or self.processing_item.match_detection_item(self._pipeline, detection_item)
                ) and (r := self.apply_detection_item(detection_item)) is not None:
                    if isinstance(r, SigmaDetectionItem):
                        r.disable_conversion_to_plain()
                    detection.detection_items[i] = r
                    self.processing_item_applied(r)

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> None:
        super().apply(pipeline, rule)
        if isinstance(rule, SigmaRule):
            for detection in rule.detection.detections.values():
                self.apply_detection(detection)


@dataclass
class FieldMappingTransformationBase(DetectionItemTransformation):
    """
    Transformation that is applied to detection items and additionally the field list of a Sigma
    rule.
    """

    @abstractmethod
    def apply_field_name(self, field: str) -> List[str]:
        """
        Apply field name transformation to a field list item of a Sigma rule. It must always return
        a list of strings that are expanded into a new field list.
        """

    def _apply_field_name(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", field: str
    ) -> List[str]:
        """
        Evaluate field name conditions and perform transformation with apply_field_name() method if
        condition matches, else return original value.
        """
        if self.processing_item is None or self.processing_item.match_field_name(pipeline, field):
            result = self.apply_field_name(field)
            if self.processing_item is not None:
                pipeline.track_field_processing_items(
                    field, result, self.processing_item.identifier
                )
            return result
        else:
            return [field]

    def apply(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> None:
        """Apply field name transformations to Sigma rule field names listed in 'fields' attribute."""
        _apply_field_name = partial(self._apply_field_name, pipeline)
        rule.fields = [item for mapping in map(_apply_field_name, rule.fields) for item in mapping]
        if isinstance(rule, SigmaCorrelationRule):
            if rule.group_by is not None:
                # first iterate over aliases, map the field names contained in them and keep track
                # of aliases used later in grouping list and shouldn't be mapped.
                aliases = set()
                for alias in rule.aliases:
                    aliases.add(alias.alias)
                    for rule_reference, field_name in alias.mapping.items():
                        mapped_field_name = _apply_field_name(field_name)
                        if len(mapped_field_name) > 1:
                            raise SigmaConfigurationError(
                                "Field name mapping transformation can't be applied to correlation rule alias mapping because it results in multiple field names."
                            )
                        alias.mapping[rule_reference] = mapped_field_name[0]

                # now iterate over grouping list and map field names if not contained in aliases
                rule.group_by = [
                    item
                    for field_name in rule.group_by
                    for item in (
                        _apply_field_name(field_name) if field_name not in aliases else [field_name]
                    )
                ]

            # finally map the field name in the condition
            if rule.condition is not None and (fieldref := rule.condition.fieldref) is not None:
                mapped_field = _apply_field_name(fieldref)
                if len(mapped_field) > 1:
                    raise SigmaConfigurationError(
                        "Field name mapping transformation can't be applied to correlation rule condition field reference because it results in multiple field names."
                    )
                rule.condition.fieldref = mapped_field[0]

        return super().apply(pipeline, rule)

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        """Apply field name transformations to field references in detection item values."""
        new_values = []
        match = False
        for value in detection_item.value:
            if self.processing_item is not None and self.processing_item.match_field_in_value(
                self._pipeline, value
            ):
                new_values.extend(
                    (
                        SigmaFieldReference(mapped_field)
                        for mapped_field in self._apply_field_name(self._pipeline, value.field)
                    )
                )
                match = True
            else:
                new_values.append(value)

        if match:  # replace value only if something matched
            detection_item.value = new_values

        return super().apply_detection_item(detection_item)


@dataclass
class ValueTransformation(DetectionItemTransformation):
    """
    Iterates over all values in all detection items of a Sigma rule and call apply_value method
    for each of them. The apply_value method can return a single value or a list of values which
    are inserted into the value list or None if the original value should be passed through. An
    empty list should be returned by apply_value to drop the value from the transformed results.
    """

    def __post_init__(self):
        argtypes = list(
            self.apply_value.__annotations__.values()
        )  # get type annotations of apply_value method
        try:  # try to extract type annotation of first argument and derive accepted types
            argtype = argtypes[1]
            if (
                hasattr(argtype, "__origin__") and argtype.__origin__ is Union
            ):  # if annotation is an union the list of types is contained in __args__
                self.value_types = argtype.__args__
            else:
                self.value_types = argtype
        except IndexError:  # No type annotation found
            self.value_types = None

    def apply_detection_item(self, detection_item: SigmaDetectionItem):
        """Call apply_value for each value and integrate results into value list."""
        results = []
        modified = False
        for value in detection_item.value:
            if self.value_types is None or isinstance(
                value, self.value_types
            ):  # run replacement if no type annotation is defined or matching to type of value
                res = self.apply_value(detection_item.field, value)
                if res is None:  # no value returned: drop value
                    results.append(value)
                elif isinstance(res, Iterable) and not isinstance(res, SigmaType):
                    results.extend(res)
                    modified = True
                else:
                    results.append(res)
                    modified = True
            else:  # pass original value if type doesn't matches to apply_value argument type annotation
                results.append(value)
        if modified:
            detection_item.value = results
            self.processing_item_applied(detection_item)

    @abstractmethod
    def apply_value(
        self, field: str, val: SigmaType
    ) -> Optional[Union[SigmaType, Iterable[SigmaType]]]:
        """
        Perform a value transformation. This method can return:

        * None to drop the value
        * a single SigmaType object which replaces the original value.
        * an iterable of SigmaType objects. These objects are used as replacement for the
          original value.

        The type annotation of the val argument is used to skip incompatible values.
        """


class StringValueTransformation(ValueTransformation):
    """
    Base class for transformations that operate on SigmaString values.
    """

    def apply_value(self, field: str, val: SigmaString) -> Optional[SigmaString]:
        if isinstance(val, SigmaString):
            return self.apply_string_value(field, val)

    @abstractmethod
    def apply_string_value(self, field: str, val: SigmaString) -> Optional[SigmaString]:
        """
        Perform a value transformation. This method can return:

        * None to drop the value
        * a single SigmaString object which replaces the original value.
        """


@dataclass
class ConditionTransformation(Transformation):
    """
    Iterates over all rule conditions and calls the apply_condition method for each condition. Automatically
    takes care of marking condition as applied by processing item.
    """

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> None:
        super().apply(pipeline, rule)
        if isinstance(rule, SigmaRule):
            for i, condition in enumerate(rule.detection.parsed_condition):
                condition_before = condition.condition
                self.apply_condition(condition)
                if (
                    condition.condition != condition_before
                ):  # Condition was changed by transformation,
                    self.processing_item_applied(
                        condition
                    )  # mark as processed by processing item containing this transformation

    @abstractmethod
    def apply_condition(self, cond: SigmaCondition) -> None:
        """
        This method is invoked for each condition and can change it.
        """
