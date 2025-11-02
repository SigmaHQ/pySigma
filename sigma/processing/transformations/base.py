from abc import ABC, abstractmethod
import dataclasses
from typing import Any, Iterable, Optional, Union, TYPE_CHECKING
from dataclasses import dataclass, field
from sigma.conditions import ConditionOR
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem
from sigma.exceptions import (
    SigmaConfigurationError,
    SigmaTransformationError,
)
from sigma.types import (
    SigmaString,
    SigmaType,
    SigmaFieldReference,
    SpecialChars,
)

if TYPE_CHECKING:
    from sigma.processing.pipeline import ProcessingItemBase, ProcessingItem, ProcessingPipeline
    from sigma.conditions import SigmaCondition


### Base Classes ###
@dataclass
class Transformation(ABC):
    """
    Base class for processing steps used in pipelines. Override `apply` with transformation that is
    applied to the whole rule.
    """

    processing_item: Optional["ProcessingItemBase"] = field(init=False, compare=False, default=None)

    _pipeline: Optional["ProcessingPipeline"] = field(init=False, compare=False, default=None)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Transformation":
        try:
            return cls(**d)
        except TypeError as e:
            raise SigmaConfigurationError("Error in instantiation of transformation: " + str(e))

    def set_pipeline(self, pipeline: "ProcessingPipeline") -> None:
        if self._pipeline is None:
            self._pipeline = pipeline
        else:
            raise SigmaTransformationError("Pipeline for transformation was already set.")

    def _clear_pipeline(self) -> None:
        self._pipeline = None

    def set_processing_item(self, processing_item: "ProcessingItemBase") -> None:
        self.processing_item = processing_item

    def processing_item_applied(
        self,
        d: Union[
            SigmaRule,
            SigmaDetection,
            SigmaDetectionItem,
            "SigmaCondition",
            SigmaCorrelationRule,
        ],
    ) -> None:
        """Mark detection item or detection as applied."""
        if self.processing_item is not None:
            d.add_applied_processing_item(self.processing_item)


@dataclass
class PreprocessingTransformation(Transformation, ABC):
    """
    Intermediate base class for preprocessing transformations.
    """

    @abstractmethod
    def apply(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> None:
        """Apply transformation on Sigma rule."""
        self.processing_item_applied(rule)


@dataclass
class DetectionItemTransformation(PreprocessingTransformation):
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

    processing_item: Optional["ProcessingItem"] = field(init=False, compare=False, default=None)

    @abstractmethod
    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        """Apply transformation on detection item."""

    def apply_detection(self, detection: SigmaDetection) -> None:
        for i, detection_item in enumerate(detection.detection_items):
            if isinstance(detection_item, SigmaDetection):  # recurse into nested detection items
                self.apply_detection(detection_item)
            else:
                if (
                    self.processing_item is None
                    or self.processing_item.match_detection_item(detection_item)
                ) and (r := self.apply_detection_item(detection_item)) is not None:
                    if isinstance(r, SigmaDetectionItem):
                        r.disable_conversion_to_plain()
                    detection.detection_items[i] = r
                    self.processing_item_applied(r)

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
        super().apply(rule)
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
    def apply_field_name(self, field: Optional[str]) -> Union[None, str, list[str]]:
        """
        Map a field name to one or multiple field names. The result is used in detection items, references
        as well as in the field list of the Sigma rule. If the result is None, the field name is
        passed through unchanged. If the result is an empty list, the field name is dropped from the
        transformed result.
        """

    def _add_wildcards_to_value(self, value: SigmaString) -> SigmaString:
        """
        Add wildcards around a SigmaString value if they're not already present.

        This is used when mapping keyword searches (None field) to a specific field
        to preserve the keyword search semantics (substring matching).

        :param value: SigmaString value to wrap with wildcards
        :return: SigmaString with wildcards added at start and end if not present
        """
        if not value.startswith(SpecialChars.WILDCARD_MULTI):
            value = SpecialChars.WILDCARD_MULTI + value
        if not value.endswith(SpecialChars.WILDCARD_MULTI):
            value = value + SpecialChars.WILDCARD_MULTI
        return value

    def _apply_field_name(self, field: str) -> list[str]:
        """
        Evaluate field name conditions and perform transformation with apply_field_name() method if
        condition matches, else return original value.
        """
        result = self.apply_field_name(field)
        if result is not None and (
            self.processing_item is None or self.processing_item.match_field_name(field)
        ):
            if isinstance(result, str):
                result = [result]
            if self.processing_item is not None and self._pipeline is not None:
                self._pipeline.track_field_processing_items(
                    field, result, self.processing_item.identifier
                )
            return result
        else:
            return [field]

    def apply(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> None:
        """Apply field name transformations to Sigma rule field names listed in 'fields' attribute."""
        rule.fields = [
            item for mapping in map(self._apply_field_name, rule.fields) for item in mapping
        ]
        if isinstance(rule, SigmaCorrelationRule):
            if rule.group_by is not None:
                # first iterate over aliases, map the field names contained in them and keep track
                # of aliases used later in grouping list and shouldn't be mapped.
                aliases = set()
                for alias in rule.aliases:
                    aliases.add(alias.alias)
                    for rule_reference, field_name in alias.mapping.items():
                        mapped_field_name = self._apply_field_name(field_name)
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
                        self._apply_field_name(field_name)
                        if field_name not in aliases
                        else [field_name]
                    )
                ]

            # finally map the field name in the condition
            if rule.condition is not None and (fieldref := rule.condition.fieldref) is not None:
                if isinstance(fieldref, list):
                    mapped_fields = []
                    for field in fieldref:
                        mapped_field = self._apply_field_name(field)
                        if len(mapped_field) > 1:
                            raise SigmaConfigurationError(
                                "Field name mapping transformation can't be applied to correlation rule condition field reference because it results in multiple field names."
                            )
                        mapped_fields.append(mapped_field[0])
                    rule.condition.fieldref = mapped_fields
                else:
                    mapped_field = self._apply_field_name(fieldref)
                    if len(mapped_field) > 1:
                        raise SigmaConfigurationError(
                            "Field name mapping transformation can't be applied to correlation rule condition field reference because it results in multiple field names."
                        )
                    rule.condition.fieldref = mapped_field[0]

        return super().apply(rule)

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        """Apply field name transformations to field references in detection item values."""
        new_values: list[SigmaType] = []
        fieldref_match = False
        for value in detection_item.value:
            if isinstance(value, SigmaFieldReference) and (
                self.processing_item is None or self.processing_item.match_field_in_value(value)
            ):
                new_values.extend(
                    (
                        SigmaFieldReference(mapped_field, value.starts_with, value.ends_with)
                        for mapped_field in self._apply_field_name(value.field)
                    )
                )
                fieldref_match = True
            else:
                new_values.append(value)

        if fieldref_match:  # replace value only if something matched
            detection_item.value = new_values
            result: Union[SigmaDetectionItem, SigmaDetection] = detection_item

        field = detection_item.field
        mapping = self.apply_field_name(field)
        field_match = False
        if mapping is not None and (
            self.processing_item is None or self.processing_item.match_field_name(field)
        ):
            field_match = True
            # If mapping from None (keyword) to a field, add wildcards to preserve keyword semantics
            if field is None and isinstance(mapping, (str, list)):
                # Wrap string values with wildcards to maintain keyword search behavior
                new_values = []
                for value in detection_item.value:
                    if isinstance(value, SigmaString):
                        value = self._add_wildcards_to_value(value)
                    new_values.append(value)
                detection_item.value = new_values

            if isinstance(mapping, str):  # 1:1 mapping, map field name of detection item directly
                detection_item.field = mapping
                self.processing_item_applied(detection_item)
                result = detection_item
            else:
                result = SigmaDetection(
                    [
                        dataclasses.replace(detection_item, field=field, auto_modifiers=False)
                        for field in mapping
                    ],
                    item_linking=ConditionOR,
                )
        if field_match or fieldref_match:  # field name was changed or field reference was mapped
            if self._pipeline is not None and mapping is not None:
                self._pipeline.field_mappings.add_mapping(field, mapping)
            return result
        return None  # no replacement was made


@dataclass
class ValueTransformation(DetectionItemTransformation):
    """
    Iterates over all values in all detection items of a Sigma rule and call apply_value method
    for each of them. The apply_value method can return a single value or a list of values which
    are inserted into the value list or None if the original value should be passed through. An
    empty list should be returned by apply_value to drop the value from the transformed results.
    """

    def __post_init__(self) -> None:
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

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[SigmaDetectionItem]:
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
            return detection_item
        return None  # no replacement was made

    @abstractmethod
    def apply_value(
        self, field: Optional[str], val: SigmaType
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

    def apply_value(
        self, field: Optional[str], val: SigmaType
    ) -> Optional[Union[SigmaType, list[SigmaType]]]:
        if isinstance(val, SigmaString):
            return self.apply_string_value(field, val)
        return None

    @abstractmethod
    def apply_string_value(
        self, field: Optional[str], val: SigmaString
    ) -> Optional[Union[SigmaType, list[SigmaType]]]:
        """
        Perform a value transformation. This method can return:

        * None to drop the value
        * a single SigmaType object which replaces the original value.
        * a list of SigmaType objects. These objects are used as replacement for the
          original value.
        """


@dataclass
class ConditionTransformation(PreprocessingTransformation):
    """
    Iterates over all rule conditions and calls the apply_condition method for each condition. Automatically
    takes care of marking condition as applied by processing item.
    """

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
        super().apply(rule)
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
    def apply_condition(self, cond: "SigmaCondition") -> None:
        "This method is invoked for each condition and can change it."
