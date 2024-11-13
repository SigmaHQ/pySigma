import dataclasses
from sigma.conditions import ConditionOR
from typing import (
    List,
    Dict,
    Union,
    Callable,
)
from dataclasses import dataclass, field
import sigma
from sigma.processing.transformations.base import (
    FieldMappingTransformationBase,
    Transformation,
)
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem


@dataclass
class FieldMappingTransformation(FieldMappingTransformationBase):
    """Map a field name to one or multiple different."""

    mapping: Dict[str, Union[str, List[str]]]

    def get_mapping(self, field: str) -> Union[None, str, List[str]]:
        return self.mapping.get(field)

    def apply_detection_item(self, detection_item: SigmaDetectionItem):
        super().apply_detection_item(detection_item)
        field = detection_item.field
        mapping = self.get_mapping(field)
        if mapping is not None and self.processing_item.match_field_name(field):
            self._pipeline.field_mappings.add_mapping(field, mapping)
            if isinstance(mapping, str):  # 1:1 mapping, map field name of detection item directly
                detection_item.field = mapping
                self.processing_item_applied(detection_item)
            else:
                return SigmaDetection(
                    [
                        dataclasses.replace(detection_item, field=field, auto_modifiers=False)
                        for field in mapping
                    ],
                    item_linking=ConditionOR,
                )

    def apply_field_name(self, field: str) -> Union[str, List[str]]:
        mapping = self.get_mapping(field) or field
        if isinstance(mapping, str):
            return [mapping]
        else:
            return mapping


@dataclass
class FieldPrefixMappingTransformation(FieldMappingTransformation):
    """Map a field name prefix to one or multiple different prefixes."""

    def get_mapping(self, field: str) -> Union[None, str, List[str]]:
        for src, dest in self.mapping.items():
            if field.startswith(src):  # found matching prefix
                if isinstance(dest, str):
                    return dest + field[len(src) :]
                else:
                    return [dest_item + field[len(src) :] for dest_item in dest]


@dataclass
class FieldFunctionTransformation(FieldMappingTransformationBase):
    """Map a field name to another using provided transformation function.
    You can overwrite transformation by providing explicit mapping for a field."""

    transform_func: Callable[[str], str]
    mapping: Dict[str, str] = field(default_factory=lambda: {})

    def _transform_name(self, f: str) -> str:
        if f:
            return self.mapping.get(f, self.transform_func(f))
        return f

    def apply_detection_item(self, detection_item: SigmaDetectionItem):
        super().apply_detection_item(detection_item)
        f = detection_item.field
        mapping = self._transform_name(f)
        if self.processing_item.match_field_name(f):
            self._pipeline.field_mappings.add_mapping(f, mapping)
            detection_item.field = mapping
            self.processing_item_applied(detection_item)

    def apply_field_name(self, f: str) -> Union[str, List[str]]:
        return [self._transform_name(f)]


@dataclass
class AddFieldnameSuffixTransformation(FieldMappingTransformationBase):
    """
    Add field name suffix.
    """

    suffix: str

    def apply_detection_item(self, detection_item: SigmaDetectionItem):
        super().apply_detection_item(detection_item)
        if type(orig_field := detection_item.field) is str and (
            self.processing_item is None or self.processing_item.match_field_name(orig_field)
        ):
            detection_item.field += self.suffix
            self._pipeline.field_mappings.add_mapping(orig_field, detection_item.field)
        self.processing_item_applied(detection_item)

    def apply_field_name(self, field: str) -> List[str]:
        return [field + self.suffix]


@dataclass
class AddFieldnamePrefixTransformation(FieldMappingTransformationBase):
    """
    Add field name prefix.
    """

    prefix: str

    def apply_detection_item(self, detection_item: SigmaDetectionItem):
        super().apply_detection_item(detection_item)
        if type(orig_field := detection_item.field) is str and (
            self.processing_item is None or self.processing_item.match_field_name(orig_field)
        ):
            detection_item.field = self.prefix + detection_item.field
            self._pipeline.field_mappings.add_mapping(orig_field, detection_item.field)
        self.processing_item_applied(detection_item)

    def apply_field_name(self, field: str) -> List[str]:
        return [self.prefix + field]


@dataclass
class AddFieldTransformation(Transformation):
    """
    Add one or multiple fields to the Sigma rule. The field is added to the fields list of the rule:
    """

    field: Union[str, List[str]]

    def apply(self, rule: SigmaRule) -> None:
        super().apply(rule)
        if isinstance(self.field, str):
            rule.fields.append(self.field)
        elif isinstance(self.field, list):
            rule.fields.extend(self.field)


@dataclass
class RemoveFieldTransformation(Transformation):
    """
    Remove one or multiple fields from the Sigma rules field list. If a given field is not in the
    rules list, it is ignored.
    """

    field: Union[str, List[str]]

    def apply(self, rule: SigmaRule) -> None:
        super().apply(rule)
        if isinstance(self.field, str):
            try:
                rule.fields.remove(self.field)
            except ValueError:
                pass
        elif isinstance(self.field, list):
            for field in self.field:
                try:
                    rule.fields.remove(field)
                except ValueError:
                    pass


@dataclass
class SetFieldTransformation(Transformation):
    """
    Set fields to the Sigma rule. The fields are set to the fields list of the transformation.
    """

    fields: List[str]

    def apply(self, rule: SigmaRule) -> None:
        super().apply(rule)
        rule.fields = self.fields
