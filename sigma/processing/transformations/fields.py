import dataclasses
from sigma.conditions import ConditionOR
from typing import (
    List,
    Dict,
    Optional,
    Union,
    Callable,
)
from dataclasses import dataclass, field
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.transformations.base import (
    FieldMappingTransformationBase,
    PreprocessingTransformation,
)
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem


@dataclass
class FieldMappingTransformation(FieldMappingTransformationBase):
    """Map a field name to one or multiple different."""

    mapping: Dict[str, Union[str, List[str]]]

    def get_mapping(self, field: str) -> Union[None, str, List[str]]:
        return self.mapping.get(field)

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        super().apply_detection_item(detection_item)
        field = detection_item.field
        if field is None:
            return None
        mapping = self.get_mapping(field)
        if (
            mapping is not None
            and self.processing_item is not None
            and self.processing_item.match_field_name(field)
        ):
            if self._pipeline is not None:
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
        return None

    def apply_field_name(self, field: str) -> List[str]:
        mapping = self.get_mapping(field) or field
        if isinstance(mapping, str):
            return [mapping]
        else:
            return mapping


@dataclass
class FieldPrefixMappingTransformation(FieldMappingTransformation):
    """Map a field name prefix to one or multiple different prefixes."""

    def get_mapping(self, field: str) -> Union[None, str, List[str]]:
        if field is None:
            return None

        for src, dest in self.mapping.items():
            if field.startswith(src):  # found matching prefix
                if isinstance(dest, str):
                    return dest + field[len(src) :]
                else:
                    return [dest_item + field[len(src) :] for dest_item in dest]
        return None  # no matching prefix found


@dataclass
class FieldFunctionTransformation(FieldMappingTransformation):
    """Map a field name to another using provided transformation function.
    You can overwrite transformation by providing explicit mapping for a field."""

    transform_func: Callable[[str], str]

    def get_mapping(self, field: str) -> Union[None, str, List[str]]:
        return self.mapping.get(field, self.transform_func(field))


@dataclass
class AddFieldnameSuffixTransformation(FieldMappingTransformationBase):
    """
    Add field name suffix.
    """

    suffix: str

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[SigmaDetectionItem]:
        super().apply_detection_item(detection_item)
        if isinstance(detection_item.field, str) and (
            self.processing_item is None
            or self.processing_item.match_field_name(detection_item.field)
        ):
            orig_field: str = detection_item.field
            detection_item.field += self.suffix
            if self._pipeline is not None:
                self._pipeline.field_mappings.add_mapping(orig_field, detection_item.field)
            return detection_item
        return None

    def apply_field_name(self, field: str) -> List[str]:
        return [field + self.suffix]


@dataclass
class AddFieldnamePrefixTransformation(FieldMappingTransformationBase):
    """
    Add field name prefix.
    """

    prefix: str

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[SigmaDetectionItem]:
        super().apply_detection_item(detection_item)
        if isinstance(detection_item.field, str) and (
            self.processing_item is None
            or self.processing_item.match_field_name(detection_item.field)
        ):
            orig_field: str = detection_item.field
            detection_item.field = self.prefix + detection_item.field
            if self._pipeline is not None:
                self._pipeline.field_mappings.add_mapping(orig_field, detection_item.field)
            return detection_item
        return None

    def apply_field_name(self, field: str) -> List[str]:
        return [self.prefix + field]


@dataclass
class AddFieldTransformation(PreprocessingTransformation):
    """
    Add one or multiple fields to the Sigma rule. The field is added to the fields list of the rule:
    """

    field: Union[str, List[str]]

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
        super().apply(rule)
        if isinstance(self.field, str):
            rule.fields.append(self.field)
        elif isinstance(self.field, list):
            rule.fields.extend(self.field)


@dataclass
class RemoveFieldTransformation(PreprocessingTransformation):
    """
    Remove one or multiple fields from the Sigma rules field list. If a given field is not in the
    rules list, it is ignored.
    """

    field: Union[str, List[str]]

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
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
class SetFieldTransformation(PreprocessingTransformation):
    """
    Set fields to the Sigma rule. The fields are set to the fields list of the transformation.
    """

    fields: List[str]

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
        super().apply(rule)
        rule.fields = self.fields
