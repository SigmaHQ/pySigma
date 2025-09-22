import dataclasses
from sigma.conditions import ConditionOR
from typing import (
    Optional,
    Union,
    Callable,
)
from dataclasses import dataclass, field
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaProcessingItemError
from sigma.processing.transformations.base import (
    FieldMappingTransformationBase,
    PreprocessingTransformation,
)
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem


@dataclass
class FieldMappingTransformation(FieldMappingTransformationBase):
    """Map a field name to one or multiple different."""

    mapping: dict[Optional[str], Union[str, list[str]]]

    def apply_field_name(self, field: Optional[str]) -> Union[None, str, list[str]]:
        return self.mapping.get(field)


@dataclass
class FieldPrefixMappingTransformation(FieldMappingTransformation):
    """Map a field name prefix to one or multiple different prefixes."""

    def apply_field_name(self, field: Optional[str]) -> Union[None, str, list[str]]:
        if field is None:
            return None

        for src, dest in self.mapping.items():
            if src is None:
                raise SigmaProcessingItemError(
                    "FieldPrefixMappingTransformation: None is not a valid prefix."
                )
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

    transform_func: Callable[[Optional[str]], str]
    apply_keyword: bool = False

    def apply_field_name(self, field: Optional[str]) -> Union[None, str, list[str]]:
        if field is None and not self.apply_keyword:
            return None
        return self.mapping.get(field, self.transform_func(field))


@dataclass
class AddFieldnameSuffixTransformation(FieldMappingTransformationBase):
    """
    Add field name suffix.
    """

    suffix: str

    def apply_field_name(self, field: Optional[str]) -> Optional[str]:
        if field is None:
            return None
        return field + self.suffix


@dataclass
class AddFieldnamePrefixTransformation(FieldMappingTransformationBase):
    """
    Add field name prefix.
    """

    prefix: str

    def apply_field_name(self, field: Optional[str]) -> Optional[str]:
        if field is None:
            return None
        return self.prefix + field


@dataclass
class AddFieldTransformation(PreprocessingTransformation):
    """
    Add one or multiple fields to the Sigma rule. The field is added to the fields list of the rule:
    """

    field: Union[str, list[str]]

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

    field: Union[str, list[str]]

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

    fields: list[str]

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
        super().apply(rule)
        rule.fields = self.fields
