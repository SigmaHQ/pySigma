from abc import ABC, abstractmethod
from collections import defaultdict
import dataclasses
from functools import partial
from sigma.conditions import ConditionOR, SigmaCondition
from typing import (
    Any,
    ClassVar,
    Iterable,
    List,
    Dict,
    Literal,
    Optional,
    Set,
    Tuple,
    Union,
    Iterator,
    Callable,
)
from dataclasses import dataclass, field
import random
import string
import re
import sigma
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.transformations.base import (
    ConditionTransformation,
    DetectionItemTransformation,
    FieldMappingTransformationBase,
    StringValueTransformation,
    Transformation,
    ValueTransformation,
)
from sigma.rule import SigmaLogSource, SigmaRule, SigmaDetection, SigmaDetectionItem
from sigma.exceptions import (
    SigmaRegularExpressionError,
    SigmaTransformationError,
    SigmaValueError,
    SigmaConfigurationError,
)
from sigma.types import (
    Placeholder,
    SigmaBool,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SigmaType,
    SpecialChars,
    SigmaQueryExpression,
)


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
        if mapping is not None and self.processing_item.match_field_name(self._pipeline, field):
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
        if self.processing_item.match_field_name(self._pipeline, f):
            self._pipeline.field_mappings.add_mapping(f, mapping)
            detection_item.field = mapping
            self.processing_item_applied(detection_item)

    def apply_field_name(self, f: str) -> Union[str, List[str]]:
        return [self._transform_name(f)]


@dataclass
class DropDetectionItemTransformation(DetectionItemTransformation):
    """Deletes detection items. This should only used in combination with a detection item
    condition."""

    class DeleteSigmaDetectionItem(SigmaDetectionItem):
        """Class is used to mark detection item as to be deleted. It's just for having all the
        detection item functionality available."""

        @classmethod
        def create(cls):
            return cls(None, [], [])

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[SigmaDetectionItem]:
        """This function only marks detection items for deletion."""
        return self.DeleteSigmaDetectionItem.create()

    def apply_detection(self, detection: SigmaDetection):
        super().apply_detection(detection)
        detection.detection_items = list(
            filter(
                lambda d: not isinstance(d, self.DeleteSigmaDetectionItem),
                detection.detection_items,
            )
        )


@dataclass
class AddFieldnameSuffixTransformation(FieldMappingTransformationBase):
    """
    Add field name suffix.
    """

    suffix: str

    def apply_detection_item(self, detection_item: SigmaDetectionItem):
        super().apply_detection_item(detection_item)
        if type(orig_field := detection_item.field) is str and (
            self.processing_item is None
            or self.processing_item.match_field_name(self._pipeline, orig_field)
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
            self.processing_item is None
            or self.processing_item.match_field_name(self._pipeline, orig_field)
        ):
            detection_item.field = self.prefix + detection_item.field
            self._pipeline.field_mappings.add_mapping(orig_field, detection_item.field)
        self.processing_item_applied(detection_item)

    def apply_field_name(self, field: str) -> List[str]:
        return [self.prefix + field]


@dataclass
class PlaceholderIncludeExcludeMixin:
    include: Optional[List[str]] = field(default=None)
    exclude: Optional[List[str]] = field(default=None)

    def __post_init__(self):
        super().__post_init__()
        if self.include is not None and self.exclude is not None:
            raise SigmaConfigurationError(
                "Placeholder transformation include and exclude lists can only be used exclusively!"
            )

    def is_handled_placeholder(self, p: Placeholder) -> bool:
        return (
            (self.include is None and self.exclude is None)
            or (self.include is not None and p.name in self.include)
            or (self.exclude is not None and p.name not in self.exclude)
        )


@dataclass
class BasePlaceholderTransformation(PlaceholderIncludeExcludeMixin, ValueTransformation):
    """
    Placeholder base transformation. The parameters include and exclude can contain variable names that
    are handled by this transformation. Unhandled placeholders are left as they are and must be handled by
    later transformations.
    """

    def __post_init__(self):
        super().__post_init__()

    def apply_value(
        self, field: str, val: SigmaString
    ) -> Union[SigmaString, Iterable[SigmaString]]:
        if val.contains_placeholder(self.include, self.exclude):
            return val.replace_placeholders(self.placeholder_replacements_base)
        else:
            return None

    def placeholder_replacements_base(
        self, p: Placeholder
    ) -> Iterator[Union[str, SpecialChars, Placeholder]]:
        """
        Base placeholder replacement callback. Calls real callback if placeholder is included or not excluded,
        else it passes the placeholder back to caller.
        """
        if self.is_handled_placeholder(p):
            yield from self.placeholder_replacements(p)
        else:
            yield p

    @abstractmethod
    def placeholder_replacements(
        self, p: Placeholder
    ) -> Iterator[Union[str, SpecialChars, Placeholder]]:
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
        return [SpecialChars.WILDCARD_MULTI]


@dataclass
class ValueListPlaceholderTransformation(BasePlaceholderTransformation):
    """
    Replaces placeholders with values contained in variables defined in the configuration.
    """

    def placeholder_replacements(self, p: Placeholder) -> List[str]:
        try:
            values = self._pipeline.vars[p.name]
        except KeyError:
            raise SigmaValueError(f"Placeholder replacement variable '{ p.name }' doesn't exists.")

        if not isinstance(values, List):
            values = [values]

        if {isinstance(item, (str, int, float)) for item in values} != {True}:
            raise SigmaValueError(
                f"Replacement variable '{ p.name }' contains value which is not a string or number."
            )

        return [SigmaString(str(v)) for v in values]


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

    expression: str = ""
    mapping: Dict[str, str] = field(default_factory=dict)

    def apply_value(
        self, field: str, val: SigmaString
    ) -> Union[SigmaString, Iterable[SigmaString]]:
        if val.contains_placeholder():
            if len(val.s) == 1:  # Sigma string must only contain placeholder, nothing else.
                p = val.s[0]
                if self.is_handled_placeholder(p):
                    return SigmaQueryExpression(self.expression, self.mapping.get(p.name) or p.name)
            else:  # SigmaString contains placeholder as well as other parts
                raise SigmaValueError(
                    f"Placeholder query expression transformation only allows placeholder-only strings."
                )
        return None


@dataclass
class AddConditionTransformation(ConditionTransformation):
    """
    Add a condition expression to rule conditions.

    If template is set to True the condition values are interpreted as string templates and the
    following placeholders are replaced:

    * $category, $product and $service: with the corresponding values of the Sigma rule log source.
    """

    conditions: Dict[str, Union[str, List[str]]] = field(default_factory=dict)
    name: Optional[str] = field(default=None, compare=False)
    template: bool = False
    negated: bool = False

    def __post_init__(self):
        if self.name is None:  # generate random detection item name if none is given
            self.name = "_cond_" + ("".join(random.choices(string.ascii_lowercase, k=10)))

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> None:
        if isinstance(rule, SigmaRule):
            if self.template:
                conditions = {
                    field: (
                        [
                            string.Template(item).safe_substitute(
                                category=rule.logsource.category,
                                product=rule.logsource.product,
                                service=rule.logsource.service,
                            )
                            for item in value
                        ]
                        if isinstance(value, list)
                        else string.Template(value).safe_substitute(
                            category=rule.logsource.category,
                            product=rule.logsource.product,
                            service=rule.logsource.service,
                        )
                    )
                    for field, value in self.conditions.items()
                }
            else:
                conditions = self.conditions

            rule.detection.detections[self.name] = SigmaDetection.from_definition(conditions)
            self.processing_item_applied(rule.detection.detections[self.name])
            super().apply(pipeline, rule)

    def apply_condition(self, cond: SigmaCondition) -> None:
        cond.condition = ("not " if self.negated else "") + f"{self.name} and ({cond.condition})"


@dataclass
class ChangeLogsourceTransformation(Transformation):
    """Replace log source as defined in transformation parameters."""

    category: Optional[str] = field(default=None)
    product: Optional[str] = field(default=None)
    service: Optional[str] = field(default=None)

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> None:
        super().apply(pipeline, rule)
        logsource = SigmaLogSource(self.category, self.product, self.service)
        rule.logsource = logsource


@dataclass
class AddFieldTransformation(Transformation):
    """
    Add one or multiple fields to the Sigma rule. The field is added to the fields list of the rule:
    """

    field: Union[str, List[str]]

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> None:
        super().apply(pipeline, rule)
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

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> None:
        super().apply(pipeline, rule)
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

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> None:
        super().apply(pipeline, rule)
        rule.fields = self.fields


@dataclass
class SetStateTransformation(Transformation):
    """Set pipeline state key to value."""

    key: str
    val: Any

    def apply(self, pipeline: "sigma.processing.pipeline.Proces", rule: SigmaRule) -> None:
        super().apply(pipeline, rule)
        pipeline.state[self.key] = self.val


@dataclass
class RuleFailureTransformation(Transformation):
    """
    Raise a SigmaTransformationError with the provided message. This enables transformation
    pipelines to signalize that a certain situation can't be handled, e.g. only a subset of values
    is allowed because the target data model doesn't offers all possibilities.
    """

    message: str

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> None:
        raise SigmaTransformationError(self.message)


@dataclass
class DetectionItemFailureTransformation(DetectionItemTransformation):
    """
    Raise a SigmaTransformationError with the provided message. This enables transformation
    pipelines to signalize that a certain situation can't be handled, e.g. only a subset of values
    is allowed because the target data model doesn't offers all possibilities.
    """

    message: str

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        raise SigmaTransformationError(self.message)


@dataclass
class SetCustomAttributeTransformation(Transformation):
    """
    Sets an arbitrary custom attribute on a rule, that can be used by a backend during processing.
    """

    attribute: str
    value: Any

    def apply(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> None:
        super().apply(pipeline, rule)
        rule.custom_attributes[self.attribute] = self.value


@dataclass
class NestedProcessingTransformation(Transformation):
    """Executes a nested processing pipeline as transformation. Main purpose is to apply a
    whole set of transformations that match the given conditions of the enclosng processing item.
    """

    items: List["sigma.processing.pipeline.ProcessingItem"]
    _nested_pipeline: "sigma.processing.pipeline.ProcessingPipeline" = field(
        init=False, compare=False, repr=False
    )

    def __post_init__(self):
        from sigma.processing.pipeline import (
            ProcessingPipeline,
        )  # TODO: move to top-level after restructuring code

        self._nested_pipeline = ProcessingPipeline(items=self.items)

    @classmethod
    def from_dict(cls, d: Dict) -> "NestedProcessingTransformation":
        from sigma.processing.pipeline import (
            ProcessingItem,
        )  # TODO: move to top-level after restructuring code

        try:
            return cls(items=[ProcessingItem.from_dict(item) for item in d["items"]])
        except KeyError:
            raise SigmaConfigurationError(
                "Nested processing transformation requires an 'items' key."
            )

    def apply(
        self,
        pipeline: "sigma.processing.pipeline.ProcessingPipeline",
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> None:
        super().apply(pipeline, rule)
        self._nested_pipeline.apply(rule)
        pipeline.applied.extend(self._nested_pipeline.applied)
        pipeline.applied_ids.update(self._nested_pipeline.applied_ids)
        pipeline.field_name_applied_ids.update(self._nested_pipeline.field_name_applied_ids)
        pipeline.field_mappings.merge(self._nested_pipeline.field_mappings)
        pipeline.state.update(self._nested_pipeline.state)
