from abc import abstractmethod
from typing import (
    Iterable,
    Optional,
    Union,
    Iterator,
)
from dataclasses import dataclass, field
from sigma.processing.transformations.base import StringValueTransformation, ValueTransformation
from sigma.exceptions import (
    SigmaValueError,
    SigmaConfigurationError,
)
from sigma.types import (
    Placeholder,
    SigmaString,
    SigmaType,
    SigmaRegularExpression,
    SpecialChars,
    SigmaQueryExpression,
)


@dataclass
class PlaceholderIncludeExcludeMixin:
    include: Optional[list[str]] = field(default=None)
    exclude: Optional[list[str]] = field(default=None)

    def check_exclusivity(self) -> None:
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
class BasePlaceholderTransformation(ValueTransformation, PlaceholderIncludeExcludeMixin):
    """
    Placeholder base transformation. The parameters include and exclude can contain variable names that
    are handled by this transformation. Unhandled placeholders are left as they are and must be handled by
    later transformations.
    """

    def __post_init__(self) -> None:
        self.check_exclusivity()
        return super().__post_init__()

    def apply_value(self, field: Optional[str], val: SigmaType) -> Union[
        None,
        SigmaString,
        Iterable[SigmaString],
        SigmaRegularExpression,
        Iterable[SigmaRegularExpression],
    ]:
        if isinstance(val, (SigmaString, SigmaRegularExpression)) and val.contains_placeholder(
            self.include, self.exclude
        ):
            return val.replace_placeholders(self.placeholder_replacements_base)
        else:
            return None

    def placeholder_replacements_base(
        self, p: Placeholder
    ) -> Iterator[Union[str, SpecialChars, Placeholder, SigmaString]]:
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
    ) -> Iterable[Union[str, SpecialChars, Placeholder, SigmaString]]:
        """
        Placeholder replacement callback used by SigmaString.replace_placeholders(). This must return one
        of the following object types:

        * Plain strings
        * SpecialChars instances for insertion of wildcards
        * Placeholder instances, it may even return the same placeholder. These must be handled by following processing
          pipeline items or the backend or the conversion will fail.
        * SigmaString instances, these are used to replace the placeholder with a SigmaString that
          may contain plain strings, placeholders and special characters.
        """


@dataclass
class WildcardPlaceholderTransformation(BasePlaceholderTransformation):
    """
    Replaces placeholders with wildcards. This transformation is useful if remaining placeholders should
    be replaced with something meaningful to make conversion of rules possible without defining the
    placeholders content.
    """

    def placeholder_replacements(self, p: Placeholder) -> Iterable[SpecialChars]:
        return [SpecialChars.WILDCARD_MULTI]


@dataclass
class ValueListPlaceholderTransformation(BasePlaceholderTransformation):
    """
    Replaces placeholders with values contained in variables defined in the configuration.
    """

    def placeholder_replacements(self, p: Placeholder) -> Iterable[SigmaString]:
        try:
            if self._pipeline is None:
                raise SigmaValueError("No pipeline available for placeholder replacement.")
            values = self._pipeline.vars[p.name]
        except KeyError:
            raise SigmaValueError(f"Placeholder replacement variable '{ p.name }' doesn't exists.")

        if not isinstance(values, list):
            values = [values]

        if {isinstance(item, (str, int, float)) for item in values} != {True}:
            raise SigmaValueError(
                f"Replacement variable '{ p.name }' contains value which is not a string or number."
            )

        return [SigmaString(str(v)) for v in values]


@dataclass
class QueryExpressionPlaceholderTransformation(
    StringValueTransformation, PlaceholderIncludeExcludeMixin
):
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
    mapping: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.check_exclusivity()
        return super().__post_init__()

    def apply_string_value(self, field: Optional[str], val: SigmaString) -> Optional[SigmaType]:
        if val.contains_placeholder():
            if len(val.s) == 1 and isinstance(
                val.s[0], Placeholder
            ):  # Sigma string must only contain placeholder, nothing else.
                p = val.s[0]
                if self.is_handled_placeholder(p):
                    return SigmaQueryExpression(self.expression, self.mapping.get(p.name) or p.name)
            else:  # SigmaString contains placeholder as well as other parts
                raise SigmaValueError(
                    "Placeholder query expression transformation only allows placeholder-only strings."
                )
        return None
