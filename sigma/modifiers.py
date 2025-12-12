from abc import ABC, abstractmethod
import re
from typing import (
    Any,
    ClassVar,
    Generator,
    Iterator,
    Optional,
    Union,
    Type,
    cast,
    get_origin,
    get_args,
    get_type_hints,
    Generic,
    TypeVar,
    TYPE_CHECKING,
)
from collections.abc import Sequence as SequenceABC
from base64 import b64encode
from sigma.types import (
    CompareOperators,
    Placeholder,
    SigmaBool,
    SigmaCasedString,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaRegularExpressionFlag,
    SigmaType,
    SigmaString,
    SigmaNumber,
    SpecialChars,
    SigmaRegularExpression,
    SigmaCompareExpression,
    SigmaCIDRExpression,
    SigmaTimestampPart,
    TimestampPart,
    SigmaStringPartType,
)
from sigma.exceptions import SigmaRuleLocation, SigmaTypeError, SigmaValueError

if TYPE_CHECKING:
    from .rule import SigmaDetectionItem

T = TypeVar("T", bound=Union[SigmaType, list[SigmaType]])
R = TypeVar("R", bound=Union[SigmaType, list[SigmaType]])


### Base Classes ###
class SigmaModifier(ABC, Generic[T, R]):
    """Base class for all Sigma modifiers"""

    detection_item: "SigmaDetectionItem"
    applied_modifiers: list[Type["SigmaModifier[T, R]"]]

    def __init__(
        self,
        detection_item: "SigmaDetectionItem",
        applied_modifiers: list[Type["SigmaModifier[T, R]"]],
        source: Optional[SigmaRuleLocation] = None,
    ):
        self.detection_item = detection_item
        self.applied_modifiers = applied_modifiers
        self.source = source

    def type_check(self, val: Any, explicit_type: Optional[Type[Any]] = None) -> bool:
        th = (
            explicit_type or get_type_hints(self.modify)["val"]
        )  # get type annotation from val parameter of apply method or explicit_type parameter
        if th is Any:
            return True
        to = get_origin(th)  # get possible generic type of type hint
        if to is None:  # Plain type in annotation
            return isinstance(val, th)
        elif to is Union:  # type hint is Union of multiple types, check if val is one of them
            for t in get_args(th):
                if isinstance(val, t):
                    return True
            return False
        elif to is list and isinstance(val, list):  # type hint is sequence
            inner_type = get_args(th)[0]
            return all([self.type_check(item, explicit_type=inner_type) for item in val])
        return False

    @abstractmethod
    def modify(self, val: T) -> R:
        """This method should be overridden with the modifier implementation."""

    def apply(self, val: T) -> list[T]:
        """
        Modifier entry point containing the default operations:
        * Type checking
        * Ensure returned value is a list
        * Handle values of SigmaExpansion objects separately.
        """
        if isinstance(val, SigmaExpansion):  # Handle each SigmaExpansion item separately
            return [
                cast(
                    T,
                    SigmaExpansion(
                        [cast(SigmaType, va) for v in val.values for va in self.apply(cast(T, v))]
                    ),
                )
            ]
        else:
            if not self.type_check(val):
                raise SigmaTypeError(
                    f"Modifier {self.__class__.__name__} incompatible to value type of '{ val }'",
                    source=self.source,
                )
            r = self.modify(val)
            if isinstance(r, list):
                return [cast(T, item) for item in r]
            else:
                return [cast(T, r)]


class SigmaValueModifier(SigmaModifier[T, R]):
    """Base class for all modifiers that handle each value for the modifier scope separately"""

    @abstractmethod
    def modify(self, val: T) -> R:
        """This method should be overridden with the modifier implementation."""


class SigmaListModifier(SigmaModifier[T, R]):
    """Base class for all modifiers that handle all values for the modifier scope as a whole."""

    @abstractmethod
    def modify(self, val: T) -> R:
        """This method should be overridden with the modifier implementation."""


### Modifier Implementations ###
class SigmaContainsModifier(
    SigmaValueModifier[
        Union[SigmaString, SigmaRegularExpression, SigmaFieldReference],
        Union[SigmaString, SigmaRegularExpression, SigmaFieldReference],
    ]
):
    """Puts wildcards around a string to match it somewhere inside another string instead of as a whole."""

    def modify(
        self, val: Union[SigmaString, SigmaRegularExpression, SigmaFieldReference]
    ) -> Union[SigmaString, SigmaRegularExpression, SigmaFieldReference]:
        if isinstance(val, SigmaString):
            if not val.startswith(SpecialChars.WILDCARD_MULTI):
                val = SpecialChars.WILDCARD_MULTI + val
            if not val.endswith(SpecialChars.WILDCARD_MULTI):
                val += SpecialChars.WILDCARD_MULTI
        elif isinstance(val, SigmaRegularExpression):
            regexp_str = str(val.regexp)
            if regexp_str[:2] != ".*" and regexp_str[0] != "^":
                val.regexp = SigmaString(".") + SpecialChars.WILDCARD_MULTI + val.regexp
            if regexp_str[-2:] != ".*" and regexp_str[-1] != "$":
                val.regexp += SigmaString(".") + SpecialChars.WILDCARD_MULTI
            val.compile()
        elif isinstance(val, SigmaFieldReference):
            val.starts_with = True
            val.ends_with = True
        return val


class SigmaStartswithModifier(
    SigmaValueModifier[
        Union[SigmaString, SigmaRegularExpression, SigmaFieldReference],
        Union[SigmaString, SigmaRegularExpression, SigmaFieldReference],
    ]
):
    """Puts a wildcard at the end of a string to match arbitrary values after the given prefix."""

    def modify(
        self, val: Union[SigmaString, SigmaRegularExpression, SigmaFieldReference]
    ) -> Union[SigmaString, SigmaRegularExpression, SigmaFieldReference]:
        if isinstance(val, SigmaString):
            if not val.endswith(SpecialChars.WILDCARD_MULTI):
                val += SpecialChars.WILDCARD_MULTI
        elif isinstance(val, SigmaRegularExpression):
            regexp_str = str(val.regexp)
            if regexp_str[-2:] != ".*" and regexp_str[-1] != "$":
                val.regexp += SigmaString(".") + SpecialChars.WILDCARD_MULTI
            val.compile()
        elif isinstance(val, SigmaFieldReference):
            val.starts_with = True
        return val


class SigmaEndswithModifier(
    SigmaValueModifier[
        Union[SigmaString, SigmaRegularExpression, SigmaFieldReference],
        Union[SigmaString, SigmaRegularExpression, SigmaFieldReference],
    ]
):
    """Puts a wildcard before a string to match arbitrary values before it."""

    def modify(
        self, val: Union[SigmaString, SigmaRegularExpression, SigmaFieldReference]
    ) -> Union[SigmaString, SigmaRegularExpression, SigmaFieldReference]:
        if isinstance(val, SigmaString):
            if not val.startswith(SpecialChars.WILDCARD_MULTI):
                val = SpecialChars.WILDCARD_MULTI + val
        elif isinstance(val, SigmaRegularExpression):
            regexp_str = str(val.regexp)
            if regexp_str[:2] != ".*" and regexp_str[0] != "^":
                val.regexp = SigmaString(".") + SpecialChars.WILDCARD_MULTI + val.regexp
            val.compile()
        elif isinstance(val, SigmaFieldReference):
            val.ends_with = True
        return val


class SigmaBase64Modifier(SigmaValueModifier[SigmaString, SigmaString]):
    """Encode string as Base64 value."""

    def modify(self, val: SigmaString) -> SigmaString:
        if val.contains_special():
            raise SigmaValueError(
                "Base64 encoding of strings with wildcards is not allowed",
                source=self.source,
            )
        return SigmaString(b64encode(bytes(val)).decode())


class SigmaBase64OffsetModifier(SigmaValueModifier[SigmaString, SigmaExpansion]):
    """
    Encode string as Base64 value with different offsets to match it at different locations in
    encoded form.
    """

    start_offsets = (0, 2, 3)
    end_offsets = (None, -3, -2)

    def modify(self, val: SigmaString) -> SigmaExpansion:
        if val.contains_special():
            raise SigmaValueError(
                "Base64 encoding of strings with wildcards is not allowed",
                source=self.source,
            )
        return SigmaExpansion(
            [
                SigmaString(
                    b64encode(i * b" " + bytes(val))[
                        self.start_offsets[i] : self.end_offsets[(len(val) + i) % 3]
                    ].decode()
                )
                for i in range(3)
            ]
        )


class SigmaWideModifier(SigmaValueModifier[SigmaString, SigmaString]):
    """Encode string as wide string (UTF-16LE)."""

    def modify(self, val: SigmaString) -> SigmaString:
        r: list[SigmaStringPartType] = list()
        for item in val.s:
            if isinstance(
                item, str
            ):  # put 0x00 after each character by encoding it to utf-16le and decoding it as utf-8
                try:
                    r.append(item.encode("utf-16le").decode("utf-8"))
                except UnicodeDecodeError:  # this method only works for ascii characters
                    raise SigmaValueError(
                        f"Wide modifier only allowed for ascii strings, input string '{str(val)}' isn't one",
                        source=self.source,
                    )
            else:  # just append special characters without further handling
                r.append(item)

        s = SigmaString()
        s.s = r
        return s


class SigmaWindowsDashModifier(SigmaValueModifier[SigmaString, SigmaExpansion]):
    """
    Expand parameter characters / and - that are often interchangeable in Windows into the other
    form if it appears between word boundaries. E.g. in -param-name the first dash will be expanded
    into /param-name while the second dash is left untouched.
    """

    en_dash = chr(int("2013", 16))
    em_dash = chr(int("2014", 16))
    horizontal_bar = chr(int("2015", 16))

    def modify(self, val: SigmaString) -> SigmaExpansion:
        def callback(p: Placeholder) -> Iterator[Union[str, Placeholder]]:
            if p.name == "_windash":
                yield from ("-", "/", self.en_dash, self.em_dash, self.horizontal_bar)
            else:
                yield p

        return SigmaExpansion(
            cast(
                list[SigmaType],
                val.replace_with_placeholder(
                    re.compile("\\B[-/]\\b"), "_windash"
                ).replace_placeholders(callback),
            )
        )


class SigmaRegularExpressionModifier(SigmaValueModifier[SigmaString, SigmaRegularExpression]):
    """Treats string value as (case-sensitive) regular expression."""

    def modify(self, val: SigmaString) -> SigmaRegularExpression:
        if len(self.applied_modifiers) > 0:
            raise SigmaValueError(
                "Regular expression modifier only applicable to unmodified values",
                source=self.source,
            )
        return SigmaRegularExpression(val.original)


class SigmaRegularExpressionFlagModifier(
    SigmaValueModifier[SigmaRegularExpression, SigmaRegularExpression]
):
    """Generic base class for setting a regular expression flag including checks"""

    flag: ClassVar[SigmaRegularExpressionFlag]

    def modify(self, val: SigmaRegularExpression) -> SigmaRegularExpression:
        val.add_flag(self.flag)
        return val


class SigmaRegularExpressionIgnoreCaseFlagModifier(SigmaRegularExpressionFlagModifier):
    """Match regular expression case-insensitive."""

    flag: ClassVar[SigmaRegularExpressionFlag] = SigmaRegularExpressionFlag.IGNORECASE


class SigmaRegularExpressionMultilineFlagModifier(SigmaRegularExpressionFlagModifier):
    """Match regular expression across multiple lines."""

    flag: ClassVar[SigmaRegularExpressionFlag] = SigmaRegularExpressionFlag.MULTILINE


class SigmaRegularExpressionDotAllFlagModifier(SigmaRegularExpressionFlagModifier):
    """Regular expression dot matches all characters."""

    flag: ClassVar[SigmaRegularExpressionFlag] = SigmaRegularExpressionFlag.DOTALL


class SigmaCaseSensitiveModifier(SigmaValueModifier[SigmaString, SigmaCasedString]):
    def modify(self, val: SigmaString) -> SigmaCasedString:
        return SigmaCasedString.from_sigma_string(val)


class SigmaCIDRModifier(SigmaValueModifier[SigmaString, SigmaCIDRExpression]):
    """Treat value as IP (v4 or v6) CIDR network."""

    def modify(self, val: SigmaString) -> SigmaCIDRExpression:
        if len(self.applied_modifiers) > 0:
            raise SigmaValueError(
                "CIDR expression modifier only applicable to unmodified values",
                source=self.source,
            )
        return SigmaCIDRExpression(str(val), source=self.source)


class SigmaAllModifier(SigmaListModifier[Any, Any]):
    """Match all values of a list instead of any pf them."""

    def modify(self, val: Any) -> Any:
        from sigma.conditions import ConditionAND

        self.detection_item.value_linking = ConditionAND
        return val


class SigmaCompareModifier(SigmaValueModifier[SigmaNumber, SigmaCompareExpression]):
    """Base class for numeric comparison operator modifiers."""

    op: ClassVar[CompareOperators]

    def modify(self, val: SigmaNumber) -> SigmaCompareExpression:
        return SigmaCompareExpression(val, self.op, self.source)


class SigmaLessThanModifier(SigmaCompareModifier):
    """Numeric less than (<) matching."""

    op: ClassVar[CompareOperators] = CompareOperators.LT


class SigmaLessThanEqualModifier(SigmaCompareModifier):
    """Numeric less than or equal (<=) matching."""

    op: ClassVar[CompareOperators] = CompareOperators.LTE


class SigmaGreaterThanModifier(SigmaCompareModifier):
    """Numeric greater than (>) matching."""

    op: ClassVar[CompareOperators] = CompareOperators.GT


class SigmaGreaterThanEqualModifier(SigmaCompareModifier):
    """Numeric greater than or equal (>=) matching."""

    op: ClassVar[CompareOperators] = CompareOperators.GTE


class SigmaNotEqualModifier(SigmaCompareModifier):
    """Numeric not equal (!=) matching."""

    op: ClassVar[CompareOperators] = CompareOperators.NEQ


class SigmaFieldReferenceModifier(SigmaValueModifier[SigmaString, SigmaFieldReference]):
    """Modifiers a plain string into the field reference type."""

    def modify(self, val: SigmaString) -> SigmaFieldReference:
        if val.contains_special():
            raise SigmaValueError("Field references must not contain wildcards", source=self.source)
        return SigmaFieldReference(val.to_plain())


class SigmaExistsModifier(SigmaValueModifier[SigmaBool, SigmaExists]):
    """Modifies to check if the field name provided as value exists in the matched event."""

    def modify(self, val: SigmaBool) -> SigmaExists:
        if self.detection_item.field is None:
            raise SigmaValueError("Exists modifier must be applied to field", source=self.source)
        if len(self.applied_modifiers) > 0:
            raise SigmaValueError(
                "Exists modifier only applicable to unmodified boolean values",
                source=self.source,
            )
        return SigmaExists(val.boolean)


class SigmaExpandModifier(
    SigmaValueModifier[
        Union[SigmaString, SigmaRegularExpression], Union[SigmaString, SigmaRegularExpression]
    ]
):
    """
    Modifier for expansion of placeholders in values. It replaces placeholder strings (%something%)
    with stub objects that are later expanded to one or multiple strings or replaced with some SIEM
    specific list item or lookup by the processing pipeline.
    """

    def modify(
        self, val: Union[SigmaString, SigmaRegularExpression]
    ) -> Union[SigmaString, SigmaRegularExpression]:
        return val.insert_placeholders()


class SigmaTimestampModifier(SigmaValueModifier[SigmaNumber, SigmaTimestampPart]):
    """
    Base class for timestamp modifiers that parse the field as a datetime/timestamp and transform it to a specific part.
    """

    time_part_unit: ClassVar[TimestampPart]

    def modify(self, val: SigmaNumber) -> SigmaTimestampPart:
        return SigmaTimestampPart(self.time_part_unit, int(val.number))


class SigmaTimestampMinuteModifier(SigmaTimestampModifier):
    """
    Modifier that parses the field as a datetime/timestamp and transforms it to the minute number. Between 0 and 59.
    """

    time_part_unit: ClassVar[TimestampPart] = TimestampPart.MINUTE


class SigmaTimestampHourModifier(SigmaTimestampModifier):
    """
    Modifier that parses the field as a datetime/timestamp and transforms it to the hour number. Between 0 and 23.
    """

    time_part_unit: ClassVar[TimestampPart] = TimestampPart.HOUR


class SigmaTimestampDayModifier(SigmaTimestampModifier):
    """
    Modifier that parses the field as a datetime/timestamp and transforms it to the day of the month number. Between 1 and 31.
    """

    time_part_unit: ClassVar[TimestampPart] = TimestampPart.DAY


class SigmaTimestampWeekModifier(SigmaTimestampModifier):
    """
    Modifier that parses the field as a datetime/timestamp and transforms it to the week of the year number. Between 1 and 52.
    """

    time_part_unit: ClassVar[TimestampPart] = TimestampPart.WEEK


class SigmaTimestampMonthModifier(SigmaTimestampModifier):
    """
    Modifier that parses the field as a datetime/timestamp and transforms it to the month of the year number. Between 1 and 12.
    """

    time_part_unit: ClassVar[TimestampPart] = TimestampPart.MONTH


class SigmaTimestampYearModifier(SigmaTimestampModifier):
    """
    Modifier that parses the field as a datetime/timestamp and transforms it to the year number.
    """

    time_part_unit: ClassVar[TimestampPart] = TimestampPart.YEAR


# Mapping from modifier identifier strings to modifier classes
modifier_mapping: dict[str, Type[SigmaModifier[Any, Any]]] = {
    "all": SigmaAllModifier,
    "base64": SigmaBase64Modifier,
    "base64offset": SigmaBase64OffsetModifier,
    "cased": SigmaCaseSensitiveModifier,
    "cidr": SigmaCIDRModifier,
    "contains": SigmaContainsModifier,
    "day": SigmaTimestampDayModifier,
    "dotall": SigmaRegularExpressionDotAllFlagModifier,
    "endswith": SigmaEndswithModifier,
    "exists": SigmaExistsModifier,
    "expand": SigmaExpandModifier,
    "fieldref": SigmaFieldReferenceModifier,
    "gt": SigmaGreaterThanModifier,
    "gte": SigmaGreaterThanEqualModifier,
    "hour": SigmaTimestampHourModifier,
    "i": SigmaRegularExpressionIgnoreCaseFlagModifier,
    "ignorecase": SigmaRegularExpressionIgnoreCaseFlagModifier,
    "lt": SigmaLessThanModifier,
    "lte": SigmaLessThanEqualModifier,
    "m": SigmaRegularExpressionMultilineFlagModifier,
    "minute": SigmaTimestampMinuteModifier,
    "month": SigmaTimestampMonthModifier,
    "multiline": SigmaRegularExpressionMultilineFlagModifier,
    "re": SigmaRegularExpressionModifier,
    "s": SigmaRegularExpressionDotAllFlagModifier,
    "startswith": SigmaStartswithModifier,
    "week": SigmaTimestampWeekModifier,
    "wide": SigmaWideModifier,
    "windash": SigmaWindowsDashModifier,
    "year": SigmaTimestampYearModifier,
}

# Mapping from modifier class to identifier
reverse_modifier_mapping: dict[str, str] = {
    modifier_class.__name__: identifier for identifier, modifier_class in modifier_mapping.items()
}
