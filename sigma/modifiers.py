from abc import ABC, abstractmethod
import re
from typing import ClassVar, Optional, Union, List, Sequence, Dict, Type, get_origin, get_args, get_type_hints
from collections.abc import Sequence as SequenceABC
from base64 import b64encode
from sigma.types import Placeholder, SigmaExpansion, SigmaType, SigmaString, SigmaNumber, SpecialChars, SigmaRegularExpression, SigmaCompareExpression, SigmaCIDRExpression
from sigma.conditions import ConditionAND
from sigma.exceptions import SigmaRuleLocation, SigmaTypeError, SigmaValueError
import sigma

### Base Classes ###
class SigmaModifier(ABC):
    """Base class for all Sigma modifiers"""
    detection_item : "sigma.rule.SigmaDetectionItem"
    applied_modifiers : List["SigmaModifier"]

    def __init__(self, detection_item : "sigma.rule.SigmaDetectionItem", applied_modifiers : List["SigmaModifier"], source : Optional[SigmaRuleLocation] = None):
        self.detection_item = detection_item
        self.applied_modifiers = applied_modifiers
        self.source = source

    def type_check(self, val : Union[SigmaType, Sequence[SigmaType]], explicit_type=None) -> bool:
        th = explicit_type or get_type_hints(self.modify)["val"]      # get type annotation from val parameter of apply method or explicit_type parameter
        to = get_origin(th)                         # get possible generic type of type hint
        if to is None:                              # Plain type in annotation
            return isinstance(val, th)
        elif to is Union:                           # type hint is Union of multiple types, check if val is one of them
            for t in get_args(th):
                if isinstance(val, t):
                    return True
            return False
        elif to is SequenceABC:                     # type hint is sequence
            inner_type = get_args(th)[0]
            return all([
                self.type_check(item, explicit_type=inner_type)
                for item in val
            ])

    @abstractmethod
    def modify(self, val : Union[SigmaType, Sequence[SigmaType]]) -> Union[SigmaType, List[SigmaType]]:
        """This method should be overridden with the modifier implementation."""

    def apply(self, val : Union[SigmaType, Sequence[SigmaType]]) -> List[SigmaType]:
        """
        Modifier entry point containing the default operations:
        * Type checking
        * Ensure returned value is a list
        * Handle values of SigmaExpansion objects separately.
        """
        if isinstance(val, SigmaExpansion):     # Handle each SigmaExpansion item separately
            return [
                SigmaExpansion([
                    va
                    for v in val.values
                    for va in self.apply(v)
                ])
            ]
        else:
            if not self.type_check(val):
                raise SigmaTypeError(f"Modifier {self.__class__.__name__} incompatible to value type of '{ val }'", source=self.source)
            r = self.modify(val)
            if isinstance(r, List):
                return r
            else:
                return [r]

class SigmaValueModifier(SigmaModifier):
    """Base class for all modifiers that handle each value for the modifier scope separately"""
    @abstractmethod
    def modify(self, val : SigmaType) -> Union[SigmaType, List[SigmaType]]:
        """This method should be overridden with the modifier implementation."""

class SigmaListModifier(SigmaModifier):
    """Base class for all modifiers that handle all values for the modifier scope as a whole."""
    @abstractmethod
    def modify(self, val : Sequence[SigmaType]) -> Union[SigmaType, List[SigmaType]]:
        """This method should be overridden with the modifier implementation."""

### Modifier Implementations ###
class SigmaContainsModifier(SigmaValueModifier):
    """Puts wildcards around a string to match it somewhere inside another string instead of as a whole."""
    def modify(self, val : Union[SigmaString, SigmaRegularExpression]) -> Union[SigmaString, SigmaRegularExpression]:
        if isinstance(val, SigmaString):
            if not val.startswith(SpecialChars.WILDCARD_MULTI):
                val = SpecialChars.WILDCARD_MULTI + val
            if not val.endswith(SpecialChars.WILDCARD_MULTI):
                val += SpecialChars.WILDCARD_MULTI
        elif isinstance(val, SigmaRegularExpression):
            if val.regexp[:2] != '.*' and val.regexp[0] != "^":
                val.regexp = '.*' + val.regexp
            if val.regexp[-2:] != '.*' and val.regexp[-1] != "$":
                val.regexp = val.regexp + '.*'
            val.compile()
        return val

class SigmaStartswithModifier(SigmaValueModifier):
    """Puts a wildcard at the end of a string to match arbitrary values after the given prefix."""
    def modify(self, val : Union[SigmaString, SigmaRegularExpression]) -> Union[SigmaString, SigmaRegularExpression]:
        if isinstance(val, SigmaString):
            if not val.endswith(SpecialChars.WILDCARD_MULTI):
                val += SpecialChars.WILDCARD_MULTI
        elif isinstance(val, SigmaRegularExpression):
            if val.regexp[-2:] != '.*' and val.regexp[-1] != "$":
                val.regexp = val.regexp + '.*'
            val.compile()
        return val

class SigmaEndswithModifier(SigmaValueModifier):
    """Puts a wildcard before a string to match arbitrary values before it."""
    def modify(self, val : Union[SigmaString, SigmaRegularExpression]) -> Union[SigmaString, SigmaRegularExpression]:
        if isinstance(val, SigmaString):
            if not val.startswith(SpecialChars.WILDCARD_MULTI):
                val = SpecialChars.WILDCARD_MULTI + val
        elif isinstance(val, SigmaRegularExpression):
            if val.regexp[:2] != '.*' and val.regexp[0] != "^":
                val.regexp = '.*' + val.regexp
            val.compile()
        return val

class SigmaBase64Modifier(SigmaValueModifier):
    """Encode string as Base64 value."""
    def modify(self, val : SigmaString) -> SigmaString:
        if val.contains_special():
            raise SigmaValueError("Base64 encoding of strings with wildcards is not allowed", source=self.source)
        return SigmaString(b64encode(bytes(val)).decode())

class SigmaBase64OffsetModifier(SigmaValueModifier):
    """
    Encode string as Base64 value with different offsets to match it at different locations in
    encoded form.
    """
    start_offsets = (0, 2, 3)
    end_offsets = (None, -3, -2)

    def modify(self, val : SigmaString) -> SigmaExpansion:
        if val.contains_special():
            raise SigmaValueError("Base64 encoding of strings with wildcards is not allowed", source=self.source)
        return SigmaExpansion([
            SigmaString(b64encode(
                i * b' ' + bytes(val)
                )[
                    self.start_offsets[i]:
                    self.end_offsets[(len(val) + i) % 3]
                ].decode()
            )
            for i in range(3)
            ])

class SigmaWideModifier(SigmaValueModifier):
    """Encode string as wide string (UTF-16LE)."""
    def modify(self, val : SigmaString) -> SigmaString:
        r = list()
        for item in val.s:
            if isinstance(item, str):       # put 0x00 after each character by encoding it to utf-16le and decoding it as utf-8
                try:
                    r.append(item.encode("utf-16le").decode("utf-8"))
                except UnicodeDecodeError:         # this method only works for ascii characters
                    raise SigmaValueError(f"Wide modifier only allowed for ascii strings, input string '{str(val)}' isn't one", source=self.source)
            else:                           # just append special characters without further handling
                r.append(item)

        s = SigmaString()
        s.s = tuple(r)
        return(s)

class SigmaWindowsDashModifier(SigmaValueModifier):
    """
    Expand parameter characters / and - that are often interchangeable in Windows into the other
    form if it appears between word boundaries. E.g. in -param-name the first dash will be expanded
    into /param-name while the second dash is left untouched.
    """
    def modify(self, val : SigmaString) -> SigmaExpansion:
        def callback(p : Placeholder):
            if p.name == "_windash":
                yield from ("-", "/")
            else:
                yield p
        return SigmaExpansion(
            val.replace_with_placeholder(re.compile("\\B[-/]\\b"), "_windash") \
                .replace_placeholders(callback)
        )

class SigmaRegularExpressionModifier(SigmaValueModifier):
    def modify(self, val : SigmaString) -> SigmaRegularExpression:
        if len(self.applied_modifiers) > 0:
            raise SigmaValueError("Regular expression modifier only applicable to unmodified values", source=self.source)
        return SigmaRegularExpression(val.original)

class SigmaCIDRModifier(SigmaValueModifier):
    def modify(self, val : SigmaString) -> SigmaCIDRExpression:
        if len(self.applied_modifiers) > 0:
            raise SigmaValueError("CIDR expression modifier only applicable to unmodified values", source=self.source)
        return SigmaCIDRExpression(str(val), source=self.source)

class SigmaAllModifier(SigmaListModifier):
    def modify(self, val : Sequence[SigmaType]) -> List[SigmaType]:
        self.detection_item.value_linking = ConditionAND
        return val

class SigmaCompareModifier(SigmaValueModifier):
    """Base class for numeric comparison operator modifiers."""
    op : ClassVar[SigmaCompareExpression.CompareOperators]

    def modify(self, val : SigmaNumber) -> SigmaCompareExpression:
        return SigmaCompareExpression(val, self.op, self.source)

class SigmaLessThanModifier(SigmaCompareModifier):
    op : ClassVar[SigmaCompareExpression.CompareOperators] = SigmaCompareExpression.CompareOperators.LT

class SigmaLessThanEqualModifier(SigmaCompareModifier):
    op : ClassVar[SigmaCompareExpression.CompareOperators] = SigmaCompareExpression.CompareOperators.LTE

class SigmaGreaterThanModifier(SigmaCompareModifier):
    op : ClassVar[SigmaCompareExpression.CompareOperators] = SigmaCompareExpression.CompareOperators.GT

class SigmaGreaterThanEqualModifier(SigmaCompareModifier):
    op : ClassVar[SigmaCompareExpression.CompareOperators] = SigmaCompareExpression.CompareOperators.GTE

class SigmaExpandModifier(SigmaValueModifier):
    """
    Modifier for expansion of placeholders in values. It replaces placeholder strings (%something%)
    with stub objects that are later expanded to one or multiple strings or replaced with some SIEM
    specific list item or lookup by the processing pipeline.
    """
    def modify(self, val : SigmaString) -> SigmaString:
        return val.insert_placeholders()

# Mapping from modifier identifier strings to modifier classes
modifier_mapping : Dict[str, Type[SigmaModifier]] = {
    "contains"      : SigmaContainsModifier,
    "startswith"    : SigmaStartswithModifier,
    "endswith"      : SigmaEndswithModifier,
    "base64"        : SigmaBase64Modifier,
    "base64offset"  : SigmaBase64OffsetModifier,
    "wide"          : SigmaWideModifier,
    "windash"       : SigmaWindowsDashModifier,
    "re"            : SigmaRegularExpressionModifier,
    "cidr"          : SigmaCIDRModifier,
    "all"           : SigmaAllModifier,
    "lt"            : SigmaLessThanModifier,
    "lte"           : SigmaLessThanEqualModifier,
    "gt"            : SigmaGreaterThanModifier,
    "gte"           : SigmaGreaterThanEqualModifier,
    "expand"        : SigmaExpandModifier,
}

# Mapping from modifier class to identifier
reverse_modifier_mapping : Dict[str, str] = {
    modifier_class.__name__: identifier
    for identifier, modifier_class in modifier_mapping.items()
}