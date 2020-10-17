from abc import ABC, abstractmethod
from typing import Union, List, Sequence, get_origin, get_args, get_type_hints
from collections.abc import Sequence as SequenceABC
from sigma.types import SigmaType, SigmaString, SpecialChars
from sigma.exceptions import SigmaTypeError

### Base Classes ###
class SigmaModifier(ABC):
    """Base class for all Sigma modifiers"""
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
        """
        if not self.type_check(val):
            raise SigmaTypeError(f"Modifier {self.__class__.__name__} incompatible to value type of '{ val }'")
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
    def modify(self, val : SigmaString) -> SigmaString:
        if not val.startswith(SpecialChars.WILDCARD_MULTI):
            val = SpecialChars.WILDCARD_MULTI + val
        if not val.endswith(SpecialChars.WILDCARD_MULTI):
            val += SpecialChars.WILDCARD_MULTI
        return val