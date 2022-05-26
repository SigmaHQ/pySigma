from dataclasses import dataclass, field
from abc import ABC
import re
from sigma.processing.tracking import ProcessingItemTrackingMixin
from pyparsing import Word, alphanums, Keyword, infix_notation, opAssoc, ParseResults, ParseException
from typing import ClassVar, List, Literal, Optional, Union, Type
from sigma.types import SigmaType
from sigma.exceptions import SigmaConditionError, SigmaRuleLocation
import sigma

@dataclass
class ParentChainMixin:
    """Class to resolve parent chains of condition objects."""
    parent : Optional["ConditionItem"] = field(init=False, compare=False, default=None)      # Link to parent containing this condition
    operator : ClassVar[bool] = False       # is class a boolean operator?

    def parent_chain(self) -> List["ConditionType"]:
        """Return complete parent chain of condition object."""
        if self.parent is None:     # root of chain, return empty list
            return []
        else:
            return [ self.parent ] + self.parent.parent_chain()

    def parent_chain_classes(self) -> List[Type["ConditionType"]]:
        """Return classes of parent chain."""
        return [
            item.__class__
            for item in self.parent_chain()
        ]

    def parent_chain_condition_classes(self) -> List[Type["ConditionType"]]:
        """Only return list of parent chain condition classes which are boolean operators."""
        return [
            item
            for item in self.parent_chain_classes()
            if item.operator
        ]

    def parent_condition_chain_contains(self, cond_class : Type["ConditionType"]):
        """Determines if the class cond_class is contained in parent condition class chain."""
        return cond_class in self.parent_chain_condition_classes()

    def postprocess(self, detections : "sigma.rule.SigmaDetections", parent : Optional["ConditionItem"] = None, source : Optional[SigmaRuleLocation] = None) -> "ConditionItem":
        """
        Minimal default postprocessing implementation for classes which don't bring their own postprocess method.
        Just sets the parent and source property.
        """
        self.parent = parent
        try:
            self.source = source or self.source
        except AttributeError:
            self.source = None
        return self

@dataclass
class ConditionItem(ParentChainMixin, ABC):
    arg_count : ClassVar[int]
    token_list : ClassVar[bool] = False     # determines if the value passed as tokenized is a ParseResult or a simple list object
    args : List[Union["ConditionItem", "ConditionFieldEqualsValueExpression", "ConditionValueExpression"]]
    source : Optional[SigmaRuleLocation] = field(default=None, compare=False)

    @classmethod
    def from_parsed(cls, s : str, l : int, t : Union[ParseResults, list]) -> "ConditionItem":
        """Create condition object from parse result"""
        if cls.arg_count == 1:
            if cls.token_list:
                args = [ t[0] ]
            else:
                args = [ t[0][-1] ]
        elif cls.arg_count > 1:
            if cls.token_list:
                args = t[0::2]
            else:
                args = t[0][0::2]
        else:                   # pragma: no cover
            args = list()       # this case can only happen if broken classes are defined
        return [cls(args)]

    def postprocess(self, detections : "sigma.rule.SigmaDetections", parent : Optional["ConditionItem"] = None, source : Optional[SigmaRuleLocation] = None) -> "ConditionItem":
        """
        Postprocess condition parse tree after initial parsing. In this stage the detections
        are available, this allows to resolve references to detections into concrete conditions.

        This function should finally return itself or an instance of a ConditionItem subclass object.
        """
        super().postprocess(detections, parent, source)
        self.args = [
            arg.postprocess(detections, self, source)
            for arg in self.args
        ]
        self.args = list(       # filter all None entries from argument list. These can be caused by empty detection items from applied transformations.
            filter(
                lambda arg: arg is not None,
                self.args
            )
        )
        if self.arg_count > 1 and len(self.args) == 1:  # multi-argument condition (AND, OR) has only one argument left: return the single argument
            return self.args[0]
        else:
            return self

@dataclass
class ConditionOR(ConditionItem):
    arg_count : ClassVar[int] = 2
    operator : ClassVar[bool] = True

@dataclass
class ConditionAND(ConditionItem):
    arg_count : ClassVar[int] = 2
    operator : ClassVar[bool] = True

@dataclass
class ConditionNOT(ConditionItem):
    arg_count : ClassVar[int] = 1
    operator : ClassVar[bool] = True

@dataclass
class ConditionIdentifier(ConditionItem):
    arg_count : ClassVar[int] = 1
    token_list : ClassVar[bool] = True
    identifier : str = field(init=False)

    def __post_init__(self):
        self.identifier = self.args[0]

    def postprocess(self, detections : "sigma.rule.SigmaDetections", parent : Optional["ConditionItem"] = None, source : Optional[SigmaRuleLocation] = None) -> Union[ConditionAND, ConditionOR]:
        """Converts an identifier into a condition with SigmaDetectionItems at its leaf nodes."""
        self.parent = parent
        try:
            detection = detections[self.identifier]
        except KeyError:
            raise SigmaConditionError(f"Detection '{ self.identifier }' not defined in detections", source=source)
        return detection.postprocess(detections, self)

@dataclass
class ConditionSelector(ConditionItem):
    arg_count : ClassVar[int] = 2
    token_list : ClassVar[bool]  = True
    cond_class : Union[ConditionAND, ConditionOR] = field(init=False)
    pattern : str = field(init=False)

    def __post_init__(self):
        if self.args[0] in ["1", "any"]:
            self.cond_class = ConditionOR
        else:
            self.cond_class = ConditionAND
        self.pattern = self.args[1]

    def postprocess(self, detections : "sigma.rule.SigmaDetections", parent : Optional["ConditionItem"] = None, source : Optional[SigmaRuleLocation] = None) -> Union[ConditionAND, ConditionOR]:
        """Converts selector into an AND or OR condition"""
        self.parent = parent

        if self.pattern == "them":
            r = re.compile(".*")
        else:
            r = re.compile(self.pattern.replace("*", ".*"))

        ids = [
            ConditionIdentifier([ identifier ])
            for identifier in detections.detections.keys()
            if r.match(identifier)
        ]
        cond = self.cond_class(ids)
        return cond.postprocess(detections, parent, source)

@dataclass
class ConditionFieldEqualsValueExpression(ParentChainMixin):
    """Field equals value"""
    field : str
    value : SigmaType

@dataclass
class ConditionValueExpression(ParentChainMixin):
    """Match on value without field"""
    value : SigmaType

identifier = Word(alphanums + "_-")
identifier.setParseAction(ConditionIdentifier.from_parsed)

quantifier = Keyword("1") | Keyword("any") | Keyword("all")
identifier_pattern = Word(alphanums + "*_")
selector = quantifier + Keyword("of") + identifier_pattern
selector.setParseAction(ConditionSelector.from_parsed)

operand = selector | identifier
condition = infix_notation(
    operand,
    [
        ("not", 1, opAssoc.RIGHT, ConditionNOT.from_parsed),
        ("and", 2, opAssoc.LEFT, ConditionAND.from_parsed),
        ("or", 2, opAssoc.LEFT, ConditionOR.from_parsed),
    ]
)

@dataclass
class SigmaCondition(ProcessingItemTrackingMixin):
    condition : str
    detections : "sigma.rule.SigmaDetections"
    source : Optional[SigmaRuleLocation] = field(default=None, compare=False)

    @property
    def parsed(self):
        """
        Parse on first access on parsed condition tree.

        The main reason for this behavior is that rule processing occurrs after rule-parsing time. Therefore,
        the condition parsing has to be delayed after the processing, as field name or value changes have to be
        reflected. It turned out, that the access time is most appropriate. No caching is done to reflect the current
        state of the rule.
        """
        try:
            parsed = condition.parseString(self.condition, parse_all=True)[0]
            return parsed.postprocess(self.detections, source=self.source)
        except ParseException as e:
            raise SigmaConditionError(str(e))

ConditionType = Union[
    ConditionOR,
    ConditionAND,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
    ConditionValueExpression,
]
