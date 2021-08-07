from enum import Enum, auto
from dataclasses import dataclass, field
from abc import ABC
import re
from pyparsing import Word, alphanums, Keyword, infixNotation, opAssoc, ParseResults
from typing import ClassVar, List, Union
from sigma.types import SigmaType
from sigma.exceptions import SigmaConditionError
import sigma

@dataclass
class ConditionItem(ABC):
    arg_count : ClassVar[int]
    token_list : ClassVar[bool] = False     # determines if the value passed as tokenized is a ParseResult or a simple list object
    args : List[Union["ConditionItem", "ConditionFieldEqualsValueExpression", "ConditionFieldValueInExpression", "ConditionValueExpression"]]

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

    def postprocess(self, detections : "sigma.rule.SigmaDetections") -> "ConditionItem":
        """
        Postprocess condition parse tree after initial parsing. In this stage the detections
        are available, this allows to resolve references to detections into concrete conditions.

        This function should finally return itself or an instance of a ConditionItem subclass object.
        """
        self.args = [
            arg.postprocess(detections)
            for arg in self.args
        ]
        return self

@dataclass
class ConditionOR(ConditionItem):
    arg_count : ClassVar[int] = 2

@dataclass
class ConditionAND(ConditionItem):
    arg_count : ClassVar[int] = 2

@dataclass
class ConditionNOT(ConditionItem):
    arg_count : ClassVar[int] = 1

@dataclass
class ConditionIdentifier(ConditionItem):
    arg_count : ClassVar[int] = 1
    token_list : ClassVar[bool] = True
    identifier : str = field(init=False)

    def __post_init__(self):
        self.identifier = self.args[0]

    def postprocess(self, detections : "sigma.rule.SigmaDetections") -> Union[ConditionAND, ConditionOR]:
        """Converts an identifier into a condition with SigmaDetectionItems at its leaf nodes."""
        try:
            detection = detections[self.identifier]
        except KeyError:
            raise SigmaConditionError(f"Detection '{ self.identifier }' not defined in detections")
        return detection.postprocess(detections)

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

    def postprocess(self, detections : "sigma.rule.SigmaDetections") -> Union[ConditionAND, ConditionOR]:
        """Converts selector into an AND or OR condition"""
        r = re.compile(self.pattern.replace("*", ".*"))
        ids = [
            ConditionIdentifier([ identifier ])
            for identifier in detections.detections.keys()
            if r.match(identifier)
        ]
        cond = self.cond_class(ids)
        return cond.postprocess(detections)

@dataclass
class ConditionFieldEqualsValueExpression:
    """Field equals value"""
    field : str
    value : SigmaType

@dataclass
class ConditionFieldValueInExpression:
    """Field has value contained in list"""
    field : str
    value : List[SigmaType]

@dataclass
class ConditionValueExpression:
    """Match on value without field"""
    value : SigmaType

identifier = Word(alphanums + "_-")
identifier.setParseAction(ConditionIdentifier.from_parsed)

quantifier = Keyword("1") | Keyword("any") | Keyword("all")
identifier_pattern = Word(alphanums + "*")
selector = quantifier + Keyword("of") + identifier_pattern
selector.setParseAction(ConditionSelector.from_parsed)

operand = selector | identifier
condition = infixNotation(
    operand,
    [
        ("not", 1, opAssoc.RIGHT, ConditionNOT.from_parsed),
        ("and", 2, opAssoc.LEFT, ConditionAND.from_parsed),
        ("or", 2, opAssoc.LEFT, ConditionOR.from_parsed),
    ]
)

@dataclass
class SigmaCondition:
    condition : str
    detections : "sigma.rule.SigmaDetections"

    @property
    def parsed(self):
        """
        Parse on first access on parsed condition tree.

        The main reason for this behavior is that rule processing occurrs after rule-parsing time. Therefore,
        the condition parsing has to be delayed after the processing, as field name or value changes have to be
        reflected. It turned out, that the access time is most appropriate. No caching is done to reflect the current
        state of the rule.
        """
        parsed = condition.parseString(self.condition)[0]
        return parsed.postprocess(self.detections)

ConditionType = Union[
    ConditionOR,
    ConditionAND,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
    ConditionFieldValueInExpression,
    ConditionValueExpression,
]