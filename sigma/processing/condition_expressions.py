from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, ClassVar, Dict, Iterable, Optional, Set, Union

from pyparsing import (
    ParseException,
    Word,
    alphanums,
    infix_notation,
    opAssoc,
    ParseResults,
)

from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError, SigmaPipelineConditionError
from sigma.processing.conditions import ProcessingCondition
from sigma.rule import SigmaDetectionItem, SigmaRule
import sigma


@dataclass
class ConditionExpression(ABC):
    """
    Class to store the condition expression.
    """

    location: int
    pipeline: "sigma.pipeline.SigmaPipeline" = field(init=False, repr=False, default=None)
    expression: Optional[str] = field(init=False, repr=False, compare=False, default=None)

    @classmethod
    @abstractmethod
    def from_parsed(cls, s: str, l: int, t: Union[ParseResults, list]) -> "ConditionExpression":
        """Create condition object from parse result"""
        pass

    @abstractmethod
    def resolve(self, conditions: Dict[str, ProcessingCondition]) -> Set[str]:
        """
        Resolve identifiers contained in the condition expression.

        :param conditions: Processing condition objects defined for condition expression.
        :return: Set of resolved identifiers.
        """
        pass

    @abstractmethod
    def match(self, item: Union[SigmaRule, SigmaCorrelationRule, SigmaDetectionItem]) -> bool:
        """
        Check if the condition expression matches the rule or detection item.

        :param rule: Sigma rule or correlation rule.
        :return: True if the condition expression matches the rule, False otherwise.
        """

    @abstractmethod
    def match_detection_item(self, detection_item: SigmaDetectionItem) -> bool:
        """
        Check if the condition expression matches the detection item.

        :param detection_item: Sigma detection item.
        :return: True if the condition expression matches the detection item, False otherwise.
        """

    @abstractmethod
    def match_field_name(self, field_name: str) -> bool:
        """
        Check if the condition expression matches the field name.

        :param field_name: Field name.
        :return: True if the condition expression matches the field name, False otherwise.
        """

    def set_expression(self, expression: str) -> None:
        self.expression = expression

    def set_pipeline(self, pipeline: "sigma.pipeline.SigmaPipeline") -> None:
        """
        Set the pipeline object for the condition expression.

        :param pipeline: Sigma pipeline object.
        """
        if self.pipeline is None:
            self.pipeline = pipeline
        else:
            raise SigmaError("Pipeline already set for condition expression.")


@dataclass
class ConditionIdentifier(ConditionExpression):
    """
    Class to store the condition identifier.
    """

    identifier: str
    _condition: ProcessingCondition = field(init=False, repr=False, default=None, compare=False)
    """
    The identifier of the condition.
    """

    @classmethod
    def from_parsed(cls, s: str, l: int, t: ParseResults) -> "ConditionIdentifier":
        expr = cls(l, t[0])
        expr.set_expression(s)
        return expr

    def resolve(self, conditions: Dict[str, ProcessingCondition]) -> Set[str]:
        """
        Resolve identifiers contained in the condition expression.

        :param conditions: Processing condition objects defined for condition expression.
        """
        try:
            self._condition = conditions[self.identifier]
            return {self.identifier}
        except KeyError:
            raise SigmaPipelineConditionError(
                self.expression,
                self.location,
                f"Condition identifier '{self.identifier}' not found.",
            )

    def match(self, item: Union[SigmaRule, SigmaCorrelationRule, SigmaDetectionItem]) -> bool:
        return self._condition.match(self.pipeline, item)

    def match_detection_item(self, detection_item: SigmaDetectionItem) -> bool:
        return self._condition.match_detection_item(self.pipeline, detection_item)

    def match_field_name(self, field_name: str) -> bool:
        return self._condition.match_field_name(self.pipeline, field_name)


@dataclass
class BinaryConditionOp(ConditionExpression):
    """
    Base class for logic condition operators.
    """

    left: ConditionExpression
    right: ConditionExpression
    _function: ClassVar[Callable[[Iterable[bool]], bool]]  # any or all

    @classmethod
    def from_parsed(cls, s: str, l: int, t: ParseResults) -> "BinaryConditionOp":
        expr = cls(l, t[0][0], t[0][2])
        expr.set_expression(s)
        return expr

    def resolve(self, conditions: Dict[str, ProcessingCondition]) -> Set[str]:
        """
        Resolve identifiers contained in the condition expression.

        :param conditions: Processing condition objects defined for condition expression.
        """
        return self.left.resolve(conditions).union(self.right.resolve(conditions))

    def match(self, item: Union[SigmaRule, SigmaCorrelationRule, SigmaDetectionItem]) -> bool:
        return self._function([self.left.match(item), self.right.match(item)])

    def match_detection_item(self, detection_item: SigmaDetectionItem) -> bool:
        return self._function(
            [
                self.left.match_detection_item(detection_item),
                self.right.match_detection_item(detection_item),
            ]
        )

    def match_field_name(self, field_name: str) -> bool:
        return self._function(
            [self.left.match_field_name(field_name), self.right.match_field_name(field_name)]
        )


@dataclass
class ConditionAND(BinaryConditionOp):
    """
    Class to store the AND condition operator.
    """

    _function: ClassVar[Callable[[Iterable[bool]], bool]] = all


@dataclass
class ConditionOR(BinaryConditionOp):
    """
    Class to store the OR condition operator.
    """

    _function: ClassVar[Callable[[Iterable[bool]], bool]] = any


@dataclass
class ConditionNOT(ConditionExpression):
    """
    Class to store the NOT condition operator.
    """

    condition: ConditionExpression

    @classmethod
    def from_parsed(cls, s: str, l: int, t: ParseResults) -> "ConditionNOT":
        expr = cls(l, t[0][1])
        expr.set_expression(s)
        return expr

    def resolve(self, conditions: Dict[str, ProcessingCondition]) -> None:
        """
        Resolve identifiers contained in the condition expression.

        :param conditions: Processing condition objects defined for condition expression.
        """
        return self.condition.resolve(conditions)

    def match(self, item: Union[SigmaRule, SigmaCorrelationRule, SigmaDetectionItem]) -> bool:
        return not self.condition.match(item)

    def match_detection_item(self, detection_item: SigmaDetectionItem) -> bool:
        return not self.condition.match_detection_item(detection_item)

    def match_field_name(self, field_name: str) -> bool:
        return not self.condition.match_field_name(field_name)


def parse_condition_expression(
    condition_expression: str,
    conditions: Dict[str, ProcessingCondition],
) -> Optional[str]:
    identifier = Word(alphanums + "_-")
    identifier.setParseAction(ConditionIdentifier.from_parsed)
    condition_parser = infix_notation(
        identifier,
        [
            ("not", 1, opAssoc.RIGHT, ConditionNOT.from_parsed),
            ("and", 2, opAssoc.LEFT, ConditionAND.from_parsed),
            ("or", 2, opAssoc.LEFT, ConditionOR.from_parsed),
        ],
    )
    try:
        parsed = condition_parser.parseString(condition_expression, parse_all=True)[0]
    except ParseException as e:
        raise SigmaPipelineConditionError(
            condition_expression, e.column, f"Error parsing condition expression: {e.msg}"
        )
    return parsed
