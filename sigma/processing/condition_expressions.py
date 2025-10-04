from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    ClassVar,
    Iterable,
    Optional,
    Union,
    cast,
    TYPE_CHECKING,
)

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
from sigma.processing.conditions.base import (
    DetectionItemProcessingCondition,
    FieldNameProcessingCondition,
    RuleProcessingCondition,
)
from sigma.rule import SigmaDetectionItem, SigmaRule

if TYPE_CHECKING:
    from sigma.processing.pipeline import ProcessingPipeline


@dataclass
class ConditionExpression(ABC):
    """
    Class to store the condition expression.
    """

    location: int
    pipeline: Optional["ProcessingPipeline"] = field(init=False, repr=False, default=None)
    expression: str = field(init=False, repr=False, compare=False, default="")

    @classmethod
    @abstractmethod
    def from_parsed(
        cls, s: str, l: int, t: Union[ParseResults, list[Any]]
    ) -> "ConditionExpression":
        """Create condition object from parse result"""
        pass

    @abstractmethod
    def resolve(self, conditions: dict[str, ProcessingCondition]) -> set[str]:
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
    def match_field_name(self, field_name: Optional[str]) -> bool:
        """
        Check if the condition expression matches the field name.

        :param field_name: Field name.
        :return: True if the condition expression matches the field name, False otherwise.
        """

    def set_expression(self, expression: str) -> None:
        self.expression = expression

    def set_pipeline(self, pipeline: "ProcessingPipeline") -> None:
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
    _condition: ProcessingCondition = field(
        init=False, repr=False, default_factory=ProcessingCondition, compare=False
    )
    """
    The identifier of the condition.
    """

    @classmethod
    def from_parsed(
        cls, s: str, l: int, t: Union[ParseResults, list[Any]]
    ) -> "ConditionIdentifier":
        expr = cls(l, t[0])
        expr.set_expression(s)
        return expr

    def resolve(self, conditions: dict[str, ProcessingCondition]) -> set[str]:
        """
        Resolve identifiers contained in the condition expression.

        :param conditions: Processing condition objects defined for condition expression.
        """
        try:
            self._condition = conditions[self.identifier]
            return {self.identifier}
        except KeyError:
            raise SigmaPipelineConditionError(
                f"Condition identifier '{self.identifier}' not found.",
                self.expression,
                self.location,
            )

    def match(self, item: Union[SigmaRule, SigmaCorrelationRule, SigmaDetectionItem]) -> bool:
        if isinstance(self._condition, RuleProcessingCondition) and isinstance(
            item, (SigmaRule, SigmaCorrelationRule)
        ):
            return self._condition.match(item)
        elif isinstance(self._condition, DetectionItemProcessingCondition) and isinstance(
            item, SigmaDetectionItem
        ):
            return self._condition.match(item)
        else:
            raise SigmaPipelineConditionError(
                f"Condition identifier '{self.identifier}' type {type(self._condition).__name__} does not match to the item type {type(item).__name__}.",
                self.expression,
                self.location,
            )

    def match_detection_item(self, detection_item: SigmaDetectionItem) -> bool:
        if not isinstance(self._condition, FieldNameProcessingCondition):
            raise SigmaPipelineConditionError(
                f"Condition identifier '{self.identifier}' type {type(self._condition).__name__} does not match to the item type {type(detection_item).__name__}.",
                self.expression,
                self.location,
            )
        return self._condition.match_detection_item(detection_item)

    def match_field_name(self, field_name: Optional[str]) -> bool:
        if not isinstance(self._condition, FieldNameProcessingCondition):
            raise SigmaPipelineConditionError(
                f"Condition identifier '{self.identifier}' type {type(self._condition).__name__} does not match to the item type {type(field_name).__name__}.",
                self.expression,
                self.location,
            )
        return self._condition.match_field_name(field_name)


@dataclass
class BinaryConditionOp(ConditionExpression):
    """
    Base class for logic condition operators.
    """

    left: ConditionExpression
    right: ConditionExpression
    _function: ClassVar[Callable[[Iterable[bool]], bool]]  # any or all

    @classmethod
    def from_parsed(cls, s: str, l: int, t: Union[ParseResults, list[Any]]) -> "BinaryConditionOp":
        expr = cls(l, t[0][0], t[0][2])
        expr.set_expression(s)
        return expr

    def resolve(self, conditions: dict[str, ProcessingCondition]) -> set[str]:
        """
        Resolve identifiers contained in the condition expression.

        :param conditions: Processing condition objects defined for condition expression.
        """
        return self.left.resolve(conditions).union(self.right.resolve(conditions))

    def match(self, item: Union[SigmaRule, SigmaCorrelationRule, SigmaDetectionItem]) -> bool:
        return self.__class__._function([self.left.match(item), self.right.match(item)])

    def match_detection_item(self, detection_item: SigmaDetectionItem) -> bool:
        return self.__class__._function(
            [
                self.left.match_detection_item(detection_item),
                self.right.match_detection_item(detection_item),
            ]
        )

    def match_field_name(self, field_name: Optional[str]) -> bool:
        return self.__class__._function(
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
    def from_parsed(cls, s: str, l: int, t: Union[ParseResults, list[Any]]) -> "ConditionNOT":
        expr = cls(l, t[0][1])
        expr.set_expression(s)
        return expr

    def resolve(self, conditions: dict[str, ProcessingCondition]) -> set[str]:
        """
        Resolve identifiers contained in the condition expression.

        :param conditions: Processing condition objects defined for condition expression.
        """
        return self.condition.resolve(conditions)

    def match(self, item: Union[SigmaRule, SigmaCorrelationRule, SigmaDetectionItem]) -> bool:
        return not self.condition.match(item)

    def match_detection_item(self, detection_item: SigmaDetectionItem) -> bool:
        return not self.condition.match_detection_item(detection_item)

    def match_field_name(self, field_name: Optional[str]) -> bool:
        return not self.condition.match_field_name(field_name)


def parse_condition_expression(
    condition_expression: str,
) -> ConditionExpression:
    identifier = Word(alphanums + "_-")
    identifier.set_parse_action(ConditionIdentifier.from_parsed)
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
            f"Error parsing condition expression: {e.msg}",
            condition_expression,
            e.column,
        )
    return cast(ConditionExpression, parsed)
