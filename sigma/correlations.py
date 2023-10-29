from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional
import sigma.exceptions as sigma_exceptions
from sigma.exceptions import SigmaRuleLocation, SigmaTimespanError
from sigma.rule import EnumLowercaseStringMixin, SigmaRule, SigmaRuleBase


class SigmaCorrelationType(EnumLowercaseStringMixin, Enum):
    """
    Supported correlation types.
    """

    EVENT_COUNT = auto()
    VALUE_COUNT = auto()
    TEMPORAL = auto()


@dataclass
class SigmaRuleReference:
    """
    Reference to a Sigma rule. Initially this only contains the plain reference as string that is
    then resolved into a rule reference.
    """

    reference: str
    rule: SigmaRule = field(init=False, repr=False, compare=False)


class SigmaCorrelationConditionOperator(Enum):
    LT = auto()
    LTE = auto()
    GT = auto()
    GTE = auto()


@dataclass
class SigmaCorrelationCondition:
    op: SigmaCorrelationConditionOperator
    count: int
    source: Optional[SigmaRuleLocation] = field(default=None, compare=False)

    @classmethod
    def from_dict(
        cls, d: dict, source: Optional[SigmaRuleLocation] = None
    ) -> "SigmaCorrelationCondition":
        if len(d) != 1:
            raise sigma_exceptions.SigmaCorrelationConditionError(
                f"Sigma correlation condition must have exactly one item"
            )

        cond_def = list(d.items())[0]
        try:
            cond_op = SigmaCorrelationConditionOperator[cond_def[0].upper()]
        except KeyError:
            raise sigma_exceptions.SigmaCorrelationConditionError(
                f"Sigma correlation condition operator '{ cond_def[0] }' is invalid"
            )

        try:
            cond_count = int(cond_def[1])
        except ValueError:
            raise sigma_exceptions.SigmaCorrelationConditionError(
                f"'{ cond_def[1] }' is no valid Sigma correlation condition count"
            )

        return cls(op=cond_op, count=cond_count)

    def to_dict(self) -> dict:
        return {self.op.name.lower(): self.count}


def parse_timespan(timespan: str, source: Optional[SigmaRuleLocation] = None) -> int:
    """
    Parses a string representing a time span and returns the equivalent number of seconds.

    Args:
        timespan (str): A string representing a time span, e.g. "5m", "1h", "3d", etc.

    Returns:
        int: The equivalent number of seconds for the given time span.

    Raises:
        sigma_exceptions.SigmaTimespanError: If the given time span is invalid.
    """
    try:
        return (
            int(timespan[:-1])
            * {
                "s": 1,
                "m": 60,
                "h": 3600,
                "d": 86400,
                "w": 604800,
                "M": 2629746,
                "y": 31556952,
            }[timespan[-1]]
        )
    except (ValueError, KeyError):
        raise sigma_exceptions.SigmaTimespanError(
            f"Timespan '{ timespan }' is invalid.", source=source
        )


def seconds_to_timespan(seconds: int) -> str:
    """
    Converts a number of seconds into a time span string.

    Args:
        seconds (int): The number of seconds to convert.

    Returns:
        str: The time span string.
    """
    if seconds % 31556952 == 0:
        return f"{ seconds // 31556952 }y"
    elif seconds % 2629746 == 0:
        return f"{ seconds // 2629746 }M"
    elif seconds % 604800 == 0:
        return f"{ seconds // 604800 }w"
    elif seconds % 86400 == 0:
        return f"{ seconds // 86400 }d"
    elif seconds % 3600 == 0:
        return f"{ seconds // 3600 }h"
    elif seconds % 60 == 0:
        return f"{ seconds // 60 }m"
    else:
        return f"{ seconds }s"


@dataclass
class SigmaCorrelationRule(SigmaRuleBase):
    type: SigmaCorrelationType = None
    rules: List[SigmaRuleReference] = field(default_factory=list)
    timespan: int = (
        0  # Time frame in seconds that has to be converted into target-specific notation.
    )
    group_by: Optional[List[str]] = None
    ordered: bool = False
    condition: Optional[SigmaCorrelationCondition] = None
    source: Optional[SigmaRuleLocation] = field(default=None, compare=False)

    def __post_init__(self):
        super().__post_init__()
        if self.type != SigmaCorrelationType.TEMPORAL and self.condition is None:
            raise sigma_exceptions.SigmaCorrelationRuleError(
                f"Non-temporal Sigma correlation rule without condition", source=self.source
            )

    @classmethod
    def from_dict(
        cls,
        rule: dict,
        collect_errors: bool = False,
        source: Optional[SigmaRuleLocation] = None,
    ) -> "SigmaCorrelationRule":
        kwargs, errors = super().from_dict(rule, collect_errors, source)
        correlation_rule = rule.get("correlation", dict())

        # Correlation type
        correlation_type = correlation_rule.get("type")
        if correlation_type is not None:
            try:
                correlation_type = SigmaCorrelationType[correlation_type.upper()]
            except KeyError:
                errors.append(
                    sigma_exceptions.SigmaCorrelationTypeError(
                        f"'{ correlation_type }' is no valid Sigma correlation type", source=source
                    )
                )
        else:  # no correlation type provided
            errors.append(
                sigma_exceptions.SigmaCorrelationTypeError(
                    f"Sigma correlation rule without type", source=source
                )
            )

        # Rules
        rules = correlation_rule.get("rules")
        if rules is not None:
            if isinstance(rules, str):
                rules = [SigmaRuleReference(rules)]
            elif isinstance(rules, list):
                rules = [SigmaRuleReference(rule) for rule in rules]
            else:
                errors.append(
                    sigma_exceptions.SigmaCorrelationRuleError(
                        f"Rule reference must be plain string or list.", source=source
                    )
                )
        else:
            errors.append(
                sigma_exceptions.SigmaCorrelationRuleError(
                    f"Sigma correlation rule without rule references", source=source
                )
            )

        # Group by
        group_by = correlation_rule.get("group-by")
        if group_by is not None:
            if isinstance(group_by, str):
                group_by = [group_by]
            if isinstance(group_by, list):
                group_by = [str(group) for group in group_by]
            else:
                errors.append(
                    sigma_exceptions.SigmaCorrelationRuleError(
                        f"Sigma correlation group-by definition must be string or list",
                        source=source,
                    )
                )

        # Time span
        timespan = correlation_rule.get("timespan")
        if timespan is not None:
            try:
                timespan = parse_timespan(timespan)
            except SigmaTimespanError as e:
                errors.append(e)
        else:
            errors.append(
                sigma_exceptions.SigmaCorrelationRuleError(
                    f"Sigma correlation rule without timespan", source=source
                )
            )

        # Ordered
        ordered = correlation_rule.get("ordered")
        if ordered is not None:
            if not isinstance(ordered, bool):
                errors.append(
                    sigma_exceptions.SigmaCorrelationRuleError(
                        f"Sigma correlation ordered definition must be boolean", source=source
                    )
                )
        else:
            ordered = False

        # Condition
        condition = correlation_rule.get("condition")
        if condition is not None:
            if isinstance(condition, dict):
                condition = SigmaCorrelationCondition.from_dict(condition, source=source)
            else:
                errors.append(
                    sigma_exceptions.SigmaCorrelationRuleError(
                        f"Sigma correlation condition definition must be a dict", source=source
                    )
                )
        elif correlation_type != SigmaCorrelationType.TEMPORAL:
            errors.append(
                sigma_exceptions.SigmaCorrelationRuleError(
                    f"Non-temporal Sigma correlation rule without condition", source=source
                )
            )

        if not collect_errors and errors:
            raise errors[0]

        return cls(
            type=correlation_type,
            rules=rules,
            timespan=timespan,
            group_by=group_by,
            ordered=ordered,
            condition=condition,
            errors=errors,
            **kwargs,
        )

    def to_dict(self) -> dict:
        d = super().to_dict()
        dc = {
            "type": self.type.name.lower(),
            "rules": [rule.reference for rule in self.rules],
            "timespan": seconds_to_timespan(self.timespan),
            "group-by": self.group_by,
            "ordered": self.ordered,
        }
        if self.condition is not None:
            dc["condition"] = self.condition.to_dict()
        d["correlation"] = dc

        return d
