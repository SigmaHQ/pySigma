from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Literal, cast

import sigma.exceptions as sigma_exceptions
from sigma.exceptions import SigmaRuleLocation, SigmaTimespanError
from sigma.processing.tracking import ProcessingItemTrackingMixin
from sigma.rule import EnumLowercaseStringMixin, SigmaRule, SigmaRuleBase

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sigma.collection import SigmaCollection


class SigmaCorrelationType(EnumLowercaseStringMixin, Enum):
    """
    Supported correlation types.
    """

    EVENT_COUNT = auto()
    VALUE_COUNT = auto()
    TEMPORAL = auto()
    TEMPORAL_ORDERED = auto()
    VALUE_SUM = auto()
    VALUE_AVG = auto()
    VALUE_PERCENTILE = auto()


# TODO: type supported from 3.12
# type SigmaCorrelationTypeLiteral = Literal[
SigmaCorrelationTypeLiteral = Literal[
    "event_count",
    "value_count",
    "temporal",
    "temporal_ordered",
    "value_sum",
    "value_avg",
    "value_percentile",
]


@dataclass(unsafe_hash=True)
class SigmaRuleReference:
    """
    Reference to a Sigma rule. Initially this only contains the plain reference as string that is
    then resolved into a rule reference.
    """

    reference: str
    rule: SigmaRule | SigmaCorrelationRule = field(init=False, repr=False, compare=False)

    def resolve(self, rule_collection: SigmaCollection) -> None:
        """
        Resolves the reference to the actual Sigma rule.

        Raises:
            sigma_exceptions.SigmaRuleNotFoundError: If the referenced rule cannot be found in the given rule collection.
        """
        self.rule = rule_collection[self.reference]


class SigmaCorrelationConditionOperator(Enum):
    LT = auto()
    LTE = auto()
    GT = auto()
    GTE = auto()
    EQ = auto()
    NEQ = auto()

    @classmethod
    def operators(cls) -> set[str]:
        return {op.name.lower() for op in cls}


@dataclass
class SigmaCorrelationCondition:
    op: SigmaCorrelationConditionOperator
    count: int
    fieldref: str | list[str] | None = field(default=None)
    source: SigmaRuleLocation | None = field(default=None, compare=False)

    @classmethod
    def from_dict(
        cls, d: dict[str, Any], source: SigmaRuleLocation | None = None
    ) -> SigmaCorrelationCondition:
        d_keys = frozenset(d.keys())
        ops = frozenset(SigmaCorrelationConditionOperator.operators())
        if len(d_keys.intersection(ops)) != 1:
            raise sigma_exceptions.SigmaCorrelationConditionError(
                "Sigma correlation condition must have exactly one condition item", source=source
            )
        unknown_keys = d_keys.difference(ops).difference({"field"})
        if unknown_keys:
            raise sigma_exceptions.SigmaCorrelationConditionError(
                "Sigma correlation condition contains invalid items: " + ", ".join(unknown_keys),
                source=source,
            )

        # Condition operator and count
        for (
            op
        ) in (
            SigmaCorrelationConditionOperator.operators()
        ):  # It's already tested above if there's an operator.
            if op in d:
                cond_op = SigmaCorrelationConditionOperator[op.upper()]
                try:
                    cond_count = int(d[op])
                except ValueError:
                    raise sigma_exceptions.SigmaCorrelationConditionError(
                        f"'{ d[op] }' is no valid Sigma correlation condition count", source=source
                    )
                break

        # Condition field
        try:
            cond_field = d["field"]
        except KeyError:
            cond_field = None

        return cls(op=cond_op, count=cond_count, fieldref=cond_field, source=source)

    def to_dict(self) -> dict[str, Any]:
        if not self.fieldref:
            return {self.op.name.lower(): self.count}
        return {self.op.name.lower(): self.count, "field": self.fieldref}


@dataclass
class SigmaCorrelationTimespan:
    spec: str = field(compare=False)
    seconds: int = field(init=False)
    count: int = field(init=False)
    unit: str = field(init=False)

    def __post_init__(self) -> None:
        """
        Parses a string representing a time span and stores the equivalent number of seconds.

        Raises:
            sigma_exceptions.SigmaTimespanError: If the given time span is invalid.
        """
        try:
            self.count = int(self.spec[:-1])
            self.unit = self.spec[-1]
            self.seconds = (
                self.count
                * {
                    "s": 1,
                    "m": 60,
                    "h": 3600,
                    "d": 86400,
                    "w": 604800,
                    "M": 2629746,
                    "y": 31556952,
                }[self.unit]
            )
        except (ValueError, KeyError):
            raise sigma_exceptions.SigmaTimespanError(f"Timespan '{ self.spec }' is invalid.")


@dataclass
class SigmaCorrelationFieldAlias:
    """
    The Sigma rules used in a correlation rule possibly match events that use different field names
    for the same information. An alias field definition maps a field name that can be used in the
    group-by definition of a correlation rule to their respective field names in the events matched
    by the Sigma rules.
    """

    alias: str
    mapping: dict[SigmaRuleReference, str]

    def resolve_rule_references(self, rule_collection: SigmaCollection) -> None:
        """
        Resolves all rule references in the mapping property to actual Sigma rules.

        Raises:
            sigma_exceptions.SigmaRuleNotFoundError: If a referenced rule cannot be found in the given rule collection.
        """
        for rule_ref in self.mapping.keys():
            rule_ref.resolve(rule_collection)


@dataclass
class SigmaCorrelationFieldAliases:
    aliases: dict[str, SigmaCorrelationFieldAlias] = field(default_factory=dict)

    def __iter__(self) -> Iterator[SigmaCorrelationFieldAlias]:
        return iter(self.aliases.values())

    def __len__(self) -> int:
        return len(self.aliases)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SigmaCorrelationFieldAliases:
        aliases = {}
        for alias, mapping in d.items():
            if not isinstance(mapping, dict):
                raise sigma_exceptions.SigmaCorrelationRuleError(
                    "Sigma correlation field alias mapping must be a dict"
                )

            aliases[alias] = SigmaCorrelationFieldAlias(
                alias=alias,
                mapping={
                    SigmaRuleReference(rule_ref): field_name
                    for rule_ref, field_name in mapping.items()
                },
            )

        return cls(aliases=aliases)

    def to_dict(self) -> dict[str, dict[str, str]]:
        return {
            alias: {
                rule_ref.reference: field_name for rule_ref, field_name in alias_def.mapping.items()
            }
            for alias, alias_def in self.aliases.items()
        }

    def resolve_rule_references(self, rule_collection: SigmaCollection) -> None:
        """
        Resolves all rule references in the aliases property to actual Sigma rules.

        Raises:
            sigma_exceptions.SigmaRuleNotFoundError: If a referenced rule cannot be found in the given rule collection.
        """
        for alias in self.aliases.values():
            alias.resolve_rule_references(rule_collection)


@dataclass
class SigmaCorrelationRule(SigmaRuleBase, ProcessingItemTrackingMixin):
    type: SigmaCorrelationType = SigmaCorrelationType.EVENT_COUNT
    rules: list[SigmaRuleReference] = field(default_factory=list)
    generate: bool = field(default=False)
    timespan: SigmaCorrelationTimespan = field(
        default_factory=lambda: SigmaCorrelationTimespan("1m")
    )
    group_by: list[str] | None = None
    aliases: SigmaCorrelationFieldAliases = field(default_factory=SigmaCorrelationFieldAliases)
    condition: SigmaCorrelationCondition = field(
        default_factory=lambda: SigmaCorrelationCondition(SigmaCorrelationConditionOperator.GTE, 1)
    )
    source: SigmaRuleLocation | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        if (
            self.type not in {SigmaCorrelationType.TEMPORAL, SigmaCorrelationType.TEMPORAL_ORDERED}
            and self.condition is None
        ):
            raise sigma_exceptions.SigmaCorrelationRuleError(
                "Non-temporal Sigma correlation rule without condition", source=self.source
            )
        if self.type in {
            SigmaCorrelationType.VALUE_COUNT,
            SigmaCorrelationType.VALUE_SUM,
            SigmaCorrelationType.VALUE_AVG,
            SigmaCorrelationType.VALUE_PERCENTILE,
        } and self.condition.fieldref is None:
            # Format type name for error message (special case for VALUE_COUNT to match existing tests)
            if self.type == SigmaCorrelationType.VALUE_COUNT:
                type_name = "Value count"
            else:
                type_name = self.type.name.replace("_", " ").capitalize()
            raise sigma_exceptions.SigmaCorrelationRuleError(
                f"{type_name} correlation rule without field reference",
                source=self.source,
            )

    @classmethod
    def from_dict(
        cls,
        rule: dict[str, Any],
        collect_errors: bool = False,
        source: SigmaRuleLocation | None = None,
    ) -> SigmaCorrelationRule:
        kwargs, errors = super().from_dict_common_params(rule, collect_errors, source)
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
                    "Sigma correlation rule without type", source=source
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
                        "Rule reference must be plain string or list.", source=source
                    )
                )
        else:
            errors.append(
                sigma_exceptions.SigmaCorrelationRuleError(
                    "Sigma correlation rule without rule references", source=source
                )
            )

        # Generate
        generate = correlation_rule.get("generate")
        if generate is not None:
            if not isinstance(generate, bool):
                errors.append(
                    sigma_exceptions.SigmaCorrelationRuleError(
                        "Sigma correlation generate definition must be a boolean", source=source
                    )
                )
        else:
            generate = False

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
                        "Sigma correlation group-by definition must be string or list",
                        source=source,
                    )
                )

        # Time span
        timespan = correlation_rule.get("timespan")
        if timespan is not None:
            try:
                timespan = SigmaCorrelationTimespan(timespan)
            except SigmaTimespanError as e:
                errors.append(e)
        else:
            errors.append(
                sigma_exceptions.SigmaCorrelationRuleError(
                    "Sigma correlation rule without timespan", source=source
                )
            )

        # Aliases
        aliases = correlation_rule.get("aliases")
        if aliases is not None:
            if isinstance(aliases, dict):
                aliases = SigmaCorrelationFieldAliases.from_dict(aliases)
            else:
                errors.append(
                    sigma_exceptions.SigmaCorrelationRuleError(
                        "Sigma correlation aliases definition must be a dict", source=source
                    )
                )
        else:
            aliases = SigmaCorrelationFieldAliases()

        # Condition
        condition = correlation_rule.get("condition")
        if condition is not None:
            if isinstance(condition, dict):
                condition = SigmaCorrelationCondition.from_dict(condition, source=source)
            else:
                errors.append(
                    sigma_exceptions.SigmaCorrelationRuleError(
                        "Sigma correlation condition definition must be a dict", source=source
                    )
                )
        elif correlation_type not in (
            SigmaCorrelationType.TEMPORAL,
            SigmaCorrelationType.TEMPORAL_ORDERED,
        ):
            errors.append(
                sigma_exceptions.SigmaCorrelationRuleError(
                    "Non-temporal Sigma correlation rule without condition", source=source
                )
            )
        elif correlation_type in (
            SigmaCorrelationType.TEMPORAL,
            SigmaCorrelationType.TEMPORAL_ORDERED,
        ):  # default condition for temporal correlation rules: count >= number of rules
            condition = SigmaCorrelationCondition(
                op=SigmaCorrelationConditionOperator.GTE, count=len(rules), source=source
            )

        if not collect_errors and errors:
            raise errors[0]

        return cls(
            type=correlation_type,
            rules=rules,
            generate=generate,
            timespan=timespan,
            group_by=group_by,
            aliases=aliases,
            condition=condition,
            errors=errors,
            **kwargs,
        )

    @classmethod
    def from_yaml(cls, rule: str, collect_errors: bool = False) -> SigmaCorrelationRule:
        """Convert YAML input string with single document into SigmaCorrelationRule object."""
        return cast("SigmaCorrelationRule", super().from_yaml(rule, collect_errors))

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        dc = {
            "type": self.type.name.lower(),
            "rules": [rule.reference for rule in self.rules],
            "timespan": self.timespan.spec,
            "group-by": self.group_by,
            "aliases": self.aliases.to_dict() if self.aliases is not None else None,
            "condition": self.condition.to_dict() if self.condition is not None else None,
        }
        d["correlation"] = dc

        return d

    def resolve_rule_references(self, rule_collection: SigmaCollection) -> None:
        """
        Resolves all rule references in the rules property to actual Sigma rules.

        Raises:
            sigma_exceptions.SigmaRuleNotFoundError: If a referenced rule cannot be found in the given rule collection.
        """
        for rule_ref in self.rules:
            rule_ref.resolve(rule_collection)
            rule = rule_ref.rule
            rule.add_backreference(self)
            if not self.generate:
                rule.disable_output()

        self.aliases.resolve_rule_references(rule_collection)

    def flatten_rules(
        self, include_correlations: bool = True
    ) -> list[SigmaRule | SigmaCorrelationRule]:
        """
        Flattens the rules in the correlation rule and returns a list of Sigma rules. If include_correlations
        is set to False, only the Sigma rules are returned, excluding nested correlation rules.

        Returns:
            List of Sigma rules.
        """
        rules: list[SigmaRule | SigmaCorrelationRule] = []
        for rule_ref in self.rules:
            rule = rule_ref.rule
            if isinstance(rule, SigmaCorrelationRule):
                if include_correlations:
                    rules.append(rule)
                rules.extend(rule.flatten_rules())
            else:
                rules.append(rule)
        return rules
