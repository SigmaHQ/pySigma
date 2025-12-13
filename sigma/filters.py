from __future__ import annotations

import random
import re
import string
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from typing_extensions import Self

from sigma import exceptions as sigma_exceptions
from sigma.correlations import SigmaCorrelationRule, SigmaRuleReference
from sigma.rule import SigmaDetection, SigmaDetections, SigmaLogSource, SigmaRule, SigmaRuleBase

if TYPE_CHECKING:
    from sigma.exceptions import SigmaRuleLocation


@dataclass
class SigmaGlobalFilter(SigmaDetections):
    rules: list[SigmaRuleReference] | str = field(default_factory=list)

    @classmethod
    def from_dict(
        cls: type[Self], detections: dict[str, Any], source: SigmaRuleLocation | None = None
    ) -> Self:
        try:
            if isinstance(detections["condition"], str):
                condition = [detections["condition"]]
            else:
                raise sigma_exceptions.SigmaFilterConditionError(
                    "Sigma filter condition must be a string", source=source
                )
        except KeyError:
            raise sigma_exceptions.SigmaFilterConditionError(
                "Sigma filter must contain exactly one condition", source=source
            )

        try:
            rules: list[SigmaRuleReference] | str
            if isinstance(detections["rules"], str):
                # Check if it's "any" keyword
                if detections["rules"].lower() == "any":
                    rules = detections["rules"].lower()
                else:
                    # Single rule reference
                    rules = [SigmaRuleReference(detections["rules"])]
            elif isinstance(detections["rules"], list):
                # Empty list is treated as "any"
                if not detections["rules"]:
                    rules = "any"
                else:
                    rules = [SigmaRuleReference(detection) for detection in detections["rules"]]
            else:
                raise sigma_exceptions.SigmaFilterRuleReferenceError(
                    "Sigma filter rules field must be 'any', a rule ID/name, or a list of rule IDs/names",
                    source=source,
                )
        except KeyError:
            # Rules field is required - must explicitly specify "any" or specific rule references
            raise sigma_exceptions.SigmaFilterRuleReferenceError(
                "Sigma filter must have a 'rules' field (use 'any' to apply to all rules matching the logsource)",
                source=source,
            )

        return cls(
            detections={
                name: SigmaDetection.from_definition(definition, source)
                for name, definition in detections.items()
                if name
                not in (
                    "condition",
                    "rules",
                )  # TODO Fix standard
            },
            rules=rules,
            condition=condition,
            source=source,
        )

    def to_dict(self: Self) -> dict[str, Any]:
        d = super().to_dict()
        d.update(
            {
                "rules": (
                    self.rules
                    if isinstance(self.rules, str)
                    else [ref.reference for ref in self.rules]
                ),
            }
        )

        return d


@dataclass
class SigmaFilter(SigmaRuleBase):
    """
    SigmaFilter class is used to represent a Sigma filter object.
    """

    logsource: SigmaLogSource = field(default_factory=SigmaLogSource)
    filter: SigmaGlobalFilter = field(
        default_factory=lambda: SigmaGlobalFilter({}, []),
    )

    @classmethod
    def from_dict(
        cls: type[Self],
        sigma_filter: dict[str, Any],
        collect_errors: bool = False,
        source: SigmaRuleLocation | None = None,
    ) -> Self:
        """
        Converts from a dictionary object to a SigmaFilter object.
        """
        kwargs, errors = super().from_dict_common_params(sigma_filter, collect_errors, source)

        # parse log source
        try:
            filter_logsource = SigmaLogSource.from_dict(sigma_filter["logsource"], source)
        except KeyError:
            errors.append(
                sigma_exceptions.SigmaLogsourceError(
                    "Sigma filter must have a log source", source=source
                )
            )
        except AttributeError:
            errors.append(
                sigma_exceptions.SigmaLogsourceError(
                    "Sigma logsource must be a valid YAML map", source=source
                )
            )
        except sigma_exceptions.SigmaError as e:
            errors.append(e)

        # parse detections
        try:
            filter_global_filter = SigmaGlobalFilter.from_dict(sigma_filter["filter"], source)
        except KeyError:
            errors.append(
                sigma_exceptions.SigmaFilterError(
                    "Sigma filter must have a filter defined", source=source
                )
            )
        except TypeError:
            errors.append(
                sigma_exceptions.SigmaFilterError(
                    "Sigma filter must be a dictionary", source=source
                )
            )
        except sigma_exceptions.SigmaError as e:
            errors.append(e)

        if not collect_errors and errors:
            raise errors[0]

        return cls(
            logsource=filter_logsource,
            filter=filter_global_filter,
            errors=errors,
            **kwargs,
        )

    def to_dict(self: Self) -> dict[str, Any]:
        """Convert filter object into dict."""
        d = super().to_dict()
        d.update(
            {
                "logsource": self.logsource.to_dict(),
                "filter": self.filter.to_dict(),
            }
        )

        return d

    def _should_apply_on_rule(self: Self, rule: SigmaRule | SigmaCorrelationRule) -> bool:
        from sigma.collection import SigmaCollection

        # Don't apply filters to correlation rules
        if isinstance(rule, SigmaCorrelationRule):
            return False

        # Check if logsource matches
        if rule.logsource not in self.logsource:
            return False

        # If rules is "any", apply to all rules matching the logsource
        if isinstance(self.filter.rules, str) and self.filter.rules.lower() == "any":
            return True

        # At this point, rules must be a list (not a string)
        assert isinstance(self.filter.rules, list)

        # For each rule ID/title in the filter.rules, add the rule to the reference using the resolve method,
        # then filter each reference to see if the rule is in the reference
        matches = []
        for reference in self.filter.rules:
            try:
                matches.append(SigmaCollection([rule])[reference.reference])
            except sigma_exceptions.SigmaRuleNotFoundError:
                pass

        if not matches:
            return False

        return True

    def apply_on_rule(
        self: Self, rule: SigmaRule | SigmaCorrelationRule
    ) -> SigmaRule | SigmaCorrelationRule:
        if not self._should_apply_on_rule(rule) or isinstance(rule, SigmaCorrelationRule):
            return rule

        filter_condition = self.filter.condition[0]
        for original_cond_name, condition in self.filter.detections.items():
            cond_name = "_filt_" + ("".join(random.choices(string.ascii_lowercase, k=10)))

            # Replace each instance of the original condition name with the new condition name to avoid conflicts
            filter_condition = re.sub(
                rf"(\s|\(|^){original_cond_name}(\s|$|\))",
                r"\1" + cond_name + r"\2",
                filter_condition,
            )
            rule.detection.detections[cond_name] = condition

        for i, condition_str in enumerate(rule.detection.condition):
            rule.detection.condition[i] = f"({condition_str}) and " + f"({filter_condition})"

        # Reparse the rule to update the parsed conditions
        rule.detection.__post_init__()

        return rule

    @classmethod
    def from_yaml(cls: type[Self], rule: str, collect_errors: bool = False) -> Self:
        """Convert YAML input string with single document into SigmaFilter object."""
        return super().from_yaml(rule, collect_errors)
