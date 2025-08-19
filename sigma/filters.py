import random
import re
import string
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from typing_extensions import Self

from sigma import exceptions as sigma_exceptions
from sigma.correlations import SigmaCorrelationRule, SigmaRuleReference
from sigma.exceptions import SigmaRuleLocation
from sigma.rule import SigmaDetection, SigmaDetections, SigmaLogSource, SigmaRule, SigmaRuleBase


@dataclass
class SigmaGlobalFilter(SigmaDetections):
    rules: List[SigmaRuleReference] = field(default_factory=list)

    @classmethod
    def from_dict(
        cls, detections: Dict[str, Any], source: Optional[SigmaRuleLocation] = None
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
            if isinstance(detections["rules"], list):
                rules = [SigmaRuleReference(detection) for detection in detections["rules"]]
            elif isinstance(detections["rules"], str):
                rules = [SigmaRuleReference(detections["rules"])]
            else:
                raise sigma_exceptions.SigmaFilterRuleReferenceError(
                    "Sigma filter rules field must be a list of Sigma rule IDs or rule names",
                    source=source,
                )
        except KeyError:
            raise sigma_exceptions.SigmaFilterRuleReferenceError(
                "Sigma filter must contain at least a rules section", source=source
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

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d.update(
            {
                "rules": self.rules,
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
        cls,
        sigma_filter: Dict[str, Any],
        collect_errors: bool = False,
        source: Optional[SigmaRuleLocation] = None,
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

    def to_dict(self) -> Dict[str, Any]:
        """Convert filter object into dict."""
        d = super().to_dict()
        d.update(
            {
                "logsource": self.logsource.to_dict(),
                "filter": self.filter.to_dict(),
            }
        )

        return d

    def _should_apply_on_rule(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> bool:
        from sigma.collection import SigmaCollection

        if not self.filter.rules or isinstance(rule, SigmaCorrelationRule):
            return False

        # For each rule ID/title in the filter.rules, add the rule to the reference using the resolve method,
        # then filter each reference to see if the rule is in the reference
        matches = []
        for reference in self.filter.rules:
            try:
                matches.append(SigmaCollection([rule])[reference.reference])
            except sigma_exceptions.SigmaRuleNotFoundError:
                pass

        if all([match is None for match in matches]):
            return False

        if rule.logsource not in self.logsource:
            return False

        return True

    def apply_on_rule(
        self, rule: Union[SigmaRule, SigmaCorrelationRule]
    ) -> Union[SigmaRule, SigmaCorrelationRule]:
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
