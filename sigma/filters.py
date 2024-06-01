import random
import re
import string
from dataclasses import dataclass, field
from typing import List, Optional, Union
from uuid import UUID

import yaml

from sigma import exceptions as sigma_exceptions
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaRuleLocation
from sigma.rule import (
    SigmaYAMLLoader,
    SigmaLogSource,
    SigmaDetections,
    SigmaDetection,
    SigmaRule,
    SigmaRuleBase,
)


class SigmaFilterLocation(sigma_exceptions.SigmaRuleLocation):
    """Location of Sigma filter in source file."""

    pass


@dataclass
class SigmaGlobalFilter(SigmaDetections):
    rules: List[UUID] = field(default_factory=list)

    @classmethod
    def from_dict(
        cls, detections: dict, source: Optional[SigmaRuleLocation] = None
    ) -> "SigmaGlobalFilter":
        try:
            if isinstance(detections["condition"], list):
                condition = detections["condition"]
            else:
                condition = [detections["condition"]]
        except KeyError:
            raise sigma_exceptions.SigmaConditionError(
                "Sigma rule must contain at least one condition", source=source
            )

        try:
            if isinstance(detections["rules"], list):
                rules = detections["rules"]
            else:
                rules = [detections["rules"]]
        except KeyError:
            raise sigma_exceptions.SigmaConditionError(
                "Sigma rule must contain at least one condition", source=source
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


@dataclass
class SigmaFilter(SigmaRuleBase):
    """
    SigmaFilter class is used to represent a Sigma filter object.
    """

    logsource: SigmaLogSource = field(default_factory=SigmaLogSource)
    global_filter: SigmaGlobalFilter = field(default_factory=SigmaGlobalFilter)

    @classmethod
    def from_dict(
        cls,
        sigma_filter: dict,
        collect_errors: bool = False,
        source: Optional[SigmaFilterLocation] = None,
    ) -> "SigmaFilter":
        """
        Converts from a dictionary object to a SigmaFilter object.
        """
        kwargs, errors = super().from_dict(sigma_filter, collect_errors, source)

        # parse log source
        filter_logsource = None
        try:
            filter_logsource = SigmaLogSource.from_dict(sigma_filter["logsource"], source)
        except KeyError:
            errors.append(
                sigma_exceptions.SigmaLogsourceError(
                    "Sigma rule must have a log source", source=source
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
        filter_global_filter = None
        try:
            filter_global_filter = SigmaGlobalFilter.from_dict(
                sigma_filter["global_filter"], source
            )
        except KeyError:
            errors.append(
                sigma_exceptions.SigmaDetectionError(
                    "Sigma filter must have a detection definitions", source=source
                )
            )
        except TypeError:
            errors.append(
                sigma_exceptions.SigmaDetectionError(
                    "Sigma filter must have a detection definitions", source=source
                )
            )
        except sigma_exceptions.SigmaError as e:
            errors.append(e)

        if not collect_errors and errors:
            raise errors[0]

        return cls(
            logsource=filter_logsource,
            global_filter=filter_global_filter,
            errors=errors,
            **kwargs,
        )

    @classmethod
    def from_yaml(cls, rule: str, collect_errors: bool = False) -> "SigmaFilter":
        """Convert YAML input string with single document into SigmaRule object."""
        parsed_rule = yaml.load(rule, SigmaYAMLLoader)
        return cls.from_dict(parsed_rule, collect_errors)

    def to_dict(self) -> dict:
        """Convert rule object into dict."""
        d = super().to_dict()
        d.update(
            {
                "logsource": self.logsource.to_dict(),
                "global_filter": self.global_filter.to_dict(),
            }
        )

        return d

    def _should_apply_on_rule(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> bool:
        # Matches whether the filter.global_filter.rules contains the rule.id
        return self.global_filter.rules and str(rule.id) in self.global_filter.rules

    def apply_on_rule(
        self, rule: Union[SigmaRule, SigmaCorrelationRule]
    ) -> Union[SigmaRule, SigmaCorrelationRule]:
        if not self._should_apply_on_rule(rule):
            return rule

        for original_cond_name, condition in self.global_filter.detections.items():
            cond_name = "_filt_" + ("".join(random.choices(string.ascii_lowercase, k=10)))

            # Replace each instance of the original condition name with the new condition name to avoid conflicts
            self.global_filter.condition[0] = re.sub(
                rf"[^ ]*{original_cond_name}[^ ]*",
                cond_name,
                self.global_filter.condition[0],
            )
            rule.detection.detections[cond_name] = condition

        for i, condition in enumerate(rule.detection.condition):
            rule.detection.condition[i] = (
                f"({condition}) and " + f"({self.global_filter.condition[0]})"
            )

        # Reparse the rule to update the parsed conditions
        if hasattr(rule, "detection"):
            rule.detection.__post_init__()
        if hasattr(rule, "correlation"):
            rule.correlation.__post_init__()

        return rule
