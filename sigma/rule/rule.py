from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from typing_extensions import Self

import sigma.exceptions as sigma_exceptions
from sigma.exceptions import SigmaError, SigmaRuleLocation
from sigma.processing.tracking import ProcessingItemTrackingMixin
from sigma.rule.base import SigmaRuleBase
from sigma.rule.detection import EmptySigmaDetections, SigmaDetections
from sigma.rule.logsource import EmptyLogSource, SigmaLogSource


@dataclass
class SigmaRule(SigmaRuleBase, ProcessingItemTrackingMixin):
    """
    A single Sigma rule.
    """

    logsource: SigmaLogSource = field(default_factory=SigmaLogSource)
    detection: SigmaDetections = field(default_factory=EmptySigmaDetections)

    @classmethod
    def from_dict(
        cls: type[Self],
        rule: dict[str, Any],
        collect_errors: bool = False,
        source: SigmaRuleLocation | None = None,
    ) -> Self:
        """
        Convert Sigma rule parsed in dict structure into SigmaRule object.

        if collect_errors is set to False exceptions are collected in the errors property of the resulting
        SigmaRule object. Else the first recognized error is raised as exception.
        """
        kwargs, errors = super().from_dict_common_params(rule, collect_errors, source)

        # parse log source
        try:
            logsource = SigmaLogSource.from_dict(rule["logsource"], source)
        except KeyError:
            logsource = EmptyLogSource()
            errors.append(
                sigma_exceptions.SigmaLogsourceError(
                    "Sigma rule must have a log source", source=source
                )
            )
        except AttributeError:
            logsource = EmptyLogSource()
            errors.append(
                sigma_exceptions.SigmaLogsourceError(
                    "Sigma logsource must be a valid YAML map", source=source
                )
            )
        except SigmaError as e:
            logsource = EmptyLogSource()
            errors.append(e)

        # parse detections
        try:
            detections = SigmaDetections.from_dict(rule["detection"], source)
        except KeyError:
            detections = EmptySigmaDetections()
            errors.append(
                sigma_exceptions.SigmaDetectionError(
                    "Sigma rule must have a detection definitions", source=source
                )
            )
        except SigmaError as e:
            detections = EmptySigmaDetections()
            errors.append(e)

        if not collect_errors and errors:
            raise errors[0]

        return cls(
            logsource=logsource,
            detection=detections,
            errors=errors,
            **kwargs,
        )

    @classmethod
    def from_yaml(cls: type[Self], rule: str, collect_errors: bool = False) -> Self:
        """Convert YAML input string with single document into SigmaRule object."""
        return super().from_yaml(rule, collect_errors)

    def to_dict(self) -> dict[str, Any]:
        """Convert rule object into dict."""
        d = super().to_dict()
        d.update(
            {
                "logsource": self.logsource.to_dict(),
                "detection": self.detection.to_dict(),
            }
        )

        return d
