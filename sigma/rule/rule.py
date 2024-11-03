from dataclasses import dataclass, field
from typing import Optional
from sigma.rule.base import SigmaRuleBase
from sigma.processing.tracking import ProcessingItemTrackingMixin
import sigma.exceptions as sigma_exceptions
from sigma.exceptions import (
    SigmaRuleLocation,
    SigmaError,
)
from sigma.rule.detection import SigmaDetections
from sigma.rule.logsource import SigmaLogSource


@dataclass
class SigmaRule(SigmaRuleBase, ProcessingItemTrackingMixin):
    """
    A single Sigma rule.
    """

    logsource: SigmaLogSource = field(default_factory=SigmaLogSource)
    detection: SigmaDetections = field(default_factory=SigmaDetections)

    @classmethod
    def from_dict(
        cls,
        rule: dict,
        collect_errors: bool = False,
        source: Optional[SigmaRuleLocation] = None,
    ) -> "SigmaRule":
        """
        Convert Sigma rule parsed in dict structure into SigmaRule object.

        if collect_errors is set to False exceptions are collected in the errors property of the resulting
        SigmaRule object. Else the first recognized error is raised as exception.
        """
        kwargs, errors = super().from_dict(rule, collect_errors, source)

        # parse log source
        logsource = None
        try:
            logsource = SigmaLogSource.from_dict(rule["logsource"], source)
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
        except SigmaError as e:
            errors.append(e)

        # parse detections
        detections = None
        try:
            detections = SigmaDetections.from_dict(rule["detection"], source)
        except KeyError:
            errors.append(
                sigma_exceptions.SigmaDetectionError(
                    "Sigma rule must have a detection definitions", source=source
                )
            )
        except SigmaError as e:
            errors.append(e)

        if not collect_errors and errors:
            raise errors[0]

        return cls(
            logsource=logsource,
            detection=detections,
            errors=errors,
            **kwargs,
        )

    def to_dict(self) -> dict:
        """Convert rule object into dict."""
        d = super().to_dict()
        d.update(
            {
                "logsource": self.logsource.to_dict(),
                "detection": self.detection.to_dict(),
            }
        )

        return d
