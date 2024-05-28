import random
import re
import string
from dataclasses import dataclass, field, Field
from datetime import datetime, date
from typing import List, Optional, Tuple
from uuid import UUID

import yaml
from sigma import exceptions as sigma_exceptions
from sigma.conditions import SigmaCondition
from sigma.exceptions import SigmaRuleLocation
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import AddConditionTransformation, ConditionTransformation

from sigma.rule import SigmaYAMLLoader, SigmaLogSource, SigmaDetections, SigmaDetection, SigmaRule


class SigmaFilterLocation(sigma_exceptions.SigmaRuleLocation):
    """Location of Sigma filter in source file."""

    pass


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
            condition=condition,
            source=source,
        )


@dataclass
class SigmaFilterTransformation(ConditionTransformation):
    """
    Adds a filter to the rule by modifying the detection and condition fields to
    """

    sigma_filter: "SigmaFilter" = field(default=None)
    negated: bool = False

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule
    ) -> None:
        # TODO Add Templates similar to AddConditionTransformation
        # TODO Only add if rule ID / Rule Name / Logsource matches

        for original_cond_name, condition in self.sigma_filter.global_filter.detections.items():
            cond_name = "_cond_" + ("".join(random.choices(string.ascii_lowercase, k=10)))

            # Replace each instance of the original condition name with the new condition name to avoid conflicts
            self.sigma_filter.global_filter.condition[0] = re.sub(
                rf"[^ ]*{original_cond_name}[^ ]*",
                cond_name,
                self.sigma_filter.global_filter.condition[0],
            )
            rule.detection.detections[cond_name] = condition

            self.processing_item_applied(rule.detection.detections[cond_name])

        super().apply(pipeline, rule)

    def apply_condition(self, cond: SigmaCondition) -> None:
        cond.condition = (
            f"({cond.condition}) and "
            + ("not " if self.negated else "")
            + f"({self.sigma_filter.global_filter.condition[0]})"
        )


@dataclass
class SigmaFilter:
    title: str
    description: str
    id: Optional[UUID] = None
    author: Optional[str] = None
    date: Optional["datetime.date"] = None
    modified: Optional["datetime.date"] = None
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
        errors = []

        # Filter ID validation
        filter_id = sigma_filter.get("id")
        if filter_id is not None:
            try:
                filter_id = UUID(filter_id)
            except ValueError:
                errors.append(
                    sigma_exceptions.SigmaIdentifierError(
                        "Sigma rule identifier must be an UUID", source=source
                    )
                )

        # Filter title validation
        filter_title = sigma_filter.get("title")
        if filter_title is None:
            errors.append(
                sigma_exceptions.SigmaTitleError(
                    "Sigma rule must have a title",
                    source=source,
                )
            )
        elif not isinstance(filter_title, str):
            errors.append(
                sigma_exceptions.SigmaTitleError(
                    "Sigma rule title must be a string",
                    source=source,
                )
            )
        elif len(filter_title) > 256:
            errors.append(
                sigma_exceptions.SigmaTitleError(
                    "Sigma rule title length must not exceed 256 characters",
                    source=source,
                )
            )

        # Filter description validation
        filter_description = sigma_filter.get("description")
        if filter_description is not None and not isinstance(filter_description, str):
            errors.append(
                sigma_exceptions.SigmaDescriptionError(
                    "Sigma rule description must be a string",
                    source=source,
                )
            )

        # Filter author validation
        filter_author = sigma_filter.get("author")
        if filter_author is not None and not isinstance(filter_author, str):
            errors.append(
                sigma_exceptions.SigmaAuthorError(
                    "Sigma rule author must be a string",
                    source=source,
                )
            )

        # parse rule date if existing
        filter_date = sigma_filter.get("date")
        if filter_date is not None:
            if not isinstance(filter_date, date) and not isinstance(filter_date, datetime):
                try:
                    filter_date = date(*(int(i) for i in filter_date.split("/")))
                except ValueError:
                    try:
                        filter_date = date(*(int(i) for i in filter_date.split("-")))
                    except ValueError:
                        errors.append(
                            sigma_exceptions.SigmaDateError(
                                f"Rule date '{filter_date}' is invalid, must be yyyy/mm/dd or yyyy-mm-dd",
                                source=source,
                            )
                        )

        # parse rule modified if existing
        filter_modified = sigma_filter.get("modified")
        if filter_modified is not None:
            if not isinstance(filter_modified, date) and not isinstance(filter_modified, datetime):
                try:
                    filter_modified = date(*(int(i) for i in filter_modified.split("/")))
                except ValueError:
                    try:
                        filter_modified = date(*(int(i) for i in filter_modified.split("-")))
                    except ValueError:
                        errors.append(
                            sigma_exceptions.SigmaModifiedError(
                                f"Rule modified '{filter_modified}' is invalid, must be yyyy/mm/dd or yyyy-mm-dd",
                                source=source,
                            )
                        )

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
        except sigma_exceptions.SigmaError as e:
            errors.append(e)

        if not collect_errors and errors:
            raise errors[0]

        return cls(
            title=filter_title,
            description=filter_description,
            id=filter_id,
            author=filter_author,
            date=filter_date,
            modified=filter_modified,
            logsource=filter_logsource,
            global_filter=filter_global_filter,
        )

    @classmethod
    def from_yaml(cls, rule: str, collect_errors: bool = False) -> "SigmaFilter":
        """Convert YAML input string with single document into SigmaRule object."""
        parsed_rule = yaml.load(rule, SigmaYAMLLoader)
        return cls.from_dict(parsed_rule, collect_errors)

    def to_processing_pipeline(self):
        return ProcessingPipeline(
            name="Global Filter Pipeline",
            priority=0,
            items=[
                ProcessingItem(
                    SigmaFilterTransformation(negated=True, sigma_filter=self),
                    rule_conditions=[
                        LogsourceCondition(**self.logsource.to_dict()),
                        # TODO: Add where the rule IDs match
                    ],
                ),
            ],
        )
