from dataclasses import dataclass, field
from datetime import datetime, date
from typing import List, Optional, Tuple
from uuid import UUID

import yaml
from sigma import exceptions as sigma_exceptions

from sigma.rule import SigmaYAMLLoader, SigmaLogSource, SigmaDetections


class SigmaFilterLocation(sigma_exceptions.SigmaRuleLocation):
    """Location of Sigma filter in source file."""

    pass


class SigmaGlobalFilter(SigmaDetections):
    rules: List[UUID] = field(default_factory=list)


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
        filter: dict,
        collect_errors: bool = False,
        source: Optional[SigmaFilterLocation] = None,
    ) -> "SigmaFilter":
        """
        Converts from a dictionary object to a SigmaFilter object.
        """
        errors = []

        # Filter ID validation
        filter_id = filter.get("id")
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
        filter_title = filter.get("title")
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
        filter_description = filter.get("description")
        if filter_description is not None and not isinstance(filter_description, str):
            errors.append(
                sigma_exceptions.SigmaDescriptionError(
                    "Sigma rule description must be a string",
                    source=source,
                )
            )

        # Filter author validation
        filter_author = filter.get("author")
        if filter_author is not None and not isinstance(filter_author, str):
            errors.append(
                sigma_exceptions.SigmaAuthorError(
                    "Sigma rule author must be a string",
                    source=source,
                )
            )

        # parse rule date if existing
        filter_date = filter.get("date")
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
        filter_modified = filter.get("modified")
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
            filter_logsource = SigmaLogSource.from_dict(filter["logsource"], source)
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
            filter_global_filter = SigmaGlobalFilter.from_dict(filter["global_filter"], source)
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
