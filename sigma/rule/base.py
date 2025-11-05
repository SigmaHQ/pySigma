from __future__ import annotations

import datetime as dt
import re
from abc import abstractmethod
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

import yaml
from typing_extensions import Self

import sigma.exceptions as sigma_exceptions
from sigma.rule.attributes import SigmaLevel, SigmaRelated, SigmaRuleTag, SigmaStatus

if TYPE_CHECKING:
    from sigma.conversion.state import ConversionState
    from sigma.exceptions import SigmaError, SigmaRuleLocation


class SigmaYAMLLoader(yaml.CSafeLoader):
    """Custom YAML loader implementing additional functionality for Sigma."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        keys = set()
        for k, v in node.value:
            key = self.construct_object(k, deep=deep)  # type: ignore
            if key in keys:
                raise yaml.error.YAMLError("Duplicate key '{k}'")
            else:
                keys.add(key)

        return super().construct_mapping(node, deep)


@dataclass
class SigmaRuleBase:
    title: str = ""
    id: UUID | None = None
    name: str | None = None
    taxonomy: str = "sigma"
    related: SigmaRelated | None = None
    status: SigmaStatus | None = None
    description: str | None = None
    license: str | None = None
    references: list[str] = field(default_factory=list)
    tags: list[SigmaRuleTag] = field(default_factory=list)
    author: str | None = None
    date: dt.date | None = None
    modified: dt.date | None = None
    fields: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    level: SigmaLevel | None = None
    scope: list[str] | None = None

    errors: list[sigma_exceptions.SigmaError] = field(default_factory=list)
    source: SigmaRuleLocation | None = field(default=None, compare=False)
    custom_attributes: dict[str, Any] = field(compare=False, default_factory=dict)

    _backreferences: list[SigmaRuleBase] = field(
        init=False, default_factory=list, repr=False, compare=False
    )
    _conversion_result: list[Any] | None = field(
        init=False, default=None, repr=False, compare=False
    )
    _conversion_states: list[ConversionState] | None = field(
        init=False, default=None, repr=False, compare=False
    )
    _output: bool = field(init=False, default=True, repr=False, compare=False)

    def __post_init__(self: Self) -> None:
        for field in ("references", "tags", "fields", "falsepositives"):
            if self.__getattribute__(field) is None:
                self.__setattr__(field, [])
        if self.id is not None and not isinstance(
            self.id, UUID
        ):  # Try to convert rule id into UUID object, but keep it if not possible
            try:
                self.id = UUID(self.id)
            except ValueError:
                pass

    @classmethod
    def from_dict_common_params(
        cls: type[Self],
        rule: dict[str, Any],
        collect_errors: bool = False,
        source: SigmaRuleLocation | None = None,
    ) -> tuple[dict[str, Any], list[SigmaError]]:
        """
        Convert Sigma rule base parsed in dict structure into kwargs dict that can be passed to the
        class instantiation of an object derived from the SigmaRuleBase class and the errors list.
        This is intended to be called only by to_dict() methods for processing the general
        parameters defined in the base class.

        if collect_errors is set to False exceptions are collected in the errors property of the resulting
        SigmaRule object. Else the first recognized error is raised as exception.
        """
        errors = []

        def get_rule_as_date(name: str, exception_class: type[SigmaError]) -> date | None:
            """
            Accepted string based date formats are in range 1000-01-01 .. 3999-12-31:
              * XXXX-XX-XX                                 -- fully corresponds to yaml date format
              * XXXX/XX/XX, XXXX/XX/X, XXXX/X/XX, XXXX/X/X -- often occurs in the US-based sigmas
            Not accepted are ambiguous dates such as:
                2024-01-1, 24-1-24, 24/1/1, ...
            """
            nonlocal errors, rule, source
            value = rule.get(name)
            if (
                value is not None
                and not isinstance(value, date)
                and not isinstance(value, datetime)
            ):
                error = True
                try:
                    value = str(value)  # forcifully convert whatever the type is into string
                    accepted_regexps = (
                        "([1-3][0-9][0-9][0-9])-([01][0-9])-([0-3][0-9])",  # 1000-01-01 .. 3999-12-31
                        "([1-3][0-9][0-9][0-9])/([01]?[0-9])/([0-3]?[0-9])",  # 1000/1/1, 1000/01/01 .. 3999/12/31
                    )
                    for date_regexp in accepted_regexps:
                        matcher = re.fullmatch(date_regexp, value)
                        if matcher:
                            result = date(int(matcher[1]), int(matcher[2]), int(matcher[3]))
                            error = False
                            break
                except Exception:
                    pass
                if error:
                    errors.append(
                        exception_class(
                            f"Rule {name} '{ value }' is invalid, use yyyy-mm-dd", source=source
                        )
                    )
                    return None
                return result
            else:
                return value

        # Rule identifier may be empty or must be valid UUID
        rule_id = rule.get("id")
        if rule_id is not None:
            try:
                rule_id = UUID(rule_id)
            except ValueError:
                errors.append(
                    sigma_exceptions.SigmaIdentifierError(
                        "Sigma rule identifier must be an UUID", source=source
                    )
                )

        # Rule name
        rule_name = rule.get("name")
        if rule_name is not None:
            if not isinstance(rule_name, str):
                errors.append(
                    sigma_exceptions.SigmaTypeError(
                        "Sigma rule name must be a string", source=source
                    )
                )
            else:
                if rule_name == "":
                    errors.append(
                        sigma_exceptions.SigmaNameError(
                            "Sigma rule name must not be empty", source=source
                        )
                    )
                else:
                    rule_name = rule_name

        # Rule taxonomy
        rule_taxonomy = rule.get("taxonomy", "sigma")
        if rule_taxonomy is not None:
            if not isinstance(rule_taxonomy, str):
                errors.append(
                    sigma_exceptions.SigmaTaxonomyError(
                        "Sigma rule taxonomy must be a string", source=source
                    )
                )
            else:
                if rule_taxonomy == "":
                    errors.append(
                        sigma_exceptions.SigmaTaxonomyError(
                            "Sigma rule taxonomy must not be empty", source=source
                        )
                    )
                else:
                    rule_taxonomy = rule_taxonomy

        # Rule related validation
        rule_related = rule.get("related")
        if rule_related is not None:
            if not isinstance(rule_related, list):
                errors.append(
                    sigma_exceptions.SigmaRelatedError(
                        "Sigma rule related must be a list", source=source
                    )
                )
            else:
                try:
                    rule_related = SigmaRelated.from_dict(rule_related)
                except sigma_exceptions.SigmaRelatedError as e:
                    errors.append(e)

        # Rule level validation
        rule_level = rule.get("level")
        if rule_level is not None:
            try:
                rule_level = SigmaLevel[rule_level.upper()]
            except KeyError:
                errors.append(
                    sigma_exceptions.SigmaLevelError(
                        f"'{ rule_level }' is not a valid Sigma rule level", source=source
                    )
                )

        # Rule status validation
        rule_status = rule.get("status")
        if rule_status is not None:
            if not isinstance(rule_status, str):
                errors.append(
                    sigma_exceptions.SigmaStatusError(
                        "Sigma rule status cannot be a list", source=source
                    )
                )
            else:
                try:
                    rule_status = SigmaStatus[rule_status.upper()]
                except KeyError:
                    errors.append(
                        sigma_exceptions.SigmaStatusError(
                            f"'{ rule_status }' is not a valid Sigma rule status", source=source
                        )
                    )

        # parse rule date if existing
        rule_date = get_rule_as_date("date", sigma_exceptions.SigmaDateError)

        # parse rule modified if existing
        rule_modified = get_rule_as_date("modified", sigma_exceptions.SigmaModifiedError)

        # Rule fields validation
        rule_fields = rule.get("fields")
        if rule_fields is not None and not isinstance(rule_fields, list):
            errors.append(
                sigma_exceptions.SigmaFieldsError(
                    "Sigma rule fields must be a list",
                    source=source,
                )
            )

        # Rule falsepositives validation
        rule_falsepositives = rule.get("falsepositives")
        if rule_falsepositives is not None and not isinstance(rule_falsepositives, list):
            errors.append(
                sigma_exceptions.SigmaFalsePositivesError(
                    "Sigma rule falsepositives must be a list",
                    source=source,
                )
            )

        # Rule author validation
        rule_author = rule.get("author")
        if rule_author is not None and not isinstance(rule_author, str):
            errors.append(
                sigma_exceptions.SigmaAuthorError(
                    "Sigma rule author must be a string",
                    source=source,
                )
            )

        # Rule description validation
        rule_description = rule.get("description")
        if rule_description is not None and not isinstance(rule_description, str):
            errors.append(
                sigma_exceptions.SigmaDescriptionError(
                    "Sigma rule description must be a string",
                    source=source,
                )
            )

        # Rule references validation
        rule_references = rule.get("references")
        if rule_references is not None and not isinstance(rule_references, list):
            errors.append(
                sigma_exceptions.SigmaReferencesError(
                    "Sigma rule references must be a list",
                    source=source,
                )
            )

        # Rule title validation
        rule_title = rule.get("title")
        if rule_title is None:
            errors.append(
                sigma_exceptions.SigmaTitleError(
                    "Sigma rule must have a title",
                    source=source,
                )
            )
        elif not isinstance(rule_title, str):
            errors.append(
                sigma_exceptions.SigmaTitleError(
                    "Sigma rule title must be a string",
                    source=source,
                )
            )
        elif len(rule_title) > 256:
            errors.append(
                sigma_exceptions.SigmaTitleError(
                    "Sigma rule title length must not exceed 256 characters",
                    source=source,
                )
            )

        # Rule scope validation
        rule_scope = rule.get("scope")
        if rule_scope is not None and not isinstance(rule_scope, list):
            errors.append(
                sigma_exceptions.SigmaScopeError(
                    "Sigma rule scope must be a list",
                    source=source,
                )
            )
        # Rule license validation
        rule_license = rule.get("license")
        if rule_license is not None and not isinstance(rule_license, str):
            errors.append(
                sigma_exceptions.SigmaLicenseError(
                    "Sigma rule license must be a string",
                    source=source,
                )
            )

        if not collect_errors and errors:
            raise errors[0]

        return (
            {
                "title": rule_title,
                "id": rule_id,
                "name": rule_name,
                "taxonomy": rule_taxonomy,
                "related": rule_related,
                "level": rule_level,
                "status": rule_status,
                "description": rule_description,
                "references": rule_references,
                "tags": [SigmaRuleTag.from_str(tag) for tag in rule.get("tags", list())],
                "author": rule_author,
                "date": rule_date,
                "modified": rule_modified,
                "fields": rule_fields,
                "falsepositives": rule_falsepositives,
                "scope": rule_scope,
                "license": rule_license,
                "source": source,
                "custom_attributes": {
                    k: v
                    for k, v in rule.items()
                    if k
                    not in set(cls.__dataclass_fields__.keys())
                    - {"errors", "source", "applied_processing_items"}
                },
            },
            errors,
        )

    @classmethod
    @abstractmethod
    def from_dict(cls: type[Self], rule: dict[str, Any], collect_errors: bool = False) -> Self:
        """Convert dict input into SigmaRule object."""
        raise NotImplementedError(
            "from_dict method must be implemented in the derived class of SigmaRuleBase"
        )

    @classmethod
    def from_yaml(cls: type[Self], rule: str, collect_errors: bool = False) -> Self:
        """Convert YAML input string with single document into SigmaRule object."""
        parsed_rule = yaml.load(rule, SigmaYAMLLoader)
        return cls.from_dict(parsed_rule, collect_errors)

    def to_dict(self: Self) -> dict[str, Any]:
        """Convert rule object into dict."""
        d: dict[str, Any] = {
            "title": self.title,
        }
        # Convert to string where possible
        for field in ("id", "status", "level", "author", "description", "name"):
            if (s := self.__getattribute__(field)) is not None:
                d[field] = str(s)

        # copy list of strings
        for field in ("references", "fields", "falsepositives", "scope"):
            if (l := self.__getattribute__(field)) is not None and len(l) > 0:
                d[field] = l.copy()

        # the special cases
        if len(self.tags) > 0:
            d["tags"] = [str(tag) for tag in self.tags]
        if self.date is not None:
            d["date"] = self.date.isoformat()
        if self.modified is not None:
            d["modified"] = self.modified.isoformat()

        # custom attributes
        d.update(self.custom_attributes)

        return d

    def add_backreference(self: Self, rule: SigmaRuleBase) -> None:
        """Add backreference to another rule."""
        self._backreferences.append(rule)

    def referenced_by(self: Self, rule: SigmaRuleBase) -> bool:
        """Check if rule is referenced by another rule."""
        return rule in self._backreferences

    def set_conversion_result(self: Self, result: list[Any]) -> None:
        """Set conversion result."""
        self._conversion_result = result

    def get_conversion_result(self: Self) -> list[Any]:
        """Get conversion result."""
        if self._conversion_result is None:
            raise sigma_exceptions.SigmaConversionError(
                self,
                None,
                "Conversion result not available",
            )
        return self._conversion_result

    def set_conversion_states(self: Self, state: list[ConversionState]) -> None:
        """Set conversion state."""
        self._conversion_states = state

    def get_conversion_states(self: Self) -> list[ConversionState]:
        """Get conversion state."""
        if self._conversion_states is None:
            raise sigma_exceptions.SigmaConversionError(
                self,
                None,
                "Conversion state not available",
            )
        return self._conversion_states

    def disable_output(self: Self) -> None:
        """Disable output of rule."""
        self._output = False

    def __lt__(self: Self, other: SigmaRuleBase) -> bool:
        """Sort rules by backreference. A rule referenced by another rule is smaller."""
        return self.referenced_by(other)
