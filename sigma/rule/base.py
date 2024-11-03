from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple, List
from uuid import UUID
from datetime import date, datetime
import yaml
import sigma
import sigma.exceptions as sigma_exceptions
from sigma.exceptions import SigmaRuleLocation
from sigma.rule.attributes import SigmaLevel, SigmaRelated, SigmaRuleTag, SigmaStatus


class SigmaYAMLLoader(yaml.SafeLoader):
    """Custom YAML loader implementing additional functionality for Sigma."""

    def construct_mapping(self, node, deep=...):
        keys = set()
        for k, v in node.value:
            key = self.construct_object(k, deep=deep)
            if key in keys:
                raise yaml.error.YAMLError("Duplicate key '{k}'")
            else:
                keys.add(key)

        return super().construct_mapping(node, deep)


@dataclass
class SigmaRuleBase:
    title: str = ""
    id: Optional[UUID] = None
    name: Optional[str] = None
    taxonomy: str = "sigma"
    related: Optional["sigma.rule.attributes.SigmaRelated"] = None
    status: Optional["sigma.rule.attributes.SigmaStatus"] = None
    description: Optional[str] = None
    license: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: List["sigma.rule.attributes.SigmaRuleTag"] = field(default_factory=list)
    author: Optional[str] = None
    date: Optional["datetime.date"] = None
    modified: Optional["datetime.date"] = None
    fields: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    level: Optional["sigma.rule.attributes.SigmaLevel"] = None
    scope: Optional[List[str]] = None

    errors: List[sigma_exceptions.SigmaError] = field(default_factory=list)
    source: Optional[SigmaRuleLocation] = field(default=None, compare=False)
    custom_attributes: Dict[str, Any] = field(compare=False, default_factory=dict)

    _backreferences: List["SigmaRuleBase"] = field(
        init=False, default_factory=list, repr=False, compare=False
    )
    _conversion_result: Optional[List[Any]] = field(
        init=False, default=None, repr=False, compare=False
    )
    _conversion_states: Optional[List["sigma.conversion.state.ConversionState"]] = field(
        init=False, default=None, repr=False, compare=False
    )
    _output: bool = field(init=False, default=True, repr=False, compare=False)

    def __post_init__(self):
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
    def from_dict(
        cls,
        rule: dict,
        collect_errors: bool = False,
        source: Optional[SigmaRuleLocation] = None,
    ) -> Tuple[dict, List[Exception]]:
        """
        Convert Sigma rule base parsed in dict structure into kwargs dict that can be passed to the
        class instantiation of an object derived from the SigmaRuleBase class and the errors list.
        This is intended to be called only by to_dict() methods for processing the general
        parameters defined in the base class.

        if collect_errors is set to False exceptions are collected in the errors property of the resulting
        SigmaRule object. Else the first recognized error is raised as exception.
        """
        errors = []
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
        rule_date = rule.get("date")
        if rule_date is not None:
            if not isinstance(rule_date, date) and not isinstance(rule_date, datetime):
                try:
                    rule_date = date(*(int(i) for i in rule_date.split("-")))
                except ValueError:
                    errors.append(
                        sigma_exceptions.SigmaDateError(
                            f"Rule date '{ rule_date }' is invalid, must be yyyy-mm-dd",
                            source=source,
                        )
                    )

        # parse rule modified if existing
        rule_modified = rule.get("modified")
        if rule_modified is not None:
            if not isinstance(rule_modified, date) and not isinstance(rule_modified, datetime):
                try:
                    rule_modified = date(*(int(i) for i in rule_modified.split("-")))
                except ValueError:
                    errors.append(
                        sigma_exceptions.SigmaModifiedError(
                            f"Rule modified '{ rule_modified }' is invalid, must be yyyy-mm-dd",
                            source=source,
                        )
                    )

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
    def from_yaml(cls, rule: str, collect_errors: bool = False) -> "SigmaRuleBase":
        """Convert YAML input string with single document into SigmaRule object."""
        parsed_rule = yaml.load(rule, SigmaYAMLLoader)
        return cls.from_dict(parsed_rule, collect_errors)

    def to_dict(self) -> dict:
        """Convert rule object into dict."""
        d = {
            "title": self.title,
        }
        # Convert to string where possible
        for field in ("id", "status", "level", "author", "description", "name"):
            if (s := self.__getattribute__(field)) is not None:
                d[field] = str(s)

        # copy list of strings
        for field in ("references", "fields", "falsepositives"):
            if len(l := self.__getattribute__(field)) > 0:
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

    def add_backreference(self, rule: "SigmaRuleBase"):
        """Add backreference to another rule."""
        self._backreferences.append(rule)

    def referenced_by(self, rule: "SigmaRuleBase") -> bool:
        """Check if rule is referenced by another rule."""
        return rule in self._backreferences

    def set_conversion_result(self, result: List[Any]):
        """Set conversion result."""
        self._conversion_result = result

    def get_conversion_result(self) -> List[Any]:
        """Get conversion result."""
        if self._conversion_result is None:
            raise sigma_exceptions.SigmaConversionError(
                self,
                "Conversion result not available",
            )
        return self._conversion_result

    def set_conversion_states(self, state: List["sigma.conversion.state.ConversionState"]):
        """Set conversion state."""
        self._conversion_states = state

    def get_conversion_states(self) -> List["sigma.conversion.state.ConversionState"]:
        """Get conversion state."""
        if self._conversion_states is None:
            raise sigma_exceptions.SigmaConversionError(
                self,
                "Conversion state not available",
            )
        return self._conversion_states

    def disable_output(self):
        """Disable output of rule."""
        self._output = False

    def __lt__(self, other: "SigmaRuleBase") -> bool:
        """Sort rules by backreference. A rule referenced by another rule is smaller."""
        return self.referenced_by(other)
