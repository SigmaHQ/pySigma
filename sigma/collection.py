from dataclasses import InitVar, dataclass, field
from functools import reduce
from pathlib import Path
from typing import IO, Any, Callable, Dict, Iterable, List, Optional, Union
from uuid import UUID

import yaml
from typing_extensions import Self

from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import (
    SigmaCollectionError,
    SigmaError,
    SigmaRuleLocation,
    SigmaRuleNotFoundError,
)
from sigma.filters import SigmaFilter
from sigma.rule import SigmaRule
from sigma.rule.base import SigmaRuleBase

NestedDict = Dict[str, Union[str, int, float, bool, None, "NestedDict"]]


@dataclass
class SigmaCollection:
    """Collection of Sigma rules"""

    init_rules: InitVar[List[SigmaRuleBase]]
    errors: List[SigmaError] = field(default_factory=list)
    collect_filters: InitVar[bool] = False
    rules: List[Union[SigmaRule, SigmaCorrelationRule]] = field(default_factory=list)
    filters: List[SigmaFilter] = field(default_factory=list)
    ids_to_rules: Dict[UUID, SigmaRuleBase] = field(
        init=False, repr=False, hash=False, compare=False
    )
    names_to_rules: Dict[str, SigmaRuleBase] = field(
        init=False, repr=False, hash=False, compare=False
    )

    def __post_init__(
        self,
        init_rules: List[SigmaRuleBase],
        collect_filters: bool,
    ) -> None:
        """
        Map rule identifiers to rules and resolve rule references in correlation rules.
        """
        self.ids_to_rules = {}
        self.names_to_rules = {}
        for rule in init_rules:
            if isinstance(rule, (SigmaRule, SigmaCorrelationRule)):
                self.rules.append(rule)
                if rule.id is not None:
                    self.ids_to_rules[rule.id] = rule
                if rule.name is not None:
                    self.names_to_rules[rule.name] = rule
            elif isinstance(rule, SigmaFilter):
                self.filters.append(rule)
            else:
                raise TypeError(f"Object of type { type(rule) } not supported in SigmaCollection")
        if self.filters and not collect_filters:
            self.apply_filters(self.filters)

    def apply_filters(self, filters: List[SigmaFilter]) -> None:
        """
        Apply filters on each rule and replace the rule with the filtered rule
        """
        self.rules = [
            reduce(
                lambda r, f: f.apply_on_rule(r) if isinstance(r, SigmaRule) else r,
                filters,
                rule,
            )
            for rule in self.rules
        ]

    def resolve_rule_references(self) -> None:
        """
        Resolve rule references in correlation rules to the actual rule objects and sort the rules
        by reference order (rules that are referenced by other rules come first).

        This must be called before referencing rules are converted into queries to make references available.
        """
        for rule in self.rules:
            # Resolves all rule references in the rules property to actual Sigma rules.
            if isinstance(rule, SigmaCorrelationRule):
                rule.resolve_rule_references(self)

        # Extract all filters from the rules
        filters: List[SigmaFilter] = [rule for rule in self.rules if isinstance(rule, SigmaFilter)]
        self.rules = [rule for rule in self.rules if not isinstance(rule, SigmaFilter)]

        # Apply filters on each rule and replace the rule with the filtered rule
        self.rules = (
            [
                reduce(lambda r, f: f.apply_on_rule(r), filters, rule)
                for rule in self.rules
                if isinstance(rule, (SigmaRule, SigmaCorrelationRule))
            ]
            if filters
            else self.rules
        )

        # Sort rules by reference order
        self.rules = list(sorted(self.rules))

    @classmethod
    def from_dicts(
        cls,
        rules: List[NestedDict],
        collect_errors: bool = False,
        source: Optional[SigmaRuleLocation] = None,
        collect_filters: bool = False,
    ) -> Self:
        """
        Generate a rule collection from list of dicts containing parsed YAML content.

        If the collect_errors parameters is set, exceptions are not raised while parsing but collected
        in the errors property individually for each Sigma rule and the whole SigmaCollection.

        If collect_filters is set, filters are only collected in the collection but not yet applied to the rules.
        """
        errors: List[SigmaError] = []
        parsed_rules: List[SigmaRuleBase] = list()
        prev_rule = dict()
        global_rule: NestedDict = dict()

        for i, rule in zip(range(1, len(rules) + 1), rules):
            if isinstance(
                rule, SigmaRule
            ):  # Included rules are already parsed, skip collection action processing
                parsed_rules.append(rule)
                rule.source = source
            else:
                action = rule.get("action")
                if action is None:  # no action defined
                    if "correlation" in rule:  # correlation rule - no global rule merge
                        parsed_correlation_rule = SigmaCorrelationRule.from_dict(
                            rule,
                            collect_errors,
                            source,
                        )
                        parsed_rules.append(parsed_correlation_rule)
                        errors.extend(parsed_correlation_rule.errors)  # Propagate errors from rule
                    elif "filter" in rule:  # correlation rule - no global rule merge
                        parsed_filter_rule = SigmaFilter.from_dict(
                            rule,
                            collect_errors,
                            source,
                        )
                        parsed_rules.append(parsed_filter_rule)
                        errors.extend(parsed_filter_rule.errors)  # Propagate errors from rule
                    else:  # merge with global rule and parse as simple rule
                        parsed_merged_rule = SigmaRule.from_dict(
                            deep_dict_update(rule, global_rule), collect_errors, source
                        )
                        parsed_rules.append(parsed_merged_rule)
                        errors.extend(parsed_merged_rule.errors)  # Propagate errors from rule
                        prev_rule = rule
                elif action == "global":  # set global rule template
                    del rule["action"]
                    global_rule = rule
                    prev_rule = global_rule
                elif action == "reset":  # remove global rule
                    global_rule = dict()
                elif (
                    action == "repeat"
                ):  # add content of current rule to previous rule and parse it
                    prev_rule = deep_dict_update(prev_rule, rule)
                    parsed_rule = SigmaRule.from_dict(prev_rule, collect_errors, source)
                    parsed_rules.append(parsed_rule)
                    errors.extend(parsed_rule.errors)  # Propagate errors from rule
                else:
                    exception = SigmaCollectionError(
                        f"Unknown Sigma collection action '{ action }' in rule { i }",
                        source=source,
                    )
                    if collect_errors:
                        errors.append(exception)
                    else:
                        raise exception

        return cls(parsed_rules, errors, collect_filters)

    @classmethod
    def from_yaml(
        cls,
        yaml_str: Union[bytes, str, IO[Any]],
        collect_errors: bool = False,
        source: Optional[SigmaRuleLocation] = None,
        collect_filters: bool = False,
    ) -> Self:
        """
        Generate a rule collection from a string containing one or multiple YAML documents.

        If the collect_errors parameters is set, exceptions are not raised while parsing but collected
        in the errors property individually for each Sigma rule and the whole SigmaCollection.

        If collect_filters is set, filters are only collected in the collection but not yet applied to the rules.
        """
        return cls.from_dicts(
            list(yaml.safe_load_all(yaml_str)), collect_errors, source, collect_filters
        )

    @classmethod
    def resolve_paths(
        cls,
        inputs: List[Union[str, Path]],
        recursion_pattern: str = "**/*.yml",
    ) -> Iterable[Path]:
        """
        Resolve list of paths *inputs* that can contain files as well as directories into a flat list of
        files matching *resursion_pattern*.
        """
        paths = (  # Normalize all inputs into paths
            input if isinstance(input, Path) else Path(input) for input in inputs
        )
        paths_recurse = (  # Recurse into directories if provided
            path.glob(recursion_pattern) if path.is_dir() else (path,) for path in paths
        )
        return (subpath for subpaths in paths_recurse for subpath in subpaths)  # Flatten the list

    @classmethod
    def load_ruleset(
        cls,
        inputs: List[Union[str, Path]],
        collect_errors: bool = False,
        on_beforeload: Optional[Callable[[Path], Optional[Path]]] = None,
        on_load: Optional[Callable[[Path, Self], Optional[Self]]] = None,
        recursion_pattern: str = "**/*.yml",
    ) -> Self:
        """
        Load a ruleset from a list of files or directories and construct a :class:`SigmaCollection`
        object.

        :param inputs: List of strings and :class:`pathlib.Path` objects that reference files or
        directories that should be loaded.
        :param collect_errors: parse or verification errors are collected in :class:`SigmaRuleBase`
        objects instead of raising them immediately. Defaults to ``False``.
        :param on_beforeload: Optional function that is called for each path to a Sigma rule before the parsing and
        construction of the :class:`SigmaCollection` object is done. The path returned by this function is
        used as input. A rule path is skipped if ``None`` is returned.
        :param on_load: Optional function that is called after the :class:`SigmaCollection` was
        constructed from the path. The path and the SigmaCollection object are passed to this
        function and it is expected to return a :class:`SigmaCollection` object that is merged in
        the collection of the ruleset or ``None`` if the generated collection should be skipped.
        :param recursion_pattern: Pattern used to recurse into directories, defaults to ``**/*.yml``.

        :return: :class:`SigmaCollection` of all sigma rules contained in given paths.

        """
        if not isinstance(inputs, Iterable) or isinstance(inputs, str):
            raise TypeError(
                "Parameter 'inputs' must be list of strings or pathlib.Path objects, not "
                + str(type(inputs))
            )

        paths = cls.resolve_paths(inputs, recursion_pattern)
        sigma_collections = list()
        for path in paths:
            if (
                on_beforeload is not None
            ):  # replace path with return value of on_beforeload function if provided
                result_path: Optional[Path] = on_beforeload(path)
            else:
                result_path = path
            if result_path is not None:  # Skip if path is None
                sigma_collection = cls.from_yaml(
                    result_path.open(encoding="utf-8"),
                    collect_errors,
                    collect_filters=True,
                    source=SigmaRuleLocation(result_path),
                )
                if (
                    on_load is not None
                ):  # replace SigmaCollection generated from file content with the return value from on_load function if provided
                    result_sigma_collection = on_load(result_path, sigma_collection)
                else:
                    result_sigma_collection = sigma_collection
                if result_sigma_collection is not None:  # Skip if nothing
                    sigma_collections.append(result_sigma_collection)

        # Finally merge all SigmaCollection's and return the result
        return cls.merge(sigma_collections)

    @classmethod
    def merge(cls, collections: Iterable[Self]) -> Self:
        """Merge multiple SigmaCollection objects into one and return it."""
        return cls(
            init_rules=[
                rule for collection in collections for rule in collection.rules + collection.filters
            ],
            errors=[error for collection in collections for error in collection.errors],
        )

    def get_output_rules(self) -> Iterable[SigmaRuleBase]:
        """Returns an iterator across all rules where the output property is set to true"""
        return (rule for rule in self.rules if rule._output)

    def get_unreferenced_rules(self) -> Iterable[SigmaRuleBase]:
        """Returns an iterator across all rules that are not referenced by any other rule"""
        return (rule for rule in self.rules if not rule._backreferences)

    def __iter__(self) -> Iterable[SigmaRuleBase]:
        return iter(self.rules)

    def __len__(self) -> int:
        return len(self.rules)

    def __getitem__(self, i: Union[int, str, UUID]) -> SigmaRuleBase:
        try:
            if isinstance(i, int):  # Index by position
                return self.rules[i]
            elif isinstance(i, UUID):  # Index by UUID
                return self.ids_to_rules[i]
            elif isinstance(i, str):  # Index by UUID or name
                try:  # Try UUID first
                    return self.ids_to_rules[UUID(i)]
                except ValueError:  # Try name if UUID fails
                    return self.names_to_rules[i]
        except IndexError:
            raise SigmaRuleNotFoundError(f"Rule at position { i } not found in rule collection")
        except KeyError:
            raise SigmaRuleNotFoundError(f"Rule '{ i }' not found in rule collection")


def deep_dict_update(dest: Dict[Any, Any], src: Dict[Any, Any]) -> Dict[Any, Any]:
    for k, v in src.items():
        if isinstance(v, dict):
            dest[k] = deep_dict_update(dest.get(k, {}), v)
        else:
            dest[k] = v
    return dest
