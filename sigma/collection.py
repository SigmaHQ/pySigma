from dataclasses import dataclass, field
from functools import reduce
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Union, IO
from uuid import UUID

import yaml

from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import (
    SigmaCollectionError,
    SigmaError,
    SigmaRuleLocation,
    SigmaRuleNotFoundError,
)
from sigma.rule import SigmaRule, SigmaRuleBase
from sigma.filters import SigmaFilter


@dataclass
class SigmaCollection:
    """Collection of Sigma rules"""

    rules: List[SigmaRuleBase]
    errors: List[SigmaError] = field(default_factory=list)
    ids_to_rules: Dict[UUID, SigmaRuleBase] = field(
        init=False, repr=False, hash=False, compare=False
    )
    names_to_rules: Dict[str, SigmaRuleBase] = field(
        init=False, repr=False, hash=False, compare=False
    )

    def __post_init__(self):
        """
        Map rule identifiers to rules and resolve rule references in correlation rules.
        """
        self.ids_to_rules = {}
        self.names_to_rules = {}
        for rule in self.rules:
            if rule.id is not None:
                self.ids_to_rules[rule.id] = rule
            if rule.name is not None:
                self.names_to_rules[rule.name] = rule

    def resolve_rule_references(self):
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
            [reduce(lambda r, f: f.apply_on_rule(r), filters, rule) for rule in self.rules]
            if filters
            else self.rules
        )

        # Sort rules by reference order
        self.rules = list(sorted(self.rules))

    @classmethod
    def from_dicts(
        cls,
        rules: List[dict],
        collect_errors: bool = False,
        source: Optional[SigmaRuleLocation] = None,
    ) -> "SigmaCollection":
        """
        Generate a rule collection from list of dicts containing parsed YAML content.

        If the collect_errors parameters is set, exceptions are not raised while parsing but collected
        in the errors property individually for each Sigma rule and the whole SigmaCollection.
        """
        errors = []
        parsed_rules = list()
        prev_rule = None
        global_rule = dict()

        for i, rule in zip(range(1, len(rules) + 1), rules):
            if isinstance(
                rule, SigmaRule
            ):  # Included rules are already parsed, skip collection action processing
                parsed_rule = rule
                parsed_rules.append(parsed_rule)
                parsed_rule.source = source
            else:
                action = rule.get("action")
                if action is None:  # no action defined
                    if "correlation" in rule:  # correlation rule - no global rule merge
                        parsed_rule = SigmaCorrelationRule.from_dict(
                            rule,
                            collect_errors,
                            source,
                        )
                        parsed_rules.append(parsed_rule)
                        errors.extend(parsed_rule.errors)  # Propagate errors from rule
                    elif "filter" in rule:  # correlation rule - no global rule merge
                        parsed_rule = SigmaFilter.from_dict(
                            rule,
                            collect_errors,
                            source,
                        )
                        parsed_rules.append(parsed_rule)
                        errors.extend(parsed_rule.errors)  # Propagate errors from rule
                    else:  # merge with global rule and parse as simple rule
                        parsed_rule = SigmaRule.from_dict(
                            deep_dict_update(rule, global_rule), collect_errors, source
                        )
                        parsed_rules.append(parsed_rule)
                        errors.extend(parsed_rule.errors)  # Propagate errors from rule
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

        return cls(parsed_rules, errors)

    @classmethod
    def from_yaml(
        cls,
        yaml_str: Union[bytes, str, IO],
        collect_errors: bool = False,
        source: Optional[SigmaRuleLocation] = None,
    ) -> "SigmaCollection":
        """
        Generate a rule collection from a string containing one or multiple YAML documents.

        If the collect_errors parameters is set, exceptions are not raised while parsing but collected
        in the errors property individually for each Sigma rule and the whole SigmaCollection.
        """
        return cls.from_dicts(list(yaml.safe_load_all(yaml_str)), collect_errors, source)

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
        paths = (  # Recurse into directories if provided
            path.glob(recursion_pattern) if path.is_dir() else (path,) for path in paths
        )
        return (subpath for subpaths in paths for subpath in subpaths)  # Flatten the list

    @classmethod
    def load_ruleset(
        cls,
        inputs: List[Union[str, Path]],
        collect_errors: bool = False,
        on_beforeload: Optional[Callable[[Path], Optional[Path]]] = None,
        on_load: Optional[Callable[[Path, "SigmaCollection"], Optional["SigmaCollection"]]] = None,
        recursion_pattern: str = "**/*.yml",
    ) -> "SigmaCollection":
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
                path = on_beforeload(path)
            if path is not None:  # Skip if path is None
                sigma_collection = SigmaCollection.from_yaml(
                    path.open(encoding="utf-8"), collect_errors, SigmaRuleLocation(path)
                )
                if (
                    on_load is not None
                ):  # replace SigmaCollection generated from file content with the return value from on_load function if provided
                    sigma_collection = on_load(path, sigma_collection)
                if sigma_collection is not None:  # Skip if nothing
                    sigma_collections.append(sigma_collection)

        # Finally merge all SigmaCollection's and return the result
        return cls.merge(sigma_collections)

    @classmethod
    def merge(cls, collections: Iterable["SigmaCollection"]) -> "SigmaCollection":
        """Merge multiple SigmaCollection objects into one and return it."""
        return cls(
            rules=[rule for collection in collections for rule in collection],
            errors=[error for collection in collections for error in collection.errors],
        )

    def get_output_rules(self) -> Iterable[SigmaRuleBase]:
        """Returns an iterator across all rules where the output property is set to true"""
        return (rule for rule in self.rules if rule._output)

    def get_unreferenced_rules(self) -> Iterable[SigmaRuleBase]:
        """Returns an iterator across all rules that are not referenced by any other rule"""
        return (rule for rule in self.rules if not rule._backreferences)

    def __iter__(self):
        return iter(self.rules)

    def __len__(self):
        return len(self.rules)

    def __getitem__(self, i: Union[int, str, UUID]):
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


def deep_dict_update(dest: SigmaRule, src: SigmaRule) -> "SigmaRule":
    for k, v in src.items():
        if isinstance(v, dict):
            dest[k] = deep_dict_update(dest.get(k, {}), v)
        else:
            dest[k] = v
    return dest
