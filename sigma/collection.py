from dataclasses import dataclass, field
from typing import Iterable, List, Union, IO
from sigma.rule import SigmaRule
from sigma.exceptions import SigmaCollectionError, SigmaError
import yaml

@dataclass
class SigmaCollection:
    """Collection of Sigma rules"""
    rules : List[SigmaRule]
    errors : List[SigmaError] = field(default_factory=list)

    @classmethod
    def from_dicts(
        cls,
        rules : List[dict],
        collect_errors : bool = False,
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
            if isinstance(rule, SigmaRule):     # Included rules are already parsed, skip collection action processing
                parsed_rules.append(rule)
            else:
                action = rule.get("action")
                if action is None:          # no action defined: merge with global rule and handle as simple rule
                    parsed_rules.append(SigmaRule.from_dict(deep_dict_update(rule, global_rule), collect_errors))
                    prev_rule = rule
                elif action == "global":    # set global rule template
                    del rule["action"]
                    global_rule = rule
                    prev_rule = global_rule
                elif action == "reset":     # remove global rule
                    global_rule = dict()
                elif action == "repeat":    # add content of current rule to previous rule and parse it
                    prev_rule = deep_dict_update(prev_rule, rule)
                    parsed_rules.append(SigmaRule.from_dict(prev_rule, collect_errors))
                else:
                    exception = SigmaCollectionError(f"Unknown Sigma collection action '{ action }' in rule { i }")
                    if collect_errors:
                        errors.append(exception)
                    else:
                        raise exception

        return cls(parsed_rules, errors)

    @classmethod
    def from_yaml(
        cls,
        yaml_str : Union[bytes, str, IO],
        collect_errors : bool = False,
        ) -> "SigmaCollection":
        """
        Generate a rule collection from a string containing one or multiple YAML documents.

        If the collect_errors parameters is set, exceptions are not raised while parsing but collected
        in the errors property individually for each Sigma rule and the whole SigmaCollection.
        """
        return cls.from_dicts(list(yaml.safe_load_all(yaml_str)), collect_errors)

    @classmethod
    def merge(cls, collections : Iterable["SigmaCollection"]) -> "SigmaCollection":
        """Merge multiple SigmaCollection objects into one and return it."""
        return cls([
            rule
            for collection in collections
            for rule in collection
        ])

    def __iter__(self):
        return iter(self.rules)

    def __len__(self):
        return len(self.rules)

    def __getitem__(self, i : int):
        return self.rules[i]

def deep_dict_update(dest, src):
    for k, v in src.items():
        if isinstance(v, dict):
            dest[k] = deep_dict_update(dest.get(k, {}), v)
        else:
            dest[k] = v
    return dest
