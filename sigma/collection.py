from dataclasses import dataclass
from typing import List, Union, Optional, IO
from sigma.rule import SigmaRule
from sigma.exceptions import SigmaCollectionError
from pathlib import Path
import yaml

max_recursion : int = 10

@dataclass
class SigmaCollection:
    """Collection of Sigma rules"""
    rules : List[SigmaRule]

    @classmethod
    def from_dicts(
        cls,
        rules : List[dict],
        base_path_name : Optional[Union[str, Path]] = None,
        recursion : int = 0,
        ) -> "SigmaCollection":
        """
        Generate rule from list of dicts containing parsed YAML content.

        Include actions load files relative to the base_path. They are not allowed
        for security reasons if base_path is not provided.
        """
        # Check: abort if too many recursion levels are reached
        if recursion > max_recursion:
            raise SigmaCollectionError("Too many recursions while resolving rule file inclusions.")

        # First step: scan rules input for include actions, recursively create a collection and append it at the location of the include action document
        all_rules = list()
        if base_path_name is not None:
            base_path = Path(base_path_name)
            if not base_path.is_dir():
                raise SigmaCollectionError(f"Provided base path '{ base_path_name }' is not a directory.")

        for i, rule in enumerate(rules):
            if rule.get("action", "") == "include":
                # Security checks against path traversal: include action in a collection can only reference rule files in the same path as the collection
                if base_path_name is None:
                    raise SigmaCollectionError("Inclusions are not allowed without specification of a base path")
                try:
                    target_path = (base_path / rule["filename"]).resolve()      # raises KeyError if filename is missing
                    target_path.relative_to(base_path.resolve())    # raises ValueError if referenced file is not in base path
                except KeyError:
                    raise SigmaCollectionError(f"Include rule { i } without filename")
                except ValueError:
                    raise SigmaCollectionError(f"Include rule { i } attempt to include file outside of its own path")

                included_rules = cls.from_yaml_path(str(target_path), recursion + 1)
                all_rules.extend(included_rules.rules)
            else:
                all_rules.append(rule)

        # Second step: resolve collection actions to Sigma rules
        parsed_rules = list()
        prev_rule = None
        global_rule = dict()

        for i, rule in zip(range(1, len(all_rules) + 1), all_rules):
            if isinstance(rule, SigmaRule):     # Included rules are already parsed, skip collection action processing
                parsed_rules.append(rule)
            else:
                action = rule.get("action")
                if action is None:          # no action defined: merge with global rule and handle as simple rule
                    parsed_rules.append(SigmaRule.from_dict(deep_dict_update(rule, global_rule)))
                    prev_rule = rule
                elif action == "global":    # set global rule template
                    del rule["action"]
                    global_rule = rule
                    prev_rule = global_rule
                elif action == "reset":     # remove global rule
                    global_rule = dict()
                elif action == "repeat":    # add content of current rule to previous rule and parse it
                    prev_rule = deep_dict_update(prev_rule, rule)
                    parsed_rules.append(SigmaRule.from_dict(prev_rule))
                else:
                    raise SigmaCollectionError(f"Unknown Sigma collection action '{ action }' in rule { i }")

        return cls(parsed_rules)

    @classmethod
    def from_yaml(
        cls,
        yaml_str : Union[bytes, str, IO],
        base_path_name : Optional[Union[str, Path]] = None,
        recursion : int = 0,
        ) -> "SigmaCollection":
        return cls.from_dicts(list(yaml.safe_load_all(yaml_str)), base_path_name, recursion)

    @classmethod
    def from_yaml_path(
        cls,
        yaml_path : Union[str, Path],
        recursion : int = 0,
        ) -> "SigmaCollection":
        f = open(yaml_path)
        return cls.from_yaml(f, Path(f.name).parent, recursion)

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
