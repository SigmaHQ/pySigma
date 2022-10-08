from collections import defaultdict
from typing import DefaultDict, Dict, Iterable, Iterator, List, Set, Type
from uuid import UUID
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaConfigurationError
from sigma.rule import SigmaRule
from sigma.validators.base import SigmaRuleValidator, SigmaValidationIssue
from sigma.validators import validators
import yaml

class SigmaValidator:
    """
    A SigmaValidator instantiates the given SigmaRuleValidator classes once at instantiation and
    uses them to check Sigma rules and collections. The validators can keep a state across the
    whole lifecycle of the SigmaValidator and can therefore also conduct uniqueness and other
    checks.

    Exclusions can be defined to exclude validators checks for given rule identifiers.
    """
    validators : Set[SigmaRuleValidator]
    exclusions : DefaultDict[UUID, Set[Type[SigmaRuleValidator]]]

    def __init__(self, validators : Iterable[Type[SigmaRuleValidator]], exclusions: Dict[UUID, Set[SigmaRuleValidator]] = dict()):
        self.validators = {
            validator()
            for validator in validators
        }
        self.exclusions = defaultdict(set, exclusions)

    @classmethod
    def from_dict(cls, d : Dict) -> "SigmaValidator":
        """
        Instantiate SigmaValidator from dict definition. The dict should have the following
        elements:

        * validators: a list of validators to use or not to use, if prefixed with -. The name 'all'
          represents all known validators.
        * exclusion: a map between rule ids and lists of validator names or a single validator name
          to define validation exclusions.

        :param d: Definition of the SigmaValidator.
        :type d: Dict
        :return: Instantiated SigmaValidator
        :rtype: SigmaValidator
        """
        # Build validator class set
        vs = set()
        for v in d.get("validators", []):
            if v == "all":      # all = all known validators
                vs = set(validators.keys())
            elif v.startswith("-"):     # remove validator from set
                vn = v[1:]
                try:
                    vs.remove(vn)
                except KeyError:
                    raise SigmaConfigurationError(f"Attempting to remove not existing validator '{ vn }' from validator set { vs }.")
            else:       # handle as validator name and try to add it to set.
                vs.add(v)

        try:        # convert validator names into classes
            validator_classes = {
                validators[v]
                for v in vs
            }
        except KeyError as e:
            raise SigmaConfigurationError(f"Unknown validator '{ e.args[0] }'")

        # Build exclusion dict
        try:
            exclusions = {
                UUID(rule_id): {
                    validators[exclusion_name]      # main purpose of the generators: resolve identifiers into classes
                    for exclusion_name in (
                        rule_exclusions
                        if isinstance(rule_exclusions, list)
                        else [ rule_exclusions ]
                    )
                }
                for rule_id, rule_exclusions in d.get("exclusions", dict()).items()
            }
        except KeyError as e:
            raise SigmaConfigurationError(f"Unknown validator '{ e.args[0] }'")

        return cls(validator_classes, exclusions)

    @classmethod
    def from_yaml(cls, validator_config: str) -> "SigmaValidator":
        return cls.from_dict(yaml.safe_load(validator_config))

    def validate_rule(self, rule : SigmaRule) -> List[SigmaValidationIssue]:
        """
        Validate a single rule with all rule validators configured in this SigmaValidator object. A
        rule validator can keep state information across the validation of multiple rules. Therefore
        the validation of a single rule is not necessarily isolated to itself but can also influence
        the result of the validation of other rules or cause that additional issues are emitted on
        finalization of the validator object.

        :param rule: Sigma rule that should be validated.
        :type rule: SigmaRule
        :return: A list of SigmaValidationIssue objects describing potential issues.
        :rtype: List[SigmaValidationIssue]
        """
        issues : List[SigmaValidationIssue] = []
        exclusions = self.exclusions[rule.id]
        for validator in self.validators:
            if not validator.__class__ in exclusions:       # Skip if validator is excluded for this rule
                issues.extend(validator.validate(rule))
        return issues

    def finalize(self) -> List[SigmaValidationIssue]:
        """
        Finalize all rule validators, collect their issues and return them as flat list.

        :return: a list of all issues emitted by rule validators on finalization.
        :rtype: List[SigmaValidationIssue]
        """
        return [
            issue
            for validator in self.validators
            for issue in validator.finalize()
        ]

    def validate_rules(self, rules : Iterator[SigmaRule]) -> List[SigmaValidationIssue]:
        """
        Validate Sigma rules. This method runs all validators on all rules and finalizes
        the validators at the end.

        :param rules: Rule collection that should be validated.
        :type rules: Iterator[SigmaRule]
        :return: A list of SigmaValidationIssue objects describing potential issues.
        :rtype: List[SigmaValidationIssue]
        """
        return [
            issue
            for rule in rules
            for issue in self.validate_rule(rule)
        ] + self.finalize()