from collections import defaultdict
from typing import Any, DefaultDict, Iterable, Iterator, Optional, Set, Type, Union
from uuid import UUID
from sigma.exceptions import SigmaConfigurationError, SigmaValidatorConfigurationParsingError
from sigma.rule import SigmaRule
from sigma.validators.base import SigmaRuleValidator, SigmaValidationIssue
import yaml

from sigma.validators.core import validator_classname_to_identifier


class SigmaValidator:
    """
    A SigmaValidator instantiates the given SigmaRuleValidator classes once at instantiation and
    uses them to check Sigma rules and collections. The validators can keep a state across the
    whole lifecycle of the SigmaValidator and can therefore also conduct uniqueness and other
    checks.

    Exclusions can be defined to exclude validators checks for given rule identifiers.
    """

    validators: set[SigmaRuleValidator]
    exclusions: DefaultDict[Optional[UUID], set[Type[SigmaRuleValidator]]]

    def __init__(
        self,
        validators: Iterable[Type[SigmaRuleValidator]],
        exclusions: dict[Optional[UUID], set[Type[SigmaRuleValidator]]] = dict(),
        config: dict[str, dict[str, Union[str, int, float, bool]]] = dict(),
    ):
        self.validators = {
            validator(**config.get(validator_classname_to_identifier(validator.__name__), {}))
            for validator in validators
        }
        self.exclusions = defaultdict(set, exclusions)

    @classmethod
    def from_dict(
        cls, d: dict[str, Any], validators: dict[str, Type[SigmaRuleValidator]]
    ) -> "SigmaValidator":
        """
        Instantiate SigmaValidator from dict definition. The dict should have the following
        elements:

        * validators: a list of validators to use or not to use, if prefixed with -. The name 'all'
          represents all known validators.
        * exclusion: a map between rule ids and lists of validator names or a single validator name
          to define validation exclusions.
        * config: a map between validator names and configuration dicts that are passed as
          keyword arguments to the validator constructor.

        :param d: Definition of the SigmaValidator.
        :type d: dict
        :param validators: Mapping from string identifiers to validator classes.
        :type validators: dict[str, SigmaRuleValidator]
        :return: Instantiated SigmaValidator
        :rtype: SigmaValidator
        """
        # Build validator class set
        vs = set()
        for v in d.get("validators", []):
            if v == "all":  # all = all known validators
                vs = set(validators.keys())
            elif v.startswith("-"):  # remove validator from set
                vn = v[1:]
                try:
                    vs.remove(vn)
                except KeyError:
                    raise SigmaConfigurationError(
                        f"Attempting to remove not existing validator '{ vn }' from validator set { vs }."
                    )
            else:  # handle as validator name and try to add it to set.
                vs.add(v)

        try:  # convert validator names into classes
            validator_classes = {validators[v] for v in vs}
        except KeyError as e:
            raise SigmaConfigurationError(f"Unknown validator '{ e.args[0] }'")

        # Build exclusion dict
        try:
            exclusions = {
                (UUID(rule_id) if rule_id is not None else None): {
                    validators[
                        exclusion_name
                    ]  # main purpose of the generators: resolve identifiers into classes
                    for exclusion_name in (
                        rule_exclusions if isinstance(rule_exclusions, list) else [rule_exclusions]
                    )
                }
                for rule_id, rule_exclusions in d.get("exclusions", dict()).items()
            }
        except KeyError as e:
            raise SigmaConfigurationError(f"Unknown validator '{ e.args[0] }'")

        # Build configuration dict
        configuration = dict()
        for validator_name, params in d.get("config", {}).items():
            if validator_name not in validators:
                raise SigmaConfigurationError(f"Unknown validator '{ validator_name }'")
            if not isinstance(params, dict):
                raise SigmaConfigurationError(
                    f"Configuration for validator '{ validator_name }' is not a dict."
                )
            configuration[validator_name] = params

        return cls(validator_classes, exclusions, configuration)

    @classmethod
    def from_yaml(
        cls, validator_config: str, validators: dict[str, Type[SigmaRuleValidator]]
    ) -> "SigmaValidator":
        try:
            return cls.from_dict(yaml.safe_load(validator_config), validators)
        except yaml.parser.ParserError as e:
            raise SigmaValidatorConfigurationParsingError(
                f"Error in parsing of a Sigma validation configuration file: {str(e)}"
            ) from e

    def validate_rule(self, rule: SigmaRule) -> list[SigmaValidationIssue]:
        """
        Validate a single rule with all rule validators configured in this SigmaValidator object. A
        rule validator can keep state information across the validation of multiple rules. Therefore
        the validation of a single rule is not necessarily isolated to itself but can also influence
        the result of the validation of other rules or cause that additional issues are emitted on
        finalization of the validator object.

        :param rule: Sigma rule that should be validated.
        :type rule: SigmaRule
        :return: A list of SigmaValidationIssue objects describing potential issues.
        :rtype: list[SigmaValidationIssue]
        """
        issues: list[SigmaValidationIssue] = []
        exclusions = self.exclusions[rule.id]
        for validator in self.validators:
            if validator.__class__ not in exclusions:  # Skip if validator is excluded for this rule
                issues.extend(validator.validate(rule))
        return issues

    def finalize(self) -> list[SigmaValidationIssue]:
        """
        Finalize all rule validators, collect their issues and return them as flat list.

        :return: a list of all issues emitted by rule validators on finalization.
        :rtype: list[SigmaValidationIssue]
        """
        return [issue for validator in self.validators for issue in validator.finalize()]

    def validate_rules(self, rules: Iterator[SigmaRule]) -> list[SigmaValidationIssue]:
        """
        Validate Sigma rules. This method runs all validators on all rules and finalizes
        the validators at the end.

        :param rules: Rule collection that should be validated.
        :type rules: Iterator[SigmaRule]
        :return: A list of SigmaValidationIssue objects describing potential issues.
        :rtype: list[SigmaValidationIssue]
        """
        return [issue for rule in rules for issue in self.validate_rule(rule)] + self.finalize()
