from dataclasses import dataclass
from sigma.processing.conditions.base import RuleProcessingCondition
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from typing import Union

@dataclass
class LogsourceCategoryStartsWithCondition(RuleProcessingCondition):
    """
    Matches if the logsource category of a rule starts with a given prefix.
    """
    prefix: str

    def match(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        if isinstance(rule, SigmaRule):
            return rule.logsource.category is not None and rule.logsource.category.startswith(self.prefix)
        elif isinstance(rule, SigmaCorrelationRule):
            # This condition is not supported for correlation rules for now.
            return False
