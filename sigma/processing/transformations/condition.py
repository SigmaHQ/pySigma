from sigma.conditions import SigmaCondition
from typing import (
    Optional,
    Union,
)
from dataclasses import dataclass, field
import random
import string
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.transformations.base import (
    ConditionTransformation,
)
from sigma.rule import SigmaRule, SigmaDetection


@dataclass
class AddConditionTransformation(ConditionTransformation):
    """
    Add a condition expression to rule conditions.

    If template is set to True the condition values are interpreted as string templates and the
    following placeholders are replaced:

    * $category, $product and $service: with the corresponding values of the Sigma rule log source.
    """

    conditions: dict[str, Union[int, str, list[str]]] = field(default_factory=dict)
    name: str = field(
        default_factory=lambda: "_cond_" + ("".join(random.choices(string.ascii_lowercase, k=10))),
        compare=False,
    )
    template: bool = False
    negated: bool = False

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule]) -> None:
        if isinstance(rule, SigmaRule):
            if self.template:
                conditions = {
                    field: (
                        [
                            (
                                string.Template(item).safe_substitute(
                                    category=rule.logsource.category,
                                    product=rule.logsource.product,
                                    service=rule.logsource.service,
                                )
                                if isinstance(item, str)
                                else item
                            )
                            for item in value
                        ]
                        if isinstance(value, list)
                        else (
                            string.Template(value).safe_substitute(
                                category=rule.logsource.category,
                                product=rule.logsource.product,
                                service=rule.logsource.service,
                            )
                            if isinstance(value, str)
                            else value
                        )
                    )
                    for field, value in self.conditions.items()
                }
            else:
                conditions = self.conditions

            rule.detection.detections[self.name] = SigmaDetection.from_definition(conditions)
            self.processing_item_applied(rule.detection.detections[self.name])
            super().apply(rule)

    def apply_condition(self, cond: SigmaCondition) -> None:
        if cond.condition:  # If condition is not empty
            cond.condition = (
                "not " if self.negated else ""
            ) + f"{self.name} and ({cond.condition})"
        else:  # If condition is empty, just use the added condition name
            cond.condition = ("not " if self.negated else "") + self.name
