from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import sigma
from sigma.types import SigmaString, SigmaType
from typing import Dict, List, Pattern, Literal, Optional
import re
from sigma.rule import SigmaRule, SigmaDetectionItem, SigmaLogSource
from sigma.exceptions import SigmaConfigurationError, SigmaRegularExpressionError

### Base Classes ###

@dataclass
class RuleProcessingCondition(ABC):
    """
    Base for Sigma rule processing condition classes used in processing pipelines.
    """
    @abstractmethod
    def match(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", rule : SigmaRule) -> bool:
        """Match condition on Sigma rule."""

@dataclass
class DetectionItemProcessingCondition(ABC):
    """
    Base for Sigma detection item processing condition classes used in processing pipelines.
    """
    @abstractmethod
    def match(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", detection_item : SigmaDetectionItem) -> bool:
        """Match condition on Sigma rule."""

@dataclass
class ValueProcessingCondition(DetectionItemProcessingCondition):
    """
    Base class for conditions on values in detection items. The 'cond' parameter determines if any or all
    values of a multivalued detection item must match to result in an overall match.

    The method match_value is called for each value and must return a bool result. It should reject values
    which are incompatible with the condition with a False return value.
    """
    cond : Literal["any", "all"]

    def __post_init__(self):
        if self.cond == "any":
            self.match_func = any
        elif self.cond == "all":
            self.match_func = all
        else:
            raise SigmaConfigurationError(f"The parameter '{self.cond}' for the 'match' parameter is invalid. It must be 'any' or 'all'.")

    def match(self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", detection_item: SigmaDetectionItem) -> bool:
        return self.match_func((
            self.match_value(pipeline, value)
            for value in detection_item.value
        ))

    @abstractmethod
    def match_value(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", value : SigmaType) -> bool:
        """Match condition on detection item values."""

### Rule Condition Classes ###
@dataclass
class LogsourceCondition(RuleProcessingCondition):
    """
    Matches log source on rule. Not specified log source fields are ignored.
    """
    category : Optional[str] = field(default=None)
    product : Optional[str] = field(default=None)
    service : Optional[str] = field(default=None)

    def __post_init__(self):
        self.logsource = SigmaLogSource(self.category, self.product, self.service)

    def match(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", rule : SigmaRule) -> bool:
        return rule.logsource in self.logsource

### Detection Item Condition Classes ###
@dataclass
class IncludeFieldCondition(DetectionItemProcessingCondition):
    """
    Matches on field name if it is contained in fields list. The parameter 'type' determines if field names are matched as
    plain string ("plain") or regular expressions ("re").
    """
    fields : List[str]
    type : Literal["plain", "re"] = field(default="plain")
    patterns : List[Pattern] = field(init=False, repr=False, default_factory=list)

    def __post_init__(self):
        """
        Check if type is known and pre-compile regular expressions.
        """
        if self.type == "plain":
            pass
        elif self.type == "re":
            self.patterns = [
                re.compile(field)
                for field in self.fields
            ]
        else:
            raise SigmaConfigurationError(f"Invalid detection item field name condition type '{self.type}', supported types are 'plain' or 're'.")

    def match(self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", detection_item: SigmaDetectionItem) -> bool:
        if self.type == "plain":
            return detection_item.field in self.fields
        else:   # regular expression matching
            return any((
                pattern.match(detection_item.field)
                for pattern in self.patterns
             ))

@dataclass
class ExcludeFieldCondition(IncludeFieldCondition):
    """Matches on field name if it is not contained in fields list."""
    def match(self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", detection_item: SigmaDetectionItem) -> bool:
        return not super().match(pipeline, detection_item)

@dataclass
class MatchStringCondition(ValueProcessingCondition):
    """
    Match string values with a regular expression 'pattern'. The parameter 'cond' determines for detection items with multiple
    values if any or all strings must match. Generally, values which aren't strings are skipped in any mode or result in a
    false result in all match mode.
    """
    pattern : str

    def __post_init__(self):
        super().__post_init__()
        try:
            self.re = re.compile(self.pattern)
        except re.error as e:
            raise SigmaRegularExpressionError(f"Regular expression '{self.pattern}' is invalid: {str(e)}") from e

    def match_value(self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", value: SigmaType) -> bool:
        if isinstance(value, SigmaString):
            return self.re.match(str(value))
        else:
            return False

### Condition mappings between rule identifier and class

rule_conditions : Dict[str, RuleProcessingCondition] = {
    "logsource": LogsourceCondition,
}
detection_item_conditions : Dict[str, DetectionItemProcessingCondition] = {
    "include_fields": IncludeFieldCondition,
    "exclude_fields": ExcludeFieldCondition,
    "match_string": MatchStringCondition,
}