from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Pattern, Literal, Optional
import re
from sigma.rule import SigmaRule, SigmaDetectionItem, SigmaLogSource
from sigma.exceptions import SigmaConfigurationError

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

### Condition mappings between rule identifier and class

rule_conditions : Dict[str, RuleProcessingCondition] = {
    "logsource": LogsourceCondition,
}
detection_item_conditions : Dict[str, DetectionItemProcessingCondition] = {
    "include_fields": IncludeFieldCondition,
    "exclude_fields": ExcludeFieldCondition,
}