from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List
from sigma.rule import SigmaRule, SigmaDetectionItem

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

### Detection Item Condition Classes ###
@dataclass
class IncludeFieldCondition(DetectionItemProcessingCondition):
    """Matches on field name if it is contained in fields list."""
    fields : List[str]

    def match(self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", detection_item: SigmaDetectionItem) -> bool:
        return detection_item.field in self.fields

@dataclass
class ExcludeFieldCondition(IncludeFieldCondition):
    """Matches on field name if it is not contained in fields list."""
    def match(self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", detection_item: SigmaDetectionItem) -> bool:
        return not super().match(pipeline, detection_item)

rule_conditions : Dict[str, RuleProcessingCondition] = {}
detection_item_conditions : Dict[str, DetectionItemProcessingCondition] = {
    "include_fields": IncludeFieldCondition,
    "exclude_fields": ExcludeFieldCondition,
}