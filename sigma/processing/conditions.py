from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict
from sigma.rule import SigmaRule

@dataclass
class ProcessingCondition(ABC):
    """
    Base for Sigma rule processing condition classes used in processing pipelines.
    """
    @abstractmethod
    def match(self, pipeline : "sigma.processing.pipeline.ProcessingPipeline", rule : SigmaRule) -> bool:
        """Match condition on Sigma rule."""

conditions : Dict[str, ProcessingCondition] = {}