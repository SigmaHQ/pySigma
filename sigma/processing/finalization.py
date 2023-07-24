from abc import abstractmethod
from dataclasses import dataclass
import json
from typing import Any, Dict, List, Optional

import yaml
import sigma
from sigma.exceptions import SigmaConfigurationError


@dataclass
class Finalizer:
    """Conversion output transformation base class."""

    @classmethod
    def from_dict(cls, d: dict) -> "Finalizer":
        try:
            return cls(**d)
        except TypeError as e:
            raise SigmaConfigurationError("Error in instantiation of finalizer: " + str(e))

    @abstractmethod
    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", queries: List[Any]
    ) -> Any:
        """Finalize output by applying a transformation to the list of generated and postprocessed queries.

        :param pipeline: Processing pipeline this transformation was contained.
        :type pipeline: sigma.processing.pipeline.ProcessingPipeline
        :param queries: List of converted and postprocessed queries that should be finalized.
        :type queries: List[Any]
        :return: Output that can be used in further processing of the conversion result.
        :rtype: Any
        """


@dataclass
class ConcatenateQueriesFinalizer(Finalizer):
    """Concatenate queries with a given separator and embed result within a prefix or suffix
    string."""

    separator: str = "\n"
    prefix: str = ""
    suffix: str = ""

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", queries: List[str]
    ) -> str:
        return self.prefix + self.separator.join(queries) + self.suffix


finalizers: Dict[str, Finalizer] = {
    "concat": ConcatenateQueriesFinalizer,
}


@dataclass
class JSONFinalizer(Finalizer):
    indent: Optional[int] = None

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", queries: List[Any]
    ) -> str:
        return json.dumps(queries, indent=self.indent)


@dataclass
class YAMLFinalizer(Finalizer):
    indent: Optional[int] = None

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", queries: List[Any]
    ) -> str:
        yaml.safe_dump(queries, indent=self.indent)
