from abc import abstractmethod
from dataclasses import dataclass, field
import json
from typing import Any, Dict, List, Optional, Type, TYPE_CHECKING

import yaml
from sigma.exceptions import SigmaConfigurationError, SigmaTransformationError

from sigma.processing.templates import TemplateBase

if TYPE_CHECKING:
    from sigma.processing.pipeline import ProcessingPipeline


@dataclass
class Finalizer:
    """Conversion output transformation base class."""

    _pipeline: Optional["ProcessingPipeline"] = field(init=False, compare=False, default=None)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finalizer":
        try:
            return cls(**d)
        except TypeError as e:
            raise SigmaConfigurationError("Error in instantiation of finalizer: " + str(e))

    def set_pipeline(self, pipeline: "ProcessingPipeline") -> None:
        if self._pipeline is None:
            self._pipeline = pipeline
        else:
            raise SigmaTransformationError("Pipeline for finalizer was already set.")

    @abstractmethod
    def apply(self, queries: List[Any]) -> Any:
        """Finalize output by applying a transformation to the list of generated and postprocessed queries.

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

    def apply(self, queries: List[str]) -> str:
        return self.prefix + self.separator.join(queries) + self.suffix


@dataclass
class JSONFinalizer(Finalizer):
    indent: Optional[int] = None

    def apply(self, queries: List[Any]) -> str:
        return json.dumps(queries, indent=self.indent)


@dataclass
class YAMLFinalizer(Finalizer):
    indent: Optional[int] = None

    def apply(self, queries: List[Any]) -> str:
        return yaml.safe_dump(queries, indent=self.indent)


@dataclass
class TemplateFinalizer(Finalizer, TemplateBase):
    """Apply Jinja2 template provided as template object variable to the queries. The following
    variables are available in the context:

    * queries: all post-processed queries generated by the backend.
    * pipeline: the Sigma processing pipeline where this transformation is applied including all
      current state information in pipeline.state.

    if *path* is given, *template* is considered as a relative path to a template file below the
    specified path. If it is not provided, the template is specified as plain string. *autoescape*
    controls the Jinja2 HTML/XML auto-escaping.
    """

    def apply(self, queries: List[Any]) -> str:
        return self.j2template.render(queries=queries, pipeline=self._pipeline)


@dataclass
class NestedFinalizer(Finalizer):
    """Apply a list of finalizers to the queries in a nested fashion."""

    finalizers: List[Finalizer]
    _nested_pipeline: "ProcessingPipeline" = field(init=False, compare=False)

    def __post_init__(self) -> None:
        from sigma.processing.pipeline import (
            ProcessingPipeline,
        )  # TODO: move to top after restructuring code.

        self._nested_pipeline = ProcessingPipeline(finalizers=self.finalizers)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "NestedFinalizer":
        if "finalizers" not in d:
            raise SigmaConfigurationError("Nested finalizer requires a 'finalizers' key.")
        fs = []
        for finalizer in d["finalizers"]:
            try:
                finalizer_type = finalizer.pop("type")
            except KeyError:
                raise SigmaConfigurationError("Finalizer type not specified for: " + str(finalizer))
            fs.append(finalizers[finalizer_type].from_dict(finalizer))
        return cls(finalizers=fs)

    def apply(self, queries: List[Any]) -> Any:
        return self._nested_pipeline.finalize(queries)


finalizers: Dict[str, Type[Finalizer]] = {
    "concat": ConcatenateQueriesFinalizer,
    "json": JSONFinalizer,
    "yaml": YAMLFinalizer,
    "template": TemplateFinalizer,
    "nested": NestedFinalizer,
}
