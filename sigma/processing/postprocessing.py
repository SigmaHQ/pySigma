from abc import abstractmethod
from dataclasses import dataclass, field
import json
import re
from typing import Any, Optional, Type, Union, TYPE_CHECKING
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaConfigurationError
import sigma.processing.postprocessing
from sigma.processing.templates import TemplateBase
from sigma.processing.transformations import Transformation
from sigma.rule import SigmaRule

if TYPE_CHECKING:
    from sigma.processing.pipeline import QueryPostprocessingItem, ProcessingPipeline


@dataclass
class QueryPostprocessingTransformation(Transformation):
    """Query post processing transformation base class."""

    processing_item: Optional["QueryPostprocessingItem"] = field(
        init=False, compare=False, default=None
    )

    @abstractmethod
    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule], query: Any) -> Any:
        """Applies post-processing transformation to arbitrary typed query.

        :param pipeline: Processing pipeline this transformation was contained.
        :type pipeline: sigma.processing.pipeline.ProcessingPipeline
        :param rule: Sigma rule that is associated with the generated query.
        :type rule: SigmaRule
        :param query: Query that should be transformed.
        :type query: Any
        :return: Transformed query.
        :rtype: Any
        """
        self.processing_item_applied(rule)


@dataclass
class EmbedQueryTransformation(QueryPostprocessingTransformation):
    """Embeds a query between a given prefix and suffix. Only applicable to string queries."""

    prefix: str = ""
    suffix: str = ""

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule], query: Any) -> Any:
        super().apply(rule, query)
        if isinstance(query, str):
            return self.prefix + query + self.suffix
        raise TypeError("Query must be a string for EmbedQueryTransformation.")


@dataclass
class QuerySimpleTemplateTransformation(QueryPostprocessingTransformation):
    """
    Replace query with template that can refer to the following placeholders:

    * query: the postprocessed query.
    * rule: the Sigma rule including all its attributes like `rule.title`.
    * pipeline: the Sigma processing pipeline where this transformation is applied including all
      current state information in pipeline.state.

    The Python format string syntax (str.format()) is used.
    """

    template: str

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule], query: Any) -> Any:
        return self.template.format(
            query=query,
            rule=rule,
            pipeline=self._pipeline,
        )


@dataclass
class QueryTemplateTransformation(QueryPostprocessingTransformation, TemplateBase):
    """Apply Jinja2 template provided as template object variable to a query. The following
    variables are available in the context:

    * query: the postprocessed query.
    * rule: the Sigma rule including all its attributes like rule.title.
    * pipeline: the Sigma processing pipeline where this transformation is applied including all
      current state information in pipeline.state.

    if *path* is given, *template* is considered as a relative path to a template file below the
    specified path. If it is not provided, the template is specified as plain string. *autoescape*
    controls the Jinja2 HTML/XML auto-escaping.

    if *vars* is given, it should point to a Python file containing helper functions and variables
    to be made available in the Jinja2 template context. See TemplateBase for details on the format.
    """

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule], query: Any) -> Any:
        return self.j2template.render(query=query, rule=rule, pipeline=self._pipeline)


@dataclass
class EmbedQueryInJSONTransformation(QueryPostprocessingTransformation):
    """Embeds a query into a JSON structure defined as string. the placeholder value %QUERY% is
    replaced with the query."""

    json_template: str

    def _replace_placeholder(
        self, v: Union[dict[str, Any], list[Any], str, int, float], query: str
    ) -> Union[dict[str, Any], list[Any], str, int, float]:
        if isinstance(v, dict):
            return {k: self._replace_placeholder(v, query) for k, v in v.items()}
        elif isinstance(v, list):
            return [self._replace_placeholder(i, query) for i in v]
        elif isinstance(v, str) and v == "%QUERY%":
            return query
        else:
            return v

    def __post_init__(self) -> None:
        self.parsed_json = json.loads(self.json_template)

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule], query: Any) -> Any:
        super().apply(rule, query)
        return json.dumps(self._replace_placeholder(self.parsed_json, query))


@dataclass
class ReplaceQueryTransformation(QueryPostprocessingTransformation):
    """Replace query part specified by regular expression with a given string."""

    pattern: str
    replacement: str

    def __post_init__(self) -> None:
        self.re = re.compile(self.pattern)

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule], query: Any) -> Any:
        super().apply(rule, query)
        return self.re.sub(self.replacement, query)


@dataclass
class NestedQueryPostprocessingTransformation(QueryPostprocessingTransformation):
    """Applies a list of query postprocessing transformations to the query in a nested manner."""

    items: list["QueryPostprocessingItem"]
    _nested_pipeline: "ProcessingPipeline" = field(init=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        from sigma.processing.pipeline import (
            ProcessingPipeline,
        )  # TODO: move to top-level after restructuring code

        self._nested_pipeline = ProcessingPipeline(postprocessing_items=self.items)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "NestedQueryPostprocessingTransformation":
        from sigma.processing.pipeline import QueryPostprocessingItem

        try:
            return NestedQueryPostprocessingTransformation(
                items=[QueryPostprocessingItem.from_dict(item) for item in d["items"]]
            )
        except KeyError:
            raise SigmaConfigurationError(
                "Nested post-processing transformation requires an 'items' key."
            )

    def apply(self, rule: Union[SigmaRule, SigmaCorrelationRule], query: Any) -> Any:
        super().apply(rule, query)
        query = self._nested_pipeline.postprocess_query(rule, query)
        if self._pipeline is not None:
            self._pipeline.applied_ids.update(self._nested_pipeline.applied_ids)
        return query


query_postprocessing_transformations: dict[str, Type[QueryPostprocessingTransformation]] = {
    "embed": EmbedQueryTransformation,
    "simple_template": QuerySimpleTemplateTransformation,
    "template": QueryTemplateTransformation,
    "json": EmbedQueryInJSONTransformation,
    "replace": ReplaceQueryTransformation,
    "nest": NestedQueryPostprocessingTransformation,
}
