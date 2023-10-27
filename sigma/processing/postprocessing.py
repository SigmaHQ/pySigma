from abc import abstractmethod
from dataclasses import dataclass, field
import json
import re
from typing import Any, Dict, List, Optional, Union
import sigma
from sigma.processing.templates import TemplateBase
from sigma.processing.transformations import Transformation
from sigma.rule import SigmaRule


@dataclass
class QueryPostprocessingTransformation(Transformation):
    """Query post processing transformation base class."""

    processing_item: Optional["sigma.processing.pipeline.QueryPostprocessingItem"] = field(
        init=False, compare=False, default=None
    )

    @abstractmethod
    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule, query: Any
    ) -> Any:
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
        super().apply(pipeline, rule)  # tracking of applied rules and assigning self.pipeline


@dataclass
class EmbedQueryTransformation(QueryPostprocessingTransformation):
    """Embeds a query between a given prefix and suffix. Only applicable to string queries."""

    prefix: Optional[str] = None
    suffix: Optional[str] = None

    def __post_init__(self):
        self.prefix = self.prefix or ""
        self.suffix = self.suffix or ""

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule, query: str
    ) -> str:
        super().apply(pipeline, rule, query)
        return self.prefix + query + self.suffix


@dataclass
class QuerySimpleTemplateTransformation(QueryPostprocessingTransformation):
    """Replace query with template that can refer to the following placeholders:
    * query: the postprocessed query.
    * rule: the Sigma rule including all its attributes like rule.title.
    * pipeline: the Sigma processing pipeline where this transformation is applied including all
      current state information in pipeline.state.

    The Python format string syntax (str.format()) is used.
    """

    template: str

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule, query: str
    ) -> str:
        return self.template.format(
            query=query,
            rule=rule,
            pipeline=pipeline,
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
    """

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule, query: str
    ) -> str:
        return self.j2template.render(query=query, rule=rule, pipeline=pipeline)


@dataclass
class EmbedQueryInJSONTransformation(QueryPostprocessingTransformation):
    """Embeds a query into a JSON structure defined as string. the placeholder value %QUERY% is
    replaced with the query."""

    json_template: str

    def _replace_placeholder(
        self, v: Union[Dict, List, str, int, float], query: str
    ) -> Union[Dict, List, str, int, float]:
        if isinstance(v, dict):
            return {k: self._replace_placeholder(v, query) for k, v in v.items()}
        elif isinstance(v, list):
            return [self._replace_placeholder(i, query) for i in v]
        elif isinstance(v, str) and v == "%QUERY%":
            return query
        else:
            return v

    def __post_init__(self):
        self.parsed_json = json.loads(self.json_template)

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule, query: str
    ):
        super().apply(pipeline, rule, query)
        return json.dumps(self._replace_placeholder(self.parsed_json, query))


@dataclass
class ReplaceQueryTransformation(QueryPostprocessingTransformation):
    """Replace query part specified by regular expression with a given string."""

    pattern: str
    replacement: str

    def __post_init__(self):
        self.re = re.compile(self.pattern)

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule, query: str
    ):
        super().apply(pipeline, rule, query)
        return self.re.sub(self.replacement, query)


query_postprocessing_transformations = {
    "embed": EmbedQueryTransformation,
    "simple_template": QuerySimpleTemplateTransformation,
    "template": QueryTemplateTransformation,
    "json": EmbedQueryInJSONTransformation,
    "replace": ReplaceQueryTransformation,
}
