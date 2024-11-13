import pytest
from sigma.exceptions import SigmaConfigurationError
from sigma.processing.pipeline import ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.postprocessing import (
    EmbedQueryInJSONTransformation,
    EmbedQueryTransformation,
    NestedQueryPostprocessingTransformation,
    QuerySimpleTemplateTransformation,
    QueryTemplateTransformation,
    ReplaceQueryTransformation,
)
from sigma.rule import SigmaRule
from .test_processing_transformations import dummy_pipeline, sigma_rule


def test_embed_query_transformation(dummy_pipeline, sigma_rule):
    transformation = EmbedQueryTransformation("[ ", " ]")
    transformation.set_pipeline(dummy_pipeline)
    assert transformation.apply(sigma_rule, "field=value") == "[ field=value ]"


def test_embed_query_transformation_none(dummy_pipeline, sigma_rule):
    transformation = EmbedQueryTransformation()
    transformation.set_pipeline(dummy_pipeline)
    assert transformation.apply(sigma_rule, "field=value") == "field=value"


def test_query_simple_template_transformation(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    transformation = QuerySimpleTemplateTransformation(
        """
title = {rule.title}
query = {query}
state = {pipeline.state[test]}
    """
    )
    transformation.set_pipeline(dummy_pipeline)
    dummy_pipeline.state["test"] = "teststate"
    assert (
        transformation.apply(sigma_rule, 'field="value"')
        == """
title = Test
query = field="value"
state = teststate
    """
    )


def test_query_template_transformation(dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule):
    transformation = QueryTemplateTransformation(
        """
title = {{ rule.title }}
query = {{ query }}
state = {{ pipeline.state.test }}
    """
    )
    transformation.set_pipeline(dummy_pipeline)
    dummy_pipeline.state["test"] = "teststate"
    assert (
        transformation.apply(sigma_rule, 'field="value"')
        == """
title = Test
query = field="value"
state = teststate
    """
    )


def test_embed_query_in_json_transformation_dict(dummy_pipeline, sigma_rule):
    transformation = EmbedQueryInJSONTransformation('{ "field": "value", "query": "%QUERY%" }')
    transformation.set_pipeline(dummy_pipeline)
    assert (
        transformation.apply(sigma_rule, 'field="value"')
        == '{"field": "value", "query": "field=\\"value\\""}'
    )


def test_embed_query_in_json_transformation_list(dummy_pipeline, sigma_rule):
    transformation = EmbedQueryInJSONTransformation(
        '{ "field": "value", "query": ["foo", "%QUERY%", "bar"] }'
    )
    transformation.set_pipeline(dummy_pipeline)
    assert (
        transformation.apply(sigma_rule, 'field="value"')
        == '{"field": "value", "query": ["foo", "field=\\"value\\"", "bar"]}'
    )


def test_replace_query_transformation(dummy_pipeline, sigma_rule):
    transformation = ReplaceQueryTransformation("v\\w+e", "replaced")
    transformation.set_pipeline(dummy_pipeline)
    assert transformation.apply(sigma_rule, 'field="value"') == 'field="replaced"'


@pytest.fixture
def nested_query_postprocessing_transformation(dummy_pipeline):
    transformation = NestedQueryPostprocessingTransformation(
        items=[
            QueryPostprocessingItem(ReplaceQueryTransformation("foo", "bar")),
            QueryPostprocessingItem(EmbedQueryTransformation("[", "]"), identifier="test"),
            QueryPostprocessingItem(
                QuerySimpleTemplateTransformation("title = {rule.title}\nquery = {query}")
            ),
        ]
    )
    transformation.set_pipeline(dummy_pipeline)
    return transformation


def test_nested_query_postprocessing_transformation_from_dict(
    nested_query_postprocessing_transformation,
):
    assert (
        NestedQueryPostprocessingTransformation.from_dict(
            {
                "items": [
                    {"type": "replace", "pattern": "foo", "replacement": "bar"},
                    {"type": "embed", "prefix": "[", "suffix": "]", "id": "test"},
                    {
                        "type": "simple_template",
                        "template": "title = {rule.title}\nquery = {query}",
                    },
                ],
            }
        )
        == nested_query_postprocessing_transformation
    )


def test_nested_query_postprocessing_transformation_no_items():
    with pytest.raises(
        SigmaConfigurationError,
        match="Nested post-processing transformation requires an 'items' key.",
    ):
        NestedQueryPostprocessingTransformation.from_dict({})


def test_nested_query_postprocessing_transformation(
    nested_query_postprocessing_transformation, sigma_rule
):
    result = nested_query_postprocessing_transformation.apply(sigma_rule, 'field="foobar"')
    assert result == 'title = Test\nquery = [field="barbar"]'
    assert sigma_rule.was_processed_by("test")
