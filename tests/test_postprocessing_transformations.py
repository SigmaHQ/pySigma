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
from .test_backend_identifier import DummyBackend


def test_embed_query_transformation(dummy_pipeline, sigma_rule):
    transformation = EmbedQueryTransformation("[ ", " ]")
    assert transformation.apply(dummy_pipeline, sigma_rule, "field=value") == "[ field=value ]"


def test_embed_query_transformation_none(dummy_pipeline, sigma_rule):
    transformation = EmbedQueryTransformation()
    assert transformation.apply(dummy_pipeline, sigma_rule, "field=value") == "field=value"


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
    dummy_pipeline.state["test"] = "teststate"
    assert (
        transformation.apply(dummy_pipeline, sigma_rule, 'field="value"')
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
backend_id = {{ backend.identifier }}
    """
    )
    dummy_pipeline.state["test"] = "teststate"

    assert (
        transformation.apply(dummy_pipeline, sigma_rule, 'field="value"', DummyBackend)
        == """
title = Test
query = field="value"
state = teststate
backend_id = dummy
    """
    )


def test_embed_query_in_json_transformation_dict(dummy_pipeline, sigma_rule):
    transformation = EmbedQueryInJSONTransformation('{ "field": "value", "query": "%QUERY%" }')
    assert (
        transformation.apply(dummy_pipeline, sigma_rule, 'field="value"')
        == '{"field": "value", "query": "field=\\"value\\""}'
    )


def test_embed_query_in_json_transformation_list(dummy_pipeline, sigma_rule):
    transformation = EmbedQueryInJSONTransformation(
        '{ "field": "value", "query": ["foo", "%QUERY%", "bar"] }'
    )
    assert (
        transformation.apply(dummy_pipeline, sigma_rule, 'field="value"')
        == '{"field": "value", "query": ["foo", "field=\\"value\\"", "bar"]}'
    )


def test_replace_query_transformation(dummy_pipeline, sigma_rule):
    transformation = ReplaceQueryTransformation("v\\w+e", "replaced")
    assert transformation.apply(dummy_pipeline, sigma_rule, 'field="value"') == 'field="replaced"'


@pytest.fixture
def nested_query_postprocessing_transformation():
    return NestedQueryPostprocessingTransformation(
        items=[
            QueryPostprocessingItem(ReplaceQueryTransformation("foo", "bar")),
            QueryPostprocessingItem(EmbedQueryTransformation("[", "]"), identifier="test"),
            QueryPostprocessingItem(
                QuerySimpleTemplateTransformation("title = {rule.title}\nquery = {query}")
            ),
        ]
    )


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
    nested_query_postprocessing_transformation, dummy_pipeline, sigma_rule
):
    result = nested_query_postprocessing_transformation.apply(
        dummy_pipeline, sigma_rule, 'field="foobar"'
    )
    assert result == 'title = Test\nquery = [field="barbar"]'
    assert sigma_rule.was_processed_by("test")
