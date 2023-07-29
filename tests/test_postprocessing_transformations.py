from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.postprocessing import (
    EmbedQueryInJSONTransformation,
    EmbedQueryTransformation,
    QuerySimpleTemplateTransformation,
    QueryTemplateTransformation,
)
from sigma.rule import SigmaRule
from .test_processing_transformations import dummy_pipeline, sigma_rule


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
