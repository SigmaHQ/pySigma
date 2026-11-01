import pytest
import os
from sigma.exceptions import SigmaConfigurationError, SigmaSecurityError
from sigma.policy import SigmaPolicy
from sigma.policy.regex_engine import RE2RegexEngine
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

_ALLOW_VARS_POLICY = SigmaPolicy(regex_engine=RE2RegexEngine(), allow_template_vars=True)


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
    transformation = QuerySimpleTemplateTransformation("""
title = {rule.title}
query = {query}
state = {pipeline.state[test]}
    """)
    transformation.set_pipeline(dummy_pipeline)
    dummy_pipeline.state["test"] = "teststate"
    assert transformation.apply(sigma_rule, 'field="value"') == """
title = Test
query = field="value"
state = teststate
    """


def test_query_template_transformation(dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule):
    transformation = QueryTemplateTransformation("""
title = {{ rule.title }}
query = {{ query }}
state = {{ pipeline.state.test }}
    """)
    transformation.set_pipeline(dummy_pipeline)
    dummy_pipeline.state["test"] = "teststate"
    assert transformation.apply(sigma_rule, 'field="value"') == """
title = Test
query = field="value"
state = teststate
    """


@pytest.mark.parametrize(
    "template_type, template",
    [("simple_template", "[{query}]"), ("template", "[{{ query }}]")],
)
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("applies", [False, True])
def test_query_templates_track_applied_items(sigma_rule, template_type, template, nested, applies):
    items = [
        {
            "id": "rendered",
            "type": template_type,
            "template": template,
            "rule_conditions": [{"type": "logsource", "category": "test" if applies else "other"}],
        },
        {
            "type": "embed",
            "prefix": "after:",
            "rule_conditions": [
                {"type": "processing_item_applied", "processing_item_id": "rendered"}
            ],
        },
    ]
    postprocessing_items = [QueryPostprocessingItem.from_dict(item) for item in items]
    if nested:
        postprocessing_items = [
            QueryPostprocessingItem(NestedQueryPostprocessingTransformation(postprocessing_items))
        ]
    pipeline = ProcessingPipeline(postprocessing_items=postprocessing_items)
    pipeline.apply(sigma_rule)

    query = 'field="value"'
    assert pipeline.postprocess_query(sigma_rule, query) == (
        f"after:[{query}]" if applies else query
    )
    assert sigma_rule.was_processed_by("rendered") is applies
    assert ("rendered" in pipeline.applied_ids) is applies


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


def test_replace_query_transformation_invalid_regex():
    with pytest.raises(SigmaConfigurationError, match="Regular expression .* is invalid"):
        ReplaceQueryTransformation("[invalid", "x")


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


def test_query_template_transformation_with_vars(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    """Test template transformation with custom vars from Python file."""
    transformation = QueryTemplateTransformation(
        template='value = {{ parse_json(\'{"key": "value"}\').key }}\nquery = {{ query }}',
        vars="tests/files/template_vars.py",
        policy=_ALLOW_VARS_POLICY,
    )
    transformation.set_pipeline(dummy_pipeline)
    assert (
        transformation.apply(sigma_rule, 'field="value"') == 'value = value\nquery = field="value"'
    )


def test_query_template_transformation_with_vars_and_path(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    """Test template transformation with custom vars from Python file and template from file."""
    transformation = QueryTemplateTransformation(
        template="finalize.j2",
        path="tests/files",
        vars="tests/files/template_vars.py",
        policy=_ALLOW_VARS_POLICY,
    )
    transformation.set_pipeline(dummy_pipeline)
    dummy_pipeline.state["setting"] = "value"
    result = transformation.apply(sigma_rule, 'field="value"')
    assert "[config]" in result
    assert "setting = value" in result


def test_query_template_transformation_with_json_parsing(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    """Test template with JSON parsing helper function."""
    transformation = QueryTemplateTransformation(
        template='{{ parse_json(\'{"key": "value"}\').key }}',
        vars="tests/files/template_vars.py",
        policy=_ALLOW_VARS_POLICY,
    )
    transformation.set_pipeline(dummy_pipeline)
    assert transformation.apply(sigma_rule, 'field="value"') == "value"


def test_query_template_transformation_with_invalid_vars_file(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    """Test that missing 'vars' dict raises appropriate error."""
    with pytest.raises(ValueError, match="must define a 'vars' dictionary"):
        QueryTemplateTransformation(
            template="test",
            vars="tests/files/invalid_template_vars.py",
            policy=_ALLOW_VARS_POLICY,
        )


def test_query_template_transformation_with_nonexistent_vars_file(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    """Test that nonexistent vars file raises appropriate error."""
    with pytest.raises(ValueError, match="Could not load vars file"):
        QueryTemplateTransformation(
            template="test", vars="tests/files/nonexistent.py", policy=_ALLOW_VARS_POLICY
        )


def test_query_template_transformation_from_dict_with_vars(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    """Test that vars parameter works when loading from pipeline dict with policy."""
    pipeline = ProcessingPipeline.from_dict(
        {
            "postprocessing": [
                {
                    "type": "template",
                    "template": 'value = {{ parse_json(\'{"key": "value"}\').key }}\nquery = {{ query }}',
                    "vars": "tests/files/template_vars.py",
                }
            ]
        },
        policy=_ALLOW_VARS_POLICY,
    )
    rule = SigmaRule.from_yaml("""
        title: Test
        status: test
        logsource:
            category: test
        detection:
            sel:
                field: value
            condition: sel
    """)
    pipeline.apply(rule)
    result = pipeline.postprocess_query(rule, 'field="value"')
    assert result == 'value = value\nquery = field="value"'


def test_query_template_transformation_vars_blocked_by_default(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    """Test that vars usage without allow_template_vars raises SigmaSecurityError."""
    with pytest.raises(SigmaSecurityError, match="disabled by default for security reasons"):
        QueryTemplateTransformation(
            template="test",
            vars="tests/files/template_vars.py",
        )


def test_query_template_transformation_vars_blocked_by_default_from_dict(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    """Test that vars usage from dict without allow_template_vars raises SigmaSecurityError."""
    with pytest.raises(SigmaSecurityError, match="disabled by default for security reasons"):
        QueryTemplateTransformation.from_dict(
            {
                "template": "test",
                "vars": "tests/files/template_vars.py",
            }
        )


def test_query_template_transformation_vars_allowed_via_env(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule, monkeypatch
):
    """Test that vars usage is allowed when env var is set."""
    monkeypatch.setenv("PYSIGMA_ALLOW_VARS_EXECUTION", "1")
    transformation = QueryTemplateTransformation(
        template='{{ parse_json(\'{"key": "value"}\').key }}',
        vars="tests/files/template_vars.py",
    )
    transformation.set_pipeline(dummy_pipeline)
    assert transformation.apply(sigma_rule, 'field="value"') == "value"


def test_query_template_transformation_no_vars_no_error(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    """Test that templates without vars work normally without allow_template_vars."""
    transformation = QueryTemplateTransformation(template="{{ query }}")
    transformation.set_pipeline(dummy_pipeline)
    assert transformation.apply(sigma_rule, 'field="value"') == 'field="value"'


def test_query_template_transformation_vars_allowed_path(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    """Test that vars file under an allowed base path is accepted."""
    policy = SigmaPolicy(
        regex_engine=RE2RegexEngine(),
        allow_template_vars=True,
        vars_allowed_paths=(os.path.realpath("tests/files"),),
    )
    transformation = QueryTemplateTransformation(
        template='{{ parse_json(\'{"key": "value"}\').key }}',
        vars="tests/files/template_vars.py",
        policy=policy,
    )
    transformation.set_pipeline(dummy_pipeline)
    assert transformation.apply(sigma_rule, 'field="value"') == "value"


def test_query_template_transformation_vars_allowed_path_subdir(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    """Test that vars file in a subdirectory of an allowed base path is accepted."""
    policy = SigmaPolicy(
        regex_engine=RE2RegexEngine(),
        allow_template_vars=True,
        vars_allowed_paths=(os.path.realpath("tests"),),
    )
    transformation = QueryTemplateTransformation(
        template='{{ parse_json(\'{"key": "value"}\').key }}',
        vars="tests/files/template_vars.py",
        policy=policy,
    )
    transformation.set_pipeline(dummy_pipeline)
    assert transformation.apply(sigma_rule, 'field="value"') == "value"


def test_query_template_transformation_vars_blocked_by_path_allowlist(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    """Test that vars file outside allowed base paths raises SigmaSecurityError."""
    policy = SigmaPolicy(
        regex_engine=RE2RegexEngine(),
        allow_template_vars=True,
        vars_allowed_paths=("/some/other/directory",),
    )
    with pytest.raises(SigmaSecurityError, match="outside the allowed base directories"):
        QueryTemplateTransformation(
            template="test",
            vars="tests/files/template_vars.py",
            policy=policy,
        )


def test_query_template_transformation_vars_no_path_restriction(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    """Test that vars_allowed_paths=None imposes no path restriction."""
    policy = SigmaPolicy(
        regex_engine=RE2RegexEngine(),
        allow_template_vars=True,
        vars_allowed_paths=None,
    )
    transformation = QueryTemplateTransformation(
        template='{{ parse_json(\'{"key": "value"}\').key }}',
        vars="tests/files/template_vars.py",
        policy=policy,
    )
    transformation.set_pipeline(dummy_pipeline)
    assert transformation.apply(sigma_rule, 'field="value"') == "value"


def test_query_template_transformation_vars_allowed_paths_from_yaml(
    dummy_pipeline: ProcessingPipeline, sigma_rule: SigmaRule
):
    """Test that vars_allowed_paths specified in YAML is stripped and has no effect."""
    with pytest.raises(SigmaSecurityError, match="disabled by default for security reasons"):
        ProcessingPipeline.from_yaml("""
            postprocessing:
              - type: template
                template: "{{ query }}"
                vars: "tests/files/template_vars.py"
                vars_allowed_paths:
                  - "tests/files"
            """)
