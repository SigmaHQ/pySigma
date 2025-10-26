import pytest
from sigma.exceptions import SigmaConfigurationError, SigmaTransformationError
from sigma.processing.finalization import (
    ConcatenateQueriesFinalizer,
    NestedFinalizer,
    TemplateFinalizer,
)
from .test_processing_transformations import dummy_pipeline, sigma_rule


def test_finalization_multiple_pipeline_set(dummy_pipeline):
    finalizer = ConcatenateQueriesFinalizer()
    finalizer.set_pipeline(dummy_pipeline)
    with pytest.raises(SigmaTransformationError, match="Pipeline.*already set"):
        finalizer.set_pipeline(dummy_pipeline)


def test_concatenate_queries_tranformation(dummy_pipeline):
    transformation = ConcatenateQueriesFinalizer(separator="', '", prefix="('", suffix="')")
    transformation.set_pipeline(dummy_pipeline)
    assert (
        transformation.apply(['field1="value1"', 'field2="value2"'])
        == """('field1="value1"', 'field2="value2"')"""
    )


def test_template_transformation(dummy_pipeline):
    dummy_pipeline.state["setting"] = "value"
    transformation = TemplateFinalizer(
        """
[config]
setting = {{ pipeline.state.setting }}

[queries]{% for query in queries %}
query{{ loop.index }} = {{ query }}{% endfor %}
"""
    )
    transformation.set_pipeline(dummy_pipeline)
    assert (
        transformation.apply(
            [
                "fieldA=val1",
                "fieldB=val2",
                "fieldC=val3",
            ],
        )
        == """
[config]
setting = value

[queries]
query1 = fieldA=val1
query2 = fieldB=val2
query3 = fieldC=val3"""
    )


def test_template_transformation_from_file(dummy_pipeline):
    dummy_pipeline.state["setting"] = "value"
    transformation = TemplateFinalizer(template="finalize.j2", path="tests/files")
    transformation.set_pipeline(dummy_pipeline)
    assert (
        transformation.apply(
            [
                "fieldA=val1",
                "fieldB=val2",
                "fieldC=val3",
            ],
        )
        == """[config]
setting = value

[queries]
query1 = fieldA=val1
query2 = fieldB=val2
query3 = fieldC=val3"""
    )


@pytest.fixture
def nested_finalizer(dummy_pipeline):
    nested_finalizer = NestedFinalizer(
        finalizers=[
            ConcatenateQueriesFinalizer(separator="', '", prefix="('", suffix="')"),
            TemplateFinalizer("allOf({{ queries }})"),
        ]
    )
    nested_finalizer.set_pipeline(dummy_pipeline)
    return nested_finalizer


def test_nested_finalizer_from_dict(nested_finalizer):
    NestedFinalizer.from_dict(
        {
            "finalizers": [
                {
                    "type": "concat",
                    "separator": "', '",
                    "prefix": "('",
                    "suffix": "')",
                },
                {
                    "type": "template",
                    "template": "allOf({{ queries }})",
                },
            ]
        }
    ) == nested_finalizer


def test_nested_finalizer_no_finalizers():
    with pytest.raises(
        SigmaConfigurationError, match="Nested finalizer requires a 'finalizers' key."
    ):
        NestedFinalizer.from_dict({})


def test_nested_finalizer_no_type():
    with pytest.raises(SigmaConfigurationError, match="Finalizer type not specified"):
        NestedFinalizer.from_dict({"finalizers": [{"foo": "bar"}]})


def test_nested_finalizer_apply(nested_finalizer):
    assert (
        nested_finalizer.apply(
            [
                "fieldA=val1",
                "fieldB=val2",
                "fieldC=val3",
            ],
        )
        == """allOf(('fieldA=val1', 'fieldB=val2', 'fieldC=val3'))"""
    )


def test_template_finalizer_with_vars(dummy_pipeline):
    """Test finalizer with custom vars from Python file."""
    transformation = TemplateFinalizer(
        template="price = {{ format_price(19.99) }}",
        vars="tests/files/template_vars.py"
    )
    transformation.set_pipeline(dummy_pipeline)
    assert transformation.apply(["query1", "query2"]) == "price = 19.99€"


def test_template_finalizer_with_vars_and_queries(dummy_pipeline):
    """Test finalizer with custom vars and query iteration."""
    transformation = TemplateFinalizer(
        template="{% for query in queries %}{{ format_price(loop.index * 10) }}{% if not loop.last %}, {% endif %}{% endfor %}",
        vars="tests/files/template_vars.py"
    )
    transformation.set_pipeline(dummy_pipeline)
    assert transformation.apply(["query1", "query2", "query3"]) == "10.00€, 20.00€, 30.00€"


def test_template_finalizer_with_json_helper(dummy_pipeline):
    """Test finalizer with JSON parsing helper."""
    transformation = TemplateFinalizer(
        template='{{ parse_json(\'{"queries": ["q1", "q2"]}\').queries | join(", ") }}',
        vars="tests/files/template_vars.py"
    )
    transformation.set_pipeline(dummy_pipeline)
    assert transformation.apply(["query1", "query2"]) == "q1, q2"


def test_template_finalizer_with_invalid_vars_file(dummy_pipeline):
    """Test that missing 'vars' dict raises appropriate error."""
    with pytest.raises(ValueError, match="must define a 'vars' dictionary"):
        TemplateFinalizer(
            template="test",
            vars="tests/files/invalid_template_vars.py"
        )


def test_template_finalizer_splunk_rba_use_case(dummy_pipeline):
    """Test real-world Splunk RBA use case from the issue."""
    # This demonstrates the exact use case from the issue:
    # Mapping logsource categories to risk objects and categories
    transformation = TemplateFinalizer(
        template="""{% for query in queries %}
| Risk Based Alerting
| eval risk_object="{{ get_risk_object('process_creation') }}"
| eval risk_category="{{ get_risk_category('process_creation') }}"
| eval {{ format_risk_score(75) }}
{% endfor %}""",
        vars="tests/files/splunk_rba_helpers.py"
    )
    transformation.set_pipeline(dummy_pipeline)
    result = transformation.apply(["query1"])
    assert "risk_object=\"system\"" in result
    assert "risk_category=\"malware\"" in result
    assert "risk_score=75" in result
