import pytest
from sigma.exceptions import SigmaConfigurationError
from sigma.processing.finalization import (
    ConcatenateQueriesFinalizer,
    NestedFinalizer,
    TemplateFinalizer,
)
from .test_processing_transformations import dummy_pipeline, sigma_rule


def test_concatenate_queries_tranformation(dummy_pipeline):
    transformation = ConcatenateQueriesFinalizer(separator="', '", prefix="('", suffix="')")
    assert (
        transformation.apply(dummy_pipeline, ['field1="value1"', 'field2="value2"'])
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
    assert (
        transformation.apply(
            dummy_pipeline,
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
    assert (
        transformation.apply(
            dummy_pipeline,
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
    return NestedFinalizer(
        finalizers=[
            ConcatenateQueriesFinalizer(separator="', '", prefix="('", suffix="')"),
            TemplateFinalizer("allOf({{ queries }})"),
        ]
    )


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
            dummy_pipeline,
            [
                "fieldA=val1",
                "fieldB=val2",
                "fieldC=val3",
            ],
        )
        == """allOf(('fieldA=val1', 'fieldB=val2', 'fieldC=val3'))"""
    )
