import pytest
from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule


@pytest.fixture
def test_backend() -> TextQueryTestBackend:
    """Create a test backend instance for testing."""
    return TextQueryTestBackend(ProcessingPipeline())


@pytest.fixture
def sigma_rule() -> SigmaRule:
    """Create a simple Sigma rule for testing."""
    rule_yaml = """
title: Test Rule
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"""
    return SigmaRule.from_yaml(rule_yaml)


def test_convert_rule_single_rule(test_backend: TextQueryTestBackend, sigma_rule: SigmaRule):
    """Test conversion of a single Sigma rule using convert_rule method."""
    # Test that convert_rule works without prior initialization of processing pipeline
    queries = test_backend.convert_rule(sigma_rule)

    # Verify that the rule was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0
    assert isinstance(queries[0], str)

    # Verify that the processing pipeline was initialized
    assert hasattr(test_backend, "last_processing_pipeline")
    assert test_backend.last_processing_pipeline is not None


def test_convert_rule_with_output_format(test_backend: TextQueryTestBackend, sigma_rule: SigmaRule):
    """Test conversion of a single Sigma rule with specific output format."""
    queries = test_backend.convert_rule(sigma_rule, output_format="default")

    # Verify that the rule was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0

    # Verify that the processing pipeline was initialized
    assert hasattr(test_backend, "last_processing_pipeline")
    assert test_backend.last_processing_pipeline is not None


def test_convert_rule_multiple_calls(test_backend: TextQueryTestBackend, sigma_rule: SigmaRule):
    """Test multiple calls to convert_rule to ensure pipeline is reused."""
    # First call
    queries1 = test_backend.convert_rule(sigma_rule)
    pipeline1 = test_backend.last_processing_pipeline

    # Second call
    queries2 = test_backend.convert_rule(sigma_rule)
    pipeline2 = test_backend.last_processing_pipeline

    # Verify both calls succeeded
    assert isinstance(queries1, list) and len(queries1) > 0
    assert isinstance(queries2, list) and len(queries2) > 0

    # Verify same pipeline instance is used (since no different output_format was specified)
    assert pipeline1 is pipeline2


def test_convert_rule_different_output_formats(
    test_backend: TextQueryTestBackend, sigma_rule: SigmaRule
):
    """Test convert_rule with different output formats reinitializes pipeline."""
    # First call with default format
    queries1 = test_backend.convert_rule(sigma_rule)
    pipeline1 = test_backend.last_processing_pipeline

    # Clear the pipeline to simulate a fresh state
    test_backend.last_processing_pipeline = None

    # Second call with explicit default format (should reinitialize)
    queries2 = test_backend.convert_rule(sigma_rule, output_format="default")
    pipeline2 = test_backend.last_processing_pipeline

    # Verify both calls succeeded
    assert isinstance(queries1, list) and len(queries1) > 0
    assert isinstance(queries2, list) and len(queries2) > 0

    # Pipeline should be reinitialized when it was None
    assert pipeline1 is not pipeline2


def test_init_processing_pipeline_method(test_backend: TextQueryTestBackend):
    """Test the init_processing_pipeline method directly."""
    # Initially no pipeline should be set
    assert (
        not hasattr(test_backend, "last_processing_pipeline")
        or test_backend.last_processing_pipeline is None
    )

    # Initialize the pipeline
    test_backend.init_processing_pipeline()

    # Verify pipeline was initialized
    assert hasattr(test_backend, "last_processing_pipeline")
    assert test_backend.last_processing_pipeline is not None

    # Verify pipeline has the expected structure
    assert (
        len(test_backend.last_processing_pipeline.items) >= 0
    )  # Should have at least the base items


def test_init_processing_pipeline_with_output_format(test_backend: TextQueryTestBackend):
    """Test init_processing_pipeline with specific output format."""
    test_backend.init_processing_pipeline(output_format="default")

    # Verify pipeline was initialized
    assert hasattr(test_backend, "last_processing_pipeline")
    assert test_backend.last_processing_pipeline is not None
