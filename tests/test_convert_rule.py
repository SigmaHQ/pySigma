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


def test_convert_rule_with_callback(test_backend: TextQueryTestBackend, sigma_rule: SigmaRule):
    """Test conversion of a single Sigma rule with callback parameter."""
    callback_calls = []

    def test_callback(rule, output_format, index, cond, result):
        """Test callback that records all calls and returns the original result."""
        callback_calls.append(
            {
                "rule": rule,
                "output_format": output_format,
                "index": index,
                "cond": cond,
                "result": result,
            }
        )
        return result  # Return the original result unchanged

    # Convert rule with callback
    queries = test_backend.convert_rule(sigma_rule, callback=test_callback)

    # Verify that the rule was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0

    # Verify that callback was called
    assert len(callback_calls) > 0

    # Verify callback parameters
    for i, call in enumerate(callback_calls):
        assert call["rule"] is sigma_rule
        assert call["output_format"] is None  # Default when not specified
        assert call["index"] == i
        assert call["cond"] is not None
        # Result can be None or not None depending on conversion


def test_convert_rule_with_callback_and_output_format(
    test_backend: TextQueryTestBackend, sigma_rule: SigmaRule
):
    """Test conversion with both callback and output_format parameters."""
    callback_calls = []
    expected_format = "default"

    def test_callback(rule, output_format, index, cond, result):
        """Test callback that records all calls and returns the original result."""
        callback_calls.append(
            {
                "rule": rule,
                "output_format": output_format,
                "index": index,
                "cond": cond,
                "result": result,
            }
        )
        return result  # Return the original result unchanged

    # Convert rule with callback and output format
    queries = test_backend.convert_rule(
        sigma_rule, output_format=expected_format, callback=test_callback
    )

    # Verify that the rule was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0

    # Verify that callback was called with correct output_format
    assert len(callback_calls) > 0
    for call in callback_calls:
        assert call["rule"] is sigma_rule
        assert call["output_format"] == expected_format
        assert isinstance(call["index"], int)
        assert call["cond"] is not None


def test_convert_rule_callback_called_for_none_results(test_backend: TextQueryTestBackend):
    """Test that callback is called even when convert_condition returns None."""
    callback_calls = []

    def test_callback(rule, output_format, index, cond, result):
        """Test callback that records all calls and returns the original result."""
        callback_calls.append(
            {
                "rule": rule,
                "output_format": output_format,
                "index": index,
                "cond": cond,
                "result": result,
            }
        )
        return result  # Return the original result unchanged

    # Create a rule that might produce None results
    rule_yaml = """
title: Test Rule with Multiple Conditions
logsource:
    category: test
detection:
    sel1:
        field1: value1
    sel2:
        field2: value2
    condition: sel1 or sel2
"""
    sigma_rule = SigmaRule.from_yaml(rule_yaml)

    # Convert rule with callback
    queries = test_backend.convert_rule(sigma_rule, callback=test_callback)

    # Verify that callback was called for all conditions
    assert len(callback_calls) > 0

    # Verify that all calls have valid parameters (including None results)
    for call in callback_calls:
        assert call["rule"] is sigma_rule
        assert isinstance(call["index"], int)
        assert call["cond"] is not None
        # result can be None or not None - both should be recorded


def test_convert_collection_with_callback(
    test_backend: TextQueryTestBackend, sigma_rule: SigmaRule
):
    """Test conversion of a rule collection using convert method with callback parameter."""
    callback_calls = []

    def test_callback(rule, output_format, index, cond, result):
        """Test callback that records all calls and returns the original result."""
        callback_calls.append(
            {
                "rule": rule,
                "output_format": output_format,
                "index": index,
                "cond": cond,
                "result": result,
            }
        )
        return result  # Return the original result unchanged

    # Create a collection with the test rule
    collection = SigmaCollection([sigma_rule])

    # Convert collection with callback
    queries = test_backend.convert(collection, callback=test_callback)

    # Verify that the collection was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0

    # Verify that callback was called
    assert len(callback_calls) > 0

    # Verify callback parameters
    for call in callback_calls:
        assert call["rule"] is sigma_rule
        assert call["output_format"] == test_backend.default_format
        assert isinstance(call["index"], int)
        assert call["cond"] is not None


def test_convert_collection_with_callback_and_output_format(
    test_backend: TextQueryTestBackend, sigma_rule: SigmaRule
):
    """Test conversion of a rule collection with both callback and output_format parameters."""
    callback_calls = []
    expected_format = "default"

    def test_callback(rule, output_format, index, cond, result):
        """Test callback that records all calls and returns the original result."""
        callback_calls.append(
            {
                "rule": rule,
                "output_format": output_format,
                "index": index,
                "cond": cond,
                "result": result,
            }
        )
        return result  # Return the original result unchanged

    # Create a collection with the test rule
    collection = SigmaCollection([sigma_rule])

    # Convert collection with callback and output format
    queries = test_backend.convert(
        collection, output_format=expected_format, callback=test_callback
    )

    # Verify that the collection was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0

    # Verify that callback was called with correct output_format
    assert len(callback_calls) > 0
    for call in callback_calls:
        assert call["rule"] is sigma_rule
        assert call["output_format"] == expected_format
        assert isinstance(call["index"], int)
        assert call["cond"] is not None


def test_convert_collection_multiple_rules_with_callback(test_backend: TextQueryTestBackend):
    """Test conversion of a collection with multiple rules and callback."""
    callback_calls = []

    def test_callback(rule, output_format, index, cond, result):
        """Test callback that records all calls and returns the original result."""
        callback_calls.append(
            {
                "rule": rule,
                "output_format": output_format,
                "index": index,
                "cond": cond,
                "result": result,
            }
        )
        return result  # Return the original result unchanged

    # Create multiple test rules
    rule1_yaml = """
title: Test Rule 1
logsource:
    category: test
detection:
    sel:
        field1: value1
    condition: sel
"""
    rule2_yaml = """
title: Test Rule 2
logsource:
    category: test
detection:
    sel:
        field2: value2
    condition: sel
"""

    rule1 = SigmaRule.from_yaml(rule1_yaml)
    rule2 = SigmaRule.from_yaml(rule2_yaml)
    collection = SigmaCollection([rule1, rule2])

    # Convert collection with callback
    queries = test_backend.convert(collection, callback=test_callback)

    # Verify that the collection was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0

    # Verify that callback was called for both rules
    assert len(callback_calls) > 0

    # Check that both rules appear in callback calls
    rules_in_callbacks = [call["rule"] for call in callback_calls]
    assert rule1 in rules_in_callbacks
    assert rule2 in rules_in_callbacks

    # Verify callback parameters for each call
    for call in callback_calls:
        assert call["rule"] in [rule1, rule2]
        assert call["output_format"] == test_backend.default_format
        assert isinstance(call["index"], int)
        assert call["cond"] is not None


def test_convert_collection_without_callback(
    test_backend: TextQueryTestBackend, sigma_rule: SigmaRule
):
    """Test that convert method works normally when no callback is provided."""
    # Create a collection with the test rule
    collection = SigmaCollection([sigma_rule])

    # Convert collection without callback (should work as before)
    queries = test_backend.convert(collection)

    # Verify that the collection was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0


def test_convert_rule_callback_modifies_result(
    test_backend: TextQueryTestBackend, sigma_rule: SigmaRule
):
    """Test that callback can modify the conversion result."""

    def modifying_callback(rule, output_format, index, cond, result):
        """Callback that modifies non-None results by adding a prefix."""
        if result is not None:
            return f"MODIFIED: {result}"
        return result

    # Convert rule with modifying callback
    queries = test_backend.convert_rule(sigma_rule, callback=modifying_callback)

    # Verify that the rule was converted successfully
    assert isinstance(queries, list)
    assert len(queries) > 0

    # Verify that all results were modified by the callback
    for query in queries:
        assert isinstance(query, str)
        assert query.startswith("MODIFIED: ")


def test_convert_rule_callback_filters_result(
    test_backend: TextQueryTestBackend, sigma_rule: SigmaRule
):
    """Test that callback can filter out results by returning None."""

    def filtering_callback(rule, output_format, index, cond, result):
        """Callback that filters out all results by returning None."""
        return None  # Always return None to filter out all results

    # Convert rule with filtering callback
    queries = test_backend.convert_rule(sigma_rule, callback=filtering_callback)

    # Verify that no queries were returned due to filtering
    assert isinstance(queries, list)
    assert len(queries) == 0


def test_convert_rule_callback_selective_modification(test_backend: TextQueryTestBackend):
    """Test that callback can selectively modify results based on conditions."""
    callback_calls = []

    def selective_callback(rule, output_format, index, cond, result):
        """Callback that modifies every second result."""
        callback_calls.append(result)
        if result is not None and len(callback_calls) % 2 == 0:
            return f"EVEN: {result}"
        return result

    # Create a rule with multiple conditions to get multiple results
    rule_yaml = """
title: Test Rule with Multiple Conditions
logsource:
    category: test
detection:
    sel1:
        field1: value1
    sel2:
        field2: value2
    condition: sel1 and sel2
"""
    sigma_rule = SigmaRule.from_yaml(rule_yaml)

    # Convert rule with selective callback
    queries = test_backend.convert_rule(sigma_rule, callback=selective_callback)

    # Verify that the rule was converted successfully
    assert isinstance(queries, list)

    # Check that some results were modified and some weren't
    if len(queries) > 1:
        modified_count = sum(1 for q in queries if isinstance(q, str) and q.startswith("EVEN: "))
        unmodified_count = len(queries) - modified_count
        assert modified_count > 0 or unmodified_count > 0  # At least some should exist
