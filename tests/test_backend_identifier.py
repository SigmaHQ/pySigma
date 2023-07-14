import pytest

from sigma.plugins import InstalledSigmaPlugins
from sigma.conversion.base import TextQueryBackend
from sigma.backends.test import TextQueryTestBackend, MandatoryPipelineTestBackend


class DummyBackend(TextQueryBackend):
    """Dummy backend for testing purposes."""

    identifier = "dummy"


class DummyTestBackend(DummyBackend):
    """Dummy backend for testing purposes."""

    identifier = "dummy_test"


class Dummy2TestBackend(DummyBackend):
    """Dummy backend for testing purposes."""

    # This won't be used, because the identifier is already set by DummyTestBackend.
    __identifier__ = "dummy2_test"


class DummyDunderIdentifierBackend(TextQueryBackend):
    """Dummy backend for testing purposes."""

    __identifier__ = "dummy_dunder_identifier"


class AnotherDummyTestBackend(TextQueryBackend):
    """Dummy backend for testing purposes."""

    pass


class something_something_backend(TextQueryBackend):
    """Dummy backend for testing purposes."""

    pass


class BackendBackend(TextQueryBackend):
    """Dummy backend for testing purposes."""

    pass


class BaseBackend(TextQueryBackend):
    """Dummy backend for testing purposes."""

    pass


@pytest.mark.parametrize(
    "backend_class, expected_backend_identifier",
    [
        (None, ""),
        (TextQueryBackend, "text_query"),
        (DummyBackend, "dummy"),
        (DummyTestBackend, "dummy_test"),
        (Dummy2TestBackend, "dummy"),  # Dummy2TestBackend.__identifier__ won't be used.
        (DummyDunderIdentifierBackend, "dummy_dunder_identifier"),  # __identifier__ is used.
        (AnotherDummyTestBackend, "another_dummy_test"),  # identifier is generated from __name__.
        (something_something_backend, "something_something"),
        (BackendBackend, "backend"),
        (BaseBackend, "test_backend_identifier"),  # test file is the module name.
        (TextQueryTestBackend, "text_query_test"),
        (MandatoryPipelineTestBackend, "mandatory_pipeline_test"),
    ],
)
def test_get_backend_identifier(backend_class, expected_backend_identifier):
    """Test that the backend identifier is correctly returned."""
    assert (
        InstalledSigmaPlugins._get_backend_identifier(backend_class, "")
        == expected_backend_identifier
    )
