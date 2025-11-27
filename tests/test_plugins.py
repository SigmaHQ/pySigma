import re
from typing import Any, Dict
from uuid import UUID
from sigma.exceptions import SigmaPluginNotFoundError
from sigma.pipelines.test.pipeline import another_test_pipeline, YetAnotherTestPipeline
from sigma.plugins import (
    SigmaPlugin,
    SigmaPluginCapability,
    SigmaPluginDirectory,
    SigmaPluginState,
    SigmaPluginType,
    InstalledSigmaPlugins,
)
from sigma.backends.test import TextQueryTestBackend, MandatoryPipelineTestBackend
from sigma.pipelines.test import dummy_test_pipeline
import importlib.metadata
from packaging.specifiers import Specifier
import pytest

from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from tests.test_processing_pipeline import TransformationAppend


def test_autodiscover_backends():
    plugins = InstalledSigmaPlugins.autodiscover(include_pipelines=False, include_validators=False)
    assert plugins == InstalledSigmaPlugins(
        backends={
            "text_query_test": TextQueryTestBackend,
            "mandatory_pipeline_test": MandatoryPipelineTestBackend,
        },
        pipelines=dict(),
        validators=dict(),
    )


def test_autodiscover_pipelines_all():
    plugins = InstalledSigmaPlugins.autodiscover(include_backends=False, include_validators=False)
    assert plugins == InstalledSigmaPlugins(
        backends=dict(),
        pipelines={
            "dummy_test": dummy_test_pipeline,
            "another_test": another_test_pipeline,
            "YetAnotherTestPipeline": YetAnotherTestPipeline(),
        },
        validators=dict(),
    )


def test_autodiscover_pipelines(monkeypatch):
    monkeypatch.delattr("sigma.pipelines.test.__all__")
    plugins = InstalledSigmaPlugins.autodiscover(include_backends=False, include_validators=False)
    assert plugins == InstalledSigmaPlugins(
        backends=dict(),
        pipelines={
            "dummy_test": dummy_test_pipeline,
            "another_test": another_test_pipeline,
            "YetAnotherTestPipeline": YetAnotherTestPipeline(),
        },
        validators=dict(),
    )


def test_autodiscover_validators():
    plugins = InstalledSigmaPlugins.autodiscover(include_backends=False, include_pipelines=False)
    assert len(plugins.validators) > 10


def test_installed_sigma_plugins_get_pipeline_resolver():
    pipeline = ProcessingPipeline(
        name="Test",
        priority=10,
        items=[
            ProcessingItem(
                transformation=TransformationAppend(s="Test"),
                identifier="test",
            )
        ],
    )
    plugins = InstalledSigmaPlugins()
    plugins.register_pipeline("test", pipeline)
    pipeline_resolver = plugins.get_pipeline_resolver()
    assert pipeline_resolver.resolve_pipeline("test") == pipeline


@pytest.fixture
def sigma_plugin_dict():
    return {
        "uuid": "21c3d8c2-64e0-4134-bcd3-046b903fa5f3",
        "type": "backend",
        "id": "test",
        "description": "Test plugin",
        "package": "pySigma-backend-test",
        "project_url": "https://github.com/SigmaHQ/pySigma-backend-test",
        "report_issue_url": "https://github.com/SigmaHQ/pySigma-backend-test/issues/new",
        "state": "testing",
        "pysigma_version": ">=1.0.0",
        "capabilities": [
            "event_count_correlation_conversion",
            "value_count_correlation_conversion",
        ],
    }


@pytest.fixture
def sigma_plugin():
    return SigmaPlugin(
        uuid=UUID("21c3d8c2-64e0-4134-bcd3-046b903fa5f3"),
        type=SigmaPluginType.BACKEND,
        id="test",
        description="Test plugin",
        package="pySigma-backend-test",
        project_url="https://github.com/SigmaHQ/pySigma-backend-test",
        report_issue_url="https://github.com/SigmaHQ/pySigma-backend-test/issues/new",
        state=SigmaPluginState.TESTING,
        pysigma_version=Specifier(">=1.0.0"),
        capabilities={
            SigmaPluginCapability.EVENT_COUNT_CORRELATION_CONVERSION,
            SigmaPluginCapability.VALUE_COUNT_CORRELATION_CONVERSION,
        },
    )


def test_sigma_plugin_from_dict(sigma_plugin, sigma_plugin_dict):
    assert SigmaPlugin.from_dict(sigma_plugin_dict) == sigma_plugin


def test_sigma_plugin_from_dict_without_capabilities(monkeypatch, sigma_plugin, sigma_plugin_dict):
    monkeypatch.delitem(sigma_plugin_dict, "capabilities")
    monkeypatch.setattr(sigma_plugin, "capabilities", set())
    assert SigmaPlugin.from_dict(sigma_plugin_dict) == sigma_plugin


@pytest.mark.xfail(
    condition=re.match(r"^\d+\.\d+\.\d+\w+\d+$", importlib.metadata.version("pysigma")),
    reason="pysigma version is release candidate or other special version.",
)
def test_sigma_plugin_version_compatible(sigma_plugin):
    pysigma_version = importlib.metadata.version("pysigma")
    sigma_plugin.pysigma_version = Specifier(
        "~=" + (".".join(pysigma_version.split(".")[:-1] + ["0"]))
    )
    assert sigma_plugin.is_compatible()


def test_sigma_plugin_version_incompatible(sigma_plugin):
    sigma_plugin.pysigma_version = Specifier("<=0.1.0")
    assert not sigma_plugin.is_compatible()


def test_sigma_plugin_version_unknown(sigma_plugin, monkeypatch):
    def version_replacement(m):
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr("importlib.metadata.version", version_replacement)
    sigma_plugin.pysigma_version = Specifier("<=0.1.0")
    assert sigma_plugin.is_compatible() is None


def test_sigma_plugin_has_capability(sigma_plugin):
    assert sigma_plugin.has_capability(SigmaPluginCapability.EVENT_COUNT_CORRELATION_CONVERSION)
    assert sigma_plugin.has_capability(SigmaPluginCapability.VALUE_COUNT_CORRELATION_CONVERSION)
    assert not sigma_plugin.has_capability(SigmaPluginCapability.TEMPORAL_CORRELATION_CONVERSION)


def check_module(name: str) -> bool:
    # This was the preferred way to test module existence, but it didn't worked in GitHub Actions:
    # return bool(importlib.util.find_spec(name))
    try:
        version = importlib.metadata.version("pysigma-backend-splunk")
        if isinstance(version, str):
            return True
        else:
            return False
    except importlib.metadata.PackageNotFoundError:
        return False


@pytest.mark.online
def test_sigma_plugin_installation():
    plugin_dir = SigmaPluginDirectory.default_plugin_directory()
    plugin = plugin_dir.get_plugin_by_uuid("4af37b53-f1ec-4567-8017-2fb9315397a1")  # Splunk backend
    assert not check_module("sigma.backends.splunk")  # ensure it's not already installed
    plugin.install()
    assert check_module("sigma.backends.splunk")
    plugin.uninstall()
    assert not check_module("sigma.backends.splunk")


@pytest.mark.online
def test_sigma_plugin_pysigma_version_from_pypi(sigma_plugin):
    """Test fetching pySigma version specifier from PyPI."""
    sigma_plugin.package = "pysigma-backend-splunk"
    specifier = sigma_plugin.pysigma_version_from_pypi()
    assert specifier is not None
    # The specifier should be a valid SpecifierSet
    from packaging.specifiers import SpecifierSet

    assert isinstance(specifier, SpecifierSet)


@pytest.mark.online
def test_sigma_plugin_pysigma_version_from_pypi_specific_version(sigma_plugin):
    """Test fetching pySigma version specifier from PyPI for a specific version."""
    sigma_plugin.package = "pysigma-backend-splunk"
    specifier = sigma_plugin.pysigma_version_from_pypi("1.1.3")
    assert specifier is not None
    from packaging.version import Version

    # Version 1.1.3 requires pySigma >=0.11.18,<0.12.0
    assert Version("0.11.18") in specifier
    assert Version("0.12.0") not in specifier


@pytest.mark.online
def test_sigma_plugin_pysigma_version_from_pypi_nonexistent_package(sigma_plugin):
    """Test fetching pySigma version for a non-existent package returns None."""
    sigma_plugin.package = "nonexistent-pysigma-package-xyz"
    specifier = sigma_plugin.pysigma_version_from_pypi()
    assert specifier is None


@pytest.mark.online
def test_sigma_plugin_find_compatible_version(sigma_plugin):
    """Test finding a compatible plugin version."""
    sigma_plugin.package = "pysigma-backend-splunk"
    compatible_version = sigma_plugin.find_compatible_version()
    # Since pySigma is installed, we should find a compatible version
    assert compatible_version is not None
    from packaging.version import Version

    # Should be a valid version string
    Version(compatible_version)


@pytest.mark.online
def test_sigma_plugin_find_compatible_version_nonexistent_package(sigma_plugin):
    """Test finding compatible version for non-existent package returns None."""
    sigma_plugin.package = "nonexistent-pysigma-package-xyz"
    compatible_version = sigma_plugin.find_compatible_version()
    assert compatible_version is None


def test_sigma_plugin_find_compatible_version_pysigma_not_found(sigma_plugin, monkeypatch):
    """Test finding compatible version when pySigma is not installed."""

    def version_replacement(m):
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr("importlib.metadata.version", version_replacement)
    compatible_version = sigma_plugin.find_compatible_version()
    assert compatible_version is None


def test_sigma_plugin_extract_pysigma_specifier():
    """Test extraction of pySigma specifier from requires_dist."""
    from sigma.plugins import SigmaPlugin
    from packaging.specifiers import SpecifierSet

    # Test with valid pySigma dependency
    requires_dist = ["pysigma>=1.0.0,<2.0.0", "requests>=2.0.0"]
    specifier = SigmaPlugin._extract_pysigma_specifier(requires_dist)
    assert specifier is not None
    assert isinstance(specifier, SpecifierSet)
    from packaging.version import Version

    assert Version("1.5.0") in specifier
    assert Version("2.0.0") not in specifier


def test_sigma_plugin_extract_pysigma_specifier_no_pysigma():
    """Test extraction when pySigma is not in requires_dist."""
    from sigma.plugins import SigmaPlugin

    requires_dist = ["requests>=2.0.0", "packaging>=21.0"]
    specifier = SigmaPlugin._extract_pysigma_specifier(requires_dist)
    assert specifier is None


def test_sigma_plugin_extract_pysigma_specifier_none_input():
    """Test extraction with None input."""
    from sigma.plugins import SigmaPlugin

    specifier = SigmaPlugin._extract_pysigma_specifier(None)
    assert specifier is None


def test_sigma_plugin_extract_pysigma_specifier_empty_list():
    """Test extraction with empty list."""
    from sigma.plugins import SigmaPlugin

    specifier = SigmaPlugin._extract_pysigma_specifier([])
    assert specifier is None


def test_sigma_plugin_directory_from_dict(sigma_plugin, sigma_plugin_dict):
    sigma_plugin_dict_uuid = sigma_plugin_dict.pop("uuid")
    assert SigmaPluginDirectory.from_dict(
        {
            "note": "Test",
            "plugins": {sigma_plugin_dict_uuid: sigma_plugin_dict},
        }
    ) == SigmaPluginDirectory(note="Test", plugins={sigma_plugin.uuid: sigma_plugin})


def test_sigma_plugin_directory_default():
    plugin_dir = SigmaPluginDirectory.default_plugin_directory()
    assert plugin_dir.plugin_count() > 10


@pytest.fixture
def plugin_directory(sigma_plugin: SigmaPlugin, sigma_plugin_dict: dict[str, Any]):
    plugin_directory = SigmaPluginDirectory()
    plugin_directory.register_plugin(sigma_plugin)

    # register another one: broken backend
    sigma_plugin_dict_broken = sigma_plugin_dict.copy()
    sigma_plugin_dict_broken["uuid"] = "54397ed0-3e26-471d-80ad-08ef35af5b68"
    sigma_plugin_dict_broken["id"] = "test_broken"
    sigma_plugin_dict_broken["state"] = "broken"
    sigma_plugin_dict_broken["description"] = "Broken backend"
    sigma_plugin_broken = SigmaPlugin.from_dict(sigma_plugin_dict_broken)
    plugin_directory.register_plugin(sigma_plugin_broken)

    # register another one: pipeline
    sigma_plugin_dict_pipeline = sigma_plugin_dict.copy()
    sigma_plugin_dict_pipeline["uuid"] = "09b0cefd-f3d9-49d2-894b-2920e10a9f73"
    sigma_plugin_dict_pipeline["id"] = "test_pipeline"
    sigma_plugin_dict_pipeline["type"] = "pipeline"
    sigma_plugin_dict_pipeline["description"] = "Test pipeline"
    sigma_plugin_pipeline = SigmaPlugin.from_dict(sigma_plugin_dict_pipeline)
    plugin_directory.register_plugin(sigma_plugin_pipeline)

    return plugin_directory


def test_sigma_plugin_directory_count(plugin_directory: SigmaPluginDirectory):
    assert plugin_directory.plugin_count() == 3


def test_sigma_plugin_directory_get_by_uuid(plugin_directory: SigmaPluginDirectory):
    assert (
        plugin_directory.get_plugin_by_uuid(UUID("09b0cefd-f3d9-49d2-894b-2920e10a9f73")).id
        == "test_pipeline"
    )


def test_sigma_plugin_directory_get_by_uuid_str(plugin_directory: SigmaPluginDirectory):
    assert (
        plugin_directory.get_plugin_by_uuid("09b0cefd-f3d9-49d2-894b-2920e10a9f73").id
        == "test_pipeline"
    )


def test_sigma_plugin_directory_get_by_uuid_not_found(plugin_directory: SigmaPluginDirectory):
    with pytest.raises(SigmaPluginNotFoundError, match="Plugin with UUID.*not found"):
        plugin_directory.get_plugin_by_uuid("6029969b-4e6b-4060-bb0d-464d476065e0")


def test_sigma_plugin_directory_get_by_id(plugin_directory: SigmaPluginDirectory):
    assert plugin_directory.get_plugin_by_id("test_pipeline").uuid == UUID(
        "09b0cefd-f3d9-49d2-894b-2920e10a9f73"
    )


def test_sigma_plugin_directory_get_by_id_not_found(plugin_directory: SigmaPluginDirectory):
    with pytest.raises(SigmaPluginNotFoundError, match="Plugin with identifier.*not found"):
        plugin_directory.get_plugin_by_id("not_existing")


def test_sigma_plugin_directory_get_plugins(plugin_directory: SigmaPluginDirectory):
    assert plugin_directory.get_plugins() == list(plugin_directory.plugins.values())


def test_sigma_plugin_directory_get_plugins_filtered(plugin_directory: SigmaPluginDirectory):
    plugins = plugin_directory.get_plugins(
        plugin_types={SigmaPluginType.BACKEND}, plugin_states={SigmaPluginState.TESTING}
    )
    assert len(plugins) == 1
    assert plugins[0].id == "test"


def test_sigma_plugin_directory_get_plugins_compatible(
    plugin_directory: SigmaPluginDirectory, sigma_plugin_dict: dict[str, Any]
):
    sigma_plugin_dict_incompatible = sigma_plugin_dict.copy()
    sigma_plugin_dict_incompatible["uuid"] = "a350e4dd-6813-4549-a76d-b2c0d4925e62"
    sigma_plugin_dict_incompatible["id"] = "incompatible"
    sigma_plugin_dict_incompatible["description"] = "Incompatible plugin"
    sigma_plugin_dict_incompatible["pysigma_version"] = "<0.1.0"

    sigma_plugin = SigmaPlugin.from_dict(sigma_plugin_dict_incompatible)
    plugin_directory.register_plugin(sigma_plugin)
    assert plugin_directory.get_plugins(compatible_only=True) < plugin_directory.get_plugins()
