from uuid import UUID
from sigma.plugins import SigmaPlugin, SigmaPluginDirectory, SigmaPluginState, SigmaPluginType, SigmaPlugins
from sigma.backends.test import TextQueryTestBackend
import importlib.metadata
from packaging.specifiers import Specifier
import sigma
import pytest

def test_autodiscover_backends():
    plugins = SigmaPlugins.autodiscover(include_pipelines=False, include_validators=False)
    assert plugins == SigmaPlugins(
        backends={
            "test": TextQueryTestBackend,
        },
        pipelines=dict(),
        validators=dict(),
    )

def test_autodiscover_pipelines_none():
    plugins = SigmaPlugins.autodiscover(include_backends=False, include_validators=False)
    assert plugins == SigmaPlugins(
        backends=dict(),
        pipelines=dict(),
        validators=dict(),
    )

def test_autodiscover_validators():
    plugins = SigmaPlugins.autodiscover(include_backends=False, include_pipelines=False)
    assert len(plugins.validators) > 10

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
        "pysigma_version": ">=0.9.0",
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
        pysigma_version=Specifier(">=0.9.0"),
    )

def test_sigma_plugin_from_dict(sigma_plugin, sigma_plugin_dict):
    assert SigmaPlugin.from_dict(sigma_plugin_dict) == sigma_plugin

def test_sigma_plugin_version_compatible(sigma_plugin):
    pysigma_version = importlib.metadata.version("pysigma")
    sigma_plugin.pysigma_version = Specifier("~=" + (".".join(pysigma_version.split(".")[:-1] + ["0"])))
    assert sigma_plugin.is_compatible()

def test_sigma_plugin_directory_from_dict(sigma_plugin, sigma_plugin_dict):
    sigma_plugin_dict_uuid = sigma_plugin_dict.pop("uuid")
    assert SigmaPluginDirectory.from_dict({
        "note": "Test",
        "plugins": {
            sigma_plugin_dict_uuid: sigma_plugin_dict
        },
    }) == SigmaPluginDirectory(
        note="Test",
        plugins={
            sigma_plugin.uuid: sigma_plugin
        }
    )

def test_sigma_plugin_directory_default():
    plugin_dir = SigmaPluginDirectory.default_plugin_directory()
    assert len(plugin_dir.plugins) > 10