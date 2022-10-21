from sigma.plugins import SigmaPlugins
from sigma.backends.test import TextQueryTestBackend
import sigma

def test_autodiscover_backends_none():
    plugins = SigmaPlugins.autodiscover(include_pipelines=False, include_validators=False)
    assert plugins == SigmaPlugins(
        backends=dict(),
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