from sigma.collection import SigmaCollection
from tests.test_conversion_base import TextQueryTestBackend
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.processing import pipeline
from sigma.processing.pipelines.resolver import DefaultPipelineResolver
import pytest

@pytest.fixture
def resolver():
    return DefaultPipelineResolver

@pytest.fixture
def process_creation_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Sysmon Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
                Image: "*\\\\test.exe"
            condition: sel
    """)

def test_sysmon_pipeline(resolver : ProcessingPipelineResolver, process_creation_sigma_rule):
    pipeline = resolver.resolve_pipeline("sysmon")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(process_creation_sigma_rule) == ["EventID=1 and CommandLine=\"test.exe foo bar\" and Image=\"*\\test.exe\""]

def test_crowdstrike_pipeline(resolver : ProcessingPipelineResolver, process_creation_sigma_rule):
    pipeline = resolver.resolve_pipeline("crowdstrike")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(process_creation_sigma_rule) == ["event_simpleName=\"ProcessRollup2\" and CommandLine=\"test.exe foo bar\" and ImageFileName=\"*\\test.exe\""]