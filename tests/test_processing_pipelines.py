from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
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
        title: Process Creation Test
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

@pytest.fixture
def process_creation_sigma_rule_parentimage():
    return SigmaCollection.from_yaml("""
        title: Process Creation Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
                ParentImage: "*\\\\parent.exe"
            condition: sel
    """)

@pytest.fixture
def process_creation_sigma_rule_parentimage_path():
    return SigmaCollection.from_yaml("""
        title: Process Creation Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
                ParentImage: "*\\\\Windows\\\\System32\\\\parent.exe"
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

def test_crowdstrike_pipeline_parentimage(resolver : ProcessingPipelineResolver, process_creation_sigma_rule_parentimage):
    pipeline = resolver.resolve_pipeline("crowdstrike")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(process_creation_sigma_rule_parentimage) == ["event_simpleName=\"ProcessRollup2\" and CommandLine=\"test.exe foo bar\" and ParentBaseFileName=\"parent.exe\""]

def test_crowdstrike_pipeline_parentimage_path(resolver : ProcessingPipelineResolver, process_creation_sigma_rule_parentimage_path):
    pipeline = resolver.resolve_pipeline("crowdstrike")
    backend = TextQueryTestBackend(pipeline)
    with pytest.raises(SigmaTransformationError, match="CrowdStrike"):
        backend.convert(process_creation_sigma_rule_parentimage_path)