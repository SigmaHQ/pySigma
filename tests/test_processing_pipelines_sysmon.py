from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from tests.test_conversion_base import TextQueryTestBackend
from sigma.processing.resolver import ProcessingPipelineResolver
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
def file_change_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: File Change Test
        status: test
        logsource:
            category: file_change
            product: windows
        detection:
            sel:
                TargetFilename: test
            condition: sel
    """)

@pytest.fixture
def network_connection_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Network Connection Test
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
               Initiated: "true"
               DestinationIp: "1.2.3.4"
            condition: sel
    """)

def test_sysmon_process_creation(resolver : ProcessingPipelineResolver, process_creation_sigma_rule):
    pipeline = resolver.resolve_pipeline("sysmon")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(process_creation_sigma_rule) == ["EventID=1 and CommandLine=\"test.exe foo bar\" and Image=\"*\\test.exe\""]

def test_sysmon_file_change(resolver : ProcessingPipelineResolver, file_change_sigma_rule):
    pipeline = resolver.resolve_pipeline("sysmon")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(file_change_sigma_rule) == ["EventID=2 and TargetFilename=\"test\""]

def test_sysmon_network_connect(resolver : ProcessingPipelineResolver, network_connection_sigma_rule):
    pipeline = resolver.resolve_pipeline("sysmon")
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(network_connection_sigma_rule) == ["EventID=3 and Initiated=\"true\" and DestinationIp=\"1.2.3.4\""]