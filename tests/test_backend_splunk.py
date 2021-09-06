import pytest
from sigma.conversion.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection

@pytest.fixture
def splunk_backend():
    return SplunkBackend()

def test_splunk_regex_query(splunk_backend : SplunkBackend):
    assert splunk_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """)
    ) == ["fieldB=\"foo\" fieldC=\"bar\"\n| regex fieldA=\"foo.*bar\""]

def test_splunk_single_regex_query(splunk_backend : SplunkBackend):
    assert splunk_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                condition: sel
        """)
    ) == ["*\n| regex fieldA=\"foo.*bar\""]

def test_splunk_cidr_query(splunk_backend : SplunkBackend):
    assert splunk_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cidrv4: 192.168.0.0/16
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """)
    ) == ["fieldB=\"foo\" fieldC=\"bar\"\n| where cidrmatch(\"192.168.0.0/16\", fieldA)"]