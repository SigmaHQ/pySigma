from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
import pytest
from sigma.backends.splunk import SplunkBackend
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

def test_splunk_regex_query_implicit_or(splunk_backend : SplunkBackend):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="ORing regular expressions"):
        splunk_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|re:
                            - foo.*bar
                            - boo.*foo
                        fieldB: foo
                        fieldC: bar
                    condition: sel
            """)
        )

def test_splunk_regex_query_explicit_or(splunk_backend : SplunkBackend):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="ORing regular expressions"):
        splunk_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel1:
                        fieldA|re: foo.*bar
                    sel2:
                        fieldB|re: boo.*foo
                    condition: sel1 or sel2
            """)
        )

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
                    fieldA|cidr: 192.168.0.0/16
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """)
    ) == ["fieldB=\"foo\" fieldC=\"bar\"\n| where cidrmatch(\"192.168.0.0/16\", fieldA)"]

def test_splunk_cidr_or(splunk_backend : SplunkBackend):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="ORing CIDR"):
        splunk_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|cidr:
                            - 192.168.0.0/16
                            - 10.0.0.0/8
                        fieldB: foo
                        fieldC: bar
                    condition: sel
            """)
        )

def test_splunk_savedsearch_output(splunk_backend : SplunkBackend):
    rules = """
title: Test 1
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
---
title: Test 2
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: foo
        fieldB: bar
    condition: sel
    """
    assert splunk_backend.convert(SigmaCollection.from_yaml(rules), "savedsearches") == """
[default]
dispatch.earliest_time = -30d
dispatch.latest_time = now

[Test 1]
search = fieldB="foo" fieldC="bar" \\
| regex fieldA="foo.*bar"

[Test 2]
search = fieldA="foo" fieldB="bar\""""