import json
import pytest
from sigma.collection import SigmaCollection
from sigma.backends.siem import SiemBackend

@pytest.fixture
def siem_backend():
    # We need a new instance for each test to reset the rows list
    return SiemBackend()

def test_siem_backend_simple_rule(siem_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Rule
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Image: 'C:\\Windows\\System32\\cmd.exe'
            condition: selection
    """)
    expected_json = {
        "actions": [
            {
                "ACTION_UNIQUE_NAME": "PLACEHOLDER_ACTION",
                "pattern": "1",
                "rows": [
                    {
                        "CONDI": "EQ",
                        "FIELD": "PROCESSNAME",
                        "VALUE": "C:\\Windows\\System32\\cmd.exe",
                        "TYPE": "TEXT",
                        "LOGIC": "AND"
                    }
                ]
            }
        ]
    }
    result = siem_backend.convert(rule)
    assert json.loads(result[0]) == expected_json

def test_siem_backend_and_condition(siem_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Rule
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Image: 'C:\\Windows\\System32\\cmd.exe'
                CommandLine: '/c echo hello'
            condition: selection
    """)
    expected_json = {
        "actions": [
            {
                "ACTION_UNIQUE_NAME": "PLACEHOLDER_ACTION",
                "pattern": "1 AND 2",
                "rows": [
                    {
                        "CONDI": "EQ",
                        "FIELD": "PROCESSNAME",
                        "VALUE": "C:\\Windows\\System32\\cmd.exe",
                        "TYPE": "TEXT",
                        "LOGIC": "AND"
                    },
                    {
                        "CONDI": "EQ",
                        "FIELD": "COMMANDLINE",
                        "VALUE": "/c echo hello",
                        "TYPE": "TEXT",
                        "LOGIC": "AND"
                    }
                ]
            }
        ]
    }
    result = siem_backend.convert(rule)
    assert json.loads(result[0]) == expected_json

def test_siem_backend_multi_value_in(siem_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Rule
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Image:
                    - 'C:\\Windows\\System32\\cmd.exe'
                    - 'C:\\Windows\\System32\\powershell.exe'
            condition: selection
    """)
    expected_json = {
        "actions": [
            {
                "ACTION_UNIQUE_NAME": "PLACEHOLDER_ACTION",
                "pattern": "1",
                "rows": [
                    {
                        "CONDI": "IN",
                        "FIELD": "PROCESSNAME",
                        "VALUE": [
                            "C:\\Windows\\System32\\cmd.exe",
                            "C:\\Windows\\System32\\powershell.exe"
                        ],
                        "TYPE": "TEXT",
                        "LOGIC": "AND"
                    }
                ]
            }
        ]
    }
    result = siem_backend.convert(rule)
    assert json.loads(result[0]) == expected_json

def test_siem_backend_multi_value_contains(siem_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Rule
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine|contains:
                    - 'foo'
                    - 'bar'
            condition: selection
    """)
    expected_json = {
        "actions": [
            {
                "ACTION_UNIQUE_NAME": "PLACEHOLDER_ACTION",
                "pattern": "1",
                "rows": [
                    {
                        "CONDI": "CONT",
                        "FIELD": "COMMANDLINE",
                        "VALUE": ["foo", "bar"],
                        "TYPE": "TEXT",
                        "LOGIC": "AND"
                    }
                ]
            }
        ]
    }
    result = siem_backend.convert(rule)
    assert json.loads(result[0]) == expected_json

def test_siem_backend_balanced_chunking(siem_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Rule
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine|contains:
                    - val1
                    - val2
                    - val3
                    - val4
                    - val5
                    - val6
                    - val7
                    - val8
                    - val9
                    - val10
                    - val11
                    - val12
                    - val13
                    - val14
                    - val15
                    - val16
                    - val17
                    - val18
                    - val19
                    - val20
                    - val21
                    - val22
                    - val23
                    - val24
                    - val25
                    - val26
                    - val27
                    - val28
                    - val29
                    - val30
            condition: selection
    """)
    result = siem_backend.convert(rule)
    result_json = json.loads(result[0])

    assert result_json["actions"][0]["pattern"] == "1 OR 2"
    rows = result_json["actions"][0]["rows"]
    assert len(rows) == 2
    assert len(rows[0]["VALUE"]) == 15
    assert len(rows[1]["VALUE"]) == 15
    assert rows[0]["LOGIC"] == "AND"
    assert rows[1]["LOGIC"] == "OR"

def test_siem_backend_not_or_condition_nin(siem_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Rule
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Image:
                    - 'C:\\Windows\\System32\\cmd.exe'
                    - 'C:\\Windows\\System32\\powershell.exe'
            condition: not selection
    """)
    expected_json = {
        "actions": [
            {
                "ACTION_UNIQUE_NAME": "PLACEHOLDER_ACTION",
                "pattern": "1",
                "rows": [
                    {
                        "CONDI": "NIN",
                        "FIELD": "PROCESSNAME",
                        "VALUE": [
                            "C:\\Windows\\System32\\cmd.exe",
                            "C:\\Windows\\System32\\powershell.exe"
                        ],
                        "TYPE": "TEXT",
                        "LOGIC": "AND"
                    }
                ]
            }
        ]
    }
    result = siem_backend.convert(rule)
    assert json.loads(result[0]) == expected_json

def test_siem_backend_not_and_condition(siem_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Rule
        logsource:
            category: process_creation
            product: windows
        detection:
            selection1:
                Image: 'C:\\Windows\\System32\\cmd.exe'
            selection2:
                CommandLine: '/c echo hello'
            condition: not (selection1 and selection2)
    """)
    expected_json = {
        "actions": [
            {
                "ACTION_UNIQUE_NAME": "PLACEHOLDER_ACTION",
                "pattern": "1 OR 2",
                "rows": [
                    {
                        "CONDI": "NEQ",
                        "FIELD": "PROCESSNAME",
                        "VALUE": "C:\\Windows\\System32\\cmd.exe",
                        "TYPE": "TEXT",
                        "LOGIC": "AND"
                    },
                    {
                        "CONDI": "NEQ",
                        "FIELD": "COMMANDLINE",
                        "VALUE": "/c echo hello",
                        "TYPE": "TEXT",
                        "LOGIC": "OR"
                    }
                ]
            }
        ]
    }
    result = siem_backend.convert(rule)
    assert json.loads(result[0]) == expected_json

def test_siem_backend_null_condition(siem_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Rule
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine: null
            condition: selection
    """)
    expected_json = {
        "actions": [
            {
                "ACTION_UNIQUE_NAME": "PLACEHOLDER_ACTION",
                "pattern": "1",
                "rows": [
                    {
                        "CONDI": "NOT_EXISTS",
                        "FIELD": "COMMANDLINE",
                        "TYPE": "TEXT",
                        "LOGIC": "AND"
                    }
                ]
            }
        ]
    }
    result = siem_backend.convert(rule)
    assert json.loads(result[0]) == expected_json

def test_siem_backend_not_null_condition(siem_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Rule
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine: null
            condition: not selection
    """)
    expected_json = {
        "actions": [
            {
                "ACTION_UNIQUE_NAME": "PLACEHOLDER_ACTION",
                "pattern": "1",
                "rows": [
                    {
                        "CONDI": "EXISTS",
                        "FIELD": "COMMANDLINE",
                        "TYPE": "TEXT",
                        "LOGIC": "AND"
                    }
                ]
            }
        ]
    }
    result = siem_backend.convert(rule)
    assert json.loads(result[0]) == expected_json

def test_siem_backend_unsupported_cidr(siem_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Unsupported CIDR
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                DestinationIp|cidr: '192.168.0.0/16'
            condition: selection
    """)
    with pytest.raises(NotImplementedError, match="CIDR expressions are not supported"):
        siem_backend.convert(rule)

def test_siem_backend_unsupported_fieldref(siem_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Unsupported FieldRef
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Image|fieldref: 'ParentImage'
            condition: selection
    """)
    with pytest.raises(NotImplementedError, match="Field references are not supported"):
        siem_backend.convert(rule)

def test_siem_backend_windash_modifier(siem_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Windash
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine|contains|all|windash:
                    - '-s '
                    - '-f '
            condition: selection
    """)
    result_json = json.loads(siem_backend.convert(rule)[0])

    # Check the pattern
    assert result_json["actions"][0]["pattern"] == "1 AND 2"

    # Check the rows
    rows = result_json["actions"][0]["rows"]
    assert len(rows) == 2

    assert rows[0]["FIELD"] == "COMMANDLINE"
    assert rows[0]["CONDI"] == "CONT"
    assert "-s " in rows[0]["VALUE"]
    assert "/s " in rows[0]["VALUE"]

    assert rows[1]["FIELD"] == "COMMANDLINE"
    assert rows[1]["CONDI"] == "CONT"
    assert "-f " in rows[1]["VALUE"]
    assert "/f " in rows[1]["VALUE"]
