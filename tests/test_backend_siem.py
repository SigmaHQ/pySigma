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
                        "FIELD": "IMAGE",
                        "VALUE": "C:\\\\Windows\\\\System32\\\\cmd.exe",
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
                        "FIELD": "IMAGE",
                        "VALUE": "C:\\\\Windows\\\\System32\\\\cmd.exe",
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

def test_siem_backend_or_condition(siem_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Rule
        logsource:
            category: process_creation
            product: windows
        detection:
            selection1:
                Image: 'C:\\Windows\\System32\\cmd.exe'
            selection2:
                Image: 'C:\\Windows\\System32\\powershell.exe'
            condition: selection1 or selection2
    """)
    expected_json = {
        "actions": [
            {
                "ACTION_UNIQUE_NAME": "PLACEHOLDER_ACTION",
                "pattern": "1",
                "rows": [
                    {
                        "CONDI": "EQ",
                        "FIELD": "IMAGE",
                        "VALUE": "C:\\\\Windows\\\\System32\\\\cmd.exe,C:\\\\Windows\\\\System32\\\\powershell.exe",
                        "TYPE": "TEXT",
                        "LOGIC": "AND"
                    }
                ]
            }
        ]
    }
    result = siem_backend.convert(rule)
    assert json.loads(result[0]) == expected_json

def test_siem_backend_not_condition(siem_backend):
    rule = SigmaCollection.from_yaml("""
        title: Test Rule
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                Image: 'C:\\Windows\\System32\\cmd.exe'
            condition: not selection
    """)
    expected_json = {
        "actions": [
            {
                "ACTION_UNIQUE_NAME": "PLACEHOLDER_ACTION",
                "pattern": "1",
                "rows": [
                    {
                        "CONDI": "NEQ",
                        "FIELD": "IMAGE",
                        "VALUE": "C:\\\\Windows\\\\System32\\\\cmd.exe",
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
                        "FIELD": "IMAGE",
                        "VALUE": "C:\\\\Windows\\\\System32\\\\cmd.exe",
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
