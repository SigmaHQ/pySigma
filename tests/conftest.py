"""
Pytest configuration and fixtures for pySigma tests.
"""

import pytest

from sigma.data import mitre_attack


# Mock MITRE ATT&CK data for testing
MOCK_ATTACK_DATA = {
    "mitre_attack_version": "17.1",
    "mitre_attack_tactics": {
        "TA0001": "initial-access",
        "TA0011": "command-and-control",
    },
    "mitre_attack_techniques": {
        "T1001": "Data Obfuscation",
        "T1001.001": "Junk Data",
    },
    "mitre_attack_techniques_tactics_mapping": {
        "T1001": ["command-and-control"],
        "T1001.001": ["command-and-control"],
    },
    "mitre_attack_intrusion_sets": {
        "G0001": "Axiom",
    },
    "mitre_attack_software": {
        "S0001": "Mimikatz",
        "S0005": "Windows Credential Editor",
    },
    "mitre_attack_datasources": {
        "DS0026": "Active Directory",
    },
    "mitre_attack_mitigations": {
        "M1015": "Active Directory Configuration",
    },
}

# Mock MITRE D3FEND data for testing
MOCK_D3FEND_DATA = {
    "mitre_d3fend_version": "0.16.0",
    "mitre_d3fend_tactics": {
        "Deceive": "Deceive",
        "Isolate": "Isolate",
        "Detect": "Detect",
    },
    "mitre_d3fend_techniques": {
        "D3-MFA": "Multi-factor Authentication",
        "D3-OTP": "One-time Password",
    },
    "mitre_d3fend_artifacts": {
        "d3f-AccessControlConfiguration": "Access Control Configuration",
    },
}


@pytest.fixture(autouse=True)
def mock_mitre_data(monkeypatch):
    """Mock MITRE ATT&CK and D3FEND data to avoid network calls in tests."""
    from sigma.data import mitre_d3fend

    # Mock the _get_cached_data functions to return our mock data
    def mock_attack_cached_data():
        return MOCK_ATTACK_DATA

    def mock_d3fend_cached_data():
        return MOCK_D3FEND_DATA

    monkeypatch.setattr(mitre_attack, "_get_cached_data", mock_attack_cached_data)
    monkeypatch.setattr(mitre_d3fend, "_get_cached_data", mock_d3fend_cached_data)

    # Clear any existing cache
    mitre_attack.clear_cache()
    mitre_d3fend.clear_cache()
