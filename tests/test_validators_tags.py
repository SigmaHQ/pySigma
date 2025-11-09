from wsgiref.validate import validator
from unittest.mock import patch

import pytest
from sigma.exceptions import SigmaValueError

from sigma.rule import SigmaRule, SigmaRuleTag
from sigma.types import SigmaString

from sigma.validators.core.tags import (
    ATTACKTagValidator,
    D3FENDTagValidator,
    DuplicateTagIssue,
    DuplicateTagValidator,
    InvalidATTACKTagIssue,
    InvalidD3FENDagIssue,
    InvalidTLPTagIssue,
    TLPTagValidator,
    TLPv1TagValidator,
    TLPv2TagValidator,
    CARTagValidator,
    CVETagValidator,
    DetectionTagValidator,
    STPTagValidator,
    InvalidPatternTagIssue,
    NamespaceTagValidator,
    InvalidNamespaceTagIssue,
    TagFormatValidator,
    InvalidTagFormatIssue,
)


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
    from sigma.data import mitre_attack_data, mitre_d3fend_data

    # Mock the _get_cached_data functions to return our mock data
    def mock_attack_cached_data():
        return MOCK_ATTACK_DATA

    def mock_d3fend_cached_data():
        return MOCK_D3FEND_DATA

    monkeypatch.setattr(mitre_attack_data, "_get_cached_data", mock_attack_cached_data)
    monkeypatch.setattr(mitre_d3fend_data, "_get_cached_data", mock_d3fend_cached_data)

    # Clear any existing cache
    mitre_attack_data.clear_cache()
    mitre_d3fend_data.clear_cache()


def test_validator_invalid_attack_tags():
    validator = ATTACKTagValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    tags:
        - attack.test1
        - attack.test2
    """
    )
    assert validator.validate(rule) == [
        InvalidATTACKTagIssue([rule], SigmaRuleTag.from_str("attack.test1")),
        InvalidATTACKTagIssue([rule], SigmaRuleTag.from_str("attack.test2")),
    ]


def test_validator_valid_attack_tags():
    validator = ATTACKTagValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    tags:
        - attack.command-and-control
        - attack.t1001.001
        - attack.g0001
        - attack.s0001
        - attack.s0005
        - attack.ds0026
        - attack.m1015
    """
    )
    assert validator.validate(rule) == []


def test_validator_invalid_d3fend_tags():
    validator = D3FENDTagValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    tags:
        - d3fend.test1
        - d3fend.test2
    """
    )
    assert validator.validate(rule) == [
        InvalidD3FENDagIssue([rule], SigmaRuleTag.from_str("d3fend.test1")),
        InvalidD3FENDagIssue([rule], SigmaRuleTag.from_str("d3fend.test2")),
    ]


def test_validator_valid_d3fend_tags():
    validator = D3FENDTagValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    tags:
        - d3fend.isolate
        - d3fend.d3-mfa
        - attack.d3f-AccessControlConfiguration
    """
    )
    assert validator.validate(rule) == []


@pytest.mark.parametrize(
    "validator_class,tags,issue_tags",
    [
        (TLPv1TagValidator, ["tlp.clear", "tlp.white"], ["tlp.clear"]),
        (TLPv2TagValidator, ["tlp.clear", "tlp.white"], ["tlp.white"]),
        (TLPTagValidator, ["tlp.clear", "tlp.white"], []),
        (TLPTagValidator, ["tlp.clear", "tlp.white", "tlp.test"], ["tlp.test"]),
    ],
    ids=[
        "TLPv1-invalid",
        "TLPv2-invalid",
        "TLP-valid",
        "TLP-invalid",
    ],
)
def test_validator_tlp_tags(validator_class, tags, issue_tags):
    validator = validator_class()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    rule.tags = [SigmaRuleTag.from_str(tag) for tag in tags]
    assert validator.validate(rule) == [
        InvalidTLPTagIssue([rule], SigmaRuleTag.from_str(tag)) for tag in issue_tags
    ]


def test_validator_duplicate_tags():
    validator = DuplicateTagValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    tags:
        - attack.command_and_control
        - attack.t1001.001
        - attack.g0001
        - attack.g0001
        - attack.s0001
        - attack.s0005
    """
    )
    assert validator.validate(rule) == [DuplicateTagIssue([rule], SigmaRuleTag("attack", "g0001"))]


@pytest.mark.parametrize(
    "opt_validator_class,opt_tags,opt_issue_tags,opt_issue_class",
    [
        (
            CVETagValidator,
            ["cve.2023-11-04", "cve.2023-007"],
            ["cve.2023-11-04"],
            InvalidPatternTagIssue,
        ),
        (CVETagValidator, ["cve.2023-007", "cve.2022-963"], [], InvalidPatternTagIssue),
        (
            DetectionTagValidator,
            ["detection.new-threats", "cve.2023-007"],
            ["detection.new-threats"],
            InvalidPatternTagIssue,
        ),
        (
            DetectionTagValidator,
            ["detection.emerging-threats", "cve.2022-963"],
            [],
            InvalidPatternTagIssue,
        ),
        (
            CARTagValidator,
            ["car.2016-04-005", "car.2023-011-11"],
            ["car.2023-011-11"],
            InvalidPatternTagIssue,
        ),
        (CARTagValidator, ["car.2016-04-005", "car.2023-11-011"], [], InvalidPatternTagIssue),
        (STPTagValidator, ["stp.5k", "stp.1"], [], InvalidPatternTagIssue),
        (
            STPTagValidator,
            [
                "stp.5k",
                "stp.1A",
            ],
            ["stp.1A"],
            InvalidPatternTagIssue,
        ),
        (
            NamespaceTagValidator,
            ["attaque.command_and_control"],
            ["attaque.command_and_control"],
            InvalidNamespaceTagIssue,
        ),
        (
            NamespaceTagValidator,
            [
                "attack.t1234",
                "car.2016-04-005",
                "stp.3k",
                "cve.2023-007",
                "tlp.amber",
                "detection.threat-hunting",
            ],
            [],
            InvalidNamespaceTagIssue,
        ),
        (
            TagFormatValidator,
            ["custom.my tag", "custom.my2tag"],
            ["custom.my tag"],
            InvalidTagFormatIssue,
        ),
        (
            TagFormatValidator,
            ["custom.my_tag", "custom.my-tag"],
            [],
            InvalidTagFormatIssue,
        ),
    ],
)
def test_validator_optional_tag(opt_validator_class, opt_tags, opt_issue_tags, opt_issue_class):
    validator = opt_validator_class()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    rule.tags = [SigmaRuleTag.from_str(tag) for tag in opt_tags]
    assert validator.validate(rule) == [
        opt_issue_class([rule], SigmaRuleTag.from_str(tag)) for tag in opt_issue_tags
    ]
