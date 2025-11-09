from wsgiref.validate import validator
from unittest.mock import patch
import tempfile
import json

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
from sigma.data import mitre_attack_data, mitre_d3fend_data


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


def test_mitre_attack_set_url_with_file(monkeypatch):
    """Test setting a custom file path for MITRE ATT&CK data."""
    import os

    # Remove the monkeypatch for this test so we can test the real function
    monkeypatch.undo()

    # Save the original state
    original_cache = mitre_attack_data._cache
    original_url = mitre_attack_data._custom_url

    # Create a temporary file with minimal MITRE ATT&CK data
    attack_data = {
        "objects": [
            {
                "type": "x-mitre-collection",
                "x_mitre_version": "99.9",
            },
            {
                "type": "attack-pattern",
                "name": "Test Technique",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "test-tactic"}
                ],
            },
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(attack_data, f)
        temp_path = f.name

    try:
        # Use set_url which clears cache and sets custom URL
        mitre_attack_data.set_url(temp_path)

        # Access the data to trigger loading
        techniques = mitre_attack_data.mitre_attack_techniques
        assert "T9999" in techniques
        assert techniques["T9999"] == "Test Technique"

        # Verify it works with the validator
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
            - attack.t9999
        """
        )
        assert validator.validate(rule) == []
    finally:
        # Clean up and restore original state
        mitre_attack_data._cache = original_cache
        mitre_attack_data._custom_url = original_url
        os.unlink(temp_path)


def test_mitre_d3fend_set_url_with_file(monkeypatch):
    """Test setting a custom file path for MITRE D3FEND data."""
    import os

    # Remove the monkeypatch for this test so we can test the real function
    monkeypatch.undo()

    # Save the original state
    original_cache = mitre_d3fend_data._cache
    original_url = mitre_d3fend_data._custom_url

    # Create a temporary file with minimal D3FEND data
    d3fend_data = {
        "@graph": [
            {
                "@type": "owl:Ontology",
                "owl:versionIRI": "http://d3fend.mitre.org/ontologies/d3fend/99.9",
            },
            {
                "@id": "http://d3fend.mitre.org/ontologies/d3fend.owl#D3-TEST",
                "@type": "d3f:DefensiveTechnique",
                "rdfs:label": "Test Technique",
            },
            {
                "@type": "d3f:DefensiveTactic",
                "rdfs:label": "test-tactic",
            },
        ]
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(d3fend_data, f)
        temp_path = f.name

    try:
        # Use set_url which clears cache and sets custom URL
        mitre_d3fend_data.set_url(temp_path)

        # Access the data to trigger loading
        techniques = mitre_d3fend_data.mitre_d3fend_techniques
        assert "D3-TEST" in techniques
        assert techniques["D3-TEST"] == "Test Technique"

        # Verify it works with the validator
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
            - d3fend.d3-test
        """
        )
        assert validator.validate(rule) == []
    finally:
        # Clean up and restore original state
        mitre_d3fend_data._cache = original_cache
        mitre_d3fend_data._custom_url = original_url
        os.unlink(temp_path)
