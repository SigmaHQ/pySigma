from wsgiref.validate import validator

import pytest
from sigma.exceptions import SigmaValueError

from sigma.rule import SigmaRule, SigmaRuleTag
from sigma.types import SigmaString

from sigma.validators.core.tags import (
    ATTACKTagValidator,
    DuplicateTagIssue,
    DuplicateTagValidator,
    InvalidATTACKTagIssue,
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
)


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
