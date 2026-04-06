import re
from pathlib import Path

import pytest

from sigma.exceptions import ExceptionOnUsage, SigmaDetectionError, SigmaError, SigmaRuleLocation


@pytest.fixture
def sigma_path():
    return Path("/path/to/sigma_rule.yml")


@pytest.fixture
def sigma_rule_location(sigma_path):
    return SigmaRuleLocation(sigma_path)


@pytest.fixture
def sigma_rule_location_with_line(sigma_path):
    return SigmaRuleLocation(sigma_path, 5)


@pytest.fixture
def sigma_rule_location_with_line_and_char(sigma_path):
    return SigmaRuleLocation(sigma_path, 5, 3)


def test_sigmalocation_pathify():
    assert SigmaRuleLocation("test.yml") == SigmaRuleLocation(Path("test.yml"))


def test_sigmalocation_file(sigma_rule_location):
    assert str(sigma_rule_location) == "/path/to/sigma_rule.yml" or str(
        sigma_rule_location
    ).endswith("\\path\\to\\sigma_rule.yml")


def test_sigmalocation_file_with_line(sigma_rule_location_with_line):
    locstr = str(sigma_rule_location_with_line)
    assert locstr == "/path/to/sigma_rule.yml:5" or locstr.endswith("\\path\\to\\sigma_rule.yml:5")


def test_sigmalocation_file_with_line_and_char(sigma_rule_location_with_line_and_char):
    locstr = str(sigma_rule_location_with_line_and_char)
    assert locstr == "/path/to/sigma_rule.yml:5:3" or locstr.endswith(
        "\\path\\to\\sigma_rule.yml:5:3"
    )


def test_exception_with_location(sigma_rule_location_with_line_and_char):
    errstr = str(SigmaDetectionError("Test", source=sigma_rule_location_with_line_and_char))
    assert errstr == "Test in /path/to/sigma_rule.yml:5:3" or re.match(
        "Test in \\w:\\\\path\\\\to\\\\sigma_rule.yml:5:3", errstr
    )


def test_exception_equalness():
    assert SigmaError("A") == SigmaError("A")


def test_exception_unequalness_same_type():
    assert SigmaError("A") != SigmaError("B")


def test_exception_unequalness_different_type():
    assert SigmaDetectionError("A") != SigmaError("A")


def test_exception_unequalness_incompatible_type():
    assert SigmaDetectionError("A") != ValueError("A")


def test_exception_on_usage() -> None:
    test_exception_message: str = "some message"
    test_exception: ValueError = ValueError(test_exception_message)
    e: ExceptionOnUsage = ExceptionOnUsage(test_exception)
    with pytest.deprecated_call(
        match=r"\w+ is deprecated and will be removed in a future release."
    ), pytest.raises(ValueError, match=test_exception_message):
        e.test
