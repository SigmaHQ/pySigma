from pathlib import Path
import re
import pytest
from sigma.exceptions import SigmaDetectionError, SigmaRuleLocation

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
    assert str(sigma_rule_location) == "/path/to/sigma_rule.yml" or str(sigma_rule_location).endswith("\\path\\to\\sigma_rule.yml")

def test_sigmalocation_file_with_line(sigma_rule_location_with_line):
    locstr = str(sigma_rule_location_with_line)
    assert locstr == "/path/to/sigma_rule.yml:5" or locstr.endswith("\\path\\to\\sigma_rule.yml:5")

def test_sigmalocation_file_with_line_and_char(sigma_rule_location_with_line_and_char):
    locstr = str(sigma_rule_location_with_line_and_char)
    assert locstr == "/path/to/sigma_rule.yml:5:3" or locstr.endswith("\\path\\to\\sigma_rule.yml:5:3")

def test_exception_with_location(sigma_rule_location_with_line_and_char):
    errstr = str(SigmaDetectionError("Test", source=sigma_rule_location_with_line_and_char))
    assert errstr == "Test in /path/to/sigma_rule.yml:5:3" or re.match("Test in \\w:\\\\path\\\\to\\\\sigma_rule.yml:5:3", errstr)