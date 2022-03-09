from pathlib import Path
import pytest
from sigma.exceptions import SigmaDetectionError, SigmaRuleLocation

@pytest.fixture
def sigma_path():
    return Path("/path/to/sigma_rule.yml")

@pytest.fixture
def sigma_rule_location(sigma_path):
    return SigmaRuleLocation(sigma_path)

def test_sigmalocation_pathify():
    assert SigmaRuleLocation("test.yml") == SigmaRuleLocation(Path("test.yml"))

def test_sigmalocation_file(sigma_rule_location):
    assert str(sigma_rule_location) == "/path/to/sigma_rule.yml"

def test_sigmalocation_file_with_line(sigma_path):
    assert str(SigmaRuleLocation(sigma_path, 5)) == "/path/to/sigma_rule.yml:5"

def test_sigmalocation_file_with_line_and_char(sigma_path):
    assert str(SigmaRuleLocation(sigma_path, 5, 3)) == "/path/to/sigma_rule.yml:5:3"

def test_exception_with_location(sigma_path):
    assert str(SigmaDetectionError("Test", source=str(SigmaRuleLocation(sigma_path, 5, 3)))) == "Test in /path/to/sigma_rule.yml:5:3"