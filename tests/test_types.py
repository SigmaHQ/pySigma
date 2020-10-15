import pytest
from sigma.types import SigmaString, SpecialChars, SigmaNumber, SigmaRegularExpression
from sigma.exceptions import SigmaValueError, SigmaRegularExpressionError

def test_strings_plain():
    assert SigmaString("plain").s == ( "plain", )

def test_strings_wildcards():
    assert SigmaString("wild*cards?contained").s == ( "wild", SpecialChars.WILDCARD_MULTI, "cards", SpecialChars.WILDCARD_SINGLE, "contained" )

def test_strings_escaping():
    assert SigmaString("escaped\\*\\?\\\\*?").s == ( "escaped*?\\", SpecialChars.WILDCARD_MULTI, SpecialChars.WILDCARD_SINGLE )

def test_strings_escaping_nonspecial():
    assert SigmaString("escaped\\nonspecial").s == ( "escaped\\nonspecial", )

def test_strings_escaping_end():
    assert SigmaString("finalescape\\").s == ( "finalescape\\", )

def test_strings_equal():
    assert SigmaString("test*string") == SigmaString("test*string")

def test_strings_not_equal():
    assert SigmaString("test\\*string") != SigmaString("test*string")

def test_strings_equal_str():
    assert SigmaString("test*string") == "test*string"

def test_strings_not_equal_str():
    assert SigmaString("test\\*string") != "test*string"

def test_strings_equal_invalid_type():
    with pytest.raises(NotImplementedError):
        SigmaString("123") == 123

def test_strings_stringable():
    assert str(SigmaString("test*?")) == "test*?"

def test_number_equal():
    assert SigmaNumber(123) == SigmaNumber(123)

def test_number_equal_plain():
    assert SigmaNumber(123) == 123

def test_number_invalid():
    with pytest.raises(SigmaValueError):
        SigmaNumber("test")

def test_re_ok():
    assert SigmaRegularExpression("test.*")

def test_re_invalid():
    with pytest.raises(SigmaRegularExpressionError):
        SigmaRegularExpression("(test.*")