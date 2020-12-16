import pytest
from sigma.types import SigmaString, SpecialChars, SigmaNumber, SigmaNull, SigmaRegularExpression, sigma_type
from sigma.exceptions import SigmaValueError, SigmaRegularExpressionError

def test_strings_empty():
    assert SigmaString().s == tuple()

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

def test_strings_startswith_str():
    assert SigmaString("foobar").startswith("foo")

def test_strings_startswith_special():
    assert SigmaString("*foobar").startswith(SpecialChars.WILDCARD_MULTI)

def test_strings_startswith_difftypes():
    assert not SigmaString("*foobar").startswith("foo")

def test_strings_endswith_str():
    assert SigmaString("foobar").endswith("bar")

def test_strings_endswith_special():
    assert SigmaString("foobar*").endswith(SpecialChars.WILDCARD_MULTI)

def test_strings_endswith_difftypes():
    assert not SigmaString("foobar*").endswith("bar")

def test_strings_contains_special():
    assert SigmaString("foo*bar").contains_special()

def test_strings_not_contains_special():
    assert not SigmaString("foobar").contains_special()

def test_strings_add_sigmastring():
    assert SigmaString("*foo?") + SigmaString("bar*") == SigmaString("*foo?bar*")

def test_strings_add_lstr():
    assert "*foo?" + SigmaString("?bar*") == SigmaString("\\*foo\\??bar*")

def test_strings_add_rstr():
    assert SigmaString("*foo?") + "?bar*" == SigmaString("*foo?\\?bar\\*")

def test_strings_add_linvalid():
    with pytest.raises(TypeError):
        123 + SigmaString("foo")

def test_strings_add_rinvalid():
    with pytest.raises(TypeError):
        SigmaString("foo") + 123

def test_strings_add_lspecial():
    assert SpecialChars.WILDCARD_MULTI + SigmaString("foo*") == SigmaString("*foo*")

def test_strings_add_rspecial():
    assert SigmaString("*foo") + SpecialChars.WILDCARD_MULTI == SigmaString("*foo*")

def test_strings_to_string():
    assert str(SigmaString("test*?")) == "test*?"

def test_strings_to_bytes():
    assert bytes(SigmaString("test*?")) == b"test*?"

def test_strings_len():
    assert len(SigmaString("foo*bar?")) == 8

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

def test_null_equality():
    assert SigmaNull() == SigmaNull("foo")

def test_null_inequality():
    assert SigmaNull() != SigmaString("foo")

def test_conversion_str():
    assert sigma_type("Test") == SigmaString("Test")

def test_conversion_int():
    assert sigma_type(123) == SigmaNumber(123)

def test_conversion_float():
    assert sigma_type(12.34) == SigmaNumber(12.34)

def test_conversion_none():
    assert sigma_type(None) == SigmaNull()