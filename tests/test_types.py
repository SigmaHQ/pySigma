import re
import pytest
from sigma.types import SigmaBool, SigmaCompareExpression, SigmaString, Placeholder, SpecialChars, SigmaNumber, SigmaNull, SigmaRegularExpression, SigmaQueryExpression, sigma_type, SigmaCIDRExpression
from sigma.exceptions import SigmaTypeError, SigmaValueError, SigmaRegularExpressionError

@pytest.fixture
def sigma_string():
    return SigmaString("*Test*Str\\*ing*")

@pytest.fixture
def empty_sigma_string():
    return SigmaString("")

def test_strings_empty():
    assert SigmaString().s == tuple()

def test_strings_plain():
    assert SigmaString("plain").s == ( "plain", )

def test_strings_merge():
    s = SigmaString()
    s.s = (SpecialChars.WILDCARD_MULTI, "te", "st", SpecialChars.WILDCARD_MULTI)
    assert s._merge_strs().s == (SpecialChars.WILDCARD_MULTI, "test", SpecialChars.WILDCARD_MULTI)

def test_strings_merge_end():
    s = SigmaString()
    s.s = (SpecialChars.WILDCARD_MULTI, "test", SpecialChars.WILDCARD_MULTI, "te", "st", "test")
    assert s._merge_strs().s == (SpecialChars.WILDCARD_MULTI, "test", SpecialChars.WILDCARD_MULTI, "testtest")

def test_strings_merge_start():
    s = SigmaString()
    s.s = ("te", "st", "test", SpecialChars.WILDCARD_MULTI, "test", SpecialChars.WILDCARD_MULTI)
    assert s._merge_strs().s == ("testtest", SpecialChars.WILDCARD_MULTI, "test", SpecialChars.WILDCARD_MULTI)

def test_strings_wildcards():
    assert SigmaString("wild*cards?contained").s == ( "wild", SpecialChars.WILDCARD_MULTI, "cards", SpecialChars.WILDCARD_SINGLE, "contained" )

def test_strings_escaping():
    assert SigmaString("escaped\\*\\?\\\\*?").s == ( "escaped*?\\", SpecialChars.WILDCARD_MULTI, SpecialChars.WILDCARD_SINGLE )

def test_strings_escaping_nonspecial():
    assert SigmaString("escaped\\nonspecial").s == ( "escaped\\nonspecial", )

def test_strings_escaping_end():
    assert SigmaString("finalescape\\").s == ( "finalescape\\", )

def test_string_placeholders_single():
    assert SigmaString("test1%var%test2").insert_placeholders().s == ("test1", Placeholder("var"), "test2")

def test_string_placeholders_multi():
    assert SigmaString("%start%te*st1%middle%te?st2%end%").insert_placeholders().s == (Placeholder("start"), "te", SpecialChars.WILDCARD_MULTI, "st1", Placeholder("middle"), "te", SpecialChars.WILDCARD_SINGLE, "st2", Placeholder("end"))

def test_string_replace_with_placeholder():
    assert SigmaString("testx1xfoox1xtest*x2x*bar*x3x").replace_with_placeholder(re.compile("x\\dx"), "test").s == \
        ("test", Placeholder("test"), "foo", Placeholder("test"), "test", SpecialChars.WILDCARD_MULTI, Placeholder("test"), SpecialChars.WILDCARD_MULTI, "bar", SpecialChars.WILDCARD_MULTI, Placeholder("test"))

def test_string_placeholders_replace():
    def callback(p):
        yield from ["A", SpecialChars.WILDCARD_MULTI]

    assert SigmaString("test%var1%something%var2%end").insert_placeholders().replace_placeholders(callback) == [
        SigmaString("testAsomethingAend"),
        SigmaString("testAsomething*end"),
        SigmaString("test*somethingAend"),
        SigmaString("test*something*end"),
    ]

def test_string_placeholders_escape():
    assert SigmaString("\\%test1\\%test2\\%%var%\\%test3\\%").insert_placeholders().s == ("%test1%test2%", Placeholder("var"), "%test3%")

def test_string_contains_placeholders():
    assert SigmaString("test1%var%test2").insert_placeholders().contains_placeholder()

def test_string_contains_placeholders_none():
    assert SigmaString("test1test2").insert_placeholders().contains_placeholder() == False

def test_string_contains_placeholders_included():
    assert SigmaString("test1%var%test2%test%").insert_placeholders().contains_placeholder(include=["var"])

def test_string_contains_placeholders_no_included():
    assert SigmaString("test1%var%test2%test%").insert_placeholders().contains_placeholder(include=["other"]) == False

def test_string_contains_placeholders_one_excluded():
    assert SigmaString("test1%var%test2%test%").insert_placeholders().contains_placeholder(exclude=["var"])

def test_string_contains_placeholders_all_excluded():
    assert SigmaString("test1%var%test2%test%").insert_placeholders().contains_placeholder(exclude=["var", "test"]) == False

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

def test_strings_to_plain():
    assert SigmaString("test*?").to_plain() == "test*?"

def test_strings_to_bytes():
    assert bytes(SigmaString("test*?")) == b"test*?"

def test_strings_len(sigma_string):
    assert len(sigma_string) == 14

def test_strings_iter():
    assert list(SigmaString("foo*bar")) == ["f", "o", "o", SpecialChars.WILDCARD_MULTI, "b", "a", "r"]

def test_strings_convert():
    assert SigmaString("foo?\\*bar*").convert(add_escaped="f", filter_chars="o") == "\\f?\\*bar*"

def test_strings_convert_no_multiwildcard():
    with pytest.raises(SigmaValueError, match="Multi-character wildcard"):
        SigmaString("foo*bar").convert(wildcard_multi=None)

def test_strings_convert_no_singlewildcard():
    with pytest.raises(SigmaValueError, match="Single-character wildcard"):
        SigmaString("foo?bar").convert(wildcard_single=None)

def test_string_index(sigma_string):
    assert sigma_string[3] == SigmaString("s")

def test_string_index_negative(sigma_string):
    assert sigma_string[-1] == SigmaString("*")

def test_string_index_open_start(sigma_string):
    assert sigma_string[:3] == SigmaString("*Te")

def test_string_index_slice_without_escaped(sigma_string):
    assert sigma_string[3:9] == SigmaString("st*Str")

def test_string_index_slice_with_escaped(sigma_string):
    assert sigma_string[3:10] == SigmaString("st*Str\\*")

def test_string_index_slice_start_and_end_in_same_string_part(sigma_string):
    assert sigma_string[2:4] == SigmaString("es")

def test_string_index_slice_negative_end(sigma_string):
    assert sigma_string[3:-1] == SigmaString("st*Str\\*ing")

def test_string_index_slice_cut_first_and_last(sigma_string):
    assert sigma_string[1:-1] == SigmaString("Test*Str\\*ing")

def test_empty_string_index_slice_cut_first_and_last(empty_sigma_string):
    assert empty_sigma_string[1:-1] == SigmaString("")

def test_string_index_slice_negative_start_and_end(sigma_string):
    assert sigma_string[-3:-1] == SigmaString("ng")

def test_string_index_slice_open_end_with_escaped(sigma_string):
    assert sigma_string[9:] == SigmaString("\\*ing*")

def test_string_index_slice_open_end_without_escaped(sigma_string):
    assert sigma_string[10:] == SigmaString("ing*")

def test_string_index_slice_empty_result(sigma_string):
    assert sigma_string[4:2] == SigmaString("")

def test_string_index_slice_start_after_end(sigma_string):
    with pytest.raises(IndexError, match="out of range"):
        assert sigma_string[100:]

def test_string_index_slice_open_start_negative_end(sigma_string):
    assert sigma_string[:-1] == SigmaString("*Test*Str\\*ing")

def test_string_index_invalid_type(sigma_string):
    with pytest.raises(TypeError, match="indices must be"):
        sigma_string["invalid"]

def test_string_index_slice_with_step(sigma_string):
    with pytest.raises(IndexError, match="slice index with step"):
        sigma_string[2:8:2]

def test_number_int():
    assert SigmaNumber(123).number == 123

def test_number_float():
    assert SigmaNumber(12.34).number == 12.34

def test_number_to_plain():
    assert SigmaNumber(123).to_plain() == 123

def test_number_equal():
    assert SigmaNumber(123) == SigmaNumber(123)

def test_number_equal_plain():
    assert SigmaNumber(123) == 123

def test_number_invalid():
    with pytest.raises(SigmaValueError):
        SigmaNumber("test")

def test_re_ok():
    assert SigmaRegularExpression("test.*")

def test_re_to_plain():
    assert SigmaRegularExpression("test.*").to_plain() == "test.*"

def test_re_invalid():
    with pytest.raises(SigmaRegularExpressionError):
        SigmaRegularExpression("(test.*")

def test_re_escape():
    assert SigmaRegularExpression("foo\\d+bar-test").escape(("foo", "-", "t"), "\\") == "\\foo\\\\d+bar\\-\\tes\\t"

def test_bool():
    assert SigmaBool(True).boolean == True

def test_bool_str():
    assert str(SigmaBool(True)) == "True"

def test_bool_to_plain():
    assert SigmaBool(True).to_plain() == True

def test_bool_invalid():
    with pytest.raises(SigmaTypeError, match="must be a boolean"):
        SigmaBool(123)

def test_null_to_plain():
    assert SigmaNull().to_plain() == None

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

def test_conversion_bool():
    assert sigma_type(True) == SigmaBool(True)

def test_conversion_none():
    assert sigma_type(None) == SigmaNull()

def test_query_expression():
    assert str(SigmaQueryExpression("test\\test*test?test[]", "id")) == "test\\test*test?test[]"

def test_query_expression_finalize():
    assert SigmaQueryExpression("{field} in list({id})", "id").finalize("xxx") == "xxx in list(id)"

def test_query_expression_finalize_nofield_error():
    with pytest.raises(SigmaValueError, match="no field was given"):
        SigmaQueryExpression("{field} in list({id})", "id").finalize()

def test_query_expression_to_plain():
    with pytest.raises(SigmaValueError, match="can't be converted into a plain representation"):
        SigmaQueryExpression("test", "id").to_plain()

def test_query_expression_wrong_expr_type():
    with pytest.raises(SigmaTypeError, match="must be a string"):
        SigmaQueryExpression(123, "id")

def test_query_expression_wrong_id_type():
    with pytest.raises(SigmaTypeError, match="must be a string"):
        SigmaQueryExpression("123", 123)

def test_cidr_ok():
    assert SigmaCIDRExpression("192.168.1.0/24")

def test_cidr_to_plain():
    with pytest.raises(SigmaValueError, match="can't be converted into a plain representation"):
        SigmaCIDRExpression("192.168.1.0/24").to_plain()

def test_cidr_invalid():
    with pytest.raises(SigmaTypeError, match="Invalid IPv4 CIDR expression"):
        SigmaCIDRExpression("::1/128")

def test_cidr_expand_31_no_wildcard():
    assert SigmaCIDRExpression("192.168.1.0/31").expand(wildcard=None) == ['192.168.1.0/31']

def test_cidr_expand_31_wildcard():
    assert SigmaCIDRExpression("192.168.1.0/31").expand(wildcard='*') == ['192.168.1.0', '192.168.1.1']

def test_cidr_expand_24_wildcard():
    assert SigmaCIDRExpression("192.168.1.0/24").expand(wildcard='*') == ['192.168.1.*']

def test_cidr_expand_23_wildcard():
    assert SigmaCIDRExpression("192.168.0.0/23").expand(wildcard='*') == ['192.168.0.*', '192.168.1.*']

def test_cidr_expand_14_wildcard():
    assert SigmaCIDRExpression("192.168.0.0/14").expand(wildcard='*') == ['192.168.*', '192.169.*', '192.170.*', '192.171.*']

def test_cidr_expand_8_wildcard():
    assert SigmaCIDRExpression("192.0.0.0/8").expand(wildcard='*') == ['192.*']

def test_cidr_convert_23_no_wildcard():
    assert SigmaCIDRExpression("192.168.0.0/23").convert(
        "not relevant",
        "cidr({network})",
        None
    ) == 'cidr(192.168.0.0/23)'

def test_cidr_convert_23_wildcard():
    assert SigmaCIDRExpression("192.168.0.0/23").convert(
        " OR ",
        '"{network}"',
        "*",
    ) == '"192.168.0.*" OR "192.168.1.*"'

def test_cidr_invalid():
    with pytest.raises(SigmaTypeError, match="Invalid IPv4 CIDR expression"):
        SigmaCIDRExpression("192.168.1.2/24")

def test_compare_to_plain():
    with pytest.raises(SigmaValueError, match="can't be converted into a plain representation"):
        SigmaCompareExpression(SigmaNumber(123), SigmaCompareExpression.CompareOperators.LTE).to_plain()

def test_compare_string():
    with pytest.raises(SigmaTypeError, match="expects number"):
        SigmaCompareExpression(SigmaString("123"), SigmaCompareExpression.CompareOperators.LTE).to_plain()