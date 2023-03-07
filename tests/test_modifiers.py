import pytest
from typing import Union, Sequence, List
from sigma.modifiers import \
    SigmaExistsModifier, \
    SigmaModifier, \
    SigmaContainsModifier, \
    SigmaRegularExpressionIgnoreCaseFlagModifier, \
    SigmaRegularExpressionMultilineFlagModifier, \
    SigmaRegularExpressionDotAllFlagModifier, \
    SigmaStartswithModifier, \
    SigmaEndswithModifier, \
    SigmaBase64Modifier, \
    SigmaBase64OffsetModifier, \
    SigmaWideModifier, \
    SigmaRegularExpressionModifier, \
    SigmaCIDRModifier, \
    SigmaAllModifier, \
    SigmaLessThanModifier, \
    SigmaLessThanEqualModifier, \
    SigmaGreaterThanModifier, \
    SigmaGreaterThanEqualModifier, \
    SigmaExpandModifier, \
    SigmaWindowsDashModifier
from sigma.rule import SigmaDetectionItem
from sigma.types import SigmaBool, SigmaExists, SigmaExpansion, SigmaRegularExpressionFlag, SigmaString, Placeholder, SigmaNumber, SigmaRegularExpression, SigmaCompareExpression, SigmaCIDRExpression
from sigma.conditions import ConditionAND
from sigma.exceptions import SigmaRuleLocation, SigmaTypeError, SigmaValueError

@pytest.fixture
def dummy_detection_item():
    return SigmaDetectionItem(None, [], ["foobar"])

@pytest.fixture
def dummy_plain_modifier(dummy_detection_item):
    class DummyPlainModifier(SigmaModifier):
        def modify(self, val : SigmaString) -> SigmaString:
            return SigmaString("")
    return DummyPlainModifier(dummy_detection_item, [], SigmaRuleLocation("test.yml"))

@pytest.fixture
def dummy_union_modifier(dummy_detection_item):
    class DummyUnionModifier(SigmaModifier):
        def modify(self, val : Union[SigmaString, SigmaNumber]) -> SigmaString:
            return SigmaString("")
    return DummyUnionModifier(dummy_detection_item, [])

@pytest.fixture
def dummy_sequence_modifier(dummy_detection_item):
    class DummySequenceModifier(SigmaModifier):
        def modify(self, val : Sequence[SigmaString]) -> List[SigmaString]:
            return [ SigmaString("") ]
    return DummySequenceModifier(dummy_detection_item, [])

def test_typecheck_plain(dummy_plain_modifier):
    assert dummy_plain_modifier.type_check(SigmaString("foobar"))

def test_typecheck_plain_wrong(dummy_plain_modifier):
    assert not dummy_plain_modifier.type_check(SigmaNumber(123))

def test_typecheck_plain_wrong_apply(dummy_plain_modifier):
    with pytest.raises(SigmaTypeError, match="incompatible.*type.*test.yml"):
        dummy_plain_modifier.apply(SigmaNumber(123))

def test_typecheck_apply_list_input(dummy_sequence_modifier):
    assert dummy_sequence_modifier.apply([SigmaString("foobar")]) == [ SigmaString("") ]

def test_typecheck_union(dummy_union_modifier):
    assert dummy_union_modifier.type_check(SigmaString("foobar"))

def test_typecheck_union_wrong(dummy_union_modifier):
    assert not dummy_union_modifier.type_check(SigmaRegularExpression(".*"))

def test_typecheck_sequence(dummy_sequence_modifier):
    assert dummy_sequence_modifier.type_check([SigmaString("foobar")])

def test_typecheck_sequence_wrong(dummy_sequence_modifier):
    assert not dummy_sequence_modifier.type_check([SigmaNumber(123)])

def test_contains_nowildcards(dummy_detection_item):
    assert SigmaContainsModifier(dummy_detection_item, []).apply(SigmaString("foobar")) == [ SigmaString("*foobar*") ]

def test_contains_leading_wildcard(dummy_detection_item):
    assert SigmaContainsModifier(dummy_detection_item, []).apply(SigmaString("*foobar")) == [ SigmaString("*foobar*") ]

def test_contains_trailing_wildcard(dummy_detection_item):
    assert SigmaContainsModifier(dummy_detection_item, []).apply(SigmaString("foobar*")) == [ SigmaString("*foobar*") ]

def test_contains_leading_and_trailing_wildcard(dummy_detection_item):
    assert SigmaContainsModifier(dummy_detection_item, []).apply(SigmaString("*foobar*")) == [ SigmaString("*foobar*") ]

def test_startswith_nowildcards(dummy_detection_item):
    assert SigmaStartswithModifier(dummy_detection_item, []).apply(SigmaString("foobar")) == [ SigmaString("foobar*") ]

def test_startswith_trailing_wildcard(dummy_detection_item):
    assert SigmaStartswithModifier(dummy_detection_item, []).apply(SigmaString("foobar*")) == [ SigmaString("foobar*") ]

def test_endswith_nowildcards(dummy_detection_item):
    assert SigmaEndswithModifier(dummy_detection_item, []).apply(SigmaString("foobar")) == [ SigmaString("*foobar") ]

def test_endswith_trailing_wildcard(dummy_detection_item):
    assert SigmaEndswithModifier(dummy_detection_item, []).apply(SigmaString("*foobar")) == [ SigmaString("*foobar") ]

def test_base64(dummy_detection_item):
    assert SigmaBase64Modifier(dummy_detection_item, []).apply(SigmaString("foobar")) == [ SigmaString("Zm9vYmFy") ]

def test_base64_wildcards(dummy_detection_item):
    with pytest.raises(SigmaValueError, match="wildcards is not allowed.*test.yml"):
        SigmaBase64Modifier(dummy_detection_item, [], SigmaRuleLocation("test.yml")).apply(SigmaString("foo*bar"))

def test_base64offset(dummy_detection_item):
    assert SigmaBase64OffsetModifier(dummy_detection_item, []).apply(SigmaString("foobar")) == [
        SigmaExpansion([
            SigmaString("Zm9vYmFy"),
            SigmaString("Zvb2Jhc"),
            SigmaString("mb29iYX"),
        ])
    ]

def test_base64offset_wildcards(dummy_detection_item):
    with pytest.raises(SigmaValueError, match="wildcards is not allowed.*test.yml"):
        SigmaBase64OffsetModifier(dummy_detection_item, [], SigmaRuleLocation("test.yml")).apply(SigmaString("foo*bar"))

def test_base64offset_re(dummy_detection_item):
    with pytest.raises(SigmaTypeError, match="incompatible.*type.*test.yml"):
        SigmaBase64OffsetModifier(dummy_detection_item, [], SigmaRuleLocation("test.yml")).apply(SigmaRegularExpression("foo.*bar"))

def test_wide(dummy_detection_item):
    assert SigmaWideModifier(dummy_detection_item, []).apply(SigmaString("*foobar*")) == [ SigmaString("*f\x00o\x00o\x00b\x00a\x00r\x00*") ]

def test_wide_noascii(dummy_detection_item):
    with pytest.raises(SigmaValueError, match="ascii strings.*test.yml"):
        SigmaWideModifier(dummy_detection_item, [], SigmaRuleLocation("test.yml")).apply(SigmaString("foobär"))

def test_windash(dummy_detection_item):
    assert SigmaWindowsDashModifier(dummy_detection_item, []).modify(SigmaString("-param-1 -param2")) == SigmaExpansion([
        SigmaString("-param-1 -param2"),
        SigmaString("-param-1 /param2"),
        SigmaString("/param-1 -param2"),
        SigmaString("/param-1 /param2"),
    ])

def test_re(dummy_detection_item):
    assert SigmaRegularExpressionModifier(dummy_detection_item, []).modify(SigmaString("foo?bar.*")) == SigmaRegularExpression("foo?bar.*")

@pytest.fixture
def sigma_regex():
    return SigmaRegularExpression("foo.*bar")

@pytest.fixture
def re_detection_item(sigma_regex):
    return SigmaDetectionItem("test", [], [sigma_regex])

def test_re_modifier_ignorecase(re_detection_item, sigma_regex):
    assert SigmaRegularExpressionIgnoreCaseFlagModifier(re_detection_item, []).modify(sigma_regex) == SigmaRegularExpression("foo.*bar", {SigmaRegularExpressionFlag.IGNORECASE})

def test_re_modifier_multiline(re_detection_item, sigma_regex):
    assert SigmaRegularExpressionMultilineFlagModifier(re_detection_item, []).modify(sigma_regex) == SigmaRegularExpression("foo.*bar", {SigmaRegularExpressionFlag.MULTILINE})

def test_re_modifier_dotall(re_detection_item, sigma_regex):
    assert SigmaRegularExpressionDotAllFlagModifier(re_detection_item, []).modify(sigma_regex) == SigmaRegularExpression("foo.*bar", {SigmaRegularExpressionFlag.DOTALL})

def test_do_not_escape_regular_expressions(dummy_detection_item):
    assert SigmaRegularExpressionModifier(dummy_detection_item, []).modify(SigmaString(r"foo\\bar")) == SigmaRegularExpression(r"foo\\bar")

def test_re_contains(dummy_detection_item):
    assert SigmaContainsModifier(dummy_detection_item, []).modify(SigmaRegularExpression("foo?bar")) == SigmaRegularExpression(".*foo?bar.*")

def test_re_contains_start(dummy_detection_item):
    assert SigmaContainsModifier(dummy_detection_item, []).modify(SigmaRegularExpression("^foo?bar")) == SigmaRegularExpression("^foo?bar.*")

def test_re_contains_end(dummy_detection_item):
    assert SigmaContainsModifier(dummy_detection_item, []).modify(SigmaRegularExpression("foo?bar$")) == SigmaRegularExpression(".*foo?bar$")

def test_re_contains_startswith_wildcard(dummy_detection_item):
    assert SigmaContainsModifier(dummy_detection_item, []).modify(SigmaRegularExpression(".*foo?bar")) == SigmaRegularExpression(".*foo?bar.*")

def test_re_contains_endswith_wildcard(dummy_detection_item):
    assert SigmaContainsModifier(dummy_detection_item, []).modify(SigmaRegularExpression("foo?bar.*")) == SigmaRegularExpression(".*foo?bar.*")

def test_re_startswith(dummy_detection_item):
    assert SigmaStartswithModifier(dummy_detection_item, []).modify(SigmaRegularExpression("foo?bar")) == SigmaRegularExpression("foo?bar.*")

def test_re_endswith(dummy_detection_item):
    assert SigmaEndswithModifier(dummy_detection_item, []).modify(SigmaRegularExpression("foo?bar")) == SigmaRegularExpression(".*foo?bar")

def test_re_startswith_start(dummy_detection_item):
    assert SigmaStartswithModifier(dummy_detection_item, []).modify(SigmaRegularExpression("^foo?bar")) == SigmaRegularExpression("^foo?bar.*")

def test_re_endswith_start(dummy_detection_item):
    assert SigmaEndswithModifier(dummy_detection_item, []).modify(SigmaRegularExpression("^foo?bar")) == SigmaRegularExpression("^foo?bar")

def test_re_startswith_end(dummy_detection_item):
    assert SigmaStartswithModifier(dummy_detection_item, []).modify(SigmaRegularExpression("foo?bar$")) == SigmaRegularExpression("foo?bar$")

def test_re_endswith_end(dummy_detection_item):
    assert SigmaEndswithModifier(dummy_detection_item, []).modify(SigmaRegularExpression("foo?bar$")) == SigmaRegularExpression(".*foo?bar$")

def test_re_endswith_startswith_wildcard(dummy_detection_item):
    assert SigmaEndswithModifier(dummy_detection_item, []).modify(SigmaRegularExpression(".*foo?bar")) == SigmaRegularExpression(".*foo?bar")

def test_re_startswith_endswith_wildcard(dummy_detection_item):
    assert SigmaStartswithModifier(dummy_detection_item, []).modify(SigmaRegularExpression("foo?bar.*")) == SigmaRegularExpression("foo?bar.*")

def test_re_with_other(dummy_detection_item):
    with pytest.raises(SigmaValueError, match="only applicable to unmodified values.*test.yml"):
        SigmaRegularExpressionModifier(dummy_detection_item, [SigmaBase64Modifier], SigmaRuleLocation("test.yml")).modify(SigmaString("foo?bar.*"))

def test_all(dummy_detection_item):
    values = [
        SigmaString("*foobar*"),
        SigmaNumber(123),
        SigmaRegularExpression(".*foobar.*")
        ]
    assert SigmaAllModifier(dummy_detection_item, []).modify(values) == values and dummy_detection_item.value_linking == ConditionAND

def test_lt(dummy_detection_item):
    assert SigmaLessThanModifier(dummy_detection_item, []).modify(SigmaNumber(123)) == SigmaCompareExpression(SigmaNumber(123), SigmaCompareExpression.CompareOperators.LT)

def test_lte(dummy_detection_item):
    assert SigmaLessThanEqualModifier(dummy_detection_item, []).modify(SigmaNumber(123)) == SigmaCompareExpression(SigmaNumber(123), SigmaCompareExpression.CompareOperators.LTE)

def test_gt(dummy_detection_item):
    assert SigmaGreaterThanModifier(dummy_detection_item, []).modify(SigmaNumber(123)) == SigmaCompareExpression(SigmaNumber(123), SigmaCompareExpression.CompareOperators.GT)

def test_gte(dummy_detection_item):
    assert SigmaGreaterThanEqualModifier(dummy_detection_item, []).modify(SigmaNumber(123)) == SigmaCompareExpression(SigmaNumber(123), SigmaCompareExpression.CompareOperators.GTE)

def test_exists(dummy_detection_item):
    dummy_detection_item.field = "test"
    assert SigmaExistsModifier(dummy_detection_item, []).modify(SigmaBool(True)) == SigmaExists(True)

def test_exists_without_field(dummy_detection_item):
    with pytest.raises(SigmaValueError, match="must be applied to field.*test.yml"):
        SigmaExistsModifier(dummy_detection_item, [], SigmaRuleLocation("test.yml")).modify(SigmaBool(True)) == SigmaExists(True)

def test_exists_with_other(dummy_detection_item):
    dummy_detection_item.field = "test"
    with pytest.raises(SigmaValueError, match="only applicable to unmodified boolean values.*test.yml"):
        SigmaExistsModifier(dummy_detection_item, [SigmaBase64Modifier], SigmaRuleLocation("test.yml")).modify(SigmaBool(True))

def test_compare_string(dummy_detection_item):
    with pytest.raises(SigmaTypeError, match="expects number.*test.yml"):
        SigmaGreaterThanEqualModifier(dummy_detection_item, [], SigmaRuleLocation("test.yml")).modify(SigmaString("123"))

def test_expand(dummy_detection_item):
    assert SigmaExpandModifier(dummy_detection_item, []).modify(SigmaString("test%var%test")).s == ("test", Placeholder("var"), "test")

def test_cidr(dummy_detection_item):
    assert SigmaCIDRModifier(dummy_detection_item, []).modify(SigmaString("192.168.1.0/24")) == SigmaCIDRExpression("192.168.1.0/24")

def test_cidr_with_other(dummy_detection_item):
    with pytest.raises(SigmaValueError, match="only applicable to unmodified values.*test.yml"):
        SigmaCIDRModifier(dummy_detection_item, [SigmaBase64Modifier], SigmaRuleLocation("test.yml")).modify(SigmaString("192.168.1.0/24"))

def test_cidr_invalid(dummy_detection_item):
    with pytest.raises(SigmaTypeError, match="Invalid CIDR expression.*test.yml"):
        SigmaCIDRModifier(dummy_detection_item, [], SigmaRuleLocation("test.yml")).modify(SigmaString("192.168.1.1/24"))
