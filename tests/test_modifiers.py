import pytest
from typing import Union, Sequence, List
from sigma.modifiers import SigmaModifier, SigmaContainsModifier, SigmaStartswithModifier, SigmaEndswithModifier, SigmaBase64Modifier, SigmaBase64OffsetModifier, SigmaWideModifier
from sigma.types import SigmaString, SigmaNumber, SigmaRegularExpression
from sigma.exceptions import SigmaTypeError, SigmaValueError

@pytest.fixture
def dummy_plain_modifier():
    class DummyPlainModifier(SigmaModifier):
        def modify(self, val : SigmaString) -> SigmaString:
            return SigmaString("")
    return DummyPlainModifier()

@pytest.fixture
def dummy_union_modifier():
    class DummyUnionModifier(SigmaModifier):
        def modify(self, val : Union[SigmaString, SigmaNumber]) -> SigmaString:
            return SigmaString("")
    return DummyUnionModifier()

@pytest.fixture
def dummy_sequence_modifier():
    class DummySequenceModifier(SigmaModifier):
        def modify(self, val : Sequence[SigmaString]) -> List[SigmaString]:
            return [ SigmaString("") ]
    return DummySequenceModifier()

def test_typecheck_plain(dummy_plain_modifier):
    assert dummy_plain_modifier.type_check(SigmaString("foobar"))

def test_typecheck_plain_wrong(dummy_plain_modifier):
    assert not dummy_plain_modifier.type_check(SigmaNumber(123))

def test_typecheck_plain_wrong_apply(dummy_plain_modifier):
    with pytest.raises(SigmaTypeError):
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

def test_contains_nowildcards():
    assert SigmaContainsModifier().apply(SigmaString("foobar")) == [ SigmaString("*foobar*") ]

def test_contains_leading_wildcard():
    assert SigmaContainsModifier().apply(SigmaString("*foobar")) == [ SigmaString("*foobar*") ]

def test_contains_trailing_wildcard():
    assert SigmaContainsModifier().apply(SigmaString("foobar*")) == [ SigmaString("*foobar*") ]

def test_contains_leading_and_trailing_wildcard():
    assert SigmaContainsModifier().apply(SigmaString("*foobar*")) == [ SigmaString("*foobar*") ]

def test_startswith_nowildcards():
    assert SigmaStartswithModifier().apply(SigmaString("foobar")) == [ SigmaString("foobar*") ]

def test_startswith_trailing_wildcard():
    assert SigmaStartswithModifier().apply(SigmaString("foobar*")) == [ SigmaString("foobar*") ]

def test_endswith_nowildcards():
    assert SigmaEndswithModifier().apply(SigmaString("foobar")) == [ SigmaString("*foobar") ]

def test_endswith_trailing_wildcard():
    assert SigmaEndswithModifier().apply(SigmaString("*foobar")) == [ SigmaString("*foobar") ]

def test_base64():
    assert SigmaBase64Modifier().apply(SigmaString("foobar")) == [ SigmaString("Zm9vYmFy") ]

def test_base64_wildcards():
    with pytest.raises(SigmaValueError):
        SigmaBase64Modifier().apply(SigmaString("foo*bar"))

def test_base64offset():
    assert SigmaBase64OffsetModifier().apply(SigmaString("foobar")) == [
        SigmaString("Zm9vYmFy"),
        SigmaString("Zvb2Jhc"),
        SigmaString("mb29iYX")
        ]

def test_base64offset_wildcards():
    with pytest.raises(SigmaValueError):
        SigmaBase64OffsetModifier().apply(SigmaString("foo*bar"))

def test_wide():
    assert SigmaWideModifier().apply(SigmaString("foobar")) == [ SigmaString("f\x00o\x00o\x00b\x00a\x00r\x00") ]

def test_wide_noascii():
    with pytest.raises(SigmaValueError):
        SigmaWideModifier().apply(SigmaString("foobär"))