from uuid import UUID
import pytest
from sigma.exceptions import SigmaValueError
from sigma.rule import SigmaDetectionItem, SigmaLogSource, SigmaRule
from sigma.types import SigmaString
from .test_correlations import correlation_rule


from sigma.modifiers import (
    SigmaAllModifier,
    SigmaBase64OffsetModifier,
    SigmaContainsModifier,
)

from sigma.validators.core.modifiers import (
    AllWithoutContainsModifierIssue,
    Base64OffsetWithoutContainsModifierIssue,
    InvalidModifierCombinationsValidator,
    ModifierAppliedMultipleIssue,
)


def test_validator_all_without_contains():
    validator = InvalidModifierCombinationsValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field|all:
                - value1
                - value2
                - value3
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        AllWithoutContainsModifierIssue(
            [rule],
            SigmaDetectionItem(
                "field",
                [SigmaAllModifier],
                [SigmaString("value1"), SigmaString("value2"), SigmaString("value3")],
            ),
        )
    ]


def test_validator_all_without_contains_unbound():
    validator = InvalidModifierCombinationsValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            "|all":
                - value1
                - value2
                - value3
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_all_with_contains():
    validator = InvalidModifierCombinationsValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field|contains|all:
                - value1
                - value2
                - value3
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_base64offset_without_contains_modifier():
    validator = InvalidModifierCombinationsValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field|base64offset: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        Base64OffsetWithoutContainsModifierIssue(
            [rule], SigmaDetectionItem("field", [SigmaBase64OffsetModifier], [SigmaString("value")])
        )
    ]


def test_validator_invalid_modifier_combination_correlation_rule(correlation_rule):
    validator = InvalidModifierCombinationsValidator()
    assert validator.validate(correlation_rule) == []


def test_validator_base64offset_after_contains_modifier():
    with pytest.raises(SigmaValueError, match="strings with wildcards"):
        rule = SigmaRule.from_yaml(
            """
        title: Test
        status: test
        logsource:
            category: test
        detection:
            sel:
                field|contains|base64offset: value
            condition: sel
        """
        )


def test_validator_base64offset_with_contains_modifier():
    validator = InvalidModifierCombinationsValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field|base64offset|contains: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_multiple_modifier():
    validator = InvalidModifierCombinationsValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field|base64offset|base64offset|contains|contains: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        ModifierAppliedMultipleIssue(
            [rule],
            SigmaDetectionItem(
                "field",
                [
                    SigmaBase64OffsetModifier,
                    SigmaBase64OffsetModifier,
                    SigmaContainsModifier,
                    SigmaContainsModifier,
                ],
                [SigmaString("value")],
            ),
            {SigmaBase64OffsetModifier, SigmaContainsModifier},
        )
    ]


def test_validator_multiple_base64_modifier():
    validator = InvalidModifierCombinationsValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field|base64|base64: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_windowsdash_combined_with_all_modifier():
    """Test that windash combined with all modifier is allowed (no longer raises an error)."""
    validator = InvalidModifierCombinationsValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field|contains|windash|all:
                - value1
                - value2
        condition: sel
    """
    )
    # windash+all is now allowed because SigmaExpansion correctly preserves grouping
    assert validator.validate(rule) == []
