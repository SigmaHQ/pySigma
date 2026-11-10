from dataclasses import dataclass
from typing import ClassVar, cast
from sigma.modifiers import (
    SigmaAllModifier,
    SigmaContainsModifier,
    SigmaEndswithModifier,
    SigmaStartswithModifier,
)
from sigma.rule import SigmaDetectionItem
from sigma.types import SigmaString, SigmaType, SpecialChars
from sigma.validators.base import (
    SigmaDetectionItemValidator,
    SigmaStringValueValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)


@dataclass
class DoubleWildcardIssue(SigmaValidationIssue):
    description: ClassVar[str] = "String contains multiple consecutive * wildcards"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    string: SigmaString


class DoubleWildcardValidator(SigmaStringValueValidator):
    """Check strings for consecutive multi-character wildcards."""

    def validate_string(self, value: SigmaString) -> list[SigmaValidationIssue]:
        prev_wildcard = False
        for c in value.s:
            if c == SpecialChars.WILDCARD_MULTI:
                if prev_wildcard:  # previous character was also a wildcard
                    return [DoubleWildcardIssue([self.rule], value)]
                else:
                    prev_wildcard = True
            else:
                prev_wildcard = False
        return []


@dataclass
class NumberAsStringIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A number was expressed as string"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    string: SigmaString


class NumberAsStringValidator(SigmaStringValueValidator):
    """Check numbers that were expressed as strings."""

    def validate_string(self, value: SigmaString) -> list[SigmaValidationIssue]:
        if len(value.s) == 1 and isinstance(value.s[0], str) and not " " in value.s[0]:
            try:
                int(value.s[0])
                return [NumberAsStringIssue([self.rule], value)]
            except ValueError:
                pass
        return []


@dataclass
class ControlCharacterIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "String contains control character likely caused by missing (double-)slash"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    string: SigmaString


class ControlCharacterValidator(SigmaStringValueValidator):
    """
    Check for control characters in string values, which are normally inserted unintentionally by
    wrong usage of single backslashes, e.g. before a t character, where double backslashes are required.
    """

    def validate_string(self, value: SigmaString) -> list[SigmaValidationIssue]:
        if any((ord(c) < 32 for s in value.s for c in (s if isinstance(s, str) else ""))):
            return [ControlCharacterIssue([self.rule], value)]
        else:
            return []


@dataclass
class WildcardsInsteadOfContainsModifierIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "String contains wildcards at beginning and end instead of being modified with contains modifier"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    detection_item: SigmaDetectionItem


@dataclass
class WildcardInsteadOfStartswithIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "String contains wildcard at end instead of being modified with startswith modifier"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    detection_item: SigmaDetectionItem


@dataclass
class WildcardInsteadOfEndswithIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "String contains wildcard at beginning instead of being modified with endswith modifier"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    detection_item: SigmaDetectionItem


class WildcardsInsteadOfModifiersValidator(SigmaDetectionItemValidator):
    """Check if wildcards were used where usage of startswith, endswith and contains modifiers would be possible."""

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> list[SigmaValidationIssue]:
        # Warning rule use a single '*' waiting for the `exists` modifier  so check len(value)>1 to allow it
        if (
            detection_item.original_value is not None
            and all(
                (
                    isinstance(value, SigmaString)
                    and len(value) > 1
                    and value.startswith(SpecialChars.WILDCARD_MULTI)
                    and value.endswith(SpecialChars.WILDCARD_MULTI)
                    and not value[1:-1].contains_special()
                    for value in detection_item.original_value
                )
            )
            and SigmaContainsModifier not in detection_item.modifiers
        ):
            return [WildcardsInsteadOfContainsModifierIssue([self.rule], detection_item)]
        elif (
            detection_item.original_value is not None
            and all(
                (
                    isinstance(value, SigmaString)
                    and len(value) > 1
                    and value.startswith(SpecialChars.WILDCARD_MULTI)
                    and not value[1:].contains_special()
                    for value in detection_item.original_value
                )
            )
            and SigmaEndswithModifier not in detection_item.modifiers
        ):
            return [WildcardInsteadOfEndswithIssue([self.rule], detection_item)]
        elif (
            detection_item.original_value is not None
            and all(
                (
                    isinstance(value, SigmaString)
                    and len(value) > 1
                    and value.endswith(SpecialChars.WILDCARD_MULTI)
                    and not value[:-1].contains_special()
                    for value in detection_item.original_value
                )
            )
            and SigmaStartswithModifier not in detection_item.modifiers
        ):
            return [WildcardInsteadOfStartswithIssue([self.rule], detection_item)]
        else:
            return []


@dataclass
class EscapedWildcardIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule contains an escaped wildcard in the rule logic. Make sure the escape is intentional."
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    string: SigmaString


class EscapedWildcardValidator(SigmaStringValueValidator):
    """Check for the presence of escaped wildcards."""

    wildcard_list = ["*", "?"]

    def validate_string(self, value: SigmaString) -> list[SigmaValidationIssue]:
        if any([x in s for x in self.wildcard_list for s in value.s if isinstance(s, str)]):
            return [EscapedWildcardIssue([self.rule], value)]
        else:
            return []


@dataclass
class TautologicalValueIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "String with contains, startswith or endswith modifier is empty or, with the contains "
        "modifier, reduces to a single path separator, which matches (almost) every value"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    detection_item: SigmaDetectionItem


class TautologicalValueValidator(SigmaDetectionItemValidator):
    """
    Check for strings that match (almost) every value of a field because they are empty or,
    with the ``contains`` modifier, reduce to a single path separator.

    Sigma string parsing collapses escape sequences, e.g. two backslashes in a YAML rule denote
    a single literal backslash. A ``contains`` modifier with such a value matches every value
    containing a backslash, which for path-like fields is every value. The same problem occurs
    with an empty value, which matches everything regardless of the modifier.

    A lone separator is not reported for ``startswith`` and ``endswith``: these modifiers only
    anchor the match at the beginning or end of the value (e.g. ``startswith: '\\'`` matches
    values starting with a backslash), so the value remains selective.

    Detection items with the ``all`` modifier are not reported: all values have to match, so a
    value that matches (almost) everything does not turn the whole detection item into a
    tautology.
    """

    separators = ("\\", "/")
    tautological_modifiers = (
        SigmaContainsModifier,
        SigmaStartswithModifier,
        SigmaEndswithModifier,
    )

    def validate_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> list[SigmaValidationIssue]:
        if SigmaAllModifier in detection_item.modifiers or not any(
            modifier in self.tautological_modifiers for modifier in detection_item.modifiers
        ):
            return []

        # The modifiers add wildcards around the values, therefore the values stored in
        # original_value are inspected whenever possible.
        values = (
            detection_item.original_value
            if detection_item.original_value is not None
            else detection_item.value
        )
        # A lone separator only makes the match (almost) universal with contains. With
        # startswith and endswith it merely anchors the value at one end.
        single_separator_is_tautological = SigmaContainsModifier in detection_item.modifiers
        for value in values:
            # Values containing wildcards or placeholders are not plain strings and are
            # covered by other validators.
            if not isinstance(value, SigmaString) or any(not isinstance(c, str) for c in value.s):
                continue

            literal = "".join(cast(list[str], value.s))
            if literal == "" or (
                single_separator_is_tautological
                and len(literal) == 1
                and literal in self.separators
            ):
                return [TautologicalValueIssue([self.rule], detection_item)]

        return []
