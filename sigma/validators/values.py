from dataclasses import dataclass
import string
from typing import ClassVar, List
from sigma.modifiers import SigmaContainsModifier, SigmaEndswithModifier, SigmaStartswithModifier
from sigma.rule import SigmaDetectionItem
from sigma.types import SigmaString, SpecialChars
from sigma.validators.base import SigmaDetectionItemValidator, SigmaStringValueValidator, SigmaValidationIssue, SigmaValidationIssueSeverity

@dataclass
class DoubleWildcardIssue(SigmaValidationIssue):
    description: ClassVar[str] = "String contains multiple consecutive * wildcards"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    string : SigmaString

class DoubleWildcardValidator(SigmaStringValueValidator):
    """Check strings for consecutive multi-character wildcards."""
    def validate_value(self, value: SigmaString) -> List[SigmaValidationIssue]:
        prev_wildcard = False
        for c in value.s:
            if c == SpecialChars.WILDCARD_MULTI:
                if prev_wildcard:       # previous character was also a wildcard
                    return [ DoubleWildcardIssue([ self.rule ], value) ]
                else:
                    prev_wildcard = True
            else:
                prev_wildcard = False
        return []

@dataclass
class NumberAsStringIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A number was expressed as string"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    string : SigmaString

class NumberAsStringValidator(SigmaStringValueValidator):
    """Check numbers that were expressed as strings."""
    def validate_value(self, value: SigmaString) -> List[SigmaValidationIssue]:
        if len(value.s) == 1 and isinstance(value.s[0], str) and not " " in value.s[0]:
            try:
                int(value.s[0])
                return [ NumberAsStringIssue(self.rule, value) ]
            except ValueError:
                pass
        return []

@dataclass
class ControlCharacterIssue(SigmaValidationIssue):
    description: ClassVar[str] = "String contains control character likely caused by missing (double-)slash"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    string : SigmaString

class ControlCharacterValidator(SigmaStringValueValidator):
    """
    Check for control characters in string values, which are normally inserted unintentionally by
    wrong usage of single backslashes, e.g. before a t character, where double backslashes are required.
    """
    def validate_value(self, value: SigmaString) -> List[SigmaValidationIssue]:
        if any((
            ord(c) < 31
            for s in value.s
            for c in (
                s if isinstance(s, str)
                else ""
            )
        )):
            return [ ControlCharacterIssue([ self.rule ], value) ]
        else:
            return []

@dataclass
class WildcardsInsteadOfContainsModifierIssue(SigmaValidationIssue):
    description: ClassVar[str] = "String contains wildcards at beginning and end instead of being modified with contains modifier"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    detection_item: SigmaDetectionItem

@dataclass
class WildcardInsteadOfStartswithIssue(SigmaValidationIssue):
    description: ClassVar[str] = "String contains wildcard at end instead of being modified with startswith modifier"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    detection_item: SigmaDetectionItem

@dataclass
class WildcardInsteadOfEndswithIssue(SigmaValidationIssue):
    description: ClassVar[str] = "String contains wildcard at beginning instead of being modified with endswith modifier"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    detection_item: SigmaDetectionItem

class WildcardsInsteadOfModifiersValidator(SigmaDetectionItemValidator):
    """Check if wildcards were used where usage of startswith, endswith and contains modifiers would be possible."""
    def validate_detection_item(self, detection_item: SigmaDetectionItem) -> List[SigmaValidationIssue]:
        # Warning rule use a single '*' waiting for the `exists` modifier  so check len(value)>1 to allow it
        if all((
            isinstance(value, SigmaString) and
            len(value)>1 and 
            value.startswith(SpecialChars.WILDCARD_MULTI) and
            value.endswith(SpecialChars.WILDCARD_MULTI) and
            not value[1:-1].contains_special()
            for value in detection_item.original_value
        )) and SigmaContainsModifier not in detection_item.modifiers:
            return [ WildcardsInsteadOfContainsModifierIssue([ self.rule ], detection_item) ]
        elif all((
            isinstance(value, SigmaString) and
            len(value)>1 and
            value.startswith(SpecialChars.WILDCARD_MULTI) and
            not value[1:].contains_special()
            for value in detection_item.original_value
        )) and SigmaEndswithModifier not in detection_item.modifiers:
            return [ WildcardInsteadOfEndswithIssue([ self.rule ], detection_item) ]
        elif all((
            isinstance(value, SigmaString) and
            len(value)>1 and 
            value.endswith(SpecialChars.WILDCARD_MULTI) and
            not value[:-1].contains_special()
            for value in detection_item.original_value
        )) and SigmaStartswithModifier not in detection_item.modifiers:
            return [ WildcardInsteadOfStartswithIssue([ self.rule ], detection_item) ]
        else:
            return []