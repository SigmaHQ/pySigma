from dataclasses import dataclass
import string
from typing import ClassVar, List
from sigma.types import SigmaString, SpecialChars
from sigma.validation import SigmaStringValueValidator, SigmaValidationIssue, SigmaValidationIssueSeverity


@dataclass
class DoubleWildcardIssue(SigmaValidationIssue):
    description: ClassVar[str] = "String contains multiple consecutive * wildcards"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.LOW
    string : SigmaString

class DoubleWildcardValidator(SigmaStringValueValidator):
    """
    Check strings for consecutive multi-character wildcards *.
    """
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
    """
    Check numbers that were expressed as strings.
    """
    def validate_value(self, value: SigmaString) -> List[SigmaValidationIssue]:
        if len(value.s) == 1 and isinstance(value.s[0], str):
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