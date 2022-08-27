from dataclasses import dataclass
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