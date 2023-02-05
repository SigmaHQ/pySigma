from dataclasses import dataclass
from typing import ClassVar, Counter, List, Set, Type
from sigma.modifiers import SigmaAllModifier, SigmaBase64Modifier, SigmaBase64OffsetModifier, SigmaContainsModifier, SigmaModifier
from sigma.rule import SigmaDetectionItem
from sigma.validators.base import SigmaDetectionItemValidator, SigmaValidationIssue, SigmaValidationIssueSeverity

@dataclass
class AllWithoutContainsModifierIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A field-bound 'all' modifier without 'contains' modifier doesn't matches anything"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    detection_item: SigmaDetectionItem

@dataclass
class Base64OffsetWithoutContainsModifierIssue(SigmaValidationIssue):
    description: ClassVar[str] = "A 'base64offset' modifier must be followed by a 'contains' modifier, because calculated values will be prefixed/suffixed with further characters."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    detection_item: SigmaDetectionItem

@dataclass
class ModifierAppliedMultipleIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Modifiers shouldn't be applied multiple times"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    detection_item: SigmaDetectionItem
    modifiers: Set[Type[SigmaModifier]]

class InvalidModifierCombinationsValidator(SigmaDetectionItemValidator):
    """Detects invalid combinations of value modifiers."""
    def validate_detection_item(self, detection_item: SigmaDetectionItem) -> List[SigmaValidationIssue]:
        issues = []

        # Check for 'all' without 'contains' modifier
        if (
            detection_item.field is not None and
            SigmaAllModifier in detection_item.modifiers and
            SigmaContainsModifier not in detection_item.modifiers
        ):
            issues.append(AllWithoutContainsModifierIssue([ self.rule ], detection_item))

        # Check for 'base64offset' without 'contains' modifier
        if (
            SigmaBase64OffsetModifier in detection_item.modifiers and
            SigmaContainsModifier not in detection_item.modifiers
        ):
            issues.append(Base64OffsetWithoutContainsModifierIssue([ self.rule ], detection_item))

        # Check for multiple appliance of modifiers
        mod_count = Counter(detection_item.modifiers)
        multiple_modifiers = {
            mod
            for mod, count in mod_count.items()
            if (
                count > 1 and
                mod not in { SigmaBase64Modifier }      # allowlist
            )
        }
        if multiple_modifiers:
            issues.append(ModifierAppliedMultipleIssue([ self.rule ], detection_item, multiple_modifiers))

        return issues