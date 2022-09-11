import re
from typing import Dict
import sigma
from .condition import DanglingDetectionValidator
from .metadata import IdentifierExistenceValidator, IdentifierUniquenessValidator
from .modifiers import InvalidModifierCombinationsValidator
from .tags import TLPTagValidator, TLPv1TagValidator, TLPv2TagValidator, ATTACKTagValidator
from .values import (
    DoubleWildcardValidator,
    NumberAsStringValidator,
    ControlCharacterValidator,
    WildcardsInsteadOfModifiersValidator,
)

validators: Dict[str, "sigma.validation.SigmaRuleValidator"] = {
    re.sub("([A-Z]+)", "_\\1", name.replace("Validator", ""))[1:].lower(): cls    # NameOfSomeCheckValidator -> name_of_some_check
    for name, cls in globals().items()
    if name.endswith("Validator")
}