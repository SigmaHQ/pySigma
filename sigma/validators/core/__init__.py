from importlib import import_module
from pathlib import Path
from pkgutil import iter_modules
from inspect import getmembers, isabstract, isclass
import re

from sigma.validators.base import SigmaRuleValidator


def validator_classname_to_identifier(name: str) -> str:
    """Convert a validator class name (e.g. NameOfSomeCheckValidator) to an identifier (e.g. name_of_some_check)."""
    return re.sub("([A-Z]+)", "_\\1", name.replace("Validator", ""))[1:].lower()


validators = {
    validator_classname_to_identifier(name): cls
    for _, submodule, _ in iter_modules(
        [str(Path(__file__).resolve().parent)]
    )  # Iterate over modules, str around Path is due to issue with PosixPath from Python 3.10
    for name, cls in getmembers(
        import_module(__name__ + "." + submodule), isclass
    )  # Iterate over classes
    if not isabstract(cls)
    and name.endswith("Validator")
    and issubclass(cls, SigmaRuleValidator)  # Class filtering
}
