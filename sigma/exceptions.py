from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from pyparsing import List


@dataclass
class SigmaRuleLocation:
    """Describes a Sigma source file and optionally a location inside it."""

    path: Path
    line: Optional[int] = None
    char: Optional[int] = None

    def __post_init__(self):
        if isinstance(self.path, str):
            self.path = Path(self.path)

    def __str__(self):
        s = str(self.path.resolve())
        if self.line is not None:
            s += ":" + str(self.line)
            if self.char is not None:
                s += ":" + str(self.char)
        return s


class SigmaError(ValueError):
    """Generic Sigma error and super-class of all Sigma exceptions"""

    def __init__(self, *args, **kwargs):
        try:
            self.source = kwargs["source"]
            del kwargs["source"]
        except KeyError:
            self.source = None
        super().__init__(*args, **kwargs)

    def __str__(self):
        if self.source is not None:
            return super().__str__() + " in " + str(self.source)
        else:
            return super().__str__()

    def __eq__(self, other: object) -> bool:
        try:
            return (
                type(self) is type(other)
                and self.source == other.source
                and self.args == other.args
            )
        except AttributeError:
            return False


class SigmaTitleError(SigmaError):
    """Error in Sigma rule logosurce specification"""

    pass


class SigmaLogsourceError(SigmaError):
    """Error in Sigma rule logosurce specification"""

    pass


class SigmaDetectionError(SigmaError):
    """Error in Sigma rule detection"""

    pass


class SigmaConditionError(SigmaError):
    """Error in Sigma rule condition"""

    pass


class SigmaIdentifierError(SigmaError):
    """Error in Sigma rule identifier"""

    pass


class SigmaAuthorError(SigmaError):
    """Error in Sigma rule author"""

    pass


class SigmaRelatedError(SigmaError):
    """Error in Sigma rule related"""

    pass


class SigmaDateError(SigmaError):
    """Error in Sigma rule date"""

    pass


class SigmaModifiedError(SigmaError):
    """Error in Sigma rule modified"""

    pass


class SigmaDescriptionError(SigmaError):
    """Error in Sigma rule description"""

    pass


class SigmaFieldsError(SigmaError):
    """Error in Sigma rule fields"""

    pass


class SigmaFalsePositivesError(SigmaError):
    """Error in Sigma rule falsepositives"""

    pass


class SigmaStatusError(SigmaError):
    """Error in Sigma rule status"""

    pass


class SigmaLevelError(SigmaError):
    """Error in Sigma rule level"""

    pass


class SigmaModifierError(SigmaError):
    """Error in Sigma rule value modifier specification"""

    pass


class SigmaTypeError(SigmaModifierError):
    """Sigma modifier not applicable on value type"""

    pass


class SigmaValueError(SigmaError):
    """Error in Sigma rule value"""

    pass


class SigmaRegularExpressionError(SigmaValueError):
    """Error in regular expression contained in Sigma rule"""

    pass


class SigmaPlaceholderError(SigmaValueError):
    """Attempted to convert an unhandled Placeholder into a query"""

    pass


class SigmaCollectionError(SigmaError):
    """Error in Sigma collection, e.g. unknown action"""

    pass


class SigmaConfigurationError(SigmaError):
    """Error in configuration of a Sigma processing pipeline"""

    pass


class SigmaFeatureNotSupportedByBackendError(SigmaError):
    """Sigma feature is not supported by the backend."""

    pass


class SigmaPipelineNotFoundError(SigmaError, ValueError):
    """An attempt to resolve a processing pipeline from a specifier failed because it was not
    found."""

    def __init__(self, spec: str, *args, **kwargs):
        self.spec = spec
        super().__init__(*args, **kwargs)

    def __str__(self):
        return f"Processing pipeline '{self.spec}' not found"


class SigmaPipelineNotAllowedForBackendError(SigmaConfigurationError):
    """One or multiple processing pipelines doesn't matches the given backend."""

    def __init__(self, spec: str, backend: str, *args, **kwargs):
        self.wrong_pipeline = spec
        self.backend = backend
        super().__init__(*args, **kwargs)

    def __str__(self):
        return (
            f"Processing pipelines not allowed for backend '{self.backend}': {self.wrong_pipeline}"
        )


class SigmaTransformationError(SigmaError):
    """Error while transformation. Can be raised intentionally by FailureTransformation."""


class SigmaPluginNotFoundError(SigmaError):
    """Plugin was not found."""
