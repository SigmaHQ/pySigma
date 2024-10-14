from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import sigma


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


class SigmaValueError(SigmaError):
    """Error in Sigma rule value"""

    pass


class SigmaBackendError(SigmaError):
    """Error in Sigma backend."""

    pass


class SigmaCollectionError(SigmaError):
    """Error in Sigma collection, e.g. unknown action"""

    pass


class SigmaConditionError(SigmaError):
    """Error in Sigma rule condition"""

    pass


class SigmaConfigurationError(SigmaError):
    """Error in configuration of a Sigma processing pipeline"""

    pass


class SigmaConversionError(SigmaError):
    """Rule conversion failed."""

    def __init__(self, rule: "sigma.rule.SigmaRuleBase", *args, **kwargs):
        self.rule = rule
        super().__init__(*args, **kwargs)

    def __str__(self):
        return super().__str__() + " in rule " + str(self.rule)


class SigmaDetectionError(SigmaError):
    """Error in Sigma rule detection"""

    pass


class SigmaFeatureNotSupportedByBackendError(SigmaError):
    """Sigma feature is not supported by the backend."""

    pass


class SigmaModifierError(SigmaError):
    """Error in Sigma rule value modifier"""

    pass


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


class SigmaPipelineNotFoundError(SigmaError, ValueError):
    """An attempt to resolve a processing pipeline from a specifier failed because it was not
    found."""

    def __init__(self, spec: str, *args, **kwargs):
        self.spec = spec
        super().__init__(*args, **kwargs)

    def __str__(self):
        return f"Processing pipeline '{self.spec}' not found"


class SigmaPipelineParsingError(SigmaError):
    """Error in parsing of a Sigma processing pipeline"""

    pass


class SigmaPlaceholderError(SigmaValueError):
    """Attempted to convert an unhandled Placeholder into a query"""

    pass


class SigmaPluginNotFoundError(SigmaError):
    """Plugin was not found."""

    pass


class SigmaRegularExpressionError(SigmaValueError):
    """Error in regular expression contained in Sigma rule"""

    pass


class SigmaTransformationError(SigmaError):
    """Error while transformation. Can be raised intentionally by FailureTransformation."""

    pass


class SigmaTypeError(SigmaModifierError):
    """Sigma modifier not applicable on value type"""

    pass


class SigmaValidatorConfigurationParsingError(SigmaError):
    """Error in parsing of a Sigma validation configuration file."""

    pass


# Meta Rule Correlation Error


class SigmaCorrelationRuleError(SigmaValueError):
    """Error in Sigma correlation rule."""

    pass


class SigmaCorrelationConditionError(SigmaCorrelationRuleError):
    """Error in Sigma correlation condition."""

    pass


class SigmaCorrelationTypeError(SigmaCorrelationRuleError):
    """Wrong Sigma correlation type."""

    pass


class SigmaTimespanError(SigmaCorrelationRuleError):
    """Raised when the timespan for calculating sigma is invalid."""

    pass


class SigmaRuleNotFoundError(SigmaCorrelationRuleError):
    """Sigma rule not found."""

    pass


# Meta Filter Error


class SigmaFilterError(SigmaValueError):
    """Error in Sigma rule filter"""

    pass


class SigmaFilterConditionError(SigmaFilterError):
    """Error in Sigma rule filter condition"""

    pass


class SigmaFilterRuleReferenceError(SigmaFilterError):
    """Error in Sigma rule filter condition"""

    pass


# Rule Fields error


class SigmaAuthorError(SigmaError):
    """Error in Sigma rule author"""

    pass


class SigmaDateError(SigmaError):
    """Error in Sigma rule date"""

    pass


class SigmaDescriptionError(SigmaError):
    """Error in Sigma rule description"""

    pass


class SigmaFalsePositivesError(SigmaError):
    """Error in Sigma rule falsepositives field"""

    pass


class SigmaFieldsError(SigmaError):
    """Error in Sigma rule fields field"""

    pass


class SigmaIdentifierError(SigmaError):
    """Error in Sigma rule identifier"""

    pass


class SigmaLevelError(SigmaError):
    """Error in Sigma rule level"""

    pass


class SigmaLicenseError(SigmaError):
    """Error in Sigma rule license"""

    pass


class SigmaLogsourceError(SigmaError):
    """Error in Sigma rule logsource"""

    pass


class SigmaModifiedError(SigmaError):
    """Error in Sigma rule modified field"""

    pass


class SigmaNameError(SigmaError):
    """Error in Sigma rule name"""

    pass


class SigmaReferencesError(SigmaError):
    """Error in Sigma rule references"""

    pass


class SigmaRelatedError(SigmaError):
    """Error in Sigma rule related field"""

    pass


class SigmaScopeError(SigmaError):
    """Error in Sigma rule scope"""

    pass


class SigmaStatusError(SigmaError):
    """Error in Sigma rule status"""

    pass


class SigmaTitleError(SigmaError):
    """Error in Sigma rule title"""

    pass


@dataclass
class ExceptionOnUsage:
    """Raise an exception when the class is used."""

    exception: Exception

    def __getattribute__(self, item):
        raise object.__getattribute__(self, "exception")
