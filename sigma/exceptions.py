class SigmaError(ValueError):
    """Generic Sigma error and super-class of all Sigma exceptions"""
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

class SigmaDateError(SigmaError):
    """Error in Sigma rule date"""
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

class SigmaCollectionError(SigmaError):
    """Error in Sigma collection, e.g. unknown action"""
    pass

class SigmaConfigurationError(SigmaError):
    """Error in configuration of a Sigma processing pipeline"""
    pass

class SigmaFeatureNotSupportedByBackendError(SigmaError):
    """Sigma feature is not supported by the backend."""
    pass

class SigmaTransformationError(SigmaError):
    """Error while transformation. Can be raised intentionally by FailureTransformation."""