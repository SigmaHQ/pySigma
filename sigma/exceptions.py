class SigmaError(ValueError):
    pass

class SigmaLogsourceError(SigmaError):
    pass

class SigmaDetectionError(SigmaError):
    pass

class SigmaConditionError(SigmaError):
    pass

class SigmaIdentifierError(SigmaError):
    pass

class SigmaDateError(SigmaError):
    pass

class SigmaStatusError(SigmaError):
    pass

class SigmaLevelError(SigmaError):
    pass