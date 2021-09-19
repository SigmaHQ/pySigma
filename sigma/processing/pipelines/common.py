from sigma.processing.conditions import LogsourceCondition

def logsource_windows_process_creation() -> LogsourceCondition:
    return LogsourceCondition(
        category="process_creation",
        product="windows",
    )