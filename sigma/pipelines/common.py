from sigma.processing.conditions import LogsourceCondition, RuleContainsDetectionItemCondition

def logsource_windows(service : str) -> LogsourceCondition:
    return LogsourceCondition(
        product="windows",
        service=service,
    )

def logsource_windows_process_creation() -> LogsourceCondition:
    return LogsourceCondition(
        category="process_creation",
        product="windows",
    )

def logsource_windows_registry_add():
    return LogsourceCondition(
        category="registry_add",
        product="windows",
    )

def logsource_windows_registry_set():
    return LogsourceCondition(
        category="registry_set",
        product="windows",
    )

def logsource_windows_registry_delete():
    return LogsourceCondition(
        category="registry_delete",
        product="windows",
    )

def logsource_windows_registry_event():
    return LogsourceCondition(
        category="registry_event",
        product="windows",
    )

def logsource_windows_file_change() -> LogsourceCondition:
    return LogsourceCondition(
        category="file_change",
        product="windows",
    )

def logsource_windows_file_event():
    return LogsourceCondition(
        category="file_event",
        product="windows",
    )

def logsource_windows_network_connection() -> LogsourceCondition:
    return LogsourceCondition(
        category="network_connection",
        product="windows",
    )

def logsource_windows_network_connection_initiated(initiated : bool) -> RuleContainsDetectionItemCondition:
    return RuleContainsDetectionItemCondition(
        field="Initiated",
        value="true" if initiated else "false",
    )

def logsource_windows_dns_query() -> LogsourceCondition:
    return LogsourceCondition(
        category="dns_query",
        product="windows",
    )

def logsource_linux_process_creation():
    return LogsourceCondition(
        category="process_creation",
        product="linux",
    )

def logsource_linux_network_connection() -> LogsourceCondition:
    return LogsourceCondition(
        category="network_connection",
        product="linux",
    )