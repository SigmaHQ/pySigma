from sigma.processing.conditions import LogsourceCondition, RuleContainsDetectionItemCondition

windows_logsource_mapping = {       # Mapping between Sigma log source services and Windows event log channel names
    "security": "Security",
    "application": "Application",
    "system": "System",
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "powershell-classic": "Windows PowerShell",
    "taskscheduler": "Microsoft-Windows-TaskScheduler/Operational",
    "wmi": "Microsoft-Windows-WMI-Activity/Operational",
    "dns-server": "DNS Server",
    "dns-server-audit": "Microsoft-Windows-DNS-Server/Audit",
    "driver-framework": "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    "ntlm": "Microsoft-Windows-NTLM/Operational",
    "dhcp": "Microsoft-Windows-DHCP-Server/Operational",
    "msexchange-management": "MSExchange Management",
    "applocker": "Microsoft-Windows-AppLocker/EXE and DLL Management",
    "printservice-admin": "Microsoft-Windows-PrintService/Admin",
    "printservice-operational": "Microsoft-Windows-PrintService/Operational",
    "codeintegrity-operational": "Microsoft-Windows-CodeIntegrity/Operational",
    "smbclient-security": "Microsoft-Windows-SmbClient/Security",
    "firewall-as": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "bits-client": "Microsoft-Windows-Bits-Client/Operational",
    "windefend": "Microsoft-Windows-Windows Defender/Operational",
    "terminalservices-localsessionmanager": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "microsoft-servicebus-client": "Microsoft-ServiceBus-Client",
}

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