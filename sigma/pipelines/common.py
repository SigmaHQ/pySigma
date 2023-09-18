from typing import List
from sigma.processing.conditions import (
    LogsourceCondition,
    RuleContainsDetectionItemCondition,
)
from sigma.processing.pipeline import ProcessingItem
from sigma.processing.transformations import AddConditionTransformation

windows_logsource_mapping = {  # Mapping between Sigma log source services and Windows event log channel names
    "security": "Security",
    "application": "Application",
    "system": "System",
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "powershell": [
        "Microsoft-Windows-PowerShell/Operational",
        "PowerShellCore/Operational",
    ],
    "powershell-classic": "Windows PowerShell",
    "taskscheduler": "Microsoft-Windows-TaskScheduler/Operational",
    "wmi": "Microsoft-Windows-WMI-Activity/Operational",
    "dns-server": "DNS Server",
    "dns-server-audit": "Microsoft-Windows-DNS-Server/Audit",
    "dns-server-analytic": "Microsoft-Windows-DNS-Server/Analytical",
    "driver-framework": "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    "ntlm": "Microsoft-Windows-NTLM/Operational",
    "dhcp": "Microsoft-Windows-DHCP-Server/Operational",
    "msexchange-management": "MSExchange Management",
    "applocker": [
        "Microsoft-Windows-AppLocker/MSI and Script",
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/Packaged app-Deployment",
        "Microsoft-Windows-AppLocker/Packaged app-Execution",
    ],
    "printservice-admin": "Microsoft-Windows-PrintService/Admin",
    "printservice-operational": "Microsoft-Windows-PrintService/Operational",
    "codeintegrity-operational": "Microsoft-Windows-CodeIntegrity/Operational",
    "smbclient-security": "Microsoft-Windows-SmbClient/Security",
    "firewall-as": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "bits-client": "Microsoft-Windows-Bits-Client/Operational",
    "windefend": "Microsoft-Windows-Windows Defender/Operational",
    "terminalservices-localsessionmanager": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "microsoft-servicebus-client": "Microsoft-ServiceBus-Client",
    "ldap_debug": "Microsoft-Windows-LDAP-Client/Debug",
    "security-mitigations": [
        "Microsoft-Windows-Security-Mitigations/Kernel Mode",
        "Microsoft-Windows-Security-Mitigations/User Mode",
    ],
    "diagnosis-scripted": "Microsoft-Windows-Diagnosis-Scripted/Operational",
    "shell-core": "Microsoft-Windows-Shell-Core/Operational",
    "openssh": "OpenSSH/Operational",
    "bitlocker": "Microsoft-Windows-BitLocker/BitLocker Management",
    "vhdmp": "Microsoft-Windows-VHDMP/Operational",
    "appxdeployment-server": "Microsoft-Windows-AppXDeploymentServer/Operational",
    "lsa-server": "Microsoft-Windows-LSA/Operational",
    "appxpackaging-om": "Microsoft-Windows-AppxPackaging/Operational",
    "dns-client": "Microsoft-Windows-DNS Client Events/Operational",
    "appmodel-runtime": "Microsoft-Windows-AppModel-Runtime/Admin",
    "capi2": "Microsoft-Windows-CAPI2/Operational",
    "certificateservicesclient-lifecycle-system": "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
}


def logsource_windows(service: str) -> LogsourceCondition:
    return LogsourceCondition(
        product="windows",
        service=service,
    )


def logsource_linux(service: str) -> LogsourceCondition:
    return LogsourceCondition(
        product="linux",
        service=service,
    )


def logsource_macos(service: str) -> LogsourceCondition:
    return LogsourceCondition(
        product="macos",
        service=service,
    )


def logsource_category(category: str) -> LogsourceCondition:
    return LogsourceCondition(
        category=category,
    )


def logsource_windows_process_creation() -> LogsourceCondition:
    return LogsourceCondition(
        category="process_creation",
        product="windows",
    )


def logsource_windows_registry_add() -> LogsourceCondition:
    return LogsourceCondition(
        category="registry_add",
        product="windows",
    )


def logsource_windows_registry_set() -> LogsourceCondition:
    return LogsourceCondition(
        category="registry_set",
        product="windows",
    )


def logsource_windows_registry_delete() -> LogsourceCondition:
    return LogsourceCondition(
        category="registry_delete",
        product="windows",
    )


def logsource_windows_registry_event() -> LogsourceCondition:
    return LogsourceCondition(
        category="registry_event",
        product="windows",
    )


def logsource_windows_file_change() -> LogsourceCondition:
    return LogsourceCondition(
        category="file_change",
        product="windows",
    )


def logsource_windows_file_event() -> LogsourceCondition:
    return LogsourceCondition(
        category="file_event",
        product="windows",
    )


def logsource_windows_file_delete() -> LogsourceCondition:
    return LogsourceCondition(
        category="file_delete",
        product="windows",
    )


def logsource_windows_file_access() -> LogsourceCondition:
    return LogsourceCondition(
        category="file_access",
        product="windows",
    )


def logsource_windows_file_rename() -> LogsourceCondition:
    return LogsourceCondition(
        category="file_rename",
        product="windows",
    )


def logsource_windows_image_load() -> LogsourceCondition:
    return LogsourceCondition(
        category="image_load",
        product="windows",
    )


def logsource_windows_pipe_created() -> LogsourceCondition:
    return LogsourceCondition(
        category="pipe_created",
        product="windows",
    )


def logsource_windows_ps_classic_start() -> LogsourceCondition:
    return LogsourceCondition(
        category="ps_classic_start",
        product="windows",
    )


def logsource_windows_ps_module() -> LogsourceCondition:
    return LogsourceCondition(
        category="ps_module",
        product="windows",
    )


def logsource_windows_ps_script() -> LogsourceCondition:
    return LogsourceCondition(
        category="ps_script",
        product="windows",
    )


def logsource_windows_process_access() -> LogsourceCondition:
    return LogsourceCondition(
        category="process_access",
        product="windows",
    )


def logsource_windows_raw_access_thread() -> LogsourceCondition:
    return LogsourceCondition(
        category="raw_access_thread",
        product="windows",
    )


def logsource_windows_wmi_event() -> LogsourceCondition:
    return LogsourceCondition(
        category="wmi_event",
        product="windows",
    )


def logsource_windows_driver_load() -> LogsourceCondition:
    return LogsourceCondition(
        category="driver_load",
        product="windows",
    )


def logsource_windows_create_stream_hash() -> LogsourceCondition:
    return LogsourceCondition(
        category="create_stream_hash",
        product="windows",
    )


def logsource_windows_create_remote_thread() -> LogsourceCondition:
    return LogsourceCondition(
        category="create_remote_thread",
        product="windows",
    )


def logsource_windows_network_connection() -> LogsourceCondition:
    return LogsourceCondition(
        category="network_connection",
        product="windows",
    )


def logsource_windows_network_connection_initiated(
    initiated: bool,
) -> RuleContainsDetectionItemCondition:
    return RuleContainsDetectionItemCondition(
        field="Initiated",
        value="true" if initiated else "false",
    )


def logsource_windows_dns_query() -> LogsourceCondition:
    return LogsourceCondition(
        category="dns_query",
        product="windows",
    )


def logsource_linux_process_creation() -> LogsourceCondition:
    return LogsourceCondition(
        category="process_creation",
        product="linux",
    )


def logsource_linux_network_connection() -> LogsourceCondition:
    return LogsourceCondition(
        category="network_connection",
        product="linux",
    )


def logsource_linux_file_create() -> LogsourceCondition:
    return LogsourceCondition(
        category="file_create",
        product="linux",
    )


def logsource_macos_process_creation() -> LogsourceCondition:
    return LogsourceCondition(
        category="process_creation",
        product="macos",
    )


def logsource_macos_file_create() -> LogsourceCondition:
    return LogsourceCondition(
        category="file_create",
        product="macos",
    )


def logsource_azure_riskdetection() -> LogsourceCondition:
    return LogsourceCondition(
        category="riskdetection",
        product="azure",
    )


def logsource_azure_pim() -> LogsourceCondition:
    return LogsourceCondition(
        category="pim",
        product="azure",
    )


def logsource_azure_auditlogs() -> LogsourceCondition:
    return LogsourceCondition(
        category="auditlogs",
        product="azure",
    )


def logsource_azure_azureactivity() -> LogsourceCondition:
    return LogsourceCondition(
        category="azureactivity",
        product="azure",
    )


def logsource_azure_signinlogs() -> LogsourceCondition:
    return LogsourceCondition(
        category="signinlogs",
        product="azure",
    )


def generate_windows_logsource_items(
    cond_field_template: str,
    cond_value_template: str,
    identifier_template: str = "windows_logsource_{service}",
) -> List[ProcessingItem]:
    """Generate processing items for all Windows logsource mappings from templates. All templates
    are defined as Python f-string ("{variable}"). Available variables in each template are:

    * service: Sigma log source definition field 'service'. Example: security
    * source: Windows log source name. Example: Microsoft-Windows-Sysmon/Operational

    :param cond_field_template: Template for field name used in added condition. Usually some static
        field name.
    :type cond_field_template: str
    :param cond_value_template: Template for value used in added condition. Usually contains source name.
    :type cond_value_template: str
    :param identifier_template: Template for processing item identifier. Usually, the defaults are
        fine. Should contain service placeholder if changed.
    :type identifier_template: str
    :return: List of ProcessingItem that can be used in the items attribute of a ProcessingPipeline
        object. Usually, an additional field name mapping between the Sigma taxonomy and the target
        system field names is required.
    :rtype: List[ProcessingItem]
    """
    return [
        ProcessingItem(
            identifier=identifier_template.format(service=service, source=source),
            transformation=(
                AddConditionTransformation(
                    {  # source is list
                        cond_field_template.format(service=service, source=source): [
                            cond_value_template.format(service=service, source=source_item)
                            for source_item in source
                        ]
                    }
                )
                if isinstance(source, list)
                else AddConditionTransformation(
                    {  # source is plain string
                        cond_field_template.format(
                            service=service, source=source
                        ): cond_value_template.format(service=service, source=source)
                    }
                )
            ),
            rule_conditions=[logsource_windows(service)],
        )
        for service, source in windows_logsource_mapping.items()
    ]
