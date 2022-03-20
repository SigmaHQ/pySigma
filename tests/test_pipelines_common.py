import pytest
from sigma.pipelines.common import logsource_linux_network_connection, logsource_windows, logsource_windows_dns_query, logsource_windows_file_change, logsource_windows_network_connection, logsource_windows_network_connection_initiated, logsource_windows_process_creation
from sigma.processing.conditions import LogsourceCondition, RuleContainsDetectionItemCondition

def test_logsource_windows():
    assert logsource_windows("security") == LogsourceCondition(
        product="windows",
        service="security",
    )

@pytest.mark.parametrize(
    ("func", "category", "product"), [
        (logsource_windows_process_creation, "process_creation", "windows"),
        (logsource_windows_file_change, "file_change", "windows"),
        (logsource_windows_network_connection, "network_connection", "windows"),
        (logsource_linux_network_connection, "network_connection", "linux"),
        (logsource_windows_dns_query, "dns_query", "windows"),
    ]
)
def test_generic_log_sources(func, category, product):
    assert func() == LogsourceCondition(category=category, product=product)

@pytest.mark.parametrize(
    ("initiated", "result"), [
        (True, "true"),
        (False, "false"),
    ]
)
def test_logsource_windows_network_connection_initiated(initiated, result):
    assert logsource_windows_network_connection_initiated(initiated) == RuleContainsDetectionItemCondition(
        field="Initiated",
        value=result,
    )
