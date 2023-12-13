from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from .test_conversion_base import test_backend


def test_event_count_correlation(test_backend):
    rule_collection = SigmaCollection.from_yaml(
        """
title: Failed logon
name: failed_logon
status: test
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons
status: test
correlation:
    type: event_count
    rules:
        - failed_logon
    group-by:
        - TargetUserName
        - TargetDomainName
    timespan: 5m
    condition:
        gte: 10
            """
    )
    assert test_backend.convert(rule_collection) == [
        "EventID=4625\n| aggregate window=5min count() as event_count by TargetUserName, TargetDomainName\n| where event_count >= 10"
    ]
