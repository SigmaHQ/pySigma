import pytest
from sigma.collection import SigmaCollection
from sigma.correlations import (
    SigmaCorrelationCondition,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationFieldAliases,
    SigmaCorrelationRule,
    SigmaCorrelationTimespan,
    SigmaCorrelationType,
    SigmaRuleReference,
)
from sigma.exceptions import (
    SigmaCorrelationConditionError,
    SigmaCorrelationRuleError,
    SigmaCorrelationTypeError,
    SigmaRuleNotFoundError,
    SigmaTimespanError,
)
from sigma.filters import SigmaFilter, SigmaGlobalFilter
from sigma.rule import SigmaLogSource


@pytest.fixture
def rule_collection():
    return SigmaCollection.from_yaml(
        """
title: Failed login
name: failed_login
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
        """
    )


@pytest.fixture
def meta_filter():
    return SigmaFilter.from_yaml(
        """
title: Filter Administrator account
description: The valid administrator account start with adm_
logsource:
    category: process_creation
    product: windows
global_filter:
  rules:
    - 6f3e2987-db24-4c78-a860-b4f4095a7095 # Data Compressed - rar.exe
    - df0841c0-9846-4e9f-ad8a-7df91571771b # Login on jump host
  selection:
      User|startswith: 'adm_'
  condition: selection
  """
    )


def test_filter_valid_1(meta_filter):
    sigma_filter = meta_filter
    assert isinstance(sigma_filter, SigmaFilter)
    assert sigma_filter.title == "Filter Administrator account"
    assert sigma_filter.description == "The valid administrator account start with adm_"
    assert sigma_filter.logsource == SigmaLogSource.from_dict(
        {"category": "process_creation", "product": "windows"}
    )
    assert sigma_filter.global_filter == SigmaGlobalFilter.from_dict(
        {
            "rules": [
                "6f3e2987-db24-4c78-a860-b4f4095a7095",
                "df0841c0-9846-4e9f-ad8a-7df91571771b",
            ],
            "selection": {"User|startswith": "adm_"},
            "condition": "selection",
        }
    )
