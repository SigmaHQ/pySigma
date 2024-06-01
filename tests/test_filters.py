import pytest

from sigma.collection import SigmaCollection
from sigma.filters import SigmaFilter, SigmaGlobalFilter
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation
from sigma.rule import SigmaLogSource
from .test_conversion_base import test_backend


@pytest.fixture
def rule_collection():
    return SigmaCollection.from_yaml(
        """
title: Failed login
name: failed_login
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - EventID: 4625
        - EventID2: 4624
    condition: selection 
"""
    )


@pytest.fixture
def sigma_filter():
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
  condition: not selection
  """
    )


def test_filter_valid_1(sigma_filter):
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
            "condition": "not selection",
        }
    )


def test_basic_filter_application(sigma_filter, test_backend, rule_collection):
    rule_collection.rules += [sigma_filter]

    assert test_backend.convert(rule_collection) == [
        '(EventID=4625 or EventID2=4624) and not User startswith "adm_"'
    ]


def test_filter_with_field_mapping_against_it(sigma_filter, test_backend, rule_collection):
    rule_collection.rules += [sigma_filter]

    # Field Mapping
    test_backend.processing_pipeline.items.append(
        ProcessingItem(
            FieldMappingTransformation({"User": "User123"}),
            rule_conditions=[
                LogsourceCondition(**sigma_filter.logsource.to_dict()),
                # TODO: Add where the rule IDs match
            ],
        )
    )

    assert test_backend.convert(rule_collection) == [
        '(EventID=4625 or EventID2=4624) and not User123 startswith "adm_"'
    ]
