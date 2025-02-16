import copy
import uuid
from pathlib import Path
from typing import Callable

import pytest

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaRuleReference
from sigma.exceptions import (
    SigmaLogsourceError,
    SigmaDetectionError,
    SigmaTitleError,
    SigmaFilterConditionError,
    SigmaFilterError,
    SigmaFilterRuleReferenceError,
    SigmaConditionError,
)
from sigma.filters import SigmaFilter, SigmaGlobalFilter
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation
from sigma.rule import SigmaLogSource
from .test_conversion_base import test_backend


@pytest.fixture
def sigma_filter():
    return SigmaFilter.from_yaml(
        """
title: Filter Administrator account
description: The valid administrator account start with adm_
logsource:
    category: process_creation
    product: windows
filter:
  rules:
    - 6f3e2987-db24-4c78-a860-b4f4095a7095 # Data Compressed - rar.exe
    - df0841c0-9846-4e9f-ad8a-7df91571771b # Login on jump host
  selection:
      User|startswith: 'adm_'
  condition: not selection
  """
    )


@pytest.fixture
def rule_collection():
    return SigmaCollection.from_yaml(
        """
title: Failed login
id: 6f3e2987-db24-4c78-a860-b4f4095a7095
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
def event_count_correlation_rule():
    return SigmaCollection.from_yaml(
        """
title: Failed logon
name: failed_logon
id: df0841c0-9846-4e9f-ad8a-7df91571771b
status: test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons for a single user (possible brute force attack)
status: test
correlation:
    type: event_count
    rules:
        - failed_logon
    group-by:
        - TargetUserName
        - TargetDomainName
        - fieldB
    timespan: 5m
    condition:
        gte: 10
            """
    )


def test_filter_valid(sigma_filter):
    assert isinstance(sigma_filter, SigmaFilter)
    assert sigma_filter.title == "Filter Administrator account"
    assert sigma_filter.description == "The valid administrator account start with adm_"
    assert sigma_filter.logsource == SigmaLogSource.from_dict(
        {"category": "process_creation", "product": "windows"}
    )
    assert sigma_filter.filter == SigmaGlobalFilter.from_dict(
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


def test_basic_filter_application_against_correlation_rule(
    sigma_filter, test_backend, event_count_correlation_rule
):
    event_count_correlation_rule.rules += [sigma_filter]

    assert test_backend.convert(event_count_correlation_rule) == [
        'EventID=4625 and not User startswith "adm_"\n'
        "| aggregate window=5min count() as event_count by TargetUserName, "
        "TargetDomainName, mappedB\n"
        "| where event_count >= 10"
    ]


def test_filter_application_to_several_rules(sigma_filter, test_backend, rule_collection):
    rule_copy = copy.deepcopy(rule_collection.rules[0])
    rule_copy.id = uuid.UUID("257f7780-ea6c-48d4-ae8e-2b95b3740d84")
    sigma_filter.filter.rules.append(SigmaRuleReference(str(rule_copy.id)))

    rule_collection.rules.extend([rule_copy, sigma_filter])

    assert (
        test_backend.convert(rule_collection)
        == ['(EventID=4625 or EventID2=4624) and not User startswith "adm_"'] * 2
    )


def test_reducing_rule_collections(sigma_filter, test_backend, rule_collection):
    rule_collection.rules += [sigma_filter]

    assert len(rule_collection.rules) == 2

    # Applies / Flattens all the filters onto the rules in processing
    rule_collection.resolve_rule_references()

    assert len(rule_collection.rules) == 1


def test_filter_with_field_mapping_against_it(sigma_filter, test_backend, rule_collection):
    rule_collection.rules += [sigma_filter]

    # Field Mapping
    test_backend.processing_pipeline.items.append(
        ProcessingItem(
            FieldMappingTransformation({"User": "User123"}),
            rule_conditions=[
                LogsourceCondition(**sigma_filter.logsource.to_dict()),
            ],
        )
    )

    assert test_backend.convert(rule_collection) == [
        '(EventID=4625 or EventID2=4624) and not User123 startswith "adm_"'
    ]


def test_filter_sigma_collection_from_files(test_backend):
    rule_collection = SigmaCollection.load_ruleset(
        [Path("tests/files/rule_valid"), Path("tests/files/filter_valid")]
    )

    assert len(rule_collection.rules) == 2

    assert test_backend.convert(rule_collection) == [
        'EventID=1234 and not ComputerName startswith "DC-"'
    ]


def test_filter_sigma_collection_from_files_duplicated(test_backend):
    rule_collection = SigmaCollection.load_ruleset(
        [
            Path("tests/files/rule_valid"),
            Path("tests/files/filter_valid"),
            Path("tests/files/filter_valid"),
        ]
    )

    assert len(rule_collection.rules) == 3

    assert test_backend.convert(rule_collection) == [
        'EventID=1234 and not ComputerName startswith "DC-" and not ComputerName startswith "DC-"'
    ]


def test_filter_sigma_collection_from_ruleset(sigma_filter, test_backend):
    rule_collection = SigmaCollection.load_ruleset(
        [
            Path("tests/files/correlation_rule_valid"),
        ]
    )

    sigma_filter = SigmaFilter.from_dict(
        {**sigma_filter.to_dict(), **{"logsource": {"category": "test"}}}
    )
    sigma_filter.filter.rules.append(SigmaRuleReference("5d8fd9da-6916-45ef-8d4d-3fa9d19d1a64"))
    rule_collection.rules += [sigma_filter]

    assert len(rule_collection.rules) == 7

    assert test_backend.convert(rule_collection) == [
        'mappedA="value1" and mappedB="value2" and not User startswith "adm_"\n'
        "| aggregate window=15min count() as event_count by fieldC, fieldD\n"
        "| where event_count >= 10",
        'mappedA="value1" and mappedB="value2" and not User startswith "adm_"\n'
        "| aggregate window=15min value_count(fieldD) as value_count by fieldC\n"
        "| where value_count < 10",
        'subsearch { mappedA="value1" and mappedB="value2" | set '
        'event_type="base_rule_1" | set field=fieldC }\n'
        'subsearch { mappedA="value3" and mappedB="value4" | set '
        'event_type="base_rule_2" | set field=fieldD }\n'
        "\n"
        "| temporal window=15min eventtypes=base_rule_1,base_rule_2 by fieldC\n"
        "\n"
        "| where eventtype_count >= 2",
    ]


def test_invalid_rule_id_matching(sigma_filter, test_backend, rule_collection):
    # Change the rule id to something else
    rule_collection.rules += [sigma_filter]
    rule_collection.rules[0].id = "invalid-id"

    assert test_backend.convert(rule_collection) == ["EventID=4625 or EventID2=4624"]


def test_no_rules_section(sigma_filter, test_backend, rule_collection):
    rule_collection.rules += [sigma_filter]
    rule_collection.rules[1].filter.rules = None

    assert test_backend.convert(rule_collection) == ["EventID=4625 or EventID2=4624"]


# Validation Errors
@pytest.mark.parametrize(
    "transformation,error",
    [
        [lambda sf: sf.pop("logsource", None), SigmaLogsourceError],
        [lambda sf: sf.pop("filter", None), SigmaFilterError],
        [lambda sf: sf.pop("title", None), SigmaTitleError],
        [lambda sf: sf["filter"].pop("condition", None), SigmaFilterConditionError],
        [lambda sf: sf["filter"].pop("selection", None), SigmaDetectionError],
        [lambda sf: sf["filter"].pop("rules", None), SigmaFilterRuleReferenceError],
        # Set the value to None
        [lambda sf: sf.update({"logsource": None}), SigmaLogsourceError],
        [lambda sf: sf.update({"filter": None}), SigmaFilterError],
        [lambda sf: sf.update({"title": None}), SigmaTitleError],
        [lambda sf: sf["filter"].update({"condition": None}), SigmaFilterConditionError],
        [lambda sf: sf["filter"].update({"rules": None}), SigmaFilterRuleReferenceError],
    ],
)
def test_filter_validation_errors(transformation: Callable, error, sigma_filter):
    # Create a copy of the sigma_filter dictionary to avoid modifying the original
    sf_copy = sigma_filter.to_dict()

    # Apply the transformation to the copied dictionary
    transformation(sf_copy)

    with pytest.raises(error):
        SigmaFilter.from_dict(sf_copy)


def test_sigma_filter_with_multiple_conditions_raises_error(sigma_filter):
    # Create a copy of the sigma_filter dictionary to avoid modifying the original
    sf_copy = sigma_filter.to_dict()

    sf_copy["filter"]["condition"] = ["selection", "not selection"]

    with pytest.raises(SigmaFilterConditionError):
        SigmaFilter.from_dict(sf_copy)


def test_regression_github_issue_321(rule_collection, test_backend, sigma_filter):
    sigma_filter.filter = SigmaGlobalFilter.from_dict(
        {
            "rules": [
                "6f3e2987-db24-4c78-a860-b4f4095a7095",
            ],
            "filter": {"User|startswith": "adm_"},
            "condition": "not filter_with_suffix",
        }
    )

    rule_collection.rules += [sigma_filter]

    with pytest.raises(SigmaConditionError):
        test_backend.convert(rule_collection)


@pytest.mark.parametrize(
    "filter_condition",
    [
        "not filter",
        "not (filter)",
        "not ( filter)",
        "not (filter )",
        "not ( filter )",
        "not (   filter   )",
        "not ((filter))",
        "not (((filter)))",
    ],
)
def test_regression_github_issue_321_brackets(
    rule_collection, test_backend, sigma_filter, filter_condition
):
    sigma_filter.filter = SigmaGlobalFilter.from_dict(
        {
            "rules": [
                "6f3e2987-db24-4c78-a860-b4f4095a7095",
            ],
            "filter": {"User|startswith": "adm_"},
            "condition": filter_condition,
        }
    )

    rule_collection.rules += [sigma_filter]

    assert test_backend.convert(rule_collection) == [
        '(EventID=4625 or EventID2=4624) and not User startswith "adm_"'
    ]


def test_regression_github_issue_321_selection_confusion(rule_collection, test_backend, sigma_filter):
    sigma_filter.filter = SigmaGlobalFilter.from_dict(
        {
            "rules": [
                "6f3e2987-db24-4c78-a860-b4f4095a7095",
            ],
            "filter": {"User|startswith": "adm_"},
            "condition": "not selection",
        }
    )

    rule_collection.rules += [sigma_filter]

    assert test_backend.convert(rule_collection) == [
        '(EventID=4625 or EventID2=4624) and not User startswith "adm_"'
    ]