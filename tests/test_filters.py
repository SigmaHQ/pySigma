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
    rule_collection.apply_filters([sigma_filter])

    assert test_backend.convert(rule_collection) == [
        '(EventID=4625 or EventID2=4624) and not User startswith "adm_"'
    ]


def test_basic_filter_application_against_correlation_rule(
    sigma_filter, test_backend, event_count_correlation_rule
):
    event_count_correlation_rule.apply_filters([sigma_filter])

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

    rule_collection.rules.append(rule_copy)
    rule_collection.apply_filters([sigma_filter])

    assert (
        test_backend.convert(rule_collection)
        == ['(EventID=4625 or EventID2=4624) and not User startswith "adm_"'] * 2
    )


def test_filter_with_field_mapping_against_it(sigma_filter, test_backend, rule_collection):
    rule_collection.apply_filters([sigma_filter])

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

    assert len(rule_collection.rules) == 1
    assert len(rule_collection.filters) == 1

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

    assert len(rule_collection.rules) == 1
    assert len(rule_collection.filters) == 2

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
    rule_collection.apply_filters([sigma_filter])

    assert len(rule_collection.rules) == 6

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
    rule_collection.rules[0].id = "invalid-id"
    rule_collection.apply_filters([sigma_filter])

    assert test_backend.convert(rule_collection) == ["EventID=4625 or EventID2=4624"]


def test_no_rules_section(sigma_filter, test_backend, rule_collection):
    # When rules field is None or empty, filter should apply to all rules matching the logsource
    sigma_filter.filter.rules = None
    rule_collection.apply_filters([sigma_filter])

    assert test_backend.convert(rule_collection) == [
        '(EventID=4625 or EventID2=4624) and not User startswith "adm_"'
    ]


def test_filter_without_rules_field_applies_to_all_matching_logsource(test_backend):
    # Test that a filter without a rules field applies to all rules with matching logsource
    filter_yaml = """
title: Filter Administrator account
description: Filters all process creation events
logsource:
    category: process_creation
    product: windows
filter:
  selection:
      User|startswith: 'adm_'
  condition: not selection
"""

    rules_yaml = """
title: Rule 1
id: 11111111-1111-1111-1111-111111111111
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
---
title: Rule 2
id: 22222222-2222-2222-2222-222222222222
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
---
title: Rule 3 - Different logsource
id: 33333333-3333-3333-3333-333333333333
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 443
    condition: selection
"""

    sigma_filter = SigmaFilter.from_yaml(filter_yaml)
    rule_collection = SigmaCollection.from_yaml(rules_yaml)
    rule_collection.apply_filters([sigma_filter])

    result = test_backend.convert(rule_collection)

    # First two rules should have filter applied (matching logsource)
    assert result[0] == 'EventID=4688 and not User startswith "adm_"'
    assert result[1] == 'CommandLine contains "test" and not User startswith "adm_"'
    # Third rule should not have filter applied (different logsource)
    assert result[2] == "DestinationPort=443"


def test_filter_without_rules_field_partial_logsource_matching(test_backend):
    # Test partial logsource matching - filter with fewer attributes matches rules with more attributes
    filter_yaml = """
title: Filter all Windows events
description: Filters all windows events regardless of category
logsource:
    product: windows
filter:
  selection:
      User|startswith: 'SYSTEM'
  condition: not selection
"""

    rules_yaml = """
title: Process Creation Rule
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 4688
    condition: selection
---
title: Network Connection Rule
id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 443
    condition: selection
---
title: Linux Process Rule - Different product
id: cccccccc-cccc-cccc-cccc-cccccccccccc
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        EventID: 1
    condition: selection
"""

    sigma_filter = SigmaFilter.from_yaml(filter_yaml)
    rule_collection = SigmaCollection.from_yaml(rules_yaml)
    rule_collection.apply_filters([sigma_filter])

    result = test_backend.convert(rule_collection)

    # First two rules should have filter applied (both have product: windows)
    assert result[0] == 'EventID=4688 and not User startswith "SYSTEM"'
    assert result[1] == 'DestinationPort=443 and not User startswith "SYSTEM"'
    # Third rule should not have filter applied (different product)
    assert result[2] == "EventID=1"


def test_filter_without_rules_field_more_specific_logsource_no_match(test_backend):
    # Test that filter with MORE specific logsource does NOT match rules with less specific logsource
    filter_yaml = """
title: Filter specific process creation
description: Only applies to process_creation category with security service
logsource:
    category: process_creation
    product: windows
    service: security
filter:
  selection:
      User|startswith: 'admin'
  condition: not selection
"""

    rules_yaml = """
title: Rule with matching logsource
id: dddddddd-dddd-dddd-dddd-dddddddddddd
logsource:
    category: process_creation
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
    condition: selection
---
title: Rule with less specific logsource - no service
id: eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: test.exe
    condition: selection
"""

    sigma_filter = SigmaFilter.from_yaml(filter_yaml)
    rule_collection = SigmaCollection.from_yaml(rules_yaml)
    rule_collection.apply_filters([sigma_filter])

    result = test_backend.convert(rule_collection)

    # First rule should have filter applied (exact match)
    assert result[0] == 'EventID=4688 and not User startswith "admin"'
    # Second rule should NOT have filter applied (filter is more specific)
    assert result[1] == 'CommandLine="test.exe"'


def test_filter_without_rules_field_excludes_correlation_rules(test_backend):
    # Test that filters without rules field do not apply to correlation rules
    # This test uses the event_count_correlation_rule pattern but with matching logsource
    filter_yaml = """
title: Filter test events
description: Should not apply to correlation rules but should apply to base rules
logsource:
    category: process_creation
    product: windows
filter:
  selection:
      User: admin
  condition: not selection
"""

    rules_yaml = """
title: Failed logon
name: failed_logon
id: ffffffff-ffff-ffff-ffff-ffffffffffff
status: test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        EventID: 4625
    condition: selection
---
title: Multiple failed logons for a single user
status: test
correlation:
    type: event_count
    rules:
        - failed_logon
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 10
"""

    sigma_filter = SigmaFilter.from_yaml(filter_yaml)
    rule_collection = SigmaCollection.from_yaml(rules_yaml)
    rule_collection.apply_filters([sigma_filter])

    result = test_backend.convert(rule_collection)

    # Should return correlation rule output which includes the base rule with filter applied
    # The correlation rule itself shouldn't have the filter applied to its correlation logic
    assert len(result) == 1
    assert 'EventID=4625 and not User="admin"' in result[0]
    # Verify correlation logic is present
    assert 'aggregate window=5min' in result[0]


def test_filter_with_empty_rules_list_behaves_like_no_rules_field(test_backend):
    # Test that explicitly setting rules=[] behaves the same as omitting rules field
    filter_yaml = """
title: Filter with empty rules list
description: Empty rules list should match all rules with matching logsource
logsource:
    product: windows
filter:
  rules: []
  selection:
      User: admin
  condition: not selection
"""

    rules_yaml = """
title: Test Rule
id: 12345678-1234-1234-1234-123456789012
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 1
    condition: selection
"""

    sigma_filter = SigmaFilter.from_yaml(filter_yaml)
    rule_collection = SigmaCollection.from_yaml(rules_yaml)
    rule_collection.apply_filters([sigma_filter])

    result = test_backend.convert(rule_collection)

    # Filter should apply since rules=[] should behave like no rules field
    assert result[0] == 'EventID=1 and not User="admin"'


# Validation Errors
@pytest.mark.parametrize(
    "transformation,error",
    [
        [lambda sf: sf.pop("logsource", None), SigmaLogsourceError],
        [lambda sf: sf.pop("filter", None), SigmaFilterError],
        [lambda sf: sf.pop("title", None), SigmaTitleError],
        [lambda sf: sf["filter"].pop("condition", None), SigmaFilterConditionError],
        [lambda sf: sf["filter"].pop("selection", None), SigmaDetectionError],
        # Set the value to None
        [lambda sf: sf.update({"logsource": None}), SigmaLogsourceError],
        [lambda sf: sf.update({"filter": None}), SigmaFilterError],
        [lambda sf: sf.update({"title": None}), SigmaTitleError],
        [lambda sf: sf["filter"].update({"condition": None}), SigmaFilterConditionError],
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


def test_filter_exact_matching(rule_collection, test_backend, sigma_filter):
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
def test_filter_exact_matching_brackets(
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


@pytest.mark.skip("Decision on whether filters should support selection confusion is pending")
def test_filter_selection_confusion(rule_collection, test_backend, sigma_filter):
    """
    This test targets a weird quirk of how we do Filtering, where the filter can just use a
    selection condition as a filter condition. It's probably not desired behaviour, as you'd
    rarely want to filter on a selection condition, and it implies that every rule referenced
    also has to have a selection condition.
    """
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
