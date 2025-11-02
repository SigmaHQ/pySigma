from collections import defaultdict
import re
from typing import Any, ClassVar, Optional, Pattern, cast

from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.pipelines.test import dummy_test_pipeline
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.rule.rule import SigmaRule
from sigma.types import CompareOperators


class TextQueryTestBackend(TextQueryBackend):
    name: ClassVar[str] = "Test backend"
    formats: ClassVar[dict[str, str]] = {
        "default": "Default format",
        "test": "Dummy test format",
        "state": "Test format that obtains information from state",
        "list_of_dict": "List of Dict",
        "str": "Plain string",
        "bytes": "Plain query as bytes",
    }

    group_expression: ClassVar[str] = "({expr})"

    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"
    eq_token: ClassVar[str] = "="

    field_quote: ClassVar[str] = "'"
    field_quote_pattern: ClassVar[Pattern[str]] = re.compile("^\\w+$")

    str_quote: ClassVar[str] = '"'
    escape_char: ClassVar[str] = "\\"
    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "?"
    add_escaped: ClassVar[str] = ":"
    filter_chars: ClassVar[str] = "&"
    bool_values: ClassVar[dict[bool, Optional[str]]] = {
        True: "1",
        False: "0",
    }

    startswith_expression: ClassVar[str] = "{field} startswith {value}"
    endswith_expression: ClassVar[str] = "{field} endswith {value}"
    contains_expression: ClassVar[str] = "{field} contains {value}"
    wildcard_match_expression: ClassVar[str] = "{field} match {value}"

    field_exists_expression: ClassVar[str] = "exists({field})"
    field_not_exists_expression: ClassVar[str] = "notexists({field})"

    re_expression: ClassVar[str] = "{field}=/{regex}/"
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[list[str]] = ["/", "bar"]

    case_sensitive_match_expression = "{field} casematch {value}"
    case_sensitive_startswith_expression: ClassVar[str] = "{field} startswith_cased {value}"
    case_sensitive_endswith_expression: ClassVar[str] = "{field} endswith_cased {value}"
    case_sensitive_contains_expression: ClassVar[str] = "{field} contains_cased {value}"

    cidr_expression: ClassVar[str] = "cidrmatch('{field}', \"{value}\")"

    compare_op_expression: ClassVar[str] = "{field}{operator}{value}"
    compare_operators: ClassVar[dict[CompareOperators, str]] = {
        CompareOperators.LT: "<",
        CompareOperators.LTE: "<=",
        CompareOperators.GT: ">",
        CompareOperators.GTE: ">=",
        CompareOperators.NEQ: "!=",
    }

    field_equals_field_expression: ClassVar[str] = "{field1}=fieldref({field2})"
    field_equals_field_startswith_expression: ClassVar[str] = (
        "{field1}=fieldref_startswith({field2})"
    )
    field_equals_field_endswith_expression: ClassVar[str] = "{field1}=fieldref_endswith({field2})"
    field_equals_field_contains_expression: ClassVar[str] = "{field1}=fieldref_contains({field2})"

    field_null_expression: ClassVar[str] = "{field} is null"

    convert_or_as_in: ClassVar[bool] = True
    convert_and_as_in: ClassVar[bool] = True
    in_expressions_allow_wildcards: ClassVar[bool] = True
    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"
    or_in_operator: ClassVar[Optional[str]] = "in"
    and_in_operator: ClassVar[Optional[str]] = "contains-all"
    list_separator: ClassVar[str] = ", "

    unbound_value_str_expression: ClassVar[str] = "_={value}"
    unbound_value_num_expression: ClassVar[str] = "_={value}"
    unbound_value_re_expression: ClassVar[str] = "_=/{value}/"

    deferred_start: ClassVar[str] = " | "
    deferred_separator: ClassVar[str] = " | "
    deferred_only_query: ClassVar[str] = "*"

    backend_processing_pipeline = dummy_test_pipeline()
    output_format_processing_pipeline = defaultdict(
        ProcessingPipeline,
        test=ProcessingPipeline(
            [
                ProcessingItem(
                    FieldMappingTransformation(
                        {
                            "fieldC": "mappedC",
                        }
                    )
                )
            ]
        ),
    )

    # Correlations
    correlation_methods: ClassVar[dict[str, str]] = {
        "test": "Test correlation method",
    }
    default_correlation_method: ClassVar[str] = "test"
    default_correlation_query: ClassVar[dict[str, str]] = {
        "test": "{search}\n{aggregate}\n{condition}"
    }
    temporal_correlation_query: ClassVar[dict[str, str]] = {
        "test": "{search}\n\n{aggregate}\n\n{condition}"
    }

    correlation_search_single_rule_expression: ClassVar[str] = "{query}"
    correlation_search_multi_rule_expression: ClassVar[str] = "{queries}"
    correlation_search_multi_rule_query_expression: ClassVar[str] = (
        'subsearch {{ {query} | set event_type="{ruleid}"{normalization} }}'
    )
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = "\n"

    correlation_search_field_normalization_expression: ClassVar[str] = " | set {alias}={field}"
    correlation_search_field_normalization_expression_joiner: ClassVar[str] = ""

    event_count_aggregation_expression: ClassVar[dict[str, str]] = {
        "test": "| aggregate window={timespan} count() as event_count{groupby}"
    }
    value_count_aggregation_expression: ClassVar[dict[str, str]] = {
        "test": "| aggregate window={timespan} value_count({field}) as value_count{groupby}"
    }
    temporal_aggregation_expression: ClassVar[dict[str, str]] = {
        "test": "| temporal window={timespan} eventtypes={referenced_rules}{groupby}"
    }
    temporal_ordered_aggregation_expression: ClassVar[dict[str, str]] = {
        "test": "| temporal ordered=true window={timespan} eventtypes={referenced_rules}{groupby}"
    }
    value_sum_aggregation_expression: ClassVar[dict[str, str]] = {
        "test": "| aggregate window={timespan} sum({field}) as value_sum{groupby}"
    }
    value_avg_aggregation_expression: ClassVar[dict[str, str]] = {
        "test": "| aggregate window={timespan} avg({field}) as value_avg{groupby}"
    }
    value_percentile_aggregation_expression: ClassVar[dict[str, str]] = {
        "test": "| aggregate window={timespan} percentile({field}, {percentile}) as value_percentile{groupby}"
    }
    value_median_aggregation_expression: ClassVar[dict[str, str]] = {
        "test": "| aggregate window={timespan} median({field}) as value_median{groupby}"
    }

    timespan_mapping: ClassVar[dict[str, str]] = {
        "m": "min",
    }
    referenced_rules_expression: ClassVar[dict[str, str]] = {"test": "{ruleid}"}
    referenced_rules_expression_joiner: ClassVar[dict[str, str]] = {"test": ","}

    groupby_expression: ClassVar[dict[str, str]] = {"test": " by {fields}"}
    groupby_field_expression: ClassVar[dict[str, str]] = {"test": "{field}"}
    groupby_field_expression_joiner: ClassVar[dict[str, str]] = {"test": ", "}

    event_count_condition_expression: ClassVar[dict[str, str]] = {
        "test": "| where event_count {op} {count}"
    }
    value_count_condition_expression: ClassVar[dict[str, str]] = {
        "test": "| where value_count {op} {count}"
    }
    temporal_condition_expression: ClassVar[dict[str, str]] = {
        "test": "| where eventtype_count {op} {count}"
    }
    temporal_ordered_condition_expression: ClassVar[dict[str, str]] = {
        "test": "| where eventtype_count {op} {count} and eventtype_order={referenced_rules}"
    }
    value_sum_condition_expression: ClassVar[dict[str, str]] = {
        "test": "| where value_sum {op} {count}"
    }
    value_avg_condition_expression: ClassVar[dict[str, str]] = {
        "test": "| where value_avg {op} {count}"
    }
    value_percentile_condition_expression: ClassVar[dict[str, str]] = {
        "test": "| where value_percentile {op} {count}"
    }
    value_median_condition_expression: ClassVar[dict[str, str]] = {
        "test": "| where value_median {op} {count}"
    }

    def __init__(
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        collect_errors: bool = False,
        testparam: Optional[str] = None,
        **kwargs: dict[str, Any],
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.testparam = testparam

    def finalize_query_test(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        return "[ " + cast(str, self.finalize_query_default(rule, query, index, state)) + " ]"

    def finalize_output_test(self, queries: list[str]) -> str:
        return cast(str, self.finalize_output_default(queries))

    def finalize_query_state(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        return (
            "index="
            + cast(str, state.processing_state.get("index", "default"))
            + " ("
            + cast(str, self.finalize_query_default(rule, query, index, state))
            + ")"
        )

    def finalize_output_state(self, queries: list[str]) -> str:
        return cast(str, self.finalize_output_default(queries))

    def finalize_query_list_of_dict(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        return cast(str, self.finalize_query_default(rule, query, index, state))

    def finalize_output_list_of_dict(self, queries: list[str]) -> list[dict[str, Optional[str]]]:
        return [
            (
                {"query": query, "test": self.testparam}
                if self.testparam is not None
                else {"query": query}
            )
            for query in self.finalize_output_default(queries)
        ]

    def finalize_query_bytes(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        return cast(str, self.finalize_query_default(rule, query, index, state))

    def finalize_output_bytes(self, queries: list[str]) -> bytes:
        return bytes("\x00".join(self.finalize_output_default(queries)), "utf-8")

    def finalize_query_str(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        return cast(str, self.finalize_query_default(rule, query, index, state))

    def finalize_output_str(self, queries: list[str]) -> str:
        return "\n".join(self.finalize_output_default(queries))


class MandatoryPipelineTestBackend(TextQueryTestBackend):
    requires_pipeline: ClassVar[bool] = True
