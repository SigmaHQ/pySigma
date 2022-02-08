from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredTextQueryExpression
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionOR
from sigma.types import SigmaCompareExpression
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from typing import ClassVar, Dict, List, Tuple

class SplunkDeferredRegularExpression(DeferredTextQueryExpression):
    template = 'regex {field}{op}"{value}"'
    operators = {
        True: "!=",
        False: "=",
    }
    default_field = "_raw"

class SplunkDeferredCIDRExpression(DeferredTextQueryExpression):
    template = 'where {op}cidrmatch("{value}", {field})'
    operators = {
        True: "NOT ",
        False: "",
    }
    default_field = "_raw"

class SplunkBackend(TextQueryBackend):
    """Splunk SPL backend."""
    group_expression : ClassVar[str] = "({expr})"

    or_token : ClassVar[str] = "OR"
    and_token : ClassVar[str] = " "
    not_token : ClassVar[str] = "NOT"
    eq_token : ClassVar[str] = "="

    str_quote : ClassVar[str] = '"'
    escape_char : ClassVar[str] = "\\"
    wildcard_multi : ClassVar[str] = "*"
    wildcard_single : ClassVar[str] = "*"

    re_expression : ClassVar[str] = "{regex}"
    re_escape_char : ClassVar[str] = "\\"
    re_escape : ClassVar[Tuple[str]] = ('"',)

    cidr_expression : ClassVar[str] = "{value}"

    compare_op_expression : ClassVar[str] = "{field}{operator}{value}"
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    field_null_expression : ClassVar[str] = "{field}!=*"

    field_in_list_expression : ClassVar[str] = "{field} IN ({list})"
    list_separator : ClassVar[str] = ", "

    unbound_value_str_expression : ClassVar[str] = '"*{value}*"'
    unbound_value_num_expression : ClassVar[str] = '*{value}*'
    unbound_value_re_expression : ClassVar[str] = '{value}'

    deferred_start : ClassVar[str] = "\n| "
    deferred_separator : ClassVar[str] = "\n| "
    deferred_only_query : ClassVar[str] = "*"

    def convert_condition_field_eq_val_re(self, cond : ConditionFieldEqualsValueExpression, state : "sigma.conversion.state.ConversionState") -> SplunkDeferredRegularExpression:
        """Defer regular expression matching to pipelined regex command after main search expression."""
        if cond.parent_condition_chain_contains(ConditionOR):
            raise SigmaFeatureNotSupportedByBackendError("ORing regular expressions is not yet supported by Splunk backend")
        return SplunkDeferredRegularExpression(state, cond.field, super().convert_condition_field_eq_val_re(cond, state)).postprocess(None, cond)

    def convert_condition_field_eq_val_cidr(self, cond : ConditionFieldEqualsValueExpression, state : "sigma.conversion.state.ConversionState") -> SplunkDeferredCIDRExpression:
        """Defer CIDR network range matching to pipelined where cidrmatch command after main search expression."""
        if cond.parent_condition_chain_contains(ConditionOR):
            raise SigmaFeatureNotSupportedByBackendError("ORing CIDR matching is not yet supported by Splunk backend")
        return SplunkDeferredCIDRExpression(state, cond.field, super().convert_condition_field_eq_val_cidr(cond, state)).postprocess(None, cond)

    def finalize_query_savedsearches(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        clean_title = rule.title.translate({ord(c): None for c in "[]"})      # remove brackets from title
        escaped_query = " \\\n".join(query.split("\n"))      # escape line ends for multiline queries
        return f"""
[{clean_title}]
search = {escaped_query}"""

    def finalize_output_savedsearches(self, queries: List[str]) -> str:
        return """
[default]
dispatch.earliest_time = -30d
dispatch.latest_time = now
""" + "\n".join(queries)