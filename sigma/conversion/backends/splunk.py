from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredTextQueryExpression
from sigma.conditions import ConditionFieldEqualsValueExpression
from sigma.types import SigmaCompareExpression
from typing import ClassVar, Dict, Tuple

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

    cidrv4_expression : ClassVar[str] = "{value}"

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

    def convert_condition_field_eq_val_re(self, cond : ConditionFieldEqualsValueExpression, state : "sigma.conversion.state.ConversionState") -> SplunkDeferredRegularExpression:
        """Defer regular expression matching to pipelined regex command after main search expression."""
        return SplunkDeferredRegularExpression(state, cond.field, super().convert_condition_field_eq_val_re(cond, state))

    def convert_condition_field_eq_val_cidrv4(self, cond : ConditionFieldEqualsValueExpression, state : "sigma.conversion.state.ConversionState") -> SplunkDeferredCIDRExpression:
        """Defer CIDR network range matching to pipelined where cidrmatch command after main search expression."""
        return SplunkDeferredCIDRExpression(state, cond.field, super().convert_condition_field_eq_val_cidrv4(cond, state))