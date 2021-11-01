from sigma.conversion.base import TextQueryBackend
from sigma.types import SigmaCompareExpression
from typing import ClassVar, Dict

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

    re_expression : ClassVar[str] = "| regex field={field} \"{regex}\""
    re_escape_char : ClassVar[str] = "\\"

    cidr_expression : ClassVar[str] = "| where cidrmatch(\"{value}\", {field})"
    cidr_in_list_expression : ClassVar[str] = "{field} in ({list})"

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
    unbound_value_re_expression : ClassVar[str] = '| regex field=_raw \"{value}\"'

    deferred_start : ClassVar[str] = "\n"
    deferred_separator : ClassVar[str] = "\n"