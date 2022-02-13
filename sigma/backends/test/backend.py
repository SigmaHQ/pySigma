from typing import ClassVar, Dict, Tuple

from sigma.conversion.base import TextQueryBackend
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.types import SigmaCompareExpression


class TextQueryTestBackend(TextQueryBackend):
    group_expression : ClassVar[str] = "({expr})"

    or_token : ClassVar[str] = "or"
    and_token : ClassVar[str] = "and"
    not_token : ClassVar[str] = "not"
    eq_token : ClassVar[str] = "="

    str_quote : ClassVar[str] = '"'
    escape_char : ClassVar[str] = "\\"
    wildcard_multi : ClassVar[str] = "*"
    wildcard_single : ClassVar[str] = "?"
    add_escaped : ClassVar[str] = ":"
    filter_chars : ClassVar[str] = "&"
    bool_values : ClassVar[Dict[bool, str]] = {
        True: "1",
        False: "0",
    }

    re_expression : ClassVar[str] = "{field}=/{regex}/"
    re_escape_char : ClassVar[str] = "\\"
    re_escape : ClassVar[Tuple[str]] = ("/", "bar")

    cidr_expression : ClassVar[str] = "{field}={value}"
    cidr_in_list_expression : ClassVar[str] = "{field} in ({list})"
    cidr_wildcard : ClassVar[str] = None

    compare_op_expression : ClassVar[str] = "{field}{operator}{value}"
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    field_null_expression : ClassVar[str] = "{field} is null"

    field_in_list_expression : ClassVar[str] = "{field} in ({list})"
    list_separator : ClassVar[str] = ", "

    unbound_value_str_expression : ClassVar[str] = '_="{value}"'
    unbound_value_num_expression : ClassVar[str] = '_={value}'
    unbound_value_re_expression : ClassVar[str] = '_=/{value}/'

    deferred_start : ClassVar[str] = " | "
    deferred_separator : ClassVar[str] = " | "
    deferred_only_query : ClassVar[str] = "*"

    backend_processing_pipeline = ProcessingPipeline([
        ProcessingItem(FieldMappingTransformation({
            "fieldA": "mappedA",
        }))
    ])