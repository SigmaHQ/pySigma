import json
from typing import Any, ClassVar, Dict, List, Optional, Tuple, Union
import re

from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
    ConditionItem,
)
from sigma.types import (
    SigmaCompareExpression,
    SigmaString,
    SigmaNumber,
    SigmaRegularExpression,
)
from sigma.rule import SigmaRule


class SiemBackend(TextQueryBackend):
    """SIEM backend for pySigma."""

    name: ClassVar[str] = "SIEM backend"
    formats: ClassVar[Dict[str, str]] = {
        "default": "SIEM criteria JSON",
    }

    precedence: ClassVar[Tuple[type, type, type]] = (ConditionOR, ConditionAND, ConditionNOT)
    group_expression: ClassVar[str] = "({expr})"
    parenthesize: bool = True

    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT "
    eq_token: ClassVar[str] = " = "

    field_quote: ClassVar[str] = "'"
    str_quote: ClassVar[str] = '"'

    wildcard_multi: ClassVar[str] = "*"
    wildcard_single: ClassVar[str] = "?"

    re_expression: ClassVar[str] = "{field} MATCHES {regex}"

    compare_op_expression: ClassVar[str] = "{field} {operator} {value}"
    compare_operators: ClassVar[Dict[Any, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
        SigmaCompareExpression.CompareOperators.NEQ: "!=",
    }

    startswith_expression: ClassVar[str] = "{field} SW {value}"
    endswith_expression: ClassVar[str] = "{field} EW {value}"
    contains_expression: ClassVar[str] = "{field} CONT {value}"

    field_in_list_expression: ClassVar[str] = "{field} {op} ({list})"
    or_in_operator: ClassVar[str] = "IN"
    list_separator: ClassVar[str] = ", "

    unbound_value_str_expression: ClassVar[str] = 'RAWLOG CONT "{value}"'

    def __init__(
        self,
        processing_pipeline: Optional[Any] = None,
        collect_errors: bool = False,
        **kwargs: Any,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.rows = []

    def convert_condition(
        self,
        cond: Union[
            ConditionItem,
            ConditionFieldEqualsValueExpression,
            ConditionValueExpression,
            None,
        ],
        state: ConversionState,
    ) -> Any:
        """
        Convert query of Sigma rule into target data structure (usually query, see above).
        Dispatches to methods (see above) specialized on specific condition parse tree node objects.
        """
        if isinstance(cond, ConditionOR):
            return self.convert_condition_or(cond, state)
        elif isinstance(cond, ConditionAND):
            return self.convert_condition_and(cond, state)
        elif isinstance(cond, ConditionNOT):
            return self.convert_condition_not(cond, state)
        elif isinstance(cond, ConditionFieldEqualsValueExpression):
            return self.convert_condition_field_eq_val(cond, state)
        elif isinstance(cond, ConditionValueExpression):
            return self.convert_condition_val(cond, state)
        elif cond is None:
            return None
        else:
            raise TypeError(
                "Unexpected data type in condition parse tree: " + cond.__class__.__name__
            )

    def convert_condition_field_eq_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        """Conversion of field = value conditions."""
        if isinstance(cond.value, SigmaString):
            return self.convert_condition_field_eq_val_str(cond, state)
        elif isinstance(cond.value, SigmaNumber):
            return self.convert_condition_field_eq_val_num(cond, state)
        elif isinstance(cond.value, SigmaRegularExpression):
            return self.convert_condition_field_eq_val_re(cond, state)
        elif isinstance(cond.value, SigmaCompareExpression):
            return self.convert_condition_field_compare_op_val(cond, state)
        else:
            raise NotImplementedError(f"Unsupported value type: {type(cond.value)}")

    def add_row(self, field: str, operator: str, value: Any, value_type: str) -> int:
        """Adds a row to the criteria and returns its index."""
        row_index = len(self.rows) + 1

        # Escape backslashes for JSON
        if isinstance(value, str):
            value = value.replace("\\", "\\\\")

        self.rows.append(
            {
                "CONDI": operator,
                "FIELD": field.upper(),
                "VALUE": str(value),
                "TYPE": value_type,
                "LOGIC": "AND",  # Default, will be adjusted later
            }
        )
        return row_index

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        """Convert field = string value expressions."""
        value_str = str(cond.value)
        if cond.value.endswith("*") and cond.value.startswith("*"):
            operator = "CONT"
            value = value_str[1:-1]
        elif cond.value.endswith("*"):
            operator = "SW"
            value = value_str[:-1]
        elif cond.value.startswith("*"):
            operator = "EW"
            value = value_str[1:]
        else:
            operator = "EQ"
            value = value_str

        values = value.split(",")
        if len(values) > 25:
            # Split into multiple rows
            chunks = [",".join(values[i : i + 25]) for i in range(0, len(values), 25)]
            row_indices = [
                self.add_row(cond.field, operator, chunk, "TEXT") for chunk in chunks
            ]
            return f"({' OR '.join(map(str, row_indices))})"
        else:
            row_index = self.add_row(cond.field, operator, value, "TEXT")
            return str(row_index)

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        """Convert field = number value expressions."""
        row_index = self.add_row(cond.field, "EQ", cond.value, "NUM")
        return str(row_index)

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        """Convert field = regex value expressions."""
        row_index = self.add_row(cond.field, "MATCHES", cond.value, "TEXT")
        return str(row_index)

    def convert_condition_field_compare_op_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        """Convert field comparison expressions."""
        op = self.compare_operators[cond.value.op]
        row_index = self.add_row(cond.field, op, cond.value.number, "NUM")
        return str(row_index)

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> str:
        """Convert string-only conditions."""
        row_index = self.add_row("RAWLOG", "CONT", cond.value, "TEXT")
        return str(row_index)

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> str:
        """Convert OR conditions."""
        parts = [self.convert_condition(arg, state) for arg in cond.args]
        return f"({' OR '.join(parts)})"

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> str:
        """Convert AND conditions."""
        parts = [self.convert_condition(arg, state) for arg in cond.args]
        return f"({' AND '.join(parts)})"

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> str:
        """Convert NOT conditions."""
        # NOT operations are not supported in the pattern, so we have to use negative conditions.
        # This requires modifying the condition before conversion.
        # For simplicity, we'll just raise an error for now.
        raise NotImplementedError("NOT operations are not supported in patterns.")

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Any:
        """Finalize query."""
        pattern = re.sub(r"\((\d+)\)", r"\1", query)  # Remove parentheses around single numbers

        # Set LOGIC for each row
        for i in range(len(self.rows), 0, -1):
            if i > 1:
                # Regex to find the operator between the current row and a previous one
                # This is a simplified logic and might need to be more robust
                if re.search(rf"\b{i-1}\s+AND\s+{i}\b", pattern):
                    self.rows[i - 1]["LOGIC"] = "AND"
                elif re.search(rf"\b{i-1}\s+OR\s+{i}\b", pattern):
                    self.rows[i - 1]["LOGIC"] = "OR"

        if not self.rows:
            return {"actions": [{"ACTION_UNIQUE_NAME": "PLACEHOLDER_ACTION"}]}

        return {
            "actions": [
                {
                    "ACTION_UNIQUE_NAME": "PLACEHOLDER_ACTION",
                    "pattern": pattern,
                    "rows": self.rows,
                }
            ]
        }

    def finalize_output_default(self, queries: List[Any]) -> List[str]:
        """Finalize output."""
        if not queries:
            return []
        # The queries are already in the desired JSON format.
        # If there are multiple queries, we might need to combine them.
        # For now, just return the first one, assuming one query per rule.
        return [json.dumps(queries[0], indent=2)]
