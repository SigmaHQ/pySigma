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

    or_token: ClassVar[str] = " OR "
    and_token: ClassVar[str] = " AND "
    not_token: ClassVar[str] = "NOT "
    eq_token: ClassVar[str] = "="

    # Enable conversion of OR conditions to IN expressions
    convert_or_as_in: ClassVar[bool] = True
    in_expressions_allow_wildcards: ClassVar[bool] = True

    def __init__(
        self,
        processing_pipeline: Optional[Any] = None,
        collect_errors: bool = False,
        **kwargs: Any,
    ):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.rows = []

    def add_row(self, field: str, operator: str, value: Any, value_type: str, logic: str = "AND") -> int:
        """Adds a row to the criteria and returns its index."""
        row_index = len(self.rows) + 1

        if isinstance(value, str):
            value = value.replace("\\", "\\\\")

        self.rows.append(
            {
                "CONDI": operator,
                "FIELD": field.upper(),
                "VALUE": str(value),
                "TYPE": value_type,
                "LOGIC": logic,
            }
        )
        return row_index

    def convert_condition_as_in_expression(
        self, cond: ConditionOR, state: ConversionState
    ) -> str:
        """
        Conversion of OR conditions into a single row with multiple values,
        or multiple rows if the value count exceeds 25.
        """
        if not cond.args:
            return ""

        field = cond.args[0].field

        first_value_str = str(cond.args[0].value)
        if first_value_str.startswith("*") and first_value_str.endswith("*"):
            operator = "CONT"
            strip = lambda s: s[1:-1]
        elif first_value_str.startswith("*"):
            operator = "EW"
            strip = lambda s: s[1:]
        elif first_value_str.endswith("*"):
            operator = "SW"
            strip = lambda s: s[:-1]
        else:
            operator = "EQ"
            strip = lambda s: s

        values = [strip(str(arg.value)) for arg in cond.args if isinstance(arg, ConditionFieldEqualsValueExpression)]

        if not values:
            return self.convert_condition_or(cond, state)

        if len(values) <= 25:
            row_index = self.add_row(field, operator, ",".join(values), "TEXT")
            return str(row_index)
        else:
            chunks = [values[i:i+25] for i in range(0, len(values), 25)]
            row_indices = []
            for i, chunk in enumerate(chunks):
                logic = "OR" if i > 0 else "AND"
                row_indices.append(self.add_row(field, operator, ",".join(chunk), "TEXT", logic=logic))

            return f"({' OR '.join(map(str, row_indices))})"

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        """Convert field = string value expressions."""
        value_str = str(cond.value)

        if value_str.startswith("*") and value_str.endswith("*"):
            operator = "CONT"
            value = value_str[1:-1]
        elif value_str.startswith("*"):
            operator = "EW"
            value = value_str[1:]
        elif value_str.endswith("*"):
            operator = "SW"
            value = value_str[:-1]
        else:
            operator = "EQ"
            value = value_str

        row_index = self.add_row(cond.field, operator, value, "TEXT")
        return str(row_index)

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        row_index = self.add_row(cond.field, "EQ", cond.value, "NUM")
        return str(row_index)

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        row_index = self.add_row(cond.field, "MATCHES", cond.value, "TEXT")
        return str(row_index)

    def convert_condition_field_compare_op_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        op = self.compare_operators[cond.value.op]
        row_index = self.add_row(cond.field, op, cond.value.number, "NUM")
        return str(row_index)

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> str:
        row_index = self.add_row("RAWLOG", "CONT", cond.value, "TEXT")
        return str(row_index)

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> str:
        if self.decide_convert_condition_as_in_expression(cond, state):
            return self.convert_condition_as_in_expression(cond, state)

        parts = []
        for i, arg in enumerate(cond.args):
            part = self.convert_condition(arg, state)
            if part and i > 0:
                # Find the first row number in this part to set its logic to OR
                match = re.search(r'\d+', part)
                if match:
                    row_num = int(match.group(0))
                    if 0 < row_num <= len(self.rows):
                        self.rows[row_num - 1]['LOGIC'] = 'OR'
            parts.append(part)

        return f"({' OR '.join(filter(None, parts))})"

    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> str:
        parts = [self.convert_condition(arg, state) for arg in cond.args]
        return f"({' AND '.join(filter(None, parts))})"

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> str:
        raise NotImplementedError("NOT operations are not supported in patterns.")

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
        return None

    def convert_condition_field_eq_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
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

    def convert_condition_val(self, cond: ConditionValueExpression, state: ConversionState) -> Any:
        if isinstance(cond.value, SigmaString):
            return self.convert_condition_val_str(cond, state)
        else:
            raise NotImplementedError(f"Unsupported value type: {type(cond.value)}")

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Any:
        pattern = query
        pattern = re.sub(r"\((\d+)\)", r"\1", pattern)
        # Remove outer parentheses if they are the only ones and not necessary
        if pattern.startswith("(") and pattern.endswith(")"):
            # Check if parentheses are redundant
            p_count = 0
            is_redundant = True
            for i, char in enumerate(pattern[:-1]):
                if char == '(':
                    p_count += 1
                elif char == ')':
                    p_count -= 1
                if p_count == 0 and i < len(pattern) - 2:
                    is_redundant = False
                    break
            if is_redundant:
                pattern = pattern[1:-1]

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
        if not queries:
            return []
        return [json.dumps(queries[0], indent=2)]
