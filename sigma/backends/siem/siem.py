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
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.conditions import IncludeFieldCondition
from sigma.processing.conditions.custom import LogsourceCategoryStartsWithCondition
from sigma.processing.transformations import FieldMappingTransformation
from sigma.processing.transformations.interim import TargetObjectTransformation, DuplicateTargetFilenameTransformation
from sigma.types import (
    SigmaCompareExpression,
    SigmaString,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaNull,
    SigmaCIDRExpression,
    SigmaFieldReference,
    SigmaQueryExpression,
    SigmaExpansion,
)
from sigma.rule import SigmaRule


class SiemBackend(TextQueryBackend):
    """SIEM backend for pySigma."""

    name: ClassVar[str] = "SIEM backend"
    formats: ClassVar[Dict[str, str]] = {
        "default": "SIEM criteria JSON",
    }

    field_mappings: ClassVar[Dict[str, str]] = {
        "Image": "PROCESSNAME",
        "ParentImage": "PARENTPROCESSNAME",
        "Details": "CHANGES",
        "TargetObject": "OBJECTNAME",
        "ScriptBlockText": "SCRIPTEXECUTED",
        "EventType": "EVENT_TYPE",
        "ImageLoaded": "OBJECTNAME",
        "DestinationHostname": "DESTINATIONHOST",
        "QueryName": "QUERY",
        "ParentCommandLine": "PARENTPROCESSCOMMANDLINE",
        "Product": "PRODUCT_NAME",
        "TargetFilename": "FILENAME",
        "Initiated": "IS_INITIATED",
        "Description": "MESSAGE",
        "SourceImage": "PARENTPROCESSNAME",
        "DestinationPort": "DEST_PORT",
        "PipeName": "OBJECTNAME",
        "CurrentDirectory": "CWD",
        "GrantedAccess": "ACCESSRIGHT",
        "TargetImage": "PROCESSNAME",
        "Company": "COMPANY_NAME"
    }

    backend_processing_pipeline: ClassVar[ProcessingPipeline] = ProcessingPipeline(
        items=[
            ProcessingItem(
                transformation=TargetObjectTransformation(),
                field_name_conditions=[
                    IncludeFieldCondition(fields=["TargetObject"])
                ]
            ),
            ProcessingItem(
                transformation=DuplicateTargetFilenameTransformation(),
                rule_conditions=[
                    LogsourceCategoryStartsWithCondition(prefix="file_")
                ]
            ),
            ProcessingItem(
                transformation=FieldMappingTransformation(field_mappings)
            ),
        ]
    )

    precedence: ClassVar[Tuple[type, type, type]] = (ConditionOR, ConditionAND, ConditionNOT)
    group_expression: ClassVar[str] = "({expr})"
    parenthesize: bool = True

    or_token: ClassVar[str] = " OR "
    and_token: ClassVar[str] = " AND "
    not_token: ClassVar[str] = "NOT " # This is not used in the pattern, but required by the base class
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
        self.negation_mapping = {
            "EQ": "NEQ", "NEQ": "EQ",
            "CONT": "NCONT", "NCONT": "CONT",
            "SW": "NSW", "NSW": "SW",
            "EW": "NEW", "NEW": "EW",
            "GT": "LTE", "GTE": "LT",
            "LT": "GTE", "LTE": "GT",
            "MATCHES": "NMATCHES", "NMATCHES": "MATCHES",
            "IN": "NIN", "NIN": "IN",
        }

    def add_row(self, field: str, operator: str, value: Any, value_type: str, logic: str = "AND") -> int:
        """Adds a row to the criteria and returns its index."""
        row_index = len(self.rows) + 1

        row = {
            "CONDI": operator,
            "FIELD": field.upper(),
            "TYPE": value_type,
            "LOGIC": logic,
        }

        if value is not None:
            # json.dumps will handle escaping of strings within the list
            if isinstance(value, list):
                row["VALUE"] = value
            else:
                row["VALUE"] = str(value)

        self.rows.append(row)
        return row_index

    def convert_condition_as_in_expression(
        self, cond: ConditionOR, state: ConversionState
    ) -> str:
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

        # Determine the operator and value format (list for IN, string for others)
        if operator == "EQ":
            final_operator = "IN"
            final_value = values
        else:
            final_operator = operator
            final_value = ",".join(values)

        if getattr(state, "negated", False):
            final_operator = self.negation_mapping.get(final_operator, "N" + final_operator)

        if len(values) <= 25:
            row_index = self.add_row(field, final_operator, final_value, "TEXT")
            return str(row_index)
        else:
            chunks = [values[i:i+25] for i in range(0, len(values), 25)]
            row_indices = []
            for i, chunk in enumerate(chunks):
                logic = "OR" if i > 0 else "AND"
                # For IN operator, the chunk is a list. For others, it's a comma-separated string.
                chunk_value = chunk if final_operator in ("IN", "NIN") else ",".join(chunk)
                row_indices.append(self.add_row(field, final_operator, chunk_value, "TEXT", logic=logic))

            return f"({' OR '.join(map(str, row_indices))})"

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
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

        if getattr(state, "negated", False):
            operator = self.negation_mapping.get(operator, "N" + operator)

        row_index = self.add_row(cond.field, operator, value, "TEXT")
        return str(row_index)

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        operator = "EQ"
        if getattr(state, "negated", False):
            operator = self.negation_mapping.get(operator, "N" + operator)
        row_index = self.add_row(cond.field, operator, cond.value, "NUM")
        return str(row_index)

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        operator = "MATCHES"
        if getattr(state, "negated", False):
            operator = self.negation_mapping.get(operator, "N" + operator)
        row_index = self.add_row(cond.field, operator, cond.value, "TEXT")
        return str(row_index)

    def convert_condition_field_compare_op_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        op = self.compare_operators[cond.value.op]
        if getattr(state, "negated", False):
            op = self.negation_mapping.get(op, "N" + op)
        row_index = self.add_row(cond.field, op, cond.value.number, "NUM")
        return str(row_index)

    def convert_condition_field_eq_val_null(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        if getattr(state, "negated", False):
            operator = "EXISTS"
        else:
            operator = "NOT_EXISTS"
        row_index = self.add_row(cond.field, operator, None, "TEXT")
        return str(row_index)

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> str:
        operator = "CONT"
        if getattr(state, "negated", False):
            operator = self.negation_mapping.get(operator, "N" + operator)
        row_index = self.add_row("RAWLOG", operator, cond.value, "TEXT")
        return str(row_index)

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> str:
        if self.decide_convert_condition_as_in_expression(cond, state):
            return self.convert_condition_as_in_expression(cond, state)

        parts = []
        for i, arg in enumerate(cond.args):
            part = self.convert_condition(arg, state)
            if part and i > 0:
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
        arg = cond.args[0]

        if isinstance(arg, ConditionOR):
            return self.convert_condition(ConditionAND([ConditionNOT([sub_arg]) for sub_arg in arg.args]), state)

        if isinstance(arg, ConditionAND):
            return self.convert_condition(ConditionOR([ConditionNOT([sub_arg]) for sub_arg in arg.args]), state)

        is_negated_before = getattr(state, "negated", False)
        state.negated = not is_negated_before
        result = self.convert_condition(arg, state)
        state.negated = is_negated_before
        return result

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
        elif isinstance(cond.value, SigmaNull):
            return self.convert_condition_field_eq_val_null(cond, state)
        elif isinstance(cond.value, SigmaExpansion):
            return super().convert_condition_field_eq_expansion(cond, state)
        elif isinstance(cond.value, SigmaCIDRExpression):
            raise NotImplementedError("CIDR expressions are not supported by this backend.")
        elif isinstance(cond.value, SigmaFieldReference):
            raise NotImplementedError("Field references are not supported by this backend.")
        elif isinstance(cond.value, SigmaQueryExpression):
            raise NotImplementedError("Query expressions are not supported by this backend.")
        else:
            raise NotImplementedError(f"Unsupported value type: {type(cond.value)}")

    def convert_condition_val(self, cond: ConditionValueExpression, state: ConversionState) -> Any:
        if isinstance(cond.value, SigmaString):
            return self.convert_condition_val_str(cond, state)
        elif isinstance(cond.value, SigmaQueryExpression):
            raise NotImplementedError("Query expressions are not supported by this backend.")
        else:
            raise NotImplementedError(f"Unsupported value type: {type(cond.value)}")

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> Any:
        pattern = query
        pattern = re.sub(r"\((\d+)\)", r"\1", pattern)
        if pattern.startswith("(") and pattern.endswith(")"):
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
