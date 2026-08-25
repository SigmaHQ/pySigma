from __future__ import annotations

import re
from ipaddress import ip_address, ip_network
from typing import Any, Callable

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

# Type for compiled matcher callable: (data_dict, raw_log_or_none) -> bool
CompiledMatcher = Callable[[dict[str, Any], str | None], bool]


class MatchCompiler:
    """Compiles Sigma rule detection logic into optimized Python callables."""

    def compile_rule(self, rule: SigmaRule) -> CompiledMatcher:
        """Compile a SigmaRule's conditions into a single callable matcher."""
        # A rule can have multiple conditions (one per condition string).
        # They are OR-linked by default in pySigma.
        conditions = rule.detection.parsed_condition
        closures: dict[str, Any] = {}
        parts: list[str] = []

        for cond in conditions:
            parsed = cond.parsed
            if parsed is None:
                parts.append("False")
            else:
                parts.append(self._compile_node(parsed, closures))

        if len(parts) == 1:
            expr = parts[0]
        else:
            expr = "(" + " or ".join(parts) + ")"

        func_code = f"def _match(data, raw):\n    return {expr}\n"
        namespace: dict[str, Any] = {"__builtins__": {"str": str}}
        namespace.update(closures)
        code_obj = compile(func_code, "<sigma_matcher>", "exec")
        exec(code_obj, namespace)  # noqa: S102
        return namespace["_match"]

    def _compile_node(self, node: Any, closures: dict[str, Any]) -> str:
        if isinstance(node, ConditionAND):
            sub = [self._compile_node(arg, closures) for arg in node.args]
            return "(" + " and ".join(sub) + ")"
        elif isinstance(node, ConditionOR):
            sub = [self._compile_node(arg, closures) for arg in node.args]
            return "(" + " or ".join(sub) + ")"
        elif isinstance(node, ConditionNOT):
            sub = self._compile_node(node.args[0], closures)
            return f"(not {sub})"
        elif isinstance(node, ConditionFieldEqualsValueExpression):
            return self._compile_field_value(node.field, node.value, closures)
        elif isinstance(node, ConditionValueExpression):
            return self._compile_keyword(node.value, closures)
        else:
            return "False"

    def _compile_field_value(self, field_name: str, value: Any, closures: dict[str, Any]) -> str:
        if isinstance(value, SigmaNull):
            return f"(data.get({field_name!r}) is None)"

        elif isinstance(value, SigmaBool):
            bool_val = bool(value)
            return f"(data.get({field_name!r}) is {bool_val})"

        elif isinstance(value, SigmaExists):
            if value.exists:
                return f"({field_name!r} in data)"
            else:
                return f"({field_name!r} not in data)"

        elif isinstance(value, SigmaFieldReference):
            ref_field = value.field
            if value.starts_with and value.ends_with:
                # contains
                return f"(str(data.get({ref_field!r}, '')) in str(data.get({field_name!r}, '')))"
            elif value.starts_with:
                return f"(str(data.get({field_name!r}, '')).startswith(str(data.get({ref_field!r}, ''))))"
            elif value.ends_with:
                return f"(str(data.get({field_name!r}, '')).endswith(str(data.get({ref_field!r}, ''))))"
            else:
                return f"(data.get({field_name!r}) == data.get({ref_field!r}))"

        elif isinstance(value, SigmaCompareExpression):
            num_val = value.number.number
            op_map = {
                CompareOperators.LT: "<",
                CompareOperators.LTE: "<=",
                CompareOperators.GT: ">",
                CompareOperators.GTE: ">=",
                CompareOperators.NEQ: "!=",
            }
            op_str = op_map[value.op]
            return f"(data.get({field_name!r}, 0) {op_str} {num_val!r})"

        elif isinstance(value, SigmaCIDRExpression):
            var_name = f"_cidr_{len(closures)}"
            closures[var_name] = value.network
            closures["_try_cidr"] = _try_cidr
            return f"(_try_cidr(data.get({field_name!r}, ''), {var_name}))"

        elif isinstance(value, SigmaExpansion):
            # OR over all expansion values
            sub_parts = []
            for sub_val in value.values:
                sub_parts.append(self._compile_field_value(field_name, sub_val, closures))
            return "(" + " or ".join(sub_parts) + ")"

        elif isinstance(value, SigmaRegularExpression):
            var_name = f"_re_{len(closures)}"
            flags = 0
            for flag in value.flags:
                flags |= value.sigma_to_python_flags[flag]
            closures[var_name] = re.compile(str(value.regexp), flags)
            return f"({var_name}.search(str(data.get({field_name!r}, ''))) is not None)"

        elif isinstance(value, SigmaNumber):
            num = value.number
            return f"(data.get({field_name!r}) == {num!r})"

        elif isinstance(value, SigmaCasedString):
            # Case-sensitive matching
            return self._compile_string_match(field_name, value, closures, case_sensitive=True)

        elif isinstance(value, SigmaString):
            # Case-insensitive matching
            return self._compile_string_match(field_name, value, closures, case_sensitive=False)

        else:
            return "False"

    def _compile_string_match(
        self,
        field_name: str,
        value: SigmaString,
        closures: dict[str, Any],
        case_sensitive: bool,
    ) -> str:
        if not value.contains_special():
            # Plain string equality
            plain = str(value)
            if case_sensitive:
                return f"(str(data.get({field_name!r}, '')) == {plain!r})"
            else:
                lower_val = plain.lower()
                return f"(str(data.get({field_name!r}, '')).lower() == {lower_val!r})"
        else:
            # Contains wildcards - compile to regex
            regex_str = self._sigma_string_to_regex(value)
            flags = 0 if case_sensitive else re.IGNORECASE
            var_name = f"_pat_{len(closures)}"
            closures[var_name] = re.compile(regex_str, flags)
            return f"({var_name}.search(str(data.get({field_name!r}, ''))) is not None)"

    def _sigma_string_to_regex(self, value: SigmaString) -> str:
        """Convert a SigmaString with wildcards to a regex pattern (anchored)."""
        parts: list[str] = []
        for item in value.s:
            if isinstance(item, str):
                parts.append(re.escape(item))
            elif item == SpecialChars.WILDCARD_MULTI:
                parts.append(".*")
            elif item == SpecialChars.WILDCARD_SINGLE:
                parts.append(".")
        pattern = "".join(parts)
        # Anchor: if no leading wildcard, anchor start; if no trailing, anchor end
        if not value.startswith(SpecialChars.WILDCARD_MULTI):
            pattern = "^" + pattern
        if not value.endswith(SpecialChars.WILDCARD_MULTI):
            pattern = pattern + "$"
        return pattern

    def _compile_keyword(self, value: Any, closures: dict[str, Any]) -> str:
        """Compile a keyword (value-only) expression that searches in raw log."""
        if isinstance(value, SigmaString):
            if not value.contains_special():
                plain = str(value).lower()
                return f"({plain!r} in (raw or '').lower())"
            else:
                regex_str = self._sigma_string_to_regex(value)
                # For keywords, remove anchors - search anywhere
                regex_str = regex_str.lstrip("^").rstrip("$")
                var_name = f"_kw_{len(closures)}"
                closures[var_name] = re.compile(regex_str, re.IGNORECASE)
                return f"({var_name}.search(raw or '') is not None)"
        elif isinstance(value, SigmaRegularExpression):
            var_name = f"_kw_{len(closures)}"
            flags = 0
            for flag in value.flags:
                flags |= value.sigma_to_python_flags[flag]
            closures[var_name] = re.compile(str(value.regexp), flags)
            return f"({var_name}.search(raw or '') is not None)"
        elif isinstance(value, SigmaExpansion):
            sub_parts = []
            for sub_val in value.values:
                sub_parts.append(self._compile_keyword(sub_val, closures))
            return "(" + " or ".join(sub_parts) + ")"
        else:
            return "False"


def _try_cidr(value: Any, network: Any) -> bool:
    """Check if value is an IP within the given network."""
    try:
        return ip_address(str(value)) in network
    except (ValueError, TypeError):
        return False
