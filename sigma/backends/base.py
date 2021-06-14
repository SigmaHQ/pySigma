from abc import ABC, abstractmethod
from typing import ClassVar, Optional, Tuple, List, Dict, Any
from sigma.processing.pipeline import ProcessingPipeline
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.conditions import ConditionItem, ConditionOR, ConditionAND, ConditionNOT, ConditionFieldEqualsValueExpression, ConditionFieldValueInExpression, ConditionValueExpression, ConditionType
from sigma.types import SigmaString, SigmaNumber, SigmaRegularExpression, SigmaCompareExpression, SigmaNull, SigmaQueryExpression

class Backend(ABC):
    """
    Base class for Sigma conversion backends. A backend is made up from the following elements:

    * A processing pipeline stored in backend_processing_pipeline that is applied to each Sigma
      rule that is converted by the backend. This is the location where you add generic
      transformations that should be applied to all Sigma rules before conversion.
    * An additional processing pipeline can be passed to the constructor and is applied after
      the backend pipeline. This one is configured by the user to implement transformations
      required in the environment (e.g. field renaming).
    * The method convert is the entry point for a conversion of a rule set. By default it converts
      each rule and invokes the finalization step for the whole set of converted rules. There are better
      locations to implement backend functionality.
    * convert_rule converts a single rule. By default it converts all conditions and invokes the rule
      finalization.
    * convert_condition is the entry point for conversion of a rule condition into a query. It dispatches
      to the condition element classes.
    * convert_condition_* methods must be implemented and handle the conversion of condition elements. The
      result might be an intermediate representation which is finalized by finalize_query.
    * finalize_query finalizes the conversion result of a converted rule condition. By default it simply
      passes the generated queries.
    * finalize_output_<format> finalizes the conversion result of a whole rule set in the specified format.
      By default finalize_output_default is called and outputs a list of all queries. Further formats can be
      implemented in similar methods. The defaulf format can be specified in the class variable default_format.

    Implementation of a backend:

    1. Implement conversion of condition elements in convert_condition_*. The output can be an intermediate
       or the final query representation.
    2. If required, implement a per-query finalization step in finalize_query. Each Sigma rule condition
       results in a query. This can embed the generated query into other structures (e.g. boilerplate code,
       prefix/postifx query parts) or convert the intermediate into a final query representation.
    3. If required, implement a finalization step working on all generated queries in finalize. This can
       embed the queries into other data structures (e.g. JSON or XML containers for import into the target
       system) or perform the conversion of an intermediate to the final query representation.

    Some hints and conventions:

    * Use processing pipelines to apply transformations instead of implementing transformations in the backend
      itself. Implement generic transformations if they aren't too backend-specific.
    * Use TextQueryBackend as base class for backends that output text-based queries.
    * Use intermediate representations for queries and query sets for formats that require state information,
      e.g. if the target query language results in a different structure than given by the condition.
    """
    processing_pipeline : ProcessingPipeline
    backend_processing_pipeline : ClassVar[ProcessingPipeline] = ProcessingPipeline()
    config : Dict[str, Any]
    default_format : ClassVar[str] = "default"

    def __init__(self, processing_pipeline : Optional[ProcessingPipeline] = None, **kwargs):
        self.processing_pipeline = self.backend_processing_pipeline + processing_pipeline
        self.config = kwargs

    def convert(self, rule_collection : SigmaCollection, output_format : Optional[str] = None) -> Any:
        """
        Convert a Sigma ruleset into the target data structure. Usually the result are one or
        multiple queries, but might also be some arbitrary data structure required for further
        processing.
        """
        queries = [
            query
            for rule in rule_collection.rules
            for query in self.convert_rule(rule)
        ]
        return self.finalize(rule_collection, queries, output_format or self.default_format)

    def convert_rule(self, rule : SigmaRule) -> List[Any]:
        """
        Convert a single Sigma rule into the target data structure (usually query, see above).
        """
        self.processing_pipeline.apply(rule)        # 1. Apply transformations
        queries = [                                 # 2. Convert condition
            self.convert_condition(cond.parsed)
            for cond in rule.detection.parsed_condition
        ]
        return [                                    # 3. Postprocess generated query
            self.finalize_query(rule, query)
            for query in queries
        ]

    @abstractmethod
    def convert_condition_or(self, cond : ConditionOR) -> Any:
        """Conversion of OR conditions."""

    @abstractmethod
    def convert_condition_and(self, cond : ConditionAND) -> Any:
        """Conversion of AND conditions."""

    @abstractmethod
    def convert_condition_not(self, cond : ConditionNOT) -> Any:
        """Conversion of NOT conditions."""

    @abstractmethod
    def convert_condition_field_eq_val_str(self, cond : ConditionFieldEqualsValueExpression) -> Any:
        """Conversion of field = string value expressions"""

    @abstractmethod
    def convert_condition_field_eq_val_num(self, cond : ConditionFieldEqualsValueExpression) -> Any:
        """Conversion of field = number value expressions"""

    @abstractmethod
    def convert_condition_field_eq_val_re(self, cond : ConditionFieldEqualsValueExpression) -> Any:
        """Conversion of field matches regular expression value expressions"""

    @abstractmethod
    def convert_condition_field_compare_op_val(self, cond : ConditionFieldEqualsValueExpression) -> Any:
        """Conversion of field matches regular expression value expressions"""

    @abstractmethod
    def convert_condition_field_eq_val_null(self, cond : ConditionFieldEqualsValueExpression) -> Any:
        """Conversion of field is null expression value expressions"""

    @abstractmethod
    def convert_condition_field_eq_query_expr(self, cond : ConditionFieldEqualsValueExpression) -> Any:
        """Conversion of query expressions bound to a field."""

    def convert_condition_field_eq_val(self, cond : ConditionFieldEqualsValueExpression) -> Any:
        """Conversion dispatcher of field = value conditions. Dispatches to value-specific methods."""
        if isinstance(cond.value, SigmaString):
            return self.convert_condition_field_eq_val_str(cond)
        elif isinstance(cond.value, SigmaNumber):
            return self.convert_condition_field_eq_val_num(cond)
        elif isinstance(cond.value, SigmaRegularExpression):
            return self.convert_condition_field_eq_val_re(cond)
        elif isinstance(cond.value, SigmaCompareExpression):
            return self.convert_condition_field_compare_op_val(cond)
        elif isinstance(cond.value, SigmaNull):
            return self.convert_condition_field_eq_val_null(cond)
        elif isinstance(cond.value, SigmaQueryExpression):
            return self.convert_condition_field_eq_query_expr(cond)
        else:       # pragma: no cover
            raise TypeError("Unexpected value type class in condition parse tree: " + cond.value.__class__.__name__)

    @abstractmethod
    def convert_condition_field_in_vals(self, cond : ConditionFieldValueInExpression) -> Any:
        """
        Conversion of field in value conditions.

        The value list will only contain plain strings (without wildcards) or numbers. These
        both types must be handled accordingly.
        """

    @abstractmethod
    def convert_condition_val_str(self, cond : ConditionValueExpression) -> Any:
        """Conversion of string-only conditions."""

    @abstractmethod
    def convert_condition_val_num(self, cond : ConditionValueExpression) -> Any:
        """Conversion of number-only conditions."""

    @abstractmethod
    def convert_condition_val_re(self, cond : ConditionValueExpression) -> Any:
        """Conversion of regexp-only conditions."""

    @abstractmethod
    def convert_condition_query_expr(self, cond : ConditionValueExpression) -> Any:
        """Conversion of query expressions without field association."""

    def convert_condition_val(self, cond : ConditionValueExpression) -> str:
        """Conversion of value-only conditions."""
        if isinstance(cond.value, SigmaString):
            return self.convert_condition_val_str(cond)
        elif isinstance(cond.value, SigmaNumber):
            return self.convert_condition_val_num(cond)
        elif isinstance(cond.value, SigmaRegularExpression):
            return self.convert_condition_val_re(cond)
        elif isinstance(cond.value, SigmaQueryExpression):
            return self.convert_condition_query_expr(cond)
        else:       # pragma: no cover
            raise TypeError("Unexpected value type class in condition parse tree: " + cond.value.__class__.__name__)

    def convert_condition(
        self,
        cond : ConditionType) -> Any:
        """
        Convert query of Sigma rule into target data structure (usually query, see above).
        Dispatches to methods (see above) specialized on specific condition parse tree node objects.
        """
        if isinstance(cond, ConditionOR):
            return self.convert_condition_or(cond)
        elif isinstance(cond, ConditionAND):
            return self.convert_condition_and(cond)
        elif isinstance(cond, ConditionNOT):
            return self.convert_condition_not(cond)
        elif isinstance(cond, ConditionFieldEqualsValueExpression):
            return self.convert_condition_field_eq_val(cond)
        elif isinstance(cond, ConditionFieldValueInExpression):
            return self.convert_condition_field_in_vals(cond)
        elif isinstance(cond, ConditionValueExpression):
            return self.convert_condition_val(cond)
        else:       # pragma: no cover
            raise TypeError("Unexpected data type in condition parse tree: " + cond.__class__.__name__)

    def finalize_query(self, rule : SigmaRule, query : Any) -> Any:
        """
        Finalize conversion result of a query.
        """
        return query

    def finalize(self, rules : SigmaCollection, queries : List[Any], output_format : str):
        """Finalize output. Dispatches to format-specific method."""
        return self.__getattribute__("finalize_output_" + output_format)(rules, queries)

    def finalize_output_default(self, rules : SigmaCollection, queries : List[Any]) -> Any:
        """
        Default finalization
        """
        return queries

class TextQueryBackend(Backend):
    """
    Backend base for backends generating text-based queries. The behavior can be defined by various
    class variables. If this is not sufficient, the respective methods can be implemented with more
    complex transformations.
    """
    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[Optional[str]] = None   # Expression for precedence override grouping as format string with {expr} placeholder

    # Generated query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token  : ClassVar[Optional[str]] = None
    and_token : ClassVar[Optional[str]] = None
    not_token : ClassVar[Optional[str]] = None
    eq_token  : ClassVar[Optional[str]] = None      # Token inserted between field and value (without separator)

    # String output
    str_quote       : ClassVar[Optional[str]] = None    # string quoting character (added as escaping character)
    escape_char     : ClassVar[Optional[str]] = None    # Escaping character for special characrers inside string
    wildcard_multi  : ClassVar[Optional[str]] = None    # Character used as multi-character wildcard
    wildcard_single : ClassVar[Optional[str]] = None    # Character used as single-character wildcard
    add_escaped     : ClassVar[str] = ""                # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = ""                # Characters filtered

    # Regular expressions
    re_expression : ClassVar[Optional[str]] = None      # Regular expression query as format string with placeholders {field} and {regex}
    re_escape_char : ClassVar[Optional[str]] = None     # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ()               # List of strings that are escaped

    # Numeric comparison operators
    compare_op_expression : ClassVar[Optional[str]] = None      # Compare operation query as format string with placeholders {field}, {operator} and {value}
    compare_operators : ClassVar[Optional[Dict[SigmaCompareExpression.CompareOperators, str]]] = None       # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression

    # Null/None expressions
    field_null_expression : ClassVar[Optional[str]] = None          # Expression for field has null value as format string with {field} placeholder for field name

    # Field value in list
    field_in_list_expression : ClassVar[Optional[str]] = None       # Expression for field in list of values as format string with placeholders {field} and {list}
    list_separator : ClassVar[Optional[str]] = None     # List element separator

    # Value not bound to a field
    unbound_value_str_expression : ClassVar[Optional[str]] = None   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[Optional[str]] = None   # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression : ClassVar[Optional[str]] = None   # Expression for regular expression not bound to a field as format string with placeholder {value}

    def compare_precedence(self, outer : ConditionItem, inner : ConditionType) -> bool:
        """
        Compare precedence of outer and inner condition items. Return True if precedence of
        enclosing condition item (outer) is lower than the contained (inner) condition item.
        In this case, no additional grouping is required.
        """
        try:
            idx_inner = self.precedence.index(inner)
        except ValueError:      # ConditionItem not in precedence tuple
            idx_inner = -1      # Assume precedence of inner condition item is higher than the outer

        return idx_inner <= self.precedence.index(outer)

    def convert_condition_group(self, cond : ConditionItem) -> str:
        """Group condition item."""
        return self.group_expression.format(expr=self.convert_condition(cond))

    def convert_condition_or(self, cond : ConditionOR) -> str:
        """Conversion of OR conditions."""
        try:
            return (self.token_separator + self.or_token + self.token_separator).join([
                self.convert_condition(arg) if self.compare_precedence(ConditionOR, arg.__class__)
                else self.convert_condition_group(arg)
                for arg in cond.args
                ])
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Operator 'or' not supported by the backend")

    def convert_condition_and(self, cond : ConditionAND) -> str:
        """Conversion of AND conditions."""
        try:
            return (self.token_separator + self.and_token + self.token_separator).join([
                self.convert_condition(arg) if self.compare_precedence(ConditionAND, arg.__class__)
                else self.convert_condition_group(arg)
                for arg in cond.args
                ])
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Operator 'and' not supported by the backend")

    def convert_condition_not(self, cond : ConditionNOT) -> str:
        """Conversion of NOT conditions."""
        arg = cond.args[0]
        try:
            if arg.__class__ in self.precedence:        # group if AND or OR condition is negated
                return self.not_token + self.token_separator + self.convert_condition_group(arg)
            else:
                return self.not_token + self.token_separator + self.convert_condition(arg)
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend")

    def convert_value_str(self, s : SigmaString) -> str:
        """Convert a SigmaString into a plain string which can be used in query."""
        return s.convert(
            self.escape_char,
            self.wildcard_multi,
            self.wildcard_single,
            self.str_quote + self.add_escaped,
            self.filter_chars,
        )

    def convert_condition_field_eq_val_str(self, cond : ConditionFieldEqualsValueExpression) -> str:
        """Conversion of field = string value expressions"""
        try:
            return cond.field + self.eq_token + self.str_quote + self.convert_value_str(cond.value) + self.str_quote
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Field equals string value expressions with strings are not supported by the backend.")

    def convert_condition_field_eq_val_num(self, cond : ConditionFieldEqualsValueExpression) -> str:
        """Conversion of field = number value expressions"""
        try:
            return cond.field + self.eq_token + str(cond.value)
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Field equals numeric value expressions are not supported by the backend.")

    def convert_value_re(self, r : SigmaRegularExpression) -> str:
        """Convert regular expression into string representation used in query."""
        return r.escape(self.re_escape, self.re_escape_char)

    def convert_condition_field_eq_val_re(self, cond : ConditionFieldEqualsValueExpression) -> str:
        """Conversion of field matches regular expression value expressions."""
        return self.re_expression.format(
            field=cond.field,
            regex=self.convert_value_re(cond.value),
        )
    def convert_condition_field_compare_op_val(self, cond : ConditionFieldEqualsValueExpression) -> str:
        """Conversion of numeric comparison operations into queries."""
        return self.compare_op_expression.format(
            field=cond.field,
            operator=self.compare_operators[cond.value.op],
            value=cond.value.number,
        )

    def convert_condition_field_eq_val_null(self, cond : ConditionFieldEqualsValueExpression) -> str:
        """Conversion of field is null expression value expressions"""
        return self.field_null_expression.format(field=cond.field)

    def convert_condition_field_eq_query_expr(self, cond : ConditionFieldEqualsValueExpression) -> str:
        """Conversion of field is null expression value expressions"""
        return cond.value.finalize(field=cond.field)

    def convert_condition_field_in_vals(self, cond : ConditionFieldValueInExpression) -> str:
        """Conversion of field in value list conditions."""
        return self.field_in_list_expression.format(
            field=cond.field,
            list=self.list_separator.join([
                self.str_quote + self.convert_value_str(v) + self.str_quote if isinstance(v, SigmaString)   # string escaping and qouting
                else v       # value is number
                for v in cond.value
            ]),
        )

    def convert_condition_val_str(self, cond : ConditionValueExpression) -> str:
        """Conversion of value-only strings."""
        return self.unbound_value_str_expression.format(value=self.convert_value_str(cond.value))

    def convert_condition_val_num(self, cond : ConditionValueExpression) -> str:
        """Conversion of value-only numbers."""
        return self.unbound_value_num_expression.format(value=cond.value)

    def convert_condition_val_re(self, cond : ConditionValueExpression) -> str:
        """Conversion of value-only regular expressions."""
        return self.unbound_value_re_expression.format(value=self.convert_value_re(cond.value))

    def convert_condition_query_expr(self, cond : ConditionValueExpression) -> str:
        """Conversion of value-only regular expressions."""
        return cond.value.finalize()