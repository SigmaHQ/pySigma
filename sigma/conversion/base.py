from abc import ABC, abstractmethod
from collections import defaultdict
import re

from sigma.exceptions import SigmaError, SigmaValueError
from sigma.conversion.deferred import DeferredQueryExpression
from typing import Pattern, Union, ClassVar, Optional, Tuple, List, Dict, Any
from sigma.processing.pipeline import ProcessingPipeline
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.conditions import ConditionItem, ConditionOR, ConditionAND, ConditionNOT, ConditionFieldEqualsValueExpression, ConditionValueExpression, ConditionType
from sigma.types import SigmaBool, SigmaExpansion, SigmaString, SigmaNumber, SigmaRegularExpression, SigmaCompareExpression, SigmaNull, SigmaQueryExpression, SigmaCIDRExpression, SpecialChars
from sigma.conversion.state import ConversionState

class Backend(ABC):
    """
    Base class for Sigma conversion backends. A backend is made up from the following elements:

    * A processing pipeline stored in backend_processing_pipeline that is applied to each Sigma
      rule that is converted by the backend. This is the location where you add generic
      transformations that should be applied to all Sigma rules before conversion.
    * An additional processing pipeline can be passed to the constructor and is applied after
      the backend pipeline. This one is configured by the user to implement transformations
      required in the environment (e.g. field renaming).
    * If collect_errors is set to True, exceptions will not be thrown, but collected in (sigma_rule, exception)
      tuples in the errors property.
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
    output_format_processing_pipeline : ClassVar[Dict[str, ProcessingPipeline]] = defaultdict(ProcessingPipeline)
    config : Dict[str, Any]
    default_format : ClassVar[str] = "default"
    collect_errors : bool = False
    errors : List[Tuple[SigmaRule, SigmaError]] = list()

    # in-expressions
    convert_or_as_in : ClassVar[bool] = False                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = False                    # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = False       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.

    def __init__(self, processing_pipeline : Optional[ProcessingPipeline] = None, collect_errors : bool = False, **kwargs):
        self.processing_pipeline = processing_pipeline
        self.collect_errors = collect_errors
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
            for query in self.convert_rule(rule, output_format or self.default_format)
        ]
        return self.finalize(queries, output_format or self.default_format)

    def convert_rule(self, rule : SigmaRule, output_format : Optional[str] = None) -> List[Any]:
        """
        Convert a single Sigma rule into the target data structure (usually query, see above).
        """
        state = ConversionState()
        try:
            processing_pipeline = self.backend_processing_pipeline + self.processing_pipeline + self.output_format_processing_pipeline[output_format or self.default_format]
            processing_pipeline.apply(rule)             # 1. Apply transformations
            state.processing_state = processing_pipeline.state
            queries = [                                 # 2. Convert condition
                self.convert_condition(cond.parsed, state)
                for cond in rule.detection.parsed_condition
            ]
            return [                                    # 3. Postprocess generated query
                self.finalize_query(rule, query, index, state, output_format or self.default_format)
                for index, query in enumerate(queries)
            ]
        except SigmaError as e:
            if self.collect_errors:
                self.errors.append((rule, e))
                return []
            else:
                raise e

    def decide_convert_condition_as_in_expression(self, cond : Union[ConditionOR, ConditionAND], state : ConversionState) -> bool:
        """
        Decide if an OR or AND expression should be converted as "field in (value list)" or as plain expression.

        :param cond: Condition that is converted for which the decision has to be made.
        :type cond: Union[ConditionOR, ConditionAND]
        :param state: Current conversion state.
        :type state: ConversionState
        :return: True if in-expression should be generated, else False
        :rtype: bool
        """
        # Check if conversion of condition type is enabled
        if (not self.convert_or_as_in and isinstance(cond, ConditionOR)
           or not self.convert_and_as_in and isinstance(cond, ConditionAND)):
           return False

        # Check if more than one argument is present
        #if len(cond.args <= 1):
        #    return False

        # All arguments of the given condition must reference a field
        if not all((
            isinstance(arg, ConditionFieldEqualsValueExpression)
            for arg in cond.args
        )):
            return False

        # Build a set of all fields appearing in condition arguments
        fields = {
            arg.field
            for arg in cond.args
        }
        # All arguments must reference the same field
        if len(fields) != 1:
            return False

        # All argument values must be strings or numbers
        if not all([
            isinstance(arg.value, ( SigmaString, SigmaNumber ))
            for arg in cond.args
        ]):
           return False

        # Check for plain strings if wildcards are not allowed for string expressions.
        if not self.in_expressions_allow_wildcards and any([
            arg.value.contains_special()
            for arg in cond.args
            if isinstance(arg.value, SigmaString)
        ]):
           return False

        # All checks passed, expression can be converted to in-expression
        return True

    @abstractmethod
    def convert_condition_as_in_expression(self, cond : Union[ConditionOR, ConditionAND], state : ConversionState) -> Any:
        """Conversion of OR or AND conditions into "field in (value list)" expressions."""

    @abstractmethod
    def convert_condition_or(self, cond : ConditionOR, state : ConversionState) -> Any:
        """Conversion of OR conditions."""

    @abstractmethod
    def convert_condition_and(self, cond : ConditionAND, state : ConversionState) -> Any:
        """Conversion of AND conditions."""

    @abstractmethod
    def convert_condition_not(self, cond : ConditionNOT, state : ConversionState) -> Any:
        """Conversion of NOT conditions."""

    @abstractmethod
    def convert_condition_field_eq_val_str(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Any:
        """Conversion of field = string value expressions"""

    @abstractmethod
    def convert_condition_field_eq_val_num(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Any:
        """Conversion of field = number value expressions"""

    @abstractmethod
    def convert_condition_field_eq_val_bool(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Any:
        """Conversion of field = boolean value expressions"""

    @abstractmethod
    def convert_condition_field_eq_val_re(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Any:
        """Conversion of field matches regular expression value expressions"""

    @abstractmethod
    def convert_condition_field_eq_val_cidr(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Any:
        """Conversion of field matches CIDR expression value expressions"""

    @abstractmethod
    def convert_condition_field_compare_op_val(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Any:
        """Conversion of field matches regular expression value expressions"""

    @abstractmethod
    def convert_condition_field_eq_val_null(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Any:
        """Conversion of field is null expression value expressions"""

    @abstractmethod
    def convert_condition_field_eq_query_expr(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Any:
        """Conversion of query expressions bound to a field."""

    def convert_condition_field_eq_expansion(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Any:
        """
        Convert each value of the expansion with the field from the containing condition and OR-link
        all converted subconditions.
        """
        or_cond = ConditionOR([
            ConditionFieldEqualsValueExpression(cond.field, value)
            for value in cond.value.values
        ], cond.source)
        return self.convert_condition_or(or_cond, state)

    def convert_condition_field_eq_val(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Any:
        """Conversion dispatcher of field = value conditions. Dispatches to value-specific methods."""
        if isinstance(cond.value, SigmaString):
            return self.convert_condition_field_eq_val_str(cond, state)
        elif isinstance(cond.value, SigmaNumber):
            return self.convert_condition_field_eq_val_num(cond, state)
        elif isinstance(cond.value, SigmaBool):
            return self.convert_condition_field_eq_val_bool(cond, state)
        elif isinstance(cond.value, SigmaRegularExpression):
            return self.convert_condition_field_eq_val_re(cond, state)
        elif isinstance(cond.value, SigmaCIDRExpression):
            return self.convert_condition_field_eq_val_cidr(cond, state)
        elif isinstance(cond.value, SigmaCompareExpression):
            return self.convert_condition_field_compare_op_val(cond, state)
        elif isinstance(cond.value, SigmaNull):
            return self.convert_condition_field_eq_val_null(cond, state)
        elif isinstance(cond.value, SigmaQueryExpression):
            return self.convert_condition_field_eq_query_expr(cond, state)
        elif isinstance(cond.value, SigmaExpansion):
            return self.convert_condition_field_eq_expansion(cond, state)
        else:       # pragma: no cover
            raise TypeError("Unexpected value type class in condition parse tree: " + cond.value.__class__.__name__)

    @abstractmethod
    def convert_condition_val_str(self, cond : ConditionValueExpression, state : ConversionState) -> Any:
        """Conversion of string-only conditions."""

    @abstractmethod
    def convert_condition_val_num(self, cond : ConditionValueExpression, state : ConversionState) -> Any:
        """Conversion of number-only conditions."""

    @abstractmethod
    def convert_condition_val_re(self, cond : ConditionValueExpression, state : ConversionState) -> Any:
        """Conversion of regexp-only conditions."""

    @abstractmethod
    def convert_condition_query_expr(self, cond : ConditionValueExpression, state : ConversionState) -> Any:
        """Conversion of query expressions without field association."""

    def convert_condition_val(self, cond : ConditionValueExpression, state : ConversionState) -> Any:
        """Conversion of value-only conditions."""
        if isinstance(cond.value, SigmaString):
            return self.convert_condition_val_str(cond, state)
        elif isinstance(cond.value, SigmaNumber):
            return self.convert_condition_val_num(cond, state)
        elif isinstance(cond.value, SigmaBool):
            raise SigmaValueError("Boolean values can't appear as standalone value without a field name.")
        elif isinstance(cond.value, SigmaRegularExpression):
            return self.convert_condition_val_re(cond, state)
        elif isinstance(cond.value, SigmaCIDRExpression):
            raise SigmaValueError("CIDR values can't appear as standalone value without a field name.")
        elif isinstance(cond.value, SigmaQueryExpression):
            return self.convert_condition_query_expr(cond, state)
        else:       # pragma: no cover
            raise TypeError("Unexpected value type class in condition parse tree: " + cond.value.__class__.__name__)

    def convert_condition(
        self,
        cond : ConditionType,
        state : ConversionState) -> Any:
        """
        Convert query of Sigma rule into target data structure (usually query, see above).
        Dispatches to methods (see above) specialized on specific condition parse tree node objects.

        The state mainly contains the deferred list, which is used to collect query parts that are not
        directly integrated into the generated query, but added at a postponed stage of the conversion
        process after the conversion of the condition to a query is finished. This is done in the
        finalize_query method and must be implemented individually.
        """
        if isinstance(cond, ConditionOR):
            if self.decide_convert_condition_as_in_expression(cond, state):
                return self.convert_condition_as_in_expression(cond, state)
            else:
                return self.convert_condition_or(cond, state)
        elif isinstance(cond, ConditionAND):
            if self.decide_convert_condition_as_in_expression(cond, state):
                return self.convert_condition_as_in_expression(cond, state)
            else:
                return self.convert_condition_and(cond, state)
        elif isinstance(cond, ConditionNOT):
            return self.convert_condition_not(cond, state)
        elif isinstance(cond, ConditionFieldEqualsValueExpression):
            return self.convert_condition_field_eq_val(cond, state)
        elif isinstance(cond, ConditionValueExpression):
            return self.convert_condition_val(cond, state)
        else:       # pragma: no cover
            raise TypeError("Unexpected data type in condition parse tree: " + cond.__class__.__name__)

    def finalize_query(self, rule : SigmaRule, query : Any, index : int, state : ConversionState, output_format : str):
        """
        Finalize query. Dispatches to format-specific method. The index parameter enumerates generated queries if the
        conversion of a Sigma rule results in multiple queries.

        This is the place where syntactic elements of the target format for the specific query are added,
        e.g. adding query metadata.
        """
        return self.__getattribute__("finalize_query_" + output_format)(rule, query, index, state)

    def finalize_query_default(self, rule : SigmaRule, query : Any, index : int, state : ConversionState) -> Any:
        """
        Finalize conversion result of a query. Handling of deferred query parts must be implemented by overriding
        this method.
        """
        return query

    def finalize(self, queries : List[Any], output_format : str):
        """Finalize output. Dispatches to format-specific method."""
        return self.__getattribute__("finalize_output_" + output_format)(queries)

    def finalize_output_default(self, queries : List[Any]) -> Any:
        """
        Default finalization.

        This is the place where syntactic elements of the target format for the whole output are added,
        e.g. putting individual queries into a XML file.
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
    ## Fields
    ### Quoting
    field_quote : ClassVar[Optional[str]] = None                # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern : ClassVar[Optional[Pattern]] = None    # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation : ClassVar[bool] = True        # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    ### Escaping
    field_escape : ClassVar[Optional[str]] = None               # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote : ClassVar[bool] = True                  # Escape quote string defined in field_quote
    field_escape_pattern : ClassVar[Optional[Pattern]] = None   # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote       : ClassVar[Optional[str]] = None    # string quoting character (added as escaping character)
    escape_char     : ClassVar[Optional[str]] = None    # Escaping character for special characrers inside string
    wildcard_multi  : ClassVar[Optional[str]] = None    # Character used as multi-character wildcard
    wildcard_single : ClassVar[Optional[str]] = None    # Character used as single-character wildcard
    add_escaped     : ClassVar[str] = ""                # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = ""                # Characters filtered
    bool_values     : ClassVar[Dict[bool, Optional[str]]] = {   # Values to which boolean values are mapped.
        True: None,
        False: None,
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression : ClassVar[Optional[str]] = None
    endswith_expression   : ClassVar[Optional[str]] = None
    contains_expression   : ClassVar[Optional[str]] = None
    wildcard_match_expression : ClassVar[Optional[str]] = None      # Special expression if wildcards can't be matched with the eq_token operator

    # Regular expressions
    re_expression : ClassVar[Optional[str]] = None      # Regular expression query as format string with placeholders {field} and {regex}
    re_escape_char : ClassVar[Optional[str]] = None     # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ()               # List of strings that are escaped

    # cidr expressions
    cidr_wildcard : ClassVar[Optional[str]] = None    # Character used as single wildcard
    cidr_expression : ClassVar[Optional[str]] = None    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_in_list_expression : ClassVar[Optional[str]] = None    # CIDR expression query as format string with placeholders {field} = in({list})

    # Numeric comparison operators
    compare_op_expression : ClassVar[Optional[str]] = None      # Compare operation query as format string with placeholders {field}, {operator} and {value}
    compare_operators : ClassVar[Optional[Dict[SigmaCompareExpression.CompareOperators, str]]] = None       # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression

    # Null/None expressions
    field_null_expression : ClassVar[Optional[str]] = None          # Expression for field has null value as format string with {field} placeholder for field name

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    field_in_list_expression : ClassVar[Optional[str]] = None       # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[Optional[str]] = None      # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    and_in_operator : ClassVar[Optional[str]] = None     # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator : ClassVar[Optional[str]] = None     # List element separator

    # Value not bound to a field
    unbound_value_str_expression : ClassVar[Optional[str]] = None   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[Optional[str]] = None   # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression : ClassVar[Optional[str]] = None   # Expression for regular expression not bound to a field as format string with placeholder {value}

    # Query finalization: appending and concatenating deferred query part
    deferred_start : ClassVar[Optional[str]] = None                 # String used as separator between main query and deferred parts
    deferred_separator : ClassVar[Optional[str]] = None             # String used to join multiple deferred query parts
    deferred_only_query : ClassVar[Optional[str]] = None            # String used as query if final query only contains deferred expression

    def compare_precedence(self, outer : ConditionItem, inner : ConditionItem) -> bool:
        """
        Compare precedence of outer and inner condition items. Return True if precedence of
        enclosing condition item (outer) is lower than the contained (inner) condition item.
        In this case, no additional grouping is required.
        """
        outer_class = outer.__class__
        # Special case: Conditions containing a SigmaExpansion value convert into OR conditions and therefore the precedence has to be handled the same way.
        if isinstance(inner, ( ConditionFieldEqualsValueExpression, ConditionValueExpression )) and isinstance(inner.value, SigmaExpansion):
            inner_class = ConditionOR
        else:
            inner_class = inner.__class__

        try:
            idx_inner = self.precedence.index(inner_class)
        except ValueError:      # ConditionItem not in precedence tuple
            idx_inner = -1      # Assume precedence of inner condition item is higher than the outer

        return idx_inner <= self.precedence.index(outer_class)

    def convert_condition_group(self, cond : ConditionItem, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Group condition item."""
        return self.group_expression.format(expr=self.convert_condition(cond, state))

    def convert_condition_or(self, cond : ConditionOR, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of OR conditions."""
        try:
            if self.token_separator == self.or_token:   # don't repeat the same thing triple times if separator equals or token
                joiner = self.or_token
            else:
                joiner = self.token_separator + self.or_token + self.token_separator

            return joiner.join((
                    converted
                    for converted in (
                        self.convert_condition(arg, state) if self.compare_precedence(cond, arg)
                        else self.convert_condition_group(arg, state)
                        for arg in cond.args
                    )
                    if converted is not None and not isinstance(converted, DeferredQueryExpression)
                ))
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Operator 'or' not supported by the backend")

    def convert_condition_as_in_expression(self, cond : Union[ConditionOR, ConditionAND], state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field in value list conditions."""
        return self.field_in_list_expression.format(
            field=self.escape_and_quote_field(cond.args[0].field),       # The assumption that the field is the same for all argument is valid because this is checked before
            op=self.or_in_operator if isinstance(cond, ConditionOR) else self.and_in_operator,
            list=self.list_separator.join([
                self.str_quote + self.convert_value_str(arg.value, state) + self.str_quote
                if isinstance(arg.value, SigmaString)   # string escaping and qouting
                else str(arg.value)       # value is number
                for arg in cond.args
            ]),
        )

    def convert_condition_and(self, cond : ConditionAND, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of AND conditions."""
        try:
            if self.token_separator == self.and_token:   # don't repeat the same thing triple times if separator equals and token
                joiner = self.and_token
            else:
                joiner = self.token_separator + self.and_token + self.token_separator

            return joiner.join((
                    converted
                    for converted in (
                        self.convert_condition(arg, state) if self.compare_precedence(cond, arg)
                        else self.convert_condition_group(arg, state)
                        for arg in cond.args
                    )
                    if converted is not None and not isinstance(converted, DeferredQueryExpression)
                ))
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Operator 'and' not supported by the backend")

    def convert_condition_not(self, cond : ConditionNOT, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions."""
        arg = cond.args[0]
        try:
            if arg.__class__ in self.precedence:        # group if AND or OR condition is negated
                return self.not_token + self.token_separator + self.convert_condition_group(arg, state)
            else:
                expr = self.convert_condition(arg, state)
                if isinstance(expr, DeferredQueryExpression):      # negate deferred expression and pass it to parent
                    return expr.negate()
                else:                                             # convert negated expression to string
                    return self.not_token + self.token_separator + expr
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend")

    def escape_and_quote_field(self, field_name : str) -> str:
        """
        Escape field name by prepending pattern matches of field_escape_pattern with field_escape
        string. If field_escape_quote is set to True (default) and field escaping string is defined
        in field_escape, all instances of the field quoting character are escaped before quoting.

        Quote field name with field_quote if field_quote_pattern (doesn't) matches the original
        (unescaped) field name. If field_quote_pattern_negation is set to True (default) the pattern matching
        result is negated, which is the default behavior. In this case the field name is quoted if
        the pattern doesn't matches.
        """
        if self.field_escape is not None:               # field name escaping
            if self.field_escape_pattern is not None:   # Match all occurrences of field_escpae_pattern if defined and initialize match position set with result.
                match_positions = {
                    match.start()
                    for match in self.field_escape_pattern.finditer(field_name)
                }
            else:
                match_positions = set()

            if self.field_escape_quote and self.field_quote is not None:         # Add positions of quote string to match position set
                re_quote = re.compile(re.escape(self.field_quote))
                match_positions.update((
                    match.start()
                    for match in re_quote.finditer(field_name)
                ))

            if len(match_positions) > 0:    # found matches, escape them
                r = [0] + list(sorted(match_positions)) + [len(field_name)]
                escaped_field_name = ""
                for i in range(len(r) - 1):    # TODO: from Python 3.10 this can be replaced with itertools.pairwise(), but for now we keep support for Python <3.10
                    if i == 0:          # The first range is passed to the result without escaping
                        escaped_field_name += field_name[r[i]:r[i + 1]]
                    else:               # Subsequent ranges are positions of matches and therefore are prepended with field_escape
                        escaped_field_name += self.field_escape + field_name[r[i]:r[i + 1]]
            else:                       # no matches, just pass original field name without escaping
                escaped_field_name = field_name
        else:
            escaped_field_name = field_name

        if self.field_quote is not None:                # Field quoting
            if self.field_quote_pattern is not None:    # Match field quote pattern...
                quote = bool(self.field_quote_pattern.match(escaped_field_name))
                if self.field_quote_pattern_negation:   # ...negate result of matching, if requested...
                    quote = not quote
            else:
                quote = True

            if quote:                                   #  ...and quote if pattern (doesn't) matches
                return self.field_quote + escaped_field_name + self.field_quote
        return escaped_field_name

    def convert_value_str(self, s : SigmaString, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert a SigmaString into a plain string which can be used in query."""
        return s.convert(
            self.escape_char,
            self.wildcard_multi,
            self.wildcard_single,
            self.str_quote + self.add_escaped,
            self.filter_chars,
        )

    def convert_condition_field_eq_val_str(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        try:
            if (                                                                # Check conditions for usage of 'startswith' operator
                self.startswith_expression is not None                            # 'startswith' operator is defined in backend
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)            # String ends with wildcard
                and not cond.value[:-1].contains_special()                      # Remainder of string doesn't contains special characters
                ):
                expr = self.startswith_expression                               # If all conditions are fulfilled, use 'startswith' operartor instead of equal token
                value = cond.value[:-1]
            elif (                                                              # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contains further special characters
                self.endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:].contains_special()
                ):
                expr = self.endswith_expression
                value = cond.value[1:]
            elif (                                                              # contains: string starts and ends with wildcard
                self.contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and not cond.value[1:-1].contains_special()
                ):
                expr = self.contains_expression
                value = cond.value[1:-1]
            elif (                                                              # wildcard match expression: string contains wildcard
                self.wildcard_match_expression is not None
                and cond.value.contains_special()
                ):
                expr = self.wildcard_match_expression
                value = cond.value
            else:
                expr =  "{field}" + self.eq_token + self.str_quote + "{value}" + self.str_quote # [New]
                value = cond.value
            return expr.format(field=self.escape_and_quote_field(cond.field), value=self.convert_value_str(value, state))
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Field equals string value expressions with strings are not supported by the backend.")

    def convert_condition_field_eq_val_num(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = number value expressions"""
        try:
            return self.escape_and_quote_field(cond.field) + self.eq_token + str(cond.value)
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Field equals numeric value expressions are not supported by the backend.")

    def convert_condition_field_eq_val_bool(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = bool value expressions"""
        try:
            return self.escape_and_quote_field(cond.field) + self.eq_token + self.bool_values[cond.value.boolean]
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Field equals numeric value expressions are not supported by the backend.")

    def convert_value_re(self, r : SigmaRegularExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert regular expression into string representation used in query."""
        return r.escape(self.re_escape, self.re_escape_char)

    def convert_value_cidr(self, ip : SigmaCIDRExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Convert regular expression into string representation used in query."""
        return ip.convert(join_expr=self.or_token,wildcard=self.cidr_wildcard)

    def convert_condition_field_eq_val_re(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches regular expression value expressions."""
        return self.re_expression.format(
            field=self.escape_and_quote_field(cond.field),
            regex=self.convert_value_re(cond.value, state),
        )

    def convert_condition_field_eq_val_re_contains(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only regular expressions."""
        return self.re_expression.format(
            field=self.escape_and_quote_field(cond.field),
            regex=self.convert_value_re(cond.value, state),
        )

    def convert_condition_field_eq_val_cidr(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches regular expression value expressions."""
        convert_str = self.convert_value_cidr(cond.value, state)
        if self.or_token in convert_str:
            list_ip = convert_str.split(self.or_token)
            if self.cidr_wildcard == None:
                    return self.cidr_in_list_expression.format(
                        field=self.escape_and_quote_field(cond.field),
                        list=self.list_separator.join([str(v) for v in list_ip])
                    )
            else:
                return self.cidr_in_list_expression.format(
                    field=self.escape_and_quote_field(cond.field),
                    list=self.list_separator.join([ self.str_quote + str(v) + self.str_quote for v in list_ip])
                )
        else:
            if self.cidr_wildcard == None:
                return self.cidr_expression.format(
                    field=self.escape_and_quote_field(cond.field),
                    value=convert_str,
                )
            else:
                return self.cidr_expression.format(
                    field=self.escape_and_quote_field(cond.field),
                    value=self.str_quote + convert_str + self.str_quote,
                )

    def convert_condition_field_compare_op_val(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of numeric comparison operations into queries."""
        return self.compare_op_expression.format(
            field=self.escape_and_quote_field(cond.field),
            operator=self.compare_operators[cond.value.op],
            value=cond.value.number,
        )

    def convert_condition_field_eq_val_null(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field is null expression value expressions"""
        return self.field_null_expression.format(field=self.escape_and_quote_field(cond.field))

    def convert_condition_field_eq_query_expr(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field is null expression value expressions"""
        return cond.value.finalize(field=self.escape_and_quote_field(cond.field))

    def convert_condition_val_str(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only strings."""
        return self.unbound_value_str_expression.format(value=self.convert_value_str(cond.value, state))

    def convert_condition_val_num(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only numbers."""
        return self.unbound_value_num_expression.format(value=cond.value)

    def convert_condition_val_re(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only regular expressions."""
        return self.unbound_value_re_expression.format(value=self.convert_value_re(cond.value, state))

    def convert_condition_query_expr(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only plain query expressions."""
        return cond.value.finalize()

    def finalize_query(self, rule : SigmaRule, query : Union[str, DeferredQueryExpression], index : int, state : ConversionState, output_format : str) -> Union[str, DeferredQueryExpression]:
        """
        Finalize query by appending deferred query parts to the main conversion result as specified
        with deferred_start and deferred_separator.
        """
        if state.has_deferred():
            if isinstance(query, DeferredQueryExpression):
                query = self.deferred_only_query
            return super().finalize_query(rule,
                query + self.deferred_start + self.deferred_separator.join((
                    deferred_expression.finalize_expression()
                    for deferred_expression in state.deferred
                    )
                ),
                index, state, output_format
            )
        else:
            return super().finalize_query(rule, query, index, state, output_format)
