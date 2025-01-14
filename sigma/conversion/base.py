from abc import ABC, abstractmethod
from collections import ChainMap, defaultdict
import re

from sigma.correlations import (
    SigmaCorrelationCondition,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationFieldAlias,
    SigmaCorrelationFieldAliases,
    SigmaCorrelationRule,
    SigmaCorrelationTimespan,
    SigmaCorrelationType,
    SigmaCorrelationTypeLiteral,
    SigmaRuleReference,
)

from sigma.exceptions import (
    ExceptionOnUsage,
    SigmaBackendError,
    SigmaConfigurationError,
    SigmaConversionError,
    SigmaError,
    SigmaValueError,
)
from sigma.conversion.deferred import DeferredQueryExpression
from typing import Pattern, Union, ClassVar, Optional, Tuple, List, Dict, Any, Type
from sigma.processing.pipeline import ProcessingPipeline
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.conditions import (
    ConditionItem,
    ConditionOR,
    ConditionAND,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
    ConditionValueExpression,
    ConditionType,
)
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaRegularExpressionFlag,
    SigmaString,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaCompareExpression,
    SigmaNull,
    SigmaQueryExpression,
    SigmaCIDRExpression,
    SpecialChars,
)
from sigma.conversion.state import ConversionState


class Backend(ABC):
    """
    Base class for Sigma conversion backends. A backend is made up from the following elements:

    * Some metadata about the properties of the backend.
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
      implemented in similar methods. The default format can be specified in the class variable default_format.

    Implementation of a backend:

    1. Implement conversion of condition elements in convert_condition_*. The output can be an intermediate
       or the final query representation.
    2. If required, implement a per-query finalization step in finalize_query. Each Sigma rule condition
       results in a query. This can embed the generated query into other structures (e.g. boilerplate code,
       prefix/postfix query parts) or convert the intermediate into a final query representation.
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

    name: ClassVar[str] = "Base backend"  # A descriptive name of the backend
    formats: ClassVar[Dict[str, str]] = (
        {  # Output formats provided by the backend as name -> description mapping. The name should match to finalize_output_<name>.
            "default": "Default output format",
        }
    )
    requires_pipeline: ClassVar[bool] = (
        False  # Does the backend requires that a processing pipeline is provided?
    )

    # Backends can offer different methods of correlation query generation. That are described by
    # correlation_methods:
    correlation_methods: ClassVar[Optional[Dict[str, str]]] = None
    # The following class variable defines the default method that should be chosen if none is provided.
    default_correlation_method: ClassVar[str] = "default"

    processing_pipeline: ProcessingPipeline
    last_processing_pipeline: ProcessingPipeline
    backend_processing_pipeline: ClassVar[ProcessingPipeline] = ProcessingPipeline()
    output_format_processing_pipeline: ClassVar[Dict[str, ProcessingPipeline]] = defaultdict(
        ProcessingPipeline
    )
    default_format: ClassVar[str] = "default"
    collect_errors: bool = False
    errors: List[Tuple[SigmaRule, SigmaError]]

    # in-expressions
    convert_or_as_in: ClassVar[bool] = False  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = False  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = (
        False  # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    )

    # not exists: convert as "not exists-expression" or as dedicated expression
    explicit_not_exists_expression: ClassVar[bool] = False

    def __init__(
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        collect_errors: bool = False,
        **backend_options: Dict,
    ):
        self.processing_pipeline = processing_pipeline
        self.errors = list()
        self.collect_errors = collect_errors
        self.backend_options = backend_options

    def convert(
        self,
        rule_collection: SigmaCollection,
        output_format: Optional[str] = None,
        correlation_method: Optional[str] = None,
    ) -> Any:
        """
        Convert a Sigma ruleset into the target data structure. Usually the result are one or
        multiple queries, but might also be some arbitrary data structure required for further
        processing.
        """
        rule_collection.resolve_rule_references()
        queries = [
            query
            for rule in rule_collection.rules
            for query in (
                self.convert_rule(rule, output_format or self.default_format)
                if isinstance(rule, SigmaRule)
                else self.convert_correlation_rule(
                    rule, output_format or self.default_format, correlation_method
                )
            )
        ]
        return self.finalize(queries, output_format or self.default_format)

    def convert_rule(self, rule: SigmaRule, output_format: Optional[str] = None) -> List[Any]:
        """
        Convert a single Sigma rule into the target data structure (usually query, see above).
        """
        try:
            self.last_processing_pipeline = (
                self.backend_processing_pipeline
                + self.processing_pipeline
                + self.output_format_processing_pipeline[output_format or self.default_format]
            )
            self.last_processing_pipeline.vars.update(
                {"backend_" + key: value for key, value in self.backend_options.items()}
            )

            error_state = "applying processing pipeline on"
            self.last_processing_pipeline.apply(rule)  # 1. Apply transformations

            # 2. Convert conditions
            error_state = "converting"
            states = [
                ConversionState(processing_state=dict(self.last_processing_pipeline.state))
                for _ in rule.detection.parsed_condition
            ]
            queries = [
                self.convert_condition(cond.parsed, states[index])
                for index, cond in enumerate(rule.detection.parsed_condition)
            ]

            error_state = "finalizing query for"
            # 3. Postprocess generated query if not part of a correlation rule
            finalized_queries = (
                [
                    self.finalize_query(
                        rule,
                        query,
                        index,
                        states[index],
                        output_format or self.default_format,
                    )
                    for index, query in enumerate(queries)
                ]
                if not rule._backreferences
                else queries
            )
            rule.set_conversion_result(finalized_queries)
            rule.set_conversion_states(states)
            if rule._output:
                return finalized_queries
            else:
                return []
        except SigmaError as e:
            if self.collect_errors:
                self.errors.append((rule, e))
                return []
            else:
                raise e
        except (
            Exception
        ) as e:  # enrich all other exceptions with Sigma-specific context information
            msg = f" (while {error_state} rule {str(rule.source)})"
            if len(e.args) > 1:
                e.args = (e.args[0] + msg,) + e.args[1:]
            else:
                e.args = (e.args[0] + msg,)
            raise

    def decide_convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> bool:
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
        if (
            not self.convert_or_as_in
            and isinstance(cond, ConditionOR)
            or not self.convert_and_as_in
            and isinstance(cond, ConditionAND)
        ):
            return False

        # Check if more than one argument is present
        # if len(cond.args <= 1):
        #    return False

        # All arguments of the given condition must reference a field
        if not all((isinstance(arg, ConditionFieldEqualsValueExpression) for arg in cond.args)):
            return False

        # Build a set of all fields appearing in condition arguments
        fields = {arg.field for arg in cond.args}
        # All arguments must reference the same field
        if len(fields) != 1:
            return False

        # All argument values must be strings or numbers
        if not all([isinstance(arg.value, (SigmaString, SigmaNumber)) for arg in cond.args]):
            return False

        # Check for plain strings if wildcards are not allowed for string expressions.
        if not self.in_expressions_allow_wildcards and any(
            [
                arg.value.contains_special()
                for arg in cond.args
                if isinstance(arg.value, SigmaString)
            ]
        ):
            return False

        # All checks passed, expression can be converted to in-expression
        return True

    @abstractmethod
    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Any:
        """Conversion of OR or AND conditions into "field in (value list)" expressions."""

    @abstractmethod
    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> Any:
        """Conversion of OR conditions."""

    @abstractmethod
    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> Any:
        """Conversion of AND conditions."""

    @abstractmethod
    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Any:
        """Conversion of NOT conditions."""

    @abstractmethod
    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of field = string value expressions"""

    @abstractmethod
    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of field = cased string value expressions"""

    @abstractmethod
    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of field = number value expressions"""

    @abstractmethod
    def convert_condition_field_eq_val_bool(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of field = boolean value expressions"""

    @abstractmethod
    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of field matches regular expression value expressions"""

    @abstractmethod
    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of field matches CIDR expression value expressions"""

    @abstractmethod
    def convert_condition_field_compare_op_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of field matches regular expression value expressions"""

    @abstractmethod
    def convert_condition_field_eq_field(
        self, cond: SigmaFieldReference, state: ConversionState
    ) -> Any:
        """Conversion of field equals another field expressions."""

    @abstractmethod
    def convert_condition_field_eq_val_null(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of field is null expression value expressions"""

    @abstractmethod
    def convert_condition_field_exists(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of field exists expressions"""

    @abstractmethod
    def convert_condition_field_not_exists(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of field not exists expressions"""

    def convert_condition_field_eq_val_exists(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Dispatch conversion of field exists expressions to appropriate method."""
        if (
            self.explicit_not_exists_expression
        ):  # Call distinguished methods if there is an explicit expression for field existence and non-existence.
            if cond.value:
                return self.convert_condition_field_exists(cond, state)
            else:
                return self.convert_condition_field_not_exists(cond, state)
        else:  # If there are no distinguished expressions for field (non-)existence in the target query language, just negate the expression if necessary.
            if cond.value:
                return self.convert_condition_field_exists(cond, state)
            else:
                return self.convert_condition_not(
                    ConditionNOT(
                        [ConditionFieldEqualsValueExpression(cond.field, SigmaExists(True))],
                        cond.source,
                    ),
                    state,
                )

    @abstractmethod
    def convert_condition_field_eq_query_expr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of query expressions bound to a field."""

    def convert_condition_field_eq_expansion(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """
        Convert each value of the expansion with the field from the containing condition and OR-link
        all converted subconditions.
        """
        or_cond = ConditionOR(
            [ConditionFieldEqualsValueExpression(cond.field, value) for value in cond.value.values],
            cond.source,
        )
        return self.convert_condition_or(or_cond, state)

    def convert_condition_field_eq_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Conversion dispatcher of field = value conditions. Dispatches to value-specific methods."""
        if isinstance(cond.value, SigmaCasedString):
            return self.convert_condition_field_eq_val_str_case_sensitive(cond, state)
        elif isinstance(cond.value, SigmaString):
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
        elif isinstance(cond.value, SigmaFieldReference):
            return self.convert_condition_field_eq_field(cond, state)
        elif isinstance(cond.value, SigmaNull):
            return self.convert_condition_field_eq_val_null(cond, state)
        elif isinstance(cond.value, SigmaQueryExpression):
            return self.convert_condition_field_eq_query_expr(cond, state)
        elif isinstance(cond.value, SigmaExists):
            return self.convert_condition_field_eq_val_exists(cond, state)
        elif isinstance(cond.value, SigmaExpansion):
            return self.convert_condition_field_eq_expansion(cond, state)
        else:  # pragma: no cover
            raise TypeError(
                "Unexpected value type class in condition parse tree: "
                + cond.value.__class__.__name__
            )

    @abstractmethod
    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of string-only conditions."""

    @abstractmethod
    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of number-only conditions."""

    @abstractmethod
    def convert_condition_val_re(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of regexp-only conditions."""

    @abstractmethod
    def convert_condition_query_expr(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Any:
        """Conversion of query expressions without field association."""

    def convert_condition_val(self, cond: ConditionValueExpression, state: ConversionState) -> Any:
        """Conversion of value-only conditions."""
        if isinstance(cond.value, SigmaString):
            return self.convert_condition_val_str(cond, state)
        elif isinstance(cond.value, SigmaNumber):
            return self.convert_condition_val_num(cond, state)
        elif isinstance(cond.value, SigmaBool):
            raise SigmaValueError(
                "Boolean values can't appear as standalone value without a field name."
            )
        elif isinstance(cond.value, SigmaRegularExpression):
            return self.convert_condition_val_re(cond, state)
        elif isinstance(cond.value, SigmaCIDRExpression):
            raise SigmaValueError(
                "CIDR values can't appear as standalone value without a field name."
            )
        elif isinstance(cond.value, SigmaQueryExpression):
            return self.convert_condition_query_expr(cond, state)
        else:  # pragma: no cover
            raise TypeError(
                "Unexpected value type class in condition parse tree: "
                + cond.value.__class__.__name__
            )

    def convert_condition(self, cond: ConditionType, state: ConversionState) -> Any:
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
        else:  # pragma: no cover
            raise TypeError(
                "Unexpected data type in condition parse tree: " + cond.__class__.__name__
            )

    def convert_correlation_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[Any]:
        """
        Convert a correlation rule into the target data structure (usually query).

        Args:
            rule (SigmaCorrelationRule): The correlation rule to be converted.
            output_format (Optional[str]): The desired output format. Defaults to None.
            method (Optional[str]): The correlation method to be used. Defaults to None.

        Returns:
            Any: The converted data structure.

        Raises:
            NotImplementedError: If the conversion for the given correlation rule type is not implemented.
        """
        if self.correlation_methods is None:
            raise NotImplementedError("Backend does not support correlation rules.")
        method = method or self.default_correlation_method
        if method not in self.correlation_methods:
            raise SigmaConversionError(
                f"Correlation method '{method}' is not supported by backend '{self.name}'."
            )
        self.last_processing_pipeline.apply(rule)
        correlation_methods = {
            SigmaCorrelationType.EVENT_COUNT: self.convert_correlation_event_count_rule,
            SigmaCorrelationType.VALUE_COUNT: self.convert_correlation_value_count_rule,
            SigmaCorrelationType.TEMPORAL: self.convert_correlation_temporal_rule,
            SigmaCorrelationType.TEMPORAL_ORDERED: self.convert_correlation_temporal_ordered_rule,
        }
        if rule.type not in correlation_methods:
            raise NotImplementedError(
                f"Conversion of correlation rule type {rule.type} is not implemented."
            )

        # Convert the correlation rule depending on its type
        queries = correlation_methods[rule.type](rule, output_format, method)

        states = [
            ConversionState(processing_state=dict(self.last_processing_pipeline.state))
            for _ in queries
        ]

        # Apply the finalization step
        finalized_queries = [
            self.finalize_query(
                rule,
                query,
                index,
                states[index],
                output_format or self.default_format,
            )
            for index, query in enumerate(queries)
        ]
        rule.set_conversion_result(finalized_queries)
        rule.set_conversion_states(states)

        return finalized_queries

    @abstractmethod
    def convert_correlation_event_count_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[Any]:
        """
        Convert an event count correlation rule into the target data structure (usually query).

        Args:
            rule (SigmaCorrelationRule): The event count correlation rule to be converted.
            output_format (Optional[str]): The output format for the conversion. Defaults to None.
            method (Optional[str]): The correlation method to be used. Defaults to None.

        Returns:
            Any: The converted data structure.
        """

    @abstractmethod
    def convert_correlation_value_count_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[Any]:
        """
        Convert a value count correlation rule into the target data structure (usually query).

        Args:
            rule (SigmaCorrelationRule): The value count correlation rule to be converted.
            output_format (Optional[str]): The output format for the conversion. Defaults to None.
            method (Optional[str]): The correlation method to be used. Defaults to None.

        Returns:
            Any: The converted data structure.
        """

    @abstractmethod
    def convert_correlation_temporal_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[Any]:
        """
        Convert a temporal correlation rule into the target data structure (usually query).

        Args:
            rule (SigmaCorrelationRule): The temporal correlation rule to be converted.
            output_format (Optional[str]): The output format for the conversion. Defaults to None.
            method (Optional[str]): The correlation method to be used. Defaults to None.

        Returns:
            Any: The converted data structure.
        """

    @abstractmethod
    def convert_correlation_temporal_ordered_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[Any]:
        """
        Convert an ordered temporal correlation rule into the target data structure (usually query).

        Args:
            rule (SigmaCorrelationRule): The ordered temporal correlation rule to be converted.
            output_format (Optional[str]): The output format for the conversion. Defaults to None.
            method (Optional[str]): The correlation method to be used. Defaults to None.

        Returns:
            Any: The converted data structure.
        """

    def finalize_query(
        self,
        rule: SigmaRule,
        query: Any,
        index: int,
        state: ConversionState,
        output_format: str,
    ):
        """
        Finalize query. Dispatches to format-specific method. The index parameter enumerates generated queries if the
        conversion of a Sigma rule results in multiple queries.

        This is the place where syntactic elements of the target format for the specific query are added,
        e.g. adding query metadata.
        """
        backend_query = self.__getattribute__("finalize_query_" + output_format)(
            rule, query, index, state
        )
        return self.last_processing_pipeline.postprocess_query(rule, backend_query)

    def finalize_query_default(
        self, rule: SigmaRule, query: Any, index: int, state: ConversionState
    ) -> Any:
        """
        Finalize conversion result of a query. Handling of deferred query parts must be implemented by overriding
        this method.
        """
        return query

    def finalize(self, queries: List[Any], output_format: str):
        """Finalize output. Dispatches to format-specific method."""
        output = self.__getattribute__("finalize_output_" + output_format)(queries)
        return self.last_processing_pipeline.finalize(output)

    def finalize_output_default(self, queries: List[Any]) -> Any:
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
    precedence: ClassVar[Tuple[Type[ConditionItem], Type[ConditionItem], Type[ConditionItem]]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[Optional[str]] = (
        None  # Expression for precedence override grouping as format string with {expr} placeholder
    )
    parenthesize: bool = (
        False  # Reflect parse tree by putting parenthesis around all expressions - use this for target systems without strict precedence rules.
    )

    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[Optional[str]] = None
    and_token: ClassVar[Optional[str]] = None
    not_token: ClassVar[Optional[str]] = None
    eq_token: ClassVar[Optional[str]] = (
        None  # Token inserted between field and value (without separator)
    )
    eq_expression: ClassVar[str] = (
        "{field}{backend.eq_token}{value}"  # Expression for field = value
    )

    # Query structure
    # The generated query can be embedded into further structures. One common example are data
    # source commands that are prepended to the matching condition and specify data repositories or
    # tables from which the data is queried.
    # This is specified as format string that contains the following placeholders:
    # * {query}: The generated query
    # * {rule}: The Sigma rule from which the query was generated
    # * {state}: Conversion state at the end of query generation. This state is initialized with the
    #   pipeline state.
    query_expression: ClassVar[str] = "{query}"
    # The following dict defines default values for the conversion state. They are used if
    # the respective state is not set.
    state_defaults: ClassVar[Dict[str, str]] = dict()

    # String output
    ## Fields
    ### Quoting
    field_quote: ClassVar[Optional[str]] = (
        None  # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    )
    field_quote_pattern: ClassVar[Optional[Pattern]] = (
        None  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    )
    field_quote_pattern_negation: ClassVar[bool] = (
        True  # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).
    )

    ### Escaping
    field_escape: ClassVar[Optional[str]] = (
        None  # Character to escape particular parts defined in field_escape_pattern.
    )
    field_escape_quote: ClassVar[bool] = True  # Escape quote string defined in field_quote
    field_escape_pattern: ClassVar[Optional[Pattern]] = (
        None  # All matches of this pattern are prepended with the string contained in field_escape.
    )

    # Characters to escape in addition in regular expression representation of string (regex
    # template variable) to default escaping characters.
    add_escaped_re: ClassVar[str] = ""

    ## Values
    ### String quoting
    str_quote: ClassVar[str] = ""  # string quoting character (added as escaping character)
    str_quote_pattern: ClassVar[Optional[Pattern]] = (
        None  # Quote string values that match (or don't match) this pattern
    )
    str_quote_pattern_negation: ClassVar[bool] = True  # Negate str_quote_pattern result
    ### String escaping and filtering
    escape_char: ClassVar[Optional[str]] = (
        None  # Escaping character for special characters inside string
    )
    wildcard_multi: ClassVar[Optional[str]] = None  # Character used as multi-character wildcard
    wildcard_single: ClassVar[Optional[str]] = None  # Character used as single-character wildcard
    add_escaped: ClassVar[str] = ""  # Characters quoted in addition to wildcards and string quote
    filter_chars: ClassVar[str] = ""  # Characters filtered
    ### Booleans
    bool_values: ClassVar[Dict[bool, Optional[str]]] = (
        {  # Values to which boolean values are mapped.
            True: None,
            False: None,
        }
    )

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[Optional[str]] = None
    startswith_expression_allow_special: ClassVar[bool] = False
    endswith_expression: ClassVar[Optional[str]] = None
    endswith_expression_allow_special: ClassVar[bool] = False
    contains_expression: ClassVar[Optional[str]] = None
    contains_expression_allow_special: ClassVar[bool] = False
    wildcard_match_expression: ClassVar[Optional[str]] = (
        None  # Special expression if wildcards can't be matched with the eq_token operator.
    )

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression: ClassVar[Optional[str]] = None
    re_escape_char: ClassVar[Optional[str]] = (
        None  # Character used for escaping in regular expressions
    )
    re_escape: ClassVar[Tuple[str]] = ()  # List of strings that are escaped
    re_escape_escape_char: bool = True  # If True, the escape character is also escaped
    re_flag_prefix: bool = (
        True  # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False.
    )
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    re_flags: Dict[SigmaRegularExpressionFlag, str] = SigmaRegularExpression.sigma_to_re_flag

    # Case sensitive string matching expression. String is quoted/escaped like a normal string.
    # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.
    # {regex} contains the value expressed as regular expression.
    case_sensitive_match_expression: ClassVar[Optional[str]] = None
    # Case sensitive string matching operators similar to standard string matching. If not provided,
    # case_sensitive_match_expression is used.
    case_sensitive_startswith_expression: ClassVar[Optional[str]] = None
    case_sensitive_startswith_expression_allow_special: ClassVar[bool] = False
    case_sensitive_endswith_expression: ClassVar[Optional[str]] = None
    case_sensitive_endswith_expression_allow_special: ClassVar[bool] = False
    case_sensitive_contains_expression: ClassVar[Optional[str]] = None
    case_sensitive_contains_expression_allow_special: ClassVar[bool] = False

    # CIDR expressions: define CIDR matching if backend has native support. Else pySigma expands
    # CIDR values into string wildcard matches.
    cidr_expression: ClassVar[Optional[str]] = (
        None  # CIDR expression query as format string with placeholders {field}, {value} (the whole CIDR value), {network} (network part only), {prefixlen} (length of network mask prefix) and {netmask} (CIDR network mask only)
    )

    # Numeric comparison operators
    compare_op_expression: ClassVar[Optional[str]] = (
        None  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    )
    compare_operators: ClassVar[Optional[Dict[SigmaCompareExpression.CompareOperators, str]]] = (
        None  # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    )

    # Expression for comparing two event fields
    field_equals_field_expression: ClassVar[Optional[str]] = (
        None  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    )
    field_equals_field_escaping_quoting: Tuple[bool, bool] = (
        True,
        True,
    )  # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    field_null_expression: ClassVar[Optional[str]] = (
        None  # Expression for field has null value as format string with {field} placeholder for field name
    )

    # Field existence condition expressions.
    field_exists_expression: ClassVar[Optional[str]] = (
        None  # Expression for field existence as format string with {field} placeholder for field name
    )
    field_not_exists_expression: ClassVar[Optional[str]] = (
        None  # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.
    )

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    field_in_list_expression: ClassVar[Optional[str]] = (
        None  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    )
    or_in_operator: ClassVar[Optional[str]] = (
        None  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    )
    and_in_operator: ClassVar[Optional[str]] = (
        None  # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    )
    list_separator: ClassVar[Optional[str]] = None  # List element separator

    # Value not bound to a field
    unbound_value_str_expression: ClassVar[Optional[str]] = (
        None  # Expression for string value not bound to a field as format string with placeholder {value} and {regex} (value as regular expression)
    )
    unbound_value_num_expression: ClassVar[Optional[str]] = (
        None  # Expression for number value not bound to a field as format string with placeholder {value} and {regex} (value as regular expression)
    )
    unbound_value_re_expression: ClassVar[Optional[str]] = (
        None  # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression
    )

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[Optional[str]] = (
        None  # String used as separator between main query and deferred parts
    )
    deferred_separator: ClassVar[Optional[str]] = (
        None  # String used to join multiple deferred query parts
    )
    deferred_only_query: ClassVar[Optional[str]] = (
        None  # String used as query if final query only contains deferred expression
    )

    ### Correlation rule templates
    ## Correlation query frame
    # The correlation query frame is the basic structure of a correlation query for each correlation
    # type. It contains the following placeholders:
    # * {search} is the search expression generated by the correlation query search phase.
    # * {typing} is the event typing expression generated by the correlation query typing phase.
    # * {aggregate} is the aggregation expression generated by the correlation query aggregation
    #   phase.
    # * {condition} is the condition expression generated by the correlation query condition phase.
    # If a correlation query template for a specific correlation type is not defined, the default correlation query template is used.
    default_correlation_query: ClassVar[Optional[Dict[str, str]]] = None
    event_count_correlation_query: ClassVar[Optional[Dict[str, str]]] = None
    value_count_correlation_query: ClassVar[Optional[Dict[str, str]]] = None
    temporal_correlation_query: ClassVar[Optional[Dict[str, str]]] = None
    temporal_ordered_correlation_query: ClassVar[Optional[Dict[str, str]]] = None

    ## Correlation query search phase
    # The first step of a correlation query is to match events described by the referred Sigma
    # rules. A main difference is made between single and multiple rule searches.
    # A single rule search expression defines the search expression emitted if only one rule is
    # referred by the correlation rule. It contains the following placeholders:
    # * {rule} is the referred Sigma rule.
    # * {ruleid} is the rule name or if not available the id of the rule.
    # * {query} is the query generated from the referred Sigma rule.
    # * {normalization} is the expression that normalizes the rule field names to unified alias
    #   field names that can be later used for aggregation. The expression is defined by
    #   correlation_search_field_normalization_expression defined below.
    correlation_search_single_rule_expression: ClassVar[Optional[str]] = None
    # If no single rule query expression is defined, the multi query template expressions below are
    # used and must be suitable for this purpose.

    # A multiple rule search expression defines the search expression emitted if multiple rules are
    # referred by the correlation rule. This is split into the expression for the query itself:
    correlation_search_multi_rule_expression: ClassVar[Optional[str]] = None
    # This template contains only one placeholder {queries} which contains the queries generated
    # from single queries joined with a query separator:
    # * A query template for each query generated from the referred Sigma rules similar to the
    #   search_single_rule_expression defined above:
    correlation_search_multi_rule_query_expression: ClassVar[Optional[str]] = None
    #   Usually the expression must contain some an expression that marks the matched event type as
    #   such, e.g. by using the rule name or uuid.
    # * A joiner string that is put between each search_multi_rule_query_expression:
    correlation_search_multi_rule_query_expression_joiner: ClassVar[Optional[str]] = None

    ## Correlation query typing phase (optional)
    # Event typing expression. In some query languages the initial search query only allows basic
    # boolean expressions without the possibility to mark the matched events with a type, which is
    # especially required by temporal correlation rules to distinguish between the different matched
    # event types.
    # This is the template for the event typing expression that is used to mark the matched events.
    # It contains only a {queries} placeholder that is replaced by the result of joining
    # typing_rule_query_expression with typing_rule_query_expression_joiner defined afterwards.
    typing_expression: ClassVar[Optional[str]] = None
    # This is the template for the event typing expression for each query generated from the
    # referred Sigma rules. It contains the following placeholders:
    # * {rule} is the referred Sigma rule.
    # * {ruleid} is the rule name or if not available the id of the rule.
    # * {query} is the query generated from the referred Sigma rule.
    typing_rule_query_expression: ClassVar[Optional[str]] = None
    # String that is used to join the event typing expressions for each rule query referred by the
    # correlation rule:
    typing_rule_query_expression_joiner: ClassVar[Optional[str]] = None

    # Event field normalization expression. This is used to normalize field names in events matched
    # by the Sigma rules referred by the correlation rule. This is a dictionary mapping from
    # correlation_method names to format strings hat can contain the following placeholders:
    # * {alias} is the field name to which the event field names are normalized and that is used as
    #   group-by field in the aggregation phase.
    # * {field} is the field name from the rule that is normalized.
    # The expression is generated for each Sigma rule referred by the correlation rule and each
    # alias field definition that contains a field definition for the Sigma rule for which the
    # normalization expression is generated. All such generated expressions are joined with the
    # correlation_search_field_normalization_expression_joiner and the result is passed as
    # {normalization} to the correlation_search_*_rule_expression.
    correlation_search_field_normalization_expression: ClassVar[Optional[str]] = None
    correlation_search_field_normalization_expression_joiner: ClassVar[Optional[str]] = None

    ## Correlation query aggregation phase
    # All of the following class variables are dictionaries of mappings from
    # correlation_method names to format strings with the following placeholders:
    # * {rule} contains the whole correlation rule object.
    # * {referenced_rules} contains the Sigma rules that are referred by the correlation rule.
    # * {field} contains the field specified in the condition.
    # * {timespan} contains the timespan converted into the target format by the convert_timespan
    #   method.
    # * {groupby} contains the group by expression generated by the groupby_* templates below.
    # * {search} contains the search expression generated by the correlation query search phase.
    event_count_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = (
        None  # Expression for event count correlation rules
    )
    value_count_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = (
        None  # Expression for value count correlation rules
    )
    temporal_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = (
        None  # Expression for temporal correlation rules
    )
    temporal_ordered_aggregation_expression: ClassVar[Optional[Dict[str, str]]] = (
        None  # Expression for ordered temporal correlation rules
    )

    # Mapping from Sigma timespan to target format timespan specification. This can be:
    # * A dictionary mapping Sigma timespan specifications to target format timespan specifications,
    #   e.g. the Sigma timespan specifier "m" to "min".
    # * None if the target query language uses the same timespan specification as Sigma or expects
    #   seconds (see timespan_seconds) or a custom timespan conversion is implemented in the method
    #   convert_timespan.
    # The mapping can be incomplete. Non-existent timespan specifiers will be passed as-is if no
    # mapping is defined for them.
    timespan_mapping: ClassVar[Optional[Dict[str, str]]] = None
    timespan_seconds: ClassVar[bool] = (
        False  # If True, timespan is converted to seconds instead of using a more readable timespan specification like 5m.
    )

    # Expression for a referenced rule as format string with {ruleid} placeholder that is replaced
    # with the rule name or id similar to the search query expression.
    referenced_rules_expression: ClassVar[Optional[Dict[str, str]]] = None
    # All referenced rules expressions are joined with the following joiner:
    referenced_rules_expression_joiner: ClassVar[Optional[Dict[str, str]]] = None

    # The following class variables defined the templates for the group by expression.
    # First an expression frame is definied:
    groupby_expression: ClassVar[Optional[Dict[str, str]]] = None
    # This expression only contains the {fields} placeholder that is replaced by the result of
    # groupby_field_expression for each group by field joined by groupby_field_expression_joiner. The expression template
    # itself can only contain a {field} placeholder for a single field name.
    groupby_field_expression: ClassVar[Optional[Dict[str, str]]] = None
    groupby_field_expression_joiner: ClassVar[Optional[Dict[str, str]]] = None
    # Groupy by expression in the case that no fields were provided in the correlation rule:
    groupby_expression_nofield: ClassVar[Optional[Dict[str, str]]] = None

    ## Correlation query condition phase
    # The final correlation query phase adds a final filter that filters the aggregated events
    # according to the given conditions. The following class variables define the templates for the
    # different correlation rule types and correlation methods (dict keys).
    # Each template gets the following placeholders:
    # * {op} is the condition operator mapped according o correlation_condition_mapping.
    # * {count} is the value specified in the condition.
    # * {field} is the field specified in the condition.
    # * {referenced_rules} contains the Sigma rules that are referred by the correlation rule. This
    #   expression is generated by the referenced_rules_expression template in combination with the
    #   referenced_rules_expression_joiner defined above.
    event_count_condition_expression: ClassVar[Optional[Dict[str, str]]] = None
    value_count_condition_expression: ClassVar[Optional[Dict[str, str]]] = None
    temporal_condition_expression: ClassVar[Optional[Dict[str, str]]] = None
    temporal_ordered_condition_expression: ClassVar[Optional[Dict[str, str]]] = None
    # The following mapping defines the mapping from Sigma correlation condition operators like
    # "lt", "gte" into the operatpors expected by the target query language.
    correlation_condition_mapping: ClassVar[
        Optional[Dict[SigmaCorrelationConditionOperator, str]]
    ] = {
        SigmaCorrelationConditionOperator.LT: "<",
        SigmaCorrelationConditionOperator.LTE: "<=",
        SigmaCorrelationConditionOperator.GT: ">",
        SigmaCorrelationConditionOperator.GTE: ">=",
        SigmaCorrelationConditionOperator.EQ: "==",
    }

    def __new__(cls, *args, **kwargs):
        c = super().__new__(cls)
        c.explicit_not_exists_expression = c.field_not_exists_expression is not None
        return c

    def compare_precedence(self, outer: ConditionItem, inner: ConditionItem) -> bool:
        """
        Compare precedence of outer and inner condition items. Return True if precedence of
        enclosing condition item (outer) is lower than the contained (inner) condition item.
        In this case, no additional grouping is required.
        """
        if self.parenthesize and not isinstance(
            inner, (ConditionFieldEqualsValueExpression, ConditionValueExpression)
        ):  # if parenthesize is set, parenthesis are generally put around everything.
            return False

        outer_class = outer.__class__
        # Special case: Conditions containing a SigmaExpansion value convert into OR conditions and therefore the precedence has to be handled the same way.
        if isinstance(
            inner, (ConditionFieldEqualsValueExpression, ConditionValueExpression)
        ) and isinstance(inner.value, SigmaExpansion):
            inner_class = ConditionOR
        else:
            inner_class = inner.__class__

        try:
            idx_inner = self.precedence.index(inner_class)
        except ValueError:  # ConditionItem not in precedence tuple
            idx_inner = -1  # Assume precedence of inner condition item is higher than the outer

        return idx_inner <= self.precedence.index(outer_class)

    def convert_condition_group(
        self, cond: ConditionItem, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Group condition item."""
        expr = self.convert_condition(cond, state)
        if expr is None or isinstance(expr, DeferredQueryExpression):
            return expr
        return self.group_expression.format(expr=expr)

    def convert_condition_or(
        self, cond: ConditionOR, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of OR conditions."""
        try:
            if (
                self.token_separator == self.or_token
            ):  # don't repeat the same thing triple times if separator equals or token
                joiner = self.or_token
            else:
                joiner = self.token_separator + self.or_token + self.token_separator

            return joiner.join(
                (
                    converted
                    for converted in (
                        (
                            self.convert_condition(arg, state)
                            if self.compare_precedence(cond, arg)
                            else self.convert_condition_group(arg, state)
                        )
                        for arg in cond.args
                    )
                    if converted is not None and not isinstance(converted, DeferredQueryExpression)
                )
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'or' not supported by the backend")

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field in value list conditions."""
        return self.field_in_list_expression.format(
            field=self.escape_and_quote_field(
                cond.args[0].field
            ),  # The assumption that the field is the same for all argument is valid because this is checked before
            op=self.or_in_operator if isinstance(cond, ConditionOR) else self.and_in_operator,
            list=self.list_separator.join(
                [
                    (
                        self.convert_value_str(arg.value, state)
                        if isinstance(arg.value, SigmaString)  # string escaping and qouting
                        else str(arg.value)
                    )  # value is number
                    for arg in cond.args
                ]
            ),
        )

    def convert_condition_and(
        self, cond: ConditionAND, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of AND conditions."""
        try:
            if (
                self.token_separator == self.and_token
            ):  # don't repeat the same thing triple times if separator equals and token
                joiner = self.and_token
            else:
                joiner = self.token_separator + self.and_token + self.token_separator

            return joiner.join(
                (
                    converted
                    for converted in (
                        (
                            self.convert_condition(arg, state)
                            if self.compare_precedence(cond, arg)
                            else self.convert_condition_group(arg, state)
                        )
                        for arg in cond.args
                    )
                    if converted is not None and not isinstance(converted, DeferredQueryExpression)
                )
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'and' not supported by the backend")

    def convert_condition_not(
        self, cond: ConditionNOT, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions."""
        arg = cond.args[0]
        try:
            if arg.__class__ in self.precedence:  # group if AND or OR condition is negated
                return (
                    self.not_token + self.token_separator + self.convert_condition_group(arg, state)
                )
            else:
                expr = self.convert_condition(arg, state)
                if isinstance(
                    expr, DeferredQueryExpression
                ):  # negate deferred expression and pass it to parent
                    return expr.negate()
                else:  # convert negated expression to string
                    return self.not_token + self.token_separator + expr
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend")

    def escape_and_quote_field(self, field_name: str) -> str:
        """
        Escape field name by prepending pattern matches of field_escape_pattern with field_escape
        string. If field_escape_quote is set to True (default) and field escaping string is defined
        in field_escape, all instances of the field quoting character are escaped before quoting.

        Quote field name with field_quote if field_quote_pattern (doesn't) matches the original
        (unescaped) field name. If field_quote_pattern_negation is set to True (default) the pattern matching
        result is negated, which is the default behavior. In this case the field name is quoted if
        the pattern doesn't matches.
        """
        if self.field_escape is not None:  # field name escaping
            if (
                self.field_escape_pattern is not None
            ):  # Match all occurrences of field_escpae_pattern if defined and initialize match position set with result.
                match_positions = {
                    match.start() for match in self.field_escape_pattern.finditer(field_name)
                }
            else:
                match_positions = set()

            if (
                self.field_escape_quote and self.field_quote is not None
            ):  # Add positions of quote string to match position set
                re_quote = re.compile(re.escape(self.field_quote))
                match_positions.update((match.start() for match in re_quote.finditer(field_name)))

            if len(match_positions) > 0:  # found matches, escape them
                r = [0] + list(sorted(match_positions)) + [len(field_name)]
                escaped_field_name = ""
                for i in range(
                    len(r) - 1
                ):  # TODO: from Python 3.10 this can be replaced with itertools.pairwise(), but for now we keep support for Python <3.10
                    if i == 0:  # The first range is passed to the result without escaping
                        escaped_field_name += field_name[r[i] : r[i + 1]]
                    else:  # Subsequent ranges are positions of matches and therefore are prepended with field_escape
                        escaped_field_name += self.field_escape + field_name[r[i] : r[i + 1]]
            else:  # no matches, just pass original field name without escaping
                escaped_field_name = field_name
        else:
            escaped_field_name = field_name

        if self.field_quote is not None:  # Field quoting
            if self.field_quote_pattern is not None:  # Match field quote pattern...
                quote = bool(self.field_quote_pattern.match(escaped_field_name))
                if (
                    self.field_quote_pattern_negation
                ):  # ...negate result of matching, if requested...
                    quote = not quote
            else:
                quote = True

            if quote:  #  ...and quote if pattern (doesn't) matches
                return self.field_quote + escaped_field_name + self.field_quote
        return escaped_field_name

    def decide_string_quoting(self, s: SigmaString) -> bool:
        """
        Decide if string is quoted based on the pattern in the class attribute str_quote_pattern. If
        this matches (or not matches if str_quote_pattern_negation is set to True), the string is quoted.
        """
        if self.str_quote == "":  # No quoting if quoting string is empty.
            return False

        if self.str_quote_pattern is None:  # Always quote if pattern is not set.
            return True
        else:
            match = bool(self.str_quote_pattern.match(str(s)))
            if self.str_quote_pattern_negation:
                match = not match
            return match

    def quote_string(self, s: str) -> str:
        """Put quotes around string."""
        return self.str_quote + s + self.str_quote

    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        """Convert a SigmaString into a plain string which can be used in query."""
        converted = s.convert(
            self.escape_char,
            self.wildcard_multi,
            self.wildcard_single,
            self.str_quote + self.add_escaped,
            self.filter_chars,
        )
        if self.decide_string_quoting(s):
            return self.quote_string(converted)
        else:
            return converted

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        try:
            if (  # Check conditions for usage of 'startswith' operator
                self.startswith_expression
                is not None  # 'startswith' operator is defined in backend
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)  # String ends with wildcard
                and (
                    self.startswith_expression_allow_special
                    or not cond.value[:-1].contains_special()
                )  # Remainder of string doesn't contains special characters or it's allowed
            ):
                expr = (
                    self.startswith_expression
                )  # If all conditions are fulfilled, use 'startswith' operator instead of equal token
                value = cond.value[:-1]
            elif (  # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contains further special characters
                self.endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and (
                    self.endswith_expression_allow_special or not cond.value[1:].contains_special()
                )
            ):
                expr = self.endswith_expression
                value = cond.value[1:]
            elif (  # contains: string starts and ends with wildcard
                self.contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and (
                    self.contains_expression_allow_special
                    or not cond.value[1:-1].contains_special()
                )
            ):
                expr = self.contains_expression
                value = cond.value[1:-1]
            elif (  # wildcard match expression: string contains wildcard
                self.wildcard_match_expression is not None and cond.value.contains_special()
            ):
                expr = self.wildcard_match_expression
                value = cond.value
            else:
                expr = self.eq_expression
                value = cond.value
            return expr.format(
                field=self.escape_and_quote_field(cond.field),
                value=self.convert_value_str(value, state),
                regex=self.convert_value_re(value.to_regex(self.add_escaped_re), state),
                backend=self,
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Field equals string value expressions with strings are not supported by the backend."
            )

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of case-sensitive field = string value expressions"""
        try:
            if (  # Check conditions for usage of 'startswith' operator
                self.case_sensitive_startswith_expression
                is not None  # 'startswith' operator is defined in backend
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)  # String ends with wildcard
                and (
                    self.case_sensitive_startswith_expression_allow_special
                    or not cond.value[:-1].contains_special()
                )  # Remainder of string doesn't contains special characters or it's allowed
            ):
                expr = (
                    self.case_sensitive_startswith_expression
                )  # If all conditions are fulfilled, use 'startswith' operator instead of equal token
                value = cond.value[:-1]
            elif (  # Same as above but for 'endswith' operator: string starts with wildcard and doesn't contains further special characters
                self.case_sensitive_endswith_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and (
                    self.case_sensitive_endswith_expression_allow_special
                    or not cond.value[1:].contains_special()
                )
            ):
                expr = self.case_sensitive_endswith_expression
                value = cond.value[1:]
            elif (  # contains: string starts and ends with wildcard
                self.case_sensitive_contains_expression is not None
                and cond.value.startswith(SpecialChars.WILDCARD_MULTI)
                and cond.value.endswith(SpecialChars.WILDCARD_MULTI)
                and (
                    self.case_sensitive_contains_expression_allow_special
                    or not cond.value[1:-1].contains_special()
                )
            ):
                expr = self.case_sensitive_contains_expression
                value = cond.value[1:-1]
            elif self.case_sensitive_match_expression is not None:
                expr = self.case_sensitive_match_expression
                value = cond.value
            else:
                raise NotImplementedError(
                    "Case-sensitive string matching is not supported by backend."
                )
            return expr.format(
                field=self.escape_and_quote_field(cond.field),
                value=self.convert_value_str(value, state),
                regex=self.convert_value_re(value.to_regex(self.add_escaped_re), state),
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Case-sensitive field equals string value expressions with strings are not supported by the backend."
            )

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = number value expressions"""
        try:
            return self.escape_and_quote_field(cond.field) + self.eq_token + str(cond.value)
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Field equals numeric value expressions are not supported by the backend."
            )

    def convert_condition_field_eq_val_bool(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = bool value expressions"""
        try:
            return (
                self.escape_and_quote_field(cond.field)
                + self.eq_token
                + self.bool_values[cond.value.boolean]
            )
        except TypeError:  # pragma: no cover
            raise NotImplementedError(
                "Field equals numeric value expressions are not supported by the backend."
            )

    def convert_value_re(
        self, r: SigmaRegularExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Convert regular expression into string representation used in query."""
        return r.escape(
            self.re_escape,
            self.re_escape_char,
            self.re_escape_escape_char,
            self.re_flag_prefix,
        )

    def get_flag_template(self, r: SigmaRegularExpression) -> Dict[str, str]:
        """Return the flag_x template variales used for regular expression templates as dict that
        maps flag_x template variable names to the static template if flag is set in regular
        expression r or an empty string if flag is not set."""
        try:
            return {
                f"flag_{c}": (self.re_flags[flag] if flag in r.flags else "")
                for flag, c in SigmaRegularExpression.sigma_to_re_flag.items()
            }
        except KeyError as e:
            raise NotImplementedError(
                f"Regular expression flag {e.args[0].name} not supported by the backend."
            )

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches regular expression value expressions."""
        flag_kwargs = self.get_flag_template(cond.value)
        return self.re_expression.format(
            field=self.escape_and_quote_field(cond.field),
            regex=self.convert_value_re(cond.value, state),
            **flag_kwargs,
        )

    def convert_condition_field_eq_val_re_contains(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only regular expressions."""
        flag_kwargs = self.get_flag_template(cond.value)
        return self.re_expression.format(
            field=self.escape_and_quote_field(cond.field),
            regex=self.convert_value_re(cond.value, state),
            **flag_kwargs,
        )

    def convert_condition_field_eq_val_cidr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches CIDR value expressions."""
        cidr: SigmaCIDRExpression = cond.value
        if (
            self.cidr_expression is not None
        ):  # native CIDR support from backend with expression templates.
            return self.cidr_expression.format(
                field=cond.field,
                value=str(cidr.network),
                network=cidr.network.network_address,
                prefixlen=cidr.network.prefixlen,
                netmask=cidr.network.netmask,
            )
        else:  # No native CIDR support: expand into string wildcard matches on prefixes.
            expanded = cidr.expand()
            expanded_cond = ConditionOR(
                [
                    ConditionFieldEqualsValueExpression(cond.field, SigmaString(network))
                    for network in expanded
                ],
                cond.source,
            )
            return self.convert_condition(expanded_cond, state)

    def convert_condition_field_compare_op_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of numeric comparison operations into queries."""
        return self.compare_op_expression.format(
            field=self.escape_and_quote_field(cond.field),
            operator=self.compare_operators[cond.value.op],
            value=cond.value.number,
        )

    def convert_condition_field_eq_field_escape_and_quote(
        self, field1: str, field2: str
    ) -> Tuple[str, str]:
        """Escape and quote field names of a field-quals-field expression."""
        return (
            (
                self.escape_and_quote_field(field1)
                if self.field_equals_field_escaping_quoting[0]
                else field1
            ),
            (
                self.escape_and_quote_field(field2)
                if self.field_equals_field_escaping_quoting[1]
                else field2
            ),
        )

    def convert_condition_field_eq_field(
        self, cond: SigmaFieldReference, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of comparision of two fields."""
        field1, field2 = self.convert_condition_field_eq_field_escape_and_quote(
            cond.field, cond.value.field
        )
        return self.field_equals_field_expression.format(
            field1=field1,
            field2=field2,
        )

    def convert_condition_field_eq_val_null(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field is null expression value expressions"""
        return self.field_null_expression.format(field=self.escape_and_quote_field(cond.field))

    def convert_condition_field_exists(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field exists expressions"""
        return self.field_exists_expression.format(field=self.escape_and_quote_field(cond.field))

    def convert_condition_field_not_exists(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field not exists expressions"""
        return self.field_not_exists_expression.format(
            field=self.escape_and_quote_field(cond.field)
        )

    def convert_condition_field_eq_query_expr(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field is null expression value expressions"""
        return cond.value.finalize(field=self.escape_and_quote_field(cond.field))

    def convert_condition_val_str(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only strings."""
        return self.unbound_value_str_expression.format(
            value=self.convert_value_str(cond.value, state),
            regex=self.convert_value_re(cond.value.to_regex(self.add_escaped_re), state),
        )

    def convert_condition_val_num(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only numbers."""
        return self.unbound_value_num_expression.format(value=cond.value)

    def convert_condition_val_re(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only regular expressions."""
        flag_kwargs = self.get_flag_template(cond.value)
        return self.unbound_value_re_expression.format(
            value=self.convert_value_re(cond.value, state), **flag_kwargs
        )

    def convert_condition_query_expr(
        self, cond: ConditionValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only plain query expressions."""
        return cond.value.finalize()

    # Correlation query conversion
    # The following methods are used to convert Sigma correlation rules into queries. The conversion
    # starts with the convert_correlation_rule method that calls correlation type specific methods
    # which itself call convert_correlation_rule_from_template that dispatches to the three
    # correlation query phases: search, aggregation and condition.
    def convert_correlation_rule_from_template(
        self, rule: SigmaCorrelationRule, correlation_type: SigmaCorrelationTypeLiteral, method: str
    ) -> str:
        template = (
            getattr(self, f"{correlation_type}_correlation_query") or self.default_correlation_query
        )
        if template is None:
            raise NotImplementedError(
                f"Correlation rule type '{correlation_type}' is not supported by backend."
            )

        if method not in template:
            raise SigmaConversionError(
                f"Correlation method '{method}' is not supported by backend for correlation type '{correlation_type}'."
            )

        search = self.convert_correlation_search(rule)
        return [
            template[method].format(
                search=search,
                typing=self.convert_correlation_typing(rule),
                aggregate=self.convert_correlation_aggregation_from_template(
                    rule, correlation_type, method, search
                ),
                condition=self.convert_correlation_condition_from_template(
                    rule.condition, rule.rules, correlation_type, method
                ),
            )
        ]

    def convert_correlation_event_count_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[str]:
        return self.convert_correlation_rule_from_template(rule, "event_count", method)

    def convert_correlation_value_count_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[str]:
        return self.convert_correlation_rule_from_template(rule, "value_count", method)

    def convert_correlation_temporal_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[str]:
        return self.convert_correlation_rule_from_template(rule, "temporal", method)

    def convert_correlation_temporal_ordered_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[str]:
        return self.convert_correlation_rule_from_template(rule, "temporal_ordered", method)

    # Implementation of the search phase of the correlation query.
    def convert_correlation_search(
        self,
        rule: SigmaCorrelationRule,
        **kwargs,
    ) -> str:
        if (  # if the correlation rule refers only a single rule and this rule results only in a single query
            len(rule.rules) == 1
            and len(queries := (rule_reference := rule.rules[0].rule).get_conversion_result()) == 1
            and self.correlation_search_single_rule_expression is not None
        ):
            return self.correlation_search_single_rule_expression.format(
                rule=rule_reference,
                query=queries[0],
                normalization=self.convert_correlation_search_field_normalization_expression(
                    rule.aliases, rule_reference
                ),
                **kwargs,
            )
        else:
            return self.correlation_search_multi_rule_expression.format(
                queries=self.correlation_search_multi_rule_query_expression_joiner.join(
                    (
                        self.correlation_search_multi_rule_query_expression.format(
                            rule=rule_reference.rule,
                            ruleid=rule_reference.rule.name or rule_reference.rule.id,
                            query=self.convert_correlation_search_multi_rule_query_postprocess(
                                query
                            ),
                            normalization=self.convert_correlation_search_field_normalization_expression(
                                rule.aliases,
                                rule_reference,
                            ),
                        )
                        for rule_reference in rule.rules
                        for query in rule_reference.rule.get_conversion_result()
                    )
                ),
                **kwargs,
            )

    def convert_correlation_search_multi_rule_query_postprocess(
        self,
        query: str,
    ) -> str:
        """This function is called for each query in the multi-rule correlation search phase. It can be used to postprocess the query before it is joined with the other queries."""
        return query

    def convert_correlation_search_field_normalization_expression(
        self,
        aliases: SigmaCorrelationFieldAliases,
        rule_reference: SigmaRule,
    ) -> str:
        if len(aliases) == 0:
            return ""
        elif (
            self.correlation_search_field_normalization_expression is None
            or self.correlation_search_field_normalization_expression_joiner is None
        ):
            raise NotImplementedError(
                "Correlation field normalization is not supported by backend."
            )
        else:
            return self.correlation_search_field_normalization_expression_joiner.join(
                (
                    self.correlation_search_field_normalization_expression.format(
                        alias=alias.alias,
                        field=field,
                    )
                    for alias in aliases
                    for alias_rule_reference, field in alias.mapping.items()
                    if alias_rule_reference == rule_reference
                )
            )

    # Implementation of the typing phase of the correlation query.
    def convert_correlation_typing(self, rule: SigmaCorrelationRule) -> str:
        if self.typing_expression is None:
            return ""
        else:
            return self.typing_expression.format(
                queries=self.typing_rule_query_expression_joiner.join(
                    (
                        self.typing_rule_query_expression.format(
                            rule=rule_reference.rule,
                            ruleid=rule_reference.rule.name or rule_reference.rule.id,
                            query=self.convert_correlation_typing_query_postprocess(query),
                        )
                        for rule_reference in rule.rules
                        for query in rule_reference.rule.get_conversion_result()
                    )
                )
            )

    def convert_correlation_typing_query_postprocess(
        self,
        query: str,
    ) -> str:
        """This function is called for each query in the typing phase of the correlation query. It can be used to postprocess the query before it is joined with the other queries."""
        return query

    # Implementation of the aggregation phase of the correlation query.
    def convert_correlation_aggregation_from_template(
        self,
        rule: SigmaCorrelationRule,
        correlation_type: SigmaCorrelationTypeLiteral,
        method: str,
        search: str,
    ) -> str:
        templates = getattr(self, f"{correlation_type}_aggregation_expression")
        if templates is None:
            raise NotImplementedError(
                f"Correlation type '{correlation_type}' is not supported by backend."
            )
        template = templates[method]
        return template.format(
            rule=rule,
            referenced_rules=self.convert_referenced_rules(rule.rules, method),
            field=rule.condition.fieldref,
            timespan=self.convert_timespan(rule.timespan, method),
            groupby=self.convert_correlation_aggregation_groupby_from_template(
                rule.group_by, method
            ),
            search=search,
        )

    def convert_correlation_aggregation_groupby_from_template(
        self, group_by: Optional[List[str]], method: str
    ) -> str:
        if group_by is None:
            if self.groupby_expression_nofield is None:
                return ""
            else:
                return self.groupby_expression_nofield[method]
        else:
            return self.groupby_expression[method].format(
                fields=self.groupby_field_expression_joiner[method].join(
                    (
                        self.groupby_field_expression[method].format(
                            field=self.escape_and_quote_field(field)
                        )
                        for field in group_by
                    )
                )
            )

    def convert_referenced_rules(self, referenced_rules: List[SigmaRuleReference], method: str):
        if (
            self.referenced_rules_expression is None
            or self.referenced_rules_expression_joiner is None
        ):
            return ExceptionOnUsage(
                SigmaBackendError(
                    "Backend doesn't defines referenced rule expression but uses it in correlation query template"
                )
            )
        else:
            return self.referenced_rules_expression_joiner[method].join(
                (
                    self.referenced_rules_expression[method].format(
                        ruleid=rule_reference.rule.name or rule_reference.rule.id
                    )
                    for rule_reference in referenced_rules
                )
            )

    # Implementation of the condition phase of the correlation query.
    def convert_correlation_condition_from_template(
        self,
        cond: SigmaCorrelationCondition,
        referenced_rules: List[SigmaRuleReference],
        correlation_type: SigmaCorrelationTypeLiteral,
        method: str,
    ) -> str:
        templates = getattr(self, f"{correlation_type}_condition_expression")
        if templates is None:
            raise NotImplementedError(
                f"Correlation type '{correlation_type}' is not supported by backend."
            )
        template = templates[method]
        return template.format(
            field=cond.fieldref,
            op=self.correlation_condition_mapping[cond.op],
            count=cond.count,
            referenced_rules=self.convert_referenced_rules(referenced_rules, method),
        )

    def convert_timespan(
        self,
        timespan: SigmaCorrelationTimespan,
        output_format: Optional[str] = None,
        method: Optional[str] = None,
    ) -> str:
        if self.timespan_seconds:  # return timespan in seconds
            return timespan.seconds
        elif (
            self.timespan_mapping is not None and timespan.unit in self.timespan_mapping
        ):  # return timespan converted with mapping
            return str(timespan.count) + self.timespan_mapping[timespan.unit]
        else:  # return timespan as is
            return timespan.spec

    def finalize_query(
        self,
        rule: SigmaRule,
        query: Union[str, DeferredQueryExpression],
        index: int,
        state: ConversionState,
        output_format: str,
    ) -> Union[str, DeferredQueryExpression]:
        """
        Finalize query by appending deferred query parts to the main conversion result as specified
        with deferred_start and deferred_separator.
        """
        # TODO when Python 3.8 is dropped: replace ChainMap with | operator.
        conversion_state = ChainMap(state.processing_state, self.state_defaults)

        if state.has_deferred():
            if isinstance(query, DeferredQueryExpression):
                query = self.deferred_only_query
            return super().finalize_query(
                rule,
                self.query_expression.format(
                    query=query,
                    rule=rule,
                    state=conversion_state,
                )
                + self.deferred_start
                + self.deferred_separator.join(
                    (
                        deferred_expression.finalize_expression()
                        for deferred_expression in state.deferred
                    )
                ),
                index,
                state,
                output_format,
            )
        else:
            return super().finalize_query(
                rule,
                self.query_expression.format(
                    query=query,
                    rule=rule,
                    state=conversion_state,
                ),
                index,
                state,
                output_format,
            )
