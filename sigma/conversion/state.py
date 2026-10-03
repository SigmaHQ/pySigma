from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, Mapping

if TYPE_CHECKING:
    from sigma.conversion.deferred import DeferredQueryExpression


@dataclass
class ConversionState:
    """
    State class which is passed as object to each conversion method in query conversion and
    finalization phase. All state information that is required in a later phase of the conversion
    should be stored in this class.

    The base class implements deferred query expressions, which are generated in the finalization
    phase. Conversion state objects are initialized at beginning of the conversion of a rule in
    the backends convert_rule method and are discarded after this method finishes, short after
    execution of the finalize_query method.

    In addition to deferred query expressions, ConversionState objects can be used to pass state
    down or up the parse tree.
    """

    deferred: list[DeferredQueryExpression] = field(default_factory=list)
    processing_state: Mapping[str, Any] = field(default_factory=dict)
    # Deferred expressions that were returned as operands of AND/OR conditions. They are applied
    # as filters on the main query result, which is not equivalent below a negation.
    combined_deferred: list[DeferredQueryExpression] = field(
        default_factory=list, init=False, repr=False, compare=False
    )

    def add_deferred_expression(self, deferred: DeferredQueryExpression) -> None:
        self.deferred.append(deferred)

    def add_combined_deferred_expressions(self, operands: Iterable[Any]) -> None:
        """Record deferred expressions returned as operands of an AND/OR condition."""
        from sigma.conversion.deferred import DeferredQueryExpression

        self.combined_deferred.extend(
            operand for operand in operands if isinstance(operand, DeferredQueryExpression)
        )

    def has_deferred(self) -> bool:
        """Return True when deferred expressions are contained in state object."""
        return len(self.deferred) > 0
