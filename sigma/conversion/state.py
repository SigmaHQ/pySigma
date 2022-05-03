from dataclasses import dataclass, field
from sigma.conversion.deferred import DeferredQueryExpression
from typing import Any, List, Mapping

@dataclass
class ConversionState:
    """
    State class which is passed as object to each conversion method in query conversion and
    finalization phase. All state information that is required in a later phase of the converison
    should be stored in this class.

    The base class implements deferred query expressions, which are generated in the finalization
    phase. Conversion state objects are initialized at beginning of the conversion of a rule in
    the backends convert_rule method and are discarded after this method finishes, short after
    execution of the finalize_query method.

    In addition to deferred query expressions, ConversionState objects can be used to pass state
    down or up the parse tree.
    """
    deferred : List[DeferredQueryExpression] = field(default_factory=list)
    processing_state : Mapping[str, Any] = field(default_factory=dict)

    def add_deferred_expression(self, deferred : DeferredQueryExpression) -> None:
        self.deferred.append(deferred)

    def has_deferred(self) -> bool:
        """Return True when deferred expressions are contained in state object."""
        return len(self.deferred) > 0