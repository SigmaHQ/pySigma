from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from typing import Any, ClassVar, Dict, Optional
from sigma.conditions import ParentChainMixin
import sigma

@dataclass
class DeferredQueryExpression(ParentChainMixin, ABC):
    """
    This class is the base class for deferred query expressions, which are a method to postpone
    conversion of particular query parts to the finalization phase. The reason for this can be
    (but are not limited to):

    * Functionality that is not supported in the main query expression by the backend and has to
      be generated as filtering expression after the main query is already applied. E.g. some
      target systems don't support regular expressions in the main query, but allow to conduct
      further filtering of the result set in additional expressions.
    * Situations where the information required for the conversion is not available at the time
      of the main conversion.

    Deferred query expressions are created and returned by the condition tree node conversion
    methods and collected in the ConversionState object for the rule conversion. This state
    object is also passed on initialization of the DeferredQueryExpression object and can
    contain state information that is used for the final query expression generation in the
    finalize_expression() method.

    The base class only implements the handling of query expression negations in the property
    'negated', which is toggled with toggle_negation() on appearance of not expressions in the
    Sigma rule condition.

    The method finalize_expression must implement the generation of the query expression.
    """
    conversion_state : "sigma.backends.state.ConversionState"
    negated : bool = field(init=False, default=False)

    def __post_init__(self):
       """Deferred expression automatically adds itself to conversion state."""
       self.conversion_state.add_deferred_expression(self)

    def negate(self) -> "DeferredQueryExpression":
        """Toggle negation state of deferred expression."""
        self.negated = not self.negated
        return self

    @abstractmethod
    def finalize_expression(self) -> Any:
        """Generate query from information stored in the deferred query and the conversion state object."""

@dataclass
class DeferredTextQueryExpression(DeferredQueryExpression):
  """
  Convenience class derived from DeferredQueryExpression for text query backends. It is a base class for
  implementation classes setting the following class variables:

  * template: a string template containing the following placeholders:
    * field: the field name referenced by the Sigma rule
    * value: the value from the Sigma rule
    * op: an operator that is looked up in operators depending on the state of the negated property.
  * operators: a dict containing a mapping from the two boolean states to operators inserted in the
    generated queries.
  """
  field : Optional[str]
  value : str
  template : ClassVar[str]
  operators : ClassVar[Dict[bool, str]]
  default_field : ClassVar[Optional[str]]

  def __post_init__(self):
    super().__post_init__()
    if self.field is None and self.default_field is not None:
      self.field = self.default_field

  def finalize_expression(self) -> str:
    return self.template.format(field=self.field, op=self.operators[self.negated], value=self.value)