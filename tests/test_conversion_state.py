import py
import pytest
from sigma.conversion.state import ConversionState
from sigma.conversion.deferred import DeferredTextQueryExpression

@pytest.fixture
def conversion_state():
    return ConversionState()

@pytest.fixture
def deferred_expression(conversion_state):
    return DeferredTextQueryExpression(conversion_state, "field", "value")

def test_conversion_state_empty_has_deferred(conversion_state : ConversionState):
    assert conversion_state.has_deferred() == False

def test_conversion_state_has_deferred(conversion_state : ConversionState, deferred_expression):
    conversion_state.add_deferred_expression(deferred_expression)
    assert conversion_state.has_deferred() == True
