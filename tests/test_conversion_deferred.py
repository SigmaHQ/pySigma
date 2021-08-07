import pytest
from sigma.conversion.state import ConversionState
from sigma.conversion.deferred import DeferredTextQueryExpression

@pytest.fixture
def conversion_state():
    return ConversionState()

class DeferredTestExpression(DeferredTextQueryExpression):
    template = "{field}{op}{value}"
    operators = {
        True: "!=",
        False: "=",
    }

@pytest.fixture
def deferred_expression(conversion_state):
    return DeferredTestExpression(conversion_state, "field", "value")

def test_deferred_expression(deferred_expression):
    assert deferred_expression.finalize_expression() == "field=value"

def test_deferred_expression_negation(deferred_expression):
    assert deferred_expression.negate().finalize_expression() == "field!=value"