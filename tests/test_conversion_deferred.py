import pytest
from sigma.conversion.state import ConversionState
from sigma.conversion.deferred import DeferredTextQueryExpression
from sigma.conditions import ConditionFieldEqualsValueExpression
from sigma.collection import SigmaCollection
from sigma.backends.test import TextQueryTestBackend
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError


### Base Tests ###
@pytest.fixture
def conversion_state():
    return ConversionState()


class DeferredTestExpression(DeferredTextQueryExpression):
    template = '{field}{op}"{value}"'
    operators = {
        True: "!=",
        False: "=",
    }
    default_field = "_"


@pytest.fixture
def deferred_expression(conversion_state):
    return DeferredTestExpression(conversion_state, "field", "value")


@pytest.fixture
def deferred_expression_nofield(conversion_state):
    return DeferredTestExpression(conversion_state, None, "value")


def test_deferred_expression(deferred_expression):
    assert deferred_expression.finalize_expression() == 'field="value"'


def test_deferred_expression_negation(deferred_expression):
    assert deferred_expression.negate().finalize_expression() == 'field!="value"'


def test_deferred_default_field(deferred_expression_nofield):
    assert deferred_expression_nofield.finalize_expression() == '_="value"'


### Conversion Tests ###
class DeferredTextQueryTestBackend(TextQueryTestBackend):
    re_expression = "{regex}"
    re_escape = tuple()

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> DeferredTestExpression:
        return DeferredTestExpression(
            state, cond.field, super().convert_condition_field_eq_val_re(cond, state)
        )


@pytest.fixture
def test_backend():
    return DeferredTextQueryTestBackend()


def test_deferred_conversion_and(test_backend: TextQueryTestBackend):
    assert test_backend.convert(SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """)) == ['fieldB="foo" and fieldC="bar" | mappedA="foo.*bar"']


def test_deferred_conversion_or(test_backend: TextQueryTestBackend):
    assert test_backend.convert(SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA|re: foo.*bar
                sel2:
                    fieldB: foo
                sel3:
                    fieldC: bar
                condition: sel1 or sel2 or sel3
        """)) == ['fieldB="foo" or fieldC="bar" | mappedA="foo.*bar"']


def test_deferred_conversion_multiple_cond(test_backend: TextQueryTestBackend):
    assert test_backend.convert(SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA|re: foo.*bar
                sel2:
                    fieldB|re: foo.*
                sel3:
                    fieldC|re: .*bar
                condition:
                    - sel1
                    - sel2
                    - sel3
        """)) == ['* | mappedA="foo.*bar"', '* | fieldB="foo.*"', '* | fieldC=".*bar"']


def test_deferred_conversion_not(test_backend: TextQueryTestBackend):
    assert test_backend.convert(SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldB: foo
                    fieldC: bar
                sel2:
                    fieldA|re: foo.*bar
                condition: sel1 and not sel2
        """)) == ['fieldB="foo" and fieldC="bar" | mappedA!="foo.*bar"']


def test_deferred_only_conversion(test_backend: TextQueryTestBackend):
    assert test_backend.convert(SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                condition: sel
        """)) == ['* | mappedA="foo.*bar"']


def test_deferred_conversion_correlation_rule_references(test_backend: TextQueryTestBackend):
    assert (
        test_backend.convert(SigmaCollection.from_yaml("""
title: Referenced Rule with Deferred
name: rule_with_deferred
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA|re: foo.*bar
        fieldB: normalvalue
    condition: sel
---
title: Correlation Rule
status: test
correlation:
    type: event_count
    rules:
        - rule_with_deferred
    group-by:
        - fieldC
    timespan: 5m
    condition:
        gte: 10
        """))
        == ["""fieldB="normalvalue" | mappedA="foo.*bar"
| aggregate window=5min count() as event_count by fieldC
| where event_count >= 10"""]
    )


def deferred_or_rule(condition: str) -> SigmaCollection:
    return SigmaCollection.from_yaml(f"""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel1:
        fieldA|re: foo.*bar
    sel2:
        fieldB|re: foo.*
    sel3:
        fieldC: bar
    sel_list:
        fieldA|re:
            - foo.*
            - bar.*
    condition: {condition}
""")


@pytest.mark.parametrize(
    "condition",
    ["sel_list", "sel1 or sel2", "sel1 or sel_list", "sel3 and (sel1 or sel2)"],
)
def test_deferred_conversion_all_deferred_or_unsupported(
    test_backend: TextQueryTestBackend, condition
):
    # An OR of deferred expressions can't be expressed by appending them to the main query
    # (this would AND them). The rule must not be dropped silently.
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="OR condition"):
        test_backend.convert(deferred_or_rule(condition))


def test_deferred_conversion_all_deferred_or_collect_errors():
    backend = DeferredTextQueryTestBackend(collect_errors=True)
    assert backend.convert(deferred_or_rule("sel1 or sel2")) == []
    assert len(backend.errors) == 1
    assert isinstance(backend.errors[0][1], SigmaFeatureNotSupportedByBackendError)


class DroppingDeferredTextQueryTestBackend(DeferredTextQueryTestBackend):
    """Converts fieldC conditions into nothing."""

    def convert_condition_field_eq_val_str(self, cond, state):
        if cond.field == "fieldC":
            return None
        return super().convert_condition_field_eq_val_str(cond, state)


def test_deferred_conversion_or_single_deferred_with_empty():
    assert DroppingDeferredTextQueryTestBackend().convert(deferred_or_rule("sel1 or sel3")) == [
        '* | mappedA="foo.*bar"'
    ]
