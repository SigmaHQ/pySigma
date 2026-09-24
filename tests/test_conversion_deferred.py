import pytest
from sigma.conversion.state import ConversionState
from sigma.conversion.deferred import DeferredTextQueryExpression
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionOR
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.collection import SigmaCollection
from sigma.backends.test import TextQueryTestBackend


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


def deferred_rule(detection: str) -> SigmaCollection:
    return SigmaCollection.from_yaml(f"""
title: Test
status: test
logsource:
    category: test_category
    product: test_product
detection:
{detection}
""")


def test_deferred_conversion_not_and_mixed_unsupported(test_backend: TextQueryTestBackend):
    # not (fieldB="foo" and fieldA ~ regex) can't be expressed as main query plus an appended
    # regex filter: only the fieldB part would be negated and the regex would become required.
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="Negation"):
        test_backend.convert(deferred_rule("""
    sel:
        fieldC: bar
    filter:
        fieldB: foo
        fieldA|re: foo.*bar
    condition: sel and not filter"""))


def test_deferred_conversion_not_and_mixed_collect_errors():
    backend = DeferredTextQueryTestBackend(collect_errors=True)
    assert backend.convert(deferred_rule("""
    sel:
        fieldC: bar
    filter:
        fieldB: foo
        fieldA|re: foo.*bar
    condition: sel and not filter""")) == []
    assert len(backend.errors) == 1
    assert isinstance(backend.errors[0][1], SigmaFeatureNotSupportedByBackendError)


@pytest.mark.parametrize(
    "condition",
    [
        "not (sel1 and sel2)",
        "not (sel1 or sel2)",
        "sel3 and not (sel1 or sel3)",
    ],
)
def test_deferred_conversion_not_compound_unsupported(
    test_backend: TextQueryTestBackend, condition
):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        test_backend.convert(deferred_rule(f"""
    sel1:
        fieldA|re: foo.*bar
    sel2:
        fieldB|re: foo.*
    sel3:
        fieldC: bar
    condition: {condition}"""))


@pytest.mark.parametrize(
    "detection,expected",
    [
        (
            """
    sel:
        fieldA|re: foo.*bar
        fieldB|re: foo.*
    condition: sel""",
            '* | mappedA="foo.*bar" | fieldB="foo.*"',
        ),
        (
            """
    sel1:
        fieldA|re: foo.*bar
    sel2:
        fieldB|re: foo.*
    condition: sel1 and sel2""",
            '* | mappedA="foo.*bar" | fieldB="foo.*"',
        ),
        (
            """
    sel1:
        fieldA|re: foo.*bar
    sel2:
        fieldB|re: foo.*
    condition: not sel1 and not sel2""",
            '* | mappedA!="foo.*bar" | fieldB!="foo.*"',
        ),
        (
            """
    sel1:
        fieldA|re: foo.*bar
    sel2:
        fieldB|re: foo.*
    sel3:
        fieldC: bar
    condition: sel3 and (sel1 and sel2)""",
            'fieldC="bar" | mappedA="foo.*bar" | fieldB="foo.*"',
        ),
    ],
    ids=["one_selection", "and", "not_and_not", "nested_and"],
)
def test_deferred_conversion_all_deferred_and(
    test_backend: TextQueryTestBackend, detection, expected
):
    assert test_backend.convert(deferred_rule(detection)) == [expected]


def test_deferred_conversion_double_negation(test_backend: TextQueryTestBackend):
    assert test_backend.convert(deferred_rule("""
    sel1:
        fieldA|re: foo.*bar
    sel2:
        fieldC: bar
    condition: sel2 and not (not sel1)""")) == ['fieldC="bar" | mappedA="foo.*bar"']


class EnablerDeferredTextQueryTestBackend(DeferredTextQueryTestBackend):
    """
    Converts regular expressions below an OR into a query term that is enabled by a deferred
    expression (like the rex/eval handling of the Splunk backend). Such deferred expressions are
    not operands of the condition and must not prevent negation.
    """

    def convert_condition_field_eq_val_re(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ):
        if cond.parent_condition_chain_contains(ConditionOR):
            DeferredTestExpression(state, "enable", cond.field)
            return f'{cond.field}Condition="true"'
        return super().convert_condition_field_eq_val_re(cond, state)


def test_deferred_conversion_not_with_enabler_deferred():
    assert (
        EnablerDeferredTextQueryTestBackend().convert(deferred_rule("""
    sel1:
        fieldA|re: foo.*bar
    sel2:
        fieldB: foo
    sel3:
        fieldC: bar
    condition: sel3 and not (sel1 or sel2)"""))
        == ['fieldC="bar" and not (mappedACondition="true" or fieldB="foo") | enable="mappedA"']
    )
