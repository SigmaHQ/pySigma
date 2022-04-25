from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.conversion.base import TextQueryBackend
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation, QueryExpressionPlaceholderTransformation
from sigma.types import SigmaCompareExpression
from sigma.exceptions import SigmaTypeError, SigmaValueError
from typing import ClassVar, Dict, Tuple
import pytest

@pytest.fixture
def test_backend():
    return TextQueryTestBackend(
        ProcessingPipeline([
            ProcessingItem(FieldMappingTransformation({
                "fieldB": "mappedB",
            }))
        ]),
        testparam="testvalue",
    )

def test_init_processing_pipeline(test_backend):
    assert test_backend.processing_pipeline == ProcessingPipeline([
        ProcessingItem(FieldMappingTransformation({
            "fieldA": "mappedA",
        })),
        ProcessingItem(FieldMappingTransformation({
            "fieldB": "mappedB",
        })),
    ])

def test_only_backend_pipeline():
    test_backend = TextQueryTestBackend()
    assert test_backend.processing_pipeline == ProcessingPipeline([
        ProcessingItem(FieldMappingTransformation({
            "fieldA": "mappedA",
        })),
    ])

def test_init_config(test_backend):
    assert test_backend.config == { "testparam": "testvalue" }

def test_convert_value_str(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value
                condition: sel
        """)
    ) == ['mappedA="value"']

def test_convert_value_str_startswith(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith: "value"
                condition: sel
        """)
    ) == ['mappedA startswith "value"']

def test_convert_value_str_startswith_further_wildcard(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith: "va*lue"
                condition: sel
        """)
    ) == ['mappedA="va*lue*"']

def test_convert_value_str_startswith_expression_not_defined(test_backend, monkeypatch):
    monkeypatch.setattr(test_backend, "startswith_expression", None)
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith: "value"
                condition: sel
        """)
    ) == ['mappedA="value*"']

def test_convert_value_str_endswith(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|endswith: "value"
                condition: sel
        """)
    ) == ['mappedA endswith "value"']

def test_convert_value_str_endswith_further_wildcard(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|endswith: "va*lue"
                condition: sel
        """)
    ) == ['mappedA="*va*lue"']

def test_convert_value_str_endswith_expression_not_defined(test_backend, monkeypatch):
    monkeypatch.setattr(test_backend, "endswith_expression", None)
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|endswith: "value"
                condition: sel
        """)
    ) == ['mappedA="*value"']

def test_convert_value_str_contains(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: "value"
                condition: sel
        """)
    ) == ['mappedA contains "value"']

def test_convert_value_str_contains_further_wildcard(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: "va*lue"
                condition: sel
        """)
    ) == ['mappedA="*va*lue*"']

def test_convert_value_str_contains_expression_not_defined(test_backend, monkeypatch):
    monkeypatch.setattr(test_backend, "contains_expression", None)
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: "value"
                condition: sel
        """)
    ) == ['mappedA="*value*"']

def test_convert_value_num(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: 123
                condition: sel
        """)
    ) == ['mappedA=123']

def test_convert_value_bool(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: true
                    fieldB: false
                condition: sel
        """)
    ) == ['mappedA=1 and mappedB=0']

def test_convert_value_null(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: null
                condition: sel
        """)
    ) == ['mappedA is null']

def test_convert_query_expr():
    pipeline = ProcessingPipeline([
        ProcessingItem(QueryExpressionPlaceholderTransformation(expression="{field} in list({id})"))
    ])
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|expand: "%test%"
                condition: sel
        """)
    ) == ['mappedA in list(test)']

def test_convert_query_expr_unbound():
    pipeline = ProcessingPipeline([
        ProcessingItem(QueryExpressionPlaceholderTransformation(expression="_ in list({id})"))
    ])
    backend = TextQueryTestBackend(pipeline)
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    "|expand": "%test%"
                condition: sel
        """)
    ) == ['_ in list(test)']

def test_convert_value_regex(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: pat.*tern/foobar
                condition: sel
        """)
    ) == ['mappedA=/pat.*tern\\/foo\\bar/']

def test_convert_value_regex_unbound(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    "|re": pat.*tern/foobar
                condition: sel
        """)
    ) == ['_=/pat.*tern\\/foo\\bar/']

def test_convert_value_cidr_wildcard_none(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cidr: 192.168.0.0/14
                condition: sel
        """)
    ) == ['mappedA=192.168.0.0/14']


def test_convert_value_cidr_wildcard_asterisk(test_backend):
    my_backend = test_backend
    my_backend.cidr_wildcard = "*"
    assert my_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cidr: 192.168.0.0/14
                condition: sel
        """)
    ) == ['mappedA in ("192.168.*", "192.169.*", "192.170.*", "192.171.*")']

def test_convert_compare(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|lt: 123
                    fieldB|lte: 123
                    fieldC|gt: 123
                    fieldD|gte: 123
                condition: sel
        """)
    ) == ['mappedA<123 and mappedB<=123 and fieldC>123 and fieldD>=123']

def test_convert_compare_str(test_backend):
    with pytest.raises(SigmaTypeError, match="incompatible to value type"):
        test_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|lt: test
                    condition: sel
            """))

def test_convert_or_in_list(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - value1
                        - value2
                        - value3
                condition: sel
        """)
    ) == ['mappedA in ("value1", "value2", "value3")']

def test_convert_or_in_list_with_wildcards(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - value1
                        - value2*
                        - val*ue3
                condition: sel
        """)
    ) == ['mappedA in ("value1", "value2*", "val*ue3")']

def test_convert_or_in_list_with_wildcards_disabled(test_backend):
    test_backend.in_expressions_allow_wildcards = False
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - value1
                        - value2
                        - val*ue3
                condition: sel
        """)
    ) == ['mappedA="value1" or mappedA="value2" or mappedA="val*ue3"']

def test_convert_or_in_separate(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: value1
                sel2:
                    fieldA: value2
                sel3:
                    fieldA: value3
                condition: sel1 or sel2 or sel3
        """)
    ) == ['mappedA in ("value1", "value2", "value3")']

def test_convert_or_in_mixed_keyword_field(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: value1
                sel2:
                    fieldB: value2
                sel3: value3
                condition: sel1 or sel2 or sel3
        """)
    ) == ['mappedA="value1" or mappedB="value2" or _="value3"']

def test_convert_or_in_mixed_fields(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: value1
                sel2:
                    fieldB: value2
                sel3:
                    fieldA: value3
                condition: sel1 or sel2 or sel3
        """)
    ) == ['mappedA="value1" or mappedB="value2" or mappedA="value3"']

def test_convert_or_in_unallowed_value_type(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - value1
                        - value2
                        - null
                condition: sel
        """)
    ) == ['mappedA="value1" or mappedA="value2" or mappedA is null']

def test_convert_and_in_list(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|all:
                        - value1
                        - value2
                        - value3
                condition: sel
        """)
    ) == ['mappedA contains-all ("value1", "value2", "value3")']

def test_convert_and_in_list_or_disabled(test_backend):
    test_backend.convert_or_as_in = False
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|all:
                        - value1
                        - value2
                        - value3
                condition: sel
        """)
    ) == ['mappedA contains-all ("value1", "value2", "value3")']

def test_convert_or_in_list_and_disabled(test_backend):
    test_backend.convert_and_as_in = False
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - value1
                        - value2
                        - value3
                condition: sel
        """)
    ) == ['mappedA in ("value1", "value2", "value3")']

def test_convert_or_in_list_disabled(test_backend):
    test_backend.convert_or_as_in = False
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - value1
                        - value2
                        - value3
                condition: sel
        """)
    ) == ['mappedA="value1" or mappedA="value2" or mappedA="value3"']

def test_convert_and_in_list_disabled(test_backend):
    test_backend.convert_and_as_in = False
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|all:
                        - value1
                        - value2
                        - value3
                condition: sel
        """)
    ) == ['mappedA="value1" and mappedA="value2" and mappedA="value3"']

def test_convert_or_in_list_numbers(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - 1
                        - 2
                        - 3
                condition: sel
        """)
    ) == ['mappedA in (1, 2, 3)']

def test_convert_unbound_values(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    - value1
                    - value2
                    - 123
                condition: sel
        """)
    ) == ['_="value1" or _="value2" or _=123']

def test_convert_invalid_unbound_bool(test_backend):
    with pytest.raises(SigmaValueError, match="Boolean values can't appear as standalone"):
        test_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel: true
                    condition: sel
            """)
        )

def test_convert_collect_error(test_backend):
    test_backend.collect_errors = True
    collection = SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel: true
                condition: sel
        """)
    rule = collection.rules[0]

    res = test_backend.convert(collection)
    error = test_backend.errors[0]
    assert res == [] and error[0] == rule and isinstance(error[1], SigmaValueError)

def test_convert_invalid_unbound_cidr(test_backend):
    with pytest.raises(SigmaValueError, match="CIDR values can't appear as standalone"):
        test_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                       "|cidr": 192.168.0.0/16
                    condition: sel
            """)
        )

def test_convert_and(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: value1
                sel3:
                    fieldC: value3
                condition: sel1 and sel3
        """)
    ) == ['mappedA="value1" and fieldC="value3"']

class TextQueryTestBackendEmptyAND(TextQueryTestBackend):
    and_token = " "

def test_convert_and_emptytoken():
    assert TextQueryTestBackendEmptyAND().convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: value1
                sel3:
                    fieldC: value3
                condition: sel1 and sel3
        """)
    ) == ['mappedA="value1" fieldC="value3"']

class TextQueryTestBackendEmptyOR(TextQueryTestBackend):
    or_token = " "

def test_convert_or_emptytoken():
    assert TextQueryTestBackendEmptyOR().convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: value1
                sel3:
                    fieldC: value3
                condition: sel1 or sel3
        """)
    ) == ['mappedA="value1" fieldC="value3"']

def test_convert_or(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: value1
                sel3:
                    fieldC: value3
                condition: sel1 or sel3
        """)
    ) == ['mappedA="value1" or fieldC="value3"']

def test_convert_not(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value1
                condition: not sel
        """)
    ) == ['not mappedA="value1"']

def test_convert_precedence(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: value1
                sel2:
                    fieldB: value2
                sel3:
                    fieldC: value3
                sel4:
                    fieldD: value4
                condition: (sel1 or sel2) and not (sel3 and sel4)
        """)
    ) == ['(mappedA="value1" or mappedB="value2") and not (fieldC="value3" and fieldD="value4")']

def test_convert_multi_conditions(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: value1
                sel3:
                    fieldC: value3
                condition:
                    - sel1
                    - sel3
        """)
    ) == ['mappedA="value1"', 'fieldC="value3"']

def test_convert_list_cidr_wildcard_none(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cidr:
                        - 192.168.0.0/14
                        - 10.10.10.0/24
                condition: sel
        """)
    ) == ['mappedA=192.168.0.0/14 or mappedA=10.10.10.0/24']

def test_convert_list_cidr_wildcard_asterisk(test_backend):
    my_backend = test_backend
    my_backend.cidr_wildcard = "*"
    assert my_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cidr:
                        - 192.168.0.0/14
                        - 10.10.10.0/24
                condition: sel
        """)
    ) == ['mappedA in ("192.168.*", "192.169.*", "192.170.*", "192.171.*") or mappedA="10.10.10.*"']