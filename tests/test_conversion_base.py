import re
from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.conversion.base import TextQueryBackend
from sigma.processing.conditions import IncludeFieldCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import DropDetectionItemTransformation, FieldMappingTransformation, QueryExpressionPlaceholderTransformation, SetStateTransformation
from sigma.exceptions import SigmaTypeError, SigmaValueError
import pytest

@pytest.fixture
def test_backend():
    return TextQueryTestBackend(
        ProcessingPipeline([
            ProcessingItem(FieldMappingTransformation({
                "fieldB": "mappedB",
            })),
            ProcessingItem(SetStateTransformation("index", "test")),
        ]),
        testparam="testvalue",
    )

def test_backend_pipeline():
    test_backend = TextQueryTestBackend()
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                    fieldC: valueC
                condition: sel
        """)
    ) == ['mappedA="valueA" and fieldB="valueB" and fieldC="valueC"']

def test_backend_and_custom_pipeline(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                    fieldC: valueC
                condition: sel
        """)
    ) == ['mappedA="valueA" and mappedB="valueB" and fieldC="valueC"']

def test_backend_custom_format_pipeline(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                    fieldC: valueC
                condition: sel
        """),
        output_format="test",
    ) == ['mappedA="valueA" and mappedB="valueB" and mappedC="valueC"']

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
                    field A: value
                condition: sel
        """)
    ) == ['mappedA="value" and \'field A\'="value"']

def test_convert_value_str_empty(test_backend):
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
                    fieldB: ''
                condition: sel
        """)
    ) == ['mappedA="value" and mappedB=""']

def test_convert_value_str_quote_pattern_match(test_backend, monkeypatch):
    monkeypatch.setattr(test_backend, "str_quote_pattern", re.compile("^.*\\s"))
    monkeypatch.setattr(test_backend, "str_quote_pattern_negation", False)
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: test value
                condition: sel
        """)
    ) == ['mappedA="test value"']

def test_convert_value_str_quote_pattern_nomatch(test_backend, monkeypatch):
    monkeypatch.setattr(test_backend, "str_quote_pattern", re.compile("^.*\\s"))
    monkeypatch.setattr(test_backend, "str_quote_pattern_negation", False)
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
    ) == ['mappedA=value']

def test_convert_value_str_quote_pattern_negated(test_backend, monkeypatch):
    monkeypatch.setattr(test_backend, "str_quote_pattern", re.compile("^\\w+$"))
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
    ) == ['mappedA=value']

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
                    field A|startswith: "value"
                condition: sel
        """)
    ) == ['mappedA startswith "value" and \'field A\' startswith "value"']

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
                    field A|startswith: "va*lue"
                condition: sel
        """)
    ) == ['mappedA match "va*lue*" and \'field A\' match "va*lue*"']

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
    ) == ['mappedA match "value*"']

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
                    field A|endswith: "value"
                condition: sel
        """)
    ) == ['mappedA endswith "value" and \'field A\' endswith "value"']

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
                    field A|endswith: "va*lue"
                condition: sel
        """)
    ) == ['mappedA match "*va*lue" and \'field A\' match "*va*lue"']

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
    ) == ['mappedA match "*value"']

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
                    field A|contains: "value"
                condition: sel
        """)
    ) == ['mappedA contains "value" and \'field A\' contains "value"']

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
    ) == ['mappedA match "*va*lue*"']

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
    ) == ['mappedA match "*value*"']

def test_convert_value_str_wildcard_no_match_expr(test_backend, monkeypatch):
    monkeypatch.setattr(test_backend, "wildcard_match_expression", None)
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: val*ue
                condition: sel
        """)
    ) == ['mappedA="val*ue"']

def test_convert_value_expansion_with_all(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
        title: Testrule
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                CommandLine|windash|contains|all:
                    - -foo
                    - -bar
            condition: selection
        """)
    ) == ['(CommandLine contains "-foo" or CommandLine contains "/foo") and (CommandLine contains "-bar" or CommandLine contains "/bar")']

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
                    field A: 123
                condition: sel
        """)
    ) == ['mappedA=123 and \'field A\'=123']

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
                    field B: false
                condition: sel
        """)
    ) == ['mappedA=1 and mappedB=0 and \'field B\'=0']

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
                    field A: null
                condition: sel
        """)
    ) == ['mappedA is null and \'field A\' is null']

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
                    field A|expand: "%test%"
                condition: sel
        """)
    ) == ['mappedA in list(test) and \'field A\' in list(test)']

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
                    field A|re: pat.*tern/foobar
                condition: sel
        """)
    ) == ['mappedA=/pat.*tern\\/foo\\bar/ and \'field A\'=/pat.*tern\\/foo\\bar/']

def test_convert_value_regex_multi_mapping():
    test_backend = TextQueryTestBackend(
        ProcessingPipeline([
            ProcessingItem(FieldMappingTransformation({
                "fieldB": ["mappedB1", "mappedB2"],
            })),
        ]),
    )
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldB|re: pat.*tern/foobar
                condition: sel
        """)
    ) == ['mappedB1=/pat.*tern\\/foo\\bar/ or mappedB2=/pat.*tern\\/foo\\bar/']

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

def test_convert_value_cidr_wildcard_native(test_backend):
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
                    field A|cidr: 192.168.0.0/14
                condition: sel
        """)
    ) == ['cidrmatch(\'mappedA\', "192.168.0.0/14") and cidrmatch(\'field A\', "192.168.0.0/14")']

def test_convert_value_cidr_wildcard_native_template_network_prefixlen(test_backend, monkeypatch):
    monkeypatch.setattr(test_backend, "cidr_expression", "cidrmatch('{field}', '{network}', {prefixlen})")
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
    ) == ["cidrmatch('mappedA', '192.168.0.0', 14)"]

def test_convert_value_cidr_wildcard_native_template_network_netmask(test_backend, monkeypatch):
    monkeypatch.setattr(test_backend, "cidr_expression", "cidrmatch('{field}', '{network}', '{netmask}')")
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
    ) == ["cidrmatch('mappedA', '192.168.0.0', '255.252.0.0')"]

def test_convert_value_cidr_wildcard_expression(test_backend, monkeypatch):
    monkeypatch.setattr(test_backend, "cidr_expression", None)
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
                    field A|cidr: 192.168.0.0/14
                condition: sel
        """)
    ) == ['mappedA in ("192.168.*", "192.169.*", "192.170.*", "192.171.*") and \'field A\' in ("192.168.*", "192.169.*", "192.170.*", "192.171.*")']

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
                    field A|lt: 123
                    fieldB|lte: 123
                    field B|lte: 123
                    fieldC|gt: 123
                    field C|gt: 123
                    fieldD|gte: 123
                    field D|gte: 123
                condition: sel
        """)
    ) == ['mappedA<123 and \'field A\'<123 and mappedB<=123 and \'field B\'<=123 and fieldC>123 and \'field C\'>123 and fieldD>=123 and \'field D\'>=123']

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
                    field A:
                        - value1
                        - value2
                        - value3
                condition: sel
        """)
    ) == ['(mappedA in ("value1", "value2", "value3")) and (\'field A\' in ("value1", "value2", "value3"))']

def test_convert_or_in_list_empty_string(test_backend):
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
                        - ''
                condition: sel
        """)
    ) == ['mappedA in ("value1", "value2", "")']

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
    ) == ['mappedA="value1" or mappedA="value2" or mappedA match "val*ue3"']

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
                    field A|all:
                        - value1
                        - value2
                        - value3
                condition: sel
        """)
    ) == ['mappedA contains-all ("value1", "value2", "value3") and \'field A\' contains-all ("value1", "value2", "value3")']

def test_convert_and_in_list_single_item(test_backend):
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|all: value1
                condition: sel
        """)
    ) == ['mappedA="value1"']

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

def test_convert_parenthesize(test_backend, monkeypatch):
    monkeypatch.setattr(test_backend, "parenthesize", True)
    monkeypatch.setattr(test_backend, "convert_or_as_in", False)
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
                    fieldB:
                       - value2
                       - value3
                       - value4
                sel2:
                    fieldC:
                       - value4
                       - value5
                       - value6
                    fieldD: value7
                condition: sel1 or not sel2
        """)
    ) == ['(mappedA="value1" and (mappedB="value2" or mappedB="value3" or mappedB="value4")) or (not ((fieldC="value4" or fieldC="value5" or fieldC="value6") and fieldD="value7"))']

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
    ) == ['cidrmatch(\'mappedA\', "192.168.0.0/14") or cidrmatch(\'mappedA\', "10.10.10.0/24")']

def test_convert_list_cidr_wildcard_asterisk(test_backend, monkeypatch):
    monkeypatch.setattr(test_backend, "cidr_expression", None)
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
    ) == ['mappedA in ("192.168.*", "192.169.*", "192.170.*", "192.171.*") or mappedA in ("10.10.10.*")']

def test_convert_state(test_backend):
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
        """), "state"
    ) == ['index=test (mappedA="value")']

def test_convert_dropped_detection_item_and():
    backend = TextQueryTestBackend(
        ProcessingPipeline([
            ProcessingItem(
                DropDetectionItemTransformation(),
                field_name_conditions=[ IncludeFieldCondition(fields=["EventID"]) ],
            ),
        ]),
    )
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    EventID: 123
                sel2:
                    fieldB: value
                condition: sel1 and sel2
        """)
    ) == ['fieldB="value"']

def test_convert_dropped_detection_item_or():
    backend = TextQueryTestBackend(
        ProcessingPipeline([
            ProcessingItem(
                DropDetectionItemTransformation(),
                field_name_conditions=[ IncludeFieldCondition(fields=["EventID"]) ],
            ),
        ]),
    )
    assert backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    EventID: 123
                sel2:
                    fieldB: value
                condition: sel1 or sel2
        """)
    ) == ['fieldB="value"']

# Quoting & Escaping Tests
quote_escape_config = ("'", re.compile("^[\\w.;\\\\]+$"), True, "\\", True, re.compile(";"))
quote_always_escape_quote_config = ("'", None, True, "\\", True, None)
quote_only_config = ("'", re.compile("^.*\s"), False, None, False, None)
escape_only_config = (None, None, True, "\\", False, re.compile("[\s]"))
quoting_escaping_testcases = {  # test name -> quoting/escaping parameters (see test below), test field name, expected result
    "escape_quote_nothing": (
        quote_escape_config,
        "foo.bar", "foo.bar"
    ),
    "escape_quote_quoteonly": (
        quote_escape_config,
        "foo bar", "'foo bar'"
    ),
    "escape_quote_quote_and_escape": (
        quote_escape_config,
        "foo bar;foo;bar", "'foo bar\\;foo\\;bar'"
    ),
    "escape_quote_escapeonly": (
        quote_escape_config,
        "foobar;foo;bar", "foobar\\;foo\\;bar"
    ),
    "escape_quote_escapeonly_start_end": (
        quote_escape_config,
        ";foo;bar;", "\\;foo\\;bar\\;"
    ),
    "escape_quote_quote_and_escape_quotechar": (
        quote_escape_config,
        "foo bar';foo;bar", "'foo bar\\'\\;foo\\;bar'"
    ),
    "quote_always_escape_quote_only": (
        quote_always_escape_quote_config,
        "foo 'bar'", "'foo \\'bar\\''"
    ),
    "quote_only": (
        quote_only_config,
        "foo bar", "'foo bar'"
    ),
    "escape_only": (
        escape_only_config,
        "foo bar", "foo\\ bar"
    ),
    "escape_only_start_end": (
        escape_only_config,
        " foo bar ", "\\ foo\\ bar\\ "
    ),
}

@pytest.mark.parametrize(
    "backend_parameters,input,expected_result",
    list(quoting_escaping_testcases.values()),
    ids=list(quoting_escaping_testcases.keys())
    )
def test_quote_escape(backend_parameters, input, expected_result, test_backend):
    for param, value in zip(
        (
            "field_quote",
            "field_quote_pattern",
            "field_quote_pattern_negation",
            "field_escape",
            "field_escape_quote",
            "field_escape_pattern",
        ), backend_parameters):
        setattr(test_backend, param, value)

    assert test_backend.escape_and_quote_field(input) == expected_result

def test_multi_field_mapping_conversion():
    test_backend = TextQueryTestBackend(
        ProcessingPipeline([
            ProcessingItem(FieldMappingTransformation({
                "fieldB": ["mappedB", "mappedC" ],
            })),
        ]),
    )
    assert test_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldB: value1
                condition: sel
        """)
    ) == ['mappedB="value1" or mappedC="value1"']