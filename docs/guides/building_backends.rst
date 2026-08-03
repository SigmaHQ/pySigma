Building a Backend
==================

This guide explains how to create a pySigma backend that converts Sigma rules into queries
for a target system.

Overview
--------

A backend translates Sigma's detection logic into a specific query language. pySigma provides
two base classes:

* :class:`~sigma.conversion.base.Backend` — Generic base for arbitrary output formats.
* :class:`~sigma.conversion.base.TextQueryBackend` — Specialized base for text-based query
  languages (most common).

For most query-language-based systems, you should use ``TextQueryBackend``.

Getting Started with the Cookie Cutter Template
-----------------------------------------------

The fastest way to start a new backend project is the
`pySigma Cookie Cutter Template <https://github.com/SigmaHQ/cookiecutter-pySigma-backend>`_:

.. code-block:: bash

   pip install cookiecutter
   cookiecutter https://github.com/SigmaHQ/cookiecutter-pySigma-backend

This creates a complete project structure with:

* Backend skeleton class
* Test structure
* Packaging configuration
* CI/CD pipeline

Creating a TextQueryBackend
---------------------------

The ``TextQueryBackend`` generates text-based queries by defining class variables that control
how different Sigma elements are represented in the target query language. Here is the minimal
structure:

.. code-block:: python

   from sigma.conversion.base import TextQueryBackend
   from sigma.types import CompareOperators
   from typing import ClassVar
   import re

   class MyBackend(TextQueryBackend):
       """My custom backend for TargetSystem."""
       name: ClassVar[str] = "My Backend"
       formats: ClassVar[dict[str, str]] = {
           "default": "Plain queries",
           "json": "JSON-formatted output",
       }

       # Boolean operators
       or_token: ClassVar[str] = " OR "
       and_token: ClassVar[str] = " AND "
       not_token: ClassVar[str] = "NOT "
       eq_token: ClassVar[str] = "="

       # Grouping
       group_expression: ClassVar[str] = "({expr})"

       # String quoting
       str_quote: ClassVar[str] = '"'
       escape_char: ClassVar[str] = "\\\\"
       wildcard_multi: ClassVar[str] = "*"
       wildcard_single: ClassVar[str] = "?"

       # Field quoting
       field_quote: ClassVar[str] = "'"
       field_quote_pattern: ClassVar[re.Pattern] = re.compile("^\\\\w+$")

       # Regular expressions
       re_expression: ClassVar[str] = "{field} matches /{regex}/"
       re_escape_char: ClassVar[str] = "\\\\"
       re_escape: ClassVar[list[str]] = ["/"]

       # Null/exists expressions
       field_null_expression: ClassVar[str] = "{field} IS NULL"
       field_exists_expression: ClassVar[str] = "{field} IS NOT NULL"
       field_not_exists_expression: ClassVar[str] = "{field} IS NULL"

       # Comparison operators
       compare_op_expression: ClassVar[str] = "{field}{operator}{value}"
       compare_operators: ClassVar[dict[CompareOperators, str]] = {
           CompareOperators.LT: "<",
           CompareOperators.LTE: "<=",
           CompareOperators.GT: ">",
           CompareOperators.GTE: ">=",
       }

       # CIDR expressions
       cidr_expression: ClassVar[str] = "cidrmatch({field}, \\"{value}\\")"

       # Unbound (keyword) expressions
       unbound_value_str_expression: ClassVar[str] = "\\"{value}\\""
       unbound_value_num_expression: ClassVar[str] = "{value}"
       unbound_value_re_expression: ClassVar[str] = "/{value}/"

Key Class Variables
^^^^^^^^^^^^^^^^^^^

The ``TextQueryBackend`` provides many class variables to customize query generation.
Here are the most important categories:

**Boolean Operators and Grouping:**

* ``or_token``: String placed between OR-linked conditions (e.g., ``" OR "``).
* ``and_token``: String placed between AND-linked conditions (e.g., ``" AND "``).
* ``not_token``: String placed before negated conditions (e.g., ``"NOT "``).
* ``eq_token``: String placed between field name and value (e.g., ``"="``).
* ``group_expression``: Format string for grouping with ``{expr}`` placeholder (e.g., ``"({expr})"``).
* ``token_separator``: Separator between tokens (default: ``" "``).

**Operator Precedence:**

* ``precedence``: Tuple of ``(ConditionNOT, ConditionAND, ConditionOR)`` defining precedence
  from highest to lowest.
* ``parenthesize``: Set to ``True`` to always add parentheses around expressions.

**Field Handling:**

* ``field_quote``: Character to quote field names (e.g., ``"'"`` or ``'``"``.
* ``field_quote_pattern``: Regex pattern — fields matching (or not matching, depending on
  negation) this pattern are quoted.
* ``field_quote_pattern_negation``: If ``True``, quote fields that do NOT match the pattern.
* ``field_escape``: Character used to escape special characters in field names.

**String/Value Handling:**

* ``str_quote``: Character used to quote string values.
* ``escape_char``: Character used to escape special characters in values.
* ``wildcard_multi``: Representation of multi-character wildcard (``*``).
* ``wildcard_single``: Representation of single-character wildcard (``?``).
* ``add_escaped``: Additional characters to escape beyond wildcards and quotes.
* ``filter_chars``: Characters to silently remove from values.
* ``bool_values``: Dict mapping Python booleans to their string representation.

**Pattern Matching Expressions:**

* ``startswith_expression``: Format string for startswith matching with ``{field}`` and ``{value}``.
* ``endswith_expression``: Format string for endswith matching.
* ``contains_expression``: Format string for contains matching.
* ``wildcard_match_expression``: Format string for wildcard matching.
* ``re_expression``: Format string for regex matching with ``{field}`` and ``{regex}``.

**Comparison and Special Expressions:**

* ``compare_op_expression``: Format string for comparison operations.
* ``compare_operators``: Dict mapping ``CompareOperators`` enum values to strings.
* ``cidr_expression``: Format string for CIDR/network matching.
* ``field_null_expression``: Format string for null value checks.
* ``field_exists_expression``: Format string for field existence checks.
* ``field_not_exists_expression``: Format string for non-existence checks.

**Unbound/Keyword Expressions:**

* ``unbound_value_str_expression``: Expression for string values without a field.
* ``unbound_value_num_expression``: Expression for numeric values without a field.
* ``unbound_value_re_expression``: Expression for regex values without a field.

**In-Expressions (value lists):**

* ``convert_or_as_in``: Convert OR-linked same-field values to in-expressions.
* ``convert_and_as_in``: Convert AND-linked same-field values to in-expressions.
* ``in_expressions_allow_wildcards``: Allow wildcards in in-expressions.
* ``field_in_list_expression``: Format string with ``{field}``, ``{op}``, ``{list}``.
* ``or_in_operator``: Operator string for OR in-expressions (e.g., ``"in"``).
* ``and_in_operator``: Operator string for AND in-expressions (e.g., ``"contains-all"``).
* ``list_separator``: Separator between list values (e.g., ``", "``).

**Query Structure:**

* ``query_expression``: Wraps the generated query. Default is ``"{query}"``. Supports
  ``{query}``, ``{rule}``, and ``{state}`` placeholders.
* ``state_defaults``: Default values for conversion state variables.

**Deferred Expressions:**

* ``deferred_start``: String prepended before deferred expressions.
* ``deferred_separator``: Separator between deferred expressions.
* ``deferred_only_query``: Query used when only deferred expressions exist.

Implementing Output Formats
----------------------------

**Preferred Approach: Processing Pipelines with Query Postprocessing**

The recommended way to implement output formats is through processing pipelines with query
postprocessing transformations. This approach is more flexible, better configurable via
template variables, and allows users to customize output through pipeline configuration
rather than backend code. This is the modern best practice for format handling.

Here's an example using a query postprocessing transformation for Splunk savedsearches.conf:

.. code-block:: python

   from sigma.processing.postprocessing import PostprocessingTransformation, PostprocessingItem
   from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
   from jinja2 import Template
   from typing import ClassVar

   class SplunkSavedsearchPostprocessing(PostprocessingTransformation):
       """Convert query output to Splunk savedsearches.conf format."""

       def apply_postprocessing(self, queries: list[str], **kwargs) -> str:
           """Generate Splunk savedsearches.conf content."""
           configs = []
           for i, q in enumerate(queries):
               config = f"[search_{i}]\\nquery = {q}\\ndescription = {kwargs.get('description', '')}\\n"
               configs.append(config)
           return "\\n".join(configs)

   class MyBackend(TextQueryBackend):
       # Savedsearch format via processing pipeline
       output_format_processing_pipeline: ClassVar[dict[str, ProcessingPipeline]] = {
           "savedsearch": ProcessingPipeline(
               name="splunk_savedsearch_format",
               postprocessing_items=[
                   PostprocessingItem(
                       identifier="convert_to_savedsearch",
                       transformation=SplunkSavedsearchPostprocessing(),
                       rule_conditions=[],
                   )
               ]
           )
       }

**Legacy Approach: finalize_output Methods (Deprecated)**

For backward compatibility, backends can still implement output formats using ``finalize_output_<name>``
methods, though this approach is no longer recommended:

.. code-block:: python

   class MyBackend(TextQueryBackend):
       formats: ClassVar[dict[str, str]] = {
           "default": "Plain text queries",
           "json": "JSON-formatted queries for import",
           "savedsearch": "Saved search configuration",
       }

       def finalize_output_default(self, queries: list[str]) -> list[str]:
           """Return queries as a simple list."""
           return queries

       def finalize_output_json(self, queries: list[str]) -> str:
           """Return queries as a JSON array."""
           import json
           return json.dumps([{"query": q} for q in queries], indent=2)

       def finalize_output_savedsearch(self, queries: list[str]) -> str:
           """Return queries wrapped in saved search config."""
           configs = []
           for i, q in enumerate(queries):
               configs.append(f"[search_{i}]\\nquery = {q}")
           return "\\n\\n".join(configs)

Using ``finalize_query`` for Per-Rule Wrapping
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``finalize_query`` method is called for each converted condition and can wrap or
transform the query:

.. code-block:: python

   def finalize_query(
       self,
       rule: SigmaRule,
       query: str,
       index: int,
       state: ConversionState,
       output_format: str,
   ) -> str:
       """Wrap query with data source prefix from state."""
       table = state.get("table", "default_table")
       return f"SELECT * FROM {table} WHERE {query}"

Backend Processing Pipeline
---------------------------

You can define a built-in processing pipeline that is always applied before user-specified
pipelines:

.. code-block:: python

   class MyBackend(TextQueryBackend):
       backend_processing_pipeline: ClassVar[ProcessingPipeline] = ProcessingPipeline(
           name="my_backend_pipeline",
           items=[
               ProcessingItem(
                   identifier="my_backend_field_mapping",
                   transformation=FieldMappingTransformation({
                       "EventID": "event_id",
                   }),
               )
           ]
       )

You can also define format-specific pipelines:

.. code-block:: python

   from collections import defaultdict

   class MyBackend(TextQueryBackend):
       output_format_processing_pipeline: ClassVar[dict[str, ProcessingPipeline]] = defaultdict(
           ProcessingPipeline,
           json=ProcessingPipeline(
               name="json_format_pipeline",
               items=[...]
           ),
       )

Backend Options
---------------

Backends can accept runtime options passed via the ``-O`` flag in sigma-cli. These are
available through ``self.backend_options`` and are also set as pipeline variables with a
``backend_`` prefix:

.. code-block:: python

   class MyBackend(TextQueryBackend):
       def finalize_query(self, rule, query, index, state, output_format):
           # Access backend option
           prefix = self.backend_options.get("query_prefix", "")
           return f"{prefix}{query}"

   # Usage:
   backend = MyBackend(query_prefix="index=main ")

Overriding Conversion Methods
-----------------------------

For complex cases where class variables aren't sufficient, override the conversion methods:

.. code-block:: python

   from sigma.conditions import ConditionFieldEqualsValueExpression
   from sigma.types import SigmaString, SigmaRegularExpression

   class MyBackend(TextQueryBackend):
       def convert_condition_field_eq_value_str(
           self,
           cond: ConditionFieldEqualsValueExpression,
           state: ConversionState,
       ) -> str:
           """Custom string value conversion."""
           field = self.escape_and_quote_value(cond.field)
           value = cond.value
           if value.contains_special():
               # Handle wildcard values
               return f"match({field}, {self.convert_value_str(value, state)})"
           else:
               return f"{field}={self.convert_value_str(value, state)}"

Conventions and Best Practices
------------------------------

When building a backend, follow these conventions:

1. **Provide actionable default output**: The default format should produce queries that can
   be directly used in the target system.

2. **Don't concatenate output in the default format**: Return individual queries, not a single
   concatenated string. Use specific output formats for concatenation.

3. **Don't print to console or write files**: Backends should return strings or data structures.
   Leave I/O to the calling application.

4. **Use processing pipelines for transformations**: Don't implement field mappings or log source
   handling directly in the backend. Use the built-in pipeline for generic transformations.

5. **Prefer processing pipelines with postprocessing for output formats**: Instead of implementing
   ``finalize_output_<name>`` methods, use query postprocessing transformations within processing
   pipelines. This approach is more flexible, allows users to customize output through pipeline
   configuration and template variables, and follows modern pySigma best practices.

6. **Handle backend options properly**: Accept configuration through backend options, not
   hard-coded values.

7. **Return strings or bytes from postprocessing**: Some output formats produce strings,
   others may produce bytes (e.g., binary export formats).

8. **Document supported features**: Clearly indicate which Sigma features your backend supports
   and which ones it doesn't.

Testing Your Backend
--------------------

Use pytest to test your backend. A typical test structure:

.. code-block:: python

   import pytest
   from sigma.rule import SigmaRule
   from sigma.collection import SigmaCollection
   from my_package.backend import MyBackend

   @pytest.fixture
   def backend():
       return MyBackend()

   def test_basic_query(backend):
       rule = SigmaRule.from_yaml(\"\"\"
           title: Test Rule
           status: test
           logsource:
               category: process_creation
               product: windows
           detection:
               selection:
                   CommandLine|contains: test
               condition: selection
       \"\"\")
       result = backend.convert(SigmaCollection(rules=[rule]))
       assert result == ['CommandLine contains "test"']

   def test_and_condition(backend):
       rule = SigmaRule.from_yaml(\"\"\"
           title: Test Rule
           status: test
           logsource:
               category: process_creation
               product: windows
           detection:
               selection:
                   CommandLine|contains: test
                   Image|endswith: .exe
               condition: selection
       \"\"\")
       result = backend.convert(SigmaCollection(rules=[rule]))
       assert "AND" in result[0]

Plugin Registration
-------------------

To make your backend discoverable as a plugin, place it in the ``sigma.backends`` namespace
and provide a ``backends`` dictionary:

.. code-block:: python

   # In sigma/backends/mybackend/__init__.py
   from .backend import MyBackend

   backends = {
       "mybackend": MyBackend,
   }

See the :doc:`plugin_system` guide for more details on plugin registration.
