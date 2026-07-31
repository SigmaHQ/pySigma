Converting Sigma Rules into Queries
====================================

This guide explains how to use pySigma to convert Sigma detection rules into queries for
security monitoring systems.

Basic Conversion
----------------

The simplest conversion workflow involves three steps:

1. Parse a Sigma rule into a ``SigmaRule`` object.
2. Create a backend instance (optionally with a processing pipeline).
3. Call the backend's ``convert`` method on a ``SigmaCollection``.

.. code-block:: python

   from sigma.rule import SigmaRule
   from sigma.collection import SigmaCollection

   # Step 1: Parse the rule
   rule = SigmaRule.from_yaml("""
       title: Mimikatz Detection
       status: test
       logsource:
           category: process_creation
           product: windows
       detection:
           selection:
               CommandLine|contains: mimikatz
           condition: selection
   """)

   # Step 2: Create a backend (using a real backend package)
   # from sigma.backends.splunk import SplunkBackend
   # backend = SplunkBackend()

   # For demonstration, use the test backend:
   from sigma.backends.test import TextQueryTestBackend
   backend = TextQueryTestBackend()

   # Step 3: Convert
   collection = SigmaCollection(rules=[rule])
   result = backend.convert(collection)

The result is a list of queries in the backend's output format.

Working with Rule Collections
-----------------------------

In practice, you will often work with multiple rules at once. ``SigmaCollection`` provides
several ways to load rules:

Loading from YAML Strings
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from sigma.collection import SigmaCollection

   # Single YAML document
   yaml_content = open("rule.yml").read()
   collection = SigmaCollection.from_yaml(yaml_content)

   # Multiple YAML documents in one string (separated by ---)
   multi_yaml = open("rules.yml").read()
   collection = SigmaCollection.from_yaml(multi_yaml)

Loading from Files and Directories
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from sigma.collection import SigmaCollection
   from pathlib import Path

   # Load from a list of paths (files and/or directories)
   collection = SigmaCollection.load_ruleset([
       Path("./rules/windows/"),
       Path("./rules/custom_rule.yml"),
   ])

Loading from Dicts
^^^^^^^^^^^^^^^^^^

.. code-block:: python

   import yaml
   from sigma.collection import SigmaCollection

   # Parse YAML yourself and pass dicts
   rules_data = [yaml.safe_load(open(f)) for f in rule_files]
   collection = SigmaCollection.from_dicts(rules_data)

Merging Collections
^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   collection1 = SigmaCollection.from_yaml(yaml1)
   collection2 = SigmaCollection.from_yaml(yaml2)
   merged = SigmaCollection.merge([collection1, collection2])

Using Processing Pipelines
--------------------------

Processing pipelines transform rules before conversion. They are essential for adapting
generic Sigma rules to your specific environment. Pass them to the backend constructor:

.. code-block:: python

   from sigma.processing.pipeline import ProcessingPipeline

   # Load a pipeline from a YAML definition
   pipeline = ProcessingPipeline.from_yaml("""
       name: my_field_mapping
       priority: 20
       transformations:
         - id: field_mapping
           type: field_name_mapping
           mapping:
               CommandLine: process.command_line
               Image: process.executable
               ParentImage: process.parent.executable
   """)

   backend = TextQueryTestBackend(processing_pipeline=pipeline)
   result = backend.convert(collection)

You can also combine multiple pipelines:

.. code-block:: python

   pipeline1 = ProcessingPipeline.from_yaml(yaml1)
   pipeline2 = ProcessingPipeline.from_yaml(yaml2)
   combined = pipeline1 + pipeline2

   backend = TextQueryTestBackend(processing_pipeline=combined)

Output Formats
--------------

Backends can support multiple output formats. The default format typically returns a list
of query strings, but other formats may produce structured data (e.g., JSON for import into
a SIEM):

.. code-block:: python

   # Check available formats
   print(TextQueryTestBackend.formats)
   # {'default': 'Default output format', ...}

   # Convert with a specific format
   result = backend.convert(collection, output_format="default")

Error Handling
--------------

By default, conversion raises exceptions on errors. You can collect errors instead:

.. code-block:: python

   backend = TextQueryTestBackend(collect_errors=True)
   result = backend.convert(collection)

   # Check for errors
   for rule, error in backend.errors:
       print(f"Error converting '{rule.title}': {error}")

Converting Individual Rules
---------------------------

While ``convert`` operates on collections, you can also convert single rules:

.. code-block:: python

   backend = TextQueryTestBackend()
   backend.init_processing_pipeline()
   queries = backend.convert_rule(rule)

.. note::

   You must call ``init_processing_pipeline()`` before converting individual rules outside
   of the ``convert`` method.

Correlation Rules
-----------------

Sigma supports correlation rules that combine multiple detection rules with temporal or
statistical conditions. pySigma handles these through the same conversion interface:

.. code-block:: python

   from sigma.collection import SigmaCollection

   # Load rules including correlation rules
   yaml_content = """
   title: Base Detection
   name: base_rule
   status: test
   logsource:
       category: process_creation
       product: windows
   detection:
       selection:
           CommandLine|contains: suspicious
       condition: selection
   ---
   title: Correlation Rule
   status: test
   correlation:
       type: event_count
       rules:
           - base_rule
       group-by:
           - ComputerName
       timespan: 5m
       condition:
           gte: 10
   """

   collection = SigmaCollection.from_yaml(yaml_content)
   result = backend.convert(collection)

The backend must support correlation rule conversion for this to work. Not all backends
implement correlation support.

Complete Workflow Example
-------------------------

Here is a complete example showing the typical pySigma workflow:

.. code-block:: python

   from pathlib import Path
   from sigma.collection import SigmaCollection
   from sigma.processing.pipeline import ProcessingPipeline

   # In a real project, import your actual backend:
   # from sigma.backends.splunk import SplunkBackend
   from sigma.backends.test import TextQueryTestBackend

   # 1. Load rules
   collection = SigmaCollection.load_ruleset([Path("./sigma/rules/")])

   # 2. Set up processing pipeline
   pipeline = ProcessingPipeline.from_yaml("""
       name: my_environment
       priority: 20
       transformations:
         - id: field_mapping
           type: field_name_mapping
           mapping:
               CommandLine: process.command_line
               Image: process.executable
   """)

   # 3. Create backend with pipeline
   backend = TextQueryTestBackend(processing_pipeline=pipeline)

   # 4. Convert all rules
   queries = backend.convert(collection)

   # 5. Use the generated queries
   for query in queries:
       print(query)
