Getting Started
===============

Requirements
------------

pySigma requires Python 3.10 or later.

Installation
------------

Install pySigma using your preferred Python package manager:

.. code-block:: bash

   pip install pysigma

Or with Poetry:

.. code-block:: bash

   poetry add pysigma

Or with pipenv:

.. code-block:: bash

   pipenv install pysigma

Quick Example
-------------

Here is a minimal example that converts a Sigma rule into a query:

.. code-block:: python

   from sigma.rule import SigmaRule
   from sigma.backends.test import TextQueryTestBackend
   from sigma.collection import SigmaCollection

   # Parse a Sigma rule from YAML
   rule = SigmaRule.from_yaml("""
       title: Test Rule
       status: test
       logsource:
           category: process_creation
           product: windows
       detection:
           selection:
               CommandLine|contains: mimikatz
           condition: selection
   """)

   # Create a collection and convert with a backend
   collection = SigmaCollection(rules=[rule])
   backend = TextQueryTestBackend()
   result = backend.convert(collection)
   print(result)

.. note::

   The ``TextQueryTestBackend`` is a test backend included in pySigma for testing purposes.
   For real-world use, install a backend for your target system (e.g.,
   ``pySigma-backend-splunk``).

Using Processing Pipelines
--------------------------

Processing pipelines transform rules before conversion. They are typically used to map generic
Sigma field names to the specific field names used in your environment:

.. code-block:: python

   from sigma.processing.pipeline import ProcessingPipeline
   from sigma.processing.transformations import FieldMappingTransformation

   # Create a pipeline that maps field names
   pipeline = ProcessingPipeline(
       name="my_pipeline",
       priority=20,
       items=[
           ProcessingItem(
               identifier="field_mapping",
               transformation=FieldMappingTransformation({
                   "CommandLine": "process.command_line",
                   "Image": "process.executable",
               }),
           )
       ]
   )

   # Pass pipeline to backend
   backend = TextQueryTestBackend(processing_pipeline=pipeline)
   result = backend.convert(collection)

Loading Rules from Files
------------------------

You can load rule collections from directories or individual files:

.. code-block:: python

   from sigma.collection import SigmaCollection
   from pathlib import Path

   # Load from a directory of YAML files
   collection = SigmaCollection.load_ruleset([Path("./rules/")])

   # Load from a single YAML string containing multiple documents
   collection = SigmaCollection.from_yaml(open("rules.yml").read())

Validating Rules
----------------

pySigma includes a validation framework to check rules for correctness:

.. code-block:: python

   from sigma.validation import SigmaValidator
   from sigma.validators.core.metadata import IdentifierExistenceValidator

   validator = SigmaValidator(validators=[IdentifierExistenceValidator])
   issues = validator.validate_rule(rule)
   for issue in issues:
       print(f"{issue.severity.name}: {issue}")

Next Steps
----------

* :doc:`guides/converting_rules` — Detailed guide on rule conversion
* :doc:`guides/building_backends` — How to create your own backend
* :doc:`guides/processing_pipelines` — Processing pipeline deep dive
* :doc:`guides/rule_validation` — Rule validation guide
* :doc:`guides/plugin_system` — Plugin system documentation
