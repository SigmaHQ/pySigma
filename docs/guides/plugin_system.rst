Plugin System
=============

pySigma uses a plugin system to discover and manage backends, processing pipelines, and
validators. This guide explains how to use existing plugins and how to create your own.

Overview
--------

pySigma supports three types of plugins:

* **Backends**: Convert Sigma rules into target query languages.
* **Processing Pipelines**: Transform rules for specific environments.
* **Validators**: Check rules for correctness and best practices.

Plugins are distributed as separate Python packages and discovered through Python namespace
packages.

Using Plugins
-------------

Discovering Installed Plugins
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from sigma.plugins import InstalledSigmaPlugins

   plugins = InstalledSigmaPlugins.autodiscover()

   # Access backends
   print(plugins.backends)  # dict of name -> backend class

   # Access pipelines
   print(plugins.pipelines)  # dict of name -> pipeline function

   # Access validators
   print(plugins.validators)  # dict of name -> validator class

Using the Plugin Directory
^^^^^^^^^^^^^^^^^^^^^^^^^^

pySigma maintains a public directory of available plugins:

.. code-block:: python

   from sigma.plugins import SigmaPluginDirectory

   directory = SigmaPluginDirectory.default_plugin_directory()

   # List all available plugins
   for plugin in directory.plugins:
       print(f"{plugin.id}: {plugin.description}")

   # Install a plugin
   directory.get_plugin("splunk").install()

Using Pipeline Resolvers
^^^^^^^^^^^^^^^^^^^^^^^^

The ``ProcessingPipelineResolver`` combines installed pipelines and resolves them by name,
automatically ordering them by their priority values (lowest first). This ensures pipelines are
applied in the correct sequence:

.. code-block:: python

   from sigma.processing.resolver import ProcessingPipelineResolver
   from sigma.plugins import InstalledSigmaPlugins

   plugins = InstalledSigmaPlugins.autodiscover()
   resolver = ProcessingPipelineResolver.from_pipeline_list(plugins.pipelines.values())

   # Resolve and merge pipelines by name, respecting their priority values
   pipeline = resolver.resolve(["sysmon", "windows"])
   # If sysmon has priority 10 and windows has priority 20,
   # they will be merged with sysmon applied first

Creating a Backend Plugin
-------------------------

Package Structure
^^^^^^^^^^^^^^^^^

A backend plugin follows this structure:

.. code-block:: text

   pySigma-backend-mybackend/
   ├── pyproject.toml
   ├── sigma/
   │   └── backends/
   │       └── mybackend/
   │           ├── __init__.py
   │           └── backend.py
   └── tests/
       └── test_backend.py

Namespace Package Setup
^^^^^^^^^^^^^^^^^^^^^^^

The ``sigma/`` and ``sigma/backends/`` directories must be namespace packages (no
``__init__.py`` in ``sigma/`` and ``sigma/backends/``). Only the leaf package has an
``__init__.py``:

.. code-block:: python

   # sigma/backends/mybackend/__init__.py
   from .backend import MyBackend

   backends = {
       "mybackend": MyBackend,
   }

The ``backends`` dictionary maps identifiers to backend classes. This is how the plugin
system discovers your backend.

Package Configuration
^^^^^^^^^^^^^^^^^^^^^

In ``pyproject.toml``:

.. code-block:: toml

   [project]
   name = "pySigma-backend-mybackend"
   description = "pySigma backend for MySystem"
   dependencies = ["pySigma>=1.0.0"]

   [tool.poetry.packages]
   include = "sigma"

Creating a Pipeline Plugin
--------------------------

Pipeline plugins provide reusable processing pipelines:

.. code-block:: text

   pySigma-pipeline-mypipeline/
   ├── pyproject.toml
   ├── sigma/
   │   └── pipelines/
   │       └── mypipeline/
   │           ├── __init__.py
   │           └── pipeline.py
   └── tests/
       └── test_pipeline.py

.. code-block:: python

   # sigma/pipelines/mypipeline/__init__.py
   from .pipeline import my_pipeline

   pipelines = {
       "my_pipeline": my_pipeline,
   }

.. code-block:: python

   # sigma/pipelines/mypipeline/pipeline.py
   from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
   from sigma.processing.transformations import FieldMappingTransformation
   from sigma.processing.conditions import LogsourceCondition

   def my_pipeline() -> ProcessingPipeline:
       return ProcessingPipeline(
           name="My Pipeline",
           priority=20,
           items=[
               ProcessingItem(
                   identifier="my_field_mapping",
                   transformation=FieldMappingTransformation({
                       "CommandLine": "process.command_line",
                   }),
                   rule_conditions=[
                       LogsourceCondition(
                           category="process_creation",
                           product="windows",
                       )
                   ],
               )
           ],
       )

The ``pipelines`` dictionary maps names to callable functions that return a
``ProcessingPipeline`` instance.

Creating a Validator Plugin
---------------------------

Validator plugins provide custom rule checks:

.. code-block:: text

   pySigma-validators-myvalidators/
   ├── pyproject.toml
   ├── sigma/
   │   └── validators/
   │       └── myvalidators/
   │           ├── __init__.py
   │           └── validators.py
   └── tests/
       └── test_validators.py

.. code-block:: python

   # sigma/validators/myvalidators/__init__.py
   from .validators import MyValidator, AnotherValidator

   validators = {
       "my_check": MyValidator,
       "another_check": AnotherValidator,
   }

The ``validators`` dictionary maps identifiers to validator classes.

Plugin Naming Conventions
-------------------------

Follow these naming conventions for plugins:

* **Backends**: ``pySigma-backend-<name>`` (e.g., ``pySigma-backend-splunk``)
* **Pipelines**: ``pySigma-pipeline-<name>`` (e.g., ``pySigma-pipeline-sysmon``)
* **Validators**: ``pySigma-validators-<name>``

.. note::
   It is a common practice to package processing pipelines in backend plugins. In such cases the backend naming scheme is used.



Testing Plugins
---------------

Test your plugins against the pySigma test infrastructure:

.. code-block:: python

   import pytest
   from sigma.rule import SigmaRule
   from sigma.collection import SigmaCollection

   def test_plugin_discovery():
       from sigma.plugins import InstalledSigmaPlugins
       plugins = InstalledSigmaPlugins.autodiscover()
       assert "mybackend" in plugins.backends

   def test_basic_conversion():
       from sigma.backends.mybackend import MyBackend
       backend = MyBackend()
       rule = SigmaRule.from_yaml(\"\"\"
           title: Test
           status: test
           logsource:
               category: test
           detection:
               sel:
                   field: value
               condition: sel
       \"\"\")
       result = backend.convert(SigmaCollection(rules=[rule]))
       assert len(result) > 0
