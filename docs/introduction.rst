Introduction
============

What is pySigma?
----------------

pySigma is a Python library that parses and converts `Sigma rules <https://github.com/SigmaHQ/sigma>`_
into queries for security monitoring and SIEM systems. Sigma is an open standard for writing detection
rules that describe suspicious or malicious activity in log data. pySigma serves as the core engine
that transforms these vendor-agnostic rules into specific query languages like Splunk SPL, Elasticsearch
queries, Microsoft Sentinel KQL, and many more.

pySigma replaced the legacy Sigma toolchain (``sigmac``) with a cleaner, modular design that is
thoroughly tested and maintained.

Purpose
-------

The main goals of pySigma are:

* **Parse** Sigma rules from YAML format into a structured Python object model.
* **Process** rules through configurable transformation pipelines that adapt them to specific
  environments (e.g., field name mappings, log source adjustments).
* **Convert** processed rules into target query languages via backends.
* **Validate** rules for correctness and compliance with best practices.

Core Components
^^^^^^^^^^^^^^^

**Rules** (``sigma.rule``)
   The object model representing Sigma rules. A ``SigmaRule`` contains a log source definition,
   detection logic, and metadata. Rules can be loaded individually or as collections.

**Collections** (``sigma.collection``)
   Groups of related Sigma rules that can be loaded from directories, YAML files, or dicts.
   Collections handle rule reference resolution for correlation rules.

**Processing Pipelines** (``sigma.processing``)
   Ordered sequences of transformations that modify rules before conversion.
   Pipelines can rename fields, adjust log sources, add conditions, and perform many other
   transformations. They can be defined in Python or YAML and are the primary mechanism for
   adapting generic Sigma rules to a specific environment.

**Backends** (``sigma.conversion``)
   Convert processed Sigma rules into target query languages. Each backend implements the
   translation of the Sigma detection logic into a specific query syntax. The ``TextQueryBackend``
   base class simplifies creation of backends for text-based query languages.

**Validators** (``sigma.validators``)
   Check Sigma rules for correctness, completeness, and adherence to best practices.
   Validators can check individual rules or entire collections (e.g., for uniqueness).

**Plugins** (``sigma.plugins``)
   Discovery and management of pySigma extensions. Backends, processing pipelines, and
   validators are distributed as separate packages and discovered through Python package
   namespaces.

Design Principles
^^^^^^^^^^^^^^^^^

* **Vendor-agnostic core**: pySigma itself contains no vendor-specific code. All target system
  support is provided through backend plugins.
* **Pipeline-based processing**: Transformations are applied declaratively via pipelines rather
  than being hard-coded in backends.
* **Extensibility**: New backends, transformations, conditions, and validators can be added
  through the plugin system without modifying pySigma core.
* **Error collection**: Parsing and processing can collect errors instead of immediately raising
  exceptions, enabling graceful handling of partially invalid rule sets.
* **Type safety**: The library makes extensive use of Python type hints and dataclasses for
  clear API contracts.

Ecosystem
---------

pySigma is part of a larger ecosystem:

* `sigma-cli <https://github.com/SigmaHQ/sigma-cli>`_: Command-line interface for Sigma rule
  conversion using pySigma.
* `SigmaHQ rules <https://github.com/SigmaHQ/sigma>`_: The community-maintained repository of
  Sigma detection rules.
* **Backend packages**: Target-specific conversion packages (e.g., ``pySigma-backend-splunk``,
  ``pySigma-backend-elasticsearch``).
* **Pipeline packages**: Environment-specific transformation packages (e.g.,
  ``pySigma-pipeline-sysmon``, ``pySigma-pipeline-crowdstrike``).