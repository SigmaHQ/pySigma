Using Sigma Filters
===================

Sigma filters let you tune existing rules for your environment without editing the rules
themselves. A filter is a separate YAML document that adds an extra condition to every rule it
applies to, typically to exclude known-benign activity such as administrator accounts, backup
servers or management tooling. This guide explains how filters are written, how pySigma decides
which rules a filter applies to, and how to load and apply filters with
:class:`~sigma.collection.SigmaCollection`.

Overview
--------

The filter support consists of:

* :class:`~sigma.filters.SigmaFilter`: A complete filter document with metadata, a log source and
  a ``filter`` section.
* :class:`~sigma.filters.SigmaGlobalFilter`: The parsed ``filter`` section: the rule references,
  the filter detections and the filter condition.
* :meth:`SigmaFilter.apply_on_rule() <sigma.filters.SigmaFilter.apply_on_rule>`: Merges the filter
  into a single :class:`~sigma.rule.SigmaRule`.
* :meth:`SigmaCollection.apply_filters() <sigma.collection.SigmaCollection.apply_filters>`:
  Applies a list of filters to all rules of a collection.

Filters are applied before the conversion. The backend and processing pipelines see an ordinary
rule that contains the additional filter detections, so field mappings and other transformations
also apply to the fields used in the filter.

Writing a Filter
----------------

A filter document looks similar to a Sigma rule, but has a ``filter`` section instead of a
``detection`` section:

.. code-block:: yaml

   title: Filter Administrator account
   description: The valid administrator accounts start with adm_
   logsource:
       category: process_creation
       product: windows
   filter:
     rules:
       - 6f3e2987-db24-4c78-a860-b4f4095a7095 # Data Compressed - rar.exe
       - df0841c0-9846-4e9f-ad8a-7df91571771b # Login on jump host
     selection:
         User|startswith: 'adm_'
     condition: not selection

The ``filter`` section contains:

``rules``
   The rules the filter applies to. This field is required and can be:

   * ``any``: The filter applies to all rules that match the log source of the filter.
   * A single rule ID or rule name, e.g. ``rules: 6f3e2987-db24-4c78-a860-b4f4095a7095``.
   * A list of rule IDs or rule names. An empty list is treated like ``any``.

Detections
   Any number of detection definitions, written like in the ``detection`` section of a rule.
   All modifiers can be used.

``condition``
   A single condition string that combines the filter detections. It is usually negated, e.g.
   ``not selection``, because the filter is meant to *exclude* events. The condition can only
   refer to detections defined in the filter itself, not to the detections of the rule it is
   applied to. Selectors such as ``1 of filter_*``, ``all of filter_*`` and ``1 of them`` are
   supported, where ``them`` stands for all detections of the filter.

The common rule attributes such as ``id``, ``name``, ``description``, ``author`` or ``date``
can be used in filters like in rules.

How Filters Are Applied
-----------------------

A filter is applied to a rule if all of the following is true:

1. The rule is a regular Sigma rule. Correlation rules are not modified directly, but the rules
   they refer to are filtered like any other rule, so the filter also takes effect on the
   events counted by the correlation.
2. The log source of the filter contains the log source of the rule. The filter can be less
   specific than the rule: a filter for ``product: windows`` applies to rules with
   ``category: process_creation`` and ``product: windows``, but a filter for
   ``category: process_creation`` with ``product: windows`` doesn't apply to a rule that only
   specifies ``product: windows``.
3. ``rules`` is ``any`` or one of the referenced IDs or names identifies the rule.

When a filter is applied, the filter detections are copied into the rule and every rule
condition is combined with the filter condition using ``and``:

.. code-block:: text

   (<rule condition>) and (<filter condition>)

To avoid clashes with the detection names of the rule, all filter detections are renamed with a
random prefix like ``_filt_abcdefghij_`` and the filter condition is rewritten accordingly. The
detection names of the filter therefore never collide with those of the rule, even if both use
the same names such as ``selection``, and wildcard selectors in the filter condition never match
detections of the rule. Each rule gets its own copy of the filter detections, so processing
pipelines transform them independently for every rule.

Several filters can apply to the same rule. They are applied one after another, each one adding
its own condition.

Applying Filters in Python
--------------------------

Filters in the same YAML input as the rules
   :meth:`SigmaCollection.from_yaml() <sigma.collection.SigmaCollection.from_yaml>` parses filter
   documents along with rules and applies them right away. The parsed filters are kept in the
   :attr:`~sigma.collection.SigmaCollection.filters` attribute of the collection.

Filters from separate files
   :meth:`SigmaCollection.load_ruleset() <sigma.collection.SigmaCollection.load_ruleset>` loads all
   files first and applies the filters found in any of them to the rules of all files. Rule
   directories and filter directories can simply be passed together:

   .. code-block:: python

      from pathlib import Path
      from sigma.collection import SigmaCollection

      rules = SigmaCollection.load_ruleset([Path("rules/"), Path("filters/")])

Applying filters explicitly
   Pass ``collect_filters=True`` to :meth:`~sigma.collection.SigmaCollection.from_yaml` or
   :meth:`~sigma.collection.SigmaCollection.from_dicts` to only collect the filters, or parse them
   on their own with :meth:`SigmaFilter.from_yaml() <sigma.filters.SigmaFilter.from_yaml>`, and
   apply them later with :meth:`~sigma.collection.SigmaCollection.apply_filters`:

   .. code-block:: python

      from sigma.backends.test import TextQueryTestBackend
      from sigma.collection import SigmaCollection
      from sigma.filters import SigmaFilter

      rules = SigmaCollection.from_yaml("""
      title: Failed login
      id: 6f3e2987-db24-4c78-a860-b4f4095a7095
      logsource:
          category: process_creation
          product: windows
      detection:
          selection:
              - EventID: 4625
              - EventID2: 4624
          condition: selection
      """)

      sigma_filter = SigmaFilter.from_yaml("""
      title: Filter Administrator account
      logsource:
          category: process_creation
          product: windows
      filter:
        rules:
          - 6f3e2987-db24-4c78-a860-b4f4095a7095
        selection:
            User|startswith: 'adm_'
        condition: not selection
      """)

      rules.apply_filters([sigma_filter])
      print(TextQueryTestBackend().convert(rules))
      # ['(EventID=4625 or EventID2=4624) and not User startswith "adm_"']

   :meth:`SigmaFilter.apply_on_rule() <sigma.filters.SigmaFilter.apply_on_rule>` applies a filter
   to a single rule. It modifies the rule in place and returns it, or returns the rule unchanged
   if the filter doesn't apply to it.

Filters with Several Detections
-------------------------------

Filters can contain several detections and combine them with selectors. The following filter
excludes administrator and service accounts from all Windows process creation rules:

.. code-block:: yaml

   title: Filter administrator and service accounts
   logsource:
       category: process_creation
       product: windows
   filter:
     rules: any
     filter_admin:
         User|startswith: 'adm_'
     filter_service:
         User|startswith: 'srv_'
     condition: not 1 of filter_*

Applied to a rule with the condition ``EventID: 4625``, the test backend generates
``EventID=4625 and not (User in ("adm_*", "srv_*"))``.

Error Handling
--------------

Invalid filters raise the following exceptions, or collect them in the
``errors`` attribute of the parsed filter if ``collect_errors=True`` is passed:

* :class:`~sigma.exceptions.SigmaFilterError`: The ``filter`` section is missing or isn't a map.
* :class:`~sigma.exceptions.SigmaLogsourceError`: The ``logsource`` is missing or invalid.
* :class:`~sigma.exceptions.SigmaFilterConditionError`: The ``condition`` is missing or isn't a
  single string. Lists of conditions aren't allowed in filters.
* :class:`~sigma.exceptions.SigmaFilterRuleReferenceError`: The ``rules`` field is missing or has
  an invalid type.

A rule reference that doesn't match any rule is not an error: the filter just isn't applied to
any rule.

A filter condition that refers to an undefined detection, including a detection that only exists
in the rule, raises a :class:`~sigma.exceptions.SigmaConditionError` when the filtered rule is
converted.
