Documentation TODO
==================

This file tracks documentation that still needs to be written or expanded.

Outstanding Items
-----------------

Guides
^^^^^^

* **Correlation Rules Guide**: A dedicated guide explaining how to write and use correlation
  rules (event_count, value_count, temporal_ordered, triggered types) with detailed examples.
* **Filters Guide**: Explain how to use Sigma filters (``SigmaFilter``) to globally modify
  rules in a collection.

Reference Documentation
^^^^^^^^^^^^^^^^^^^^^^^

* **Condition Expressions**: Document the ``ConditionExpression`` parser and its syntax
  for complex condition logic in pipelines (``rule_cond_expr``).
* **Field Mapping Tracking**: Document the ``FieldMappingTracking`` class and how to use
  it to trace field name changes through pipelines.
* **Conversion Callback**: Document the callback parameter of ``Backend.convert()`` and
  ``Backend.convert_rule()`` with usage examples.
* **SigmaCondition**: Document the condition parsing grammar and the ``SigmaCondition``
  class in detail (``sigma/conditions.py``).
* **Processing Templates**: Document ``TemplateBase`` and template functionality in
  post-processing and finalization.

Docstring Improvements
^^^^^^^^^^^^^^^^^^^^^^

* **sigma/processing/transformations/values.py**: Several transformation classes lack
  descriptive docstrings explaining parameters and usage.
* **sigma/processing/transformations/external.py**: External source transformations need
  more documentation about security implications and usage patterns.
* **sigma/processing/conditions/**: Most condition classes have minimal docstrings.
* **sigma/validators/core/**: Individual validator classes need documentation of what they
  check and configuration options.
* **sigma/modifiers.py**: Many modifier classes have no docstrings.
* **sigma/correlations.py**: Correlation-related classes need more detailed documentation
  of their behavior and usage.
* **sigma/filters.py**: Filter classes need comprehensive docstrings.

Examples and Tutorials
^^^^^^^^^^^^^^^^^^^^^^

* **End-to-end tutorial**: A complete tutorial building a simple backend from scratch.
* **Pipeline examples**: More real-world YAML pipeline examples for common environments
  (ECS, CIM, custom schemas).
* **Validator examples**: Examples of creating validators for organization-specific rules.
* **Integration examples**: How to integrate pySigma into larger applications and tools.

Other
^^^^^

* **Changelog/Breaking Changes**: Maintain a comprehensive changelog covering versions.
* **Contributing Guide**: Developer documentation for contributing to pySigma itself.
* **Architecture Decision Records**: Document key architectural decisions and their rationale.
