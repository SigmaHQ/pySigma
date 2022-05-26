Processing Pipelines
####################

This documentation page describes the concepts and classes of pySigma that can be used for
transformation of Sigma rules.

Sigma rules are tranformed to take care of differences between the Sigma rule and the target data
model. Examples are differences in field naming schemes or value representation.

Resolvers
*********

Pipeline resolvers resolve identifiers and file names into a consolidated processing pipeline and
take care of the appropriate ordering via the `priority` property that should be contained in a
processing pipeline.

A processing pipeline resolver is a
:py:class:`sigma.processing.resolver.ProcessingPipelineResolver` object. It is initialized with an
mapping between identifiers and :py:class:`sigma.processing.pipeline.ProcessingPipeline` objects or
callables that return such objects.

The method :py:meth:`sigma.processing.resolver.ProcessingPipelineResolver.resolve_pipeline` returns a
`ProcessingPipeline` object corresponsing with the given identifier or contained in the specified
YAML file. :py:meth:`sigma.processing.resolver.ProcessingPipelineResolver.resolve` returns a consolidated
pipeline with the appropriate ordering as specified by the `priority` property of the specified pipelines.

.. autoclass:: sigma.processing.resolver.ProcessingPipelineResolver
   :members:

Processing Pipeline
*******************

Classes
=======

.. autoclass:: sigma.processing.pipeline.ProcessingPipeline
   :members:

.. autoclass:: sigma.processing.pipeline.ProcessingItem
   :members:

Specifying Processing Pipelines as YAML
=======================================

A processing pipeline can be specified as YAML file that can be loaded with
`ProcessingPipeline.from_yaml(yaml)` or by specifying a filename to
`ProcessingPipelineResolver.resolve()` or `ProcessingPipelineResolver.resolve_pipeline()`.

The following items are expected on the root level of the YAML file:

* `name`: the name of the pipeline.
* `priority`: specifies the ordering of the pipeline in case multiple pipelines are concatenated.
  Lower priorities are used first.
* `transformations`: contains a list of transformation items.

Some conventions used for processing pipeline priorities are:

.. list-table::
   :header-rows: 1

   * - Priority
     - Description
   * - 10
     - Log source pipelines like for Sysmon.
   * - 20
     - Pipelines provided by backend packages that should be run before the backend pipeline.
   * - 50
     - Backend pipelines that are integrated in the backend and applied automatically.
   * - 60
     - Backend output format pipelines that are integrated in the backend and applied automatically for
       the asscoiated output format.

Pipelines with the same priority are applied in the order they were provided. Pipelines without a
priority are assumed to have the priority 0.

Transformation items are defined as a map as follows:

* `id`: the identifier of the item. This is also tracked at detection item or condition level and can
  be used in future conditions.
* `type`: the type of the transformation as specified in the identifier to class mappings below: :ref:`transformations`
* Arbitrary transformation parameters are specified at the samle level.
* `rule_conditions` or `detection_item_conditions`: conditions of the type corresponding to the name.

Conditions are specified as follows:

* `type`: defines the condition type. It must be one of the identifiers that are defined in
  :ref:`conditions`
* Arbitrary conditions parameters are specified on the same level.

Example:

.. code-block:: yaml

    name: Custom Sysmon field naming
    priority: 100
    transformations:
    - id: field_mapping
        type: field_name_mapping
        mapping:
            CommandLine: command_line
        rule_conditions:
        - type: logsource
            service: sysmon

.. _conditions:

Conditions
**********

There are two types of conditions: rule conditions which are evaluated to the whole rule and
detection item conditions that are evaluated for each detection item.

Rule Conditions
===============

.. csv-table:: Detection Item Identifiers
   :header-rows: 1

   "Identifier", "Class"
   "logosurce", "LogsourceCondition"

.. autoclass:: sigma.processing.conditions.LogsourceCondition

Detection Item Conditions
=========================

.. csv-table:: Detection Item Identifiers
   :header-rows: 1

   "Identifier", "Class"
   "include_fields", "IncludeFieldCondition"
   "exclude_fields", "ExcludeFieldCondition"
   "match_string", "MatchStringCondition"

.. autoclass:: sigma.processing.conditions.IncludeFieldCondition
.. autoclass:: sigma.processing.conditions.ExcludeFieldCondition
.. autoclass:: sigma.processing.conditions.MatchStringCondition

Base Classes
============

Base classes must be overridden to implement new conditions that can be used in processing
pipelines. In addition, the new class should be mapped to an identifier. This allows to use the
condition from processing pipelines defined in YAML files. The mapping is done in the dict
`rule_conditions` or `detection_item_conditions` in the `sigma.processing.conditions` package for
the respective condition types. This is not necessary for conditions that should be uses privately
and not be distributed via the main pySigma distribution.

.. autoclass:: sigma.processing.conditions.RuleProcessingCondition
.. autoclass:: sigma.processing.conditions.DetectionItemProcessingCondition
.. autoclass:: sigma.processing.conditions.ValueProcessingCondition

.. _transformations:

Transformations
***************

Implemented Transformations
===========================

The following transformations with their corresponding identifiers for usage in YAML-based pipeline
definitions are available:


.. csv-table:: Detection Item Identifiers
   :header-rows: 1

   "Identifier", "Class"
   "field_name_mapping", "FieldMappingTransformation"
   "field_name_suffix", "AddFieldnameSuffixTransformation"
   "field_name_prefix", "AddFieldnamePrefixTransformation"
   "wildcard_placeholders", "WildcardPlaceholderTransformation"
   "value_placeholders", "ValueListPlaceholderTransformation"
   "query_expression_placeholders", "QueryExpressionPlaceholderTransformation"
   "add_condition", "AddConditionTransformation"
   "change_logsource", "ChangeLogsourceTransformation"
   "replace_string", "ReplaceStringTransformation"
   "rule_failure", "RuleFailureTransformation"
   "detection_item_failure", "DetectionItemFailureTransformation"

.. autoclass:: sigma.processing.transformations.FieldMappingTransformation
.. autoclass:: sigma.processing.transformations.AddFieldnameSuffixTransformation
.. autoclass:: sigma.processing.transformations.AddFieldnamePrefixTransformation
.. autoclass:: sigma.processing.transformations.WildcardPlaceholderTransformation
.. autoclass:: sigma.processing.transformations.ValueListPlaceholderTransformation
.. autoclass:: sigma.processing.transformations.QueryExpressionPlaceholderTransformation
.. autoclass:: sigma.processing.transformations.AddConditionTransformation
.. autoclass:: sigma.processing.transformations.ChangeLogsourceTransformation
.. autoclass:: sigma.processing.transformations.ReplaceStringTransformation
.. autoclass:: sigma.processing.transformations.RuleFailureTransformation
.. autoclass:: sigma.processing.transformations.DetectionItemFailureTransformation

Base Classes
============

There are four transformation base classes that can be derived to implement transformations on
particular parts of a Sigma rule or the whole Sigma rule:

.. autoclass:: sigma.processing.transformations.Transformation
.. autoclass:: sigma.processing.transformations.DetectionItemTransformation
.. autoclass:: sigma.processing.transformations.ValueTransformation
.. autoclass:: sigma.processing.transformations.ConditionTransformation

Transformation Tracking
***********************

tbd