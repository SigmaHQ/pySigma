Processing Pipelines
####################

This documentation page describes the concepts and classes of pySigma that can be used for
transformation of Sigma rules.

Sigma rules are tranformed to take care of differences between the Sigma rule and the target data
model. Examples are differences in field naming schemes or value representation.

A processing pipeline has three stages:

1. Rule pre-processing: transformations that are applied to the rule. Example: field name mapping, adding
   conditions.
2. Query post-processing: transformations that are applied to the generated query. In this stage the
   transformaions have access to the query generated from the backend and the rule that was the
   source of the conversion. Example: embedding query and rule parts in a template to define custom
   output formats.
3. Output finalization: finalizers operate on all post-processed queries to generate the final
   output. Example: merge all queries and add a header to the output.

Further resources:

* `SigmaHQ Blog Post: Connecting Sigma Rule Sets to your Environment with Processing Pipelines <https://blog.sigmahq.io/connecting-sigma-rule-sets-to-your-environment-with-processing-pipelines-4ee1bd577070>`_ 
* `SigmaHQ Blog Post: Introducing Query Post-Processing and Output Finalization to Processing Pipelines <https://blog.sigmahq.io/introducing-query-post-processing-and-output-finalization-to-processing-pipelines-4bfe74087ac1>`_ 

.. _pipeline-resolvers:

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
* `transformations`: contains a list of transformation items for the rule pre-processing stage.
* `postprocessing`: contains a list of transformation items for the query post-processing stage.
* `finalizers`: contains a list of transformation items for the output finalization stage.

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
* `rule_conditions`, `detection_item_conditions`, `field_name_conditions`: conditions of the type corresponding to the name.

Conditions are specified as follows:

* `type`: defines the condition type. It must be one of the identifiers that are defined in
  :ref:`conditions`
* `rule_cond_op`, `detection_item_cond_op`, `field_name_cond_op`: boolean operator for the condition
  result. Must be one of `or` or `and`. Defaults to `and`.
* `rule_cond_not`, `detection_item_cond_not`, `field_name_cond_not`: if set to *True*, the condition
  result is negated.
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

.. versionadded:: 0.8.0
  Field name conditions.

There are three types of conditions:

* Rule conditions are evaluated to the whole rule. They are defined in the `rule_conditions`
  attribute of a `ProcessingItem`. These can be applied in the rule pre-processing stage and the
  query post-processing stage.
* Detection item conditions are evaluated for each detection item. They are defined in the
  `detection_item_conditions` attribute of a `ProcessingPipeline`. These can only be applied in the
  rule pre-processing stage.
* Field name conditions are evaluated for field names that can be located in detection items or in
  the field name list of a Sigma rule. They are defined in the `field_name_conditions` attribute of
  `detection_item_conditions` attribute of a `ProcessingPipeline`. These can only be applied in the
  rule pre-processing stage.

In addition to the `*_conditions` attributes of `ProcessingPipeline` objects, there are two further
attributes hat control the condition matching behavior:

* `rule_condition_linking`, `detection_item_condition_linking` and `field_name_condition_linking`:
  one of `any` or `all` functions. Controls if one or all of the conditions from the list must match
  to result in an overall match.
* `rule_condition_negation`, `detection_item_condition_negation` and
  `field_name_condition_negation`: if set to *True*, the condition result is negated.

The results of the evaluatuon of different condition types are and-linked. E.g. if a processing item
contains rule and field name conditions, both must evaluate to *True* to get the overall result of *True*.

Rule Conditions
===============

.. csv-table:: Detection Item Identifiers
   :header-rows: 1

   "Identifier", "Class"
   "logsource", "LogsourceCondition"
   "contains_detection_item", "RuleContainsDetectionItemCondition"
   "processing_item_applied", "RuleProcessingItemAppliedCondition"
   "is_sigma_rule": IsSigmaRuleCondition
   "is_sigma_correlation_rule": IsSigmaCorrelationRuleCondition
   "rule_attribute", "RuleAttributeCondition"
   "tag", "RuleTagCondition"

.. autoclass:: sigma.processing.conditions.LogsourceCondition
.. autoclass:: sigma.processing.conditions.RuleContainsDetectionItemCondition
.. autoclass:: sigma.processing.conditions.RuleProcessingItemAppliedCondition
.. autoclass:: sigma.processing.conditions.IsSigmaRuleCondition
.. autoclass:: sigma.processing.conditions.IsSigmaCorrelationRuleCondition
.. autoclass:: sigma.processing.conditions.RuleAttributeCondition
.. autoclass:: sigma.processing.conditions.RuleTagCondition

Detection Item Conditions
=========================

.. csv-table:: Detection Item Identifiers
   :header-rows: 1

   "Identifier", "Class"
   "match_string", "MatchStringCondition"
   "is_null", "IsNullCondition"
   "processing_item_applied", "DetectionItemProcessingItemAppliedCondition"

.. autoclass:: sigma.processing.conditions.MatchStringCondition
.. autoclass:: sigma.processing.conditions.IsNullCondition
.. autoclass:: sigma.processing.conditions.DetectionItemProcessingItemAppliedCondition

Field Name Conditions
=====================

.. csv-table:: Field Name Identifiers
   :header-rows: 1

   "Identifier", "Class"
   "include_fields", "IncludeFieldCondition"
   "exclude_fields", "ExcludeFieldCondition"
   "processing_item_applied", "FieldNameProcessingItemAppliedCondition"

.. autoclass:: sigma.processing.conditions.IncludeFieldCondition
.. autoclass:: sigma.processing.conditions.ExcludeFieldCondition
.. autoclass:: sigma.processing.conditions.FieldNameProcessingItemAppliedCondition

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
.. autoclass:: sigma.processing.conditions.FieldNameProcessingCondition
.. autoclass:: sigma.processing.conditions.ValueProcessingCondition

.. _transformations:

Transformations
***************

Rule Pre-Processing Transformations
===================================

The following transformations with their corresponding identifiers for usage in YAML-based pipeline
definitions are available:


.. csv-table:: Rule Pre-Processing Transformations
   :header-rows: 1

   "Identifier", "Class"
   "field_name_mapping", "FieldMappingTransformation"
   "field_name_prefix_mapping", FieldPrefixMappingTransformation
   "field_name_suffix", "AddFieldnameSuffixTransformation"
   "field_name_prefix", "AddFieldnamePrefixTransformation"
   "drop_detection_item", "DropDetectionItemTransformation"
   "wildcard_placeholders", "WildcardPlaceholderTransformation"
   "value_placeholders", "ValueListPlaceholderTransformation"
   "query_expression_placeholders", "QueryExpressionPlaceholderTransformation"
   "add_condition", "AddConditionTransformation"
   "change_logsource", "ChangeLogsourceTransformation"
   "replace_string", "ReplaceStringTransformation"
   "map_string", "MapStringTransformation"
   "regex", "RegexTransformation"
   "set_state", SetStateTransformation
   "rule_failure", "RuleFailureTransformation"
   "detection_item_failure", "DetectionItemFailureTransformation"

.. autoclass:: sigma.processing.transformations.FieldMappingTransformation

YAML example:

.. code-block:: yaml

  transformations:
    type: field_name_mapping
    mapping:
      EventID: EventCode
      CommandLine:
        - command_line
        - cmdline

This shows how to map the field name `EventID` to `EventCode` and `CommandLine` to `command_line`
and `cmdline`. For the latter, OR-conditions will be generated to match the value on both fields.
This is useful if different data models are used in the same system.

.. autoclass:: sigma.processing.transformations.FieldPrefixMappingTransformation
.. autoclass:: sigma.processing.transformations.AddFieldnameSuffixTransformation
.. autoclass:: sigma.processing.transformations.AddFieldnamePrefixTransformation
.. autoclass:: sigma.processing.transformations.DropDetectionItemTransformation
.. autoclass:: sigma.processing.transformations.WildcardPlaceholderTransformation
.. autoclass:: sigma.processing.transformations.ValueListPlaceholderTransformation
.. autoclass:: sigma.processing.transformations.QueryExpressionPlaceholderTransformation
.. autoclass:: sigma.processing.transformations.AddConditionTransformation
.. autoclass:: sigma.processing.transformations.ChangeLogsourceTransformation
.. autoclass:: sigma.processing.transformations.ReplaceStringTransformation
.. autoclass:: sigma.processing.transformations.MapStringTransformation

YAML example:

.. code-block:: yaml

  transformations:
    type: map_string
    mapping:
      value1: mapped1
      value2:
        - mapped2A
        - mapped2B

.. autoclass:: sigma.processing.transformations.CaseInsensitiveRegexTransformation
.. autoclass:: sigma.processing.transformations.SetStateTransformation
.. autoclass:: sigma.processing.transformations.RuleFailureTransformation
.. autoclass:: sigma.processing.transformations.DetectionItemFailureTransformation

Query Post-Processing Transformations
======================================

.. versionadded:: 0.10.0

.. csv-table:: Query Post-Processing Transformations
   :header-rows: 1

   "Identifier", "Class"
   "embed", "EmbedQueryTransformation"
   "simple_template", "QuerySimpleTemplateTransformation"
   "template", "QueryTemplateTransformation"
   "json", "EmbedQueryInJSONTransformation"
   "replace", "ReplaceQueryTransformation"

.. autoclass:: sigma.processing.postprocessing.EmbedQueryTransformation
.. autoclass:: sigma.processing.postprocessing.QuerySimpleTemplateTransformation
.. autoclass:: sigma.processing.postprocessing.QueryTemplateTransformation
.. autoclass:: sigma.processing.postprocessing.EmbedQueryInJSONTransformation
.. autoclass:: sigma.processing.postprocessing.ReplaceQueryTransformation

Output Finalization Transformations
====================================

.. versionadded:: 0.10.0

.. csv-table:: Output Finalization Transformations
   :header-rows: 1

   "Identifier", "Class"
   "concat", "ConcatenateQueriesFinalizer"
   "template", "TemplateFinalizer"
   "json", "JSONFinalizer"
   "yaml", "YAMLFinalizer"

.. autoclass:: sigma.processing.finalization.ConcatenateQueriesFinalizer
.. autoclass:: sigma.processing.finalization.TemplateFinalizer
.. autoclass:: sigma.processing.finalization.JSONFinalizer
.. autoclass:: sigma.processing.finalization.YAMLFinalizer

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
