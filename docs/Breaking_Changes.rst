Breaking Changes
================

This page documents breaking changes in pySigma. Normally, we try to avoid breaking changes in minor
versions and generally try to keep pySigma backwards compatible, but sometimes they are necessary to
improve the library.

Version 1.0
-----------

- The class ``CompareOperators`` was moved out of ``SigmaCompatreExpression`` into the root of the containing module ``sigma.types``. If the class was formerly used, it has now to be imported explicitly from the module.
- Initialization of a ``SigmaDetectionItem`` doesn't converts plain types to ``SigmaType`` objects anymore and expects a list as value. Use ``SigmaDetectionItem.from_mapping()`` or ``.from_value()`` instead.
- ``SigmaCollection.from_yaml()``, ``.from_dicts()`` new parameter ``collect_filters`` introduced at position after ``collect_errors``.
- ``SigmaCollection()`` constructor new parameter ``collect_filters`` introduced at position after ``errors``.
- ``SigmaPipelineConditionError``: parameter ordering changed, ``expression`` and ``location`` are now optional.
- ``QueryPostprocessingTransformation`` introduces ``apply_query()`` method for clear distinction of methods for different processing stages.
- Functionality of inherited classes was consolidated into ``FieldMappingTransformationBase``. The method ``get_mapping`` from ``FieldMappingTransformation`` and all classes inherited from it was consolidated into ``apply_field_name``. Usually, it should be sufficient to replace ``get_mapping()`` with ``apply_field_name()`` if it was overridden in a subclass.
- Validator config now uses identifier (``filename_length``) instead of class name (``FilenameLengthValidator``) to establish consistency with remaining config.
- ``SigmaValueValidator.validated_types`` was removed. Instead the type has to be checked in the ``validate_value`` method.
- The validation logic of a class inherited by ``SigmaStringValueValidator`` is now implemented in a ``validate_string`` method instead of ``validate_value``.
- The ``ProcessingPipeline`` is only initialized once per backend instantiation instead of once per converted rule. The state dict is reset for each call to ``apply()``.
- The references to the using pipeline of objects derived from classess inheriting from ``ProcessingItem``, ``Transformation``, ``RuleCondition``, ``DetectionItemCondition`` and ``FieldNameCondition`` can only be set once. Further attempts will raise an exception. This implies that such objects can't be re-used in a pipeline (e.g. as variable), but have to be instantiated again for each usage (e.g. via factory).
- The ``type`` parameter of ``IncludeFieldCondition`` and ``ExcludeFieldCondition`` was renamed to ``mode``.
- Query finalization in rule conversion was splitted into a ``finish`` step that is intended to amend the query, e.g. for handling deferred expressions or field selections and finalization for conversion into the target output format. The main difference is that the finalization step normally isn't executed for correlation rules while ``finish`` is.
- Migrated to ``pyYAML`` ``CSafeLoader``.
- ``SigmaCollection`` now resolves rule references by default on initialization. This behavior can be disabled with the optional ``resolve_references`` parameter.
- MITRE ATT&CK and D3FEND data is now downloaded on-demand instead of being shipped with the
  library. In restricted environments, use ``mitre_attack_data.set_url()`` and
  ``mitre_d3fend_data.set_url()`` to load data from local files. The content should be accessed only
  if really used to avoid performance hit by unwanted downloads.