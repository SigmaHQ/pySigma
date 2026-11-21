Architecture
============

This page gives an overview of how the ``sigma`` package is structured and how its parts work
together. pySigma parses Sigma rules into an object model, rewrites them with processing pipelines
to fit the data model of a target environment, and then hands them to a backend (to generate
queries), the matcher (to evaluate events directly) or the validator. Backends and pipelines for
specific SIEMs live in separate plugin packages.

.. image:: images/architecture.svg
   :alt: Layered architecture of pySigma: rule model, processing, execution and extension

Layers
------

**1. Rule model**
   Sigma YAML is loaded into a :class:`~sigma.collection.SigmaCollection` that contains
   :class:`~sigma.rule.SigmaRule`, :class:`~sigma.correlations.SigmaCorrelationRule` and
   :class:`~sigma.filters.SigmaFilter` objects, all derived from ``SigmaRuleBase``. A rule consists
   of a log source, detections (``SigmaDetections`` › ``SigmaDetection`` › ``SigmaDetectionItem``)
   and conditions, which are parsed into a tree (``sigma.conditions``). Modifiers
   (``sigma.modifiers``) turn raw values into Sigma types (``sigma.types``).

**2. Processing**
   The ``ProcessingPipelineResolver`` resolves pipeline specifications (YAML files, plugin IDs or
   Python code), sorts them by priority and joins them into one
   :class:`~sigma.processing.pipeline.ProcessingPipeline`. A pipeline has three stages: processing
   items (transformations with conditions) applied to the rule, postprocessing items applied to each
   generated query, and finalizers applied to the whole output. A ``SigmaPolicy`` controls the regex
   engine and whether templates may use variables or external sources; the default is the
   restrictive ``SafePolicy``. See :doc:`guides/processing_pipelines` and :doc:`guides/sigma_policy`.

**3. Execution**
   Three consumers work on the (processed) rules:

   * :class:`~sigma.conversion.base.Backend` and ``TextQueryBackend`` convert rules into queries.
     Backend plugins subclass ``TextQueryBackend`` and define tokens, operators and correlation
     templates as class attributes. See :doc:`guides/building_backends`.
   * ``SigmaMatcher`` evaluates events directly against rules, including correlation rules with
     sliding time-window state. See :doc:`guides/matching`.
   * ``SigmaValidator`` checks rules with the validators from ``sigma.validators.core``, using the
     MITRE ATT&CK and D3FEND data from ``sigma.data``. See :doc:`guides/rule_validation`.

**4. Extension**
   ``InstalledSigmaPlugins.autodiscover()`` loads backends, pipelines and validators from the
   namespace packages ``sigma.backends``, ``sigma.pipelines`` and ``sigma.validators``.
   ``SigmaPluginDirectory`` installs plugin packages from PyPI. See :doc:`guides/plugin_system`.

**Cross-cutting**
   All layers report errors through the ``SigmaError`` hierarchy in ``sigma.exceptions``, which
   carries a ``SigmaRuleLocation`` pointing to the affected rule.

Conversion flow
---------------

``Backend.convert()`` runs these steps:

#. **Build the pipeline** (``init_processing_pipeline()``): the backend's own pipeline, the
   user-supplied pipeline and the output format pipeline are added together. The variables
   ``backend`` and ``output_format`` are set in the pipeline.
#. **Resolve references** (``SigmaCollection.resolve_rule_references()``): correlation rules are
   linked to the rules they reference, and filters are applied to the affected rules.
#. **Transform the rule** (``ProcessingPipeline.apply()``): every processing item checks its
   conditions and applies its transformation, for example field mapping or log source replacement.
#. **Convert the condition** (``convert_condition()``, ``finish_query()``): the parsed condition is
   translated recursively into a query. ``ConversionState`` collects state, and
   ``DeferredQueryExpression`` holds back parts that are inserted at the end.
#. **Postprocess the query** (``finalize_query()``): the format-specific
   ``finalize_query_<format>`` method runs, followed by the pipeline's postprocessing items.
#. **Finalize the output** (``finalize()``): all queries are combined by
   ``finalize_output_<format>`` and passed through the pipeline's finalizers.
