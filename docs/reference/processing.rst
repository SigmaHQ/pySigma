Processing Pipeline
===================

The processing pipeline module provides the infrastructure for transforming Sigma rules
before conversion.

.. seealso::

   :doc:`../guides/sigma_policy` documents the effective
   ``SigmaPolicy`` object, its security-sensitive settings, and how pipeline loaders
   sanitize untrusted dictionary and YAML input.

ProcessingPipeline
------------------

.. autoclass:: sigma.processing.pipeline.ProcessingPipeline
   :members:
   :undoc-members:
   :show-inheritance:

ProcessingItem
--------------

.. autoclass:: sigma.processing.pipeline.ProcessingItem
   :members:
   :undoc-members:
   :show-inheritance:

ProcessingItemBase
------------------

.. autoclass:: sigma.processing.pipeline.ProcessingItemBase
   :members:
   :undoc-members:
   :show-inheritance:

QueryPostprocessingItem
-----------------------

.. autoclass:: sigma.processing.pipeline.QueryPostprocessingItem
   :members:
   :undoc-members:
   :show-inheritance:

ProcessingPipelineResolver
--------------------------

.. autoclass:: sigma.processing.resolver.ProcessingPipelineResolver
   :members:
   :undoc-members:
   :show-inheritance:
