Exceptions
==========

pySigma uses a hierarchy of exceptions for error handling. All exceptions inherit from
:class:`~sigma.exceptions.SigmaError` which includes optional source location tracking.

Base Exception
--------------

.. autoclass:: sigma.exceptions.SigmaError
   :members:
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaRuleLocation
   :members:
   :show-inheritance:

Rule Exceptions
---------------

.. autoclass:: sigma.exceptions.SigmaValueError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaDetectionError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaConditionError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaModifierError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaTypeError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaLogsourceError
   :show-inheritance:

Backend and Conversion Exceptions
----------------------------------

.. autoclass:: sigma.exceptions.SigmaBackendError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaConversionError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaFeatureNotSupportedByBackendError
   :show-inheritance:

Pipeline and Processing Exceptions
------------------------------------

.. autoclass:: sigma.exceptions.SigmaConfigurationError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaPipelineNotFoundError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaPipelineParsingError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaPipelineConditionError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaProcessingItemError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaTransformationError
   :show-inheritance:

Collection Exceptions
---------------------

.. autoclass:: sigma.exceptions.SigmaCollectionError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaRuleNotFoundError
   :show-inheritance:

Placeholder Exceptions
----------------------

.. autoclass:: sigma.exceptions.SigmaPlaceholderError
   :show-inheritance:

Regular Expression Exceptions
-----------------------------

.. autoclass:: sigma.exceptions.SigmaRegularExpressionError
   :show-inheritance:

Plugin Exceptions
-----------------

.. autoclass:: sigma.exceptions.SigmaPluginNotFoundError
   :show-inheritance:

Correlation Exceptions
----------------------

.. autoclass:: sigma.exceptions.SigmaCorrelationRuleError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaCorrelationConditionError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaCorrelationTypeError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaTimespanError
   :show-inheritance:

Validator Exceptions
--------------------

.. autoclass:: sigma.exceptions.SigmaValidatorConfigurationParsingError
   :show-inheritance:

Filter Exceptions
-----------------

.. autoclass:: sigma.exceptions.SigmaFilterError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaFilterConditionError
   :show-inheritance:

.. autoclass:: sigma.exceptions.SigmaFilterRuleReferenceError
   :show-inheritance:
