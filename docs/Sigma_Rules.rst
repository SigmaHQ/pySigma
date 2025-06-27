Sigma Rules
###########

This documentation page describes the parsing of Sigma rules and working with Sigma objects
resulting from parsed rules.

Parsing
*******

Programatic Construction
************************

Rule Collections
****************

.. autoclass:: sigma.collection.SigmaCollection
   :members:

Rule Object Model
*****************

SigmaRule
=========

.. autoclass:: sigma.rule.rule.SigmaRule
   :members:

SigmaRuleBase
=============

.. autoclass:: sigma.rule.base.SigmaRuleBase
   :members:

SigmaYAMLLoader
===============

.. autoclass:: sigma.rule.base.SigmaYAMLLoader
   :members:

SigmaLogSource
==============

.. autoclass:: sigma.rule.logsource.SigmaLogSource
   :members:

EmptyLogSource
==============

.. autoclass:: sigma.rule.logsource.EmptyLogSource
   :members:

SigmaDetections
===============

.. autoclass:: sigma.rule.detection.SigmaDetections
   :members:

EmptySigmaDetections
====================

.. autoclass:: sigma.rule.detection.EmptySigmaDetections
   :members:

SigmaDetection
==============

.. autoclass:: sigma.rule.detection.SigmaDetection
   :members:

SigmaDetectionItem
==================

.. autoclass:: sigma.rule.detection.SigmaDetectionItem
   :members:

SigmaRuleTag
============

.. autoclass:: sigma.rule.attributes.SigmaRuleTag
   :members:

SigmaLevel
==========

.. autoclass:: sigma.rule.attributes.SigmaLevel
   :members:

SigmaStatus
===========

.. autoclass:: sigma.rule.attributes.SigmaStatus
   :members:

EnumLowercaseStringMixin
========================

.. autoclass:: sigma.rule.attributes.EnumLowercaseStringMixin
   :members:

SigmaRelatedType
================

.. autoclass:: sigma.rule.attributes.SigmaRelatedType
   :members:

SigmaRelatedItem
================

.. autoclass:: sigma.rule.attributes.SigmaRelatedItem
   :members:

SigmaRelated
============

.. autoclass:: sigma.rule.attributes.SigmaRelated
   :members:

Sigma Data Types
*******************

SigmaString
==============

.. autoclass:: sigma.types.SigmaString
   :members:

SigmaNumber
==============

.. autoclass:: sigma.types.SigmaNumber
   :members:

SigmaBool
==============

.. autoclass:: sigma.types.SigmaBool
   :members:


SigmaNull
==============

.. autoclass:: sigma.types.SigmaNull
   :members:

SigmaRegularExpression
======================

.. autoclass:: sigma.types.SigmaRegularExpression
   :members:

SigmaCIDRExpression
=====================

.. autoclass:: sigma.types.SigmaCIDRExpression
   :members:

SigmaCompareExpression
======================

.. autoclass:: sigma.types.SigmaCompareExpression
   :members:

SigmaQueryExpression
====================

.. autoclass:: sigma.types.SigmaQueryExpression
   :members:
