Matching
========

The ``sigma.matching`` package provides a pure-Python runtime for evaluating log events directly
against Sigma rules, without converting them to a query language.

.. admonition:: Performance Note

   This engine is **not designed for high-throughput production workloads**. It prioritises
   correctness and ease of use over speed. For performance-sensitive use cases, consider the
   Rust-based Sigma engine `rsigma <https://github.com/timescale/rsigma>`_.

See also: :doc:`/guides/matching` for a step-by-step introduction with examples.

Event
-----

.. autoclass:: sigma.matching.Event
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.matching.EventLogSource
   :members:
   :undoc-members:
   :show-inheritance:

SigmaMatcher
------------

.. autoclass:: sigma.matching.SigmaMatcher
   :members:
   :undoc-members:
   :show-inheritance:

SigmaMatch
----------

.. autoclass:: sigma.matching.SigmaMatch
   :members:
   :undoc-members:
   :show-inheritance:

SigmaRuleMatcher
----------------

.. autoclass:: sigma.matching.SigmaRuleMatcher
   :members:
   :undoc-members:
   :show-inheritance:

SigmaCorrelationRuleMatcher
---------------------------

.. autoclass:: sigma.matching.SigmaCorrelationRuleMatcher
   :members:
   :undoc-members:
   :show-inheritance:

Internal Components
-------------------

The following classes are used internally by :class:`~sigma.matching.SigmaMatcher` and are not
part of the public API, but are documented here for completeness.

.. autoclass:: sigma.matching.compiler.MatchCompiler
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: sigma.matching.state.SlidingWindowState
   :members:
   :undoc-members:
   :show-inheritance:
