SigmaPolicy
===========

pySigma can be used in different environments with vastly different trust models:

* **Private detection CI/CD pipeline**: Your organization controls both the Sigma rules and
  the conversion pipeline. Rules come from trusted, internal sources. In this scenario, you
  can afford to enable more powerful features like template vars execution and broader regex
  support.

* **Public web application**: Users upload or specify Sigma rules, and you convert them and
  apply processing pipelines. Rules may come from untrusted sources or even malicious actors.
  In this scenario, you must disable powerful features that could be exploited (arbitrary code
  execution, denial-of-service via regex backtracking) and enforce path-based restrictions on
  template loading.

``SigmaPolicy`` lets you declare your trust model once and have those settings propagate
automatically through the entire pipeline. Components that might be exploited by untrusted
rules (template vars, external sources, unbounded regex) respect your policy settings and
remain disabled by default.

The effective policy is used by:

* pipeline regex resolution
* Jinja template vars loading
* template path restrictions for YAML or dictionary-defined templates
* external source placeholder transformations

API
---

.. autoclass:: sigma.policy.SigmaPolicy
   :members:
   :undoc-members:
   :show-inheritance:

Settings
--------

``regex_engine``
   Regex backend for conversions and transformations. Defaults to ``RE2RegexEngine`` for DoS
   protection with no backtracking. Can be set to ``PythonRegexEngine`` for broader regex
   support when DoS protection is not a concern.

``allow_template_vars``
   Enables the ``vars`` feature of template-based postprocessing and finalizers. That feature
   executes Python code from a referenced file and is therefore disabled by default.

``vars_allowed_paths``
   Restricts template vars files, and restricted template directories, to one or more trusted
   base paths. If this is ``None``, no base-path restriction is enforced. When a pipeline is
   loaded via ``ProcessingPipeline.from_yaml(..., source_path=...)`` and the effective policy
   has ``vars_allowed_paths=None``, pySigma derives a one-entry allowlist from the directory
   containing ``source_path``.

``allow_external_sources``
   Enables transformations that load data from local files, HTTP endpoints, or command output.
   These transformations are disabled by default.

Effective Policy Resolution
---------------------------

Processing components prefer the policy attached to the active
``ProcessingPipeline`` and fall back to ``sigma.policy.default_policy`` only when no explicit policy
was provided.

pySigma ships with these predefined profiles:

* ``sigma.policy.profiles.SafePolicy``: RE2-based default policy with the security-sensitive
  features disabled.
* ``sigma.policy.profiles.TrustedPolicy``: Python regex engine policy for trusted execution
  environments.

Usage
-----

Pass a policy when loading pipelines from YAML or dictionaries:

.. code-block:: python

   from sigma.policy import SigmaPolicy
   from sigma.policy.regex_engine import RE2RegexEngine
   from sigma.processing.pipeline import ProcessingPipeline

   policy = SigmaPolicy(
       regex_engine=RE2RegexEngine(),
       allow_template_vars=True,
       vars_allowed_paths=("/srv/sigma/pipelines",),
   )

   pipeline = ProcessingPipeline.from_yaml(
       yaml_text,
       source_path="/srv/sigma/pipelines/linux/pipeline.yml",
       policy=policy,
   )

You can also attach the same policy to a Python-constructed pipeline:

.. code-block:: python

   pipeline = ProcessingPipeline(
       items=[...],
       postprocessing_items=[...],
       finalizers=[...],
       policy=policy,
   )

This keeps the policy decisions in one place and allows nested transformations and finalizers
to inherit the same effective settings.

Trusted and Untrusted Input
---------------------------

``SigmaPolicy`` is a Python-side control surface, not a trusted YAML feature. pySigma does not
accept policy overrides from nested transformation or finalizer definitions loaded from YAML or
raw dictionaries.

The following keys are sanitized from untrusted nested definitions before object instantiation:

* ``policy``
* ``allow_template_vars``
* ``vars_allowed_paths``
* ``allow_external_sources``
* ``restrict_template_path``

This sanitization happens in these loader paths:

* ``ProcessingItemBase._instantiate_transformation()`` for transformation dictionaries
* ``ProcessingPipeline.from_dict()`` for finalizer dictionaries
* ``NestedFinalizer.from_dict()`` for nested finalizer dictionaries

Top-level pipeline loading is also strict about unknown keys. For example, a top-level
``allow_external_sources`` key in pipeline YAML is rejected instead of being treated as a
runtime opt-in.

Migration Note
--------------

The settings ``allow_template_vars``, ``vars_allowed_paths``, and
``allow_external_sources`` are no longer public per-method loader parameters. They are carried
through ``SigmaPolicy`` instead.