Rule Validation
###############

The rule validation framework of pySigma offers functionality to validate rules beyond errors that
occur while parsing of rules and the included conditions. It consists of the following components:

* The *validator* implemented by the :py:class:`sigma.validation.SigmaValidator` class that conducts
  validation of single rules or a whole ruleset with a defined set of validators and exclusions.
* *Validator checks* that implement rule checks that reside in the :py:mod:`sigma.validators` module. A
  validator can perform checks on isolated rules or keep a state and conduct additional checks in a
  finalization step.

Validator
**************

The :py:class:`~sigma.validation.SigmaValidator` class implements the process of validation of Sigma
rules. It allows to define a set of validators as well as exclusions of validators for specific
rules by rule identifiers. The configuration is passed while a *SigmaValidator* object is
instantiated. Alternatively, the object can be instantiated from a configuration contained in a
Python dict or a YAML file.

A single rule can be validated with the :py:meth:`sigma.validation.SigmaValidator.validate_rule`
method. A set of rules is validated with :py:meth:`sigma.validation.SigmaValidator.validate_rules`
and in contrast to the single rule validation this method takes care of the finalization of the
validation. Finalization of the validation can be explicitely invoked with
:py:meth:`sigma.validation.SigmaValidator.finalize` and is required for validators that perform
checks across different rules like identifier uniqueness.

.. autoclass:: sigma.validation.SigmaValidator
   :members:

Usage
=====

Initialize a *SigmaValidator* object with the set of validators that should be used. The following
code instantiates it with all available validators:::

    from sigma.validators.core import validators
    rule_validator = SigmaValidator(validators.values())

*SigmaValidator* instantiation can also be made configurable with YAML files. For this purpose
create a YAML file such as this one:

.. code-block:: yaml

    validators:
        - all
        - -tlptag
        - -tlpv1_tag
    exclusions:
        5013332f-8a70-4e04-bcc1-06a98a2cca2e: wildcards_instead_of_modifiers

The details are discussed in the next section. A *SigmaValidator* is then instantiated as follows:::

    with open("config.yml") as validation_config:
        rule_validator = SigmaValidator.from_yaml(validation_config.read())

The validation of a rule set is then run as follows:::

    issues = rule_validator.validate_rules(sigma_rules)

Where *sigma_rules* might be an arbitrary iterable of *SigmaRule* objects, including a
*SigmaCollection*. The resulting *issues* variable contains a list of
:py:meth:`sigma.validators.base.SigmaValidationIssue` objects that simply can be printed.

Configuration
=============

The configuration of a validation run can be stored in a *dict* or in a YAML file.

Validator Checks
----------------

The first item that must be contained on the top level is the *validators* list, that defines
which validator checks should be used in the run:

.. code-block:: yaml

    validators:
        - all
        - -tlptag
        - -tlpv1_tag

The list contains the identifiers of validator classes that should be used or deactivated, if the
name is prefixed with a minus *-*. The identifier *all* has a special role and activates all
validator classes. This is useful to maintain a complete set of validator checks including checks
that were added after the configuration was written. Particular unwanted checks are disabled with
the minus syntax after the initial *all* declaration.

In the above example, all validator checks are enabled except the validators for TLPv1 and the
combined TLP validator because TLPv2 should be used exclusively.

Exclusions
----------

Sometimes it can be necessary to exclude validator checks for particular rules because something
detected by the check is desired for this rule. For this purpose, exclusions can be defined by
defining a rule identifier as key and one or multiple validator check identifiers that shouldn't be
applied to the rule. Example:

.. code-block:: yaml

    exclusions:
        5013332f-8a70-4e04-bcc1-06a98a2cca2e:
            - wildcards_instead_of_modifiers

This exclusion defines that the *wildcards_instead_of_modifiers* validator check is disabled for the
rule with the identifier *5013332f-8a70-4e04-bcc1-06a98a2cca2e*.

MITRE Data Sources
------------------

Some validator checks, such as ``ATTACKTagValidator`` and ``D3FENDTagValidator``, require access to
MITRE ATT&CK and D3FEND data to validate tags. By default, this data is downloaded automatically
from the official MITRE repositories when first accessed.

In environments with restricted internet access, you can download the data separately and configure
pySigma to load it from local files:

.. code-block:: python

    from sigma.data import mitre_attack_data, mitre_d3fend_data
    
    # Load MITRE ATT&CK data from a local file
    mitre_attack_data.set_url("/path/to/enterprise-attack.json")
    
    # Load MITRE D3FEND data from a local file
    mitre_d3fend_data.set_url("/path/to/d3fend.json")

You can also use custom URLs if you maintain your own mirror of the MITRE data:

.. code-block:: python

    mitre_attack_data.set_url("https://your-mirror.example.com/enterprise-attack.json")
    mitre_d3fend_data.set_url("https://your-mirror.example.com/d3fend.json")

The data files can be obtained from:

* MITRE ATT&CK: https://github.com/mitre-attack/attack-stix-data
* MITRE D3FEND: https://github.com/d3fend/d3fend-ontology

Configuration
-------------

Validator checks that accept parameters can be configured with a dictionary that is passed as the
*config* parameter. This dictionary maps validator identifiers to dictionaries of parameter-value
pairs that are passed as keyword arguments to the validator constructor. Example:

.. code-block:: yaml

    config:
        description_length:
            min_length: 100

Validator Checks
****************

*Validator checks* implement checks of Sigma rules for particular issues. Issues can be:

* Bad practices that likely lead to erroneous detection logic.
* Usage of wrong tags.
* Missing rule attributes that don't cause rule parsing errors, but are bad practices.

A check can be conducted against a single rule or it can keep state across multiple rules and
conduct a check that is not bound to a particular rule in a finalization step of a validator run.

Validator checks emit issue objects that describe detected issues and rules they appeared in.
Details regarding issue objects are described below.

Implementing own Checks
=======================

A validator check is implemented by a class inherited from
:py:class:`sigma.validators.base.SigmaRuleValidator`. The method
:py:meth:`~sigma.validators.base.SigmaRuleValidator.validate` is called for each rule and can be
used to perform a check on the whole rule as well as collecting state information in the validator
check object itself for later usage. A common location for such deferred checks is the
:py:meth:`~sigma.validators.base.SigmaRuleValidator.finalize` method, that is invoked after all
rules were checked individually with the *validate* method.

There exist various convenience classes that can be used for validation of particular parts of a
Sigma rule. These classes offer special-purpose methods that are invoked for each appearance of a
desired rule part and takes care of the proper iteration of these parts. These classes are:

* :py:class:`sigma.validators.base.SigmaDetectionValidator` for checking all detection
    definitions below the *detection* attribute of a Sigma rule.
* :py:class:`sigma.validators.base.SigmaDetectionItemValidator` for checking all detection items
    in detection definitions.
* :py:class:`sigma.validators.base.SigmaValueValidator` for checking all values contained in
  detection items of a Sigma rule.
* :py:class:`sigma.validators.base.SigmaStringValueValidator` for checking all string values contained in
  detection items of a Sigma rule.
* :py:class:`sigma.validators.base.SigmaTagValueValidator` for checking all tags appearing beloe the
  *tags* attribute of a Sigma rule.

Parametrization of Checks
=========================

If required, checks can be parametrized by passing parameters as keyword arguments to the validator
check constructor. for this purpose, the validator check class must be a *frozen dataclass*. This
can be achieved by decorating the class with `@dataclass(frozen=True)` from the *dataclasses*
module.

The parameters can then be specified as dataclass members. The `SigmaValidator` instance will pass
the parameters to the validator check constructor as keyword arguments.

Base Classes
============

.. autoclass:: sigma.validators.base.SigmaDetectionValidator
    :members:

.. autoclass:: sigma.validators.base.SigmaDetectionItemValidator
    :members:

.. autoclass:: sigma.validators.base.SigmaValueValidator
    :members:

.. autoclass:: sigma.validators.base.SigmaStringValueValidator
    :members:

.. autoclass:: sigma.validators.base.SigmaTagValidator
    :members:

Checks Implemented in pySigma
=============================
This section lists all implemented validation check classes including their associated issue classes.

.. automodule:: sigma.validators.core.condition
    :members:

.. automodule:: sigma.validators.core.metadata
    :members:

.. automodule:: sigma.validators.core.modifiers
    :members:

.. automodule:: sigma.validators.core.tags
    :members:

.. automodule:: sigma.validators.core.values
    :members:

Issues
******

An issue is a class inherited from :py:class:`sigma.validators.base.SigmaValidationIssue`:

.. autoclass:: sigma.validators.base.SigmaValidationIssue
    :members:

It must declare at least the following class attributes:

* *description*: a string with a textual description of the issue displayed to the user.
* *severity*: a severity as :py:class:`~sigma.validators.base.SigmaValidationIssueSeverity` object.

Further attributes can be defined optionally and are rendered when the issue object is converted to
a string.

Severities are defined as follows:

.. autoclass:: sigma.validators.base.SigmaValidationIssueSeverity
    :members: