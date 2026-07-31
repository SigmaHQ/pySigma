Validating Sigma Rules
======================

pySigma includes a validation framework that checks Sigma rules for correctness, completeness,
and adherence to best practices. This guide explains how to use validators and how to create
custom ones.

Overview
--------

The validation system consists of:

* **SigmaValidator**: The main orchestrator that runs validators against rules.
* **SigmaRuleValidator**: Base class for individual validation checks.
* **SigmaValidationIssue**: Results reported by validators with severity levels.
* **Built-in validators**: A set of core validators for common checks.

Basic Usage
-----------

.. code-block:: python

   from sigma.rule import SigmaRule
   from sigma.collection import SigmaCollection
   from sigma.validation import SigmaValidator
   from sigma.validators.core.metadata import (
       IdentifierExistenceValidator,
       IdentifierUniquenessValidator,
       TitleLengthValidator,
   )
   from sigma.validators.core.values import DanglingWildcardValidator

   # Create a validator with specific checks
   validator = SigmaValidator(
       validators=[
           IdentifierExistenceValidator,
           IdentifierUniquenessValidator,
           TitleLengthValidator,
           DanglingWildcardValidator,
       ]
   )

   # Validate a single rule
   rule = SigmaRule.from_yaml(\"\"\"
       title: Test Rule
       status: test
       logsource:
           category: process_creation
           product: windows
       detection:
           selection:
               CommandLine|contains: test
           condition: selection
   \"\"\")
   issues = validator.validate_rule(rule)
   for issue in issues:
       print(f"[{issue.severity.name}] {issue}")

   # Validate a collection (enables cross-rule checks)
   collection = SigmaCollection.load_ruleset([Path("./rules/")])
   issues = validator.validate_collection(collection)
   final_issues = validator.finalize()  # Cross-rule checks like uniqueness
   all_issues = issues + final_issues

Severity Levels
^^^^^^^^^^^^^^^

Validation issues have one of three severity levels:

* ``LOW``: Minor issues, suggestions for improvement.
* ``MEDIUM``: Potential problems that should be investigated.
* ``HIGH``: Definite errors that must be fixed.

Configuring Validators from YAML
---------------------------------

Validators can be configured using a YAML configuration file:

.. code-block:: yaml

   validators:
     - all            # Start with all validators
     - -dangling_wildcard  # Remove specific validator

   exclusions:
     # Exclude specific validators for specific rules (by UUID)
     550d7260-4545-4813-9f4e-90e5f20e5ee3:
       - identifier_existence
     5b345b24-4c12-4bfe-90e0-c1b3f0e3c5d7:
       - title_length

   config:
     # Pass configuration to validators
     title_length:
       min_length: 10
       max_length: 100

Loading from YAML:

.. code-block:: python

   import yaml
   from sigma.validation import SigmaValidator
   from sigma.validators.core import validators as core_validators

   with open("validation_config.yml") as f:
       config = yaml.safe_load(f)

   validator = SigmaValidator.from_dict(config, core_validators)

The ``validators`` list supports:

* ``all``: Include all known validators.
* ``validator_name``: Include a specific validator.
* ``-validator_name``: Exclude a previously included validator.

Built-in Validators
-------------------

pySigma ships with validators in the ``sigma.validators.core`` module:

Metadata Validators (``sigma.validators.core.metadata``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check rule metadata fields for correctness and completeness.

* **IdentifierExistenceValidator**: Ensures every rule has a UUID identifier.
* **IdentifierUniquenessValidator**: Ensures rule identifiers are unique across a collection.
* **TitleLengthValidator**: Checks title length constraints.
* **DuplicateTitleValidator**: Detects duplicate titles.
* **StatusExistenceValidator**: Ensures rules have a status field.
* **LevelExistenceValidator**: Ensures rules have a level field.
* **DateExistenceValidator**: Checks for date field presence.
* **DescriptionExistenceValidator**: Checks for description field presence.

Condition Validators (``sigma.validators.core.condition``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check rule conditions for correctness.

* **AllOfThemConditionValidator**: Checks proper use of ``all of them``.
* **DanglingConditionReferenceValidator**: Detects references to non-existent detections.

Tag Validators (``sigma.validators.core.tags``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check rule tags for validity.

* **ATTACKTagValidator**: Validates MITRE ATT&CK tags.
* **TLPTagValidator**: Validates TLP (Traffic Light Protocol) tags.
* **CVETagValidator**: Validates CVE identifier tags.

Modifier Validators (``sigma.validators.core.modifiers``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check detection modifiers for correctness.

Value Validators (``sigma.validators.core.values``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check detection values for potential issues.

* **DanglingWildcardValidator**: Detects wildcards that may be unintentional.
* **DoubleWildcardValidator**: Detects consecutive wildcards.

Log Source Validators (``sigma.validators.core.logsources``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check log source definitions for issues.

Writing Custom Validators
-------------------------

To create a custom validator, subclass ``SigmaRuleValidator`` or one of the specialized
base classes:

Basic Rule Validator
^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from dataclasses import dataclass
   from sigma.rule import SigmaRule
   from sigma.validators.base import (
       SigmaRuleValidator,
       SigmaValidationIssue,
       SigmaValidationIssueSeverity,
   )

   @dataclass
   class CustomIssue(SigmaValidationIssue):
       description: str = "My custom validation issue"
       severity: SigmaValidationIssueSeverity = SigmaValidationIssueSeverity.MEDIUM

   class CustomValidator(SigmaRuleValidator):
       \"\"\"Validates that rules have a description.\"\"\"

       def validate(self, rule: SigmaRule) -> list[SigmaValidationIssue]:
           if not rule.description:
               return [CustomIssue(rules=[rule])]
           return []

Detection Item Validator
^^^^^^^^^^^^^^^^^^^^^^^^

For validators that need to check individual detection items:

.. code-block:: python

   from sigma.validators.base import SigmaDetectionValidator
   from sigma.rule.detection import SigmaDetectionItem

   class FieldNameValidator(SigmaDetectionValidator):
       \"\"\"Validates field names follow naming conventions.\"\"\"

       def validate_detection_item(
           self, detection_item: SigmaDetectionItem
       ) -> list[SigmaValidationIssue]:
           issues = []
           if detection_item.field and " " in detection_item.field:
               issues.append(CustomIssue(rules=[self._rule]))
           return issues

Finalization (Cross-Rule Checks)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Validators can implement ``finalize()`` for checks that span multiple rules:

.. code-block:: python

   class UniqueFieldValidator(SigmaRuleValidator):
       \"\"\"Check for conflicting field usage across rules.\"\"\"

       def __init__(self, **kwargs):
           super().__init__(**kwargs)
           self.field_rules: dict[str, list[SigmaRule]] = {}

       def validate(self, rule: SigmaRule) -> list[SigmaValidationIssue]:
           # Collect data during validation
           for field in rule.detection.used_fields:
               self.field_rules.setdefault(field, []).append(rule)
           return []

       def finalize(self) -> list[SigmaValidationIssue]:
           # Report cross-rule issues
           issues = []
           for field, rules in self.field_rules.items():
               if len(rules) > 100:
                   issues.append(CustomIssue(rules=rules))
           return issues

Configurable Validators
^^^^^^^^^^^^^^^^^^^^^^^

Validators can accept configuration parameters:

.. code-block:: python

   class TitleLengthValidator(SigmaRuleValidator):
       \"\"\"Validates title length with configurable bounds.\"\"\"

       def __init__(self, min_length: int = 10, max_length: int = 100, **kwargs):
           super().__init__(**kwargs)
           self.min_length = min_length
           self.max_length = max_length

       def validate(self, rule: SigmaRule) -> list[SigmaValidationIssue]:
           if rule.title and len(rule.title) > self.max_length:
               return [TitleTooLongIssue(rules=[rule])]
           return []

Configuration is passed via the ``config`` section in YAML:

.. code-block:: yaml

   config:
     title_length:
       min_length: 5
       max_length: 120

Validator Plugin Registration
-----------------------------

Custom validators are discovered through the ``sigma.validators`` namespace. Create a
package with:

.. code-block:: python

   # sigma/validators/myvalidators/__init__.py
   from .my_validators import CustomValidator, AnotherValidator

   validators = {
       "custom": CustomValidator,
       "another": AnotherValidator,
   }

See the :doc:`plugin_system` guide for details on plugin distribution.
