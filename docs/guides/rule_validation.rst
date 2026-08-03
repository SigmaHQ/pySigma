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
   issues = validator.validate_rules(collection)

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

.. list-table::
   :widths: 30 30 40
   :header-rows: 1

   * - Validator Class
     - Config Identifier
     - Description
   * - ``IdentifierExistenceValidator``
     - ``identifier_existence``
     - Ensures every rule has a UUID identifier.
   * - ``IdentifierUniquenessValidator``
     - ``identifier_uniqueness``
     - Ensures rule identifiers are unique across a collection.
   * - ``DuplicateTitleValidator``
     - ``duplicate_title``
     - Detects duplicate rule titles in a collection.
   * - ``DuplicateReferencesValidator``
     - ``duplicate_references``
     - Detects duplicate references within a rule.
   * - ``DuplicateFilenameValidator``
     - ``duplicate_filename``
     - Detects duplicate filenames across rules in a collection.
   * - ``FilenameLengthValidator``
     - ``filename_length``
     - Validates rule filename length (default: 10-90 characters).
   * - ``CustomAttributesValidator``
     - ``custom_attributes``
     - Detects custom field names similar to legitimate ones.

Condition Validators (``sigma.validators.core.condition``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check rule conditions for correctness.

.. list-table::
   :widths: 30 30 40
   :header-rows: 1

   * - Validator Class
     - Config Identifier
     - Description
   * - ``DanglingDetectionValidator``
     - ``dangling_detection``
     - Detects detection definitions not referenced from condition.
   * - ``DanglingConditionValidator``
     - ``dangling_condition``
     - Detects conditions referencing non-existent detection definitions.
   * - ``AllOfThemConditionValidator``
     - ``all_of_them_condition``
     - Discourages use of ``all of them`` condition; suggests ``all of selection*`` instead.
   * - ``ThemConditionWithSingleDetectionValidator``
     - ``them_condition_with_single_detection``
     - Detects ``them`` condition usage with only one detection.

Tag Validators (``sigma.validators.core.tags``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check rule tags for validity and format.

.. list-table::
   :widths: 30 30 40
   :header-rows: 1

   * - Validator Class
     - Config Identifier
     - Description
   * - ``TagFormatValidator``
     - ``tag_format``
     - Validates tag namespace and name against allowed character patterns.
   * - ``ATTACKTagValidator``
     - ``attack_tag``
     - Validates MITRE ATT&CK tactics, techniques, and related identifiers.
   * - ``D3FENDTagValidator``
     - ``d3fend_tag``
     - Validates MITRE D3FEND tactics and techniques.
   * - ``TLPTagValidator``
     - ``tlp_tag``
     - Validates TLP (Traffic Light Protocol) tags from all TLP versions.
   * - ``TLPv1TagValidator``
     - ``tlpv1_tag``
     - Validates TLP tags according to TLP 1.0 standard (white, green, amber, red).
   * - ``TLPv2TagValidator``
     - ``tlpv2_tag``
     - Validates TLP tags according to TLP 2.0 standard (clear, green, amber, amber-strict, red).
   * - ``DuplicateTagValidator``
     - ``duplicate_tag``
     - Detects duplicate tags within a rule.
   * - ``NamespaceTagValidator``
     - ``namespace_tag``
     - Validates that tags use allowed namespaces (attack, car, cve, d3fend, detection, stp, tlp).
   * - ``CARTagValidator``
     - ``car_tag``
     - Validates CAR (Cyber Analytics Repository) tag format.
   * - ``CVETagValidator``
     - ``cve_tag``
     - Validates CVE identifier tag format.
   * - ``DetectionTagValidator``
     - ``detection_tag``
     - Validates detection tag content.
   * - ``STPTagValidator``
     - ``stp_tag``
     - Validates STP (Security Techniques and Procedures) tag format.

Modifier Validators (``sigma.validators.core.modifiers``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check detection modifiers for correct usage and combinations.

.. list-table::
   :widths: 30 30 40
   :header-rows: 1

   * - Validator Class
     - Config Identifier
     - Description
   * - ``InvalidModifierCombinationsValidator``
     - ``invalid_modifier_combinations``
     - Detects invalid or problematic modifier combinations.

Value Validators (``sigma.validators.core.values``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check detection values for potential issues.

.. list-table::
   :widths: 30 30 40
   :header-rows: 1

   * - Validator Class
     - Config Identifier
     - Description
   * - ``DoubleWildcardValidator``
     - ``double_wildcard``
     - Detects consecutive wildcards (``**``) in values.
   * - ``NumberAsStringValidator``
     - ``number_as_string``
     - Detects numeric values expressed as strings.
   * - ``ControlCharacterValidator``
     - ``control_character``
     - Detects control characters (often from missing escape sequences).
   * - ``WildcardsInsteadOfModifiersValidator``
     - ``wildcards_instead_of_modifiers``
     - Suggests ``contains``, ``startswith``, or ``endswith`` modifiers instead of wildcards.
   * - ``EscapedWildcardValidator``
     - ``escaped_wildcard``
     - Detects escaped wildcards (``\*`` or ``\?``) in rule logic.

Log Source Validators (``sigma.validators.core.logsources``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Check log source definitions for issues and best practices.

.. list-table::
   :widths: 30 30 40
   :header-rows: 1

   * - Validator Class
     - Config Identifier
     - Description
   * - ``SpecificInsteadOfGenericLogsourceValidator``
     - ``specific_instead_of_generic_logsource``
     - Detects use of specific event IDs where generic log sources should be used.
   * - ``FieldnameLogsourceValidator``
     - ``fieldname_logsource``
     - Detects invalid field names in log source definitions.

SigmaHQ Strict Validators
-------------------------

The `pySigma-validators-SigmaHQ <https://github.com/SigmaHQ/pySigma-validators-SigmaHQ>`_
package provides additional strict validation checks used by the SigmaHQ repository.
These validators enforce the quality and consistency standards required for rules
in the official Sigma rule repository.

To use them, install the package:

.. code-block:: bash

   pip install pySigma-validators-SigmaHQ

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
