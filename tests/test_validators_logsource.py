from wsgiref.validate import validator

from sigma.rule import SigmaRule

from sigma.validators.core.logsources import FieldnameLogsourceIssue, FieldnameLogsourceValidator


def test_fieldnamelogsourcevalidator_valid():
    validator = FieldnameLogsourceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        product: test
        category: test
        service: test
        definition: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_fieldnamelogsourcevalidator_service_invalid():
    validator = FieldnameLogsourceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        product: test
        category: test
        services: test
        definition: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [FieldnameLogsourceIssue(rule, "services")]


def test_fieldnamelogsourcevalidator_definition_invalid():
    validator = FieldnameLogsourceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        product: test
        description: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [FieldnameLogsourceIssue(rule, "description")]


def test_fieldnamelogsourcevalidator_many_invalid():
    validator = FieldnameLogsourceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        editor: test
        category: test
        description: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        FieldnameLogsourceIssue(rule, "editor"),
        FieldnameLogsourceIssue(rule, "description"),
    ]
