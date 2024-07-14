from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.core.logsources import FieldnameLogsourceIssue, FieldnameLogsourceValidator
from .test_conversion_correlations import event_count_correlation_rule


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


def test_fieldnamelogsourcevalidator_correlation_rule(event_count_correlation_rule):
    validator = FieldnameLogsourceValidator()
    correlation_rule = [
        rule
        for rule in event_count_correlation_rule.rules
        if isinstance(rule, SigmaCorrelationRule)
    ][0]
    assert validator.validate(correlation_rule) == []
