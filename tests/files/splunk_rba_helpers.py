"""
Example template vars file demonstrating Risk Based Alerting configuration for Splunk ES8.

This file shows a real-world use case where helper functions can be used to:
1. Map logsource categories to risk objects and categories
2. Parse JSON configuration files
3. Provide reusable validation logic

This is the exact use case described in the issue.
"""

import json


# Example logsource to risk mapping
LOGSOURCE_RISK_MAPPING = {
    'process_creation': {
        'risk_object': 'system',
        'risk_category': 'malware',
        'required_fields': ['Image', 'CommandLine']
    },
    'network_connection': {
        'risk_object': 'network',
        'risk_category': 'intrusion',
        'required_fields': ['DestinationIp', 'DestinationPort']
    },
    'file_event': {
        'risk_object': 'system',
        'risk_category': 'unauthorized_access',
        'required_fields': ['TargetFilename']
    },
    'registry_event': {
        'risk_object': 'system',
        'risk_category': 'persistence',
        'required_fields': ['TargetObject']
    }
}


def get_risk_object(logsource_category):
    """Get the risk object for a given logsource category."""
    mapping = LOGSOURCE_RISK_MAPPING.get(logsource_category, {})
    return mapping.get('risk_object', 'unknown')


def get_risk_category(logsource_category):
    """Get the risk category for a given logsource category."""
    mapping = LOGSOURCE_RISK_MAPPING.get(logsource_category, {})
    return mapping.get('risk_category', 'unknown')


def get_required_fields(logsource_category):
    """Get the required fields for a given logsource category."""
    mapping = LOGSOURCE_RISK_MAPPING.get(logsource_category, {})
    return mapping.get('required_fields', [])


def load_logsource_config(json_str):
    """Load and parse a logsource configuration from JSON string."""
    return json.loads(json_str)


def format_risk_score(score):
    """Format a risk score for Splunk."""
    return f"risk_score={int(score)}"


# Export all helper functions
vars = {
    'get_risk_object': get_risk_object,
    'get_risk_category': get_risk_category,
    'get_required_fields': get_required_fields,
    'load_logsource_config': load_logsource_config,
    'format_risk_score': format_risk_score,
}
