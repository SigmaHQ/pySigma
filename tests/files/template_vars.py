"""
Example template vars file for testing custom Jinja2 functions.
"""

import json


def format_price(amount, currency='€'):
    """Format a price with currency symbol."""
    return f'{amount:.2f}{currency}'


def parse_json(json_str):
    """Parse JSON string into Python object."""
    return json.loads(json_str)


def get_risk_mapping(logsource_category):
    """Example function to get risk mapping based on logsource."""
    mappings = {
        'process_creation': {
            'risk_object': 'process',
            'risk_category': 'malware'
        },
        'network_connection': {
            'risk_object': 'network',
            'risk_category': 'intrusion'
        }
    }
    return mappings.get(logsource_category, {})


# This dict must be defined and contains all functions/variables to export
vars = {
    'format_price': format_price,
    'parse_json': parse_json,
    'get_risk_mapping': get_risk_mapping,
}
