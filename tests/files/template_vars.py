"""
Example template vars file for testing custom Jinja2 functions.
"""

import json


def parse_json(json_str):
    """Parse JSON string into Python object."""
    return json.loads(json_str)


# This dict must be defined and contains all functions/variables to export
vars = {
    'parse_json': parse_json,
}
