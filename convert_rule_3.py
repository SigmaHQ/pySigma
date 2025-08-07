from sigma.collection import SigmaCollection
from sigma.backends.siem import SiemBackend

# The user-provided Sigma rule
sigma_rule_yaml = r"""
title: Suspicious Environment Variable Has Been Registered
id: 966315ef-c5e1-4767-ba25-fce9c8de3660
status: test
description: Detects the creation of user-specific or system-wide environment variables via the registry. Which contains suspicious commands and strings
references:
    - https://infosec.exchange/@sbousseaden/109542254124022664
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-20
modified: 2023-08-17
tags:
    - attack.defense-evasion
    - attack.persistence
logsource:
    product: windows
    category: registry_set
detection:
    selection_main:
        TargetObject|contains: '\Environment\'
    selection_details:
        - Details:
              - 'powershell'
              - 'pwsh'
        - Details|contains:
              # Add more suspicious strings in env variables below
              - '\AppData\Local\Temp\'
              - 'C:\Users\Public\'
              # Base64 MZ Header
              - 'TVqQAAMAAAAEAAAA' # MZ..........
              - 'TVpQAAIAAAAEAA8A'
              - 'TVqAAAEAAAAEABAA'
              - 'TVoAAAAAAAAAAAAA'
              - 'TVpTAQEAAAAEAAAA'
              # Base64 Invoke- (UTF-8)
              - 'SW52b2tlL'
              - 'ludm9rZS'
              - 'JbnZva2Ut'
              # Base64 Invoke- (UTF-16LE)
              - 'SQBuAHYAbwBrAGUALQ'
              - 'kAbgB2AG8AawBlAC0A'
              - 'JAG4AdgBvAGsAZQAtA'
        - Details|startswith:  # https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639
              - 'SUVY'
              - 'SQBFAF'
              - 'SQBuAH'
              - 'cwBhA'
              - 'aWV4'
              - 'aQBlA'
              - 'R2V0'
              - 'dmFy'
              - 'dgBhA'
              - 'dXNpbm'
              - 'H4sIA'
              - 'Y21k'
              - 'cABhAH'
              - 'Qzpc'
              - 'Yzpc'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
"""

# Instantiate the backend
siem_backend = SiemBackend()

# Load the rule into a collection
# Wrap the call in a try-except block to catch potential parsing errors
try:
    rule_collection = SigmaCollection.from_yaml(sigma_rule_yaml)
    # Convert the rule
    result = siem_backend.convert(rule_collection)
    # Print the result
    print(result[0])
except Exception as e:
    print(f"An error occurred: {e}")
    import traceback
    traceback.print_exc()
