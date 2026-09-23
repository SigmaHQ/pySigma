from __future__ import annotations

from sigma.policy import SigmaPolicy
from sigma.policy.profiles import SafePolicy

default_policy: SigmaPolicy = SafePolicy
