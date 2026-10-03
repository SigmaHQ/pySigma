from __future__ import annotations

from sigma.policy import SigmaPolicy
from sigma.policy.regex_engine import PythonRegexEngine, RE2RegexEngine

SafePolicy = SigmaPolicy(regex_engine=RE2RegexEngine())
TrustedPolicy = SigmaPolicy(regex_engine=PythonRegexEngine())
