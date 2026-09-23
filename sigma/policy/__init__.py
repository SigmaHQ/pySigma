from __future__ import annotations

from dataclasses import dataclass

from sigma.policy.regex_engine import RegexEngine


@dataclass
class SigmaPolicy:
    """Holds behavioural settings for pySigma. Currently only the regex engine."""

    regex_engine: RegexEngine
