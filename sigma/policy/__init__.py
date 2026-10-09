from __future__ import annotations

from dataclasses import dataclass, field

from sigma.policy.regex_engine import RE2RegexEngine, RegexEngine


@dataclass
class SigmaPolicy:
    """Carries regex and security-related runtime settings for pySigma.

    Instances can be attached to a processing pipeline or passed to pipeline factory
    methods to control behavior such as regex selection, template vars execution and
    external source access.
    """

    regex_engine: RegexEngine = field(default_factory=RE2RegexEngine)
    allow_template_vars: bool = False
    vars_allowed_paths: tuple[str, ...] | None = None
    allow_external_sources: bool = False


from sigma.policy.profiles import SafePolicy  # noqa: E402

default_policy: SigmaPolicy = SafePolicy
