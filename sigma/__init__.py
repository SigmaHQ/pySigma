from __future__ import annotations

# Backends, pipelines and validators are distributed as separate packages that install
# modules into the sigma namespace (e.g. sigma.backends.splunk). Extend the package path so
# that these are still found when they live in another sys.path entry, e.g. when a plugin is
# installed in editable mode.
from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)

from sigma.policy import SigmaPolicy  # noqa: E402
from sigma.policy.profiles import SafePolicy  # noqa: E402

default_policy: SigmaPolicy = SafePolicy
