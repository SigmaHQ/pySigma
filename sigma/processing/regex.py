from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast, TYPE_CHECKING

if TYPE_CHECKING:
    from sigma.policy.regex_engine import RegexEngine, RegexPattern
    from sigma.processing.pipeline import ProcessingPipeline


@dataclass
class ProcessingRegularExpressionMixin:
    """Mixin providing shared regex engine resolution and operation helpers.

    Intended for ProcessingCondition and Transformation subclasses that work with
    regular expressions.  Concrete classes must expose a ``_pipeline`` attribute.
    """

    if TYPE_CHECKING:
        _pipeline: ProcessingPipeline | None

    _re: RegexPattern | None = field(init=False, default=None, repr=False, compare=False)
    _re_engine: RegexEngine | None = field(init=False, default=None, repr=False, compare=False)

    def resolve_regex_engine(self) -> RegexEngine:
        """Return the effective regex engine for this processing context."""
        import sigma

        _pipeline = getattr(self, "_pipeline", None)
        if _pipeline is None:
            return sigma.default_policy.regex_engine
        return _pipeline.resolve_regex_engine()  # type: ignore[no-any-return]

    def compile_regex(self, pattern: str) -> RegexPattern:
        """Compile and cache *pattern* with the resolved engine.

        Uses the cached compiled pattern when the active engine is unchanged.
        Recompiles automatically when the engine has changed (e.g. after a pipeline
        with a different policy is attached).
        """
        engine = self.resolve_regex_engine()
        if getattr(self, "_re", None) is None or getattr(self, "_re_engine", None) is not engine:
            self._re = engine.compile(pattern)
            self._re_engine = engine
        compiled = self._re
        assert compiled is not None
        return compiled

    def regex_match(self, pattern: str, string: str) -> Any:
        """Return the match object (or None) for *pattern* against *string*."""
        return self.compile_regex(pattern).match(string)

    def regex_sub(self, pattern: str, replacement: str, string: str) -> str:
        """Return *string* with all *pattern* matches replaced by *replacement*."""
        return self.compile_regex(pattern).sub(replacement, string)
