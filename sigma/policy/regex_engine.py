from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any, Mapping, Protocol, cast


class RegexPattern(Protocol):
    """Protocol for compiled regex objects from Python ``re`` and Google RE2."""

    groupindex: Mapping[str, int]

    def match(self, string: str, *args: Any, **kwargs: Any) -> Any: ...

    def fullmatch(self, string: str, *args: Any, **kwargs: Any) -> Any: ...

    def search(self, string: str, *args: Any, **kwargs: Any) -> Any: ...

    def sub(self, repl: Any, string: str, *args: Any, **kwargs: Any) -> str: ...


class RegexEngine(ABC):
    """Strategy base class for regex engine implementations."""

    def __eq__(self, other: object) -> bool:
        return type(self) is type(other)

    def __hash__(self) -> int:
        return hash(type(self))

    @abstractmethod
    def compile(self, pattern: str, flags: int = 0) -> RegexPattern:
        """Compile a regex pattern and return a compiled pattern object."""

    @property
    @abstractmethod
    def error(self) -> type[Exception]:
        """The exception type raised for invalid regex patterns."""


class PythonRegexEngine(RegexEngine):
    """Regex engine backed by Python's built-in re module."""

    def compile(self, pattern: str, flags: int = 0) -> RegexPattern:
        return cast(RegexPattern, re.compile(pattern, flags))

    @property
    def error(self) -> type[re.error]:
        return re.error


class RE2RegexEngine(RegexEngine):
    """DoS-safe regex engine backed by Google RE2 (no backtracking)."""

    def __init__(self) -> None:
        try:
            import re2  # type: ignore[import-untyped]

            self._re2 = re2
        except ImportError as exc:
            raise ImportError(
                "The 'google-re2' package is required for RE2RegexEngine (SafePolicy). "
                "Install it with: pip install google-re2"
            ) from exc

    def compile(self, pattern: str, flags: int = 0) -> RegexPattern:
        # RE2's Python binding doesn't accept Python re int-flags as a positional arg;
        # embed them as inline flags instead, which RE2 supports natively.
        import re

        flag_map = {re.IGNORECASE: "i", re.MULTILINE: "m", re.DOTALL: "s"}
        prefix = "".join(v for k, v in flag_map.items() if int(flags) & int(k))
        if prefix:
            pattern = f"(?{prefix})" + pattern
        return cast(RegexPattern, self._re2.compile(pattern))

    @property
    def error(self) -> type[Exception]:
        return self._re2.error  # type: ignore[no-any-return]
