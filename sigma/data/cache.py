"""
JSON file cache for pySigma data loaders.

Provides :class:`JsonFileCache`, a small on-disk key-value store used by the
data loader modules in this package. It replaces a pickle-backed store which
turned a writable cache directory into a code execution vector
(CVE-2025-69872, GHSA-w8v5-vhqr-4h9v).

Values are serialized as JSON only, so a tampered cache entry can at worst
produce a parse failure, which is treated as a cache miss. Each entry is a
separate file written through a temporary file and :func:`os.replace`, so a
concurrent reader never observes a partially written document.
"""

import contextlib
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional

# Leftovers from the former diskcache store, removed by clear() so upgrading
# does not strand a stale database nobody will ever open again.
_LEGACY_CACHE_FILES = ("cache.db", "cache.db-wal", "cache.db-shm", "cache.db-journal")


class JsonFileCache:
    """
    On-disk cache holding one JSON document per key.

    Example:
        >>> from sigma.data.cache import JsonFileCache
        >>> cache = JsonFileCache("~/.cache/pysigma/example")
        >>> cache.directory.is_absolute()
        True
        >>> cache.set("key", {"version": "1"})
        >>> cache.get("key")
        {'version': '1'}

    Note:
        Concurrent writers of the same key simply race and the last one wins.
        This is harmless for the intended use, where every writer of a key
        stores the same document.
    """

    def __init__(self, directory: Path | str) -> None:
        """
        Create the cache and its directory if needed.

        Args:
            directory: Directory holding the cache entries. A leading ``~`` is
                expanded, and the directory is created with mode 0o700 with its
                permissions tightened even if it already exists, because
                ``mkdir(exist_ok=True)`` leaves the mode of an existing
                directory untouched.
        """
        self.directory = Path(directory).expanduser()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            self.directory.chmod(0o700)

    @staticmethod
    def _path_for(directory: Path, key: str) -> Path:
        """
        Map a key to its file, so that any key is a valid and contained path.

        Args:
            directory: Cache directory.
            key: Cache key.

        Returns:
            Path of the file backing the key.
        """
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        return directory / f"{digest}.json"

    def get(self, key: str) -> Optional[Any]:
        """
        Return the value stored for a key, or None if there is none.

        A corrupted, truncated or unreadable entry is reported as a miss and
        discarded, so the caller re-fetches it instead of failing.

        Args:
            key: Cache key.

        Returns:
            The stored value, or None on a miss.
        """
        path = self._path_for(self.directory, key)
        try:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return None
        except ValueError:
            # JSONDecodeError and UnicodeDecodeError both derive from
            # ValueError.
            self.discard(key)
            return None
        except OSError:
            return None

    def set(self, key: str, value: Any) -> None:
        """
        Store a JSON-serializable value under a key.

        The value is written to a temporary file in the cache directory and
        then moved into place, so a reader never sees a partial document and an
        interrupted write leaves no usable garbage behind.

        Args:
            key: Cache key.
            value: JSON-serializable value to store.

        Raises:
            TypeError: If the value is not JSON-serializable.
        """
        payload = json.dumps(value, ensure_ascii=False)
        fd, tmp_name = tempfile.mkstemp(dir=self.directory, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(payload)
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self._path_for(self.directory, key))
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise

    def discard(self, key: str) -> None:
        """
        Remove the entry for a key if it exists.

        Args:
            key: Cache key.
        """
        with contextlib.suppress(OSError):
            self._path_for(self.directory, key).unlink()

    def clear(self) -> None:
        """Remove every entry, plus any file left by the former store."""
        # pathlib globs dotfiles, so this also sweeps aborted temporary files.
        for path in self.directory.glob("*.json"):
            with contextlib.suppress(OSError):
                path.unlink()
        for name in _LEGACY_CACHE_FILES:
            with contextlib.suppress(OSError):
                (self.directory / name).unlink()

    def close(self) -> None:
        """Release the cache. Kept for API compatibility, nothing is held open."""
