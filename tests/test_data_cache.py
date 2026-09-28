"""Tests for the JSON file cache used by the data loaders."""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from sigma.data.cache import JsonFileCache

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)

# The suite also runs on Windows, where POSIX permission bits are not meaningful.
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes only")


@pytest.fixture
def cache(tmp_path: Path) -> JsonFileCache:
    return JsonFileCache(tmp_path / "cache")


def test_roundtrip(cache: JsonFileCache) -> None:
    cache.set("key", {"version": "1.0", "fields": ["a", "b"]})
    assert cache.get("key") == {"version": "1.0", "fields": ["a", "b"]}


def test_roundtrip_preserves_unicode(cache: JsonFileCache) -> None:
    value = {"name": "Société Générale – café ☕"}
    cache.set("key", value)
    assert cache.get("key") == value


def test_get_missing_key_is_none(cache: JsonFileCache) -> None:
    assert cache.get("never_written") is None


def test_overwrite_replaces_value(cache: JsonFileCache) -> None:
    cache.set("key", {"version": "1"})
    cache.set("key", {"version": "2"})
    assert cache.get("key") == {"version": "2"}


@pytest.mark.parametrize(
    "key",
    ["../../etc/passwd", "/absolute/path", "https://example.invalid/a/b?c=d", "a" * 4096],
)
def test_key_cannot_escape_cache_directory(cache: JsonFileCache, key: str) -> None:
    cache.set(key, {"version": "1"})
    assert cache.get(key) == {"version": "1"}
    for path in cache.directory.rglob("*"):
        if path.is_file():
            assert cache.directory.resolve() in path.resolve().parents


def test_distinct_keys_do_not_collide(cache: JsonFileCache) -> None:
    cache.set("a", {"version": "1"})
    cache.set("b", {"version": "2"})
    assert cache.get("a") == {"version": "1"}
    assert cache.get("b") == {"version": "2"}


def test_entry_is_json_on_disk(cache: JsonFileCache) -> None:
    """No pickle: the entry must be readable with a plain JSON parser."""
    cache.set("key", {"version": "1"})
    path = cache._path_for(cache.directory, "key")
    assert json.loads(path.read_text(encoding="utf-8")) == {"version": "1"}


def test_corrupted_entry_is_a_miss_and_is_discarded(cache: JsonFileCache) -> None:
    cache.set("key", {"version": "1"})
    path = cache._path_for(cache.directory, "key")
    path.write_text("{ not json", encoding="utf-8")

    assert cache.get("key") is None
    assert not path.exists()


def test_truncated_entry_is_a_miss(cache: JsonFileCache) -> None:
    cache.set("key", {"version": "1"})
    cache._path_for(cache.directory, "key").write_bytes(b"")

    assert cache.get("key") is None


def test_invalid_utf8_entry_is_a_miss(cache: JsonFileCache) -> None:
    cache.set("key", {"version": "1"})
    cache._path_for(cache.directory, "key").write_bytes(b"\xff\xfe\x00")

    assert cache.get("key") is None


def test_discard_removes_entry(cache: JsonFileCache) -> None:
    cache.set("key", {"version": "1"})
    cache.discard("key")
    assert cache.get("key") is None
    cache.discard("key")  # must not raise


def test_clear_removes_entries(cache: JsonFileCache) -> None:
    cache.set("a", {"version": "1"})
    cache.set("b", {"version": "2"})
    cache.clear()
    assert cache.get("a") is None
    assert cache.get("b") is None


def test_clear_removes_legacy_store_database(cache: JsonFileCache) -> None:
    legacy = cache.directory / "cache.db"
    legacy.write_bytes(b"SQLite format 3\x00")
    cache.set("key", {"version": "1"})

    cache.clear()

    assert not legacy.exists()
    assert not list(cache.directory.glob("*.json"))


def test_clear_is_safe_on_empty_cache(cache: JsonFileCache) -> None:
    cache.clear()
    assert not list(cache.directory.glob("*.json"))


def test_set_leaves_no_temporary_file(cache: JsonFileCache) -> None:
    cache.set("key", {"version": "1"})
    assert [p.name for p in cache.directory.iterdir() if p.name.startswith(".tmp-")] == []


def test_set_rejects_non_serializable_value(cache: JsonFileCache) -> None:
    with pytest.raises(TypeError):
        cache.set("key", {"bad": object()})
    assert [p.name for p in cache.directory.iterdir() if p.name.startswith(".tmp-")] == []


def test_set_cleans_up_when_the_rename_fails(
    cache: JsonFileCache, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise OSError("rename failed")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="rename failed"):
        cache.set("key", {"version": "1"})

    assert [p.name for p in cache.directory.iterdir() if p.name.startswith(".tmp-")] == []
    assert cache.get("key") is None


@posix_only
def test_directory_is_owner_only(tmp_path: Path) -> None:
    directory = tmp_path / "cache"
    JsonFileCache(directory)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


@posix_only
def test_entry_is_owner_only(cache: JsonFileCache) -> None:
    cache.set("key", {"version": "1"})
    mode = stat.S_IMODE(cache._path_for(cache.directory, "key").stat().st_mode)
    assert mode == 0o600


@posix_only
def test_existing_loose_directory_is_tightened(tmp_path: Path) -> None:
    """mkdir(exist_ok=True) does not touch the mode of an existing directory."""
    directory = tmp_path / "cache"
    directory.mkdir(mode=0o755)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o755

    JsonFileCache(directory)

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


def test_accepts_a_string_directory(tmp_path: Path) -> None:
    store = JsonFileCache(str(tmp_path / "cache"))
    store.set("key", {"version": "1"})
    assert store.get("key") == {"version": "1"}


def test_expands_a_leading_tilde(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A literal '~' directory must not appear in the working directory."""
    home = tmp_path / "home"
    home.mkdir()
    # expanduser() reads HOME on POSIX but USERPROFILE on Windows.
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("HOMEPATH", raising=False)
    monkeypatch.delenv("HOMEDRIVE", raising=False)

    store = JsonFileCache("~/.cache/pysigma/example")

    assert store.directory == home / ".cache" / "pysigma" / "example"
    assert store.directory.is_dir()


def test_entries_are_reused_across_instances(tmp_path: Path) -> None:
    directory = tmp_path / "cache"
    JsonFileCache(directory).set("key", {"version": "1"})
    assert JsonFileCache(directory).get("key") == {"version": "1"}


def test_close_is_a_noop(cache: JsonFileCache) -> None:
    cache.set("key", {"version": "1"})
    cache.close()
    assert cache.get("key") == {"version": "1"}


def test_data_survives_a_new_process(tmp_path: Path) -> None:
    """The point of a disk cache: a fresh interpreter must still read it."""
    directory = tmp_path / "cache"
    JsonFileCache(directory).set("key", {"version": "1"})

    code = (
        "import json,sys;"
        "sys.path.insert(0, %r);"
        "from sigma.data.cache import JsonFileCache;"
        "print(json.dumps(JsonFileCache(%r).get('key')))" % (_REPO_ROOT, str(directory))
    )
    # noqa below is safe: sys.executable is this interpreter and the code
    # string is assembled here from tmp_path, never from external input.
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert json.loads(out.stdout) == {"version": "1"}


def test_concurrent_writers_leave_a_valid_document(tmp_path: Path) -> None:
    """Last writer wins, but no reader ever observes a partial document."""
    directory = tmp_path / "cache"
    JsonFileCache(directory)

    code = (
        "import sys;"
        "sys.path.insert(0, %r);"
        "from sigma.data.cache import JsonFileCache;"
        "[JsonFileCache(%r).set('key', {'version': str(i)}) for i in range(200)]"
        % (_REPO_ROOT, str(directory))
    )
    subprocess.run([sys.executable, "-c", code], check=True)  # noqa: S603

    assert JsonFileCache(directory).get("key") in ({"version": str(i)} for i in range(200))


def test_module_source_is_pickle_free() -> None:
    """Regression guard for CVE-2025-69872."""
    source = (Path(__file__).resolve().parent.parent / "sigma" / "data" / "cache.py").read_text(
        encoding="utf-8"
    )
    code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
    assert "import pickle" not in code
    assert "import marshal" not in code
    assert "import diskcache" not in code


def test_pyproject_no_longer_declares_diskcache() -> None:
    content = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert "diskcache" not in content
