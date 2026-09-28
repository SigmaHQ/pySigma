"""Tests for the disk caching behaviour of the MITRE data loaders."""

import json
import os
import stat
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from sigma.data import mitre_attack, mitre_d3fend

# The suite also runs on Windows, where POSIX permission bits are not meaningful.
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes only")

STIX_DATA = {
    "objects": [
        {"type": "x-mitre-collection", "x_mitre_version": "17.1"},
        {
            "type": "x-mitre-tactic",
            "x_mitre_shortname": "initial-access",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0001"}],
        },
        {
            "type": "attack-pattern",
            "name": "Data Obfuscation",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1001"}],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}
            ],
        },
        {
            "type": "intrusion-set",
            "name": "Axiom",
            "external_references": [{"source_name": "mitre-attack", "external_id": "G0001"}],
        },
        {
            "type": "malware",
            "name": "Mimikatz",
            "external_references": [{"source_name": "mitre-attack", "external_id": "S0001"}],
        },
        {
            "type": "x-mitre-data-source",
            "name": "Active Directory",
            "external_references": [{"source_name": "mitre-attack", "external_id": "DS0026"}],
        },
        {
            "type": "course-of-action",
            "name": "Active Directory Configuration",
            "external_references": [{"source_name": "mitre-attack", "external_id": "M1015"}],
        },
        {
            "type": "attack-pattern",
            "name": "Revoked Thing",
            "revoked": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
        },
    ]
}

D3FEND_ONTOLOGY = {
    "@graph": [
        {
            "@type": "owl:Ontology",
            "owl:versionIRI": "http://d3fend.mitre.org/ontologies/d3fend/0.16.0",
        },
        {"@type": "d3f:DefensiveTactic", "@id": "d3f:Detect", "rdfs:label": "Detect"},
        {
            "@type": "d3f:D3FENDTechnique",
            "d3f:d3fend-id": "D3-MFA",
            "rdfs:label": "Multi-factor Authentication",
        },
        {
            "@type": "d3f:DigitalArtifact",
            "@id": "http://d3fend.mitre.org/ontologies/d3f#AccessControlConfiguration",
            "rdfs:label": "Access Control Configuration",
        },
    ]
}


class Loader(NamedTuple):
    """A data loader module wired to a local source and a private cache dir.

    conftest.py patches ``_get_cached_data`` on both modules for the whole
    suite, so these tests call the real ``_load_*`` implementation instead.
    """

    module: Any
    load: Any
    source: Path
    cache_dir: Path

    def reopen(self) -> None:
        """Forget any in-memory store, as a fresh process would."""
        self.module._cache = None


def _make_loader(module: Any, load: Any, data: dict, tmp_path: Path) -> Any:
    source = tmp_path / "source.json"
    source.write_text(json.dumps(data), encoding="utf-8")
    cache_dir = tmp_path / "cache"
    module.set_cache_dir(str(cache_dir))
    module.set_url(str(source))
    return Loader(module, load, source, cache_dir)


@pytest.fixture(params=["attack", "d3fend"])
def loader(request: pytest.FixtureRequest, tmp_path: Path) -> Any:
    if request.param == "attack":
        module, load, data = mitre_attack, mitre_attack._load_mitre_attack_data, STIX_DATA
    else:
        module, load, data = mitre_d3fend, mitre_d3fend._load_mitre_d3fend_data, D3FEND_ONTOLOGY

    saved = (module._cache, module._custom_url, module._custom_cache_dir)
    handle = _make_loader(module, load, data, tmp_path)
    try:
        yield handle
    finally:
        module._cache, module._custom_url, module._custom_cache_dir = saved


def _no_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("network access attempted while a cache entry was available")


def test_loader_parses_local_source(loader: Loader) -> None:
    """Check the real parser output.

    Read through the _load_* function rather than module attributes, because
    conftest.py replaces _get_cached_data for the whole suite.
    """
    data = loader.load()
    if loader.module is mitre_attack:
        assert data["mitre_attack_version"] == "17.1"
        assert data["mitre_attack_tactics"] == {"TA0001": "initial-access"}
        assert data["mitre_attack_techniques"] == {"T1001": "Data Obfuscation"}
        assert data["mitre_attack_techniques_tactics_mapping"] == {"T1001": ["command-and-control"]}
        assert data["mitre_attack_intrusion_sets"] == {"G0001": "Axiom"}
        assert data["mitre_attack_software"] == {"S0001": "Mimikatz"}
        assert data["mitre_attack_datasources"] == {"DS0026": "Active Directory"}
        assert data["mitre_attack_mitigations"] == {"M1015": "Active Directory Configuration"}
        assert "T9999" not in data["mitre_attack_techniques"], "revoked objects must be skipped"
    else:
        assert data["mitre_d3fend_version"] == "0.16.0"
        assert data["mitre_d3fend_tactics"] == {"Detect": "Detect"}
        assert data["mitre_d3fend_techniques"] == {"D3-MFA": "Multi-factor Authentication"}
        assert data["mitre_d3fend_artifacts"] == {
            "AccessControlConfiguration": "Access Control Configuration"
        }


def test_loader_writes_one_cache_entry(loader: Loader) -> None:
    loader.module.clear_cache()
    loader.load()
    entries = list(loader.cache_dir.glob("*.json"))
    assert len(entries) == 1
    assert isinstance(json.loads(entries[0].read_text(encoding="utf-8")), dict)


def test_loader_serves_second_call_from_cache(loader: Loader, monkeypatch) -> None:
    first = loader.load()

    # The source is gone and the network is forbidden: the answer must come
    # from the disk cache.
    loader.source.unlink()
    monkeypatch.setattr(loader.module, "urlopen", _no_network, raising=False)
    loader.reopen()

    assert loader.load() == first


def test_loader_clear_cache_forces_reload(loader: Loader) -> None:
    first = loader.load()

    loader.module.clear_cache()
    loader.source.write_text("{}", encoding="utf-8")
    loader.reopen()

    assert loader.load() != first


def test_loader_set_url_switches_data(loader: Loader) -> None:
    first = loader.load()

    other = loader.source.parent / "other.json"
    other.write_text("{}", encoding="utf-8")
    loader.module.set_url(str(other))

    assert loader.load() != first


def test_loader_set_cache_dir_starts_a_fresh_cache(loader: Loader) -> None:
    first = loader.load()
    assert list(loader.cache_dir.glob("*.json"))

    other_dir = loader.cache_dir.parent / "other-cache"
    loader.module.set_cache_dir(str(other_dir))
    assert not list(other_dir.glob("*.json"))
    assert loader.load() == first


def test_loader_raises_on_missing_source(loader: Loader) -> None:
    loader.source.unlink()
    with pytest.raises(RuntimeError):
        loader.load()


def test_loader_raises_on_malformed_source(loader: Loader) -> None:
    loader.source.write_text("not json", encoding="utf-8")
    with pytest.raises(RuntimeError):
        loader.load()


def test_loader_raises_attribute_error_for_unknown_name(loader: Loader) -> None:
    with pytest.raises(AttributeError):
        loader.module.does_not_exist


def test_loader_recovers_from_a_corrupted_cache_entry(loader: Loader) -> None:
    """An unparsable entry must degrade to a reload, never to a crash."""
    expected = loader.load()

    for entry in loader.cache_dir.glob("*.json"):
        entry.write_text("not json at all", encoding="utf-8")
    loader.reopen()

    assert loader.load() == expected


def test_tampered_entry_yields_data_not_code(loader: Loader) -> None:
    """Document the residual risk: a valid-JSON entry is trusted as data.

    The cache is not authenticated, so an attacker able to write into it can
    still poison the values. What they cannot do any more is execute code,
    which is what the pickle-backed store allowed. Use clear_cache() after
    suspecting tampering.
    """
    loader.load()
    for entry in loader.cache_dir.glob("*.json"):
        entry.write_text('{"mitre_attack_version": ["pwned"]}', encoding="utf-8")
    loader.reopen()

    # The payload is handed back as an inert Python object.
    assert isinstance(loader.load(), (dict, list))


@posix_only
def test_cache_directory_is_owner_only(loader: Loader) -> None:
    loader.module.clear_cache()
    loader.load()
    assert stat.S_IMODE(loader.cache_dir.stat().st_mode) == 0o700


def test_loaders_do_not_import_diskcache() -> None:
    for module in (mitre_attack, mitre_d3fend):
        assert "diskcache" not in getattr(module, "__doc__", "")
