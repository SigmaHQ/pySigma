"""
MITRE ATT&CK data loader for pySigma.

This module provides on-demand access to MITRE ATT&CK data by downloading it from
the official MITRE ATT&CK GitHub repository. Data is cached on disk using diskcache
to avoid repeated downloads across sessions.
"""

import json
import os
from pathlib import Path
from typing import Any, Optional, Dict, List, cast
from urllib.error import URLError
from urllib.request import urlopen

import diskcache

# URLs for MITRE ATT&CK data
MITRE_ATTACK_ENTERPRISE_URL = (
    "https://github.com/mitre-attack/attack-stix-data/raw/refs/heads/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Cache directory (in user's cache directory)
_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "pysigma" / "mitre_attack"

# Disk cache instance
_cache: Optional[diskcache.Cache] = None
_custom_url: Optional[str] = None
_custom_cache_dir: Optional[Path] = None


def _get_cache() -> diskcache.Cache:
    """Get or initialize the disk cache."""
    global _cache
    if _cache is None:
        cache_dir = _custom_cache_dir if _custom_cache_dir is not None else _DEFAULT_CACHE_DIR
        cache_dir.mkdir(parents=True, exist_ok=True)
        _cache = diskcache.Cache(str(cache_dir))
    return _cache


def _get_external_id(obj: Dict[str, Any]) -> Optional[str]:
    """Extract the external ID from a STIX object's external references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            external_id = ref.get("external_id")
            if external_id is not None:
                return str(external_id)
    return None


def _load_mitre_attack_data() -> Dict[str, Any]:
    """
    Load MITRE ATT&CK data from GitHub or a custom URL/file.

    Returns a dictionary with the following keys:
    - mitre_attack_version: MITRE ATT&CK version
    - mitre_attack_tactics: dict[str, str] mapping tactic IDs to names
    - mitre_attack_techniques: dict[str, str] mapping technique IDs to names
    - mitre_attack_techniques_tactics_mapping: dict[str, list[str]] mapping techniques to tactics
    - mitre_attack_intrusion_sets: dict[str, str] mapping intrusion set IDs to names
    - mitre_attack_software: dict[str, str] mapping software IDs to names
    - mitre_attack_datasources: dict[str, str] mapping data source IDs to names
    - mitre_attack_mitigations: dict[str, str] mapping mitigation IDs to names
    """
    cache = _get_cache()
    cache_key = f"mitre_attack_data_{_custom_url or 'default'}"

    # Try to get from cache first
    cached_data = cache.get(cache_key)
    if cached_data is not None:
        return cast(dict[str, Any], cached_data)

    url = _custom_url if _custom_url is not None else MITRE_ATTACK_ENTERPRISE_URL

    try:
        # Check if it's a file path (doesn't start with http:// or https://)
        if not url.startswith(("http://", "https://")):
            with open(url, "r", encoding="utf-8") as f:
                stix_data = json.load(f)
        else:
            with urlopen(url, timeout=30) as response:
                stix_data = json.load(response)
    except (URLError, json.JSONDecodeError, OSError, IOError) as e:
        raise RuntimeError(f"Failed to load MITRE ATT&CK data: {e}") from e

    version = None
    tactics = {}
    techniques = {}
    techniques_tactics_mapping = {}
    intrusion_sets = {}
    software = {}
    datasources = {}
    mitigations = {}

    for obj in stix_data.get("objects", []):
        # Skip revoked or deprecated objects
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        obj_type = obj.get("type")

        if obj_type == "x-mitre-collection":
            version = obj.get("x_mitre_version")
        elif obj_type == "x-mitre-tactic":
            tactic_id = _get_external_id(obj)
            if tactic_id:
                tactics[tactic_id] = obj["x_mitre_shortname"]
        elif obj_type == "attack-pattern":
            technique_id = _get_external_id(obj)
            if technique_id:
                techniques[technique_id] = obj["name"]
                techniques_tactics_mapping[technique_id] = [
                    phase["phase_name"]
                    for phase in obj.get("kill_chain_phases", [])
                    if phase.get("kill_chain_name") == "mitre-attack"
                ]
        elif obj_type == "intrusion-set":
            intrusion_set_id = _get_external_id(obj)
            if intrusion_set_id:
                intrusion_sets[intrusion_set_id] = obj["name"]
        elif obj_type in ("malware", "tool"):
            software_id = _get_external_id(obj)
            if software_id:
                software[software_id] = obj["name"]
        elif obj_type == "x-mitre-data-source":
            datasource_id = _get_external_id(obj)
            if datasource_id:
                datasources[datasource_id] = obj["name"]
        elif obj_type == "course-of-action":
            mitigation_id = _get_external_id(obj)
            if mitigation_id:
                mitigations[mitigation_id] = obj["name"]

    result = {
        "mitre_attack_version": version or "unknown",
        "mitre_attack_tactics": tactics,
        "mitre_attack_techniques": techniques,
        "mitre_attack_techniques_tactics_mapping": techniques_tactics_mapping,
        "mitre_attack_intrusion_sets": intrusion_sets,
        "mitre_attack_software": software,
        "mitre_attack_datasources": datasources,
        "mitre_attack_mitigations": mitigations,
    }

    # Store in cache
    cache.set(cache_key, result)

    return result


def _get_cached_data() -> Dict[str, Any]:
    """Get cached MITRE ATT&CK data, loading it if necessary."""
    return _load_mitre_attack_data()


def __getattr__(name: str) -> Any:
    """
    Lazy-load MITRE ATT&CK data on attribute access.

    This allows the module to be used like the old static data module,
    but with on-demand loading and caching.
    """
    if name.startswith("mitre_attack_"):
        data = _get_cached_data()
        if name in data:
            return data[name]
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


def clear_cache() -> None:
    """Clear the disk cache. Useful for testing or forcing a refresh."""
    cache = _get_cache()
    cache.clear()


def set_url(url: str) -> None:
    """
    Set a custom URL or file path for loading MITRE ATT&CK data.

    This function allows you to specify an alternative source for MITRE ATT&CK data,
    which can be either:
    - An HTTP/HTTPS URL pointing to a MITRE ATT&CK STIX JSON file
    - A local file path to a downloaded MITRE ATT&CK STIX JSON file

    This is particularly useful in environments with restricted internet access,
    where you can download the data separately and load it from a local file.

    Args:
        url: URL or file path to the MITRE ATT&CK data source

    Example:
        >>> from sigma.data import mitre_attack
        >>> # Use a local file
        >>> mitre_attack.set_url("/path/to/enterprise-attack.json")
        >>> # Or use a custom URL
        >>> mitre_attack.set_url("https://example.com/custom-attack-data.json")

    Note:
        This will clear the cached data, so the next access will load from the new source.
    """
    global _custom_url
    _custom_url = url
    clear_cache()


def set_cache_dir(cache_dir: str) -> None:
    """
    Set a custom cache directory for storing MITRE ATT&CK data.

    Args:
        cache_dir: Path to the cache directory

    Example:
        >>> from sigma.data import mitre_attack
        >>> mitre_attack.set_cache_dir("/custom/cache/path")

    Note:
        This will close the current cache and create a new one in the specified directory.
    """
    global _cache, _custom_cache_dir
    _custom_cache_dir = Path(cache_dir)
    if _cache is not None:
        _cache.close()
        _cache = None
