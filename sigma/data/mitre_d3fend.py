"""
MITRE D3FEND data loader for pySigma.

This module provides on-demand access to MITRE D3FEND data by downloading it from
the official D3FEND GitHub repository. Data is cached in memory to avoid repeated downloads.
"""

import json
from typing import Any, Optional, Dict
from urllib.error import URLError
from urllib.request import urlopen

# URLs for MITRE D3FEND data - using the GitHub repository
MITRE_D3FEND_ONTOLOGY_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"

# Fallback URL if the main one is not available
MITRE_D3FEND_ONTOLOGY_FALLBACK_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"

# In-memory cache
_cache: Optional[Dict[str, Any]] = None
_custom_url: Optional[str] = None


def _load_mitre_d3fend_data() -> Dict[str, Any]:
    """
    Load MITRE D3FEND data from the D3FEND ontology or a custom URL/file.

    Returns a dictionary with the following keys:
    - mitre_d3fend_version: D3FEND version
    - mitre_d3fend_tactics: dict[str, str] mapping tactic names to names
    - mitre_d3fend_techniques: dict[str, str] mapping technique IDs to names
    - mitre_d3fend_artifacts: dict[str, str] mapping artifact IDs to names
    """
    ontology_data = None
    last_error = None

    # If custom URL is set, use it
    if _custom_url is not None:
        url = _custom_url
        try:
            # Check if it's a file path (doesn't start with http:// or https://)
            if not url.startswith(("http://", "https://")):
                with open(url, "r", encoding="utf-8") as f:
                    ontology_data = json.load(f)
            else:
                with urlopen(url, timeout=30) as response:
                    ontology_data = json.load(response)
        except (URLError, json.JSONDecodeError, OSError, IOError) as e:
            raise RuntimeError(f"Failed to load MITRE D3FEND data from custom URL: {e}") from e
    else:
        # Try primary URL first, then fallback
        for url in [MITRE_D3FEND_ONTOLOGY_URL, MITRE_D3FEND_ONTOLOGY_FALLBACK_URL]:
            try:
                with urlopen(url, timeout=30) as response:
                    ontology_data = json.load(response)
                    break
            except (URLError, json.JSONDecodeError) as e:
                last_error = e
                continue

    if ontology_data is None:
        raise RuntimeError(f"Failed to load MITRE D3FEND data: {last_error}") from last_error

    # Extract version from the ontology metadata
    version = "unknown"
    for item in ontology_data.get("@graph", []):
        if item.get("@type") == "owl:Ontology":
            version_iri = item.get("owl:versionIRI", "")
            if version_iri:
                # Extract version from IRI like "http://d3fend.mitre.org/ontologies/d3fend/0.16.0"
                # version_iri can be a string or a dict with @id
                if isinstance(version_iri, dict):
                    version_iri = version_iri.get("@id", "")
                if isinstance(version_iri, str):
                    parts = version_iri.rstrip("/").split("/")
                    if parts:
                        version = parts[-1]
            break

    tactics = {}
    techniques = {}
    artifacts = {}

    # Parse the D3FEND ontology graph
    # The ontology is a JSON-LD graph where each item represents an entity
    # Tactics: have "@type" containing "d3f:DefensiveTactic" and "rdfs:label" (e.g., "Detect", "Isolate")
    # Techniques: have "d3f:d3fend-id" field with IDs like "D3-AA", "D3-MFA" and "rdfs:label" for names
    # Artifacts: have "@type" containing "d3f:DigitalArtifact" and "rdfs:label"
    for item in ontology_data.get("@graph", []):
        item_type = item.get("@type")
        item_id = item.get("@id", "")
        label = item.get("rdfs:label", "")
        d3fend_id = item.get("d3f:d3fend-id", "")

        # Convert item_type to string/list for checking
        if isinstance(item_type, list):
            item_type_list = [str(t) for t in item_type]
        else:
            item_type_list = [str(item_type)] if item_type else []

        # Extract tactics (defensive tactics) - has d3f:DefensiveTactic in @type
        if "d3f:DefensiveTactic" in item_type_list:
            if label:
                # Handle label being a list or string
                tactic_label = label[0] if isinstance(label, list) else label
                if tactic_label:
                    tactics[tactic_label] = tactic_label

        # Extract techniques - items with d3f:d3fend-id field (like D3-AA, D3-DO, etc.)
        if d3fend_id and d3fend_id.startswith("D3-"):
            if label:
                # Handle label being a list or string
                tech_label = label[0] if isinstance(label, list) else label
                if tech_label:
                    techniques[d3fend_id] = tech_label

        # Extract artifacts - not currently used but kept for future compatibility
        # Digital artifacts don't have d3fend-id but have d3f:DigitalArtifact type
        if not d3fend_id and "d3f:DigitalArtifact" in " ".join(item_type_list):
            if label and "#" in item_id:
                artifact_id = item_id.split("#")[-1]
                artifact_label = label[0] if isinstance(label, list) else label
                if artifact_label:
                    artifacts[artifact_id] = artifact_label

    # Default tactics if none found (standard D3FEND tactics)
    if not tactics:
        tactics = {
            "Deceive": "Deceive",
            "Isolate": "Isolate",
            "Detect": "Detect",
            "Restore": "Restore",
            "Evict": "Evict",
            "Harden": "Harden",
            "Model": "Model",
        }

    return {
        "mitre_d3fend_version": version,
        "mitre_d3fend_tactics": tactics,
        "mitre_d3fend_techniques": techniques,
        "mitre_d3fend_artifacts": artifacts,
    }


def _get_cached_data() -> Dict[str, Any]:
    """Get cached MITRE D3FEND data, loading it if necessary."""
    global _cache
    if _cache is None:
        _cache = _load_mitre_d3fend_data()
    return _cache


def __getattr__(name: str) -> Any:
    """
    Lazy-load MITRE D3FEND data on attribute access.

    This allows the module to be used like the old static data module,
    but with on-demand loading and caching.
    """
    if name.startswith("mitre_d3fend_"):
        data = _get_cached_data()
        if name in data:
            return data[name]
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


def clear_cache() -> None:
    """Clear the in-memory cache. Mainly useful for testing."""
    global _cache
    _cache = None


def set_url(url: str) -> None:
    """
    Set a custom URL or file path for loading MITRE D3FEND data.

    This function allows you to specify an alternative source for MITRE D3FEND data,
    which can be either:
    - An HTTP/HTTPS URL pointing to a D3FEND ontology JSON file
    - A local file path to a downloaded D3FEND ontology JSON file

    This is particularly useful in environments with restricted internet access,
    where you can download the data separately and load it from a local file.

    Args:
        url: URL or file path to the MITRE D3FEND data source

    Example:
        >>> from sigma.data import mitre_d3fend_data
        >>> # Use a local file
        >>> mitre_d3fend_data.set_url("/path/to/d3fend.json")
        >>> # Or use a custom URL
        >>> mitre_d3fend_data.set_url("https://example.com/custom-d3fend.json")

    Note:
        This will clear any cached data, so the next access will load from the new source.
    """
    global _custom_url
    _custom_url = url
    clear_cache()
