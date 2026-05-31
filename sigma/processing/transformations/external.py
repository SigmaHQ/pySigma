"""External data source placeholder transformations.

These transformations replace Sigma placeholders with values fetched from external sources
such as local files, HTTP endpoints, or command output.

Security note: Because these transformations access external sources, they are **disabled by
default** and must be explicitly enabled by passing ``allow_external_sources=True`` when
loading a :class:`~sigma.processing.pipeline.ProcessingPipeline` or by setting the
environment variable ``PYSIGMA_ALLOW_EXTERNAL_SOURCES=1``.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, Iterable, Union

import yaml

from sigma.exceptions import SigmaConfigurationError, SigmaSecurityError, SigmaValueError
from sigma.processing.transformations.placeholder import BasePlaceholderTransformation
from sigma.types import Placeholder, SigmaString

PYSIGMA_ALLOW_EXTERNAL_SOURCES_ENV = "PYSIGMA_ALLOW_EXTERNAL_SOURCES"


# ---------------------------------------------------------------------------
# Simple jq-like expression evaluator
# ---------------------------------------------------------------------------


def _flatten(value: Any) -> list[Any]:
    """Recursively flatten nested lists into a flat list."""
    if isinstance(value, list):
        result: list[Any] = []
        for item in value:
            result.extend(_flatten(item))
        return result
    return [value]


def _eval_jq_path(data: Any, path: str) -> Any:
    """Evaluate one step (or more) of a jq path expression on *data*.

    The leading ``.`` must have already been stripped before calling this
    function.  An empty *path* means "return current value".
    """
    if not path:
        return data

    # .[]: iterate over all elements
    if path.startswith("[]"):
        remaining = path[2:]
        if remaining.startswith("."):
            remaining = remaining[1:]
        if not isinstance(data, list):
            raise SigmaValueError("jq '[]' applied to non-array value")
        return [_eval_jq_path(item, remaining) for item in data]

    # .[n]: index into an array
    if path.startswith("["):
        bracket_end = path.find("]")
        if bracket_end == -1:
            raise SigmaConfigurationError(f"jq: unmatched '[' in expression")
        idx_str = path[1:bracket_end]
        try:
            idx = int(idx_str)
        except ValueError:
            raise SigmaConfigurationError(f"jq: invalid array index '{idx_str}'")
        remaining = path[bracket_end + 1 :]
        if remaining.startswith("."):
            remaining = remaining[1:]
        if not isinstance(data, (list, tuple)):
            raise SigmaValueError(f"jq: [{idx}] applied to non-array value")
        return _eval_jq_path(data[idx], remaining)

    # .key, .key.nested, .key[], .key[n]
    dot_pos = path.find(".")
    bracket_pos = path.find("[")

    if dot_pos == -1 and bracket_pos == -1:
        key, remaining = path, ""
    elif dot_pos == -1:
        key, remaining = path[:bracket_pos], path[bracket_pos:]
    elif bracket_pos == -1:
        key, remaining = path[:dot_pos], path[dot_pos + 1 :]
    else:
        split_pos = min(dot_pos, bracket_pos)
        if split_pos == dot_pos:
            key, remaining = path[:dot_pos], path[dot_pos + 1 :]
        else:
            key, remaining = path[:bracket_pos], path[bracket_pos:]

    if not key:
        return _eval_jq_path(data, remaining)

    if not isinstance(data, dict):
        raise SigmaValueError(f"jq: key access on non-object (tried key '{key}')")
    if key not in data:
        raise SigmaValueError(f"jq: key '{key}' not found in object")
    return _eval_jq_path(data[key], remaining)


def _apply_jq_expression(data: Any, expression: str) -> list[str]:
    """Apply a jq-like expression to *data* and return the extracted string values.

    Supported syntax subset:

    * ``.`` — return the whole document
    * ``.key`` — dict key access
    * ``.key.nested`` — nested dict access
    * ``.[n]`` — array index (0-based integer)
    * ``.key[]`` — iterate over all array elements under a key
    * ``.[]`` — iterate over all array elements at the current level

    The expression must start with ``"."``.  When the result is a list its
    elements are returned individually; when it is a scalar it is returned as
    a single-element list.  ``None`` values are dropped.
    """
    expression = expression.strip()
    if not expression.startswith("."):
        raise SigmaConfigurationError(
            f"jq expression must start with '.', got: {expression!r}"
        )
    path = expression[1:]  # strip leading dot
    result = _eval_jq_path(data, path)
    flat = _flatten(result)
    return [str(v) for v in flat if v is not None]


# ---------------------------------------------------------------------------
# Mixin
# ---------------------------------------------------------------------------


@dataclass
class ExternalValueSourceMixin:
    """Mixin for placeholder transformations that fetch replacement values from
    an external source (file, HTTP, command).

    **Supported formats** (controlled by the *format* parameter):

    * ``"plaintext"`` — one value per line; an optional *filter* regex must
      match for a line to be included.
    * ``"csv"`` — CSV data; *csv_column* selects the column (column header
      name **or** 0-based integer index); an optional *filter* regex is
      applied to each extracted cell value.
    * ``"json"`` — JSON data; *jq_expression* selects the value(s).
    * ``"yaml"`` — YAML data; *jq_expression* selects the value(s).

    **Security**: external-source transformations are disabled by default.
    Enable them by passing ``allow_external_sources=True`` when loading the
    pipeline or by setting the environment variable
    ``PYSIGMA_ALLOW_EXTERNAL_SOURCES=1``.
    """

    format: str = "plaintext"
    filter: str | None = None
    csv_column: str | int | None = None
    jq_expression: str | None = None
    allow_external_sources: bool = False

    # Internal cache — not part of __init__ / equality / repr
    _values_cache: list[str] | None = field(
        init=False, default=None, repr=False, compare=False
    )

    # ------------------------------------------------------------------
    # Security helpers
    # ------------------------------------------------------------------

    def _external_sources_allowed(self) -> bool:
        """Return *True* if external data sources are permitted."""
        if self.allow_external_sources:
            return True
        return os.environ.get(PYSIGMA_ALLOW_EXTERNAL_SOURCES_ENV, "").lower() in (
            "1",
            "true",
        )

    # ------------------------------------------------------------------
    # Data fetching (to be implemented by concrete classes)
    # ------------------------------------------------------------------

    def _fetch_data(self) -> str:
        """Fetch raw text data from the external source.

        Subclasses **must** override this method.
        """
        raise NotImplementedError(
            f"{type(self).__name__} must implement _fetch_data()"
        )

    # ------------------------------------------------------------------
    # Value retrieval with caching
    # ------------------------------------------------------------------

    def _get_values(self) -> list[str]:
        """Return the list of replacement values, fetching and caching them if
        necessary.

        Raises :class:`~sigma.exceptions.SigmaSecurityError` when external
        data sources are not enabled.
        """
        if self._values_cache is not None:
            return self._values_cache

        if not self._external_sources_allowed():
            raise SigmaSecurityError(
                "External data source transformations are disabled by default for security "
                "reasons. Enable them with allow_external_sources=True when loading the "
                "pipeline or by setting the environment variable "
                f"{PYSIGMA_ALLOW_EXTERNAL_SOURCES_ENV}=1."
            )

        data = self._fetch_data()
        self._values_cache = self._parse_data(data)
        return self._values_cache

    # ------------------------------------------------------------------
    # Format parsers
    # ------------------------------------------------------------------

    def _parse_data(self, data: str) -> list[str]:
        """Dispatch to the appropriate format parser."""
        if self.format == "plaintext":
            return self._parse_plaintext(data)
        elif self.format == "csv":
            return self._parse_csv(data)
        elif self.format == "json":
            return self._parse_json(data)
        elif self.format == "yaml":
            return self._parse_yaml_data(data)
        else:
            raise SigmaConfigurationError(
                f"Unknown external source format '{self.format}'. "
                "Supported formats: plaintext, csv, json, yaml."
            )

    def _parse_plaintext(self, data: str) -> list[str]:
        values = [line for line in (line.strip() for line in data.splitlines()) if line]
        if self.filter:
            pattern = re.compile(self.filter)
            values = [v for v in values if pattern.search(v)]
        return values

    def _parse_csv(self, data: str) -> list[str]:
        if self.csv_column is None:
            raise SigmaConfigurationError(
                "'csv_column' must be specified when format is 'csv'"
            )

        values: list[str] = []

        if isinstance(self.csv_column, str):
            reader_dict = csv.DictReader(io.StringIO(data))
            for row in reader_dict:
                if self.csv_column not in row:
                    raise SigmaConfigurationError(
                        f"CSV column '{self.csv_column}' not found in data"
                    )
                val = row[self.csv_column]
                if val is not None:
                    values.append(val)
        else:
            # Integer index
            col_idx = self.csv_column
            reader_list = csv.reader(io.StringIO(data))
            for row in reader_list:
                if col_idx < len(row):
                    values.append(row[col_idx])

        if self.filter:
            pattern = re.compile(self.filter)
            values = [v for v in values if pattern.search(v)]
        return values

    def _parse_json(self, data: str) -> list[str]:
        if self.jq_expression is None:
            raise SigmaConfigurationError(
                "'jq_expression' must be specified when format is 'json'"
            )
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as e:
            raise SigmaValueError(f"Failed to parse JSON data: {e}") from e
        return _apply_jq_expression(parsed, self.jq_expression)

    def _parse_yaml_data(self, data: str) -> list[str]:
        if self.jq_expression is None:
            raise SigmaConfigurationError(
                "'jq_expression' must be specified when format is 'yaml'"
            )
        try:
            parsed = yaml.safe_load(data)
        except yaml.YAMLError as e:
            raise SigmaValueError(f"Failed to parse YAML data: {e}") from e
        return _apply_jq_expression(parsed, self.jq_expression)

    # ------------------------------------------------------------------
    # Placeholder replacement (used by BasePlaceholderTransformation)
    # ------------------------------------------------------------------

    def placeholder_replacements(self, p: Placeholder) -> Iterable[SigmaString]:
        return [SigmaString(v) for v in self._get_values()]


# ---------------------------------------------------------------------------
# Concrete transformations
# ---------------------------------------------------------------------------


@dataclass
class FilePlaceholderTransformation(ExternalValueSourceMixin, BasePlaceholderTransformation):
    """Replace placeholders with values read from a local file.

    Parameters:
    * **path** — path to the file (required)
    * **format** — data format: ``"plaintext"`` (default), ``"csv"``, ``"json"``, ``"yaml"``
    * **filter** — optional regex that each value must match (plaintext/csv)
    * **csv_column** — column name (str) or 0-based index (int) for CSV format
    * **jq_expression** — path expression for JSON/YAML formats (e.g. ``.items[]``)
    * **include** / **exclude** — placeholder name lists (from
      :class:`~sigma.processing.transformations.placeholder.BasePlaceholderTransformation`)
    """

    path: str = ""

    def __post_init__(self) -> None:
        # Validate required field before calling parent __post_init__
        if not self.path:
            raise SigmaConfigurationError(
                "FilePlaceholderTransformation requires a non-empty 'path'"
            )
        # BasePlaceholderTransformation.__post_init__ calls check_exclusivity and super
        BasePlaceholderTransformation.__post_init__(self)

    def _fetch_data(self) -> str:
        try:
            with open(self.path, encoding="utf-8") as fh:
                return fh.read()
        except OSError as e:
            raise SigmaValueError(
                f"FilePlaceholderTransformation: failed to read '{self.path}': {e}"
            ) from e


@dataclass
class HTTPPlaceholderTransformation(ExternalValueSourceMixin, BasePlaceholderTransformation):
    """Replace placeholders with values fetched from an HTTP(S) endpoint.

    Parameters:
    * **url** — URL to fetch (required)
    * **timeout** — request timeout in seconds (default: 10)
    * **format** — data format: ``"plaintext"`` (default), ``"csv"``, ``"json"``, ``"yaml"``
    * **filter** — optional regex that each value must match (plaintext/csv)
    * **csv_column** — column name (str) or 0-based index (int) for CSV format
    * **jq_expression** — path expression for JSON/YAML formats
    * **include** / **exclude** — placeholder name lists
    """

    url: str = ""
    timeout: int = 10

    def __post_init__(self) -> None:
        if not self.url:
            raise SigmaConfigurationError(
                "HTTPPlaceholderTransformation requires a non-empty 'url'"
            )
        BasePlaceholderTransformation.__post_init__(self)

    def _fetch_data(self) -> str:
        import requests  # imported here so it is not a hard requirement for tests

        try:
            response = requests.get(self.url, timeout=self.timeout)
            response.raise_for_status()
            return response.text
        except Exception as e:
            raise SigmaValueError(
                f"HTTPPlaceholderTransformation: failed to fetch '{self.url}': {e}"
            ) from e


@dataclass
class CommandPlaceholderTransformation(ExternalValueSourceMixin, BasePlaceholderTransformation):
    """Replace placeholders with the stdout output of a shell command.

    Parameters:
    * **cmd** — command string (passed to ``/bin/sh -c``) or a list of
      arguments (required)
    * **timeout** — maximum execution time in seconds (default: 30)
    * **format** — data format: ``"plaintext"`` (default), ``"csv"``, ``"json"``, ``"yaml"``
    * **filter** — optional regex that each value must match (plaintext/csv)
    * **csv_column** — column name (str) or 0-based index (int) for CSV format
    * **jq_expression** — path expression for JSON/YAML formats
    * **include** / **exclude** — placeholder name lists
    """

    cmd: str | list[str] = ""
    timeout: int = 30

    def __post_init__(self) -> None:
        if not self.cmd:
            raise SigmaConfigurationError(
                "CommandPlaceholderTransformation requires a non-empty 'cmd'"
            )
        BasePlaceholderTransformation.__post_init__(self)

    def _fetch_data(self) -> str:
        try:
            result = subprocess.run(
                self.cmd,
                shell=isinstance(self.cmd, str),
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as e:
            raise SigmaValueError(
                f"CommandPlaceholderTransformation: command timed out: {e}"
            ) from e
        except OSError as e:
            raise SigmaValueError(
                f"CommandPlaceholderTransformation: failed to execute command: {e}"
            ) from e

        if result.returncode != 0:
            raise SigmaValueError(
                f"CommandPlaceholderTransformation: command exited with code "
                f"{result.returncode}: {result.stderr.strip()}"
            )
        return result.stdout
