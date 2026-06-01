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
from abc import abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterable

import yaml

from sigma.exceptions import SigmaConfigurationError, SigmaSecurityError, SigmaValueError
from sigma.processing.transformations.placeholder import BasePlaceholderTransformation
from sigma.types import Placeholder, SigmaString

PYSIGMA_ALLOW_EXTERNAL_SOURCES_ENV = "PYSIGMA_ALLOW_EXTERNAL_SOURCES"

# Default cap on the amount of data accepted from an external source (10 MiB).
DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


@dataclass
class ExternalSourceBaseTransformation(BasePlaceholderTransformation):
    """Base class for placeholder transformations that fetch replacement values from
    an external source (file, HTTP, command).

    **Supported formats** (controlled by the *format* parameter):

    * ``"plaintext"`` — one value per line; an optional *filter* regex must
      match for a line to be included.
    * ``"csv"`` — CSV data; *csv_column* selects the column (column header
      name **or** 0-based integer index); *csv_has_header* (default ``True``)
      controls whether the first row is treated as a header; an optional
      *filter* regex is applied to each extracted cell value.
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
    csv_has_header: bool = True
    jq_expression: str | None = None
    allow_external_sources: bool = False

    _values_cache: list[str] | None = field(init=False, default=None, repr=False, compare=False)

    def _external_sources_allowed(self) -> bool:
        """Return *True* if external data sources are permitted."""
        if self.allow_external_sources:
            return True
        return os.environ.get(PYSIGMA_ALLOW_EXTERNAL_SOURCES_ENV, "").lower() in (
            "1",
            "true",
        )

    @abstractmethod
    def _fetch_data(self) -> str:
        """Fetch raw text data from the external source.

        Subclasses **must** override this method.
        """

    def _get_values(self) -> list[str]:
        """Return the list of replacement values, fetching and caching them if necessary.

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
            raise SigmaConfigurationError("'csv_column' must be specified when format is 'csv'")

        values: list[str] = []

        if isinstance(self.csv_column, str):
            if not self.csv_has_header:
                raise SigmaConfigurationError(
                    "CSV column referenced by name requires a header row (csv_has_header=True)"
                )
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
            col_idx = self.csv_column
            rows = iter(csv.reader(io.StringIO(data)))
            if self.csv_has_header:
                next(rows, None)  # discard header row for consistency with name-based mode
            for csv_row in rows:
                if col_idx < len(csv_row):
                    values.append(csv_row[col_idx])

        if self.filter:
            pattern = re.compile(self.filter)
            values = [v for v in values if pattern.search(v)]
        return values

    def _parse_json(self, data: str) -> list[str]:
        import jq  # type: ignore[import-not-found]

        if self.jq_expression is None:
            raise SigmaConfigurationError("'jq_expression' must be specified when format is 'json'")
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as e:
            raise SigmaValueError(f"Failed to parse JSON data: {e}") from e
        try:
            result = jq.all(self.jq_expression, parsed)
        except ValueError as e:
            raise SigmaConfigurationError(f"Invalid jq expression: {e}") from e
        return self._jq_results_to_values(result)

    def _parse_yaml_data(self, data: str) -> list[str]:
        import jq

        if self.jq_expression is None:
            raise SigmaConfigurationError("'jq_expression' must be specified when format is 'yaml'")
        try:
            parsed = yaml.safe_load(data)
        except yaml.YAMLError as e:
            raise SigmaValueError(f"Failed to parse YAML data: {e}") from e
        try:
            result = jq.all(self.jq_expression, parsed)
        except ValueError as e:
            raise SigmaConfigurationError(f"Invalid jq expression: {e}") from e
        return self._jq_results_to_values(result)

    @staticmethod
    def _jq_results_to_values(result: Iterable[Any]) -> list[str]:
        """Convert jq output into scalar placeholder values.

        Each placeholder replacement becomes an individual field match value,
        so a jq result must be a scalar. An expression that yields an array or
        object is rejected with guidance to project to scalars (e.g. use
        ``.items[]`` instead of ``.items``). ``None`` results are skipped.
        """
        values: list[str] = []
        for v in result:
            if v is None:
                continue
            if isinstance(v, (dict, list)):
                raise SigmaConfigurationError(
                    "jq_expression must select scalar values for placeholder "
                    f"replacement, but a {type(v).__name__} was returned; project "
                    "to scalars (e.g. '.items[]' instead of '.items')"
                )
            values.append(str(v))
        return values

    def placeholder_replacements(self, p: Placeholder) -> Iterable[SigmaString]:
        return [SigmaString(v) for v in self._get_values()]


@dataclass
class FilePlaceholderTransformation(ExternalSourceBaseTransformation):
    """Replace placeholders with values read from a local file.

    Parameters:
    * **path** — path to the file (required)
    * **format** — data format: ``"plaintext"`` (default), ``"csv"``, ``"json"``, ``"yaml"``
    * **filter** — optional regex that each value must match (plaintext/csv)
    * **csv_column** — column name (str) or 0-based index (int) for CSV format
    * **csv_has_header** — whether the first CSV row is a header (default ``True``)
    * **jq_expression** — path expression for JSON/YAML formats (e.g. ``.items[]``)
    * **include** / **exclude** — placeholder name lists (from
      :class:`~sigma.processing.transformations.placeholder.BasePlaceholderTransformation`)
    """

    path: str = ""

    def __post_init__(self) -> None:
        if not self.path:
            raise SigmaConfigurationError(
                "FilePlaceholderTransformation requires a non-empty 'path'"
            )
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
class HTTPPlaceholderTransformation(ExternalSourceBaseTransformation):
    """Replace placeholders with values fetched from an HTTP(S) endpoint.

    Parameters:
    * **url** — URL to fetch (required)
    * **method** — HTTP method (default: ``"GET"``)
    * **timeout** — request timeout in seconds (default: 10)
    * **headers** — optional dict of custom HTTP request headers
    * **params** — optional dict of URL query parameters
    * **form_data** — optional dict to send as a form-encoded request body
      (``application/x-www-form-urlencoded``)
    * **json_body** — optional dict to send as a JSON request body
      (``application/json``)
    * **max_body_size** — maximum response body size in bytes; the fetch is
      aborted with an error once this many bytes have been read (default 10 MiB)
    * **format** — data format: ``"plaintext"`` (default), ``"csv"``, ``"json"``, ``"yaml"``
    * **filter** — optional regex that each value must match (plaintext/csv)
    * **csv_column** — column name (str) or 0-based index (int) for CSV format
    * **csv_has_header** — whether the first CSV row is a header (default ``True``)
    * **jq_expression** — path expression for JSON/YAML formats
    * **include** / **exclude** — placeholder name lists
    """

    url: str = ""
    method: str = "GET"
    timeout: int = 10
    headers: dict[str, str] | None = None
    params: dict[str, str] | None = None
    form_data: dict[str, Any] | None = None
    json_body: dict[str, Any] | None = None
    max_body_size: int = DEFAULT_MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        if not self.url:
            raise SigmaConfigurationError(
                "HTTPPlaceholderTransformation requires a non-empty 'url'"
            )
        BasePlaceholderTransformation.__post_init__(self)

    def _fetch_data(self) -> str:
        import requests

        try:
            with requests.request(
                method=self.method,
                url=self.url,
                timeout=self.timeout,
                headers=self.headers,
                params=self.params,
                data=self.form_data,
                json=self.json_body,
                stream=True,
            ) as response:
                response.raise_for_status()
                content = bytearray()
                for chunk in response.iter_content(chunk_size=8192):
                    content.extend(chunk)
                    if len(content) > self.max_body_size:
                        raise SigmaValueError(
                            f"HTTPPlaceholderTransformation: response from '{self.url}' "
                            f"exceeds max_body_size ({self.max_body_size} bytes)"
                        )
                encoding = response.encoding or response.apparent_encoding or "utf-8"
                return content.decode(encoding, errors="replace")
        except SigmaValueError:
            raise
        except Exception as e:
            raise SigmaValueError(
                f"HTTPPlaceholderTransformation: failed to fetch '{self.url}': {e}"
            ) from e


@dataclass
class CommandPlaceholderTransformation(ExternalSourceBaseTransformation):
    """Replace placeholders with the stdout output of a shell command.

    Parameters:
    * **cmd** — command string (passed to ``/bin/sh -c``) or a list of
      arguments (required)
    * **timeout** — maximum execution time in seconds (default: 30)
    * **max_stdout** — maximum accepted stdout size in bytes; output larger
      than this is rejected with an error (default 10 MiB)
    * **format** — data format: ``"plaintext"`` (default), ``"csv"``, ``"json"``, ``"yaml"``
    * **filter** — optional regex that each value must match (plaintext/csv)
    * **csv_column** — column name (str) or 0-based index (int) for CSV format
    * **csv_has_header** — whether the first CSV row is a header (default ``True``)
    * **jq_expression** — path expression for JSON/YAML formats
    * **include** / **exclude** — placeholder name lists
    """

    cmd: str | list[str] = ""
    timeout: int = 30
    max_stdout: int = DEFAULT_MAX_RESPONSE_BYTES

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
        if len(result.stdout.encode("utf-8", errors="replace")) > self.max_stdout:
            raise SigmaValueError(
                f"CommandPlaceholderTransformation: command output exceeds "
                f"max_stdout ({self.max_stdout} bytes)"
            )
        return result.stdout
