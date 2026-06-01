"""Tests for external data source placeholder transformations."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from sigma.exceptions import SigmaConfigurationError, SigmaSecurityError, SigmaValueError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.transformations.external import (
    PYSIGMA_ALLOW_EXTERNAL_SOURCES_ENV,
    CommandPlaceholderTransformation,
    ExternalSourceBaseTransformation,
    FilePlaceholderTransformation,
    HTTPPlaceholderTransformation,
)
from sigma.rule.rule import SigmaRule
from sigma.types import SigmaString

FILES_DIR = Path(__file__).parent / "files"
PLAINTEXT_FILE = str(FILES_DIR / "placeholder_values.txt")
CSV_FILE = str(FILES_DIR / "placeholder_values.csv")
JSON_FILE = str(FILES_DIR / "placeholder_values.json")
YAML_FILE = str(FILES_DIR / "placeholder_values.yaml")


def _streaming_response(body: bytes, *, chunk_size: int = 8192) -> MagicMock:
    """Build a mock ``requests`` response usable as a streaming context manager."""
    resp = MagicMock()
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    resp.encoding = "utf-8"
    resp.raise_for_status = MagicMock()
    resp.iter_content.return_value = [
        body[i : i + chunk_size] for i in range(0, len(body), chunk_size)
    ]
    return resp


@pytest.fixture
def dummy_pipeline():
    return ProcessingPipeline([], {})


@pytest.fixture
def sigma_rule_with_placeholder():
    return SigmaRule.from_dict(
        {
            "title": "Test",
            "logsource": {"category": "test"},
            "detection": {
                "test": [{"field|expand": "%var1%"}],
                "condition": "test",
            },
        }
    )


class TestExternalValueSourceParsers:
    def test_plaintext_basic(self):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, allow_external_sources=True)
        t._values_cache = None
        values = t._parse_data("alpha\nbeta\ngamma\n")
        assert values == ["alpha", "beta", "gamma"]

    def test_plaintext_empty_lines_skipped(self):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, allow_external_sources=True)
        values = t._parse_data("\nalpha\n\nbeta\n")
        assert values == ["alpha", "beta"]

    def test_plaintext_filter_regex(self):
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE, allow_external_sources=True, filter=r"^\d+"
        )
        values = t._parse_data("123abc\nhello\n456def\n")
        assert values == ["123abc", "456def"]

    def test_csv_by_column_name(self):
        data = "name,score\nalice,10\nbob,20\n"
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE, allow_external_sources=True, format="csv", csv_column="score"
        )
        assert t._parse_data(data) == ["10", "20"]

    def test_csv_by_column_index(self):
        data = "name,score\nalice,10\nbob,20\n"
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE, allow_external_sources=True, format="csv", csv_column=1
        )
        # Header row is skipped by default, consistent with column-name mode.
        assert t._parse_data(data) == ["10", "20"]

    def test_csv_by_column_index_no_header(self):
        data = "alice,10\nbob,20\n"
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            allow_external_sources=True,
            format="csv",
            csv_column=1,
            csv_has_header=False,
        )
        assert t._parse_data(data) == ["10", "20"]

    def test_csv_by_column_name_without_header_raises(self):
        data = "alice,10\nbob,20\n"
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            allow_external_sources=True,
            format="csv",
            csv_column="score",
            csv_has_header=False,
        )
        with pytest.raises(SigmaConfigurationError, match="requires a header row"):
            t._parse_data(data)

    def test_csv_missing_column_raises(self):
        data = "name,score\nalice,10\n"
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            allow_external_sources=True,
            format="csv",
            csv_column="missing",
        )
        with pytest.raises(SigmaConfigurationError, match="CSV column 'missing' not found"):
            t._parse_data(data)

    def test_csv_no_column_raises(self):
        data = "a,b\n1,2\n"
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE, allow_external_sources=True, format="csv"
        )
        with pytest.raises(SigmaConfigurationError, match="csv_column"):
            t._parse_data(data)

    def test_csv_filter_regex(self):
        data = "val\nkeep_this\nskip\nkeep_too\n"
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            allow_external_sources=True,
            format="csv",
            csv_column="val",
            filter=r"^keep",
        )
        assert t._parse_data(data) == ["keep_this", "keep_too"]

    def test_json_jq_expression(self):
        data = json.dumps({"values": ["a", "b", "c"]})
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            allow_external_sources=True,
            format="json",
            jq_expression=".values[]",
        )
        assert t._parse_data(data) == ["a", "b", "c"]

    def test_json_array_value_raises(self):
        data = json.dumps({"items": ["a", "b"]})
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            allow_external_sources=True,
            format="json",
            jq_expression=".items",
        )
        with pytest.raises(SigmaConfigurationError, match="must select scalar values"):
            t._parse_data(data)

    def test_json_object_value_raises(self):
        data = json.dumps({"items": [{"a": 1}, {"a": 2}]})
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            allow_external_sources=True,
            format="json",
            jq_expression=".items[]",
        )
        with pytest.raises(SigmaConfigurationError, match="must select scalar values"):
            t._parse_data(data)

    def test_json_no_expression_raises(self):
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE, allow_external_sources=True, format="json"
        )
        with pytest.raises(SigmaConfigurationError, match="jq_expression"):
            t._parse_data('{"x": 1}')

    def test_json_invalid_raises(self):
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            allow_external_sources=True,
            format="json",
            jq_expression=".x",
        )
        with pytest.raises(SigmaValueError, match="Failed to parse JSON"):
            t._parse_data("not json")

    def test_yaml_jq_expression(self):
        data = yaml.dump({"hosts": ["host1", "host2"]})
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            allow_external_sources=True,
            format="yaml",
            jq_expression=".hosts[]",
        )
        assert t._parse_data(data) == ["host1", "host2"]

    def test_yaml_no_expression_raises(self):
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE, allow_external_sources=True, format="yaml"
        )
        with pytest.raises(SigmaConfigurationError, match="jq_expression"):
            t._parse_data("key: val")

    def test_unknown_format_raises(self):
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE, allow_external_sources=True, format="xml"
        )
        with pytest.raises(SigmaConfigurationError, match="Unknown external source format"):
            t._parse_data("<root/>")


class TestSecurityFlag:
    def test_security_error_when_disabled(self, dummy_pipeline):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, allow_external_sources=False)
        t.set_pipeline(dummy_pipeline)
        with pytest.raises(SigmaSecurityError, match="disabled by default"):
            t._get_values()

    def test_security_error_message_mentions_env_var(self, dummy_pipeline):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE)
        t.set_pipeline(dummy_pipeline)
        with pytest.raises(SigmaSecurityError, match=PYSIGMA_ALLOW_EXTERNAL_SOURCES_ENV):
            t._get_values()

    def test_allowed_via_parameter(self, dummy_pipeline):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, allow_external_sources=True)
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "value1" in values

    def test_allowed_via_env_var(self, dummy_pipeline, monkeypatch):
        monkeypatch.setenv(PYSIGMA_ALLOW_EXTERNAL_SOURCES_ENV, "1")
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, allow_external_sources=False)
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "value1" in values

    def test_allowed_via_env_var_true_string(self, dummy_pipeline, monkeypatch):
        monkeypatch.setenv(PYSIGMA_ALLOW_EXTERNAL_SOURCES_ENV, "true")
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, allow_external_sources=False)
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "value1" in values

    def test_env_var_case_insensitive(self, dummy_pipeline, monkeypatch):
        monkeypatch.setenv(PYSIGMA_ALLOW_EXTERNAL_SOURCES_ENV, "TRUE")
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, allow_external_sources=False)
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "value1" in values


class TestFilePlaceholderTransformation:
    def test_read_plaintext(self, dummy_pipeline):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, allow_external_sources=True)
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "value1" in values
        assert "value2" in values
        assert "value3" in values

    def test_read_csv_by_name(self, dummy_pipeline):
        t = FilePlaceholderTransformation(
            path=CSV_FILE,
            allow_external_sources=True,
            format="csv",
            csv_column="value",
        )
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "val1" in values
        assert "val2" in values

    def test_read_json(self, dummy_pipeline):
        t = FilePlaceholderTransformation(
            path=JSON_FILE,
            allow_external_sources=True,
            format="json",
            jq_expression=".items[]",
        )
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert values == ["json_val1", "json_val2", "json_val3"]

    def test_read_yaml(self, dummy_pipeline):
        t = FilePlaceholderTransformation(
            path=YAML_FILE,
            allow_external_sources=True,
            format="yaml",
            jq_expression=".items[]",
        )
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert values == ["yaml_val1", "yaml_val2", "yaml_val3"]

    def test_values_are_cached(self, dummy_pipeline):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, allow_external_sources=True)
        t.set_pipeline(dummy_pipeline)
        first = t._get_values()
        t._values_cache = ["cached_only"]
        second = t._get_values()
        assert second == ["cached_only"]

    def test_missing_path_raises(self, dummy_pipeline):
        t = FilePlaceholderTransformation(
            path="/nonexistent/path/to/file.txt", allow_external_sources=True
        )
        t.set_pipeline(dummy_pipeline)
        with pytest.raises(SigmaValueError, match="failed to read"):
            t._get_values()

    def test_empty_path_raises(self):
        with pytest.raises(SigmaConfigurationError, match="non-empty 'path'"):
            FilePlaceholderTransformation(path="")

    def test_placeholder_replacements(self, dummy_pipeline):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, allow_external_sources=True)
        t.set_pipeline(dummy_pipeline)
        from sigma.types import Placeholder

        replacements = list(t.placeholder_replacements(Placeholder("var1")))
        assert SigmaString("value1") in replacements
        assert SigmaString("value2") in replacements

    def test_apply_to_rule(self, dummy_pipeline, sigma_rule_with_placeholder):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, allow_external_sources=True)
        t.set_pipeline(dummy_pipeline)
        t.apply(sigma_rule_with_placeholder)
        detection = sigma_rule_with_placeholder.detection.detections["test"]
        detection_items = detection.detection_items
        for di in detection_items:
            if hasattr(di, "detection_items"):
                for inner in di.detection_items:
                    if hasattr(inner, "value"):
                        for val in inner.value:
                            assert not val.contains_placeholder()
            elif hasattr(di, "value"):
                for val in di.value:
                    assert not val.contains_placeholder()

    def test_filter_applied(self, dummy_pipeline):
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            allow_external_sources=True,
            filter=r"^value[12]$",
        )
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "value1" in values
        assert "value2" in values
        assert "value3" not in values
        assert "ignore_this" not in values


class TestHTTPPlaceholderTransformation:
    def test_fetches_url(self, dummy_pipeline):
        with patch(
            "sigma.processing.transformations.external.HTTPPlaceholderTransformation._fetch_data",
            return_value="http_val1\nhttp_val2\n",
        ):
            t = HTTPPlaceholderTransformation(
                url="http://example.com/values", allow_external_sources=True
            )
            t.set_pipeline(dummy_pipeline)
            values = t._get_values()
            assert values == ["http_val1", "http_val2"]

    def test_empty_url_raises(self):
        with pytest.raises(SigmaConfigurationError, match="non-empty 'url'"):
            HTTPPlaceholderTransformation(url="")

    def test_http_error_raises(self, dummy_pipeline):
        import requests

        with patch("requests.request", side_effect=requests.RequestException("conn error")):
            t = HTTPPlaceholderTransformation(
                url="http://bad-host.invalid/", allow_external_sources=True
            )
            t.set_pipeline(dummy_pipeline)
            with pytest.raises(SigmaValueError, match="failed to fetch"):
                t._get_values()

    def test_security_disabled_raises(self, dummy_pipeline):
        t = HTTPPlaceholderTransformation(url="http://example.com/values")
        t.set_pipeline(dummy_pipeline)
        with pytest.raises(SigmaSecurityError):
            t._get_values()

    def test_http_json_format(self, dummy_pipeline):
        json_data = json.dumps({"hosts": ["h1", "h2"]})
        with patch(
            "sigma.processing.transformations.external.HTTPPlaceholderTransformation._fetch_data",
            return_value=json_data,
        ):
            t = HTTPPlaceholderTransformation(
                url="http://example.com/",
                allow_external_sources=True,
                format="json",
                jq_expression=".hosts[]",
            )
            t.set_pipeline(dummy_pipeline)
            assert t._get_values() == ["h1", "h2"]

    def test_http_post_with_json_body(self, dummy_pipeline):
        with patch("requests.request") as mock_req:
            mock_req.return_value = _streaming_response(b"result1\nresult2\n")

            t = HTTPPlaceholderTransformation(
                url="http://example.com/api",
                allow_external_sources=True,
                method="POST",
                json_body={"query": "all"},
            )
            t.set_pipeline(dummy_pipeline)
            values = t._get_values()
            assert values == ["result1", "result2"]
            mock_req.assert_called_once_with(
                method="POST",
                url="http://example.com/api",
                timeout=10,
                headers=None,
                params=None,
                data=None,
                json={"query": "all"},
                stream=True,
            )

    def test_http_post_with_form_data(self, dummy_pipeline):
        with patch("requests.request") as mock_req:
            mock_req.return_value = _streaming_response(b"a\nb\n")

            t = HTTPPlaceholderTransformation(
                url="http://example.com/form",
                allow_external_sources=True,
                method="POST",
                form_data={"token": "secret"},
            )
            t.set_pipeline(dummy_pipeline)
            t._get_values()
            mock_req.assert_called_once_with(
                method="POST",
                url="http://example.com/form",
                timeout=10,
                headers=None,
                params=None,
                data={"token": "secret"},
                json=None,
                stream=True,
            )

    def test_http_custom_headers(self, dummy_pipeline):
        with patch("requests.request") as mock_req:
            mock_req.return_value = _streaming_response(b"v1\n")

            t = HTTPPlaceholderTransformation(
                url="http://example.com/",
                allow_external_sources=True,
                headers={"Authorization": "******"},
            )
            t.set_pipeline(dummy_pipeline)
            t._get_values()
            mock_req.assert_called_once_with(
                method="GET",
                url="http://example.com/",
                timeout=10,
                headers={"Authorization": "******"},
                params=None,
                data=None,
                json=None,
                stream=True,
            )

    def test_http_query_params(self, dummy_pipeline):
        with patch("requests.request") as mock_req:
            mock_req.return_value = _streaming_response(b"v1\n")

            t = HTTPPlaceholderTransformation(
                url="http://example.com/search",
                allow_external_sources=True,
                params={"type": "ip", "limit": "100"},
            )
            t.set_pipeline(dummy_pipeline)
            t._get_values()
            mock_req.assert_called_once_with(
                method="GET",
                url="http://example.com/search",
                timeout=10,
                headers=None,
                params={"type": "ip", "limit": "100"},
                data=None,
                json=None,
                stream=True,
            )

    def test_http_max_body_size_exceeded(self, dummy_pipeline):
        with patch("requests.request") as mock_req:
            mock_req.return_value = _streaming_response(b"x" * 5000, chunk_size=1000)

            t = HTTPPlaceholderTransformation(
                url="http://example.com/big",
                allow_external_sources=True,
                max_body_size=2000,
            )
            t.set_pipeline(dummy_pipeline)
            with pytest.raises(SigmaValueError, match="exceeds max_body_size"):
                t._get_values()


class TestCommandPlaceholderTransformation:
    def test_runs_command_string(self, dummy_pipeline):
        t = CommandPlaceholderTransformation(
            cmd="printf 'cmd_val1\\ncmd_val2\\n'", allow_external_sources=True
        )
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "cmd_val1" in values
        assert "cmd_val2" in values

    def test_runs_command_list(self, dummy_pipeline):
        t = CommandPlaceholderTransformation(
            cmd=["printf", "a\nb\nc\n"], allow_external_sources=True
        )
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "a" in values

    def test_empty_cmd_raises(self):
        with pytest.raises(SigmaConfigurationError, match="non-empty 'cmd'"):
            CommandPlaceholderTransformation(cmd="")

    def test_nonzero_exit_raises(self, dummy_pipeline):
        t = CommandPlaceholderTransformation(cmd="exit 1", allow_external_sources=True)
        t.set_pipeline(dummy_pipeline)
        with pytest.raises(SigmaValueError, match="exited with code"):
            t._get_values()

    def test_security_disabled_raises(self, dummy_pipeline):
        t = CommandPlaceholderTransformation(cmd="echo hello")
        t.set_pipeline(dummy_pipeline)
        with pytest.raises(SigmaSecurityError):
            t._get_values()

    def test_timeout_raises(self, dummy_pipeline):
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired("sleep", 0.001),
        ):
            t = CommandPlaceholderTransformation(
                cmd="sleep 999", allow_external_sources=True, timeout=1
            )
            t.set_pipeline(dummy_pipeline)
            with pytest.raises(SigmaValueError, match="timed out"):
                t._get_values()

    def test_command_json_format(self, dummy_pipeline):
        json_data = json.dumps({"items": ["x", "y"]})
        with patch(
            "sigma.processing.transformations.external.CommandPlaceholderTransformation._fetch_data",
            return_value=json_data,
        ):
            t = CommandPlaceholderTransformation(
                cmd="echo",
                allow_external_sources=True,
                format="json",
                jq_expression=".items[]",
            )
            t.set_pipeline(dummy_pipeline)
            assert t._get_values() == ["x", "y"]

    def test_max_stdout_exceeded(self, dummy_pipeline):
        t = CommandPlaceholderTransformation(
            cmd=["printf", "%s", "x" * 5000],
            allow_external_sources=True,
            max_stdout=1000,
        )
        t.set_pipeline(dummy_pipeline)
        with pytest.raises(SigmaValueError, match="exceeds max_stdout"):
            t._get_values()


class TestPipelineIntegration:
    def _rule_yaml(self) -> str:
        return """
title: Test
logsource:
    category: test
detection:
    test:
        - field|expand: "%myvar%"
    condition: test
"""

    def _pipeline_yaml(self, path: str) -> str:
        return f"""
transformations:
  - type: file_placeholders
    path: {path}
"""

    def test_pipeline_without_allow_external_sources_raises(self):
        pipeline = ProcessingPipeline.from_yaml(
            self._pipeline_yaml(PLAINTEXT_FILE), allow_external_sources=False
        )
        rule = SigmaRule.from_yaml(self._rule_yaml())
        with pytest.raises(SigmaSecurityError):
            pipeline.apply(rule)

    def test_pipeline_with_allow_external_sources(self):
        pipeline = ProcessingPipeline.from_yaml(
            self._pipeline_yaml(PLAINTEXT_FILE), allow_external_sources=True
        )
        rule = SigmaRule.from_yaml(self._rule_yaml())
        pipeline.apply(rule)

    def test_allow_external_sources_stripped_from_yaml(self):
        """allow_external_sources in pipeline YAML must not be accepted as a top-level key."""
        pipeline_yaml = f"""
allow_external_sources: true
transformations:
  - type: file_placeholders
    path: {PLAINTEXT_FILE}
"""
        with pytest.raises(SigmaConfigurationError, match="Unkown keys"):
            ProcessingPipeline.from_yaml(pipeline_yaml)

    def test_include_exclude_still_work(self, dummy_pipeline):
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            allow_external_sources=True,
            include=["var1"],
        )
        t.set_pipeline(dummy_pipeline)
        from sigma.types import Placeholder

        replacements = list(t.placeholder_replacements(Placeholder("var1")))
        assert len(replacements) > 0

    def test_registered_in_transformations_dict(self):
        from sigma.processing.transformations import transformations

        assert "file_placeholders" in transformations
        assert "http_placeholders" in transformations
        assert "command_placeholders" in transformations
