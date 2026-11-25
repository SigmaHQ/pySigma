"""Tests for external data source placeholder transformations."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
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
from sigma.policy import SigmaPolicy
from sigma.policy.regex_engine import PythonRegexEngine, RE2RegexEngine

FILES_DIR = Path(__file__).parent / "files"
PLAINTEXT_FILE = str(FILES_DIR / "placeholder_values.txt")
CSV_FILE = str(FILES_DIR / "placeholder_values.csv")
JSON_FILE = str(FILES_DIR / "placeholder_values.json")
YAML_FILE = str(FILES_DIR / "placeholder_values.yaml")

_ALLOW_EXTERNAL_POLICY = SigmaPolicy(regex_engine=RE2RegexEngine(), allow_external_sources=True)


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
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY)
        t._values_cache = None
        values = t._parse_data("alpha\nbeta\ngamma\n")
        assert values == ["alpha", "beta", "gamma"]

    def test_plaintext_empty_lines_skipped(self):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY)
        values = t._parse_data("\nalpha\n\nbeta\n")
        assert values == ["alpha", "beta"]

    def test_plaintext_filter_regex(self, dummy_pipeline):
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY, filter=r"^\d+"
        )
        t.set_pipeline(dummy_pipeline)
        with patch.object(t, "_fetch_data", return_value="123abc\nhello\n456def\n"):
            values = t._get_values()
        assert values == ["123abc", "456def"]

    def test_csv_by_column_name(self):
        data = "name,score\nalice,10\nbob,20\n"
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY, format="csv", csv_column="score"
        )
        assert t._parse_data(data) == ["10", "20"]

    def test_csv_by_column_index(self):
        data = "name,score\nalice,10\nbob,20\n"
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY, format="csv", csv_column=1
        )
        # Header row is skipped by default, consistent with column-name mode.
        assert t._parse_data(data) == ["10", "20"]

    def test_csv_by_column_index_no_header(self):
        data = "alice,10\nbob,20\n"
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="csv",
            csv_column=1,
            csv_has_header=False,
        )
        assert t._parse_data(data) == ["10", "20"]

    def test_csv_by_column_name_without_header_raises(self):
        data = "alice,10\nbob,20\n"
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
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
            policy=_ALLOW_EXTERNAL_POLICY,
            format="csv",
            csv_column="missing",
        )
        with pytest.raises(SigmaConfigurationError, match="CSV column 'missing' not found"):
            t._parse_data(data)

    def test_csv_no_column_raises(self):
        data = "a,b\n1,2\n"
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY, format="csv"
        )
        with pytest.raises(SigmaConfigurationError, match="csv_column"):
            t._parse_data(data)

    def test_csv_filter_regex(self, dummy_pipeline):
        data = "val\nkeep_this\nskip\nkeep_too\n"
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="csv",
            csv_column="val",
            filter=r"^keep",
        )
        t.set_pipeline(dummy_pipeline)
        with patch.object(t, "_fetch_data", return_value=data):
            values = t._get_values()
        assert values == ["keep_this", "keep_too"]

    def test_filter_invalid_regex_raises_at_init(self):
        with pytest.raises(SigmaConfigurationError, match="Invalid regex in 'filter'"):
            FilePlaceholderTransformation(
                path=PLAINTEXT_FILE,
                policy=_ALLOW_EXTERNAL_POLICY,
                filter="[unclosed",
            )

    def test_filter_pattern_compiled_at_init(self):
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY, filter=r"^\d+"
        )
        assert t._filter_pattern is not None
        assert t._filter_pattern.pattern == r"^\d+"

    def test_json_jq_expression(self):
        data = json.dumps({"values": ["a", "b", "c"]})
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="json",
            jq_expression=".values[]",
        )
        assert t._parse_data(data) == ["a", "b", "c"]

    def test_json_array_value_raises(self):
        data = json.dumps({"items": ["a", "b"]})
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="json",
            jq_expression=".items",
        )
        with pytest.raises(SigmaConfigurationError, match="must select scalar values"):
            t._parse_data(data)

    def test_json_object_value_raises(self):
        data = json.dumps({"items": [{"a": 1}, {"a": 2}]})
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="json",
            jq_expression=".items[]",
        )
        with pytest.raises(SigmaConfigurationError, match="must select scalar values"):
            t._parse_data(data)

    def test_json_no_expression_raises(self):
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY, format="json"
        )
        with pytest.raises(SigmaConfigurationError, match="jq_expression"):
            t._parse_data('{"x": 1}')

    def test_json_invalid_raises(self):
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="json",
            jq_expression=".x",
        )
        with pytest.raises(SigmaValueError, match="Failed to parse JSON"):
            t._parse_data("not json")

    def test_yaml_jq_expression(self):
        data = yaml.dump({"hosts": ["host1", "host2"]})
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="yaml",
            jq_expression=".hosts[]",
        )
        assert t._parse_data(data) == ["host1", "host2"]

    def test_yaml_no_expression_raises(self):
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY, format="yaml"
        )
        with pytest.raises(SigmaConfigurationError, match="jq_expression"):
            t._parse_data("key: val")

    def test_yaml_alias_bomb_raises(self):
        lines = ["v0: &v0 [host1]", "hosts: &hosts0 [*v0, *v0]"]
        lines += [f"hosts{i}: &hosts{i} [*hosts{i-1}, *hosts{i-1}]" for i in range(1, 20)]
        lines.append("hosts: *hosts19")
        data = "\n".join(lines)

        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="yaml",
            jq_expression=".hosts[]",
        )
        with pytest.raises(SigmaValueError, match="YAML aliases expand"):
            t._parse_data(data)

    def test_unknown_format_raises(self):
        with pytest.raises(SigmaConfigurationError, match="Unknown external source format"):
            FilePlaceholderTransformation(
                path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY, format="xml"
            )


class TestCSVRowFilters:
    @pytest.mark.parametrize("column", ["indicator", 0])
    def test_filters_metadata_before_extracting_column(self, column):
        t = FilePlaceholderTransformation(
            path=CSV_FILE,
            format="csv",
            csv_column=column,
            csv_filters={"actor": "APT-example", "kind": "^domain$"},
        )
        data = (
            "indicator,actor,kind\n"
            "one.example,related to APT-example,domain\n"
            "two.example,other,domain\n"
            "192.0.2.1,APT-example,ip\n"
        )
        assert t._parse_data(data) == ["one.example"]

    def test_combines_row_filters_with_existing_value_filter(self):
        t = FilePlaceholderTransformation(
            path=CSV_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="csv",
            csv_column="indicator",
            csv_filters={"actor": "^APT-example$"},
            filter=r"\.example$",
        )
        data = "indicator,actor\none.example,APT-example\n192.0.2.1,APT-example\n"
        with patch.object(t, "_fetch_data", return_value=data):
            assert t._get_values() == ["one.example"]

    def test_matches_parsed_quoted_cells(self):
        t = FilePlaceholderTransformation(
            path=CSV_FILE,
            format="csv",
            csv_column="indicator",
            csv_filters={"context": "^actor, example\nsecond line$"},
        )
        data = 'indicator,context\n"value,quoted","actor, example\nsecond line"\n'
        assert t._parse_data(data) == ["value,quoted"]

    def test_missing_cells_do_not_match_empty_pattern(self):
        t = FilePlaceholderTransformation(
            path=CSV_FILE,
            format="csv",
            csv_column="indicator",
            csv_filters={"actor": "^$"},
        )
        assert t._parse_data("indicator,actor\nempty.example,\nmissing.example\n") == [
            "empty.example"
        ]

    @pytest.mark.parametrize("column", ["indicator", 1, -1])
    def test_skips_rows_missing_output_column(self, column):
        t = FilePlaceholderTransformation(
            path=CSV_FILE,
            format="csv",
            csv_column=column,
            csv_filters={"actor": "APT-example"},
        )
        data = "actor,indicator\nAPT-example,one.example\nAPT-example\n"
        expected = ["one.example", "APT-example"] if column == -1 else ["one.example"]
        assert t._parse_data(data) == expected

    @pytest.mark.parametrize("data", ["", "indicator,actor\n", "indicator,actor\nx,other\n"])
    def test_empty_result(self, data):
        t = FilePlaceholderTransformation(
            path=CSV_FILE,
            format="csv",
            csv_column="indicator",
            csv_filters={"actor": "APT-example"},
        )
        assert t._parse_data(data) == []

    @pytest.mark.parametrize("data", ["indicator,kind\n", "indicator,kind\nx,domain\n"])
    def test_missing_filter_column_raises(self, data):
        t = FilePlaceholderTransformation(
            path=CSV_FILE,
            format="csv",
            csv_column="indicator",
            csv_filters={"actor": "APT-example"},
        )
        with pytest.raises(SigmaConfigurationError, match="CSV column 'actor' not found"):
            t._parse_data(data)

    def test_missing_output_column_raises_before_filtering(self):
        t = FilePlaceholderTransformation(
            path=CSV_FILE,
            format="csv",
            csv_column="indicator",
            csv_filters={"actor": "APT-example"},
        )
        with pytest.raises(SigmaConfigurationError, match="CSV column 'indicator' not found"):
            t._parse_data("actor\nother\n")

    @pytest.mark.parametrize(
        "kwargs", [{"format": "plaintext"}, {"format": "csv", "csv_has_header": False}]
    )
    def test_incompatible_configuration_raises_at_init(self, kwargs):
        with pytest.raises(SigmaConfigurationError, match="csv_filters.*csv.*header"):
            FilePlaceholderTransformation(
                path=CSV_FILE, csv_column=0, csv_filters={"actor": "APT-example"}, **kwargs
            )

    @pytest.mark.parametrize("filters", [["actor"], {"actor": 7}, {0: "APT-example"}])
    def test_invalid_mapping_raises_at_init(self, filters):
        with pytest.raises(SigmaConfigurationError, match="csv_filters.*mapping.*strings"):
            FilePlaceholderTransformation(
                path=CSV_FILE, format="csv", csv_column=0, csv_filters=filters
            )

    def test_invalid_regex_raises_at_init(self):
        with pytest.raises(SigmaConfigurationError, match="Invalid regex in 'csv_filters'.*actor"):
            FilePlaceholderTransformation(
                path=CSV_FILE,
                format="csv",
                csv_column=0,
                csv_filters={"actor": "[unclosed"},
            )

    def test_uses_policy_regex_engine(self):
        kwargs = dict(path=CSV_FILE, format="csv", csv_column=0, csv_filters={"actor": "(?=APT)"})
        with pytest.raises(SigmaConfigurationError, match="Invalid regex in 'csv_filters'"):
            FilePlaceholderTransformation(**kwargs, policy=_ALLOW_EXTERNAL_POLICY)
        t = FilePlaceholderTransformation(
            **kwargs, policy=SigmaPolicy(regex_engine=PythonRegexEngine())
        )
        assert t._parse_data("indicator,actor\none.example,APT-example\n") == ["one.example"]

    def test_empty_mapping_keeps_existing_csv_behavior(self):
        t = FilePlaceholderTransformation(
            path=CSV_FILE, format="csv", csv_column=0, csv_has_header=False, csv_filters={}
        )
        assert t._parse_data("one.example,APT-example\n") == ["one.example"]

    @pytest.mark.parametrize("cached", [False, True])
    def test_row_filters_follow_attached_pipeline_regex_engine(self, cached):
        t = FilePlaceholderTransformation(
            path=CSV_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="csv",
            csv_column="indicator",
            csv_filters={"actor": r"^\w+$"},
        )
        data = "indicator,actor\none.example,caf\u00e9\n"
        with patch.object(t, "_fetch_data", return_value=data) as fetch:
            if cached:
                assert t._get_values() == []  # RE2's word character class is ASCII-only.
            t.set_pipeline(ProcessingPipeline(policy=SigmaPolicy(regex_engine=PythonRegexEngine())))
            assert t._get_values() == ["one.example"]
            assert t._get_values() == ["one.example"]
            assert fetch.call_count == (2 if cached else 1)

    @pytest.mark.parametrize("cached", [False, True])
    def test_attached_pipeline_rejects_unsupported_row_filter_before_fetch(self, cached):
        t = FilePlaceholderTransformation(
            path=CSV_FILE,
            policy=SigmaPolicy(regex_engine=PythonRegexEngine(), allow_external_sources=True),
            format="csv",
            csv_column="indicator",
            csv_filters={"actor": "(?=APT)"},
        )
        with patch.object(
            t, "_fetch_data", return_value="indicator,actor\nx,APT-example\n"
        ) as fetch:
            if cached:
                assert t._get_values() == ["x"]
            t.set_pipeline(ProcessingPipeline(policy=_ALLOW_EXTERNAL_POLICY))
            with pytest.raises(SigmaConfigurationError, match="Invalid regex in 'csv_filters'"):
                t._get_values()
            assert fetch.call_count == (1 if cached else 0)

    @pytest.mark.parametrize(
        ("cls", "source_attr", "source"),
        [
            (FilePlaceholderTransformation, "path", CSV_FILE),
            (HTTPPlaceholderTransformation, "url", "https://example.invalid/feed.csv"),
            (CommandPlaceholderTransformation, "cmd", ["unused"]),
        ],
    )
    def test_existing_positional_source_argument_is_unchanged(self, cls, source_attr, source):
        t = cls(None, None, "csv", None, 0, True, None, _ALLOW_EXTERNAL_POLICY, source)
        assert getattr(t, source_attr) == source
        assert t._parse_data("indicator,actor\none.example,APT-example\n") == ["one.example"]


class TestSecurityFlag:
    def test_security_error_when_disabled(self, dummy_pipeline):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE)
        t.set_pipeline(dummy_pipeline)
        with pytest.raises(SigmaSecurityError, match="disabled by default"):
            t._get_values()

    def test_security_error_message_mentions_env_var(self, dummy_pipeline):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE)
        t.set_pipeline(dummy_pipeline)
        with pytest.raises(SigmaSecurityError, match=PYSIGMA_ALLOW_EXTERNAL_SOURCES_ENV):
            t._get_values()

    def test_allowed_via_parameter(self, dummy_pipeline):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY)
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "value1" in values

    def test_allowed_via_env_var(self, dummy_pipeline, monkeypatch):
        monkeypatch.setenv(PYSIGMA_ALLOW_EXTERNAL_SOURCES_ENV, "1")
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE)
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "value1" in values

    def test_allowed_via_env_var_true_string(self, dummy_pipeline, monkeypatch):
        monkeypatch.setenv(PYSIGMA_ALLOW_EXTERNAL_SOURCES_ENV, "true")
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE)
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "value1" in values

    def test_env_var_case_insensitive(self, dummy_pipeline, monkeypatch):
        monkeypatch.setenv(PYSIGMA_ALLOW_EXTERNAL_SOURCES_ENV, "TRUE")
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE)
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "value1" in values


class TestFilePlaceholderTransformation:
    def test_read_plaintext(self, dummy_pipeline):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY)
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "value1" in values
        assert "value2" in values
        assert "value3" in values

    def test_read_csv_by_name(self, dummy_pipeline):
        t = FilePlaceholderTransformation(
            path=CSV_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
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
            policy=_ALLOW_EXTERNAL_POLICY,
            format="json",
            jq_expression=".items[]",
        )
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert values == ["json_val1", "json_val2", "json_val3"]

    def test_read_yaml(self, dummy_pipeline):
        t = FilePlaceholderTransformation(
            path=YAML_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="yaml",
            jq_expression=".items[]",
        )
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert values == ["yaml_val1", "yaml_val2", "yaml_val3"]

    def test_values_are_cached(self, dummy_pipeline):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY)
        t.set_pipeline(dummy_pipeline)
        first = t._get_values()
        t._values_cache = ["cached_only"]
        second = t._get_values()
        assert second == ["cached_only"]

    def test_missing_path_raises(self, dummy_pipeline):
        t = FilePlaceholderTransformation(
            path="/nonexistent/path/to/file.txt", policy=_ALLOW_EXTERNAL_POLICY
        )
        t.set_pipeline(dummy_pipeline)
        with pytest.raises(SigmaValueError, match="failed to read"):
            t._get_values()

    def test_empty_path_raises(self):
        with pytest.raises(SigmaConfigurationError, match="non-empty 'path'"):
            FilePlaceholderTransformation(path="")

    def test_placeholder_replacements(self, dummy_pipeline):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY)
        t.set_pipeline(dummy_pipeline)
        from sigma.types import Placeholder

        replacements = list(t.placeholder_replacements(Placeholder("var1")))
        assert SigmaString("value1") in replacements
        assert SigmaString("value2") in replacements

    def test_apply_to_rule(self, dummy_pipeline, sigma_rule_with_placeholder):
        t = FilePlaceholderTransformation(path=PLAINTEXT_FILE, policy=_ALLOW_EXTERNAL_POLICY)
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
            policy=_ALLOW_EXTERNAL_POLICY,
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
                url="http://example.com/values", policy=_ALLOW_EXTERNAL_POLICY
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
                url="http://bad-host.invalid/", policy=_ALLOW_EXTERNAL_POLICY
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
                policy=_ALLOW_EXTERNAL_POLICY,
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
                policy=_ALLOW_EXTERNAL_POLICY,
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
                policy=_ALLOW_EXTERNAL_POLICY,
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
                policy=_ALLOW_EXTERNAL_POLICY,
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
                policy=_ALLOW_EXTERNAL_POLICY,
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
                policy=_ALLOW_EXTERNAL_POLICY,
                max_body_size=2000,
            )
            t.set_pipeline(dummy_pipeline)
            with pytest.raises(SigmaValueError, match="exceeds max_body_size"):
                t._get_values()


class TestCommandPlaceholderTransformation:
    def test_runs_command_string(self, dummy_pipeline):
        # Use platform-agnostic command
        cmd = (
            [sys.executable, "-c", 'print("cmd_val1")\nprint("cmd_val2")']
            if sys.platform == "win32"
            else "printf 'cmd_val1\\ncmd_val2\\n'"
        )
        t = CommandPlaceholderTransformation(cmd=cmd, policy=_ALLOW_EXTERNAL_POLICY)
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "cmd_val1" in values
        assert "cmd_val2" in values

    def test_runs_command_list(self, dummy_pipeline):
        # Use platform-agnostic command
        cmd = (
            [sys.executable, "-c", 'print("a")\nprint("b")\nprint("c")']
            if sys.platform == "win32"
            else ["printf", "a\nb\nc\n"]
        )
        t = CommandPlaceholderTransformation(cmd=cmd, policy=_ALLOW_EXTERNAL_POLICY)
        t.set_pipeline(dummy_pipeline)
        values = t._get_values()
        assert "a" in values

    def test_empty_cmd_raises(self):
        with pytest.raises(SigmaConfigurationError, match="non-empty 'cmd'"):
            CommandPlaceholderTransformation(cmd="")

    def test_nonzero_exit_raises(self, dummy_pipeline):
        t = CommandPlaceholderTransformation(cmd="exit 1", policy=_ALLOW_EXTERNAL_POLICY)
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
                cmd="sleep 999", policy=_ALLOW_EXTERNAL_POLICY, timeout=1
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
                policy=_ALLOW_EXTERNAL_POLICY,
                format="json",
                jq_expression=".items[]",
            )
            t.set_pipeline(dummy_pipeline)
            assert t._get_values() == ["x", "y"]

    def test_max_stdout_exceeded(self, dummy_pipeline):
        # Use platform-agnostic command
        cmd = (
            [sys.executable, "-c", 'print("x" * 5000)']
            if sys.platform == "win32"
            else ["printf", "%s", "x" * 5000]
        )
        t = CommandPlaceholderTransformation(
            cmd=cmd,
            policy=_ALLOW_EXTERNAL_POLICY,
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
        pipeline = ProcessingPipeline.from_yaml(self._pipeline_yaml(PLAINTEXT_FILE))
        rule = SigmaRule.from_yaml(self._rule_yaml())
        with pytest.raises(SigmaSecurityError):
            pipeline.apply(rule)

    def test_pipeline_with_allow_external_sources(self):
        pipeline = ProcessingPipeline.from_yaml(
            self._pipeline_yaml(PLAINTEXT_FILE), policy=_ALLOW_EXTERNAL_POLICY
        )
        rule = SigmaRule.from_yaml(self._rule_yaml())
        pipeline.apply(rule)

    @pytest.mark.parametrize("allow_external", [False, True])
    def test_http_csv_row_filters_in_yaml_pipeline(self, allow_external):
        pipeline = ProcessingPipeline.from_yaml(
            """
transformations:
  - type: http_placeholders
    url: https://example.invalid/feed.csv
    format: csv
    csv_column: indicator
    csv_filters:
      actor: '^APT-example$'
      kind: '^domain$'
""",
            policy=_ALLOW_EXTERNAL_POLICY if allow_external else None,
        )
        rule = SigmaRule.from_yaml(self._rule_yaml())
        data = (
            b"indicator,actor,kind\n"
            b"one.example,APT-example,domain\n"
            b"two.example,other,domain\n"
            b"192.0.2.1,APT-example,ip\n"
        )
        backend = TextQueryTestBackend(processing_pipeline=pipeline)
        with patch("requests.request", return_value=_streaming_response(data)) as request:
            if allow_external:
                assert backend.convert(SigmaCollection([rule])) == ['field="one.example"']
                request.assert_called_once()
            else:
                with pytest.raises(SigmaSecurityError):
                    backend.convert(SigmaCollection([rule]))
                request.assert_not_called()

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
            policy=_ALLOW_EXTERNAL_POLICY,
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


class TestFilter:
    """Tests for the unified *filter* field on ExternalSourceBaseTransformation.

    All tests use FilePlaceholderTransformation (the simplest concrete subclass) and
    drive _get_values() via a mocked _fetch_data() â€” no real network or disk I/O needed.
    """

    def test_filter_json_applied_via_get_values(self, dummy_pipeline):
        """_get_values() applies filter after JSON parsing."""
        raw = json.dumps({"hosts": ["192.168.1.1", "fe80::1", "10.0.0.1"]})
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="json",
            jq_expression=".hosts[]",
            filter=r"^\d{1,3}(\.\d{1,3}){3}$",
        )
        t.set_pipeline(dummy_pipeline)
        with patch.object(t, "_fetch_data", return_value=raw):
            values = t._get_values()
        assert values == ["192.168.1.1", "10.0.0.1"]

    def test_filter_yaml_applied_via_get_values(self, dummy_pipeline):
        """_get_values() applies filter after YAML parsing."""
        raw = yaml.dump({"hosts": ["192.168.1.1", "fe80::1", "10.0.0.1"]})
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="yaml",
            jq_expression=".hosts[]",
            filter=r"^\d{1,3}(\.\d{1,3}){3}$",
        )
        t.set_pipeline(dummy_pipeline)
        with patch.object(t, "_fetch_data", return_value=raw):
            values = t._get_values()
        assert values == ["192.168.1.1", "10.0.0.1"]

    def test_filter_plaintext_applied_via_get_values(self, dummy_pipeline):
        """filter applied after plaintext parsing keeps only matching lines."""
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="plaintext",
            filter=r"^keep",
        )
        t.set_pipeline(dummy_pipeline)
        with patch.object(t, "_fetch_data", return_value="keep_this\nskip_this\nkeep_too\n"):
            values = t._get_values()
        assert values == ["keep_this", "keep_too"]

    def test_filter_csv_applied_via_get_values(self, dummy_pipeline):
        """filter applied after CSV parsing keeps only matching cell values."""
        data = "val\nkeep_this\nskip\nkeep_too\n"
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="csv",
            csv_column="val",
            filter=r"^keep",
        )
        t.set_pipeline(dummy_pipeline)
        with patch.object(t, "_fetch_data", return_value=data):
            values = t._get_values()
        assert values == ["keep_this", "keep_too"]

    def test_no_filter_returns_all_values(self, dummy_pipeline):
        """Without filter the full jq result is returned unchanged."""
        data = json.dumps({"values": ["alpha", "beta", "gamma"]})
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="json",
            jq_expression=".values[]",
        )
        t.set_pipeline(dummy_pipeline)
        assert t._filter_pattern is None
        with patch.object(t, "_fetch_data", return_value=data):
            values = t._get_values()
        assert values == ["alpha", "beta", "gamma"]

    def test_filter_no_matches_returns_empty_list(self, dummy_pipeline):
        """When filter matches no extracted values the result is an empty list."""
        data = json.dumps({"hosts": ["fe80::1", "::1", "2001:db8::"]})
        t = FilePlaceholderTransformation(
            path=PLAINTEXT_FILE,
            policy=_ALLOW_EXTERNAL_POLICY,
            format="json",
            jq_expression=".hosts[]",
            filter=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
        )
        t.set_pipeline(dummy_pipeline)
        with patch.object(t, "_fetch_data", return_value=data):
            values = t._get_values()
        assert values == []
