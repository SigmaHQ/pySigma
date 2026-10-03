"""Regression tests for template sandbox escapes from untrusted processing pipelines."""

import os
import platform

import pytest
from jinja2.exceptions import SecurityError

from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaConfigurationError, SigmaSecurityError
from sigma.processing.pipeline import ProcessingPipeline


@pytest.fixture
def rule_collection():
    return SigmaCollection.from_yaml("""
title: Test Title
status: test
logsource:
    category: test
detection:
    sel:
        fieldA: value
    condition: sel
""")


def convert(pipeline: ProcessingPipeline, rule_collection):
    return TextQueryTestBackend(pipeline).convert(rule_collection)


def nested_command_template(marker: str) -> str:
    return (
        "{{ pipeline.from_yaml(\"transformations: [{type: command_placeholders, cmd: 'touch "
        + marker
        + "'}]\", allow_external_sources=true).items[0].transformation"
        ".placeholder_replacements(none) }}"
    )


@pytest.mark.parametrize("section", ["finalizers", "postprocessing"])
def test_template_pipeline_classmethod_call_blocked(tmp_path, rule_collection, section):
    marker = tmp_path / "pwned"
    pipeline = ProcessingPipeline.from_dict(
        {section: [{"type": "template", "template": nested_command_template(str(marker).replace("\\", "\\\\"))}]}
    )
    with pytest.raises(SecurityError, match="not safely callable"):
        convert(pipeline, rule_collection)
    assert not marker.exists()


@pytest.mark.parametrize(
    "template",
    [
        "{{ rule.to_dict() }}",
        "{{ pipeline.field_was_processed_by('fieldA', 'x') }}",
        "{{ pipeline.apply(rule) }}",
        "{{ rule.__class__.from_yaml }}",
    ],
)
def test_template_live_object_methods_blocked(rule_collection, template):
    pipeline = ProcessingPipeline.from_dict(
        {"postprocessing": [{"type": "template", "template": template}]}
    )
    with pytest.raises(SecurityError):
        convert(pipeline, rule_collection)


def test_template_legitimate_usage(rule_collection):
    pipeline = ProcessingPipeline.from_dict(
        {
            "vars": {"index": "main"},
            "postprocessing": [
                {
                    "type": "template",
                    "template": "{{ rule.title | upper }}|{{ query.replace('mappedA', 'f') }}|"
                    "{{ pipeline.vars.get('index') }}|{{ 'a,b'.split(',') | join('+') }}|"
                    "{% for i in range(2) %}{{ loop.index }}{% endfor %}",
                }
            ],
        }
    )
    assert convert(pipeline, rule_collection) == ['TEST TITLE|f="value"|main|a+b|12']


def test_template_finalizer_legitimate_usage(rule_collection):
    pipeline = ProcessingPipeline.from_dict(
        {
            "finalizers": [
                {"type": "template", "template": "{{ queries | join(' OR ') | lower }}"}
            ],
        }
    )
    assert convert(pipeline, rule_collection) == 'mappeda="value"'


@pytest.fixture
def secret_dir(tmp_path):
    d = tmp_path / "secret"
    d.mkdir()
    (d / "creds").write_text("SECRET=hunter2\n")
    return d


@pytest.fixture
def pipeline_dir(tmp_path):
    d = tmp_path / "pipelines"
    (d / "templates").mkdir(parents=True)
    (d / "templates" / "tpl.j2").write_text("tpl:{{ query }}")
    return d


@pytest.mark.parametrize("section", ["finalizers", "postprocessing"])
def test_template_path_without_base_dir_blocked(secret_dir, section):
    with pytest.raises(SigmaSecurityError, match="no allowed base directory"):
        ProcessingPipeline.from_yaml(
            f"{section}:\n  - type: template\n    path: {secret_dir}\n    template: creds\n"
        )


def test_template_path_outside_pipeline_dir_blocked(secret_dir, pipeline_dir):
    with pytest.raises(SigmaSecurityError, match="outside the allowed base directories"):
        ProcessingPipeline.from_yaml(
            f"postprocessing:\n  - type: template\n    path: {secret_dir}\n    template: creds\n",
            source_path=str(pipeline_dir / "pipeline.yml"),
        )


def test_template_path_restriction_not_overridable_from_yaml(secret_dir):
    with pytest.raises(SigmaSecurityError):
        ProcessingPipeline.from_yaml(
            "postprocessing:\n  - type: template\n"
            f"    path: {secret_dir}\n    template: creds\n    restrict_template_path: false\n"
        )


@pytest.mark.skipif(platform.system() == "Windows", reason="Symlink test not supported on Windows")
def test_template_path_symlink_escape_blocked(secret_dir, pipeline_dir, rule_collection):
    os.symlink(secret_dir / "creds", pipeline_dir / "templates" / "link.j2")
    with pytest.raises(Exception, match="link.j2"):
        ProcessingPipeline.from_yaml(
            "postprocessing:\n  - type: template\n"
            f"    path: {pipeline_dir / 'templates'}\n    template: link.j2\n",
            source_path=str(pipeline_dir / "pipeline.yml"),
        )


def test_template_path_below_pipeline_dir_allowed(pipeline_dir, rule_collection):
    pipeline = ProcessingPipeline.from_yaml(
        "postprocessing:\n  - type: template\n"
        f"    path: {pipeline_dir / 'templates'}\n    template: tpl.j2\n",
        source_path=str(pipeline_dir / "pipeline.yml"),
    )
    assert convert(pipeline, rule_collection) == ['tpl:mappedA="value"']


def test_template_path_allowed_with_external_sources_opt_in(secret_dir, rule_collection):
    pipeline = ProcessingPipeline.from_yaml(
        f"postprocessing:\n  - type: template\n    path: {secret_dir}\n    template: creds\n",
        allow_external_sources=True,
    )
    assert convert(pipeline, rule_collection) == ["SECRET=hunter2"]


def test_simple_template_globals_traversal_blocked(rule_collection, monkeypatch):
    monkeypatch.setenv("PS_SECRET", "envsecret42")
    pipeline = ProcessingPipeline.from_yaml(
        "postprocessing:\n  - type: simple_template\n"
        '    template: "{pipeline.set_pipeline.__globals__[os].environ[PS_SECRET]}"\n'
    )
    with pytest.raises(SigmaSecurityError, match="__globals__"):
        convert(pipeline, rule_collection)


def test_simple_template_huge_format_spec_blocked(rule_collection):
    pipeline = ProcessingPipeline.from_yaml(
        "postprocessing:\n  - type: simple_template\n" '    template: "{query:>999999999}"\n'
    )
    with pytest.raises(SigmaConfigurationError, match="size limit"):
        convert(pipeline, rule_collection)


def test_simple_template_legitimate_usage(rule_collection):
    pipeline = ProcessingPipeline.from_yaml(
        "vars:\n  index: main\n"
        "postprocessing:\n  - type: simple_template\n"
        '    template: "[{rule.title}] {query} ({pipeline.vars[index]}) {rule.title:>12.4}"\n',
    )
    assert convert(pipeline, rule_collection) == [
        '[Test Title] mappedA="value" (main)         Test'
    ]
