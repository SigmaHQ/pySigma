import pytest
from sigma.exceptions import (
    SigmaPipelineNotAllowedForBackendError,
    SigmaPipelineNotFoundError,
)
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import (
    AddFieldnamePrefixTransformation,
    AddFieldnameSuffixTransformation,
)
from collections.abc import Iterable


@pytest.fixture
def processing_pipeline_resolver():
    return ProcessingPipelineResolver.from_pipeline_list(
        [
            ProcessingPipeline(
                items=[ProcessingItem(AddFieldnameSuffixTransformation(".item-1"))],
                name="pipeline-1",
                priority=10,
            ),
            ProcessingPipeline(
                items=[ProcessingItem(AddFieldnameSuffixTransformation(".item-2"))],
                name="pipeline-2",
                priority=10,
            ),
            ProcessingPipeline(
                items=[ProcessingItem(AddFieldnameSuffixTransformation(".item-3"))],
                name="pipeline-3",
                allowed_backends={"some_backend"},
                priority=20,
            ),
        ]
    )


def test_resolve_order(processing_pipeline_resolver: ProcessingPipelineResolver):
    assert processing_pipeline_resolver.resolve(
        ["pipeline-3", "pipeline-2", "pipeline-1"]
    ).items == [
        ProcessingItem(AddFieldnameSuffixTransformation(".item-1")),
        ProcessingItem(AddFieldnameSuffixTransformation(".item-2")),
        ProcessingItem(AddFieldnameSuffixTransformation(".item-3")),
    ]


def test_resolve_file(processing_pipeline_resolver: ProcessingPipelineResolver):
    assert processing_pipeline_resolver.resolve_pipeline(
        "tests/files/pipeline.yml"
    ) == ProcessingPipeline(
        items=[
            ProcessingItem(
                AddFieldnameSuffixTransformation(".test"),
                identifier="test",
            )
        ],
        name="Test",
        priority=10,
    )


@pytest.fixture
def restricted_pipeline_file(tmp_path):
    pipeline_file = tmp_path / "pipeline.yml"
    pipeline_file.write_text(
        "name: restricted\nallowed_backends: [some_backend]\ntransformations: []\n",
        encoding="utf-8",
    )
    return pipeline_file


@pytest.mark.parametrize("source", ["single_file", "file_list", "directory"])
def test_resolve_file_backend_incompatible(restricted_pipeline_file, source):
    resolver = ProcessingPipelineResolver()
    spec = str(restricted_pipeline_file)
    with pytest.raises(SigmaPipelineNotAllowedForBackendError) as exc:
        if source == "single_file":
            resolver.resolve_pipeline(spec, "other_backend")
        elif source == "file_list":
            resolver.resolve([spec], "other_backend")
        else:
            resolver.resolve([str(restricted_pipeline_file.parent)], "other_backend")
    assert exc.value.wrong_pipeline == spec
    assert exc.value.backend == "other_backend"


@pytest.mark.parametrize("source", ["single_file", "file_list", "directory"])
@pytest.mark.parametrize("target", ["some_backend", None])
def test_resolve_file_backend_compatible(restricted_pipeline_file, source, target):
    resolver = ProcessingPipelineResolver()
    spec = str(restricted_pipeline_file)
    if source == "single_file":
        pipeline = resolver.resolve_pipeline(spec, target)
    elif source == "file_list":
        pipeline = resolver.resolve([spec], target)
    else:
        pipeline = resolver.resolve([str(restricted_pipeline_file.parent)], target)
    assert pipeline.name == "restricted"


@pytest.mark.parametrize("allowed_backends", ["", "allowed_backends: []\n"])
def test_resolve_file_backend_unrestricted(tmp_path, allowed_backends):
    pipeline_file = tmp_path / "pipeline.yml"
    pipeline_file.write_text(
        "name: unrestricted\n" + allowed_backends + "transformations: []\n",
        encoding="utf-8",
    )
    pipeline = ProcessingPipelineResolver().resolve_pipeline(str(pipeline_file), "any_backend")
    assert pipeline.name == "unrestricted"


def test_resolve_directory(processing_pipeline_resolver):
    assert processing_pipeline_resolver.resolve(["tests/files/pipelines"]) == ProcessingPipeline(
        items=[
            ProcessingItem(
                AddFieldnameSuffixTransformation(".test"),
                identifier="test-1",
            ),
            ProcessingItem(
                AddFieldnamePrefixTransformation("test."),
                identifier="test-2",
            ),
        ],
    )


def test_resolve_callable():
    pipeline = ProcessingPipeline(
        [ProcessingItem(AddFieldnameSuffixTransformation(".item-1"))],
        name="test",
        priority=10,
    )

    def pipeline_func():
        return pipeline

    resolver = ProcessingPipelineResolver(
        {
            "test": pipeline_func,
        }
    )
    assert resolver.resolve_pipeline("test") == pipeline


def test_resolve_callable_backend_incompatible():
    resolver = ProcessingPipelineResolver(
        {
            "restricted": lambda: ProcessingPipeline(
                name="restricted", allowed_backends={"some_backend"}
            )
        }
    )
    with pytest.raises(SigmaPipelineNotAllowedForBackendError) as exc:
        resolver.resolve_pipeline("restricted", "other_backend")
    assert exc.value.wrong_pipeline == "restricted"
    assert exc.value.backend == "other_backend"


def test_resolve_failed_not_found(
    processing_pipeline_resolver: ProcessingPipelineResolver,
):
    with pytest.raises(SigmaPipelineNotFoundError, match="pipeline.*notexisting.*not found"):
        processing_pipeline_resolver.resolve_pipeline("notexisting")


def test_resolve_failed_incompatible(
    processing_pipeline_resolver: ProcessingPipelineResolver,
):
    with pytest.raises(
        SigmaPipelineNotAllowedForBackendError,
        match="not allowed for backend.*pipeline-3",
    ):
        processing_pipeline_resolver.resolve_pipeline("pipeline-3", "test")


def test_resolve_backend_compatible(
    processing_pipeline_resolver: ProcessingPipelineResolver,
):
    assert (
        processing_pipeline_resolver.resolve_pipeline("pipeline-3", "some_backend").name
        == "pipeline-3"
    )


def test_resolve_backend_compatible_not_specified(
    processing_pipeline_resolver: ProcessingPipelineResolver,
):
    assert (
        processing_pipeline_resolver.resolve_pipeline("pipeline-2", "any_backend").name
        == "pipeline-2"
    )


def test_resolve_backend_incompatible(processing_pipeline_resolver: ProcessingPipelineResolver):
    with pytest.raises(
        SigmaPipelineNotAllowedForBackendError,
        match="not allowed for backend.*test.*pipeline-3",
    ):
        processing_pipeline_resolver.resolve_pipeline("pipeline-3", "test")


def test_resolver_add_class():
    resolver = ProcessingPipelineResolver()
    pipeline = ProcessingPipeline(name="test", items=[])
    resolver.add_pipeline_class(pipeline)
    assert resolver.pipelines == {"test": pipeline}


def test_resolver_add_class_unnamed():
    resolver = ProcessingPipelineResolver()
    pipeline = ProcessingPipeline([])
    with pytest.raises(ValueError, match="must be named"):
        resolver.add_pipeline_class(pipeline)


def test_resolver_nothing(processing_pipeline_resolver: ProcessingPipelineResolver):
    assert processing_pipeline_resolver.resolve([]) == ProcessingPipeline()


def test_resolver_list(processing_pipeline_resolver: ProcessingPipelineResolver):
    pipelines = processing_pipeline_resolver.list_pipelines()
    assert isinstance(pipelines, Iterable)
    pipelines = list(pipelines)
    assert len(pipelines) == 3
    pipeline = pipelines[0]
    assert pipeline[0] == "pipeline-1"
    assert isinstance(pipeline[1], ProcessingPipeline)
