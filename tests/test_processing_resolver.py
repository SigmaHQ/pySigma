import pytest
from sigma.exceptions import (
    SigmaPipelineNotAllowedForBackendError,
    SigmaPipelineNotFoundError,
)
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import AddFieldnameSuffixTransformation
from collections.abc import Iterable


@pytest.fixture
def processing_pipeline_resolver():
    return ProcessingPipelineResolver.from_pipeline_list(
        [
            ProcessingPipeline(
                [ProcessingItem(AddFieldnameSuffixTransformation(".item-1"))],
                name="pipeline-1",
                priority=10,
            ),
            ProcessingPipeline(
                [ProcessingItem(AddFieldnameSuffixTransformation(".item-2"))],
                name="pipeline-2",
                priority=10,
            ),
            ProcessingPipeline(
                [ProcessingItem(AddFieldnameSuffixTransformation(".item-3"))],
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
        ProcessingItem(AddFieldnameSuffixTransformation(".item-2")),
        ProcessingItem(AddFieldnameSuffixTransformation(".item-1")),
        ProcessingItem(AddFieldnameSuffixTransformation(".item-3")),
    ]


def test_resolve_file(processing_pipeline_resolver: ProcessingPipelineResolver):
    assert processing_pipeline_resolver.resolve_pipeline(
        "tests/files/pipeline.yml"
    ) == ProcessingPipeline(
        [
            ProcessingItem(
                AddFieldnameSuffixTransformation(".test"),
                identifier="test",
            )
        ],
        name="Test",
        priority=10,
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


def test_resolve_failed_not_found(
    processing_pipeline_resolver: ProcessingPipelineResolver,
):
    with pytest.raises(
        SigmaPipelineNotFoundError, match="pipeline.*notexisting.*not found"
    ):
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
