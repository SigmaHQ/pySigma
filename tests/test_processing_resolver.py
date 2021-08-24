import pytest
from sigma.processing.resolver import ProcessingPipelineResolver
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import AddFieldnameSuffixTransformation

@pytest.fixture
def processing_pipeline_resolver():
    return ProcessingPipelineResolver.from_pipeline_list([
        ProcessingPipeline([
            ProcessingItem(
                AddFieldnameSuffixTransformation(".item-1")
            )
        ],
        name="pipeline-1",
        priority=10,
        ),
        ProcessingPipeline([
            ProcessingItem(
                AddFieldnameSuffixTransformation(".item-2")
            )
        ],
        name="pipeline-2",
        priority=10,
        ),
        ProcessingPipeline([
            ProcessingItem(
                AddFieldnameSuffixTransformation(".item-3")
            )
        ],
        name="pipeline-3",
        priority=20,
        ),
    ])

def test_resolve_order(processing_pipeline_resolver : ProcessingPipelineResolver):
    assert processing_pipeline_resolver.resolve(["pipeline-3", "pipeline-2", "pipeline-1"]).items == [
            ProcessingItem(
                AddFieldnameSuffixTransformation(".item-2")
            ),
            ProcessingItem(
                AddFieldnameSuffixTransformation(".item-1")
            ),
            ProcessingItem(
                AddFieldnameSuffixTransformation(".item-3")
            ),
    ]

def test_resolve_file(processing_pipeline_resolver : ProcessingPipelineResolver):
    assert processing_pipeline_resolver.resolve_pipeline("tests/files/pipeline.yml") == ProcessingPipeline(
        [
            ProcessingItem(
                AddFieldnameSuffixTransformation(".test"),
                identifier="test",
            )
        ],
        name="Test",
        priority=10,
    )

def test_resolve_failed(processing_pipeline_resolver : ProcessingPipelineResolver):
    with pytest.raises(ValueError, match="Failed to handle specifier"):
        processing_pipeline_resolver.resolve_pipeline("error")

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