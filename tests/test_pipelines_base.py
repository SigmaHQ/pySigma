import sigma.pipelines.test
from sigma.pipelines.base import Pipeline
from sigma.pipelines.test import dummy_test_pipeline
from sigma.pipelines.test.pipeline import YetAnotherTestPipeline
from sigma.plugins import InstalledSigmaPlugins
from sigma.processing.pipeline import ProcessingPipeline


def test_pipeline_decorator_creates_distinct_objects():
    @Pipeline
    def first_pipeline() -> ProcessingPipeline:
        return ProcessingPipeline(name="first")

    @Pipeline
    def second_pipeline() -> ProcessingPipeline:
        return ProcessingPipeline(name="second")

    assert first_pipeline is not second_pipeline
    assert first_pipeline().name == "first"
    assert second_pipeline().name == "second"
    assert dummy_test_pipeline().name == "Test pipeline"


def test_pipeline_subclass_not_aliased_to_decorated_pipeline():
    pipeline = YetAnotherTestPipeline()
    assert isinstance(pipeline, YetAnotherTestPipeline)
    assert pipeline is not dummy_test_pipeline
    assert pipeline().name == "Yet Another Test pipeline"


def test_pipeline_subclass_is_singleton():
    assert YetAnotherTestPipeline() is YetAnotherTestPipeline()


def test_pipeline_subclass_of_subclass_has_own_instance():
    class DerivedPipeline(YetAnotherTestPipeline):
        def apply(self) -> ProcessingPipeline:
            return ProcessingPipeline(name="Derived pipeline")

    derived = DerivedPipeline()
    assert isinstance(derived, DerivedPipeline)
    assert derived is DerivedPipeline()
    assert derived().name == "Derived pipeline"
    assert YetAnotherTestPipeline()().name == "Yet Another Test pipeline"


def test_autodiscover_ignores_pipeline_base_class(monkeypatch):
    # A plugin module that exports the Pipeline base class it uses as decorator.
    monkeypatch.setattr(sigma.pipelines.test, "Pipeline", Pipeline, raising=False)
    monkeypatch.setattr(
        sigma.pipelines.test, "__all__", [*sigma.pipelines.test.__all__, "Pipeline"]
    )
    pipelines = InstalledSigmaPlugins.autodiscover(
        include_backends=False, include_validators=False
    ).pipelines
    assert "Pipeline" not in pipelines
    assert pipelines["dummy_test"]().name == "Test pipeline"
    assert pipelines["YetAnotherTestPipeline"]().name == "Yet Another Test pipeline"
