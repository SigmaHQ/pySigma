from dataclasses import dataclass, field
from functools import reduce
from pathlib import Path
from sigma.exceptions import (
    SigmaPipelineNotAllowedForBackendError,
    SigmaPipelineNotFoundError,
)
from sigma.processing.pipeline import ProcessingPipeline
from typing import Iterable, cast, Callable
from collections import namedtuple


@dataclass
class ProcessingPipelineResolver:
    """
    A processing pipeline resolver resolves a list of pipeline specifiers into one summarized
    processing pipeline. It handles sorting by priority, resolution of filenames, and pipeline
    name identifiers.

    **Key Feature:** When combining multiple pipelines, the resolver sorts them by their
    priority value (lowest first) before merging, ensuring pipelines are applied in the
    intended order. This is different from simple addition (``+``), which concatenates
    pipelines without considering priorities.
    """

    pipelines: dict[str, ProcessingPipeline | Callable[[], ProcessingPipeline]] = field(
        default_factory=dict
    )

    def add_pipeline_class(self, pipeline: ProcessingPipeline) -> None:
        """Add named processing pipeline object to resolver. This pipeline can be resolved by the name."""
        if pipeline.name is None:
            raise ValueError("Processing pipeline must be named to be resolvable.")
        self.pipelines[pipeline.name] = pipeline

    @classmethod
    def from_pipeline_list(
        cls, pipelines: Iterable[ProcessingPipeline]
    ) -> "ProcessingPipelineResolver":
        """Instantiate processing pipeline resolver from list of pipeline objects."""
        return cls({pipeline.name: pipeline for pipeline in pipelines if pipeline.name is not None})

    def list_pipelines(self) -> Iterable[tuple[str, ProcessingPipeline]]:
        """List identifier/processing pipeline tuples."""
        return ((id, self.resolve_pipeline(id)) for id in self.pipelines.keys())

    def resolve_pipeline(self, spec: str, target: str | None = None) -> ProcessingPipeline:
        """
        Resolve single processing pipeline. It first tries to find a pipeline with this identifier
        in the registered pipelines. If this fails, *spec* is treated as file name. If this fails
        too, a *SigmaPipelineNotFoundError* is raised.

        If *target* is specified, an additional check of the compatibility of the specified backend
        to the resolved pipeline is conducted. A *SigmaPipelineNotAllowedForBackendError* is raised
        if this check fails.
        """
        try:
            pipeline = self.pipelines[spec]
            if callable(pipeline):
                resolved_pipeline = pipeline()
            else:
                resolved_pipeline = pipeline
            if target is not None and not (
                len(resolved_pipeline.allowed_backends) == 0
                or target in resolved_pipeline.allowed_backends
            ):
                raise SigmaPipelineNotAllowedForBackendError(spec, target)
            return resolved_pipeline
        except KeyError:  # identifier not found, try it as path
            try:
                with open(spec, "r") as f:
                    return ProcessingPipeline.from_yaml(f.read(), source_path=spec)
            except OSError as e:
                raise SigmaPipelineNotFoundError(spec)

    def resolve(self, pipeline_specs: list[str], target: str | None = None) -> ProcessingPipeline:
        """
        Resolve a list of

        * processing pipeline names from pipelines added to the resolver or
        * file paths containing processing pipeline YAML definitions or
        * directories containing processing pipelines YAML definitions

        into a consolidated processing pipeline.

        **Important:** Pipelines are merged in order of their priority value (lowest first),
        not in the order specified by *pipeline_specs*. This ensures pipelines are applied
        in their intended sequence regardless of the resolution order.

        If *target* is specified this is passed in each *resolve_pipeline* call to perform a
        compatibility check for the usage of the specified backend with the pipeline.
        """

        PipelineInfo = namedtuple("PipelineInfo", ["pipeline", "priority", "path"])

        def resolve_path(spec: str) -> PipelineInfo:
            pipeline = self.resolve_pipeline(spec, target)
            return PipelineInfo(pipeline=pipeline, priority=pipeline.priority, path=spec)

        def resolve_spec(pipelines: list[PipelineInfo], spec: str) -> list[PipelineInfo]:
            spec_path = Path(spec.rstrip("/*"))
            if spec_path.is_dir():
                pipelines.extend([resolve_path(str(path)) for path in spec_path.glob("**/*.yml")])
            else:
                pipelines.append(resolve_path(spec))

            return pipelines

        pipelines: list[PipelineInfo] = reduce(resolve_spec, pipeline_specs, [])

        return (
            sum([p.pipeline for p in sorted(pipelines, key=lambda p: (p.priority, p.path))])
            or ProcessingPipeline()
        )
