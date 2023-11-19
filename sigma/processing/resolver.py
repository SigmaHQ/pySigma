from dataclasses import dataclass, field
from sigma.exceptions import (
    SigmaPipelineNotAllowedForBackendError,
    SigmaPipelineNotFoundError,
)
from sigma.processing.pipeline import ProcessingPipeline
from typing import Callable, Dict, Iterable, List, Optional, Tuple, Union


@dataclass
class ProcessingPipelineResolver:
    """
    A processing pipeline resolver resolves a list of pipeline specifiers into one summarized processing pipeline.
    It takes care of sorting by priority and resolution of filenames as well as pipeline name identifiers.
    """

    pipelines: Dict[str, Union[ProcessingPipeline, Callable[[], ProcessingPipeline]]] = field(
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
        return cls({pipeline.name: pipeline for pipeline in pipelines})

    def list_pipelines(self) -> Iterable[Tuple[str, ProcessingPipeline]]:
        """List identifier/processing pipeline tuples."""
        return ((id, self.resolve_pipeline(id)) for id in self.pipelines.keys())

    def resolve_pipeline(self, spec: str, target: Optional[str] = None) -> ProcessingPipeline:
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
            if isinstance(pipeline, Callable):
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
                return ProcessingPipeline.from_yaml(open(spec, "r").read())
            except OSError as e:
                raise SigmaPipelineNotFoundError(spec)

    def resolve(
        self, pipeline_specs: List[str], target: Optional[str] = None
    ) -> ProcessingPipeline:
        """
        Resolve a list of

        * processing pipeline names from pipelines added to the resolver or
        * file paths containing processing pipeline YAML definitions

        into a consolidated processing piepline.

        If *target* is specified this is passed in each *resolve_pipeline* call to perform a
        compatibility check for the usage of the specified backend with the pipeline.
        """
        return (
            sum(
                sorted(
                    [self.resolve_pipeline(spec, target) for spec in pipeline_specs],
                    key=lambda p: p.priority,
                )
            )
            or ProcessingPipeline()
        )
