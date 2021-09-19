from dataclasses import dataclass, field
from sigma.processing.pipeline import ProcessingPipeline
from typing import Callable, Dict, Iterable, List, Union

@dataclass
class ProcessingPipelineResolver:
    """
    A processing pipeline resolver resolves a list of pipeline specifiers into one summarized processing pipeline.
    It takes care of sorting by priority and resolution of filenames as well as pipeline name identifiers.
    """
    pipelines : Dict[str, Union[ProcessingPipeline, Callable[[], ProcessingPipeline]]] = field(default_factory=dict)

    def add_pipeline_class(self, pipeline : ProcessingPipeline) -> None:
        """Add named processing pipeline object to resolver. This pipeline can be resolved by the name."""
        if pipeline.name is None:
            raise ValueError("Processing pipeline must be named to be resolvable.")
        self.pipelines[pipeline.name] = pipeline

    @classmethod
    def from_pipeline_list(cls, pipelines : Iterable[ProcessingPipeline]) -> "ProcessingPipelineResolver":
        """Instantiate processing pipeline resolver from list of pipeline objects."""
        return cls({
            pipeline.name: pipeline
            for pipeline in pipelines
        })

    def resolve_pipeline(self, spec : str) -> ProcessingPipeline:
        """Resolve single processing pipeline."""
        try:
            pipeline = self.pipelines[spec]
            if isinstance(pipeline, Callable):
                return pipeline()
            else:
                return pipeline
        except KeyError:        # identifier not found, try it as path
            try:
                return ProcessingPipeline.from_yaml(open(spec, "r").read())
            except OSError as e:
                raise ValueError(f"Failed to handle specifier as identifier and file name ({ str(e) })")

    def resolve(self, pipeline_specs : List[str]) -> ProcessingPipeline:
        """
        Resolve a list of

        * processing pipeline names from pipelines added to the resolver or
        * file paths containing processing pipeline YAML definitions

        into a consolidated processing piepline.
        """
        return sum(
                sorted([
                    self.resolve_pipeline(spec)
                    for spec in pipeline_specs
                ],
                key=lambda p: p.priority
            )
        ) or ProcessingPipeline()