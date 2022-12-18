from dataclasses import dataclass, field
from importlib import import_module
import importlib
import pkgutil
from typing import Callable, Dict, Any

from sigma.conversion.base import Backend
from sigma.processing.pipeline import ProcessingPipeline
from sigma.validators.base import SigmaRuleValidator
import sigma.backends
import sigma.pipelines
import sigma.validators

@dataclass
class SigmaPlugins:
    """Discovery and registrstion of installed backends, pipelines and validator checks as plugins.

    This class represents a set of the objects mentioned above that are available. Further it implements
    autodiscovery of them in the sigma.backends, sigma.pipelines and sigma.validators module namespaces.
    """
    backends : Dict[str, Backend] = field(default_factory=list)
    pipelines : Dict[str, Callable[[], ProcessingPipeline]] = field(default_factory=list)
    validators : Dict[str, SigmaRuleValidator] = field(default_factory=list)

    def register_backend(self, id : str, backend : Backend):
        self.backends[id] = backend

    def register_pipeline(self, id : str, pipeline : Callable[[], ProcessingPipeline]):
        self.pipelines[id] = pipeline

    def register_validator(self, id : str, validator : SigmaRuleValidator):
        self.validators[id] = validator

    @classmethod
    def _discover_module_directories(cls, module, directory_name : str, include : bool) -> Dict[str, Any]:
        result = dict()
        if include:
            for module in pkgutil.iter_modules(module.__path__, module.__name__ + "."):
                try:        # attempt to merge backend directory from module into collected backend directory
                    imported_module = importlib.import_module(module.name)
                    directory = imported_module.__dict__[directory_name]
                    result.update(directory)
                except KeyError:
                    pass
        return result


    @classmethod
    def autodiscover(cls, include_backends : bool = True, include_pipelines : bool = True, include_validators : bool = True):
        """Automatically discovers backends, pipelines and validators in their corresponding module
        namespaces and return a SigmaPlugins class containing all identified classes and generators.
        """
        backends = cls._discover_module_directories(sigma.backends, "backends", include_backends)
        pipelines = cls._discover_module_directories(sigma.pipelines, "pipelines", include_pipelines)
        validators = cls._discover_module_directories(sigma.validators, "validators", include_validators)

        return cls(backends, pipelines, validators)