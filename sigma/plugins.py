from dataclasses import dataclass, field
from enum import Enum, auto
from importlib import import_module
import importlib
import importlib.metadata
import pkgutil
import pkg_resources
from typing import Callable, Dict, Any, Optional, Set
from uuid import UUID
import requests
from packaging.version import Version
from packaging.specifiers import Specifier

from sigma.conversion.base import Backend
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import EnumLowercaseStringMixin
from sigma.validators.base import SigmaRuleValidator
import sigma.backends
import sigma.pipelines
import sigma.validators

default_plugin_directory = "https://raw.githubusercontent.com/SigmaHQ/pySigma-plugin-directory/main/pySigma-plugins-v0.json"

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

class SigmaPluginType(EnumLowercaseStringMixin, Enum):
    BACKEND   = auto()
    PIPELINE  = auto()
    VALIDATOR = auto()

class SigmaPluginState(EnumLowercaseStringMixin, Enum):
    STABLE   = auto()
    TESTING  = auto()
    DEVEL    = auto()
    BROKEN   = auto()
    ORPHANED = auto()

@dataclass
class SigmaPlugin:
    """Sigma plugin description corresponding to https://github.com/SigmaHQ/pySigma-plugin-directory#format"""
    uuid : UUID
    type : SigmaPluginType
    id : str
    description : str
    package : str
    project_url : str
    report_issue_url : str
    state : SigmaPluginState
    pysigma_version : Specifier

    @classmethod
    def from_dict(cls, d: Dict) -> "SigmaPlugin":
        """Construct a SigmaPlugin object from a dict that results in parsing a plugin description
        from the JSON format linked above."""
        kwargs = {
            k.replace("-", "_"): v
            for k, v in d.items()
        }
        kwargs["uuid"] = UUID(kwargs["uuid"])
        kwargs["pysigma_version"] = Specifier(kwargs["pysigma_version"])
        kwargs["type"] = SigmaPluginType[ kwargs["type"].upper() ]
        kwargs["state"] = SigmaPluginState[ kwargs["state"].upper() ]

        return cls(**kwargs)

    def is_compatible(self):
        """Checks if the pySigma version specifier of the plugin matches the used pySigma
        version."""
        pysigma_version = Version(importlib.metadata.version("pysigma"))
        return pysigma_version in self.pysigma_version

@dataclass
class SigmaPluginDirectory:
    """A directory of pySigma plugins that can be loaded from the pySigma-plugin-directory
    repository or an arbitrary location."""
    plugins : Dict[UUID, SigmaPlugin] = field(default_factory=dict)
    note : Optional[str] = None

    def register_plugin(self, plugin : SigmaPlugin):
        self.plugins[plugin.uuid] = plugin

    @classmethod
    def from_dict(cls, d : Dict):
        return cls(
            plugins={
                UUID(uuid): SigmaPlugin.from_dict({"uuid": uuid, **plugin_dict})
                for uuid, plugin_dict in d["plugins"].items()
            },
            note=d.get("note", None),
        )

    @classmethod
    def from_url(cls, url : str, *args, **kwargs) -> "SigmaPluginDirectory":
        """Loads the plugin directory from an arbitrary location. All further
        arguments are passed to requests.get()."""
        response = requests.get(url, *args, **kwargs)
        response.raise_for_status()
        return cls.from_dict(response.json())

    @classmethod
    def default_plugin_directory(cls, *args, **kwargs):
        """Loads the plugin directory from the pySigma-plugin-directory repository. All further
        arguments are passed to requests.get()."""
        return cls.from_url(default_plugin_directory, *args, **kwargs)