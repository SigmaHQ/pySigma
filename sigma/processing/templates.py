from dataclasses import dataclass
from typing import Optional

from jinja2 import Environment, FileSystemLoader, Template


@dataclass
class TemplateBase:
    """Base class for Jinja template postprocessors and finalizers."""

    template: str
    path: Optional[str] = None
    autoescape: bool = False

    def __post_init__(self):
        if self.path is None:
            self.j2template = Template(self.template, autoescape=self.autoescape)
        else:
            env = Environment(autoescape=self.autoescape, loader=FileSystemLoader(self.path))
            self.j2template = env.get_template(self.template)
