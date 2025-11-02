from dataclasses import dataclass
import importlib.util
import sys
from typing import Any, Dict, Optional

from jinja2 import Environment, FileSystemLoader, Template


@dataclass
class TemplateBase:
    """Base class for Jinja template postprocessors and finalizers.

    If *vars* is provided, it should point to a Python file containing helper functions
    and variables to be made available in the Jinja2 template context. The Python file
    should define a dictionary named 'vars' containing the functions/variables to export.

    Example Python vars file:
        def format_price(amount, currency='€'):
            return f'{amount:.2f}{currency}'

        vars = {
            'format_price': format_price,
        }
    """

    template: str
    path: Optional[str] = None
    autoescape: bool = False
    vars: Optional[str] = None

    def __post_init__(self) -> None:
        if self.path is None:
            env = Environment(autoescape=self.autoescape)
            self.j2template = env.from_string(self.template)
        else:
            env = Environment(autoescape=self.autoescape, loader=FileSystemLoader(self.path))
            self.j2template = env.get_template(self.template)

        # Load custom variables/functions from Python file if provided
        if self.vars is not None:
            custom_vars = self._load_vars_from_file(self.vars)
            self.j2template.globals.update(custom_vars)

    def _load_vars_from_file(self, vars_path: str) -> Any:
        """Load variables and functions from a Python file.

        The Python file should define a dictionary named 'vars' containing
        the functions/variables to make available in templates.

        :param vars_path: Path to the Python file
        :return: Dictionary of variables to add to template globals
        """
        try:
            spec = importlib.util.spec_from_file_location("template_vars", vars_path)
        except (FileNotFoundError, OSError) as e:
            raise ValueError(f"Could not load vars file: {vars_path}") from e

        if spec is None or spec.loader is None:
            raise ValueError(f"Could not load vars file: {vars_path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules["template_vars"] = module

        try:
            spec.loader.exec_module(module)
        except FileNotFoundError as e:
            raise ValueError(f"Could not load vars file: {vars_path}") from e

        if not hasattr(module, "vars"):
            raise ValueError(f"Vars file {vars_path} must define a 'vars' dictionary")

        return module.vars
