from dataclasses import dataclass, field
import importlib.util
import os
import sys
from typing import Any, Dict

from jinja2.sandbox import SandboxedEnvironment
from jinja2 import FileSystemLoader

from sigma.exceptions import SigmaSecurityError

PYSIGMA_ALLOW_VARS_EXECUTION_ENV = "PYSIGMA_ALLOW_VARS_EXECUTION"


@dataclass
class TemplateBase:
    """Base class for Jinja template postprocessors and finalizers.

    If *vars* is provided, it should point to a Python file containing helper functions
    and variables to be made available in the Jinja2 template context. The Python file
    should define a dictionary named 'vars' containing the functions/variables to export.

    **Security warning:** The *vars* feature executes arbitrary Python code from the
    specified file. It is disabled by default and must be explicitly enabled via the
    *allow_template_vars* parameter or by setting the environment variable
    ``PYSIGMA_ALLOW_VARS_EXECUTION=1``.

    When enabled, the resolved vars file path is checked against *vars_allowed_paths*.
    The file must reside under (or in a subdirectory of) one of the listed base
    directories. If *vars_allowed_paths* is ``None`` no path restriction is applied.

    Example Python vars file:
        def format_price(amount, currency='€'):
            return f'{amount:.2f}{currency}'

        vars = {
            'format_price': format_price,
        }
    """

    template: str
    path: str | None = None
    autoescape: bool = False
    vars: str | None = None
    allow_template_vars: bool = False
    vars_allowed_paths: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if self.path is None:
            env = SandboxedEnvironment(autoescape=self.autoescape)
            self.j2template = env.from_string(self.template)
        else:
            env = SandboxedEnvironment(
                autoescape=self.autoescape, loader=FileSystemLoader(self.path)
            )
            self.j2template = env.get_template(self.template)

        # Load custom variables/functions from Python file if provided
        if self.vars is not None:
            if not self._vars_execution_allowed():
                raise SigmaSecurityError(
                    "The 'vars' feature executes Python code from an external file and is "
                    "disabled by default for security reasons. To enable it, pass "
                    "allow_template_vars=True when constructing the pipeline or set the environment "
                    f"variable {PYSIGMA_ALLOW_VARS_EXECUTION_ENV}=1."
                )
            custom_vars = self._load_vars_from_file(self.vars)
            self.j2template.globals.update(custom_vars)

    def _vars_execution_allowed(self) -> bool:
        """Check if vars execution is allowed via parameter or environment variable."""
        if self.allow_template_vars:
            return True
        return os.environ.get(PYSIGMA_ALLOW_VARS_EXECUTION_ENV, "").lower() in ("1", "true")

    def _load_vars_from_file(self, vars_path: str) -> Any:
        """Load variables and functions from a Python file.

        The Python file should define a dictionary named 'vars' containing
        the functions/variables to make available in templates.

        :param vars_path: Path to the Python file
        :return: Dictionary of variables to add to template globals
        """
        vars_path = os.path.realpath(vars_path)

        if self.vars_allowed_paths is not None:
            if not any(
                vars_path.startswith(os.path.realpath(base) + os.sep)
                or vars_path == os.path.realpath(base)
                for base in self.vars_allowed_paths
            ):
                raise SigmaSecurityError(
                    f"Vars file '{vars_path}' is outside the allowed base directories: "
                    f"{', '.join(os.path.realpath(p) for p in self.vars_allowed_paths)}"
                )

        try:
            spec = importlib.util.spec_from_file_location("template_vars", vars_path)
        except (FileNotFoundError, OSError) as e:
            raise ValueError(f"Could not load vars file: {vars_path}") from e

        if spec is None or spec.loader is None:
            raise ValueError(f"Could not load vars file: {vars_path}")

        module_name = f"_pysigma_template_vars_{id(spec)}"
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module

        try:
            spec.loader.exec_module(module)
        except FileNotFoundError as e:
            raise ValueError(f"Could not load vars file: {vars_path}") from e
        finally:
            sys.modules.pop(module_name, None)

        if not hasattr(module, "vars"):
            raise ValueError(f"Vars file {vars_path} must define a 'vars' dictionary")

        return module.vars
