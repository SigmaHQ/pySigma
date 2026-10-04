from dataclasses import dataclass, field
import datetime
import importlib.util
import os
import re
import sys
import types
import uuid
from string import Formatter
from typing import Any, Callable, Dict, Iterable, Mapping, Sequence, TYPE_CHECKING

from jinja2.sandbox import SandboxedEnvironment, SandboxedFormatter
from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateNotFound
from jinja2.exceptions import SecurityError, UndefinedError

from sigma.exceptions import SigmaConfigurationError, SigmaSecurityError

if TYPE_CHECKING:
    from sigma.policy import SigmaPolicy

PYSIGMA_ALLOW_VARS_EXECUTION_ENV = "PYSIGMA_ALLOW_VARS_EXECUTION"

# Types whose bound methods may be called from templates. Methods of all other objects (in
# particular live pySigma objects like the processing pipeline or rules, whose public methods
# and classmethods can construct new pipelines with security opt-ins enabled or read files)
# are not callable from templates.
_SAFE_METHOD_OWNER_TYPES: frozenset[type] = frozenset(
    {
        str,
        bytes,
        int,
        float,
        complex,
        bool,
        list,
        tuple,
        dict,
        set,
        frozenset,
        datetime.date,
        datetime.datetime,
        datetime.time,
        datetime.timedelta,
        uuid.UUID,
    }
)
_METHOD_TYPES = (
    types.MethodType,
    types.BuiltinMethodType,
    types.MethodWrapperType,
)


def _is_jinja_internal(obj: Any) -> bool:
    """Objects and functions provided by Jinja2 itself (macros, loop helpers, the sandbox's
    str.format wrapper etc.)."""
    if isinstance(obj, types.FunctionType):
        # __module__ of functions may be overwritten by functools.update_wrapper, the module the
        # function code was defined in is determined by its globals.
        module = str(obj.__globals__.get("__name__", ""))
    else:
        module = type(obj).__module__
    return module == "jinja2" or module.startswith("jinja2.")


class SigmaSandboxedEnvironment(SandboxedEnvironment):
    """
    Jinja2 sandbox for pySigma templates.

    The standard sandbox only blocks access to underscore-prefixed attributes and to callables that
    are explicitly marked as unsafe. Templates in pySigma get live objects (the processing pipeline,
    rules) passed in their context, and calling their public methods or classmethods (e.g.
    ``pipeline.from_yaml(..., policy=SigmaPolicy(...))``) escapes the sandbox. Therefore, this
    environment only allows calling:

    * Jinja2 globals and internals (``range``, ``dict``, ``namespace``, macros, loop helpers, ...)
    * methods of plain data types (``str``, ``list``, ``dict``, ``datetime``, ...)
    * callables explicitly registered as trusted (e.g. from an opted-in template vars file)
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._trusted_callables: list[Any] = list(self.globals.values())

    def add_trusted(self, objs: Iterable[Any]) -> None:
        """Mark objects as trusted: they and their bound methods may be called from templates."""
        self._trusted_callables.extend(objs)

    def _is_trusted(self, obj: Any) -> bool:
        return any(obj is trusted for trusted in self._trusted_callables)

    def is_safe_callable(self, obj: Any) -> bool:
        if not super().is_safe_callable(obj):
            return False
        if self._is_trusted(obj):
            return True
        if isinstance(obj, type):  # constructors of arbitrary classes
            return False
        if isinstance(obj, _METHOD_TYPES):
            owner = getattr(obj, "__self__", None)
            if isinstance(owner, (type, types.ModuleType)):  # classmethods, module functions
                return False
            return (
                type(owner) in _SAFE_METHOD_OWNER_TYPES
                or self._is_trusted(owner)
                or _is_jinja_internal(owner)
            )
        return _is_jinja_internal(obj)


class _ConfinedFileSystemLoader(FileSystemLoader):
    """File system loader that refuses templates that resolve (e.g. via symbolic links) to a
    location outside of the search path."""

    def get_source(
        self, environment: Environment, template: str
    ) -> tuple[str, str, Callable[[], bool]]:
        source, filename, uptodate = super().get_source(environment, template)
        real_filename = os.path.realpath(filename)
        if not any(
            real_filename.startswith(os.path.realpath(base) + os.sep) for base in self.searchpath
        ):
            raise TemplateNotFound(template)
        return source, filename, uptodate


class _SigmaSimpleTemplateFormatter(SandboxedFormatter):
    """str.format()-compatible formatter used for simple templates. Field lookups are routed
    through the Jinja2 sandbox (no underscore-prefixed attributes) and format specifications with
    large widths or precisions are rejected."""

    max_format_spec_number = 1000

    def __init__(self) -> None:
        super().__init__(SigmaSandboxedEnvironment(undefined=StrictUndefined))

    def format_field(self, value: Any, format_spec: str) -> Any:
        if any(
            int(number) > self.max_format_spec_number for number in re.findall(r"\d+", format_spec)
        ):
            raise SigmaConfigurationError(
                f"Format specification '{format_spec}' exceeds the allowed size limit of "
                f"{self.max_format_spec_number}."
            )
        return super().format_field(value, format_spec)


def format_simple_template(template: str, **kwargs: Any) -> str:
    """Render a str.format() template in a sandboxed way."""
    try:
        return _SigmaSimpleTemplateFormatter().format(template, **kwargs)
    except SecurityError as e:
        raise SigmaSecurityError(f"Access denied in simple template: {e}") from e
    except UndefinedError as e:
        raise SigmaConfigurationError(f"Undefined value in simple template: {e}") from e


@dataclass
class TemplateBase:
    """Base class for Jinja template postprocessors and finalizers.

    If *vars* is provided, it should point to a Python file containing helper functions
    and variables to be made available in the Jinja2 template context. The Python file
    should define a dictionary named 'vars' containing the functions/variables to export.

    **Security warning:** The *vars* feature executes arbitrary Python code from the
    specified file. It is disabled by default and must be explicitly enabled via the
    ``SigmaPolicy.allow_template_vars`` or by setting the environment variable
    ``PYSIGMA_ALLOW_VARS_EXECUTION=1``.

    When enabled, the resolved vars file path is checked against
    ``SigmaPolicy.vars_allowed_paths``. The file must reside under (or in a subdirectory
    of) one of the listed base directories. If ``vars_allowed_paths`` is ``None`` no path
    restriction is applied.

    Templates are rendered in :class:`SigmaSandboxedEnvironment`, which only allows calling
    methods of plain data types, Jinja2 helpers and functions from an opted-in vars file.
    Methods of the live pipeline and rule objects passed into the template context are not
    callable.

    If *restrict_template_path* is set (the default for pipelines loaded from YAML or
    dictionaries unless ``SigmaPolicy.allow_external_sources`` is enabled), the template
    directory *path* must resolve to a location below one of ``vars_allowed_paths`` (by
    default the directory of the pipeline file), and template files resolving outside of it
    (e.g. via symbolic links) are refused.

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
    policy: "SigmaPolicy | None" = None
    restrict_template_path: bool = False

    def __post_init__(self) -> None:
        env = SigmaSandboxedEnvironment(autoescape=self.autoescape)
        if self.path is None:
            self.j2template = env.from_string(self.template)
        else:
            if self.restrict_template_path:
                self._check_template_path(self.path)
                env.loader = _ConfinedFileSystemLoader(self.path)
            else:
                env.loader = FileSystemLoader(self.path)
            self.j2template = env.get_template(self.template)

        # Load custom variables/functions from Python file if provided
        if self.vars is not None:
            if not self._vars_execution_allowed():
                raise SigmaSecurityError(
                    "The 'vars' feature executes Python code from an external file and is "
                    "disabled by default for security reasons. To enable it, set "
                    "allow_template_vars=True in the SigmaPolicy used for the pipeline or set the environment "
                    f"variable {PYSIGMA_ALLOW_VARS_EXECUTION_ENV}=1."
                )
            custom_vars = self._load_vars_from_file(self.vars)
            self.j2template.globals.update(custom_vars)
            env.add_trusted(custom_vars.values())

    def _check_template_path(self, path: str) -> None:
        """Template directories from untrusted pipeline definitions must reside below one of the
        allowed base directories (by default the directory of the pipeline file)."""
        real_path = os.path.realpath(path)
        vars_allowed_paths = self.policy.vars_allowed_paths if self.policy is not None else None
        if vars_allowed_paths is None:
            raise SigmaSecurityError(
                f"Template path '{path}' is not allowed because no allowed base directory is "
                "known. Load the pipeline with source_path or policy.vars_allowed_paths, or pass "
                "a policy with allow_external_sources=True to allow arbitrary template directories."
            )
        if not any(
            real_path == os.path.realpath(base)
            or real_path.startswith(os.path.realpath(base) + os.sep)
            for base in vars_allowed_paths
        ):
            raise SigmaSecurityError(
                f"Template path '{real_path}' is outside the allowed base directories: "
                f"{', '.join(os.path.realpath(p) for p in vars_allowed_paths)}"
            )

    def _vars_execution_allowed(self) -> bool:
        """Check if vars execution is allowed via policy or environment variable."""
        if self.policy is not None and self.policy.allow_template_vars:
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
        vars_allowed_paths = self.policy.vars_allowed_paths if self.policy is not None else None

        if vars_allowed_paths is not None:
            if not any(
                vars_path.startswith(os.path.realpath(base) + os.sep)
                or vars_path == os.path.realpath(base)
                for base in vars_allowed_paths
            ):
                raise SigmaSecurityError(
                    f"Vars file '{vars_path}' is outside the allowed base directories: "
                    f"{', '.join(os.path.realpath(p) for p in vars_allowed_paths)}"
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
