import ast
import importlib.metadata
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).parent.parent


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def declared_dependencies() -> set[str]:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = pyproject["tool"]["poetry"]["dependencies"]
    return {normalize(name) for name in deps if name != "python"}


def is_type_checking_block(node: ast.AST) -> bool:
    if not isinstance(node, ast.If):
        return False
    test = node.test
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def runtime_imports(tree: ast.AST) -> set[str]:
    """Top-level module names imported by a module, ignoring `if TYPE_CHECKING:` blocks."""
    modules: set[str] = set()
    for node in ast.iter_child_nodes(tree):
        if is_type_checking_block(node):
            continue
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                modules.add(node.module.split(".")[0])
        else:
            modules.update(runtime_imports(node))
    return modules


def test_runtime_imports_are_declared_dependencies():
    """
    Every third-party module imported at runtime by the sigma package must come from a dependency
    declared in pyproject.toml. Modules provided only by development dependencies are installed in
    the test environment but not for users, so importing them breaks installed packages.
    """
    declared = declared_dependencies()
    module_distributions = importlib.metadata.packages_distributions()
    undeclared = {}
    for path in sorted((ROOT / "sigma").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for module in runtime_imports(tree):
            if module == "sigma" or module in sys.stdlib_module_names:
                continue
            distributions = {normalize(d) for d in module_distributions.get(module, [])}
            if not distributions & declared:
                undeclared.setdefault(module, []).append(str(path.relative_to(ROOT)))
    assert undeclared == {}, f"modules imported but not declared as dependencies: {undeclared}"
