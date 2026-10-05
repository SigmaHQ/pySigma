import os
import subprocess
import sys
from pathlib import Path


def test_plugin_module_in_other_sys_path_entry(tmp_path: Path) -> None:
    # Plugins install modules into the sigma namespace (sigma.backends.*, sigma.pipelines.*).
    # When a plugin lives in another sys.path entry than pySigma, e.g. an editable install,
    # it must still be importable even though sigma itself is a regular package.
    plugin_dir = tmp_path / "sigma" / "backends" / "namespace_test_plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "__init__.py").write_text("PLUGIN = True\n")

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(tmp_path)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sigma, sigma.backends.namespace_test_plugin as p; "
            "assert p.PLUGIN; assert sigma.default_policy is not None",
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
