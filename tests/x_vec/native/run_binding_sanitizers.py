"""Load an ASan/UBSan extension in place of the regular binary, then run its tests.

Usage: python tests/x_vec/native/run_binding_sanitizers.py PUBLIC_SO PRIVATE_SO
Start Python with the sanitizer and C++ runtimes in LD_PRELOAD (see CI).
"""

import importlib.util
from pathlib import Path
import sys

import xtrace_sdk.x_vec.crypto.bfv_cpu_ext as package

assert len(sys.argv) == 3, "Supply both sanitized extension paths; no release fallback"
for short_name, path in zip(("_bfv_rns", "_bfv_private"), sys.argv[1:], strict=True):
    name = f"xtrace_sdk.x_vec.crypto.bfv_cpu_ext.{short_name}"
    library = Path(path).resolve()
    spec = importlib.util.spec_from_file_location(name, library)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    setattr(package, short_name, module)
    assert Path(module.__file__).resolve() == library

import pytest  # noqa: E402

raise SystemExit(
    pytest.main(
        [
            "tests/x_vec/test_bfv_native.py",
            "tests/x_vec/test_bfv_residue.py",
            "tests/x_vec/test_bfv_security.py",
            "tests/x_vec/test_bfv_verified_client.py",
            "tests/x_vec/test_bfv_private.py",
            "tests/x_vec/test_bfv_guarded_client.py",
            "tests/x_vec/test_bfv_assurance.py",
            "-q",
        ]
    )
)
