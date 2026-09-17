"""Load an ASan/UBSan extension in place of the regular binary, then run its tests.

Usage: python tests/unit/native/run_binding_sanitizers.py PUBLIC_SO PRIVATE_SO
Start Python with the sanitizer and C++ runtimes in LD_PRELOAD (see CI).
"""

import importlib.util
import os
from pathlib import Path
import sys

# Installing the Nitro extra also installs CFFI. PyCryptodome then uses a loader
# with RTLD_DEEPBIND, which bypasses ASan's allocator interposition. Its supported
# override keeps sanitizers active; it applies only to this test process and must
# be set before importing the SDK (which imports PyCryptodome).
os.environ["PYCRYPTODOME_DISABLE_DEEPBIND"] = "1"

import cuhepy.bfv._cpu_ext as package

assert len(sys.argv) == 3, "Supply both sanitized extension paths; no release fallback"
for short_name, path in zip(("_bfv_rns", "_bfv_private"), sys.argv[1:], strict=True):
    name = f"cuhepy.bfv._cpu_ext.{short_name}"
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
            "tests/unit/test_bfv_native.py",
            "tests/unit/test_bfv_residue.py",
            "tests/unit/test_bfv_security.py",
            "tests/unit/test_bfv_verified_client.py",
            "tests/unit/test_bfv_private.py",
            "tests/unit/test_bfv_guarded_client.py",
            "tests/unit/test_bfv_attested_client.py",
            "tests/unit/test_bfv_assurance.py",
            "-q",
        ]
    )
)
