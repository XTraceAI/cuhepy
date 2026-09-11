"""Load an ASan/UBSan extension in place of the regular binary, then run its tests.

Usage: python tests/x_vec/native/run_binding_sanitizers.py /tmp/bfv_sanitized.so
Start Python with the sanitizer and C++ runtimes in LD_PRELOAD (see CI).
"""

import importlib.util
from pathlib import Path
import sys

import xtrace_sdk.x_vec.crypto.bfv_cpu_ext as package

name = "xtrace_sdk.x_vec.crypto.bfv_cpu_ext._bfv_rns"
library = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location(name, library)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[name] = module
spec.loader.exec_module(module)
package._bfv_rns = module
assert Path(module.__file__).resolve() == library

import pytest  # noqa: E402

raise SystemExit(pytest.main(["tests/x_vec/test_bfv_native.py", "-q"]))
