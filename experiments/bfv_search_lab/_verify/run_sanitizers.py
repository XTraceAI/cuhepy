"""Load only the requested ASan/UBSan verifier binary, then run boundary tests."""

import importlib.util
import os
from pathlib import Path
import sys

os.environ['PYCRYPTODOME_DISABLE_DEEPBIND'] = '1'
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
import experiments.bfv_search_lab._verify as package  # noqa: E402

if len(sys.argv) != 2:
    raise ValueError('Supply the sanitized extension path; no release fallback')
library = Path(sys.argv[1]).resolve()
name = 'experiments.bfv_search_lab._verify._bgv_checked'
spec = importlib.util.spec_from_file_location(name, library)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[name] = module
spec.loader.exec_module(module)
package._bgv_checked = module
assert Path(module.__file__).resolve() == library

import pytest  # noqa: E402

raise SystemExit(pytest.main(['experiments/bfv_search_lab/test_checked_switch_bgv.py',
    'experiments/bfv_search_lab/test_native_checked_switch_bgv.py', '-q']))
