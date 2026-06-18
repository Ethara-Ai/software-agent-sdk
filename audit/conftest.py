"""Pytest bootstrap: place the flat harness modules on sys.path.

Belt-and-suspenders with `[tool.pytest.ini_options] pythonpath = ["."]` so the
negative-control tests can `from verifier import ...` regardless of how pytest
is invoked.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
