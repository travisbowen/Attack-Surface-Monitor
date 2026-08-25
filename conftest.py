"""
Put the repository root on sys.path so `import asm_lite` works under a bare
`pytest` invocation, not only under `python -m pytest`.

The project is not installed as a package (no pyproject/setup.py), so without
this the tests would only pass when the current working directory happened to
be the repo root.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
