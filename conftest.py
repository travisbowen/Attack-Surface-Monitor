"""
Put the repository root on sys.path so `import asm_lite` works under a bare
`pytest` invocation, not only under `python -m pytest`.

The project is not installed as a package (no pyproject/setup.py), so without
this the tests would only pass when the current working directory happened to
be the repo root.
"""

import sys
from pathlib import Path
import os
import shutil
import uuid

import pytest

ROOT = Path(__file__).resolve().parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def pytest_configure(config):
    if os.name == "nt" and config.pluginmanager.hasplugin("cacheprovider"):
        # Avoid pytest's initial mode-0700 cache staging directory on Windows.
        (ROOT / config.getini("cache_dir")).mkdir(parents=True, exist_ok=True)


@pytest.fixture
def tmp_path(request):
    """Use inherited workspace ACLs for synthetic test files on Windows.

    Python's mode-0700 temporary directories can exclude the restricted Windows
    execution token. Other platforms retain pytest's standard temp factory.
    """
    if os.name != "nt":
        yield request.getfixturevalue("tmp_path_factory").mktemp(request.node.name, numbered=True)
        return
    root = (ROOT / "out" / "test-temp").resolve()
    path = root / uuid.uuid4().hex
    path.mkdir(parents=True)
    try:
        yield path
    finally:
        resolved = path.resolve()
        if resolved.parent != root or not resolved.is_relative_to(root):
            raise RuntimeError("Refusing cleanup outside test workspace")
        shutil.rmtree(resolved)
