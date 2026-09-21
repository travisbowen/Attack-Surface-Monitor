"""Source examples and installed defaults must describe identical experiments."""
from importlib.resources import files
from pathlib import Path
import tomllib


def test_distribution_version_matches_evidence_version():
    from ai_triage_lab import __version__
    metadata = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["version"] == __version__


def test_bundled_resources_match_source_examples():
    root = Path(__file__).resolve().parents[1]
    for source, package, target in (
        ("scenarios", "ai_triage_lab", "data/scenarios"),
        ("fixtures", "ai_triage_lab", "data/fixtures"),
        ("templates", "asm_lite", "templates"),
    ):
        originals = {p.relative_to(root / source): p for p in (root / source).rglob("*") if p.is_file()}
        bundled_root = Path(str(files(package).joinpath(target)))
        bundled = {p.relative_to(bundled_root): p for p in bundled_root.rglob("*") if p.is_file()}
        assert originals.keys() == bundled.keys()
        for relative, original in originals.items():
            assert original.read_bytes() == bundled[relative].read_bytes(), relative
