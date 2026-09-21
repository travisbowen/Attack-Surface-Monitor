"""Offline replay checks for frozen source hashes across path conventions."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path

import pytest

from ai_triage_lab import external_agent
from ai_triage_lab.contracts import canonical_hash


REPO = Path(__file__).resolve().parents[1]
BUNDLE = REPO / "research" / "astra-runtime-pilot"
PACKAGE = REPO / "ai_triage_lab"


@pytest.fixture
def verifier():
    spec = importlib.util.spec_from_file_location("pilot_verifier_under_test", BUNDLE / "verify_bundle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def independent_hashes(changed_source=False):
    sources = {p.relative_to(PACKAGE).as_posix(): p.read_text(encoding="utf-8")
               for p in PACKAGE.rglob("*.py")}
    if changed_source:
        sources["external_agent.py"] += "\n# Simulated source drift; never written to package.\n"
    return {"posix": canonical_hash(sources),
            "windows": canonical_hash({key.replace("/", "\\"): value for key, value in sources.items()})}


def archived_session():
    return json.loads((BUNDLE / "trial_01" / "session.json").read_bytes())


def test_known_conventions_hash_exact_current_source(verifier):
    expected = independent_hashes()
    assert expected["posix"] != expected["windows"]
    assert verifier._implementation_hashes() == expected


@pytest.mark.parametrize("native", ["posix", "windows"])
def test_foreign_separator_replay_preserves_archive_and_caller_session(verifier, monkeypatch, native):
    hashes = independent_hashes()
    foreign = "windows" if native == "posix" else "posix"
    archive_path = BUNDLE / "trial_01" / "session.json"
    archived_bytes = archive_path.read_bytes()
    session = archived_session()
    session["implementation_hash"] = hashes[foreign]
    original = deepcopy(session)
    monkeypatch.setattr(verifier, "implementation_hash", lambda: hashes[native])
    monkeypatch.setattr(external_agent, "implementation_hash", lambda: hashes[native])
    pending, result = verifier.reconstruct_frozen_session(session, hashes[foreign])
    expected = json.loads((BUNDLE / "trial_01" / "terminal.json").read_bytes())
    assert pending is None
    assert result["evaluation"] == expected["evaluation"]
    assert result["final_state"] == expected["final_state"]
    assert session == original
    assert archive_path.read_bytes() == archived_bytes


@pytest.mark.parametrize("claimed", ["unknown", "modified-posix", "modified-windows"])
def test_unknown_or_changed_source_hash_rejected_before_replay(verifier, monkeypatch, claimed):
    digest = "0" * 64 if claimed == "unknown" else independent_hashes(True)[claimed.removeprefix("modified-")]
    session = archived_session()
    session["implementation_hash"] = digest
    original = deepcopy(session)

    def forbidden_replay(_):
        pytest.fail("Unverified source fingerprint reached host reconstruction")

    monkeypatch.setattr(verifier, "reconstruct", forbidden_replay)
    with pytest.raises((AssertionError, ValueError), match="[Ss]ource|[Ii]mplementation|[Ff]rozen"):
        verifier.reconstruct_frozen_session(session, digest)
    assert session == original


def test_session_manifest_hash_mismatch_rejected(verifier):
    hashes = independent_hashes()
    session = archived_session()
    session["implementation_hash"] = hashes["posix"]
    original = deepcopy(session)
    with pytest.raises((AssertionError, ValueError)):
        verifier.reconstruct_frozen_session(session, hashes["windows"])
    assert session == original


def test_unrecognized_native_source_fingerprint_is_not_a_bypass(verifier, monkeypatch):
    session = archived_session()
    original = deepcopy(session)
    monkeypatch.setattr(verifier, "implementation_hash", lambda: "f" * 64)
    with pytest.raises((AssertionError, ValueError)):
        verifier.reconstruct_frozen_session(session)
    assert session == original
