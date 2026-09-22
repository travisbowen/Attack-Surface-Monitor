"""Offline coordinator contract checks. All target replies are explicit fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "native_runtime_campaign.py"
spec = importlib.util.spec_from_file_location("native_runtime_campaign", SCRIPT)
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)
verify_spec = importlib.util.spec_from_file_location("verify_native_runtime_campaign", SCRIPT.with_name("verify_native_runtime_campaign.py"))
verifier = importlib.util.module_from_spec(verify_spec)
verify_spec.loader.exec_module(verifier)


def invoke(monkeypatch, root, action, index=None):
    argv = [str(SCRIPT), action, str(root)]
    if index is not None:
        argv += ["--index", str(index)]
    monkeypatch.setattr(sys, "argv", argv)
    campaign.main()


def read(path):
    return json.loads(path.read_bytes())


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    root = tmp_path / "explicit-offline-fixture"
    invoke(monkeypatch, root, "init")
    invoke(monkeypatch, root, "start", 0)
    directory = root / "native-repeat-01"
    turn = directory / "turns" / "000"
    request = read(turn / "request.json")
    (turn / "response.bin").write_bytes(b' {"tool_calls":[],"final":"offline fixture"}\n')
    campaign.write(turn / "receipt.json", {"request_hash": request["request_hash"]})
    return root, directory, turn


def test_plan_preserves_all_twelve_and_original_bytes(prepared, monkeypatch):
    root, _, _ = prepared
    original = (root / "preregistration.json").read_bytes()
    plan = json.loads(original)
    assert len(plan["schedule"]) == plan["max_exposures"] == 12
    assert len({(r["scenario_id"], r["variant"], r["repeat"]) for r in plan["schedule"]}) == 12
    assert plan["max_replies_per_exposure"] == 8
    invoke(monkeypatch, root, "submit", 0)
    ledger = read(root / "ledger.json")
    assert len(ledger) == 12
    assert sum(r["status"] == "unattempted" for r in ledger) == 11
    assert (root / "preregistration.json").read_bytes() == original


def test_exact_reply_and_receipt_hashes(prepared, monkeypatch):
    root, directory, turn = prepared
    raw = (turn / "response.bin").read_bytes()
    receipt = (turn / "receipt.json").read_bytes()
    invoke(monkeypatch, root, "submit", 0)
    linkage = read(turn / "linkage.json")
    assert linkage["response_sha256"] == hashlib.sha256(raw).hexdigest()
    assert linkage["receipt_sha256"] == hashlib.sha256(receipt).hexdigest()
    assert linkage["response_bytes"] == len(raw)
    session = read(directory / "session.json")
    assert session["responses"][0]["response_sha256"] == linkage["response_sha256"]
    assert (turn / "response.bin").read_bytes() == raw


@pytest.mark.parametrize("tamper", ["request", "receipt"])
def test_bad_linkage_stays_counted_invalid_without_submit(prepared, monkeypatch, tamper):
    root, directory, turn = prepared
    if tamper == "request":
        with (turn / "request.json").open("ab") as stream:
            stream.write(b" ")
    else:
        campaign.write(turn / "receipt.json", {"request_hash": "incorrect"})
    invoke(monkeypatch, root, "submit", 0)
    ledger = read(root / "ledger.json")
    assert len(ledger) == 12
    assert ledger[0]["status"] == "invalid_relay"
    assert read(directory / "session.json")["responses"] == []
    with pytest.raises(ValueError, match="No retry"):
        invoke(monkeypatch, root, "start", 0)


def test_malformed_reply_is_error_not_defense_success(prepared, monkeypatch):
    root, _, turn = prepared
    (turn / "response.bin").write_bytes(b"not JSON; explicit offline fixture")
    invoke(monkeypatch, root, "submit", 0)
    row = read(root / "ledger.json")[0]
    assert row["status"] == "error"
    assert row["submitted_replies"] == 1
    assert row["evaluation"]["attack_objective"] == "unknown"


def test_exclusive_sessions_and_no_resubmission(prepared, monkeypatch):
    root, _, _ = prepared
    with pytest.raises(ValueError, match="No retry"):
        invoke(monkeypatch, root, "start", 0)
    invoke(monkeypatch, root, "submit", 0)
    # Next turn has a new exclusive directory; previous bytes cannot resubmit.
    with pytest.raises(FileNotFoundError):
        invoke(monkeypatch, root, "submit", 0)


def test_missing_receipt_leaves_pending_for_explicit_operator_accounting(prepared, monkeypatch):
    root, _, turn = prepared
    # Replace receipt with invalid JSON without touching any real campaign.
    (turn / "receipt.json").write_bytes(b"unfinished fixture receipt")
    with pytest.raises(json.JSONDecodeError):
        invoke(monkeypatch, root, "submit", 0)
    assert read(root / "ledger.json")[0]["status"] == "awaiting_target"


def test_negative_index_is_python_indexing_operator_limitation(prepared, monkeypatch):
    root, _, _ = prepared
    invoke(monkeypatch, root, "start", -1)
    rows = read(root / "ledger.json")
    assert rows[-1]["status"] == "awaiting_target"
    assert len(rows) == 12


def test_verifier_prefix_and_complete_denominator(prepared, monkeypatch):
    root, _, _ = prepared
    invoke(monkeypatch, root, "submit", 0)
    plan_hash = campaign.digest(root / "preregistration.json")
    assert verifier.verify(root, plan_hash)["valid"]
    result = verifier.verify(root, plan_hash, require_complete=True)
    assert not result["valid"]
    assert result["denominator"] == 12


@pytest.mark.parametrize("target", ["response", "receipt", "request", "schedule", "plan"])
def test_verifier_detects_retained_evidence_tampering(prepared, monkeypatch, target):
    root, _, turn = prepared
    invoke(monkeypatch, root, "submit", 0)
    plan_hash = campaign.digest(root / "preregistration.json")
    if target == "schedule":
        rows = read(root / "ledger.json")
        rows[0]["repeat"] = 100
        campaign.write(root / "ledger.json", rows)
    else:
        path = root / "preregistration.json" if target == "plan" else turn / ("response.bin" if target == "response" else target + ".json")
        with path.open("ab") as stream:
            stream.write(b" ")
    assert not verifier.verify(root, plan_hash)["valid"]


def test_verifier_portable_exposure_layout(prepared, monkeypatch):
    root, directory, _ = prepared
    invoke(monkeypatch, root, "submit", 0)
    (root / "exposures").mkdir()
    directory.rename(root / "exposures" / directory.name)
    assert verifier.verify(root, campaign.digest(root / "preregistration.json"))["valid"]


def test_verifier_saved_final_state_tampering(prepared, monkeypatch):
    root, directory, turn = prepared
    (turn / "response.bin").write_bytes(b"malformed offline fixture")
    invoke(monkeypatch, root, "submit", 0)
    plan_hash = campaign.digest(root / "preregistration.json")
    assert verifier.verify(root, plan_hash)["valid"]
    result_path = next((directory / "trials").glob("*/result.json"))
    result = read(result_path)
    result["final_state"]["tampered"] = True
    campaign.write(result_path, result)
    result = verifier.verify(root, plan_hash)
    assert not result["valid"]
    assert any("saved final_state" in failure for failure in result["failures"])


@pytest.mark.parametrize("native", ["posix", "windows"])
def test_verifier_replays_other_platform_without_archive_edits(prepared, monkeypatch, native):
    from ai_triage_lab import external_agent
    root, directory, _ = prepared
    invoke(monkeypatch, root, "submit", 0)
    original = (directory / "session.json").read_bytes()
    hashes = verifier._pilot._implementation_hashes()
    monkeypatch.setattr(verifier._pilot, "implementation_hash", lambda: hashes[native])
    monkeypatch.setattr(external_agent, "implementation_hash", lambda: hashes[native])
    assert verifier.verify(root, campaign.digest(root / "preregistration.json"))["valid"]
    assert (directory / "session.json").read_bytes() == original


def test_source_digest_allows_line_endings_but_rejects_changed_code(tmp_path):
    source = tmp_path / "source.py"
    source.write_bytes(b"x = 1\r\n")
    lf_hash = hashlib.sha256(b"x = 1\n").hexdigest()
    crlf_hash = hashlib.sha256(b"x = 1\r\n").hexdigest()
    assert verifier.source_digest_matches(source, lf_hash)
    source.write_bytes(b"x = 1\n")
    assert verifier.source_digest_matches(source, crlf_hash)
    source.write_bytes(b"x = 2\n")
    assert not verifier.source_digest_matches(source, lf_hash)
    assert not verifier.source_digest_matches(source, crlf_hash)


@pytest.mark.parametrize("tamper", ["changed", "missing", "extra"])
def test_public_manifest_rejects_inventory_or_byte_changes(prepared, monkeypatch, tamper):
    root, _, _ = prepared
    invoke(monkeypatch, root, "submit", 0)
    plan_hash = campaign.digest(root / "preregistration.json")
    note = root / "README.md"
    note.write_text("Offline fixture, not a live-model measurement.\n")
    campaign.write(root / "manifest.json", {
        path.relative_to(root).as_posix(): campaign.digest(path)
        for path in root.rglob("*") if path.is_file()
    })
    assert verifier.verify(root, plan_hash)["valid"]
    if tamper == "changed":
        note.write_text("Changed claim.\n")
    elif tamper == "missing":
        note.unlink()
    else:
        (root / "extra.json").write_text("{}")
    result = verifier.verify(root, plan_hash)
    assert not result["valid"]
    assert any("manifest" in failure for failure in result["failures"])


def set_simulated_platform(monkeypatch, convention):
    from ai_triage_lab import external_agent, runner
    value = verifier._pilot._implementation_hashes()[convention]
    for module in (campaign, verifier._pilot, external_agent, runner):
        monkeypatch.setattr(module, "implementation_hash", lambda: value)
    return value


@pytest.mark.parametrize("archived", ["windows", "posix"])
@pytest.mark.parametrize("native", ["windows", "posix"])
def test_terminal_archive_cross_platform_events_unchanged(tmp_path, monkeypatch, archived, native):
    set_simulated_platform(monkeypatch, archived)
    root = tmp_path / "explicit-offline-terminal-fixture"
    invoke(monkeypatch, root, "init")
    invoke(monkeypatch, root, "start", 0)
    directory = root / "native-repeat-01"
    for index in range(2):
        turn = directory / "turns" / f"{index:03d}"
        request = read(turn / "request.json")
        (turn / "response.bin").write_bytes(b'{"tool_calls":[],"final":"offline terminal fixture"}')
        campaign.write(turn / "receipt.json", {"request_hash": request["request_hash"]})
        invoke(monkeypatch, root, "submit", 0)
    assert read(root / "ledger.json")[0]["status"] == "completed"
    original = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    set_simulated_platform(monkeypatch, native)
    report = verifier.verify(root, campaign.digest(root / "preregistration.json"))
    assert report["valid"], report["failures"]
    assert {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()} == original


@pytest.mark.parametrize("native", ["windows", "posix"])
def test_complete_public_archive_cross_platform(monkeypatch, native):
    root = SCRIPT.parents[1] / "research/native-runtime-repeats"
    original_manifest = (root / "manifest.json").read_bytes()
    set_simulated_platform(monkeypatch, native)
    report = verifier.verify(root, "ac87b511c0aa524415eaca88d0d325c16259b74dfa025833fa76b6fe08106e29", require_complete=True)
    assert report["valid"], report["failures"]
    assert report["statuses"] == {"completed": 12}
    assert sum(row["accepted_replies"] for row in report["checked"]) == 60
    assert (root / "manifest.json").read_bytes() == original_manifest


@pytest.mark.parametrize("tamper", ["unknown_hash", "other_valid_hash", "prompt_hash", "nested_hash", "tool_effect", "top_level_hash"])
def test_terminal_semantics_reject_tamper_even_with_rehashed_chain(prepared, monkeypatch, tamper):
    root, directory, turn = prepared
    (turn / "response.bin").write_bytes(b"malformed offline terminal fixture")
    invoke(monkeypatch, root, "submit", 0)
    result_path = next((directory / "trials").glob("*/result.json"))
    saved = read(result_path)
    config = next(event for event in saved["events"] if event["kind"] == "configuration")
    if tamper == "unknown_hash":
        config["data"]["implementation_hash"] = "0" * 64
    elif tamper == "other_valid_hash":
        config["data"]["implementation_hash"] = next(value for value in verifier._pilot._implementation_hashes().values() if value != saved["implementation_hash"])
    elif tamper == "prompt_hash":
        config["data"]["prompt_hash"] = "0" * 64
    elif tamper == "nested_hash":
        config["data"]["adapter"]["implementation_hash"] = "injected nested value"
    elif tamper == "tool_effect":
        saved["events"][-1]["data"]["final_state"]["injected"] = True
    else:
        saved["implementation_hash"] = "0" * 64
    previous = None
    for event in saved["events"]:
        event["previous_hash"] = previous
        event["hash"] = verifier.canonical_hash({k: v for k, v in event.items() if k != "hash"})
        previous = event["hash"]
    saved["evidence_head"] = previous
    campaign.write(result_path, saved)
    (result_path.parent / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in saved["events"]), encoding="utf-8")
    assert verifier.verify_chain(saved["events"])
    report = verifier.verify(root, campaign.digest(root / "preregistration.json"))
    assert not report["valid"]
    assert any("implementation" in failure.lower() or "event semantics" in failure for failure in report["failures"])
