"""Offline installed-wheel smoke test. Run with installed Python -I outside checkout."""
from importlib.resources import files
import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig
from unittest.mock import patch

import ai_triage_lab
import asm_lite
from ai_triage_lab.evidence import verify_chain


def main():
    source = Path(__file__).resolve().parents[1]
    output = Path.cwd()
    assert not output.is_relative_to(source), "Run outside source checkout"
    for package in (ai_triage_lab, asm_lite):
        assert not Path(package.__file__).resolve().is_relative_to(source), "Source import instead of wheel"
    scripts = Path(sysconfig.get_path("scripts"))

    def command(name, *args):
        executable = scripts / (name + (".exe" if os.name == "nt" else ""))
        subprocess.run([str(executable), *map(str, args)], check=True)

    for name in ("asm-lite", "ai-triage-lab", "ai-triage-experiment"):
        command(name, "--help")
    command("ai-triage-lab", "run", "--suite", "all", "--out", output / "lab")
    run = next((output / "lab").iterdir())
    results = [json.loads(p.read_text(encoding="utf-8")) for p in run.glob("*/result.json")]
    assert len(results) == 48
    assert all(r["execution"]["status"] == "completed" for r in results)
    assert all(verify_chain(r["events"], r["evidence_head"]) for r in results)
    command("ai-triage-lab", "compare", run, "--out", output / "dashboard")
    fixture = Path(str(files("ai_triage_lab").joinpath("data/fixtures/asm-example")))
    command("ai-triage-lab", "import-asm", fixture, "--out", output / "imported.json")
    config = output / "model-preflight.json"
    config.write_text(json.dumps({"endpoint": "http://localhost:8000/v1/chat/completions",
                                  "model": "UNCONFIGURED-PREFLIGHT-ONLY"}), encoding="utf-8")
    command("ai-triage-experiment", "--model-config", config, "--suite", "all",
            "--repeats", "2", "--out", output / "preflight")
    # Exercise scanner orchestration and installed Jinja template without network.
    from asm_lite.cli import main as scan
    with patch("sys.argv", ["asm-lite", "--domain", "example.test", "--out", str(output / "scanner")]), \
         patch("asm_lite.cli.discover_subdomains", return_value=[]), \
         patch("asm_lite.cli.resolve_hosts", return_value=[]), \
         patch("asm_lite.cli.probe_http", return_value=[]):
        assert scan() == 0
    assert (output / "scanner/report.html").is_file()
    version = __import__("importlib.metadata").metadata.version("asm-ai-triage-lab")
    assert ai_triage_lab.__version__ == version
    record = {"installed_version": version,
              "completed_scripted_trials": len(results), "valid_evidence_chains": len(results),
              "entrypoints": 3, "network_calls": 0, "model_execution": False,
              "scanner": "mocked network; installed template rendered"}
    (output / "wheel-verification.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
