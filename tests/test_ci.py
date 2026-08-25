from pathlib import Path


WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "tests.yml"


def test_ci_runs_offline_suite_on_push_and_pull_request():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    lines = {line.strip() for line in workflow.splitlines()}

    assert "on:" in lines
    assert "push:" in lines
    assert "pull_request:" in lines
    assert "run: pip install -r requirements-dev.txt" in lines
    assert "run: python -m pytest" in lines
    assert "secrets." not in workflow
    assert "--domain" not in workflow
