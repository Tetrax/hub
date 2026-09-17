"""CI GitHub Actions : invariants du contrôle de sécurité Trivy (D21).

Verrouille la politique assumée — scan informatif (`exit-code: 0`), findings
corrigibles uniquement (`HIGH,CRITICAL` + `ignore-unfixed`), rapport publié et
archivé, scan quotidien, aucun secret — et le fait que Trivy reste hors de
l'image applicative.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/ci.yml"


def workflow_text() -> str:
    return (REPO / WORKFLOW).read_text(encoding="utf-8")


def workflow() -> dict:
    # PyYAML parse `on:` comme le booléen True ; GitHub le lit comme la clé des déclencheurs.
    return yaml.safe_load(workflow_text())


def steps(job: dict) -> list[dict]:
    return job.get("steps") or []


def test_the_scan_runs_after_the_test_suite():
    jobs = workflow()["jobs"]
    assert set(jobs) == {"tests", "security-scan"}
    assert jobs["security-scan"]["needs"] == "tests"
    assert any(
        "pytest" in str(step.get("run", "")) for step in steps(jobs["tests"])
    ), "le job tests doit exécuter la suite pytest"


def test_trivy_is_informative_and_filtered_to_actionable_findings():
    scan = next(
        step for step in steps(workflow()["jobs"]["security-scan"])
        if str(step.get("uses", "")).startswith("aquasecurity/trivy-action")
    )
    with_ = scan["with"]
    assert str(with_["exit-code"]) == "0", "un finding ne doit jamais faire échouer le run"
    assert str(with_["ignore-unfixed"]).lower() == "true"
    assert with_["vuln-type"] == "os,library"
    assert with_["severity"] == "HIGH,CRITICAL"
    assert with_["format"] == "json"
    assert with_["output"] == "trivy.json"


def test_the_image_scanned_is_the_project_image_built_by_ci():
    scan_steps = steps(workflow()["jobs"]["security-scan"])
    build = next(
        step for step in scan_steps
        if str(step.get("uses", "")).startswith("docker/build-push-action")
    )
    assert build["with"]["file"] == "Dockerfile"
    assert str(build["with"]["push"]).lower() == "false", "aucune image poussée pour le scan"
    assert build["with"]["tags"] == "hub:ci-scan"
    trivy = next(
        step for step in scan_steps
        if str(step.get("uses", "")).startswith("aquasecurity/trivy-action")
    )
    assert trivy["with"]["image-ref"] == build["with"]["tags"]


def test_report_summary_and_artifact_are_published():
    scan_steps = steps(workflow()["jobs"]["security-scan"])
    summary = next(
        step for step in scan_steps if "trivy_report.py" in str(step.get("run", ""))
    )
    assert "--summary-file" in summary["run"] and "GITHUB_STEP_SUMMARY" in summary["run"]
    assert summary.get("if") == "always()", "le résumé doit être publié même sans rapport"

    upload = next(
        step for step in scan_steps
        if str(step.get("uses", "")).startswith("actions/upload-artifact")
    )
    assert upload["with"]["name"] == "trivy-report"
    assert upload["with"]["path"] == "trivy.json"
    assert str(upload["with"]["retention-days"]) == "30"
    assert str(upload["with"].get("if-no-files-found")) == "warn"


def test_triggers_cover_push_pr_daily_scan_and_manual_run():
    triggers = workflow()[True]
    assert triggers["push"]["branches"] == ["main"]
    assert "pull_request" in triggers
    cron = triggers["schedule"][0]["cron"]
    assert cron == "23 5 * * *"  # 05:23 UTC, quotidien, distinct de FortiUpgrade
    assert "workflow_dispatch" in triggers


def test_the_workflow_needs_no_secret():
    text = workflow_text().lower()
    assert "secrets." not in text
    assert "password" not in text


def test_trivy_stays_out_of_the_image_and_requirements():
    for relative in ("Dockerfile", "requirements.txt", "requirements-dev.txt"):
        content = (REPO / relative).read_text(encoding="utf-8").lower()
        assert "trivy" not in content, f"Trivy ne doit pas entrer dans {relative}"
    dockerignore = (REPO / ".dockerignore").read_text(encoding="utf-8")
    # Le contexte de build ne doit embarquer ni données persistantes ni secrets.
    for excluded in ("runtime", ".env", "scripts", "tests"):
        assert excluded in dockerignore, f"{excluded} doit être exclu du contexte d'image"
