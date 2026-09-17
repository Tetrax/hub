"""Rendu du rapport Trivy de la CI : présentation tolérante, jamais un contrôle bloquant.

Le rapport utilisé ici est celui réellement produit par le job `security-scan` sur l'image
Hub (`hub:ci-scan`, Trivy, `severity: HIGH,CRITICAL`, `ignore-unfixed: true`) : une Debian
13.6 avec 13 findings corrigibles (3 CRITICAL + 10 HIGH, `os-pkgs` uniquement) et un
résultat Python sans vulnérabilité — `"Vulnerabilities": 0`, pas une clé absente.
"""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import trivy_report  # noqa: E402

# Les 13 findings du rapport réel de l'image Hub (Debian 13.6) : 3 CRITICAL + 10 HIGH.
REAL_FINDINGS = (
    ("perl-base", "CVE-2026-13221", "CRITICAL", "5.40.1-6", "5.40.1-6+deb13u1"),
    ("perl-base", "CVE-2026-42496", "CRITICAL", "5.40.1-6", "5.40.1-6+deb13u1"),
    ("perl-base", "CVE-2026-8376", "CRITICAL", "5.40.1-6", "5.40.1-6+deb13u1"),
    ("gzip", "CVE-2026-41992", "HIGH", "1.13-1", "1.13-1+deb13u1"),
    ("libpcre2-8-0", "CVE-2026-86145", "HIGH", "10.46-1~deb13u1", "10.46-1~deb13u2"),
    ("libpcre2-8-0", "CVE-2026-89157", "HIGH", "10.46-1~deb13u1", "10.46-1~deb13u2"),
    ("libpcre2-8-0", "CVE-2026-89161", "HIGH", "10.46-1~deb13u1", "10.46-1~deb13u2"),
    ("libsqlite3-0", "CVE-2026-11822", "HIGH", "3.46.1-7+deb13u1", "3.46.1-7+deb13u2"),
    ("libsqlite3-0", "CVE-2026-11824", "HIGH", "3.46.1-7+deb13u1", "3.46.1-7+deb13u2"),
    ("perl-base", "CVE-2026-42497", "HIGH", "5.40.1-6", "5.40.1-6+deb13u1"),
    ("perl-base", "CVE-2026-48962", "HIGH", "5.40.1-6", "5.40.1-6+deb13u1"),
    ("perl-base", "CVE-2026-57432", "HIGH", "5.40.1-6", "5.40.1-6+deb13u1"),
    ("perl-base", "CVE-2026-57433", "HIGH", "5.40.1-6", "5.40.1-6+deb13u1"),
)


def report_payload(findings=REAL_FINDINGS) -> dict:
    return {
        "SchemaVersion": 2,
        "ArtifactName": "hub:ci-scan",
        "ArtifactType": "container_image",
        "CreatedAt": "2026-09-17T18:55:13.964726549Z",
        "Trivy": {"Version": "0.69.3"},
        "Metadata": {
            "OS": {"Family": "debian", "Name": "13.6"},
            "ImageID": "sha256:0d66b8e4f6c7abcd0123456789abcdef0123456789abcdef0123456789abcdef",
            "RepoTags": ["hub:ci-scan"],
            "Reference": "hub:ci-scan",
            "Size": 208650240,
        },
        "Results": [
            {
                "Target": "hub:ci-scan (debian 13.6)",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": cve,
                        "PkgName": package,
                        "InstalledVersion": installed,
                        "FixedVersion": fixed,
                        "Severity": severity,
                        "Status": "fixed",
                        "Title": f"titre {cve}",
                        "PrimaryURL": f"https://avd.aquasec.com/nvd/{cve.lower()}",
                    }
                    for package, cve, severity, installed, fixed in findings
                ],
            },
            {
                # Résultat de langue propre : 0, pas une clé absente, dans le rapport réel.
                "Target": "Python",
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Vulnerabilities": 0,
            },
        ],
    }


def write_report(directory: Path, payload, name: str = "trivy.json") -> Path:
    path = Path(directory) / name
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return path


# --- Lecture du rapport --------------------------------------------------------


def test_real_report_shape_is_flattened_with_every_field_kept(tmp_path):
    report, findings, unavailable = trivy_report.load_report(write_report(tmp_path, report_payload()))

    assert unavailable is None
    assert len(findings) == 13
    assert trivy_report.counts(findings) == {"CRITICAL": 3, "HIGH": 10}
    first = findings[0]
    assert (first.severity, first.package, first.cve) == ("CRITICAL", "perl-base", "CVE-2026-13221")
    assert first.installed_version == "5.40.1-6"
    assert first.fixed_version == "5.40.1-6+deb13u1"
    assert first.title == "titre CVE-2026-13221"
    assert report["ArtifactName"] == "hub:ci-scan"


def test_most_severe_findings_are_listed_first(tmp_path):
    _report, findings, _unavailable = trivy_report.load_report(
        write_report(tmp_path, report_payload())
    )
    assert [finding.severity for finding in findings[:3]] == ["CRITICAL"] * 3
    assert findings[3].severity == "HIGH"


def test_clean_report_yields_no_finding_and_no_unavailable_reason(tmp_path):
    payload = report_payload(()) | {"Results": [{"Target": "t", "Class": "os-pkgs"}]}
    _report, findings, unavailable = trivy_report.load_report(write_report(tmp_path, payload))
    assert findings == []
    assert unavailable is None


@pytest.mark.parametrize(
    "payload",
    (
        {"Results": "not-a-list"},
        {"Results": [None, "x", {"Vulnerabilities": "not-a-list"}]},
        {"Results": [{"Vulnerabilities": [None, 42, {"PkgName": "p"}]}]},
        {},
    ),
)
def test_malformed_shapes_never_raise(tmp_path, payload):
    _report, findings, unavailable = trivy_report.load_report(write_report(tmp_path, payload))
    assert unavailable is None
    assert isinstance(findings, list)


def test_missing_or_invalid_report_is_an_explicit_unavailable_reason(tmp_path):
    _report, findings, unavailable = trivy_report.load_report(tmp_path / "absent.json")
    assert findings == []
    assert "absent" in (unavailable or "")

    _report, _findings, unavailable = trivy_report.load_report(write_report(tmp_path, "not json"))
    assert "JSON invalide" in (unavailable or "")

    _report, _findings, unavailable = trivy_report.load_report(write_report(tmp_path, "[1, 2, 3]"))
    assert "objet JSON attendu" in (unavailable or "")


# --- Résumé (Step Summary) -----------------------------------------------------


def render(tmp_path, payload) -> str:
    report, findings, unavailable = trivy_report.load_report(write_report(tmp_path, payload))
    return trivy_report.render_summary(findings, unavailable, report=report)


def test_summary_reports_counts_and_every_finding_field(tmp_path):
    summary = render(tmp_path, report_payload())
    assert "## ⚠️ Sécurité de l'image Docker — vulnérabilités détectées — contrôle informatif" in summary
    assert "**13 vulnérabilités corrigibles** (CRITICAL **3** · HIGH **10**)" in summary
    for package, cve, _severity, installed, fixed in REAL_FINDINGS:
        assert cve in summary
        assert f"`{package}`" in summary
        assert installed in summary
        assert fixed in summary
    assert "debian 13.6" in summary
    assert "hub:ci-scan" in summary


def test_summary_never_presents_findings_as_a_blocking_failure(tmp_path):
    summary = render(tmp_path, report_payload())
    assert "**Ce job ne bloque pas la CI.**" in summary
    assert "trivy-report" in summary


def test_partial_fields_are_tolerated_in_the_summary(tmp_path):
    """Un champ de présentation manquant ne doit jamais faire échouer la CI."""
    payload = report_payload(
        (("paquet", "CVE-2026-00001", "HIGH", None, None),)
    )
    # InstalledVersion/FixedVersion absents : remplacés par un tiret, jamais une erreur.
    for result in payload["Results"]:
        for item in result.get("Vulnerabilities") or []:
            del item["InstalledVersion"]
            del item["FixedVersion"]
            del item["Title"]
    summary = render(tmp_path, payload)
    assert "CVE-2026-00001" in summary
    assert "—" in summary


def test_clean_report_says_so_without_a_table(tmp_path):
    summary = render(tmp_path, {"ArtifactName": "hub:ci-scan", "Results": []})
    assert "## ✅ Sécurité de l'image Docker — aucune vulnérabilité" in summary
    assert "| Sévérité |" not in summary


def test_unavailable_report_is_never_read_as_zero_findings():
    summary = trivy_report.render_summary([], "aucun rapport produit (trivy.json absent)")
    assert "rapport indisponible" in summary
    assert "ce n'est PAS un « aucune vulnérabilité »" in summary
    assert "✅" not in summary


def test_the_table_is_bounded_and_announces_the_remainder(tmp_path):
    many = tuple(
        ("pkg", f"CVE-2026-{index:05d}", "HIGH", "1.0", "1.1")
        for index in range(trivy_report.MAX_ROWS + 7)
    )
    summary = render(tmp_path, report_payload(many))
    assert "… et 7 autre(s) dans le rapport JSON." in summary
    assert summary.count("| HIGH |") == trivy_report.MAX_ROWS


# --- Annotations et sortie du programme ----------------------------------------


def run_main(argv: list[str]) -> tuple[int, str]:
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        code = trivy_report.main(argv)
    return code, stdout.getvalue()


def test_summary_goes_to_the_file_and_annotations_to_stdout(tmp_path):
    report = write_report(tmp_path, report_payload())
    summary_file = tmp_path / "summary.md"
    code, stdout = run_main(["trivy_report.py", str(report), "--summary-file", str(summary_file)])
    summary = summary_file.read_text(encoding="utf-8")

    assert code == 0
    assert "::warning title=Vulnérabilités de l'image (contrôle informatif)::" in stdout
    assert "3 CRITICAL, 10 HIGH" in stdout
    assert "perl-base" in stdout
    # La commande d'annotation ne doit pas se retrouver dans le Markdown lu par l'opérateur.
    assert "::warning" not in summary
    assert "| Sévérité | Package |" in summary


def test_no_annotation_is_emitted_when_the_image_is_clean(tmp_path):
    report = write_report(tmp_path, {"ArtifactName": "hub:ci-scan", "Results": []})
    code, stdout = run_main(["trivy_report.py", str(report)])
    assert code == 0
    assert "::warning" not in stdout
    assert "## ✅" in stdout


def test_an_unavailable_report_warns_but_still_exits_zero(tmp_path):
    code, stdout = run_main(["trivy_report.py", str(tmp_path / "absent.json")])
    assert code == 0
    assert "::warning::Contrôle Trivy informatif : rapport indisponible" in stdout


def test_findings_alone_never_produce_a_non_zero_exit(tmp_path):
    report = write_report(tmp_path, report_payload())
    code, _stdout = run_main(["trivy_report.py", str(report)])
    assert code == 0
