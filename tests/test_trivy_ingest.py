"""Validation stricte du rapport Trivy (ingestion Hub) : refus en entier, jamais partiel.

Le rapport est une entrée externe : ces tests verrouillent les bornes, les types,
le contrat de sévérité HIGH/CRITICAL, les URLs et l'ordre déterministe.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "app") not in sys.path:
    sys.path.insert(0, str(ROOT / "app"))

import trivy  # noqa: E402

COMMIT = "86dc08064112e9a2cc809b82793bf230dbe948eb"


def finding(
    cve: str = "CVE-2026-13221",
    package: str = "perl-base",
    severity: str = "critical",
    installed: str = "5.40.1-6",
    fixed: str = "5.40.1-6+deb13u1",
    title: str = "",
    url: str = "",
) -> dict:
    payload = {
        "VulnerabilityID": cve,
        "PkgName": package,
        "Severity": severity,
        "InstalledVersion": installed,
        "FixedVersion": fixed,
    }
    if title:
        payload["Title"] = title
    if url:
        payload["PrimaryURL"] = url
    return payload


def report(
    findings: list[dict],
    *,
    schema: object = 2,
    artifact_type: object = "container_image",
    image: str = "hub:ci-scan",
    created: object = "2026-09-17T05:24:00.123456789Z",
    empty_python_result: bool = True,
) -> dict:
    results: list[dict] = [
        {
            "Target": f"{image} (debian 13.6)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": findings,
        }
    ]
    if empty_python_result:
        results.append(
            {"Target": "Python", "Class": "lang-pkgs", "Type": "python-pkg", "Vulnerabilities": 0}
        )
    return {
        "SchemaVersion": schema,
        "ArtifactType": artifact_type,
        "ArtifactName": image,
        "CreatedAt": created,
        "Results": results,
    }


def raw(payload: dict) -> bytes:
    return json.dumps(payload).encode()


def test_a_real_shaped_report_validates_and_is_flattened():
    payload = report(
        [
            finding(),
            finding(cve="CVE-2026-42492", package="gzip", severity="high", installed="1.13-1"),
            finding(cve="CVE-2026-89145", package="libpcre2-8-0", severity="high"),
        ]
    )
    scan = trivy.parse_report(raw(payload), commit=COMMIT)
    assert scan.image == "hub:ci-scan"
    assert scan.commit == COMMIT
    assert scan.scanned_at == "2026-09-17T05:24:00Z"  # nanosecondes normalisées
    assert scan.counts() == {"critical": 1, "high": 2}
    assert scan.findings[0].severity == "critical"  # ordre : plus sévère d'abord
    assert scan.findings[0].key == "trivy|cve|CVE-2026-13221|perl-base"


def test_the_installed_version_is_not_part_of_the_identity():
    first = trivy.parse_report(raw(report([finding(installed="5.40.1-6")])), commit=COMMIT)
    second = trivy.parse_report(raw(report([finding(installed="5.40.1-7")])), commit=COMMIT)
    assert first.findings[0].key == second.findings[0].key


def test_an_empty_vulnerabilities_list_or_zero_is_not_a_malformed_document():
    payload = report([])
    payload["Results"][0]["Vulnerabilities"] = []
    assert trivy.parse_report(raw(payload), commit=COMMIT).findings == ()


@pytest.mark.parametrize(
    "mutation",
    [
        {"SchemaVersion": 1},
        {"SchemaVersion": "2"},
        {"SchemaVersion": True},
        {"ArtifactType": "filesystem"},
        {"ArtifactName": ""},
        {"ArtifactName": "hub; rm -rf /"},
        {"CreatedAt": ""},
        {"CreatedAt": "2026-09-17T05:24:00"},  # sans fuseau
        {"CreatedAt": "hier"},
        {"Results": "non"},
    ],
)
def test_malformed_envelopes_are_refused(mutation):
    payload = report([finding()])
    payload.update(mutation)
    with pytest.raises(trivy.ReportError):
        trivy.parse_report(raw(payload), commit=COMMIT)


@pytest.mark.parametrize("commit", ["", "zzzz", "abc", None, "86dc08064112e9a2cc809b82793bf230dbe948eb0" * 2])
def test_an_unusable_commit_refuses_the_report(commit):
    with pytest.raises(trivy.ReportError):
        trivy.parse_report(raw(report([finding()])), commit=commit)


@pytest.mark.parametrize("severity", ["medium", "low", "unknown", "", "URGENT", None])
def test_a_severity_outside_the_high_critical_contract_is_refused(severity):
    with pytest.raises(trivy.ReportError):
        trivy.parse_report(raw(report([finding(severity=severity)])), commit=COMMIT)


def test_severity_case_is_normalised():
    scan = trivy.parse_report(raw(report([finding(severity="CRITICAL")])), commit=COMMIT)
    assert scan.findings[0].severity == "critical"


@pytest.mark.parametrize(
    "mutation",
    [
        {"VulnerabilityID": "CVE-26-1"},
        {"VulnerabilityID": "GHSA-xxxx"},
        {"VulnerabilityID": "a" * 201},
        {"PkgName": "paquet malveillant"},
        {"PkgName": "<script>alert(1)</script>"},
        {"PkgName": ""},
        {"InstalledVersion": "1.0; drop table"},
        {"FixedVersion": "x" * 121},
    ],
)
def test_bounded_and_filtered_identifiers_are_refused(mutation):
    entry = finding()
    entry.update(mutation)
    with pytest.raises(trivy.ReportError):
        trivy.parse_report(raw(report([entry])), commit=COMMIT)


def test_optional_versions_may_be_empty():
    entry = finding()
    entry["InstalledVersion"] = ""
    entry["FixedVersion"] = ""
    scan = trivy.parse_report(raw(report([entry])), commit=COMMIT)
    assert scan.findings[0].installed_version == ""
    assert scan.findings[0].fixed_version == ""


def test_a_long_title_is_truncated_not_refused():
    scan = trivy.parse_report(raw(report([finding(title="T" * 500)])), commit=COMMIT)
    assert len(scan.findings[0].title) == trivy.MAX_TITLE_CHARS


def test_titles_are_whitespace_normalised():
    scan = trivy.parse_report(raw(report([finding(title="  Perl   dépassement\n de tampon ")])), commit=COMMIT)
    assert scan.findings[0].title == "Perl dépassement de tampon"


@pytest.mark.parametrize("url", ["http://example.test/avis", "javascript:alert(1)", "https://", 'https://x/"onmouseover'])
def test_unusable_advisory_urls_are_dropped(url):
    scan = trivy.parse_report(raw(report([finding(url=url)])), commit=COMMIT)
    assert scan.findings[0].advisory_url == ""


def test_a_clean_https_advisory_url_is_kept():
    scan = trivy.parse_report(
        raw(report([finding(url="https://avd.aquasec.com/nvd/cve-2026-13221")])), commit=COMMIT
    )
    assert scan.findings[0].advisory_url.startswith("https://avd.aquasec.com/")


def test_duplicate_cve_package_pairs_refuse_the_report():
    with pytest.raises(trivy.ReportError):
        trivy.parse_report(raw(report([finding(), finding()])), commit=COMMIT)


def test_the_report_size_is_bounded(monkeypatch):
    monkeypatch.setattr(trivy, "MAX_REPORT_BYTES", 128)
    with pytest.raises(trivy.ReportError):
        trivy.parse_report(raw(report([finding()])), commit=COMMIT)


def test_the_finding_count_is_bounded(monkeypatch):
    monkeypatch.setattr(trivy, "MAX_FINDINGS", 2)
    findings = [
        finding(cve=f"CVE-2026-{1000 + index}", package=f"paquet-{index}") for index in range(3)
    ]
    with pytest.raises(trivy.ReportError):
        trivy.parse_report(raw(report(findings)), commit=COMMIT)


@pytest.mark.parametrize("payload", [b"", b"{", b"[]", b"null", b"\xff\xfe"])
def test_unreadable_documents_are_refused(payload):
    with pytest.raises(trivy.ReportError):
        trivy.parse_report(payload, commit=COMMIT)


def test_the_order_is_deterministic_for_an_identical_report():
    entries = [
        finding(cve="CVE-2026-0002", package="b", severity="high"),
        finding(cve="CVE-2026-0001", package="a", severity="critical"),
        finding(cve="CVE-2026-0003", package="a", severity="high"),
    ]
    first = trivy.parse_report(raw(report(entries)), commit=COMMIT)
    second = trivy.parse_report(raw(report(list(reversed(entries)))), commit=COMMIT)
    assert [item.key for item in first.findings] == [item.key for item in second.findings]
    assert [item.package for item in first.findings] == ["a", "a", "b"]


def test_state_round_trip_preserves_the_finding():
    scan = trivy.parse_report(raw(report([finding(title="titre", url="https://avd.aquasec.com/x")])), commit=COMMIT)
    restored = trivy.Finding.from_state(scan.findings[0].to_state())
    assert restored == scan.findings[0]
