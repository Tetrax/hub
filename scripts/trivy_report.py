#!/usr/bin/env python3
"""Rendu du rapport Trivy de l'image SNS Hub — présentation pour la CI GitHub Actions.

Le contrôle Trivy de ``.github/workflows/ci.yml`` est **informatif** : les findings ne
bloquent jamais le run (``exit-code: 0``). Ce script produit donc le résumé lisible de
l'exécution (Step Summary) et une annotation GitHub quand des vulnérabilités sont
détectées — il ne décide de rien et ne fait échouer aucun run.

Règles de présentation :

- tolérant par construction : un rapport absent, illisible ou partiel donne un résumé
  explicite (« rapport indisponible ») et un avertissement, jamais une erreur ni un
  « aucune vulnérabilité » trompeur ;
- borné : la table du résumé est limitée (``MAX_ROWS``) et annonce le reste ;
- le rapport JSON complet reste l'artefact ``trivy-report``.

Portée volontairement limitée à Hub : pas d'ingestion, pas d'état, pas de notification
(contrairement à FortiUpgrade, le Hub n'affiche pas les CVE et n'envoie pas d'email).

Usage :
    python3 scripts/trivy_report.py trivy.json --summary-file "$GITHUB_STEP_SUMMARY"
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

# Présentation bornée : le résumé est lu par un humain dans l'interface Actions, un rapport
# à des milliers de lignes ne doit pas produire un tableau à des milliers de lignes.
MAX_ROWS = 100
# Les plus graves d'abord — l'ordre dans lequel on trie les findings.
SEVERITY_ORDER = ("CRITICAL", "HIGH")
DEFAULT_REPORT_NAME = "trivy.json"


@dataclass(frozen=True)
class Finding:
    cve: str
    package: str
    installed_version: str
    fixed_version: str
    severity: str
    title: str


def load_report(path: Path) -> tuple[dict | None, list[Finding], str | None]:
    """Retourne ``(rapport, findings, raison_indisponible)``.

    ``raison_indisponible`` est une phrase courte, sans secret, présentée à l'opérateur ;
    ``rapport`` est le document analysé quand il existe (pour le contexte d'image).
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, [], f"aucun rapport produit ({path.name} absent)"
    except OSError as error:
        return None, [], f"rapport illisible ({type(error).__name__})"
    try:
        report = json.loads(raw)
    except ValueError:
        return None, [], "rapport illisible (JSON invalide)"
    if not isinstance(report, dict):
        return None, [], "rapport illisible (objet JSON attendu)"
    return report, _findings(report), None


def _findings(report: dict) -> list[Finding]:
    """Aplatit ``Results[].Vulnerabilities[]`` en tolérant tout champ absent ou inhabituel."""
    findings: list[Finding] = []
    for result in report.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                continue
            findings.append(
                Finding(
                    cve=str(item.get("VulnerabilityID") or "?"),
                    package=str(item.get("PkgName") or "?"),
                    installed_version=str(item.get("InstalledVersion") or "—"),
                    fixed_version=str(item.get("FixedVersion") or "—"),
                    severity=str(item.get("Severity") or "UNKNOWN").upper(),
                    title=" ".join(str(item.get("Title") or "").split()),
                )
            )
    findings.sort(key=lambda finding: (severity_rank(finding.severity), finding.package, finding.cve))
    return findings


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


def counts(findings: list[Finding]) -> dict[str, int]:
    return {severity: sum(1 for f in findings if f.severity == severity) for severity in SEVERITY_ORDER}


def _artifact_name(report: dict) -> str:
    return str(report.get("ArtifactName") or "image analysée")


def scan_context(report: dict) -> tuple[str, str]:
    """``(image, système)`` — l'OS est la source de la plupart des correctifs d'une base épinglée."""
    metadata = report.get("Metadata")
    os_info = metadata.get("OS") if isinstance(metadata, dict) else None
    family = str(os_info.get("Family") or "").strip() if isinstance(os_info, dict) else ""
    name = str(os_info.get("Name") or "").strip() if isinstance(os_info, dict) else ""
    system = " ".join(part for part in (family, name) if part) or "système non précisé"
    return _artifact_name(report), system


def render_summary(
    findings: list[Finding], unavailable_reason: str | None, *, report: dict | None = None
) -> str:
    lines: list[str] = []

    if unavailable_reason is not None:
        lines.extend(
            [
                "## ⚠️ Sécurité de l'image Docker — rapport indisponible",
                "",
                f"Le contrôle Trivy n'a pas pu produire de rapport exploitable : {unavailable_reason}.",
                "",
                (
                    "**Ce job est informatif : il ne bloque pas la CI.** Le contrôle n'a donc pas "
                    "conclu — ce n'est PAS un « aucune vulnérabilité »."
                ),
                "",
            ]
        )
        return "\n".join(lines) + "\n"

    by_severity = counts(findings)
    if not findings:
        lines.extend(
            [
                "## ✅ Sécurité de l'image Docker — aucune vulnérabilité",
                "",
                (
                    "Aucune vulnérabilité **HIGH** ou **CRITICAL** corrigible n'a été détectée "
                    "(seuil `severity: HIGH,CRITICAL`, `ignore-unfixed: true`)."
                ),
                "",
            ]
        )
    else:
        lines.extend(
            [
                "## ⚠️ Sécurité de l'image Docker — vulnérabilités détectées — contrôle informatif",
                "",
                (
                    f"**{len(findings)} vulnérabilité{'s' if len(findings) > 1 else ''} corrigible"
                    f"{'s' if len(findings) > 1 else ''}** "
                    f"(CRITICAL **{by_severity['CRITICAL']}** · HIGH **{by_severity['HIGH']}**) — "
                    "toutes corrigibles (`ignore-unfixed: true`)."
                ),
                "",
                (
                    "**Ce job ne bloque pas la CI.** Les contrôles bloquants restent la suite "
                    "pytest et la construction d'image. Le rapport JSON complet est joint en "
                    "artefact `trivy-report`."
                ),
                "",
            ]
        )

    if report is not None:
        image, system = scan_context(report)
        lines.extend([f"Image : `{image}` — système : `{system}`.", ""])

    if findings:
        shown = findings[:MAX_ROWS]
        lines.extend(
            [
                "| Sévérité | Package | CVE | Version installée | Version corrigée |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        lines.extend(
            f"| {f.severity} | `{f.package}` | {f.cve} | {f.installed_version} | {f.fixed_version} |"
            for f in shown
        )
        if len(findings) > len(shown):
            lines.extend(["", f"… et {len(findings) - len(shown)} autre(s) dans le rapport JSON."])
        lines.extend(
            [
                "",
                "<details><summary>Titres des vulnérabilités</summary>",
                "",
            ]
        )
        lines.extend(
            f"- **{f.cve}** (`{f.package}`) — {f.title or 'titre non fourni par le rapport'}"
            for f in shown
        )
        lines.extend(["", "</details>", ""])

    return "\n".join(lines) + "\n"


def render_annotations(
    findings: list[Finding], unavailable_reason: str | None, *, report: dict | None = None
) -> list[str]:
    """Commandes d'annotation GitHub écrites sur stdout — visibles sans faire échouer le run.

    Une seule annotation globale suffit : le détail vit dans le Step Summary et l'artefact,
    jamais dans des centaines d'annotations.
    """
    if unavailable_reason is not None:
        return [
            (
                "::warning::Contrôle Trivy informatif : rapport indisponible — "
                f"{unavailable_reason}. Le run n'est pas bloqué."
            )
        ]
    if not findings:
        return []
    by_severity = counts(findings)
    summary = (
        f"{len(findings)} vulnérabilité(s) corrigible(s) : "
        f"{by_severity['CRITICAL']} CRITICAL, {by_severity['HIGH']} HIGH"
    )
    packages = sorted({finding.package for finding in findings})
    image = f" Image : {_artifact_name(report)}." if report is not None else ""
    return [
        "::warning title=Vulnérabilités de l'image (contrôle informatif)::"
        + f"{summary}. Packages : {', '.join(packages)}.{image} "
        + "Voir le résumé de l'étape et l'artefact trivy-report."
    ]


def parse_args(argv: list[str]) -> tuple[Path, Path | None]:
    report_path = Path(argv[1]) if len(argv) > 1 else Path(DEFAULT_REPORT_NAME)
    summary_file: Path | None = None
    if "--summary-file" in argv:
        index = argv.index("--summary-file")
        if index + 1 < len(argv):
            summary_file = Path(argv[index + 1])
    return report_path, summary_file


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv if argv is None else argv
    report_path, summary_file = parse_args(argv)
    report, findings, unavailable_reason = load_report(report_path)
    summary = render_summary(findings, unavailable_reason, report=report)
    if summary_file is not None:
        try:
            with summary_file.open("a", encoding="utf-8") as handle:
                handle.write(summary)
        except OSError as error:
            print(f"::warning::Impossible d'écrire le résumé d'étape ({type(error).__name__}).")
            print(summary, end="")
    else:
        print(summary, end="")
    for annotation in render_annotations(findings, unavailable_reason, report=report):
        print(annotation)
    # Informatif par construction : signaler un finding n'est jamais un contrôle en échec.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
