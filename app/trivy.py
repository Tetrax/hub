"""Rapport Trivy : validation stricte et identité des findings (V1.6).

Le rapport vient de GitHub Actions : c'est une **entrée non fiable**. Avant qu'il
puisse influencer la baseline ou déclencher un email, il est validé en entier
(`parse_report`) : taille bornée, JSON, schéma, type d'artefact, sévérités du
contrat HIGH/CRITICAL corrigibles, identifiants bornés et filtrés, URLs en
HTTPS uniquement, nombre de findings borné. Un rapport invalide est **refusé en
entier** — jamais d'ingestion partielle, qui corromprait la baseline (un finding
silencieusement perdu serait relu plus tard comme « nouveau » ou « disparu »).

Aucun accès réseau ni base ici : une seule responsabilité, le format et
l'identité. L'identité stable d'un finding est `CVE + package`, **sans** la
version installée : une image reconstruite garde la même CVE sur le même paquet
alors que la version bouge (`+deb13u1` → `+deb13u2`) ; l'inclure ferait
apparaître chaque rebuild comme une salve de nouvelles CVE.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

# Bornes d'ingestion (le rapport est une entrée externe).
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 2000
MAX_IDENTIFIER_CHARS = 200
MAX_VERSION_CHARS = 120
MAX_TITLE_CHARS = 300
# Contrat de la CI Hub : `severity: HIGH,CRITICAL` + `ignore-unfixed: true`.
# Une sévérité hors de ce domaine signale un changement du pipeline CI : on refuse
# le rapport plutôt que d'ingérer un contrat qu'on ne suit pas.
ALLOWED_SEVERITIES = ("critical", "high")
SEVERITY_RANK = {"critical": 0, "high": 1}
SCHEMA_VERSION_MIN = 2

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:@/~-]{0,199}$")
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/~-]{0,254}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:~-]{0,119}$")


class ReportError(ValueError):
    """Le rapport ne peut pas être ingéré de confiance (refusé en entier)."""


@dataclass(frozen=True)
class Finding:
    """Une vulnérabilité actionnable de l'image, telle que l'ingestion la conserve."""

    cve: str
    package: str
    severity: str
    installed_version: str
    fixed_version: str
    title: str
    advisory_url: str

    @property
    def key(self) -> str:
        """Identité stable : CVE + package, sans la version installée (voir l'en-tête)."""
        return f"trivy|cve|{self.cve}|{self.package}"

    def to_state(self) -> dict:
        return {
            "key": self.key,
            "cve": self.cve,
            "package": self.package,
            "severity": self.severity,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "title": self.title,
            "advisory_url": self.advisory_url,
        }

    @classmethod
    def from_state(cls, payload: dict) -> "Finding":
        return cls(
            cve=str(payload.get("cve") or ""),
            package=str(payload.get("package") or ""),
            severity=str(payload.get("severity") or ""),
            installed_version=str(payload.get("installed_version") or ""),
            fixed_version=str(payload.get("fixed_version") or ""),
            title=str(payload.get("title") or ""),
            advisory_url=str(payload.get("advisory_url") or ""),
        )


@dataclass(frozen=True)
class Scan:
    """Un rapport validé : l'image qu'il décrit et les findings qu'il porte."""

    image: str
    commit: str
    scanned_at: str
    findings: tuple[Finding, ...]

    def counts(self) -> dict[str, int]:
        return {
            severity: sum(1 for finding in self.findings if finding.severity == severity)
            for severity in ALLOWED_SEVERITIES
        }

    def by_key(self) -> dict[str, Finding]:
        return {finding.key: finding for finding in self.findings}


def _text(
    value: Any,
    *,
    where: str,
    limit: int,
    pattern: re.Pattern[str] | None = None,
    truncate: bool = False,
) -> str:
    """Chaîne bornée, non vide, éventuellement restreinte à une classe de caractères.

    Les champs porteurs d'identité (CVE, paquet, version) sont REFUSÉS au-delà de
    la limite : tronquer un identifiant construirait une baseline sur une valeur
    mutilée. Les textes descriptifs sont tronqués (`truncate=True`) : un titre
    d'avis plus long demain ne doit pas désactiver tout le contrôle.

    La valeur fautive n'est jamais recopiée dans l'erreur : un rapport refusé est
    non fiable et son contenu pourrait finir dans un log ou dans l'interface.
    """
    if not isinstance(value, str):
        raise ReportError(f"Rapport Trivy refusé : {where} doit être une chaîne.")
    if not value:
        raise ReportError(f"Rapport Trivy refusé : {where} est vide.")
    if len(value) > limit:
        if truncate:
            value = value[:limit]
        else:
            raise ReportError(f"Rapport Trivy refusé : {where} dépasse {limit} caractères.")
    if pattern is not None and not pattern.fullmatch(value):
        raise ReportError(f"Rapport Trivy refusé : {where} contient des caractères non autorisés.")
    return value


def _optional_text(
    value: Any,
    *,
    where: str,
    limit: int,
    pattern: re.Pattern[str] | None = None,
    truncate: bool = False,
) -> str:
    if value is None or value == "":
        return ""
    return _text(value, where=where, limit=limit, pattern=pattern, truncate=truncate)


def _advisory_url(value: Any) -> str:
    """Un lien d'avis n'est conservé que si c'est une URL https simple.

    Un lien est décoratif : inutilisable, il est abandonné plutôt que de faire
    échouer le scan ; mais il n'est jamais rendu tel quel — le rendu (HTML, email)
    ne doit jamais recevoir un `href` non validé.
    """
    if not isinstance(value, str) or not value:
        return ""
    if len(value) > 500:
        return ""
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        return ""
    if any(character in value for character in ("\n", "\r", "\t", "<", ">", '"', "'")):
        return ""
    return value


def _scan_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ReportError("Rapport Trivy refusé : CreatedAt manquant.")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReportError("Rapport Trivy refusé : CreatedAt illisible.") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReportError("Rapport Trivy refusé : CreatedAt sans fuseau horaire.")
    # Normalisé à la seconde : l'état persiste et compare ces horodatages, et Trivy
    # émet des nanosecondes que `fromisoformat` tronquerait différemment selon la plateforme.
    return parsed.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _finding(payload: Any, *, where: str) -> Finding:
    if not isinstance(payload, dict):
        raise ReportError(f"Rapport Trivy refusé : {where} doit être un objet.")
    severity = payload.get("Severity")
    if not isinstance(severity, str) or severity.strip().lower() not in ALLOWED_SEVERITIES:
        raise ReportError(
            f"Rapport Trivy refusé : {where}.Severity hors contrat HIGH/CRITICAL."
        )
    return Finding(
        cve=_text(
            payload.get("VulnerabilityID"),
            where=f"{where}.VulnerabilityID",
            limit=MAX_IDENTIFIER_CHARS,
            pattern=_CVE_RE,
        ),
        package=_text(
            payload.get("PkgName"),
            where=f"{where}.PkgName",
            limit=MAX_IDENTIFIER_CHARS,
            pattern=_PACKAGE_RE,
        ),
        severity=severity.strip().lower(),
        installed_version=_optional_text(
            payload.get("InstalledVersion"),
            where=f"{where}.InstalledVersion",
            limit=MAX_VERSION_CHARS,
            pattern=_VERSION_RE,
        ),
        fixed_version=_optional_text(
            payload.get("FixedVersion"),
            where=f"{where}.FixedVersion",
            limit=MAX_VERSION_CHARS,
            pattern=_VERSION_RE,
        ),
        # Descriptif : borné par troncature, jamais refuseur.
        title=" ".join(
            _optional_text(
                payload.get("Title"),
                where=f"{where}.Title",
                limit=MAX_TITLE_CHARS,
                truncate=True,
            ).split()
        ),
        advisory_url=_advisory_url(payload.get("PrimaryURL")),
    )


def validate_report(payload: Any, *, commit: Any) -> Scan:
    """Valide strictement un rapport et l'aplatit en findings. Lève `ReportError`.

    `commit` vient du contexte d'ingestion : le rapport lui-même ne porte pas de SHA
    Git (vérifié sur l'artefact réel), donc l'appelant doit le fournir — un commit
    inexploitable refuse le rapport, la provenance fait partie de ce qui rend
    l'état digne de confiance.
    """
    if not isinstance(payload, dict):
        raise ReportError("Rapport Trivy refusé : document JSON attendu.")
    schema = payload.get("SchemaVersion")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema < SCHEMA_VERSION_MIN:
        raise ReportError(f"Rapport Trivy refusé : SchemaVersion attendu >= {SCHEMA_VERSION_MIN}.")
    if payload.get("ArtifactType") != "container_image":
        raise ReportError("Rapport Trivy refusé : ArtifactType attendu « container_image ».")
    image = _text(payload.get("ArtifactName"), where="ArtifactName", limit=255, pattern=_IMAGE_RE)
    scanned_at = _scan_timestamp(payload.get("CreatedAt"))
    normalised_commit = _text(
        commit, where="commit (contexte d'ingestion)", limit=40, pattern=_COMMIT_RE
    )

    results = payload.get("Results")
    if not isinstance(results, list):
        raise ReportError("Rapport Trivy refusé : Results doit être une liste.")

    findings: list[Finding] = []
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            raise ReportError(f"Rapport Trivy refusé : Results[{result_index}] doit être un objet.")
        vulnerabilities = result.get("Vulnerabilities")
        # Le rapport réel écrit `0` (pas une liste vide) pour un résultat sans finding :
        # les deux veulent dire « rien ici » et ne doivent pas passer pour un document malformé.
        if vulnerabilities in (None, 0, []):
            continue
        if not isinstance(vulnerabilities, list):
            raise ReportError(
                f"Rapport Trivy refusé : Results[{result_index}].Vulnerabilities doit être une liste."
            )
        for finding_index, entry in enumerate(vulnerabilities):
            findings.append(
                _finding(entry, where=f"Results[{result_index}].Vulnerabilities[{finding_index}]")
            )

    if len(findings) > MAX_FINDINGS:
        raise ReportError(
            f"Rapport Trivy refusé : {len(findings)} findings au-delà de la limite ({MAX_FINDINGS})."
        )

    duplicates = len(findings) - len({finding.key for finding in findings})
    if duplicates:
        raise ReportError("Rapport Trivy refusé : findings dupliqués (CVE + paquet).")

    # Ordre déterministe : un rapport identique ré-ingéré produit un état identique,
    # plus sévère d'abord puis par paquet et CVE.
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.package, f.cve))
    return Scan(image=image, commit=normalised_commit, scanned_at=scanned_at, findings=tuple(findings))


def parse_report(raw: bytes, *, commit: Any) -> Scan:
    """Valide les octets du rapport — l'unique porte d'entrée de l'ingestion.

    Prend délibérément des octets, pas un chemin : l'appelant vérifie le SHA-256 de
    ces octets avant de les confier ici, et relire le fichier ouvrirait une fenêtre
    où le contenu vérifié et le contenu analysé diffèrent. Un état construit sur un
    rapport non vérifié est pire qu'un rapport refusé.
    """
    if len(raw) > MAX_REPORT_BYTES:
        raise ReportError(
            f"Rapport Trivy refusé : taille {len(raw)} octets au-delà de la limite "
            f"({MAX_REPORT_BYTES} octets)."
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as error:
        raise ReportError("Rapport Trivy refusé : encodage non UTF-8.") from error
    except ValueError as error:
        raise ReportError("Rapport Trivy refusé : JSON invalide.") from error
    return validate_report(payload, commit=commit)
