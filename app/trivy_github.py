"""Accès GitHub Actions : dernier run réussi, artefact `trivy-report`, téléchargement.

Hub est un **consumer** : il ne scanne jamais, n'inspecte jamais Docker et ne lance
rien. Il lit l'API GitHub en lecture seule (dépôt public `Tetrax/hub`, workflow
`ci.yml`, branche `main`) et télécharge l'artefact déjà produit par la CI.

Accès vérifié le 2026-09-17 : la liste des runs et des artefacts est publique, mais
**le téléchargement de l'artefact exige une authentification** (401 « Requires
authentication ») — d'où un jeton en lecture seule (`HUB_GITHUB_TOKEN`, portée
Actions: Read, jamais Contents rw). Le jeton n'apparaît jamais dans un message
d'erreur, un log ou une réponse HTTP, et il n'est envoyé qu'à `api.github.com` :
une redirection inter-hôtes (URL signée de l'artefact) le voit retiré.

Le ZIP de l'artefact est traité comme une entrée non fiable : nombre d'entrées
borné, noms à un seul composant (pas de `../`, pas d'absolu, pas de répertoire),
tailles bornées, extraction en mémoire — un seul JSON attendu, `trivy.json`.
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass

REPO = "Tetrax/hub"
WORKFLOW = "ci.yml"
BRANCH = "main"
ARTIFACT_NAME = "trivy-report"
REPORT_FILENAME = "trivy.json"

API_ROOT = "https://api.github.com"
# Le jeton n'est porté que vers cet hôte (les tests le redirigent vers un serveur local).
API_NETLOC = "api.github.com"
MAX_API_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_ZIP_ENTRIES = 4
API_TIMEOUT = 20
DOWNLOAD_TIMEOUT = 60
USER_AGENT = "sns-hub-trivy-consumer"


class GitHubError(RuntimeError):
    """La récupération n'a pas abouti ; rien en local n'a été modifié."""


@dataclass(frozen=True)
class RunInfo:
    """Le dernier run réussi du workflow de scan sur la branche suivie."""

    run_id: str
    commit: str
    run_url: str
    started_at: str


class _StripAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """Retire l'en-tête Authorization dès que la redirection change d'hôte.

    Le téléchargement d'un artefact redirige vers une URL signée (autre hôte) :
    y renvoyer le jeton le ferait fuiter hors d'api.github.com.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_request = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_request is None:
            return None
        old_host = urllib.parse.urlsplit(req.full_url).netloc
        new_host = urllib.parse.urlsplit(newurl).netloc
        if old_host != new_host:
            new_request.headers.pop("Authorization", None)
        return new_request


_OPENER = urllib.request.build_opener(_StripAuthOnRedirect)


def _fetch(url: str, token: str, *, timeout: int, max_bytes: int) -> bytes:
    """GET borné, jeton porté uniquement vers api.github.com. Lève `GitHubError`."""
    request = urllib.request.Request(url, method="GET")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    request.add_header("User-Agent", USER_AGENT)
    if token and urllib.parse.urlsplit(url).netloc == API_NETLOC:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise GitHubError(
                        f"Réponse GitHub au-delà de la limite ({max_bytes} octets)."
                    )
                chunks.append(chunk)
            return b"".join(chunks)
    except urllib.error.HTTPError as error:
        status = error.code
        if status == 401:
            raise GitHubError(
                "GitHub a refusé le jeton (401). Vérifier HUB_GITHUB_TOKEN "
                "(lecture seule, portée Actions)."
            ) from error
        if status == 403:
            raise GitHubError(
                "Accès GitHub refusé (403) : jeton insuffisant, expiré ou quota atteint."
            ) from error
        if status == 404:
            raise GitHubError("Ressource GitHub introuvable (404) : dépôt, run ou artefact.")
        if status == 429:
            raise GitHubError("Quota GitHub atteint (429) : réessayer plus tard.")
        raise GitHubError(f"Réponse GitHub inattendue (HTTP {status}).") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise GitHubError(f"GitHub inaccessible ({type(error).__name__}).") from error


def _json_payload(raw: bytes, *, what: str) -> dict:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise GitHubError(f"Réponse GitHub illisible ({what}).") from error
    if not isinstance(payload, dict):
        raise GitHubError(f"Réponse GitHub inattendue ({what}).")
    return payload


def latest_successful_run(token: str) -> RunInfo:
    """Dernier run **réussi** du workflow CI sur la branche suivie."""
    url = (
        f"{API_ROOT}/repos/{REPO}/actions/workflows/{WORKFLOW}/runs"
        f"?branch={urllib.parse.quote(BRANCH)}&status=success&per_page=1"
    )
    payload = _json_payload(
        _fetch(url, token, timeout=API_TIMEOUT, max_bytes=MAX_API_BYTES), what="liste des runs"
    )
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list) or not runs:
        raise GitHubError(
            f"Aucun run réussi du workflow {WORKFLOW} sur {BRANCH} pour {REPO}."
        )
    run = runs[0]
    if not isinstance(run, dict):
        raise GitHubError("Description de run invalide.")
    run_id = run.get("id")
    commit = run.get("head_sha")
    run_url = run.get("html_url")
    started_at = run.get("run_started_at") or run.get("created_at")
    if not isinstance(run_id, int) or not isinstance(commit, str) or not commit:
        raise GitHubError("Run GitHub incomplet (identifiant ou commit manquant).")
    if not isinstance(run_url, str) or not run_url.startswith("https://github.com/"):
        raise GitHubError("Run GitHub sans URL exploitable.")
    if not isinstance(started_at, str) or not started_at:
        raise GitHubError("Run GitHub sans horodatage exploitable.")
    return RunInfo(
        run_id=str(run_id),
        commit=commit[:40],
        run_url=run_url,
        started_at=started_at,
    )


def find_artifact(run_id: str, token: str) -> int:
    """Identifiant de l'artefact `trivy-report` d'un run (refuse absent ou expiré)."""
    url = f"{API_ROOT}/repos/{REPO}/actions/runs/{urllib.parse.quote(run_id)}/artifacts?per_page=100"
    payload = _json_payload(
        _fetch(url, token, timeout=API_TIMEOUT, max_bytes=MAX_API_BYTES), what="liste des artefacts"
    )
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        raise GitHubError("Liste d'artefacts illisible.")
    for artifact in artifacts:
        if not isinstance(artifact, dict) or artifact.get("name") != ARTIFACT_NAME:
            continue
        if artifact.get("expired"):
            raise GitHubError(
                f"L'artefact {ARTIFACT_NAME} du run {run_id} a expiré ; "
                "attendre le prochain scan (quotidien) ou relancer le workflow."
            )
        artifact_id = artifact.get("id")
        if not isinstance(artifact_id, int):
            raise GitHubError("Artefact sans identifiant exploitable.")
        return artifact_id
    raise GitHubError(f"Artefact {ARTIFACT_NAME} absent du run {run_id}.")


def download_artifact(artifact_id: int, token: str) -> bytes:
    """Octets du ZIP d'artefact, bornés (le téléchargement redirige vers une URL signée)."""
    url = f"{API_ROOT}/repos/{REPO}/actions/artifacts/{artifact_id}/zip"
    return _fetch(url, token, timeout=DOWNLOAD_TIMEOUT, max_bytes=MAX_ARTIFACT_BYTES)


def _safe_zip_entries(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Entrées du ZIP, bornées : un seul niveau, pas de `../`, pas de répertoire, pas de lien."""
    infos = archive.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise GitHubError(
            f"Artefact inattendu : {len(infos)} entrées au-delà de la limite ({MAX_ZIP_ENTRIES})."
        )
    kept: list[zipfile.ZipInfo] = []
    for info in infos:
        name = info.filename
        if not name or name.endswith("/") or "/" in name or "\\" in name or name.startswith("."):
            raise GitHubError("Artefact refusé : entrée au chemin non contrôlé.")
        if name in (".", "..") or ".." in name.split("/"):
            raise GitHubError("Artefact refusé : tentative de traversée de chemin.")
        kept.append(info)
    return kept


def extract_report(zip_bytes: bytes) -> bytes:
    """Extrait l'unique rapport `trivy.json` du ZIP, en mémoire, taille bornée."""
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
            entries = _safe_zip_entries(archive)
            candidates = [entry for entry in entries if entry.filename.lower().endswith(".json")]
            preferred = [entry for entry in candidates if entry.filename == REPORT_FILENAME]
            if len(preferred) == 1:
                chosen = preferred[0]
            elif len(candidates) == 1:
                # Un renommage futur du fichier ne doit pas casser silencieusement l'ingestion.
                chosen = candidates[0]
            else:
                raise GitHubError(
                    "Artefact inattendu : un seul rapport JSON attendu "
                    f"({len(candidates)} trouvé(s))."
                )
            if chosen.file_size > MAX_ARTIFACT_BYTES:
                raise GitHubError("Rapport refusé : taille annoncée au-delà de la limite.")
            with archive.open(chosen) as stream:
                raw = stream.read(MAX_ARTIFACT_BYTES + 1)
            if len(raw) > MAX_ARTIFACT_BYTES:
                raise GitHubError("Rapport refusé : taille au-delà de la limite.")
            return raw
    except zipfile.BadZipFile as error:
        raise GitHubError("Artefact illisible (ZIP corrompu).") from error
