"""V1.4 — déploiement STANDALONE : HTTPS direct, un seul conteneur (D16).

Deux objectifs :

1. **invariants du mode standalone** — un seul service, un seul conteneur, TLS
   servi par l'application, aucune dépendance à un proxy, un fichier Compose
   autonome (Portainer ne gère qu'un fichier), aucune valeur à saisir hormis le
   nom DNS ;
2. **détection de dérive** entre `compose.standalone.yaml` (forcément autonome)
   et `compose.yaml` (base canonique du VPS et du mode « derrière un proxy ») :
   les réglages communs au service applicatif doivent rester identiques.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
STANDALONE = "compose.standalone.yaml"
BASE = "compose.yaml"

HOSTNAME = "hub.standalone.test"
ENV = {
    "HUB_HOSTNAME": HOSTNAME,
    "HUB_HTTPS_PORT": "18443",
    "HUB_IMAGE_TAG": "test",
    "HUB_GIT_SHA": "test",
}


def read(relative: str) -> str:
    return (REPO / relative).read_text(encoding="utf-8")


def compose_available() -> bool:
    if not shutil.which("docker"):
        return False
    result = subprocess.run(
        ["docker", "compose", "version"], capture_output=True, text=True, timeout=30
    )
    return result.returncode == 0


requires_compose = pytest.mark.skipif(
    not compose_available(), reason="Docker Compose indisponible sur cette machine"
)


def compose_config(files: list[str], extra_env: dict | None = None) -> subprocess.CompletedProcess:
    command = ["docker", "compose"]
    for name in files:
        command += ["-f", name]
    command.append("config")
    environment = {**os.environ, **ENV, **(extra_env or {})}
    environment.pop("COMPOSE_FILE", None)
    return subprocess.run(
        command, cwd=REPO, capture_output=True, text=True, timeout=120, env=environment
    )


def render(files: list[str] = [STANDALONE], extra_env: dict | None = None) -> dict:
    result = compose_config(files, extra_env)
    assert result.returncode == 0, result.stderr
    return yaml.safe_load(result.stdout)


# --- Un seul conteneur, aucun proxy -------------------------------------------


def test_standalone_has_exactly_one_service():
    document = yaml.safe_load(read(STANDALONE))
    assert list(document["services"]) == ["web"]


def test_no_proxy_component_anywhere_for_the_standalone():
    """Ni Caddy, ni Nginx, ni Traefik : le serveur applicatif termine TLS."""
    document = yaml.safe_load(read(STANDALONE))
    # Aucun service ni image de proxy (les commentaires, eux, peuvent en parler).
    rendered = yaml.safe_dump(document).lower()
    assert "caddy" not in rendered
    assert "nginx" not in rendered
    assert "traefik" not in rendered
    assert "hub-proxy" not in rendered
    # Aucun fichier de proxy résiduel dans le dépôt.
    assert not (REPO / "deploy" / "standalone").exists()
    assert not list((REPO / "app" / "standalone").glob("*caddy*"))


def test_standalone_file_is_self_contained():
    text = read(STANDALONE)
    assert "compose.vps.yaml" not in text
    assert "COMPOSE_FILE" not in text
    document = yaml.safe_load(text)
    assert set(document["volumes"]) == {"hub_data", "hub_certs"}


def test_only_hostname_is_required_from_the_user():
    document = yaml.safe_load(read(STANDALONE))
    environment = document["services"]["web"]["environment"]
    assert environment["HUB_TLS_HOSTNAME"] == "${HUB_HOSTNAME:?HUB_HOSTNAME est requis (nom DNS du Hub)}"
    # Tout le reste est interne au standalone : une seule variable à saisir.
    assert not any(
        ":?" in str(value) for key, value in environment.items() if key != "HUB_TLS_HOSTNAME"
    )


def test_no_placeholder_left_in_the_standalone_file():
    text = read(STANDALONE)
    for marker in ("example.com", "CHANGEME", "TODO"):
        assert marker not in text


# --- Invariants de sécurité ---------------------------------------------------


@requires_compose
def test_container_hardening():
    service = render()["services"]["web"]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert service["restart"] == "unless-stopped"
    assert service.get("privileged", False) is False
    assert service.get("network_mode") != "host"
    # L'image porte déjà l'utilisateur applicatif (1000:1000).
    assert "user" not in service
    assert "USER 1000:1000" in read("Dockerfile")


@requires_compose
def test_no_docker_socket_and_named_volumes_only():
    service = render()["services"]["web"]
    volumes = service["volumes"]
    assert not any("docker.sock" in str(entry) for entry in volumes)
    assert not any("runtime/data" in str(entry) for entry in volumes)
    targets = {entry["target"] for entry in volumes if isinstance(entry, dict)}
    assert targets == {"/data", "/certs"}
    for entry in volumes:
        assert entry["type"] == "volume", "le standalone n'utilise que des volumes Docker nommés"


@requires_compose
def test_only_https_is_published_on_a_non_privileged_container_port():
    service = render()["services"]["web"]
    assert service["ports"] == [
        {"mode": "ingress", "target": 8443, "published": "18443", "protocol": "tcp"}
    ]


@requires_compose
def test_tls_direct_configuration():
    environment = render()["services"]["web"]["environment"]
    assert environment["HUB_TLS_CERT"] == "/certs/active/fullchain.pem"
    assert environment["HUB_TLS_KEY"] == "/certs/active/privkey.pem"
    assert environment["HUB_TLS_BIND_PORT"] == "8443"
    assert environment["HUB_CERTS_DIR"] == "/certs"
    # Backend local : le serveur HTTPS du conteneur est rechargé par SIGHUP.
    assert environment["HUB_CERT_BACKEND"] == "local"
    assert environment["HUB_GUNICORN_PIDFILE"] == "/tmp/gunicorn.pid"
    assert environment["HUB_TLS_HOSTNAME"] == HOSTNAME
    # Pas de frontière proxy : le conteneur termine lui-même TLS.
    assert "HUB_TRUSTED_PROXY_CIDRS" not in environment


@requires_compose
def test_healthcheck_checks_https():
    service = render()["services"]["web"]
    test = " ".join(service["healthcheck"]["test"])
    assert "https://127.0.0.1:8443/healthz" in test
    assert service["tmpfs"] == ["/tmp:rw,noexec,nosuid,size=64m"]


@requires_compose
def test_no_subnet_is_imposed():
    document = render()
    for network in (document.get("networks") or {}).values():
        assert not network.get("ipam"), "sous-réseau imposé"


# --- Réseau Docker externe et IPv4 statique (toutes deux optionnelles) --------


def test_network_interpolation_stays_environment_neutral():
    """Le réseau du stack reste générique : aucune valeur propre à un hôte."""
    text = read(STANDALONE)
    assert "${HUB_DOCKER_NETWORK:-${COMPOSE_PROJECT_NAME:-hub-standalone}_default}" in text
    assert "external: ${HUB_DOCKER_NETWORK_EXTERNAL:-false}" in text
    assert "ipv4_address: ${HUB_IPV4_ADDRESS:-}" in text
    # Seule adresse littérale tolérée : la boucle locale du healthcheck.
    addresses = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text))
    assert addresses <= {"127.0.0.1"}, f"adresse propre à un environnement : {addresses}"


@requires_compose
def test_network_defaults_to_the_project_network():
    """Aucune variable réseau : réseau du projet (comportement historique)."""
    network = render()["networks"]["default"]
    assert network["name"].startswith("hub-standalone")
    assert network["name"].endswith("_default")
    assert network.get("external", False) is False
    assert "ipam" not in network


@requires_compose
def test_static_ip_is_optional_and_dropped_when_empty():
    # Sans HUB_IPV4_ADDRESS : la clé disparaît du rendu (configuration valide,
    # Docker attribue une adresse normalement).
    service = render()["services"]["web"]
    assert "ipv4_address" not in (service.get("networks") or {}).get("default", {})
    # Avec HUB_IPV4_ADDRESS : l'adresse est portée par le service.
    configured = render(extra_env={"HUB_IPV4_ADDRESS": "172.30.250.12"})["services"]["web"]
    assert configured["networks"]["default"]["ipv4_address"] == "172.30.250.12"


@requires_compose
def test_external_network_attachment_is_variable_driven():
    document = render(
        extra_env={"HUB_DOCKER_NETWORK": "hub-corp", "HUB_DOCKER_NETWORK_EXTERNAL": "true"}
    )
    network = document["networks"]["default"]
    assert network["name"] == "hub-corp"
    assert network["external"] is True


@requires_compose
def test_empty_network_variables_never_break_the_standard_case():
    """Variables laissées vides (champ Portainer vide) : configuration valide."""
    document = render(
        extra_env={
            "HUB_DOCKER_NETWORK": "",
            "HUB_DOCKER_NETWORK_EXTERNAL": "",
            "HUB_IPV4_ADDRESS": "",
        }
    )
    network = document["networks"]["default"]
    assert network["name"].endswith("_default")
    assert network.get("external", False) is False
    assert "ipv4_address" not in (document["services"]["web"].get("networks") or {}).get(
        "default", {}
    )


def test_network_variables_are_documented():
    for relative in (".env.example", "docs/operations.md", "README.md"):
        text = read(relative)
        assert "HUB_DOCKER_NETWORK" in text, relative
        assert "HUB_IPV4_ADDRESS" in text, relative


# --- Détection de dérive ------------------------------------------------------


@requires_compose
def test_common_settings_do_not_drift_from_base_compose():
    """Le standalone est autonome (contrainte Portainer) : ce test est le filet
    qui détecte une divergence silencieuse avec la base canonique."""
    standalone = render([STANDALONE])["services"]["web"]
    base = render([BASE])["services"]["web"]

    for field in ("read_only", "security_opt", "cap_drop", "restart"):
        assert standalone[field] == base[field], f"divergence sur {field}"
    assert base["user"] == "1000:1000"
    assert standalone["build"] == base["build"]
    assert standalone["image"].split(":")[0] == base["image"].split(":")[0]
    assert standalone["tmpfs"] == base["tmpfs"]

    base_env = base["environment"]
    standalone_env = standalone["environment"]
    for key in ("HUB_DATA_DIR", "HUB_SESSION_TTL_SECONDS", "HUB_GIT_SHA"):
        assert standalone_env[key] == base_env[key], f"divergence sur {key}"


@requires_compose
def test_base_compose_is_untouched_by_the_standalone():
    """La base canonique (VPS, proxy externe) ne doit pas changer de nature."""
    base = render([BASE])["services"]["web"]
    assert "HUB_CERT_BACKEND" not in base["environment"]
    assert "HUB_TLS_CERT" not in base["environment"]
    assert base["container_name"] == "hub-web"
    port = base["ports"][0]
    assert port["target"] == 8000 and port["published"] == "13744"


# --- Image et entrypoint ------------------------------------------------------


def test_image_serves_http_or_https_without_a_second_dockerfile():
    """Une seule image : le mode dépend de la configuration, pas d'un Dockerfile."""
    dockerfiles = sorted(path.name for path in REPO.glob("Dockerfile*"))
    assert dockerfiles == ["Dockerfile"]
    text = read("Dockerfile")
    assert 'ENTRYPOINT ["/opt/hub/app/standalone/entrypoint.sh"]' in text
    assert "EXPOSE 8000 8443" in text


def test_entrypoint_is_transparent_in_http_mode_and_bootstraps_in_https():
    entrypoint = read("app/standalone/entrypoint.sh")
    assert 'if [ -n "${HUB_TLS_CERT:-}" ]' in entrypoint
    assert "python -m app.certlocal bootstrap" in entrypoint
    assert "exec \"$@\"" in entrypoint
    # Aucune orchestration lourde : ni boucle de surveillance, ni processus multiples.
    assert entrypoint.count("exec ") == 1
    assert "gosu" not in entrypoint and "supervisord" not in entrypoint


def test_bootstrap_module_is_the_single_source():
    module = read("app/certlocal.py")
    assert "def bootstrap_certificate" in module
    assert "hub_certctl" in module  # validation/activation partagées avec le helper du VPS
    assert "signal.SIGHUP" in module or "signal" in module


def test_compose_standalone_is_referenced_in_the_documentation():
    for document in ("README.md", "docs/operations.md", "docs/state.md"):
        assert STANDALONE in read(document), f"{document} doit documenter {STANDALONE}"
