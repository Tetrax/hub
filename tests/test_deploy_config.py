"""V1.3 — portabilité du déploiement : Compose générique, surcharge VPS, scripts hôte.

Ces tests verrouillent les invariants de portabilité sans toucher à la
production : ils lisent les fichiers versionnés et, quand Docker Compose est
disponible, valident le rendu effectif des deux variantes.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# Valeurs qui ne doivent JAMAIS apparaître dans la base générique (elles
# appartiennent à la surcharge VPS ou à la configuration d'installation).
VPS_ONLY = ["172.31.244", "hub.valdev.me", "/home/tetrax", "13744:8000"]


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


def compose_render(files: list[str]) -> str:
    command = ["docker", "compose"]
    for name in files:
        command += ["-f", name]
    command.append("config")
    environment = {**os.environ, "HUB_IMAGE_TAG": "test", "HUB_GIT_SHA": "test"}
    environment.pop("COMPOSE_FILE", None)
    result = subprocess.run(
        command, cwd=REPO, capture_output=True, text=True, timeout=120, env=environment
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


# --- Compose générique -------------------------------------------------------


def test_generic_compose_has_no_vps_values():
    content = read("compose.yaml")
    for value in VPS_ONLY:
        assert value not in content, f"valeur propre au VPS dans compose.yaml : {value}"


def test_generic_compose_is_variable_driven():
    content = read("compose.yaml")
    for variable in (
        "HUB_BIND_IP",
        "HUB_PORT",
        "HUB_UID",
        "HUB_GID",
        "HUB_DATA_PATH",
        "HUB_TRUSTED_PROXY_CIDRS",
        "HUB_TLS_HOSTNAME",
        "HUB_CERT_HELPER_SOCKET",
        "HUB_CERT_HELPER_DIR",
        "HUB_CONTAINER_NAME",
        "HUB_IMAGE_TAG",
    ):
        assert f"${{{variable}" in content, f"variable absente de compose.yaml : {variable}"


def test_generic_compose_keeps_hardening():
    content = read("compose.yaml")
    for guard in (
        "read_only: true",
        "no-new-privileges:true",
        "cap_drop:",
        "- ALL",
        "tmpfs:",
        "user:",
        "healthcheck:",
        "restart: unless-stopped",
    ):
        assert guard in content, f"durcissement perdu dans compose.yaml : {guard}"


def test_generic_compose_does_not_pin_network():
    content = read("compose.yaml")
    assert "subnet" not in content
    assert "ipam" not in content


@requires_compose
def test_generic_compose_config_is_valid_and_neutral():
    rendered = compose_render(["compose.yaml"])
    assert "subnet" not in rendered
    assert 'host_ip: 127.0.0.1' in rendered
    assert 'published: "13744"' in rendered
    assert "user: 1000:1000" in rendered
    assert "container_name: hub-web" in rendered
    assert "source: /run/hub-cert-helper" in rendered
    # Aucun proxy de confiance et aucun hostname par défaut : valeurs neutres.
    assert 'HUB_TRUSTED_PROXY_CIDRS: ""' in rendered
    assert 'HUB_TLS_HOSTNAME: ""' in rendered


# --- Surcharge VPS -----------------------------------------------------------


def stripped(relative: str) -> str:
    """Contenu sans les lignes de commentaire (pour tester les directives réelles)."""
    lines = [line for line in read(relative).splitlines() if not line.lstrip().startswith("#")]
    return "\n".join(lines)


def test_vps_override_contains_only_local_specifics():
    content = read("compose.vps.yaml")
    assert "172.31.244.0/24" in content
    assert "172.31.244.1/32" in content
    assert "hub.valdev.me" in content
    assert "/run/hub-cert-helper" in content
    # Vraie surcharge : pas de redéfinition du service complet.
    assert content.count("services:") == 1
    assert "build:" not in content
    assert "healthcheck:" not in content
    assert "user:" not in content
    assert "cap_drop" not in content


@requires_compose
def test_vps_override_renders_production_configuration():
    rendered = compose_render(["compose.yaml", "compose.vps.yaml"])
    assert "subnet: 172.31.244.0/24" in rendered
    assert "HUB_TRUSTED_PROXY_CIDRS: 172.31.244.1/32" in rendered
    assert "HUB_TLS_HOSTNAME: hub.valdev.me" in rendered
    assert 'host_ip: 127.0.0.1' in rendered
    assert 'published: "13744"' in rendered
    assert "user: 1000:1000" in rendered
    # Une seule occurrence de chaque entrée : la fusion ne duplique rien.
    assert rendered.count("target: 8000") == 1
    assert rendered.count("target: /run/hub-cert-helper") == 1


# --- Configuration d'installation -------------------------------------------


def test_env_example_documents_installation_variables():
    content = read(".env.example")
    for variable in (
        "HUB_BIND_IP",
        "HUB_PORT",
        "HUB_UID",
        "HUB_GID",
        "HUB_TRUSTED_PROXY_CIDRS",
        "HUB_TLS_HOSTNAME",
        "HUB_BACKUP_DIR",
        "HUB_DATA_PATH",
        "HUB_CERT_HELPER_SOCKET",
        "COMPOSE_FILE",
    ):
        assert re.search(rf"^#?{variable}=", content, re.MULTILINE), f"{variable} absent"
    assert "COMPOSE_FILE=compose.yaml:compose.vps.yaml" in content


def test_env_example_has_no_secret():
    """Aucune *valeur* renseignée ne doit ressembler à un secret (le texte explicatif peut en parler)."""
    for line in read(".env.example").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        value = line.split("=", 1)[1].strip().strip('"').strip("'")
        if line.split("=", 1)[0].strip().endswith(("SECRET_KEY", "PASSWORD", "TOKEN")):
            assert value == "", f"valeur sensible renseignée dans .env.example : {line}"
        assert len(value) < 80, f"valeur suspecte dans .env.example : {line}"


def test_env_is_ignored_but_example_is_tracked():
    ignore = read(".gitignore")
    assert re.search(r"^\.env$", ignore, re.MULTILINE)
    assert "!.env.example" in ignore
    result = subprocess.run(
        ["git", "check-ignore", "-q", ".env.example"], cwd=REPO, capture_output=True
    )
    assert result.returncode != 0, ".env.example ne doit pas être ignoré par Git"


# --- Helper certificat : Nginx et Certbot optionnels -------------------------


def test_systemd_unit_no_longer_requires_nginx():
    content = read("deploy/hub-cert-helper.service")
    assert "Requires=nginx.service" not in content
    assert "After=local-fs.target nginx.service" in content  # ordonnancement seulement
    assert "-/run/nginx.pid" in content and "-/var/log/nginx" in content


def test_systemd_unit_keeps_hardening():
    content = read("deploy/hub-cert-helper.service")
    for guard in (
        "User=root",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "PrivateTmp=true",
        "ProtectHome=true",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "RestrictNamespaces=true",
        "MemoryDenyWriteExecute=true",
        "CapabilityBoundingSet=",
        "RuntimeDirectory=hub-cert-helper",
        "ReadWritePaths=/var/lib/hub/certificates /run/hub-cert-helper",
    ):
        assert guard in content, f"protection systemd perdue : {guard}"


def test_helper_env_example_documents_no_nginx_mode():
    content = read("deploy/hub-cert-helper.env.example")
    assert "HUB_CERT_RELOAD_NGINX=1" in content
    assert "prochain" in content or "proxy externe" in content


def test_install_helper_tolerates_missing_certbot():
    content = read("scripts/install-helper.sh")
    assert 'CERTBOT_HOOK_DIR="${HUB_CERTBOT_HOOK_DIR:-/etc/letsencrypt/renewal-hooks/deploy}"' in content
    assert '[ -d "$CERTBOT_HOOK_DIR" ]' in content
    assert "Certbot non détecté" in content
    # Le hook ne doit plus être installé inconditionnellement.
    assert 'install -m 0755 "$REPO/deploy/certbot-deploy-hub.sh" /etc/letsencrypt' not in content
    # Sans systemd, message clair et échec explicite (pas de trace obscure).
    assert "systemd est requis" in content


# --- Nginx générique ---------------------------------------------------------


def test_generic_nginx_example_is_self_contained():
    content = stripped("deploy/nginx/hub-generic.conf.example")
    assert "hub.valdev.me" not in content
    assert "letsencrypt" not in content
    assert "00-application-access" not in content
    for placeholder in ("HOSTNAME", "UPSTREAM", "CERT_PATH", "KEY_PATH"):
        assert placeholder in content
    # En-têtes indispensables au bon fonctionnement derrière proxy.
    assert "X-Forwarded-Proto $scheme" in content
    assert "proxy_set_header Host $http_host" in content


def test_vps_nginx_reference_is_untouched():
    content = read("deploy/nginx/hub.valdev.me.conf")
    assert "server_name hub.valdev.me" in content
    assert "include /etc/nginx/conf.d/00-application-access.conf" in content
    assert "/var/lib/hub/certificates/active/fullchain.pem" in content


# --- Backup / préparation des données ---------------------------------------


def test_backup_script_is_portable():
    content = read("scripts/backup.sh")
    assert "/home/tetrax" not in content
    assert "HUB_BACKUP_DIR" in content
    assert "HUB_BACKUP_KEEP" in content
    assert "HUB_DATA_PATH" in content
    assert "env_value" in content  # lecture de .env
    assert "chmod 600" in content  # archive protégée


def test_prepare_data_dir_script_matches_documented_command():
    content = read("scripts/prepare-data-dir.sh")
    assert "HUB_UID" in content and "HUB_GID" in content and "HUB_DATA_PATH" in content
    assert 'install -d -o "$UID_VALUE" -g "$GID_VALUE"' in content
    assert "sudo" in content


def test_offline_image_scripts_are_trivial_and_present():
    save = read("scripts/save-image.sh")
    load = read("scripts/load-image.sh")
    assert "docker save" in save and "gzip" in save
    assert "docker load" in load
    assert "HUB_IMAGE_TAG" in load


# --- Version applicative -----------------------------------------------------


def test_version_is_thirteen(client):
    from app import __version__

    assert __version__ == "1.3.0"
    body = client.get("/healthz").get_json()
    assert body["version"] == "1.3.0"
