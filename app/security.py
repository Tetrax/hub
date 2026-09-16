"""Frontière proxy, en-têtes de sécurité, contrôles de provenance.

Le conteneur n'est joignable qu'en loopback (port publié 127.0.0.1:<port>) et
Nginx est le seul proxy. Seules les requêtes dont l'adresse source appartient aux
CIDR de confiance (le gateway du réseau Docker) peuvent influencer la détection
HTTPS ou fournir l'IP cliente.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network

SITE_CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "script-src 'self'; "
    "style-src 'self'; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "frame-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'"
)


def parse_cidrs(raw: str) -> list:
    networks = []
    for chunk in (raw or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            networks.append(ip_network(chunk, strict=False))
        except ValueError:
            continue
    return networks


def _peer_is_trusted(request, trusted: list) -> bool:
    addr = request.remote_addr or ""
    try:
        peer = ip_address(addr)
    except ValueError:
        return False
    return any(peer in network for network in trusted)


def client_ip(request, trusted: list) -> str:
    """IP cliente réelle : X-Forwarded-For (dernier saut) uniquement depuis le proxy de confiance."""
    if _peer_is_trusted(request, trusted):
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            candidate = forwarded.split(",")[-1].strip()
            try:
                ip_address(candidate)
                return candidate
            except ValueError:
                pass
    return request.remote_addr or "inconnu"


def is_https(request, trusted: list) -> bool:
    if request.scheme == "https":
        return True
    if _peer_is_trusted(request, trusted):
        return request.headers.get("X-Forwarded-Proto", "").split(",")[-1].strip() == "https"
    return False


def expected_origin(request, trusted: list) -> str:
    scheme = "https" if is_https(request, trusted) else "http"
    return f"{scheme}://{request.host}"


def origin_ok(request, trusted: list) -> bool:
    """Contrôle d'origine pour les POST : Origin (sinon Referer) doit correspondre.

    Un client non-navigateur sans Origin ni Referer reste accepté : la protection
    principale est le jeton CSRF de session.
    """
    origin = request.headers.get("Origin")
    if origin:
        return origin == expected_origin(request, trusted)
    referer = request.headers.get("Referer")
    if referer:
        return referer.startswith(expected_origin(request, trusted) + "/") or (
            referer == expected_origin(request, trusted)
        )
    return True


def apply_security_headers(response, request, trusted: list):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Content-Security-Policy", SITE_CSP)
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"
    )
    response.headers.setdefault("X-Robots-Tag", "noindex, nofollow, noarchive")
    if is_https(request, trusted):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response
