"""
Host allowlist: Gauntlet refuses to attack a host it doesn't recognize
as safe, unless the user explicitly overrides it with
--i-own-this-target.

Allowed without override:
    - localhost, 127.0.0.1, ::1
    - any *.localhost
    - Docker Compose service names on the private network used by this
      repo's compose file (gullible-llm, agent-unprotected,
      agent-protected, aegis), with or without a port
    - private IP ranges (RFC 1918 / loopback / link-local), since these
      can only be reached from inside the operator's own network

Anything else requires explicit opt-in, because Gauntlet fires real
HTTP requests designed to find exploitable behavior, and must never be
pointed at a host the operator doesn't control by accident.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

_ALLOWED_COMPOSE_SERVICE_NAMES = {
    "gullible-llm",
    "agent-unprotected",
    "agent-protected",
    "aegis",
    "postgres",
    "redis",
}


class DisallowedHostError(ValueError):
    pass


def _is_private_or_loopback_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def is_host_allowed(url: str, extra_allowlist: set[str] | None = None) -> bool:
    """Return True if ``url``'s host is safe to attack without override."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return False

    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    if host.endswith(".localhost"):
        return True
    if host in _ALLOWED_COMPOSE_SERVICE_NAMES:
        return True
    if extra_allowlist and host in extra_allowlist:
        return True
    if _is_private_or_loopback_ip(host):
        return True
    return False


def assert_host_allowed(
    url: str,
    i_own_this_target: bool = False,
    extra_allowlist: set[str] | None = None,
) -> None:
    """Raise DisallowedHostError unless the host is safe or overridden."""
    if i_own_this_target:
        return
    if not is_host_allowed(url, extra_allowlist=extra_allowlist):
        parsed = urlparse(url)
        raise DisallowedHostError(
            f"Refusing to target host {parsed.hostname!r}: it is not localhost, "
            "a private/Docker network address, or on the allowlist. "
            "If you own this target, pass --i-own-this-target (CLI) or set "
            "i_own_this_target: true in your run config."
        )
