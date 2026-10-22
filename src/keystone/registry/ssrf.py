"""The SSRF guard for upstream URLs (KS-202).

Whoever can register an upstream makes Keystone send requests to its URL. Without a check, that
URL could name an internal service or the cloud metadata endpoint (169.254.169.254) and Keystone
would fetch from it with its own network access. `check_upstream_url` resolves the host the way
the HTTP client will and refuses every address that is not globally routable.

What it does not do: it checks at registration time. A hostname that resolves to a public address
now and to a private one later (DNS rebinding) passes. Closing that gap means pinning the resolved
address in the HTTP client's transport, which Keystone does not do yet. In production, also keep
the gateway's network policy tight; this check is the first line, not the only one.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Sequence
from urllib.parse import urlsplit

Resolver = Callable[[str], Sequence[str]]

_SCHEMES = ("http", "https")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class UnsafeUpstreamUrl(ValueError):
    """The URL names something Keystone must not connect to, or cannot be checked."""


def resolve(host: str) -> list[str]:
    """Every address the host resolves to, as the system resolver reports them."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    # An IPv6 address can carry a zone ("fe80::1%en0"). The zone is not part of the address.
    return sorted({str(info[4][0]).partition("%")[0] for info in infos})


def _embedded_ipv4(ip: IPAddress) -> IPAddress | None:
    """The IPv4 address hidden inside an IPv6 one, if any. A request to ::ffff:10.0.0.5 reaches
    10.0.0.5, so the IPv4 rules must apply to it too."""
    if isinstance(ip, ipaddress.IPv4Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def blocked_reason(ip: IPAddress) -> str | None:
    """Why Keystone may not connect to this address, or None when it may."""
    inner = _embedded_ipv4(ip)
    if inner is not None:
        reason = blocked_reason(inner)
        if reason is not None:
            return f"{reason} (inside {ip})"
    if ip.is_loopback:
        return "a loopback address"
    if ip.is_link_local:
        return "a link-local address (the cloud metadata endpoint lives here)"
    if ip.is_multicast:
        return "a multicast address"
    if ip.is_unspecified:
        return "the unspecified address"
    # is_global is false for RFC 1918, unique-local (fc00::/7), CGNAT (100.64.0.0/10),
    # documentation and benchmarking ranges. Reserved space has no business hosting a server.
    if ip.is_reserved:
        return "a reserved address"
    if not ip.is_global:
        return "a private or shared address"
    return None


def check_upstream_url(
    url: str, allow_private: bool = False, *, resolver: Resolver = resolve
) -> None:
    """Raise UnsafeUpstreamUrl unless Keystone may connect to `url`.

    The scheme must be http or https, and the URL must name a host and carry no credentials
    (those belong in the vault). Unless `allow_private` is set, the host is resolved and every
    address it resolves to must be public: one private answer among several is enough to refuse.
    A host that does not resolve is refused too, because it cannot be shown to be public.
    `allow_private` skips the address check, never the scheme and shape checks.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise UnsafeUpstreamUrl(f"not a valid URL: {url!r}") from exc
    if parts.scheme.lower() not in _SCHEMES:
        raise UnsafeUpstreamUrl(f"the scheme must be http or https, not {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise UnsafeUpstreamUrl("the URL has no host")
    if parts.username is not None or parts.password is not None:
        raise UnsafeUpstreamUrl("the URL must not carry credentials; store them in the vault")
    if port == 0:
        raise UnsafeUpstreamUrl("port 0 is not a valid port")
    if allow_private:
        return

    try:
        addresses = [ipaddress.ip_address(host.partition("%")[0])]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(a) for a in resolver(host)]
        except (OSError, ValueError) as exc:
            raise UnsafeUpstreamUrl(f"cannot resolve host {host!r}") from exc
    if not addresses:
        raise UnsafeUpstreamUrl(f"host {host!r} resolves to no address")
    for address in addresses:
        reason = blocked_reason(address)
        if reason is not None:
            raise UnsafeUpstreamUrl(
                f"host {host!r} is {reason}: {address}. "
                "Set KEYSTONE_ALLOW_PRIVATE_UPSTREAMS=true only for a local setup"
            )
