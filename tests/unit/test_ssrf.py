import pytest

from keystone.registry.ssrf import UnsafeUpstreamUrl, check_upstream_url, resolve

# Name servers that the tests stand in for. No test touches real DNS.
ZONE = {
    "internal.example": ["10.1.2.3"],
    "metadata.example": ["169.254.169.254"],
    "dual.example": ["93.184.216.34", "10.0.0.5"],
    "dual6.example": ["2606:2800:220:1:248:1893:25c8:1946", "fd00::1"],
    "localhost": ["127.0.0.1", "::1"],
    "public.example": ["93.184.216.34"],
    "public6.example": ["2606:2800:220:1:248:1893:25c8:1946"],
    "empty.example": [],
}


def resolver(host: str) -> list[str]:
    if host not in ZONE:
        raise OSError(f"no such host: {host}")
    return ZONE[host]


IPV4_BLOCKED = [
    "http://127.0.0.1/mcp",
    "http://127.1.2.3:8101/mcp",
    "http://10.0.0.5/",
    "http://172.16.0.1/",
    "http://172.31.255.255/",
    "http://192.168.1.10:9000/mcp",
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://100.64.0.1/",  # CGNAT
    "http://100.127.255.254/",
    "http://0.0.0.0/",
    "http://224.0.0.1/",
    "http://255.255.255.255/",
    "http://192.0.2.1/",
]

IPV6_BLOCKED = [
    "http://[::1]/",
    "http://[::1]:8080/mcp",
    "http://[fc00::1]/",  # unique local
    "http://[fd12:3456:789a::1]/",
    "http://[fd00:ec2::254]/",  # the AWS metadata endpoint over IPv6
    "http://[fe80::1]/",  # link-local
    "http://[fe80::1%25en0]/",
    "http://[::]/",
    "http://[ff02::1]/",
    "http://[::ffff:10.0.0.5]/",  # IPv4-mapped private
    "http://[::ffff:169.254.169.254]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[64:ff9b::a00:1]/",  # NAT64 of 10.0.0.1
    "http://[2002:a00:1::]/",  # 6to4 of 10.0.0.1
    "http://[2001:db8::1]/",  # documentation range
]

HOSTNAMES_BLOCKED = [
    "http://internal.example/mcp",
    "http://metadata.example/",
    "http://dual.example/mcp",  # one private answer among public ones
    "http://dual6.example/mcp",
    "http://localhost:8101/mcp",
    "http://unknown.example/mcp",  # cannot be shown to be public
    "http://empty.example/mcp",
]


@pytest.mark.phase(2)
@pytest.mark.parametrize("url", [*IPV4_BLOCKED, *IPV6_BLOCKED, *HOSTNAMES_BLOCKED])
def test_blocks_private_ranges(url: str) -> None:
    with pytest.raises(UnsafeUpstreamUrl):
        check_upstream_url(url, allow_private=False, resolver=resolver)


@pytest.mark.phase(2)
def test_the_two_addresses_from_the_story_are_refused_by_default() -> None:
    for url in ("http://169.254.169.254/", "http://10.0.0.5/"):
        with pytest.raises(UnsafeUpstreamUrl):
            check_upstream_url(url)


@pytest.mark.phase(2)
@pytest.mark.parametrize(
    "url",
    [
        "http://93.184.216.34/mcp",
        "https://93.184.216.34:8443/mcp",
        "http://8.8.8.8/",
        "http://[2606:2800:220:1:248:1893:25c8:1946]/mcp",
        "http://[2001:4860:4860::8888]:8080/",
        "http://[::ffff:8.8.8.8]/",  # IPv4-mapped public
        "http://public.example/mcp",
        "https://public.example:8443/mcp",
        "http://public6.example/mcp",
    ],
)
def test_allows_public_and_flagged_private(url: str) -> None:
    check_upstream_url(url, allow_private=False, resolver=resolver)


@pytest.mark.phase(2)
@pytest.mark.parametrize("url", [*IPV4_BLOCKED, *IPV6_BLOCKED, *HOSTNAMES_BLOCKED])
def test_allow_private_accepts_what_the_guard_blocks(url: str) -> None:
    check_upstream_url(url, allow_private=True, resolver=resolver)


@pytest.mark.phase(2)
def test_allow_private_does_not_resolve_anything() -> None:
    def fail(host: str) -> list[str]:
        raise AssertionError("the resolver must not be called")

    check_upstream_url("http://mail-mcp:8101/mcp", allow_private=True, resolver=fail)


@pytest.mark.phase(2)
@pytest.mark.parametrize(
    "url",
    [
        "ftp://93.184.216.34/",
        "file:///etc/passwd",
        "gopher://93.184.216.34/",
        "javascript:alert(1)",
        "93.184.216.34/mcp",  # no scheme
        "http:///mcp",  # no host
        "http://user:secret@93.184.216.34/",
        "http://user@93.184.216.34/",
        "http://93.184.216.34:0/",
        "http://93.184.216.34:99999/",
        "http://[::1/",
        "",
    ],
)
@pytest.mark.parametrize("allow_private", [False, True])
def test_the_shape_of_the_url_is_checked_either_way(url: str, allow_private: bool) -> None:
    with pytest.raises(UnsafeUpstreamUrl):
        check_upstream_url(url, allow_private, resolver=resolver)


@pytest.mark.phase(2)
def test_the_message_names_the_range_and_the_switch() -> None:
    with pytest.raises(UnsafeUpstreamUrl) as raised:
        check_upstream_url("http://169.254.169.254/", resolver=resolver)

    assert "link-local" in str(raised.value)
    assert "KEYSTONE_ALLOW_PRIVATE_UPSTREAMS" in str(raised.value)


@pytest.mark.phase(2)
def test_a_url_with_credentials_does_not_echo_them() -> None:
    with pytest.raises(UnsafeUpstreamUrl) as raised:
        check_upstream_url("http://user:hunter2@93.184.216.34/", resolver=resolver)

    assert "hunter2" not in str(raised.value)


@pytest.mark.phase(2)
def test_numeric_host_spellings_are_resolved_like_the_http_client_would() -> None:
    # 2130706433 is 127.0.0.1 as one integer, and getaddrinfo accepts it. The guard must see
    # the address that the client would connect to, not the spelling.
    with pytest.raises(UnsafeUpstreamUrl):
        check_upstream_url("http://2130706433/", resolver=resolve)
    with pytest.raises(UnsafeUpstreamUrl):
        check_upstream_url("http://0x7f.0.0.1/", resolver=resolve)
