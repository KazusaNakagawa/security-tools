"""Scope Guard: every network check goes through here (design §7.2).

Requests to anything outside ``scope.yaml`` are refused before they leave the
process, so a bug in a check cannot turn into scanning a third party.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import posixpath
import re
import socket
import ssl
import zlib
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit

import httpcore
import httpx

from alertcheck import __version__
from alertcheck.config.scope import ScopeConfig
from alertcheck.core.masking import mask_text
from alertcheck.core.ratelimit import HostRateLimiter

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str], Awaitable[list[str]]]

_DEFAULT_PORTS = {"http": 80, "https": 443}
_REDIRECT_CODES = {301, 302, 303, 307, 308}
_CREDENTIAL_HEADERS = ("authorization", "cookie", "proxy-authorization")
_BODY_KWARGS = ("content", "data", "files", "json")
_SENSITIVE_PARAM = re.compile(
    r"token|key|secret|pass|pwd|auth|sig|session|code|credential", re.IGNORECASE
)


class ScopeViolation(Exception):
    """A request or tool target was refused by the Scope Guard."""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""
    warnings: tuple[str, ...] = field(default_factory=tuple)


_ALLOW = Decision(True)


def normalize_path(path: str) -> str:
    """Decode, resolve dot segments and collapse slashes, keeping a trailing slash.

    Backslashes are treated as separators because some servers do so; being
    stricter than the server only ever narrows what is allowed.
    """
    decoded = unquote(path or "/").replace("\\", "/")
    trailing = decoded.endswith(("/", "/.", "/..")) or decoded in (".", "..")
    normalized = "/" + posixpath.normpath("/" + decoded).lstrip("/")
    if trailing and normalized != "/":
        normalized += "/"
    return normalized


@dataclass(frozen=True)
class UrlPrefix:
    scheme: str
    host: str
    port: int
    path: str

    @classmethod
    def parse(cls, url: str) -> UrlPrefix:
        """Parse an http(s) URL; raises ValueError for anything else."""
        parts = urlsplit(url)
        if parts.scheme not in _DEFAULT_PORTS or not parts.hostname:
            raise ValueError(f"not an http(s) URL with a host: {url!r}")
        port = parts.port or _DEFAULT_PORTS[parts.scheme]
        return cls(parts.scheme, parts.hostname.lower(), port, normalize_path(parts.path))

    @property
    def origin(self) -> tuple[str, str, int]:
        return (self.scheme, self.host, self.port)

    def covers(self, other: UrlPrefix) -> bool:
        if self.origin != other.origin:
            return False
        base = self.path.rstrip("/")
        return other.path.rstrip("/") == base or other.path.startswith(base + "/")


def _as_ip(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _domain_match(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


async def system_resolver(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


class ScopeGuard:
    def __init__(self, scope: ScopeConfig, *, resolver: Resolver = system_resolver) -> None:
        self._scope = scope
        self._resolver = resolver
        targets = scope.targets
        self._domains = list(targets.domains)
        self._prefixes = [UrlPrefix.parse(u) for u in targets.urls]
        self._networks: list[IPNetwork] = [ipaddress.ip_network(h) for h in targets.hosts] + [
            ipaddress.ip_network(c, strict=False) for c in targets.cidrs
        ]

        # scope.yaml validation guarantees every entry parses as one of these
        self._excl_prefixes: list[UrlPrefix] = []
        self._excl_networks: list[IPNetwork] = []
        self._excl_domains: list[str] = []
        for entry in scope.exclude:
            if "://" in entry:
                self._excl_prefixes.append(UrlPrefix.parse(entry))
                continue
            try:
                self._excl_networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                self._excl_domains.append(entry.strip().lower().rstrip("."))
        self._dns_cache: dict[str, Decision] = {}
        self._pinned: dict[str, str] = {}
        self.warnings: list[str] = []

    @property
    def authorized(self) -> bool:
        return self._scope.authorization.confirmed

    @property
    def allow_private(self) -> bool:
        return self._scope.limits.allow_private_targets

    def _in_networks(self, ip: IPAddress, networks: list[IPNetwork]) -> bool:
        return any(ip.version == n.version and ip in n for n in networks)

    def _host_excluded(self, host: str) -> str | None:
        ip = _as_ip(host)
        if ip is not None:
            if self._in_networks(ip, self._excl_networks):
                return f"excluded: {host}"
            return None
        for domain in self._excl_domains:
            if _domain_match(host, domain):
                return f"excluded by domain {domain}"
        return None

    def _host_in_scope(self, host: str) -> bool:
        ip = _as_ip(host)
        if ip is not None:
            return self._in_networks(ip, self._networks)
        return any(_domain_match(host, d) for d in self._domains)

    def check_host(self, host: str) -> Decision:
        """Whole-host authorization, used for host-wide tools such as nmap.

        A URL-prefix target authorizes only that path, so its host is not
        allowed here unless it is also covered by a domain, IP or CIDR target.
        """
        host = host.lower().rstrip(".")
        if not self.authorized:
            return Decision(False, "authorization.confirmed is false")
        if reason := self._host_excluded(host):
            return Decision(False, reason)
        if self._host_in_scope(host):
            return _ALLOW
        return Decision(False, f"out of scope: {host}")

    def check_url(self, url: str) -> Decision:
        if not self.authorized:
            return Decision(False, "authorization.confirmed is false")
        try:
            target = UrlPrefix.parse(url)
        except ValueError:
            return Decision(False, f"not an http(s) URL: {url}")
        if reason := self._host_excluded(target.host):
            return Decision(False, reason)
        for prefix in self._excl_prefixes:
            if prefix.covers(target):
                return Decision(False, f"excluded by {prefix.scheme}://{prefix.host}{prefix.path}")
        if self._host_in_scope(target.host) or any(p.covers(target) for p in self._prefixes):
            return _ALLOW
        return Decision(False, f"out of scope: {url}")

    async def resolve(self, host: str) -> list[str]:
        """Plain name resolution (no validation), for inventory comparison only."""
        return await self._resolver(host.lower().rstrip("."))

    async def check_resolved(self, host: str) -> Decision:
        """check_host plus validation of where the name actually resolves."""
        decision = self.check_host(host)
        if not decision.allowed:
            return decision
        return await self.validate_resolution(host)

    async def validate_resolution(self, host: str) -> Decision:
        """Validate the addresses a host name resolves to and pin the result.

        IP literals are accepted as-is (they were authorized by check_url or
        check_host). Results are cached so every connection to the host uses
        the same validated address (see PinnedBackend).
        """
        host = host.lower().rstrip(".")
        if _as_ip(host) is not None:
            return _ALLOW
        if host not in self._dns_cache:
            decision, address = await self._validate_dns(host)
            self._dns_cache[host] = decision
            if decision.allowed and address:
                self._pinned[host] = address
            for w in decision.warnings:
                if w not in self.warnings:
                    self.warnings.append(w)
        return self._dns_cache[host]

    async def _validate_dns(self, host: str) -> tuple[Decision, str | None]:
        addresses = await self._resolver(host)
        if not addresses:
            return Decision(False, f"could not resolve {host}"), None
        warnings = []
        for raw in addresses:
            ip = ipaddress.ip_address(raw)
            if self._in_networks(ip, self._excl_networks):
                return Decision(False, f"{host} resolves to excluded address {ip}"), None
            if self._in_networks(ip, self._networks):
                continue
            if not ip.is_global:
                if not self.allow_private:
                    reason = (
                        f"{host} resolves to private/internal address {ip}; "
                        "set limits.allow_private_targets to scan it"
                    )
                    return Decision(False, reason), None
                continue
            if self._networks:
                warnings.append(f"{host} resolves to {ip}, outside targets.hosts/cidrs")
        return Decision(True, warnings=tuple(warnings)), addresses[0]

    def pinned_address(self, host: str) -> str | None:
        """Address a connection to ``host`` may use, or None to refuse it."""
        host = host.lower().rstrip(".")
        ip = _as_ip(host)
        if ip is not None:
            in_scope = self._host_in_scope(host) or any(p.host == host for p in self._prefixes)
            if self.authorized and in_scope and not self._host_excluded(host):
                return str(ip)
            return None
        return self._pinned.get(host)

    async def resolve_targets(self) -> list[str]:
        """Hosts and networks that host-wide tools (nmap, nuclei) may be given."""
        if not self.authorized:
            return []
        out = [d for d in self._domains if (await self.check_resolved(d)).allowed]
        out += [h for h in self._scope.targets.hosts if self.check_host(h).allowed]
        out += list(self._scope.targets.cidrs)
        return out

    def tool_excludes(self) -> list[str]:
        """IPs/CIDRs to pass to tools as explicit excludes (e.g. nmap --exclude)."""
        return [str(n) for n in self._excl_networks]


class PinnedBackend(httpcore.AsyncNetworkBackend):
    """Connects only to the address the Scope Guard validated for a host.

    httpcore passes the original host name here and keeps using it for SNI and
    certificate verification, so swapping in the pinned IP preserves TLS
    semantics while closing the gap between validation and connection.
    """

    def __init__(self, guard: ScopeGuard, inner: httpcore.AsyncNetworkBackend | None = None):
        self._guard = guard
        self._inner = inner or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        address = self._guard.pinned_address(host)
        if address is None:
            raise httpcore.ConnectError(f"scope guard: no validated address for {host}")
        return await self._inner.connect_tcp(
            address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(self, *args: Any, **kwargs: Any) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("scope guard: unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class _PinnedTransport(httpx.AsyncHTTPTransport):
    def __init__(self, guard: ScopeGuard, ssl_context: ssl.SSLContext) -> None:
        super().__init__(verify=ssl_context, trust_env=False)
        # httpx has no public hook for the network backend; replace its pool.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context, network_backend=PinnedBackend(guard)
        )


def redact_url(url: str) -> str:
    """Drop userinfo and hide secret-looking query values before logging."""
    parts = urlsplit(url)
    netloc = parts.netloc.rpartition("@")[2]
    query = urlencode(
        [
            (k, "***" if _SENSITIVE_PARAM.search(k) else v)
            for k, v in parse_qsl(parts.query, keep_blank_values=True)
        ],
        safe="*",
    )
    return mask_text(urlunsplit((parts.scheme, netloc, parts.path, query, "")))


class _BoundedDecoder:
    """Decodes gzip/deflate with a hard cap on output, so compression bombs stay bounded.

    httpx's own decoding yields whole decompressed chunks before the caller can
    stop, which is why raw bytes are decoded here instead.
    """

    def __init__(self, encoding: str) -> None:
        encoding = encoding.strip().lower()
        if encoding in ("gzip", "x-gzip"):
            self._zlib: Any = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif encoding == "deflate":
            self._zlib = zlib.decompressobj(zlib.MAX_WBITS)
        else:
            self._zlib = None  # identity, or an encoding we leave undecoded

    def feed(self, data: bytes, limit: int) -> bytes:
        if self._zlib is None:
            return data[:limit]
        return self._zlib.decompress(data, limit)


async def _read_bounded(response: httpx.Response, max_body: int) -> tuple[bytes, bool]:
    decoder = _BoundedDecoder(response.headers.get("content-encoding", ""))
    out = bytearray()
    raw_budget = 4 * max_body + 64 * 1024  # stop even if compressed data decodes to nothing
    raw_read = 0
    async for raw in response.aiter_raw():
        raw_read += len(raw)
        try:
            out += decoder.feed(raw, max_body + 1 - len(out))
        except zlib.error:
            break
        if len(out) > max_body or raw_read > raw_budget:
            return bytes(out[:max_body]), True
    return bytes(out), False


_URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>]+")


def redact_urls_in(value: Any) -> Any:
    """Apply redact_url to every URL found in strings of a nested structure."""
    if isinstance(value, str):
        return _URL_IN_TEXT.sub(lambda m: redact_url(m.group(0)), value)
    if isinstance(value, dict):
        return {k: redact_urls_in(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_urls_in(v) for v in value]
    return value


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    port = parts.port or _DEFAULT_PORTS.get(parts.scheme, 0)
    return (parts.scheme, (parts.hostname or "").lower(), port)


def _drop_credentials(kwargs: dict[str, Any]) -> dict[str, Any]:
    kwargs = {k: v for k, v in kwargs.items() if k not in ("auth", "cookies")}
    if "headers" in kwargs:
        headers = httpx.Headers(kwargs["headers"])
        for name in _CREDENTIAL_HEADERS:
            headers.pop(name, None)
        kwargs["headers"] = headers
    return kwargs


def _has_url_credentials(url: str) -> bool:
    parts = urlsplit(url)
    return bool(parts.username or parts.password)


def _has_credentials(kwargs: dict[str, Any]) -> bool:
    if kwargs.get("auth") or kwargs.get("cookies"):
        return True
    headers = httpx.Headers(kwargs.get("headers") or {})
    return any(name in headers for name in _CREDENTIAL_HEADERS)


class GuardedHttpClient:
    """httpx client that enforces the Scope Guard on every hop and logs requests.

    Certificates are verified by default. ``verify=False`` exists for checks
    that must inspect sites with broken TLS; such a client refuses to send
    credentials.
    """

    def __init__(
        self,
        guard: ScopeGuard,
        *,
        request_log: Path | None = None,
        rps: float = 5,
        concurrency: int = 4,
        timeout: float = 10,
        max_redirects: int = 10,
        verify: bool = True,
    ) -> None:
        self._guard = guard
        self._log_path = request_log
        self._limiter = HostRateLimiter(rps=rps, concurrency=concurrency)
        self._max_redirects = max_redirects
        self.verify = verify
        ssl_context = httpx.create_ssl_context(verify=verify)
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            trust_env=False,  # an environment proxy would bypass address pinning
            headers={"User-Agent": f"alertcheck/{__version__} (+authorized self-assessment)"},
            transport=_PinnedTransport(guard, ssl_context),
        )

    async def __aenter__(self) -> GuardedHttpClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    def _write_log(self, entry: dict[str, Any]) -> None:
        if self._log_path is None:
            return
        entry = {"ts": datetime.now(UTC).isoformat(), **entry}
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _log_outcome(self, entry: dict[str, Any]) -> None:
        # The intent was already recorded before sending; losing the outcome
        # line must not turn a completed request into a check failure.
        with contextlib.suppress(OSError):
            self._write_log(entry)

    async def _decide(self, url: str) -> Decision:
        decision = self._guard.check_url(url)
        if not decision.allowed:
            return decision
        return await self._guard.validate_resolution(urlsplit(url).hostname or "")

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def _send(
        self, method: str, url: str, max_body: int | None, kwargs: dict[str, Any]
    ) -> httpx.Response:
        if max_body is None:
            return await self._client.request(method, url, **kwargs)
        headers = httpx.Headers(kwargs.pop("headers", None) or {})
        headers.setdefault("accept-encoding", "identity")
        request = self._client.build_request(method, url, headers=headers, **kwargs)
        response = await self._client.send(request, stream=True)
        try:
            content, truncated = await _read_bounded(response, max_body)
        finally:
            await response.aclose()
        limited = httpx.Response(
            response.status_code,
            # the body is already decoded and possibly cut, so these no longer apply
            headers=[
                (k, v)
                for k, v in response.headers.multi_items()
                if k not in ("content-encoding", "content-length", "transfer-encoding")
            ],
            content=content,
            request=request,
        )
        limited.extensions["alertcheck_truncated"] = truncated
        return limited

    async def request(
        self,
        method: str,
        url: str,
        *,
        max_body: int | None = None,
        redirects: int | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Send a scope-checked request.

        ``max_body`` caps how many body bytes are read (the rest is discarded),
        so probing a large dump or archive never downloads it in full.
        ``redirects`` overrides how many redirects to follow; 0 returns the
        first response, redirect or not.
        """
        limit = self._max_redirects if redirects is None else redirects
        if max_body is not None and max_body <= 0:
            raise ValueError("max_body must be positive")
        if "follow_redirects" in kwargs:
            raise ValueError("follow_redirects is not supported; redirects are checked per hop")
        if not self.verify and _has_credentials(kwargs):
            raise ValueError("refusing to send credentials over an unverified TLS client")

        history: list[httpx.Response] = []
        while True:
            if not self.verify and _has_url_credentials(url):
                raise ValueError("refusing to send URL credentials over an unverified TLS client")
            safe_url = redact_url(url)
            decision = await self._decide(url)
            if not decision.allowed:
                self._write_log(
                    {
                        "event": "blocked",
                        "method": method,
                        "url": safe_url,
                        "reason": decision.reason,
                    }
                )
                if not history:
                    raise ScopeViolation(decision.reason)
                last = history.pop()
                last.history = history
                last.extensions["alertcheck_blocked_redirect"] = url
                return last

            intent: dict[str, Any] = {"event": "request", "method": method, "url": safe_url}
            if decision.warnings:
                intent["warnings"] = list(decision.warnings)
            self._write_log(intent)  # raises before sending if the audit log is unwritable

            host = urlsplit(url).hostname or ""
            try:
                async with self._limiter.slot(host):
                    response = await self._send(method, url, max_body, kwargs)
            except Exception as e:
                error = f"{type(e).__name__}: {e}"
                self._log_outcome({"event": "error", "url": safe_url, "error": error})
                raise
            self._log_outcome(
                {"event": "response", "url": safe_url, "status": response.status_code}
            )

            location = response.headers.get("location")
            if response.status_code not in _REDIRECT_CODES or not location or limit == 0:
                response.history = history
                return response
            history.append(response)
            if len(history) > limit:
                raise httpx.TooManyRedirects("too many redirects", request=response.request)

            next_url = urljoin(url, location)
            code = response.status_code
            if (code == 303 and method != "HEAD") or (code in (301, 302) and method == "POST"):
                method = "GET"
                kwargs = {k: v for k, v in kwargs.items() if k not in _BODY_KWARGS}
            if _origin(next_url) != _origin(url):
                kwargs = _drop_credentials(kwargs)
            url = next_url
