"""Scope Guard: every network check goes through here (design §7.2).

Requests to anything outside ``scope.yaml`` are refused before they leave the
process, so a bug in a check cannot turn into scanning a third party.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from alertcheck import __version__
from alertcheck.config.scope import ScopeConfig
from alertcheck.core.ratelimit import HostRateLimiter

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str], Awaitable[list[str]]]

_DEFAULT_PORTS = {"http": 80, "https": 443}
_REDIRECT_CODES = {301, 302, 303, 307, 308}


class ScopeViolation(Exception):
    """A request or tool target was refused by the Scope Guard."""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""
    warnings: tuple[str, ...] = field(default_factory=tuple)


_ALLOW = Decision(True)


@dataclass(frozen=True)
class _UrlPrefix:
    scheme: str
    host: str
    port: int
    path: str

    @classmethod
    def parse(cls, url: str) -> _UrlPrefix | None:
        parts = urlsplit(url)
        if parts.scheme not in _DEFAULT_PORTS or not parts.hostname:
            return None
        try:
            port = parts.port or _DEFAULT_PORTS[parts.scheme]
        except ValueError:
            return None
        return cls(parts.scheme, parts.hostname.lower(), port, parts.path or "/")

    def covers(self, other: _UrlPrefix) -> bool:
        return (
            self.scheme == other.scheme
            and self.host == other.host
            and self.port == other.port
            and other.path.startswith(self.path)
        )


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
        self._prefixes = [p for u in targets.urls if (p := _UrlPrefix.parse(u))]
        self._networks: list[IPNetwork] = [ipaddress.ip_network(h) for h in targets.hosts] + [
            ipaddress.ip_network(c, strict=False) for c in targets.cidrs
        ]

        self._excl_prefixes: list[_UrlPrefix] = []
        self._excl_networks: list[IPNetwork] = []
        self._excl_domains: list[str] = []
        for entry in scope.exclude:
            if "://" in entry:
                if prefix := _UrlPrefix.parse(entry):
                    self._excl_prefixes.append(prefix)
                continue
            try:
                self._excl_networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                self._excl_domains.append(entry.strip().lower().rstrip("."))
        self._dns_cache: dict[str, Decision] = {}

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
        host = host.lower().rstrip(".")
        if not self.authorized:
            return Decision(False, "authorization.confirmed is false")
        if reason := self._host_excluded(host):
            return Decision(False, reason)
        if self._host_in_scope(host) or any(p.host == host for p in self._prefixes):
            return _ALLOW
        return Decision(False, f"out of scope: {host}")

    def check_url(self, url: str) -> Decision:
        if not self.authorized:
            return Decision(False, "authorization.confirmed is false")
        target = _UrlPrefix.parse(url)
        if target is None:
            return Decision(False, f"not an http(s) URL: {url}")
        if reason := self._host_excluded(target.host):
            return Decision(False, reason)
        for prefix in self._excl_prefixes:
            if prefix.covers(target):
                return Decision(False, f"excluded by {prefix.scheme}://{prefix.host}{prefix.path}")
        if self._host_in_scope(target.host) or any(p.covers(target) for p in self._prefixes):
            return _ALLOW
        return Decision(False, f"out of scope: {url}")

    async def check_resolved(self, host: str) -> Decision:
        """check_host plus validation of where the name actually resolves."""
        host = host.lower().rstrip(".")
        decision = self.check_host(host)
        if not decision.allowed or _as_ip(host) is not None:
            return decision
        if host not in self._dns_cache:
            self._dns_cache[host] = await self._validate_dns(host)
        return self._dns_cache[host]

    async def _validate_dns(self, host: str) -> Decision:
        addresses = await self._resolver(host)
        if not addresses:
            return Decision(False, f"could not resolve {host}")
        warnings = []
        for raw in addresses:
            ip = ipaddress.ip_address(raw)
            if self._in_networks(ip, self._networks):
                continue
            if not ip.is_global:
                if not self.allow_private:
                    return Decision(
                        False,
                        f"{host} resolves to private/internal address {ip}; "
                        "set limits.allow_private_targets to scan it",
                    )
                continue
            if self._networks:
                warnings.append(f"{host} resolves to {ip}, outside targets.hosts/cidrs")
        return Decision(True, warnings=tuple(warnings))

    async def resolve_targets(self) -> list[str]:
        """Hosts and networks that external tools (nmap, nuclei) may be given."""
        if not self.authorized:
            return []
        names = list(dict.fromkeys(self._domains + [p.host for p in self._prefixes]))
        out = []
        for name in names:
            if (await self.check_resolved(name)).allowed:
                out.append(name)
        out += [h for h in self._scope.targets.hosts if self.check_host(h).allowed]
        out += list(self._scope.targets.cidrs)
        return out

    def tool_excludes(self) -> list[str]:
        """IPs/CIDRs to pass to tools as explicit excludes (e.g. nmap --exclude)."""
        return [str(n) for n in self._excl_networks]


class GuardedHttpClient:
    """httpx client that enforces the Scope Guard on every hop and logs requests."""

    def __init__(
        self,
        guard: ScopeGuard,
        *,
        request_log: Path | None = None,
        rps: float = 5,
        concurrency: int = 4,
        timeout: float = 10,
        max_redirects: int = 10,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._guard = guard
        self._log_path = request_log
        self._limiter = HostRateLimiter(rps=rps, concurrency=concurrency)
        self._max_redirects = max_redirects
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            verify=False,  # certificate problems are reported by the tls check, not fatal here
            headers={"User-Agent": f"alertcheck/{__version__} (+authorized self-assessment)"},
            transport=transport,
        )

    async def __aenter__(self) -> GuardedHttpClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    def _log(self, entry: dict[str, Any]) -> None:
        if self._log_path is None:
            return
        entry = {"ts": datetime.now(UTC).isoformat(), **entry}
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    async def _decide(self, url: str) -> Decision:
        # httpx resolves the name again when connecting, so a name that changes
        # between the two lookups is not caught. Acceptable for self-owned
        # targets; pin the resolved IP in a custom transport if that changes.
        decision = self._guard.check_url(url)
        if not decision.allowed:
            return decision
        host = urlsplit(url).hostname or ""
        return await self._guard.check_resolved(host)

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        history: list[httpx.Response] = []
        while True:
            decision = await self._decide(url)
            if not decision.allowed:
                self._log(
                    {"method": method, "url": url, "blocked": True, "reason": decision.reason}
                )
                if not history:
                    raise ScopeViolation(decision.reason)
                last = history.pop()
                last.history = history
                last.extensions["alertcheck_blocked_redirect"] = url
                return last

            host = urlsplit(url).hostname or ""
            async with self._limiter.slot(host):
                response = await self._client.request(method, url, **kwargs)
            self._log({"method": method, "url": url, "status": response.status_code})

            location = response.headers.get("location")
            if response.status_code not in _REDIRECT_CODES or not location:
                response.history = history
                return response
            history.append(response)
            if len(history) > self._max_redirects:
                raise httpx.TooManyRedirects("too many redirects", request=response.request)
            if response.status_code == 303:
                method, kwargs = "GET", {k: v for k, v in kwargs.items() if k == "headers"}
            url = urljoin(url, location)
