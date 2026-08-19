#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK — Centralized Network Security Policy (SEC-004 / SEC-005)

Single choke point for outbound-request safety:

* scheme validation (http/https only),
* hostname normalization (incl. alternative IP notations, via ScopePolicy),
* label-aware domain allowlisting,
* private/loopback/link-local/metadata blocking by default,
* DNS resolution before every hop so hostnames resolving to private ranges are
  treated exactly like literal private IP addresses,
* an explicit scoped-private exception for owner-authorized scans.

Consumers:
* ``utils/requester.Requester`` — validates the request URL and every
  redirect hop when a policy is attached (closes redirect-based scope
  drift),
* ``web/app.py`` repeater endpoint — authenticated SSRF protection,
* ``web/app.py`` tool endpoints keep their dedicated scope helper for
  backward compatibility; both delegate to the same matching rules.

The policy is fail-closed: any parse/validation error denies the request.
Redirect targets are resolved and validated before connection.  Connection-IP
pinning remains transport-adapter specific, so consumers must re-check every
hop immediately before dispatch.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from typing import Optional, Tuple
from urllib.parse import urlparse


_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local + cloud metadata
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_LOCAL_HOSTNAMES = frozenset(
    {"localhost", "ip6-localhost", "ip6-loopback", "metadata.google.internal"}
)


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


class NetworkSecurityPolicy:
    """Deterministic outbound-request policy.  Deny-by-default on errors."""

    def __init__(
        self,
        allowed_domains: Optional[list] = None,
        block_private: bool = False,
        enforce_domains: bool = False,
        resolve_dns: bool = False,
        allow_private_scoped: bool = False,
    ) -> None:
        from core.scope import ScopePolicy  # local import: avoid cycles

        self._normalize = ScopePolicy._normalize_hostname
        self.block_private = bool(block_private)
        self.enforce_domains = bool(enforce_domains)
        self.resolve_dns = bool(resolve_dns)
        self.allow_private_scoped = bool(allow_private_scoped)
        self.allowed_domains = set()
        for d in allowed_domains or []:
            norm = self._normalize(str(d).strip())
            if norm:
                self.allowed_domains.add(norm)
        if self.allowed_domains:
            # Domain allowlist configured -> enforce it.
            self.enforce_domains = True

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "NetworkSecurityPolicy":
        raw = os.environ.get("ATOMIC_ALLOWED_DOMAINS", "").strip()
        domains = [x.strip() for x in raw.split(",") if x.strip()] if raw else []
        return cls(
            allowed_domains=domains,
            # Safe default for the web/repeater surface. Owner-authorized scan
            # targets get a narrowly scoped exception from AtomicEngine.
            block_private=not _truthy_env("ATOMIC_ALLOW_PRIVATE_TARGETS"),
            enforce_domains=_truthy_env("ATOMIC_TOOL_SCOPE_STRICT") or bool(domains),
            resolve_dns=not _truthy_env("ATOMIC_DISABLE_DNS_POLICY"),
            allow_private_scoped=_truthy_env("ATOMIC_ALLOW_PRIVATE_SCOPED"),
        )

    @property
    def active(self) -> bool:
        """True when the policy imposes any constraint at all."""
        return bool(self.allowed_domains) or self.block_private

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def _host_is_explicitly_scoped(self, host: str) -> bool:
        norm = self._normalize(host or "")
        if not norm:
            return False
        return norm in self.allowed_domains or any(
            norm.endswith("." + base) for base in self.allowed_domains if base
        )

    def _resolve_host_ips(self, host: str):
        """Resolve all A/AAAA records without caching (fail closed on errors)."""
        norm = self._normalize((host or "").strip().lower().strip("[]"))
        try:
            return {ipaddress.ip_address(norm)}
        except ValueError:
            pass
        if not self.resolve_dns:
            return set()
        try:
            records = socket.getaddrinfo(norm, None, type=socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            return None
        addresses = set()
        for record in records:
            try:
                addresses.add(ipaddress.ip_address(record[4][0].split("%", 1)[0]))
            except (ValueError, IndexError, TypeError):
                return None
        return addresses or None

    def is_private_host(self, host: str) -> bool:
        """True for loopback/RFC1918/link-local/metadata hosts (IP or name)."""
        h = (host or "").strip().lower().strip("[]")
        if not h:
            return True  # unparseable -> treat as unsafe
        if h in _LOCAL_HOSTNAMES or h.endswith(".localhost") or h.endswith(".local"):
            return True
        norm = self._normalize(h)
        try:
            ip = ipaddress.ip_address(norm or h)
        except ValueError:
            if not self.resolve_dns:
                return False
            addresses = self._resolve_host_ips(norm or h)
            if addresses is None:
                return True
            return any(
                any(ip in net for net in _PRIVATE_NETWORKS)
                for ip in addresses
            )
        return any(ip in net for net in _PRIVATE_NETWORKS)

    def is_host_allowed(self, host: str) -> bool:
        norm = self._normalize(host or "")
        if not norm:
            return False
        if self.block_private and self.is_private_host(norm):
            if not (self.allow_private_scoped and self._host_is_explicitly_scoped(norm)):
                return False
        if not self.enforce_domains:
            return True
        if norm in self.allowed_domains:
            return True
        # Label-aware subdomain match: ``sub.example.com`` matches
        # ``example.com`` but ``evilexample.com`` does not.
        return any(
            norm.endswith("." + base) for base in self.allowed_domains if base
        )

    def allow_url(self, url: str) -> Tuple[bool, str]:
        """Validate a full URL.  Returns (allowed, reason)."""
        try:
            parsed = urlparse(str(url or ""))
        except ValueError:
            return False, "unparseable URL"
        if parsed.scheme.lower() not in ("http", "https"):
            return False, f"scheme '{parsed.scheme}' not allowed"
        host = parsed.hostname or ""
        if not host:
            return False, "missing host"
        if self.resolve_dns:
            try:
                ipaddress.ip_address(self._normalize(host) or host)
            except ValueError:
                if self._resolve_host_ips(host) is None:
                    return False, f"DNS resolution failed for '{host}'"
        if not self.is_host_allowed(host):
            return False, f"host '{host}' outside network policy"
        return True, "ok"
