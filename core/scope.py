#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK
Scope & Policy Engine

Enforces target scope and scanning policies:
  - Validates endpoints against allowed domains, subdomains, and paths
  - Respects robots.txt and sitemap.xml directives
  - Blocks out-of-scope endpoints
  - Enforces rate-limit policies
"""

import time
import threading
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser


from config import Colors

# Default user-agent name for robots.txt compliance
SCANNER_USER_AGENT = "AtomicScanner"

# Polite default: 10 requests per second across all modules.
# 0 = unlimited.  Override via --rate-limit on the CLI or
# config["rate_limit"].
DEFAULT_RATE_LIMIT = 10.0


class ScopePolicy:
    """Defines and enforces scanning scope and policies."""

    def __init__(self, engine):
        self.engine = engine
        self.verbose = engine.config.get("verbose", False)
        self.strict_scope = bool(engine.config.get("strict_scope", False))
        scope_cfg = engine.config.get("scope", {})

        # Scope boundaries
        self.allowed_domains = set()
        self.allowed_subdomains = set()
        self.allowed_paths = list(scope_cfg.get("allowed_paths", []))
        self.excluded_paths = list(scope_cfg.get("excluded_paths", []))

        for domain in scope_cfg.get("allowed_domains", []):
            cleaned = str(domain).strip().lower()
            if not cleaned:
                continue
            self.allowed_domains.add(cleaned)
            self.allowed_subdomains.add(cleaned)
            # Never derive a scope boundary from the last two labels.
            # That is incorrect for public suffixes such as ``co.uk`` and
            # could turn an allowlist entry like ``example.co.uk`` into a
            # wildcard for every ``*.co.uk`` host.  Subdomain scope is
            # derived only from the complete configured hostname below.

        # robots.txt compliance
        self.robots_parser = None
        self.robots_loaded = False

        # Rate limiting
        self.rate_limit = engine.config.get("rate_limit", DEFAULT_RATE_LIMIT)
        self._last_request_time = 0.0
        self._request_count = 0
        # The rate-limit state is mutated from every thread that issues
        # an HTTP request (worker pool, module thread pools, race
        # tester, etc.).  Without this lock concurrent callers all
        # observe the same ``_last_request_time`` and skip the throttle
        # in lock-step, producing bursts well above ``rate_limit``.
        self._rate_lock = threading.Lock()

        # Statistics
        self.blocked_count = 0
        self.allowed_count = 0

    # ------------------------------------------------------------------
    # Scope definition
    # ------------------------------------------------------------------

    def set_target_scope(self, target_url):
        """Derive scope boundaries from the primary target URL."""
        parsed = urlparse(target_url)
        domain = self._normalize_hostname(parsed.hostname or "")

        # In strict scope mode with explicit domains configured, do not
        # auto-expand scope from target to avoid widening boundaries.
        if self.strict_scope and self.allowed_domains:
            if self.verbose:
                print(f"{Colors.info(f'Scope (strict): allowed={sorted(self.allowed_domains)}')}")
            return

        if domain:
            self.allowed_domains.add(domain)
            # Only this exact target hostname becomes the subdomain boundary.
            # This avoids the unsafe ``last two labels`` heuristic.
            self.allowed_subdomains.add(domain)

        if self.verbose:
            print(f"{Colors.info(f'Scope: domain={domain}')}")

    def load_robots_txt(self, target_url):
        """Fetch and parse robots.txt for scope-aware crawling."""
        parsed = urlparse(target_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        try:
            self.robots_parser = RobotFileParser()
            self.robots_parser.set_url(robots_url)
            self.robots_parser.read()
            self.robots_loaded = True

            # Extract disallowed paths as excluded paths
            if hasattr(self.robots_parser, "entries"):
                for entry in self.robots_parser.entries:
                    for line in entry.rulelines:
                        if not line.allowance:
                            self.excluded_paths.append(line.path)

            if self.verbose:
                print(f"{Colors.info(f'robots.txt loaded: {len(self.excluded_paths)} disallowed paths')}")
        except Exception:
            self.robots_loaded = False
            if self.verbose:
                print(f"{Colors.warning('Could not load robots.txt')}")

    # ------------------------------------------------------------------
    # Scope validation
    # ------------------------------------------------------------------

    def is_in_scope(self, url):
        """Check whether a URL falls within the defined scan scope.

        Returns True if in scope, False if out of scope (should be skipped).
        """
        parsed = urlparse(url)
        domain = self._normalize_hostname(parsed.hostname or "")
        if parsed.scheme.lower() not in ("http", "https") or not domain:
            self.blocked_count += 1
            return False

        # Check domain scope
        if not self._domain_allowed(domain):
            self.blocked_count += 1
            return False

        # Check excluded paths using URL path-segment boundaries.
        # A rule such as "/admin" must match "/admin" and "/admin/...",
        # but must not accidentally match "/administrator".
        path = parsed.path or "/"
        for excluded in self.excluded_paths:
            if self._path_matches_rule(path, excluded):
                self.blocked_count += 1
                return False

        # Check robots.txt compliance
        if self.robots_loaded and self.robots_parser:
            if not self.robots_parser.can_fetch(SCANNER_USER_AGENT, url):
                self.blocked_count += 1
                return False

        # Check allowed paths (if explicitly set), also respecting
        # path-segment boundaries so "/api" does not authorize "/apix".
        if self.allowed_paths:
            if not any(self._path_matches_rule(path, ap) for ap in self.allowed_paths):
                self.blocked_count += 1
                return False

        self.allowed_count += 1
        return True

    @staticmethod
    def _path_matches_rule(path: str, rule: str) -> bool:
        """Return True when *path* is exactly *rule* or a descendant.

        Path policy entries are normalized to URL-path semantics rather than
        raw string prefixes. This prevents accidental scope expansion such as
        allowing ``/api`` to also allow ``/apix``.
        """
        path = str(path or "/")
        rule = str(rule or "/")
        if not rule.startswith("/"):
            rule = "/" + rule
        if rule != "/" and rule.endswith("/"):
            rule = rule.rstrip("/")
        if rule == "/":
            return path.startswith("/")
        return path == rule or path.startswith(rule + "/")

    @staticmethod
    def _normalize_hostname(hostname: str) -> str:
        """Canonicalize a DNS hostname for safe scope comparisons."""
        value = (hostname or "").strip().rstrip(".").lower()
        if not value:
            return ""
        try:
            return value.encode("idna").decode("ascii")
        except UnicodeError:
            return ""

    def _domain_allowed(self, domain):
        """Check whether a hostname is exactly allowed or a true subdomain.

        Matching is label-aware: ``evil-example.com`` never matches
        ``example.com`` and ``attacker.co.uk`` never matches ``example.co.uk``.
        """
        domain = self._normalize_hostname(domain)
        if not domain:
            return False

        if domain in self.allowed_domains or domain in self.allowed_subdomains:
            return True

        for base in self.allowed_subdomains:
            base = self._normalize_hostname(base)
            if base and domain.endswith("." + base):
                return True

        return False

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def enforce_rate_limit(self):
        """Sleep if necessary to respect the configured rate limit.

        Thread-safe: the read-modify-write cycle on ``_last_request_time``
        is serialised with ``_rate_lock`` so concurrent worker threads
        don't all observe the same timestamp and bypass the throttle.
        """
        if self.rate_limit <= 0:
            return

        min_interval = 1.0 / self.rate_limit
        with self._rate_lock:
            now = time.time()
            elapsed = now - self._last_request_time

            if elapsed < min_interval:
                sleep_for = min_interval - elapsed
            else:
                sleep_for = 0.0

            # Reserve our slot BEFORE releasing the lock so that a
            # second thread arriving immediately after us computes its
            # interval relative to our reserved slot, not the previous
            # one.  This prevents two threads from each computing
            # "no wait needed" against the same baseline.
            self._last_request_time = now + sleep_for
            self._request_count += 1

        if sleep_for > 0:
            time.sleep(sleep_for)

    # ------------------------------------------------------------------
    # Filtering helpers
    # ------------------------------------------------------------------

    def filter_urls(self, urls):
        """Filter a set of URLs, keeping only in-scope ones."""
        filtered = set()
        for url in urls:
            if self.is_in_scope(url):
                filtered.add(url)
        return filtered

    def filter_parameters(self, parameters):
        """Filter parameter tuples, keeping only in-scope ones."""
        filtered = []
        for param_tuple in parameters:
            url = param_tuple[0] if isinstance(param_tuple, (list, tuple)) else param_tuple.get("url", "")
            if self.is_in_scope(url):
                filtered.append(param_tuple)
        return filtered

    def get_scope_summary(self):
        """Return a summary of scope enforcement statistics."""
        return {
            "allowed_domains": list(self.allowed_domains),
            "excluded_paths": len(self.excluded_paths),
            "robots_loaded": self.robots_loaded,
            "allowed_count": self.allowed_count,
            "blocked_count": self.blocked_count,
        }
