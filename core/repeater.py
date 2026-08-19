#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ATOMIC FRAMEWORK
Repeater - Manual HTTP Request Replay & Modification Tool"""

import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

# ------------------------------------------------------------------ #
#  RepeaterResponse                                                   #
# ------------------------------------------------------------------ #


class RepeaterResponse:
    """Immutable container for an HTTP response and its originating request."""

    __slots__ = (
        "status_code",
        "headers",
        "body",
        "elapsed",
        "size",
        "cookies",
        "url",
        "method",
        "request_headers",
        "request_body",
        "timestamp",
    )

    def __init__(
        self,
        *,
        status_code,
        headers,
        body,
        elapsed,
        size,
        cookies,
        url,
        method,
        request_headers,
        request_body,
        timestamp,
    ):
        self.status_code = status_code
        self.headers = headers
        self.body = body
        self.elapsed = elapsed
        self.size = size
        self.cookies = cookies
        self.url = url
        self.method = method
        self.request_headers = request_headers
        self.request_body = request_body
        self.timestamp = timestamp

    def to_dict(self):
        """Serialise to a plain dict (handy for Comparer integration)."""
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body,
            "elapsed": self.elapsed,
            "size": self.size,
            "cookies": self.cookies,
            "url": self.url,
            "method": self.method,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "timestamp": self.timestamp,
        }


# ------------------------------------------------------------------ #
#  Repeater                                                           #
# ------------------------------------------------------------------ #


class Repeater:
    """Burp-style HTTP request repeater for manual replay and modification."""

    def __init__(
        self,
        timeout=15,
        proxy=None,
        verify_ssl=True,
        network_policy=None,
        max_response_bytes=1024 * 1024,
        max_redirects=10,
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.network_policy = network_policy
        self.max_response_bytes = min(10 * 1024 * 1024, max(64 * 1024, int(max_response_bytes)))
        self.max_redirects = min(20, max(0, int(max_redirects)))
        self.session = requests.Session()
        self._history = []

        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy,
            }

    # ------------------------------------------------------------------ #
    #  Public API                                                         #
    # ------------------------------------------------------------------ #

    def send(self, method, url, headers=None, body=None, params=None, cookies=None, allow_redirects=True):
        """Send an HTTP request and return a *RepeaterResponse*.

        Parameters mirror the standard *requests* API so callers can
        freely tweak any part of the request between replays.
        """
        method = method.upper()
        req_headers = dict(headers) if headers else {}
        req_body = body

        start = time.monotonic()
        current_method = method
        current_url = url
        current_headers = dict(req_headers)
        current_body = body
        current_params = params
        history = []
        resp = None

        for hop in range(self.max_redirects + 1):
            self._require_allowed(current_url)
            resp = self.session.request(
                method=current_method,
                url=current_url,
                headers=current_headers,
                data=current_body,
                params=current_params,
                cookies=cookies,
                allow_redirects=False,
                timeout=self.timeout,
                verify=self.verify_ssl,
                stream=True,
            )
            status = int(getattr(resp, "status_code", 0) or 0)
            location = str(getattr(resp, "headers", {}).get("Location") or "").strip()
            if not allow_redirects or status not in (301, 302, 303, 307, 308) or not location:
                break
            if hop >= self.max_redirects:
                resp.close()
                raise requests.TooManyRedirects(f"Exceeded {self.max_redirects} redirects")
            next_url = urljoin(getattr(resp, "url", "") or current_url, location)
            self._require_allowed(next_url)
            next_headers = dict(current_headers)
            if self._origin(current_url) != self._origin(next_url):
                for name in list(next_headers):
                    if name.lower() in {"authorization", "cookie", "proxy-authorization", "host"}:
                        next_headers.pop(name, None)
            resp.close()
            history.append(resp)
            current_url = next_url
            current_headers = next_headers
            current_params = None
            if status == 303 or (status in (301, 302) and current_method not in ("GET", "HEAD")):
                current_method = "GET"
                current_body = None
                for name in list(current_headers):
                    if name.lower() in {"content-length", "content-type", "transfer-encoding"}:
                        current_headers.pop(name, None)

        if resp is None:
            raise requests.RequestException("No response returned")
        try:
            resp.history = history
        except Exception:
            pass
        self._read_bounded(resp)
        elapsed = time.monotonic() - start

        rr = self._build_response(resp, method, req_headers, req_body, elapsed)
        self._record(method, url, req_headers, req_body, params, cookies, allow_redirects, rr)
        return rr

    @staticmethod
    def _origin(url):
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        return parsed.scheme.lower(), (parsed.hostname or "").lower(), port

    def _require_allowed(self, url):
        if self.network_policy is None:
            return
        try:
            allowed, reason = self.network_policy.allow_url(url)
        except Exception as exc:
            raise PermissionError(f"URL denied by network policy: {exc}") from exc
        if not allowed:
            raise PermissionError(f"URL denied by network policy: {reason}")

    def _read_bounded(self, resp):
        """Read at most the configured response limit and close the socket."""
        limit = self.max_response_bytes
        truncated = False
        if isinstance(resp, requests.Response):
            chunks = []
            total = 0
            try:
                for chunk in resp.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    remaining = limit - total
                    if remaining <= 0:
                        truncated = True
                        break
                    chunks.append(chunk[:remaining])
                    total += min(len(chunk), remaining)
                    if len(chunk) > remaining:
                        truncated = True
                        break
                resp._content = b"".join(chunks)
                resp._content_consumed = True
            finally:
                resp.close()
        else:
            # Lightweight test doubles do not provide a real streaming body.
            raw = getattr(resp, "content", b"")
            if isinstance(raw, str):
                raw = raw.encode("utf-8", errors="replace")
            if isinstance(raw, (bytes, bytearray)) and len(raw) > limit:
                resp.content = bytes(raw[:limit])
                resp.text = resp.content.decode("utf-8", errors="replace")
                truncated = True
        if truncated:
            try:
                resp.headers["X-Atomic-Response-Truncated"] = "true"
            except Exception:
                pass

    def send_raw(self, raw_request, host=None, port=80, use_ssl=False):
        """Parse a raw HTTP request string and send it.

        Behaves like Burp Suite's raw request editor: the *Host* header
        in the request is authoritative unless *host* is overridden.
        """
        method, path, headers, body = self.parse_raw_request(raw_request)

        effective_host = host or headers.get("Host") or headers.get("host", "")
        scheme = "https" if use_ssl else "http"

        if (not use_ssl and port == 80) or (use_ssl and port == 443):
            url = f"{scheme}://{effective_host}{path}"
        else:
            url = f"{scheme}://{effective_host}:{port}{path}"

        return self.send(method, url, headers=headers, body=body)

    # -- raw request helpers ------------------------------------------- #

    @staticmethod
    def parse_raw_request(raw_request):
        """Parse a raw HTTP request into *(method, path, headers, body)*.

        Accepts the typical format produced by Burp / browser dev-tools::

            GET /index.html HTTP/1.1
            Host: example.com
            Accept: text/html

            optional body
        """
        parts = raw_request.split("\r\n\r\n", 1)
        if len(parts) == 1:
            parts = raw_request.split("\n\n", 1)

        header_block = parts[0]
        body = parts[1] if len(parts) > 1 else None

        lines = header_block.replace("\r\n", "\n").split("\n")
        request_line = lines[0].strip()
        tokens = request_line.split()
        method = tokens[0] if tokens else "GET"
        path = tokens[1] if len(tokens) > 1 else "/"

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()

        if body is not None and body.strip() == "":
            body = None

        return method, path, headers, body

    @staticmethod
    def build_raw_request(method, url, headers=None, body=None):
        """Build a raw HTTP request string from components."""
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        host = parsed.netloc

        lines = [f"{method.upper()} {path} HTTP/1.1"]

        merged_headers = {"Host": host}
        if headers:
            merged_headers.update(headers)

        for key, value in merged_headers.items():
            lines.append(f"{key}: {value}")

        raw = "\r\n".join(lines) + "\r\n\r\n"
        if body:
            raw += body

        return raw

    # -- history ------------------------------------------------------- #

    @property
    def history(self):
        """Return a list of *(request_info, RepeaterResponse)* tuples."""
        return list(self._history)

    def clear_history(self):
        """Discard all recorded request/response pairs."""
        self._history.clear()

    # -- replay -------------------------------------------------------- #

    def replay(self, index, modifications=None):
        """Replay a previous request, optionally applying *modifications*.

        *modifications* is a dict that can contain any of the keys
        ``headers``, ``body``, ``params``, ``cookies``, ``method``,
        ``url``, or ``allow_redirects``.
        """
        if index < 0 or index >= len(self._history):
            raise IndexError(f"History index {index} out of range")

        req_info, _ = self._history[index]
        mods = modifications or {}

        return self.send(
            method=mods.get("method", req_info["method"]),
            url=mods.get("url", req_info["url"]),
            headers=mods.get("headers", req_info.get("headers")),
            body=mods.get("body", req_info.get("body")),
            params=mods.get("params", req_info.get("params")),
            cookies=mods.get("cookies", req_info.get("cookies")),
            allow_redirects=mods.get("allow_redirects", req_info.get("allow_redirects", True)),
        )

    # -- diff ---------------------------------------------------------- #

    def diff_responses(self, index1, index2):
        """Compare two responses from history.

        Delegates to *utils.comparer.Comparer* when available, falling
        back to a basic dict diff otherwise.
        """
        if index1 < 0 or index1 >= len(self._history):
            raise IndexError(f"History index {index1} out of range")
        if index2 < 0 or index2 >= len(self._history):
            raise IndexError(f"History index {index2} out of range")

        _, resp1 = self._history[index1]
        _, resp2 = self._history[index2]

        try:
            from utils.comparer import Comparer

            comparer = Comparer()
            return comparer.compare_responses(resp1.to_dict(), resp2.to_dict())
        except ImportError:
            return self._basic_diff(resp1, resp2)

    # ------------------------------------------------------------------ #
    #  Private helpers                                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _build_response(resp, method, req_headers, req_body, elapsed):
        """Wrap a *requests.Response* in a *RepeaterResponse*."""
        return RepeaterResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text,
            elapsed=round(elapsed, 4),
            size=len(resp.content),
            cookies={k: v for k, v in resp.cookies.items()},
            url=resp.url,
            method=method,
            request_headers=req_headers,
            request_body=req_body,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def _record(self, method, url, headers, body, params, cookies, allow_redirects, rr):
        """Append a request/response pair to history."""
        req_info = {
            "method": method,
            "url": url,
            "headers": headers,
            "body": body,
            "params": params,
            "cookies": cookies,
            "allow_redirects": allow_redirects,
        }
        self._history.append((req_info, rr))

    @staticmethod
    def _basic_diff(resp1, resp2):
        """Minimal diff when Comparer is unavailable."""
        return {
            "status": {
                "response1": resp1.status_code,
                "response2": resp2.status_code,
                "changed": resp1.status_code != resp2.status_code,
            },
            "body_length": {
                "response1": resp1.size,
                "response2": resp2.size,
                "changed": resp1.size != resp2.size,
            },
            "headers_changed": resp1.headers != resp2.headers,
        }
