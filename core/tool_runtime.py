"""Managed, integrity-aware runtime for bundled security tools.

The framework prefers binaries shipped under ``runtime/bin``. Host PATH
resolution remains an explicit compatibility fallback so existing installs do
not break, but it is disabled when ``ATOMIC_REQUIRE_BUNDLED_TOOLS=1`` is set.

No tool is executed until its executable path has been resolved and, when a
manifest entry supplies a SHA-256, its integrity has been verified.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version: str = ""
    sha256: str = ""
    binary: str = ""
    platforms: tuple[str, ...] = ()


class ToolRuntime:
    def __init__(self, base_dir: Optional[str] = None):
        root = Path(base_dir or Path(__file__).resolve().parents[1])
        self.root = root
        self.bin_dir = root / "runtime" / "bin"
        self.manifest_path = root / "runtime" / "metadata" / "tools.json"
        # Production/security default: never silently fall back to an
        # unpinned host executable.  Legacy host resolution is an explicit
        # opt-in via ATOMIC_ALLOW_HOST_TOOLS=1.
        self.allow_host_tools = os.environ.get("ATOMIC_ALLOW_HOST_TOOLS", "").lower() in {"1", "true", "yes"}
        self.require_bundled = not self.allow_host_tools
        self._manifest = self._load_manifest()

    def _load_manifest(self) -> Dict[str, ToolSpec]:
        if not self.manifest_path.is_file():
            return {}
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}
        specs = {}
        for name, raw in (data.get("tools", {}) if isinstance(data, dict) else {}).items():
            if not isinstance(raw, dict):
                continue
            specs[name] = ToolSpec(
                name=name,
                version=str(raw.get("version", "")),
                sha256=str(raw.get("sha256", "")).lower(),
                binary=str(raw.get("binary", name)),
                platforms=tuple(raw.get("platforms", ()) or ()),
            )
        return specs

    @staticmethod
    def _platform_key() -> str:
        system = platform.system().lower()
        machine = platform.machine().lower().replace("amd64", "x86_64")
        return f"{system}-{machine}"

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def bundled_path(self, name: str) -> Optional[str]:
        spec = self._manifest.get(name, ToolSpec(name=name, binary=name))
        path = (self.bin_dir / spec.binary).resolve()
        try:
            path.relative_to(self.bin_dir.resolve())
        except ValueError:
            return None
        if not path.is_file() or not os.access(path, os.X_OK):
            return None
        if spec.platforms and self._platform_key() not in spec.platforms:
            return None
        # A bundled executable is trusted only when the manifest pins its
        # digest.  An empty digest means "artifact not provisioned", not
        # "implicitly trusted".
        if not spec.sha256 or not re.fullmatch(r"[0-9a-f]{64}", spec.sha256):
            return None
        if self._sha256(path) != spec.sha256:
            return None
        return str(path)

    def resolve(self, name: str) -> Optional[str]:
        bundled = self.bundled_path(name)
        if bundled:
            return bundled
        if self.require_bundled:
            return None
        return shutil.which(name)

    def status(self) -> Dict[str, dict]:
        names = set(self._manifest)
        names.update({"nmap", "nuclei", "nikto", "whatweb", "subfinder", "httpx", "ffuf", "amass", "dnsx", "katana", "naabu", "interactsh-client"})
        out = {}
        for name in sorted(names):
            bundled = self.bundled_path(name)
            host = shutil.which(name)
            out[name] = {
                "available": bool(bundled or (host and self.allow_host_tools)),
                "source": "bundled" if bundled else ("host" if host and self.allow_host_tools else "none"),
                "integrity": "verified" if bundled else ("unverified-host" if host and self.allow_host_tools else "missing"),
            }
        return out


RUNTIME = ToolRuntime()


def resolve_tool(name: str) -> Optional[str]:
    return RUNTIME.resolve(name)
