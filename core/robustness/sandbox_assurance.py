#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Authorized-lab sandbox assurance checks.

This module intentionally does NOT attempt sandbox escape, privilege escalation,
or destructive exploitation.  It validates isolation properties using local,
non-destructive observations and returns fail-closed findings when a boundary is
weaker than the configured policy.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Set


_CAP_NAMES = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}

_DEFAULT_FORBIDDEN_CAPS = {
    "CAP_SYS_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_BPF",
    "CAP_PERFMON",
    "CAP_CHECKPOINT_RESTORE",
}


@dataclass(frozen=True)
class SandboxPolicy:
    """Expected isolation properties for an authorized lab sandbox."""

    require_non_root: bool = True
    require_seccomp: bool = True
    require_no_new_privs: bool = True
    require_lsm_profile: bool = False
    require_no_default_route: bool = False
    forbidden_capabilities: Set[str] = field(default_factory=lambda: set(_DEFAULT_FORBIDDEN_CAPS))
    forbidden_writable_paths: tuple[str, ...] = ("/etc", "/usr", "/boot", "/proc/sys")


@dataclass(frozen=True)
class AssuranceFinding:
    check: str
    severity: str
    passed: bool
    detail: str


@dataclass
class AssuranceReport:
    findings: List[AssuranceFinding]

    @property
    def passed(self) -> bool:
        return all(f.passed for f in self.findings)

    @property
    def failed_checks(self) -> List[AssuranceFinding]:
        return [f for f in self.findings if not f.passed]

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "failed_count": len(self.failed_checks),
            "findings": [
                {
                    "check": f.check,
                    "severity": f.severity,
                    "passed": f.passed,
                    "detail": f.detail,
                }
                for f in self.findings
            ],
        }


class SandboxAssurance:
    """Non-destructive sandbox boundary verifier.

    The verifier never tries to exploit a kernel/container bug.  Instead it
    checks whether the runtime exposes capabilities or configuration states
    that would make containment materially weaker than the requested policy.
    """

    def __init__(self, policy: Optional[SandboxPolicy] = None):
        self.policy = policy or SandboxPolicy()

    @staticmethod
    def _read_proc_status() -> dict[str, str]:
        out: dict[str, str] = {}
        try:
            for line in Path("/proc/self/status").read_text(encoding="utf-8", errors="replace").splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    out[k.strip()] = v.strip()
        except OSError:
            pass
        return out

    @staticmethod
    def _effective_capabilities(status: dict[str, str]) -> Set[str]:
        raw = status.get("CapEff", "0")
        try:
            mask = int(raw, 16)
        except ValueError:
            return set()
        enabled: Set[str] = set()
        for bit, name in _CAP_NAMES.items():
            if mask & (1 << bit):
                enabled.add(name)
        return enabled

    @staticmethod
    def _apparmor_profile() -> str:
        try:
            return Path("/proc/self/attr/current").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return ""

    @staticmethod
    def _has_default_route() -> bool:
        """Observe IPv4 routing only; no packets are transmitted."""
        try:
            lines = Path("/proc/net/route").read_text(encoding="utf-8", errors="replace").splitlines()[1:]
        except OSError:
            return False
        for line in lines:
            cols = re.split(r"\s+", line.strip())
            if len(cols) >= 4 and cols[1] == "00000000":
                try:
                    flags = int(cols[3], 16)
                except ValueError:
                    continue
                if flags & 0x1:  # RTF_UP
                    return True
        return False

    def run(self) -> AssuranceReport:
        findings: List[AssuranceFinding] = []
        status = self._read_proc_status()

        # Identity / privilege
        if hasattr(os, "geteuid"):
            euid = os.geteuid()
            ok = not self.policy.require_non_root or euid != 0
            findings.append(AssuranceFinding(
                "non_root_identity",
                "CRITICAL" if not ok else "INFO",
                ok,
                f"effective_uid={euid}",
            ))

        # Linux capabilities
        caps = self._effective_capabilities(status)
        forbidden = sorted(caps & self.policy.forbidden_capabilities)
        findings.append(AssuranceFinding(
            "forbidden_capabilities",
            "CRITICAL" if forbidden else "INFO",
            not forbidden,
            "none" if not forbidden else ", ".join(forbidden),
        ))

        # no_new_privs
        nnp = status.get("NoNewPrivs", "0") == "1"
        ok_nnp = (not self.policy.require_no_new_privs) or nnp
        findings.append(AssuranceFinding(
            "no_new_privs",
            "HIGH" if not ok_nnp else "INFO",
            ok_nnp,
            f"NoNewPrivs={status.get('NoNewPrivs', 'unknown')}",
        ))

        # seccomp: 0 disabled, 1 strict, 2 filter
        seccomp_mode = status.get("Seccomp", "unknown")
        seccomp_enabled = seccomp_mode in {"1", "2"}
        ok_seccomp = (not self.policy.require_seccomp) or seccomp_enabled
        findings.append(AssuranceFinding(
            "seccomp",
            "HIGH" if not ok_seccomp else "INFO",
            ok_seccomp,
            f"Seccomp={seccomp_mode}",
        ))

        # LSM/AppArmor profile presence
        profile = self._apparmor_profile()
        confined = bool(profile and profile not in {"unconfined", "unconfined\n"})
        ok_lsm = (not self.policy.require_lsm_profile) or confined
        findings.append(AssuranceFinding(
            "lsm_profile",
            "HIGH" if not ok_lsm else "INFO",
            ok_lsm,
            profile or "not available",
        ))

        # Observe dangerous writable paths without modifying them.
        writable = [p for p in self.policy.forbidden_writable_paths if os.path.exists(p) and os.access(p, os.W_OK)]
        findings.append(AssuranceFinding(
            "forbidden_writable_paths",
            "HIGH" if writable else "INFO",
            not writable,
            "none" if not writable else ", ".join(writable),
        ))

        # Network isolation observation (does not initiate any connection).
        default_route = self._has_default_route()
        ok_route = (not self.policy.require_no_default_route) or not default_route
        findings.append(AssuranceFinding(
            "network_default_route",
            "HIGH" if not ok_route else "INFO",
            ok_route,
            f"default_route={'present' if default_route else 'absent'}",
        ))

        return AssuranceReport(findings)


def assert_sandbox_assured(policy: Optional[SandboxPolicy] = None) -> AssuranceReport:
    """Fail closed when the configured isolation contract is not satisfied."""
    report = SandboxAssurance(policy).run()
    if not report.passed:
        failed = "; ".join(f"{f.check}: {f.detail}" for f in report.failed_checks)
        raise PermissionError(f"sandbox assurance failed: {failed}")
    return report
