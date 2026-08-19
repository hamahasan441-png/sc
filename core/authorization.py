"""
ATOMIC Framework — Centralized authorization gate for post-exploit.

This module exists because, in a default install, the engine's
``--full`` profile implicitly enables ``auto_exploit`` /
``smart_attack`` without an explicit operator ack. A single
``python main.py -t https://target --full`` will deploy a web shell
on the target. The fix is a single fail-closed check that every
post-exploit entry point must call before any destructive / exploitative
network action.

The check is:

    1. ``ATOMIC_AUTHORIZED=1`` env var, OR
    2. ``--authorized`` on the command line, OR
    3. An operator-confirmed "lab mode" via the ``atomic`` wrapper
       (which already prompts and refuses without ack).

All three are required to be PRESENT in the running process; we do
not require both env and CLI — either is sufficient but both are
deliberately not auto-set by the framework.
"""
from __future__ import annotations
import json
import os
import sys
import secrets
from datetime import datetime, timezone
from typing import Optional


def _authorization_file() -> str:
    root = os.environ.get("ATOMIC_HOME", "").strip()
    if not root:
        root = os.path.join(os.path.expanduser("~"), ".atomic")
    return os.environ.get(
        "ATOMIC_OWNER_AUTHORIZATION_FILE",
        os.path.join(root, "owner_authorization.json"),
    )


def acknowledge_owner_authorization(username: str) -> None:
    """Persist the first-run owner's authorized-use acknowledgement.

    This is written only by the one-time web setup flow after the operator
    checks the authorized-use confirmation.  It gives the local owner the same
    durable capability as ``ATOMIC_AUTHORIZED=1`` without hard-coding that env
    flag into the shipped image.
    """
    path = _authorization_file()
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    payload = {
        "version": 1,
        "authorized": True,
        "username": str(username)[:64],
        "acknowledged_at": datetime.now(timezone.utc).isoformat(),
    }
    data = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
    temp_path = f"{path}.tmp-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temp_path, flags, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp_path, path)
    os.chmod(path, 0o600)


def _owner_authorized() -> bool:
    path = _authorization_file()
    try:
        if os.path.islink(path):
            return False
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload.get("authorized") is True and bool(payload.get("username"))
    except (OSError, ValueError, TypeError):
        return False


def is_authorized() -> bool:
    """Return True iff the operator has acknowledged post-exploit risk."""
    env = os.environ.get("ATOMIC_AUTHORIZED", "").strip().lower()
    if env in ("1", "true", "yes", "on"):
        return True
    if "--authorized" in sys.argv[1:]:
        return True
    if _owner_authorized():
        return True
    return False


def require_authorized(action: str, target: Optional[str] = None) -> None:
    """Raise ``PermissionError`` unless the operator has authorized the action.

    *action* is a short human label (e.g. "auto-attack", "shell-upload").
    *target* is the URL the action would run against (for the audit log).
    """
    if is_authorized():
        # Audit log import is deferred (and best-effort) so this helper
        # works in lean test environments where PyYAML / SQLAlchemy
        # may be missing. We use a direct file-path import to avoid
        # triggering the eager ``core/__init__.py`` package import
        # (which pulls in AtomicEngine and its heavy deps).
        try:
            import importlib.util
            from pathlib import Path
            here = Path(__file__).resolve().parent
            audit_path = here / "audit_logger.py"
            spec = importlib.util.spec_from_file_location("_audit_logger_lazy", str(audit_path))
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                audit = mod.AuditLogger()
                audit.log_config(
                    "post_exploit.authorized",
                    result="executed",
                    action=action,
                    target=target or "",
                )
        except Exception:
            pass
        return
    raise PermissionError(
        f"post-exploit action {action!r} requires explicit operator "
        f"authorization. Re-run with --authorized or set "
        f"ATOMIC_AUTHORIZED=1. See atomic wrapper for an interactive "
        f"confirmation flow."
    )
