"""
``atomic`` — the easy-mode wrapper.

    python -m atomic scan https://example.com --profile quick
    python -m atomic scan https://example.com --profile full --authorized
    python -m atomic dashboard
    python -m atomic lab
    python -m atomic update
    python -m atomic version

Run ``python -m atomic --help`` to see the help text.
"""
from __future__ import annotations
import argparse
import os
import subprocess
import sys
from typing import List, Optional

from . import __version__
from .profiles import PROFILES, get, to_main_args
from .urlnorm import normalize, is_acceptable_target


BANNER = (
    "ATOMIC Framework v11.0 — easy-mode wrapper\n"
    "  https://github.com/hamahasan441-png/Scanner-\n"
)


def _print_banner() -> None:
    print(BANNER)


def _is_authorized(cli_flag: bool) -> bool:
    """Confirm the operator has explicitly accepted exploit risk."""
    if cli_flag:
        return True
    env = os.environ.get("ATOMIC_AUTHORIZED", "").strip().lower()
    if env in ("1", "true", "yes", "on"):
        return True
    return False


def _confirm_post_exploit(profile_name: str) -> bool:
    """Print a clear warning and require an interactive y/N for post-exploit."""
    print()
    print("!" * 60)
    print(f"  profile = {profile_name!r} enables POST-EXPLOITATION")
    print("  (auto-attack, shell upload, database dump, brute force).")
    print()
    print("  The framework will actively exploit confirmed findings")
    print("  against the target. Only run this against systems you")
    print("  are explicitly authorized to test.")
    print("!" * 60)
    while True:
        try:
            ans = input("\nType 'I am authorized' to continue: ").strip()
        except EOFError:
            return False
        if ans == "I am authorized":
            return True
        print("Aborted.")
        return False


def cmd_scan(args: argparse.Namespace) -> int:
    # Normalize the target: accept bare hostnames, host:port,
    # host/path, and either http:// or https://. See atomic.urlnorm.
    try:
        target = normalize(args.target)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    if target != args.target:
        print(f"[i] Using target: {target}  (from input {args.target!r})")
    profile = get(args.profile)
    authorized = _is_authorized(args.authorized)
    if profile.auto_attack and not authorized:
        print(
            f"[!] profile={profile.name!r} requires --authorized "
            "(or ATOMIC_AUTHORIZED=1) because it enables auto-attack, "
            "shell upload, database dump, and brute force.",
            file=sys.stderr,
        )
        print(
            "    Falling back to: profile=deep (no post-exploit).",
            file=sys.stderr,
        )
        profile = get("deep")
    if profile.auto_attack and not args.yes:
        if not _confirm_post_exploit(profile.name):
            return 2
    argv = to_main_args(profile, target, authorized=authorized)
    print(f"[i] Running: python {' '.join(argv)}")
    return subprocess.call([sys.executable] + argv, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def cmd_dashboard(args: argparse.Namespace) -> int:
    # Default to loopback. The operator must explicitly opt in to LAN exposure.
    if not args.explicit_host:
        if args.host in ("0.0.0.0", ""):
            args.host = "127.0.0.1"
    # Refuse to bind 0.0.0.0 without an API key.
    if args.host == "0.0.0.0" and not os.environ.get("ATOMIC_API_KEY"):
        print(
            "[!] Refusing to bind 0.0.0.0 without ATOMIC_API_KEY set.",
            file=sys.stderr,
        )
        print(
            "    Set ATOMIC_API_KEY (or pass --host 127.0.0.1).",
            file=sys.stderr,
        )
        return 2
    os.environ.setdefault("ATOMIC_AUTH_REQUIRED", "true")
    return subprocess.call(
        [sys.executable, "main.py", "--web",
         "--host", args.host, "--port", str(args.port)],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )


def cmd_lab(_: argparse.Namespace) -> int:
    print(
        "lab: an isolated, intentionally-vulnerable target for testing the\n"
        "framework end-to-end. This is NOT included in this build.\n"
        "\n"
        "To get a local lab, run one of:\n"
        "  docker run -d -p 80:80 vulnerables/web-dvwa\n"
        "  docker run -d -p 3000:3000 bkimminich/juice-shop\n"
        "  docker run -d -p 8000:8000 projectdiscovery/nuclei-test\n"
        "\n"
        "Then:\n"
        "  atomic scan http://localhost --profile quick\n",
    )
    return 0


def cmd_update(_: argparse.Namespace) -> int:
    return subprocess.call([sys.executable, "main.py", "--update"])


def cmd_version(_: argparse.Namespace) -> int:
    print(f"atomic wrapper v{__version__}")
    try:
        from config import Config
        print(f"ATOMIC Framework v{Config.VERSION} ({Config.CODENAME})")
    except Exception as exc:  # pragma: no cover - defensive
        print(f"ATOMIC Framework version: <unable to read: {exc}>")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="atomic",
        description="ATOMIC Framework — easy-mode wrapper.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  atomic scan https://example.com --profile quick\n"
            "  atomic scan https://example.com --profile full --authorized --yes\n"
            "  atomic dashboard --host 127.0.0.1 --port 5000\n"
            "  atomic lab\n"
            "  atomic version\n"
        ),
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Scan a target with a named profile.")
    p_scan.add_argument("target", help="Target URL (http:// or https://)")
    p_scan.add_argument(
        "--profile", "-p",
        choices=list(PROFILES), default="standard",
        help="Scan profile (default: standard).",
    )
    p_scan.add_argument(
        "--authorized", action="store_true",
        help=(
            "I have explicit written authorization to test this target "
            "and to perform post-exploitation (auto-attack, shell upload, "
            "DB dump, brute force). Without this flag, the framework will "
            "NOT run any post-exploit action."
        ),
    )
    p_scan.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip the interactive post-exploit confirmation prompt.",
    )
    p_scan.set_defaults(func=cmd_scan)

    p_dash = sub.add_parser("dashboard", help="Start the web dashboard.")
    p_dash.add_argument("--host", default="127.0.0.1",
                        help="Bind host (default 127.0.0.1; use 0.0.0.0 for LAN).")
    p_dash.add_argument("--port", type=int, default=5000)
    p_dash.set_defaults(func=cmd_dashboard, explicit_host=False)

    p_lab = sub.add_parser("lab", help="Print instructions for a local test target.")
    p_lab.set_defaults(func=cmd_lab)

    p_upd = sub.add_parser("update", help="Update to the latest version.")
    p_upd.set_defaults(func=cmd_update)

    p_ver = sub.add_parser("version", help="Print version info.")
    p_ver.set_defaults(func=cmd_version)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Mark whether --host was passed explicitly.
    if args.cmd == "dashboard":
        args.explicit_host = "--host" in (argv or sys.argv[1:])
    _print_banner()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
