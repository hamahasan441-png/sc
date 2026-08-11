#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Enhanced Main Entry Point
Refactored from 2521-line monolith to modular CLI architecture.

New structure:
- core/cli/parser/        → Argument groups (target, scan, modules, etc.)
- core/cli/commands/      → Command handlers (tools, recon, web, scan, etc.)
- core/cli/helpers.py     → Shared helpers (_parse_csv, update notices)
- core/cli/app.py         → Main dispatcher (run_cli)

This file is now ~80 lines vs 2521 lines previously, with:
- Faster startup (lazy imports)
- Better maintainability (single responsibility per module)
- Easier testing (each command independently testable)
- Clear separation of concerns

For legacy reference, see main_legacy.py (original 2521-line version).
For authorized testing only.
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Delegate to new modular CLI
from core.cli.app import run_cli

# Backward compatibility exports for tests that imported from old main.py
# These were previously defined directly in main.py, now moved to helpers
try:
    from core.cli.helpers import (
        parse_csv as _parse_csv,
        print_update_status as _print_update_status,
        maybe_auto_update as _maybe_auto_update,
        startup_update_notice as _startup_update_notice,
    )
except ImportError:
    def _parse_csv(value):
        if not value:
            return []
        return [x.strip() for x in value.split(",") if x.strip()]

    def _print_update_status(status, did_update=False):
        pass

    def _maybe_auto_update(quiet=False):
        pass

    def _startup_update_notice():
        pass

# Additional backward compat exports for legacy tests that patch main.*
# These were previously imported directly in old main.py
try:
    from core.banner import print_banner
except ImportError:
    def print_banner():
        pass

try:
    from utils.helpers import check_dependencies, install_deps
except ImportError:
    def check_dependencies():
        return False

    def install_deps():
        pass

try:
    from core.engine import AtomicEngine
except ImportError:
    AtomicEngine = None

# Alias for test that expects main.AtomicEngine to be patchable
# Also expose Config and Colors for completeness
try:
    from config import Config, Colors
except ImportError:
    Config = None
    Colors = None


def main():
    """Enhanced main entry point — delegates to modular CLI."""
    run_cli()


if __name__ == "__main__":
    main()
