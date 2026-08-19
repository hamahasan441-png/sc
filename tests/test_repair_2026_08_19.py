"""Regression tests for the 2026-08-19 repair pass."""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


def _engine():
    return SimpleNamespace(
        target="https://example.test/",
        requester=MagicMock(),
        config={"verbose": False},
    )


def test_shell_uploader_direct_run_fails_closed(monkeypatch):
    monkeypatch.delenv("ATOMIC_AUTHORIZED", raising=False)
    from modules.uploader import ShellUploader

    uploader = ShellUploader(_engine(), scan_only=False)
    with pytest.raises(PermissionError):
        uploader.run([], [])


def test_data_dumper_direct_run_fails_closed(monkeypatch, tmp_path):
    monkeypatch.delenv("ATOMIC_AUTHORIZED", raising=False)
    from modules.dumper import DataDumper

    dumper = DataDumper(_engine())
    dumper.dump_dir = str(tmp_path)
    with pytest.raises(PermissionError):
        dumper.run([])


def test_bruteforce_direct_run_fails_closed(monkeypatch):
    monkeypatch.delenv("ATOMIC_AUTHORIZED", raising=False)
    from modules.brute_force import BruteForceModule

    bruter = BruteForceModule(_engine())
    with pytest.raises(PermissionError):
        bruter.run([])


def test_batch_html_report_escapes_untrusted_fields(tmp_path):
    from core.batch_scanner import BatchResult, BatchScanner, TargetResult

    scanner = object.__new__(BatchScanner)
    result = BatchResult(
        target_results=[
            TargetResult(
                target='<img src=x onerror="alert(1)">',
                error='<script>alert("x")</script>',
            )
        ]
    )
    path = scanner.generate_consolidated_report(result, fmt="html", output_dir=str(tmp_path))
    body = open(path, encoding="utf-8").read()
    assert "<script>alert" not in body
    assert "<img src=x" not in body
    assert "&lt;script&gt;" in body
    assert "&lt;img" in body


def test_external_tool_unknown_option_is_rejected():
    from core.tool_integrator import _sanitize_tool_cmd

    ok, message = _sanitize_tool_cmd(["subfinder", "--definitely-not-a-real-framework-flag", "example.test"])
    assert ok is False
    assert "Unsupported" in message


def test_external_tool_rejects_metacharacters_in_value():
    from core.tool_integrator import _sanitize_tool_cmd

    ok, message = _sanitize_tool_cmd(["subfinder", "-d", "example.test;ignored"])
    assert ok is False
    assert "Invalid argument value" in message
