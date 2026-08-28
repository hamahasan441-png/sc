#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core/cli/commands/coverage.py — post-scan coverage hooks."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from core.cli.commands.coverage import (
    apply_post_scan_coverage,
    collect_coverage,
    print_coverage_summary,
    run_auto_close,
)
from core.models import CanonicalFinding, SurfaceEndpoint, SurfaceParam, TargetSurface


def _engine(modules=None):
    from core.engine import AtomicEngine
    if modules is None:
        modules = {"sqli": True, "idor": True}
    return AtomicEngine({"quiet": True, "modules": modules})


def _with_surface(eng):
    eng.surface = TargetSurface(target="https://demo.test", endpoints=[
        SurfaceEndpoint(url="https://demo.test/search", method="GET",
                        params=[SurfaceParam(name="q", value="1")]),
        SurfaceEndpoint(url="https://demo.test/profile", method="GET"),
    ])
    f = CanonicalFinding(technique="sqli", url="https://demo.test/search",
                         method="GET", param="q")
    eng._canonical_findings[f.finding_id] = f
    return eng


class TestCollect(unittest.TestCase):
    def test_collect_has_all_blocks(self):
        pic = collect_coverage(_with_surface(_engine()))
        self.assertIn("coverage", pic)
        self.assertIn("surface_coverage", pic)
        self.assertIn("coverage_plan", pic)
        self.assertIsNotNone(pic["coverage"])

    def test_collect_empty_engine_is_safe(self):
        pic = collect_coverage(_engine(modules={}))
        # nothing scanned -> None blocks, no crash
        self.assertIn("coverage", pic)


class TestPrint(unittest.TestCase):
    def test_summary_mentions_coverage_and_blind_spots(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_coverage_summary(_with_surface(_engine()))
        out = buf.getvalue()
        self.assertIn("Attack-Surface Coverage", out)
        self.assertIn("Endpoints", out)
        self.assertIn("Surfaces", out)


class TestAutoClose(unittest.TestCase):
    def test_auto_close_no_modules_runs_nothing(self):
        eng = _engine(modules={})
        _with_surface(eng)
        buf = io.StringIO()
        with redirect_stdout(buf):
            report = run_auto_close(eng, budget=10)
        self.assertEqual(report["executed_count"], 0)

    def test_apply_hooks_writes_json(self):
        eng = _with_surface(_engine())
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "cov.json")
            config = {"auto_close": False, "coverage_report": False,
                      "coverage_json": path, "coverage_budget": 100}
            buf = io.StringIO()
            with redirect_stdout(buf):
                apply_post_scan_coverage(eng, config)
            self.assertTrue(os.path.exists(path))
            data = json.load(open(path))
            self.assertIn("surface_coverage", data)

    def test_apply_hooks_all_disabled_is_noop(self):
        eng = _with_surface(_engine())
        buf = io.StringIO()
        with redirect_stdout(buf):
            apply_post_scan_coverage(eng, {})
        self.assertEqual(buf.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
