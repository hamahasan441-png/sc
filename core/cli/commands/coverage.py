#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - CLI: Coverage reporting & auto-close

Post-scan hooks that make the coverage system real from the command line:

* ``--coverage-report`` prints the attack-surface coverage summary for the
  scan that just ran.
* ``--coverage-json PATH`` writes the full coverage picture (endpoint grid +
  surface ledger + closure plan).
* ``--auto-close`` runs the remaining NON-INVASIVE validations to close
  coverage gaps (invasive/exploitative validators are never auto-run — they
  are reported for deliberate, authorized handling).
"""

import json
import sys

from config import Colors


def collect_coverage(engine) -> dict:
    """Assemble the full coverage picture from a scanned engine (read-only)."""
    picture = {}
    for key, getter in (
        ("coverage", "get_coverage_summary"),
        ("surface_coverage", "get_surface_ledger"),
        ("coverage_plan", "get_coverage_plan"),
    ):
        try:
            obj = getattr(engine, getter)()
            picture[key] = obj.to_dict() if hasattr(obj, "to_dict") else obj
        except Exception:
            picture[key] = None
    return picture


def print_coverage_summary(engine) -> None:
    """Human-readable coverage summary for a completed scan."""
    pic = collect_coverage(engine)
    print(f"\n  {Colors.BOLD}Attack-Surface Coverage{Colors.RESET}")

    cov = pic.get("coverage") or {}
    print(f"    Endpoints:  {cov.get('endpoints_tested', 0)}/{cov.get('endpoints_total', 0)} "
          f"tested ({cov.get('endpoint_coverage_pct', 0.0)}%), "
          f"{cov.get('endpoints_validated', 0)} with findings")

    sc = (pic.get("surface_coverage") or {}).get("summary", {})
    print(f"    Surfaces:   {sc.get('categories_assessed', 0)}/{sc.get('categories_total', 0)} "
          f"assessed ({sc.get('assessment_pct', 0.0)}%)")
    blind = sc.get("blind_spots", [])
    if blind:
        print(f"    {Colors.warning('Blind spots')}: {', '.join(blind[:8])}"
              + (" ..." if len(blind) > 8 else ""))

    plan = pic.get("coverage_plan") or {}
    psum = plan.get("summary", {})
    if psum:
        print(f"    Gaps:       {psum.get('endpoint_gap_count', 0)} endpoint, "
              f"{psum.get('surface_blind_spot_count', 0)} surface; "
              f"{psum.get('total_recommended', 0)} recommended next tests")
        for t in plan.get("recommended_tasks", [])[:5]:
            if t.get("kind") == "endpoint":
                print(f"      - run {t.get('validator')} on {t.get('target')}")
            else:
                mods = ", ".join(t.get("suggested_modules", [])[:3])
                print(f"      - assess {t.get('target')} (e.g. {mods})")


def write_coverage_json(engine, path: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(collect_coverage(engine), fh, indent=2, sort_keys=True)
        print(f"{Colors.info(f'Coverage JSON written to {path}')}")
    except OSError as exc:
        print(f"{Colors.error(f'Could not write coverage JSON: {exc}')}", file=sys.stderr)


def run_auto_close(engine, budget: int = 100) -> dict:
    """Drive real non-invasive coverage closure and print a short summary."""
    print(f"\n  {Colors.BOLD}Auto-closing coverage (non-invasive){Colors.RESET}")
    report = engine.run_coverage_closure(budget=budget)
    print(f"    Ran {report.get('executed_count', 0)} validations; "
          f"stop: {report.get('stop_reason', '?')}; "
          f"remaining endpoint gaps: {report.get('remaining_endpoint_gaps', 0)}")
    skipped = report.get("skipped_invasive", [])
    if skipped:
        print(f"    {Colors.warning('Skipped (invasive, needs authorized handling)')}: "
              f"{len(skipped)} — {', '.join(sorted({s.split('@')[0] for s in skipped}))}")
    return report


def apply_post_scan_coverage(engine, config) -> None:
    """Run the coverage hooks selected on the CLI, in order."""
    if config.get("auto_close"):
        try:
            run_auto_close(engine, budget=config.get("coverage_budget", 100))
        except Exception as exc:
            print(f"{Colors.error(f'Auto-close failed: {exc}')}", file=sys.stderr)
    if config.get("coverage_report"):
        try:
            print_coverage_summary(engine)
        except Exception as exc:
            print(f"{Colors.error(f'Coverage report failed: {exc}')}", file=sys.stderr)
    if config.get("coverage_json"):
        write_coverage_json(engine, config["coverage_json"])
