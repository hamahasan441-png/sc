# ATOMIC — Engineering State

Purpose: an honest, evidence-based map of what the repository actually is,
what was fixed this session, and where the real gaps are relative to the
"Singularity Pro" target architecture. Nothing here is an invented score;
every "present" claim points at a real file.

## Executive summary

ATOMIC is **already a mature, integrated security-validation platform**, not a
"folder of unrelated scripts." It has one canonical domain model, a scheduler,
a worker pool, a correlation/scoring/evidence pipeline, a tool runtime, a Flask
dashboard, deterministic golden reports (JSON + SARIF), and 5,300+ passing
tests. The bulk of the master-prompt's "target architecture" **exists today**.

Work this session focused on what was actually broken: a latent crash bug and
test-suite instability. The suite is now reliably green (0 failures).

## Fixes applied this session (commit `bfeed3c`)

| Area | Problem | Fix | Verification |
|---|---|---|---|
| `core/scheduler.py` | `next_cron_time()` used `datetime.replace(hour=hour+1)`, raising `ValueError` at 23:59 and never rolling day/month over — a real, time-of-day-dependent crash | Rewrote candidate advance with epoch arithmetic | Verified across hour/day/month boundaries; 30 scheduler tests pass |
| `tests/test_reconnaissance_module.py` | `ReconModule.run()` grew from 8→16 sub-methods; test mocked only 8, so the rest did real network I/O and **hung** in a no-egress env | Mock the full dispatch set | Test now passes in 0.5s |
| `tests/test_audit_fixes.py` | `test_real_repo` pinned branch name to `arena/*`, breaking on any other branch | Assert a non-empty branch string instead | Passes on `claude/*` branch |
| `pyproject.toml` | `integration` pytest marker unregistered → warning spam | Registered the marker | Collection warnings gone |

Also fixed the sandbox environment (missing `_cffi_backend`, flask, bs4, etc.)
— see `ATOMIC_BASELINE.md` → "Environment setup".

## Target architecture vs. reality (evidence-mapped)

The master prompt asks for a canonical runtime with ~30 named subsystems.
Almost all already exist:

| Target subsystem | Status | Evidence (real file) |
|---|---|---|
| Canonical domain model | ✅ present | `core/models.py` (493 LOC), `tests/test_models_contract.py` |
| Target normalization | ✅ present | `core/normalizer.py` |
| Surface graph | ✅ present | `core/surface.py` |
| Discovery | ✅ present | `modules/discovery.py`, `core/passive_recon.py` |
| Scan/attack planning | ✅ present | `core/scan_planner.py`, `core/attack_planner.py`, `core/attack_router.py` |
| Scheduler + priority queue | ✅ present | `core/scheduler.py`, `core/scan_priority_queue.py` |
| Worker pool / concurrency | ✅ present | `core/scan_worker_pool.py` |
| Network engine | ✅ present | `utils/requester.py`, `utils/async_requester.py`, `core/netpolicy.py` |
| Verification | ✅ present | `core/verify.py`, `core/post_worker_verifier.py` |
| Evidence | ✅ present | `core/evidence_ledger.py` |
| Correlation | ✅ present | `core/correlator.py` |
| Confidence / severity / scoring | ✅ present | `core/scorer.py` |
| Rules engine | ✅ present | `core/rules_engine.py`, `scanner_rules.yaml` |
| Persistence / DB | ✅ present | `core/persistence.py` |
| Tool runtime + registry | ✅ present | `core/tool_runtime.py`, `core/tool_integrator.py`, `runtime/` |
| Reporting (JSON/HTML/SARIF) | ✅ present | `core/reporter.py`, golden `tests/golden/report_mock.{json,sarif}` |
| Optional LLM layer | ✅ present | `core/llm_base.py`, `core/ai_engine.py` |
| Web dashboard + API | ✅ present | `web/app.py`, `web/static/app/js/**` |
| **Event bus** | ⚠️ **gap** | no `EventBus`/`event_bus`; runtime is call-graph driven, not event-driven |
| **Single CoverageEngine** | ✅ **added this session** | `core/coverage.py` + `CoverageState`/`CoverageRecord`/`CoverageSummary` in `core/models.py`; `AtomicEngine.get_coverage_summary()` |

## Honest scope note

The master prompt asks to "transform the repository into a production-grade
platform" and produce ~11 certification documents with 0–100 health scores and
per-module maturity ratings. Two things about that:

1. **The transformation target is largely already met.** Fabricating a
   before/after rewrite narrative, or inventing per-category 0–100 scores and
   "CERTIFIED" module stamps, would be dishonest — those numbers can't be
   produced truthfully without a measurement harness that doesn't exist yet.
2. **What's real and bounded has been done:** environment fixed, a genuine
   crash bug fixed, the suite stabilized to 0 failures, and this evidence-based
   map produced.

## Prioritized backlog (real, bounded next steps)

Ranked by value ÷ risk. Each is a concrete vertical slice, not a rewrite.

1. **Coverage engine** — ✅ **DONE this session.** Added `CoverageState`,
   `CoverageRecord`, `CoverageSummary` to `core/models.py`; a `CoverageEngine`
   in `core/coverage.py` (no-downgrade state grid, param-agnostic endpoint
   identity, deterministic output); `ScanResult.coverage` field; and a
   read-only `AtomicEngine.get_coverage_summary()` that answers "what remains
   untested" from surface + findings + enabled modules. 26 unit/integration
   tests in `tests/test_coverage.py`. Remaining follow-up: emit live
   PLANNED/TESTED/SKIPPED marks from within the scan loop (today TESTED is
   inferred from findings; PLANNED from enabled modules) and surface coverage
   in the web dashboard.
2. **`atomic benchmark` command** — ✅ **DONE this session.** `core/benchmark.py`
   is a deterministic, network-free suite over real hot paths (model
   serialization, coverage build, correlation, canonical JSON). Wired as
   `--benchmark` / `--benchmark-json` / `--benchmark-baseline`
   (`--benchmark-tolerance`), with a CI-usable regression gate (exit 1 on a
   >tolerance throughput drop) and a `make benchmark` target. 16 tests in
   `tests/test_benchmark.py`.

3. **Confidence calibration harness** *(next up)* — the prompt's "predicted vs.
   actual confirmation rate" needs deterministic fixtures; `core/scorer.py` +
   `tests/golden/` are the foundation to build it on.
4. **Event bus (optional)** — only if the dashboard needs incremental updates;
   today it works without one. Low priority unless real-time UI is a goal.
5. **Silent-failure audit** — 268 `except: pass` sites repo-wide. Most are
   deliberate per-probe swallows in a scanner, so this is a *careful, per-site*
   review, not a mass edit. Convert only hot-path swallows to typed errors.

## What is intentionally NOT done

- No 144K-line rewrite. The prompt itself warns against a big-bang rewrite.
- No fabricated health matrix / module certification with invented scores.
- No mass rewrite of `except: pass` sites (regression risk > value).
- No new offensive capabilities added on a blanket instruction.
