# ATOMIC Framework — Repair Stage 2 (2026-08-19)

This stage focuses on defensive correctness, scanner reliability, canonical finding integrity, evidence/reproduction quality, and concurrency safety. It does not add destructive exploitation capability.

## Repairs

1. **Atomic canonical finding deduplication** (`core/emit.py`)
   - Replaced the separate duplicate-check and insert operations with one atomic registration path.
   - Reuses the engine finding lock when present and retains compatibility with lightweight engines without a lock.
   - Prevents duplicate canonical findings when multiple scan workers emit the same observation concurrently.

2. **Canonical store consistency** (`core/engine.py`)
   - Fixed `add_finding_dict()` so a successfully constructed `CanonicalFinding` is actually inserted into `_canonical_findings`.
   - Added canonical-ID deduplication for this path.
   - Preserved the legacy findings list for backward-compatible consumers.

3. **Thread-safe canonical snapshots** (`core/engine.py`)
   - `get_canonical_findings()` now snapshots under the engine findings lock when available.
   - Added a compatibility fallback for plugin/test engine objects constructed without running `AtomicEngine.__init__`.

4. **Reproduction-template correctness** (`core/emit.py`)
   - Query reconstruction now preserves duplicate parameters, blank values, URL parameters, and fragments.
   - The old `parse_qs -> dict` conversion silently collapsed repeated keys.
   - Path injection reproduction is now handled as a path mutation instead of being incorrectly treated as query injection.

5. **Legacy vulnerability classification** (`core/emit.py`)
   - Replaced first-word classification (`SQL Injection` -> `sql`) with deterministic canonical mapping (`sqli`, `xss`, `cmdi`, `ssrf`, etc.).
   - Restores correct CWE/MITRE/remediation lookup for legacy findings entering the canonical pipeline.

6. **Regression tests** (`tests/test_repair_stage2.py`)
   - Concurrent signal deduplication test (200 parallel emissions).
   - `add_finding_dict()` canonical-store consistency and deduplication.
   - Query reproduction duplicate-param/fragment preservation.
   - Path reproduction marker placement.
   - Legacy technique-to-vulnerability canonical mapping.

## Validation performed

- `python -m compileall -q .` — PASS
- `tests/test_repair_stage2.py`
- `tests/test_emit_contract.py`
- `tests/test_models_contract.py`
- `tests/test_engine_surface_integration.py`
- `tests/test_persistence_canonical.py`

Combined targeted suite: **125 passed**.

## Remaining work for later stages

- Consolidate overlapping verification/orchestration implementations and define a single authoritative verification contract.
- Reduce false positives in modules that rely on single-response heuristics or weak timing/error signals.
- Audit async request lifecycle, cancellation, retry/backoff, and timeout propagation.
- Audit module-by-module exception handling and response assumptions.
- Expand integration fixtures for vulnerable vs patched targets so detection quality can be measured, not just code coverage.
- Review report severity/confidence semantics so unverified observations cannot be represented as fully confirmed findings.
