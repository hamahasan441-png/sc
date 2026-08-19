# ATOMIC Framework — Repair Pass 2026-08-19

This repair pass was performed against the uploaded archive, not against README claims.

## Baseline

- ZIP integrity: passed (`ZipFile.testzip()` returned no corrupt member).
- Archive members: 531.
- Python files: 357.
- `python -m compileall -q .`: passed before changes.
- Initial pytest collection in this environment was blocked by optional/runtime packages not installed in the execution container (Flask, Flask-CORS, Flask-SocketIO, Scapy, pytest-timeout). These packages are declared by the project; this is an environment limitation, not treated as a source-code failure.
- With Flask-dependent tests excluded, the first run reached 337 passed / 9 skipped before the first environment-dependent Flask import failure. A broader run progressed further but exceeded the execution time budget and exposed an unrelated bundled-tool fixture issue.

## Repairs applied

### 1. Defense-in-depth authorization gates

Files:
- `core/engine.py`
- `modules/uploader.py`
- `modules/dumper.py`
- `modules/brute_force.py`

Problem: the central post-exploitation paths were partly gated, but several legacy/manual dispatch paths and direct module entry points could reach shell deployment, data extraction, or credential brute force without enforcing the same gate locally.

Repair:
- Added explicit `require_authorized(...)` checks before legacy shell upload, data dump, and credential-bruteforce dispatch in the engine.
- Added local fail-closed authorization checks inside the three modules so a future caller cannot bypass the engine-level guard by instantiating a module directly.
- Kept scan-only upload detection unchanged.

### 2. Nuclei template path containment

File: `web/app.py`

Problem: the template endpoint used string-prefix containment after `os.path.join`. Prefix tests are brittle for filesystem security and are weaker than canonical path containment.

Repair:
- Normalize and reject absolute/parent paths.
- Canonicalize both root and requested file with `realpath`.
- Enforce containment with `os.path.commonpath` and fail closed on cross-drive/path errors.

### 3. Batch HTML report injection hardening

File: `core/batch_scanner.py`

Problem: target names and scanner error strings were embedded directly into generated HTML. A crafted target/error could become active markup when a report was opened.

Repair:
- HTML-escape target, error, severity label, and severity CSS token before interpolation.
- Added regression coverage with hostile `<img>` / `<script>` input.

### 4. External-tool argument validation

File: `core/tool_integrator.py`

Problem: subprocess execution correctly used argv arrays rather than `shell=True`, but the option sanitizer was permissive: unknown dash-prefixed options could pass in several positions and `key=value` options were accepted too broadly.

Repair:
- Reworked validation around an explicit known-option set and value-taking option set.
- Reject unknown external-tool options.
- Reject option injection where a target/value is expected.
- Reject shell metacharacters/control characters in positional values.
- Reject missing values for value-taking options.

## Regression tests added

File: `tests/test_repair_2026_08_19.py`

Coverage added for:
- direct shell-uploader authorization bypass,
- direct data-dumper authorization bypass,
- direct brute-force authorization bypass,
- HTML escaping in batch reports,
- unknown external-tool option rejection,
- metacharacter rejection in external-tool values.

The new repair suite passes: **6 passed**.

Existing targeted authorization/audit tests that do not require Flask also pass after these changes.

## Validation after repairs

- Modified files compile successfully.
- New regression suite: 6/6 passed.
- Existing `tests/test_audit_fixes.py` plus the initial repair tests passed (one pre-existing skip).
- Existing hardening test for flag injection passed.
- Full-suite completion could not be honestly claimed in this container because required web/runtime packages are absent and the suite is large enough to exceed the available single-command execution window.

## Important remaining engineering work

This archive is large (357 Python files) and contains overlapping/legacy implementations. A single repair pass should not be represented as proof that every scanner module is production-grade. Highest-value next work:

1. Consolidate duplicate core implementations (`verify`/`verifier`, scan pools, correlators) and delete dead paths only after dependency tracing.
2. Run the complete matrix in the project's declared environment with all pinned dependencies installed.
3. Add deterministic vulnerable/patched fixtures for every detection module and require both true-positive and true-negative assertions.
4. Tighten evidence contracts so a finding requires independent verification rather than one response heuristic.
5. Measure false-positive rates per module and gate release quality on them.
6. Continue reviewing dashboard endpoints, persistence, plugin loading, updater behavior, archive handling, and report serialization for trust-boundary bugs.
7. Keep destructive/post-exploitation functionality explicitly authorized and auditable; do not make it an implicit scan behavior.

## Files changed in this pass

- `core/engine.py`
- `core/batch_scanner.py`
- `core/tool_integrator.py`
- `web/app.py`
- `modules/uploader.py`
- `modules/dumper.py`
- `modules/brute_force.py`
- `tests/test_repair_2026_08_19.py`
- `REPAIR_REPORT_2026-08-19.md`
