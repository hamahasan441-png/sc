# ATOMIC v12 Security Checkpoint — 2026-08-19

This archive is a **work-in-progress checkpoint**, not a final production release.

## Completed in this checkpoint

- One-time web Owner/Admin setup with persistent scrypt password storage.
- Persistent private JWT/session secret and owner authorization acknowledgement.
- Admin/Owner permission bypass for all current and future permission names.
- Bearer-token login/refresh/logout flow in the modern dashboard and authenticated WebSocket setup.
- Strict API permission checks for audit, export, plugin, shell, external-tool and Ollama surfaces.
- Repeater and requester redirect validation before each network hop, TLS verification by default, bounded bodies, cache isolation by effective headers, and DNS/private-network policy checks.
- Browser scanner request routing/scope checks; unsafe `--no-sandbox` defaults removed.
- Plugin integrity manifest checks, permissions checks, and non-blocking timeout handling.
- External-tool argv allowlisting, typed web parameters, trusted executable-path checks, bounded output, and process-tree timeouts.
- Ollama model-name, response, job, concurrency, duration and model-size limits.
- Local GGUF download requires an operator-supplied publisher SHA-256, validates the GGUF header, uses private storage, and enforces download limits.
- CSV spreadsheet-formula neutralization.
- Private data/report/database permissions and redacted shell command parameters by default.
- Read-only shell-command restrictions for state-changing `ip`, `ifconfig`, `hostname`, `date`, and dangerous `find` options.
- Python, JavaScript, JSON, YAML and shell syntax validation passed for this checkpoint.

## Still required before a final release

1. Update Dockerfile and Compose: multi-stage image, loopback host binding, persistent `ATOMIC_HOME`, healthcheck, and v12 labels.
2. Add/repair gating CI workflows and remove non-gating security commands from the Makefile.
3. Update old tests for the new safe DNS/TLS defaults and the new `_filter_tool_params(..., family)` signature.
4. Run the full test suite in an environment with all pinned runtime/dev dependencies. This build environment lacked Flask, Requests, SQLAlchemy and pytest.
5. Add integration tests for first-run setup/login/refresh, SSRF redirects, DNS rebinding-style resolution, bounded Ollama pulls, and external-tool output truncation.
6. Finish shell-manager outbound network-policy/redirect enforcement and streaming response caps.
7. Reconcile README/SECURITY/version references with v12 and write final migration/setup documentation.
8. Remove obsolete legacy dashboard/template, historical repair reports, and bundled simulated runtime wrappers; rebuild the runtime manifest.
9. Produce a reviewed dependency lock with publisher/package hashes and verify every optional dependency/tool version.
10. Recalculate the trusted plugin manifest if any plugin source changes.
11. Run Docker build/health checks and an end-to-end scan against a controlled local lab.
12. GitHub push/repository replacement was not performed from this environment.

## Password behavior

No password is embedded in the source or archive. `admin23` is intentionally not used because it is short and was exposed in chat. On first launch, the web setup page asks the owner to create a password with at least eight characters, including uppercase, lowercase and a digit.

## Validation snapshot

- 359 Python files parsed: PASS
- 16 JSON files parsed: PASS
- 22 YAML files parsed: PASS
- All dashboard JavaScript passed `node --check`: PASS
- All shell scripts passed `bash -n`: PASS
- Auth unit tests: 44 PASS
- Network-policy unit run: 14 PASS, 3 legacy-fixture failures
- Web/Repeater dynamic tests: not run because optional test/runtime dependencies were unavailable

