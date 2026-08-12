# Next-level hardening — 2026-08-13

On top of PR #11 (default credentials, cache isolation, loopback bind).

## Fixes

1. **Unsigned plugin load (HIGH)** — `load_plugin` now requires `PLUGIN.sha256` matching `__init__.py`, unless `ATOMIC_ALLOW_UNSIGNED_PLUGINS=1`. Bundled plugins shipped with manifests. Tests set the opt-in via `conftest.py`.

2. **Ollama SSRF (HIGH)** — `_ollama_host()` only allows `localhost` / `127.0.0.1` / `::1`. Remote hosts need `ATOMIC_OLLAMA_ALLOW_REMOTE=1`.

3. **Chat identity spoof (MEDIUM)** — HTTP chat uses the authenticated principal (`sub`), not `body.sender`.

4. **Tool/recon scope fail-closed (MEDIUM)** — When `ATOMIC_AUTH_REQUIRED` is on and no `ATOMIC_ALLOWED_DOMAINS`, dashboard tool targets are denied. Flask `TESTING` still allows local suite.

## Tests

`tests/test_next_level_2026_08_13.py` — 8 cases. Targeted run: **43 passed**.

## Operator notes

```
# production plugins
# ship PLUGIN.sha256 next to each plugin, or:
ATOMIC_ALLOW_UNSIGNED_PLUGINS=1   # only if you trust plugins/

ATOMIC_ALLOWED_DOMAINS=example.com
ATOMIC_TOOL_SCOPE_STRICT=1

# remote Ollama only if you mean it
ATOMIC_OLLAMA_ALLOW_REMOTE=1
OLLAMA_HOST=http://ollama.internal:11434
```
