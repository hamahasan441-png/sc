import threading
from concurrent.futures import ThreadPoolExecutor

from core.emit import emit_signal
from core.engine import AtomicEngine
from core.models import ModuleSignal


class MiniEngine:
    def __init__(self):
        self._canonical_findings = {}
        self.findings = []
        self.config = {"verbose": False}
        self._findings_lock = threading.Lock()

    def add_finding(self, finding):
        # emit.py releases the canonical lock before the legacy bridge.
        with self._findings_lock:
            if not any(
                getattr(x, "technique", None) == getattr(finding, "technique", None)
                and getattr(x, "url", None) == getattr(finding, "url", None)
                and getattr(x, "param", None) == getattr(finding, "param", None)
                and getattr(x, "payload", None) == getattr(finding, "payload", None)
                for x in self.findings
            ):
                self.findings.append(finding)


def _signal():
    return ModuleSignal(
        vuln_type="sqli",
        technique="SQL Injection (test observation)",
        url="https://example.test/item?id=1",
        method="GET",
        param="id",
        payload="test-marker",
        injection_point="query",
        evidence_text="deterministic test evidence",
        raw_confidence=0.5,
    )


def test_emit_signal_dedup_is_atomic_across_threads():
    engine = MiniEngine()
    with ThreadPoolExecutor(max_workers=24) as pool:
        results = list(pool.map(lambda _: emit_signal(_signal(), engine), range(200)))

    assert sum(result is not None for result in results) == 1
    assert len(engine._canonical_findings) == 1
    assert len(engine.findings) == 1


def test_add_finding_dict_populates_canonical_store_and_deduplicates():
    engine = object.__new__(AtomicEngine)
    engine._findings_lock = threading.Lock()
    engine._canonical_findings = {}
    engine.findings = []

    item = {
        "technique": "Configuration Observation",
        "url": "https://example.test/",
        "method": "GET",
        "param": "",
        "payload": "",
        "severity": "INFO",
        "confidence": 0.5,
    }
    engine.add_finding_dict(item)
    engine.add_finding_dict(item)

    assert len(engine._canonical_findings) == 1
    assert len(engine.findings) == 1
    snap = engine.get_canonical_findings()
    assert len(snap) == 1
    assert snap[0].technique == "Configuration Observation"


def test_query_repro_preserves_duplicate_params_and_fragment():
    from core.emit import build_repro
    s = ModuleSignal(
        vuln_type="hpp",
        technique="HTTP Parameter Pollution",
        url="https://example.test/search?a=1&a=2&empty=#frag",
        method="GET",
        param="a",
        payload="marker",
        injection_point="query",
    )
    r = build_repro(s)
    assert r.url_template.count("a=") == 2
    assert "a=%7BPAYLOAD%7D" not in r.url_template
    assert "a={PAYLOAD}" in r.url_template
    assert "empty=" in r.url_template
    assert r.url_template.endswith("#frag")


def test_path_repro_puts_marker_in_path_not_query():
    from core.emit import build_repro
    s = ModuleSignal(
        vuln_type="lfi",
        technique="Path Traversal",
        url="https://example.test/files/report.txt?download=1#top",
        method="GET",
        param="report.txt",
        payload="marker",
        injection_point="path",
    )
    r = build_repro(s)
    assert "/files/{PAYLOAD}" in r.url_template
    assert "download=1" in r.url_template
    assert r.url_template.endswith("#top")


def test_legacy_technique_mapping_is_canonical():
    from core.emit import _infer_vuln_type_from_technique
    assert _infer_vuln_type_from_technique("SQL Injection (Error-based)") == "sqli"
    assert _infer_vuln_type_from_technique("Cross-Site Scripting (Reflected)") == "xss"
    assert _infer_vuln_type_from_technique("Open Redirect") == "open_redirect"
    assert _infer_vuln_type_from_technique("Something Unknown") == "unknown"
