#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Signal Emission Pipeline
==================================================

Modules emit ``ModuleSignal`` observations; this module transforms them
into ``CanonicalFinding`` objects via a validated, normalized pipeline.

Contract
--------
* Modules call ``emit_signal(signal, engine)`` instead of creating
  ``Finding`` objects directly.
* ``emit_signal`` validates the signal, calls verification and scoring,
  enforces the evidence contract, deduplicates, and — only if all checks
  pass — creates and registers a ``CanonicalFinding``.
* The legacy ``engine.add_finding(Finding(...))`` path is preserved for
  backward compatibility; it is bridged into the canonical model by
  ``bridge_legacy_finding``.

Pipeline stages inside emit_signal
------------------------------------
1. ``validate_signal`` — schema-level checks (required fields)
2. ``normalize_signal`` — strip payload noise, canonicalize URL
3. ``build_evidence`` — construct Evidence + request fingerprint
4. ``score_signal`` — derive confidence/severity from raw_confidence
5. ``build_repro`` — minimal replay template
6. ``dedupe_check`` — skip if canonical finding_id already registered
7. ``register`` — create and store CanonicalFinding
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Dict, Optional

from core.models import (
    CanonicalFinding,
    Evidence,
    EvidenceSnippet,
    ModuleSignal,
    Repro,
    VerificationResult,
)
from core.normalizer import normalize

if TYPE_CHECKING:
    pass  # avoid circular imports with engine

logger = logging.getLogger(__name__)

# Severity thresholds (raw_confidence → severity)
_SEVERITY_FROM_CONFIDENCE = [
    (0.85, "CRITICAL"),
    (0.70, "HIGH"),
    (0.45, "MEDIUM"),
    (0.20, "LOW"),
    (0.0, "INFO"),
]

# CWE / MITRE lookup (subset — extend as needed)
_VULN_TO_MITRE_CWE: Dict[str, tuple] = {
    "sqli": ("T1190", "CWE-89"),
    "xss": ("T1059.007", "CWE-79"),
    "lfi": ("T1083", "CWE-22"),
    "cmdi": ("T1059", "CWE-78"),
    "ssrf": ("T1090", "CWE-918"),
    "ssti": ("T1059", "CWE-94"),
    "xxe": ("T1190", "CWE-611"),
    "idor": ("T1078", "CWE-639"),
    "nosql": ("T1190", "CWE-943"),
    "cors": ("T1600", "CWE-942"),
    "jwt": ("T1528", "CWE-287"),
    "upload": ("T1190", "CWE-434"),
    "open_redirect": ("T1566", "CWE-601"),
    "crlf": ("T1190", "CWE-113"),
    "hpp": ("T1190", "CWE-235"),
    "proto_pollution": ("T1059.007", "CWE-1321"),
    "race_condition": ("T1499", "CWE-362"),
    "websocket": ("T1071", "CWE-1385"),
    "deserialization": ("T1190", "CWE-502"),
}

# Remediation suggestions keyed by vuln_type
_REMEDIATION: Dict[str, str] = {
    "sqli": "Use parameterized queries / prepared statements.",
    "xss": "Encode output contextually (HTML, JS, URL). Use Content-Security-Policy.",
    "lfi": "Validate and whitelist file paths.",
    "cmdi": "Avoid passing user input to OS commands. Use safe API alternatives.",
    "ssrf": "Validate and whitelist URLs. Block internal/metadata IP ranges.",
    "ssti": "Use a sandboxed template engine. Never pass user input into templates.",
    "xxe": "Disable external entity processing in XML parsers.",
    "idor": "Implement per-object authorization checks. Use indirect references.",
    "cors": "Restrict Access-Control-Allow-Origin to trusted domains.",
    "jwt": "Enforce strong signing algorithms (RS256+). Validate all claims.",
    "nosql": "Sanitize input before NoSQL queries. Avoid operator injection.",
    "upload": "Validate file type, size, and content. Store uploads outside webroot.",
    "open_redirect": "Validate and whitelist redirect URLs.",
    "crlf": "Strip or encode CR/LF characters from user input.",
    "hpp": "Normalize duplicate parameters server-side.",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def emit_signal(signal: ModuleSignal, engine) -> Optional[CanonicalFinding]:
    """Transform a raw ``ModuleSignal`` into a registered ``CanonicalFinding``.

    Returns the created ``CanonicalFinding`` if the signal passed all
    pipeline stages, or ``None`` if it was rejected (invalid, duplicate,
    or below threshold).

    Args:
        signal:  Raw observation from a scan module.
        engine:  The running ``AtomicEngine`` instance (provides
                 ``add_finding``, ``findings`` list, and config access).
    """
    # 1. Validate
    if not validate_signal(signal):
        logger.debug("Signal rejected (invalid): %s @ %s", signal.vuln_type, signal.url)
        return None

    # 2. Normalize
    norm_signal = normalize_signal(signal)

    # 3. Build evidence
    evidence = build_evidence(norm_signal)

    # 4. Score
    severity, confidence = score_signal(norm_signal)

    # 5. Build repro
    repro = build_repro(norm_signal)

    # 6. MITRE / CWE
    mitre_id, cwe_id = _lookup_mitre_cwe(norm_signal.vuln_type)

    # 7. Build the CanonicalFinding (finding_id is auto-computed)
    finding = CanonicalFinding(
        technique=norm_signal.technique or norm_signal.vuln_type,
        url=norm_signal.url,
        method=norm_signal.method.upper(),
        param=norm_signal.param,
        payload=norm_signal.payload,
        severity=severity,
        confidence=confidence,
        cvss=_confidence_to_cvss(confidence, norm_signal.vuln_type),
        mitre_id=mitre_id,
        cwe_id=cwe_id,
        evidence=evidence,
        repro=repro,
        verification=VerificationResult(
            verified=False,
            method="pending",
            notes="verification not yet run",
        ),
        remediation=_REMEDIATION.get(norm_signal.vuln_type.lower(), ""),
        signals={
            "response_status": norm_signal.response_status,
            "response_time": norm_signal.response_time,
            "response_length": norm_signal.response_length,
        },
    )

    # 8/9. Atomically deduplicate + register.  Scan modules may emit from
    # multiple worker threads; checking and inserting in two separate
    # operations allows the same finding to race through twice.
    if not _register_finding_if_new(finding, engine):
        logger.debug("Signal deduplicated: %s", finding.finding_id)
        return None
    return finding


def bridge_legacy_finding(legacy_finding, engine) -> Optional[CanonicalFinding]:
    """Convert a legacy ``core.engine.Finding`` into a ``CanonicalFinding``.

    Called by the updated ``BaseModule._add_finding`` wrapper to ensure
    all findings, whether from old or new module code, enter the
    canonical model.

    Returns the ``CanonicalFinding`` or ``None`` if the legacy finding
    was invalid.
    """
    try:
        technique = getattr(legacy_finding, "technique", "")
        signal = ModuleSignal(
            vuln_type=_infer_vuln_type_from_technique(technique),
            technique=getattr(legacy_finding, "technique", ""),
            url=getattr(legacy_finding, "url", ""),
            method=getattr(legacy_finding, "method", "GET"),
            param=getattr(legacy_finding, "param", ""),
            payload=getattr(legacy_finding, "payload", ""),
            injection_point="query",
            evidence_text=getattr(legacy_finding, "evidence", ""),
            raw_confidence=getattr(legacy_finding, "confidence", 0.0),
        )
        if not signal.is_valid():
            return None
        return emit_signal(signal, engine)
    except Exception as exc:
        logger.debug("bridge_legacy_finding failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Pipeline stage implementations
# ---------------------------------------------------------------------------


def validate_signal(signal: ModuleSignal) -> bool:
    """Return True only when the signal has all required fields."""
    if not isinstance(signal, ModuleSignal):
        return False
    return signal.is_valid()


def normalize_signal(signal: ModuleSignal) -> ModuleSignal:
    """Return a normalized copy of *signal*.

    * URL is canonicalized via ``core.surface.normalize_url``.
    * evidence_text is stripped of dynamic noise via ``core.normalizer.normalize``.
    * payload is stripped of leading/trailing whitespace.
    """
    from core.surface import normalize_url

    normalized = ModuleSignal(
        vuln_type=signal.vuln_type.lower().strip(),
        technique=signal.technique.strip(),
        url=normalize_url(signal.url) if signal.url else signal.url,
        method=signal.method.upper(),
        param=signal.param.strip(),
        payload=signal.payload.strip(),
        injection_point=signal.injection_point,
        evidence_text=normalize(signal.evidence_text) if signal.evidence_text else "",
        response_status=signal.response_status,
        response_time=signal.response_time,
        response_length=signal.response_length,
        raw_confidence=signal.raw_confidence,
        extra=dict(signal.extra),
    )
    return normalized


def build_evidence(signal: ModuleSignal) -> Evidence:
    """Construct an ``Evidence`` object from a signal."""
    snippets = []
    if signal.evidence_text:
        snippet_text = signal.evidence_text[:500]
        snippets.append(EvidenceSnippet(offset=0, context=snippet_text, mime_hint="text"))

    fingerprint = _build_request_fingerprint(signal)

    return Evidence(
        payload_used=signal.payload,
        injection_point=signal.injection_point,
        snippets=snippets,
        request_fingerprint=fingerprint,
        raw_response_snippet=signal.evidence_text[:200] if signal.evidence_text else "",
    )


def build_repro(signal: ModuleSignal) -> Repro:
    """Build a minimal replay template from the signal.

    Query reconstruction deliberately preserves duplicate parameters, blank
    values and URL fragments.  The old ``parse_qs`` -> ``dict`` round-trip
    collapsed duplicates (common in HPP/API cases) and silently discarded the
    fragment, so the generated reproduction could differ from the request that
    produced the observation.
    """
    if signal.injection_point == "query":
        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
        try:
            parsed = urlparse(signal.url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            replaced = False
            rebuilt = []
            for key, value in pairs:
                if signal.param and key == signal.param and not replaced:
                    rebuilt.append((key, "__PAYLOAD_PLACEHOLDER__"))
                    replaced = True
                else:
                    rebuilt.append((key, value))
            if signal.param and not replaced:
                rebuilt.append((signal.param, "__PAYLOAD_PLACEHOLDER__"))
            new_query = urlencode(rebuilt, doseq=True)
            url_template = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                new_query, parsed.fragment
            ))
            url_template = url_template.replace("__PAYLOAD_PLACEHOLDER__", "{PAYLOAD}")
        except (TypeError, ValueError):
            url_template = signal.url
        return Repro(method=signal.method, url_template=url_template)

    if signal.injection_point == "path":
        from urllib.parse import urlparse, urlunparse
        try:
            parsed = urlparse(signal.url)
            path = parsed.path
            if signal.param and signal.param in path:
                path = path.replace(signal.param, "{PAYLOAD}", 1)
            elif signal.payload and signal.payload in path:
                path = path.replace(signal.payload, "{PAYLOAD}", 1)
            elif not path.endswith("/"):
                path = f"{path}/{{PAYLOAD}}"
            else:
                path = f"{path}{{PAYLOAD}}"
            url_template = urlunparse((
                parsed.scheme, parsed.netloc, path, parsed.params,
                parsed.query, parsed.fragment
            ))
        except (TypeError, ValueError):
            url_template = signal.url
        return Repro(method=signal.method, url_template=url_template)

    elif signal.injection_point == "form":
        body_template = f"{signal.param}={{PAYLOAD}}" if signal.param else "{PAYLOAD}"
        return Repro(
            method=signal.method,
            url_template=signal.url,
            body_template=body_template,
        )

    return Repro(method=signal.method, url_template=signal.url)


def score_signal(signal: ModuleSignal) -> tuple:
    """Derive (severity, confidence) from a ModuleSignal.

    The deterministic engine — never the LLM — has the final word on
    confidence (SEC-007):

    * Signals carrying a non-zero ``raw_confidence`` start from it.
    * Signals whose ``extra['source'] == "llm"`` are AI judgement.  When
      they are NOT backed by deterministic evidence
      (``extra['deterministic']`` falsy) and NOT independently verified,
      the confidence is capped below the HIGH band so an unverified model
      verdict can never mint HIGH/CRITICAL findings on its own.
    * Signals with deterministic evidence or verifier confirmation keep
      their evidence-derived score.

    Returns:
        (severity: str, confidence: float)
    """
    confidence = float(signal.raw_confidence or 0.0)
    confidence = max(0.0, min(1.0, confidence))

    if confidence == 0.0:
        # Minimal signal: assign LOW confidence by default
        confidence = 0.25

    extra = signal.extra or {}
    if (
        extra.get("source") == "llm"
        and not extra.get("verified")
        and not extra.get("deterministic")
    ):
        # Unsubstantiated AI judgement: cap below HIGH (0.70).
        confidence = min(confidence, 0.60)

    severity = "INFO"
    for threshold, sev in _SEVERITY_FROM_CONFIDENCE:
        if confidence >= threshold:
            severity = sev
            break

    return severity, round(confidence, 3)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------




def _infer_vuln_type_from_technique(technique: str) -> str:
    """Map legacy human-readable technique labels to canonical vuln keys.

    Legacy modules historically used the first word of the technique label,
    turning ``SQL Injection`` into ``sql`` and losing CWE/remediation mapping.
    Keep this deterministic and conservative; unknown labels stay ``unknown``.
    """
    text = (technique or "").strip().lower()
    aliases = (
        (("sql injection", "sqli"),),
        (("cross-site scripting", "xss"), ("cross site scripting", "xss"), (" xss", "xss")),
        (("command injection", "cmdi"), ("os command", "cmdi")),
        (("server-side request forgery", "ssrf"), ("ssrf", "ssrf")),
        (("server-side template injection", "ssti"), ("ssti", "ssti")),
        (("xml external entity", "xxe"), ("xxe", "xxe")),
        (("local file inclusion", "lfi"), ("path traversal", "lfi"), ("lfi", "lfi")),
        (("insecure direct object", "idor"), ("idor", "idor"), ("bola", "idor")),
        (("nosql", "nosql"),),
        (("cors", "cors"),),
        (("jwt", "jwt"),),
        (("open redirect", "open_redirect"),),
        (("crlf", "crlf"),),
        (("parameter pollution", "hpp"), ("hpp", "hpp")),
        (("prototype pollution", "proto_pollution"),),
        (("race condition", "race_condition"),),
        (("deserialization", "deserialization"),),
        (("file upload", "upload"), ("upload", "upload")),
    )
    for group in aliases:
        for needle, canonical in group:
            if needle.strip() in text:
                return canonical
    return "unknown"

def _lookup_mitre_cwe(vuln_type: str) -> tuple:
    entry = _VULN_TO_MITRE_CWE.get(vuln_type.lower(), ("", ""))
    return entry


def _confidence_to_cvss(confidence: float, vuln_type: str = "") -> float:
    """Compute a coarse CVSS-v3.1 base-score estimate.

    The previous implementation used ``confidence * 10`` which is not
    CVSS at all — a 0.5-confidence finding became "5.0" regardless of
    impact. This version starts from a per-vuln-class baseline that
    reflects typical exploitability + impact for that family, then
    attenuates by confidence so that low-confidence signals cannot
    masquerade as high-severity issues. The result is still a coarse
    estimate (an authoritative score requires a real CVSS vector built
    from the concrete environment), but it no longer pretends accuracy
    it doesn't have.
    """
    # Baseline severity per vuln family (CVSS v3.1 ranges): roughly the
    # median observed for confirmed instances of the class.
    BASELINE = {
        "sqli": 9.0,                # CWE-89: full DB compromise common
        "cmdi": 9.8,                # CWE-78: arbitrary OS command
        "ssti": 9.8,                # CWE-94: typically RCE
        "deserialization": 9.0,     # CWE-502: typically RCE
        "xxe": 8.0,                 # CWE-611: SSRF + file read
        "ssrf": 7.5,                # CWE-918: internal exposure
        "lfi": 7.5,                 # CWE-22: file disclosure → RCE
        "upload": 8.5,              # CWE-434: shell upload
        "proto_pollution": 7.5,
        "xss": 6.1,                 # CWE-79: typical reflected
        "jwt": 7.5,                 # CWE-287: auth bypass
        "idor": 6.5,                # CWE-639: data exposure
        "nosql": 7.5,
        "open_redirect": 6.1,
        "cors": 6.5,
        "crlf": 5.4,
        "hpp": 5.0,
        "race_condition": 5.0,
        "websocket": 5.4,
    }
    base = BASELINE.get((vuln_type or "").lower(), 5.0)
    confidence = max(0.0, min(1.0, float(confidence or 0.0)))
    # Attenuate by confidence with a floor so a high-impact-but-low-
    # confidence finding still surfaces above noise.  At confidence 1.0
    # the score equals the baseline; at confidence 0.25 it's halved.
    attenuated = base * (0.5 + 0.5 * confidence)
    return round(min(10.0, attenuated), 1)


def _build_request_fingerprint(signal: ModuleSignal) -> dict:
    """Create a non-secret request fingerprint for the signal."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(signal.url)
        canonical_url_hash = hashlib.sha256(
            f"{signal.method.upper()}:{parsed.scheme}://{parsed.netloc}{parsed.path}".encode()
        ).hexdigest()[:16]
    except Exception:
        canonical_url_hash = ""

    body_hash = ""
    if signal.payload:
        body_hash = hashlib.sha256(signal.payload.encode()).hexdigest()[:16]

    return {
        "canonical_url_hash": canonical_url_hash,
        "method": signal.method.upper(),
        "payload_hash": body_hash,
    }


def _canonical_lock(engine):
    """Return the engine lock used to protect finding stores, when present.

    Real ``AtomicEngine`` instances expose ``_findings_lock``.  Lightweight
    test/plugin engines may not, so ``nullcontext`` preserves compatibility.
    """
    from contextlib import nullcontext

    return getattr(engine, "_findings_lock", None) or nullcontext()


def _is_duplicate(finding: CanonicalFinding, engine) -> bool:
    """Return True if a finding with the same finding_id already exists.

    Kept for compatibility with callers/tests; emission itself uses the
    atomic ``_register_finding_if_new`` path below.
    """
    with _canonical_lock(engine):
        existing = getattr(engine, "_canonical_findings", None)
        if existing is None:
            engine._canonical_findings = {}
            return False
        return finding.finding_id in existing


def _register_finding_if_new(finding: CanonicalFinding, engine) -> bool:
    """Atomically register *finding* if its canonical id is new.

    Returns ``True`` only for the thread that performed the insertion.
    The legacy reporting bridge runs after the canonical insertion, so a
    failure in legacy presentation cannot lose the canonical record.
    """
    with _canonical_lock(engine):
        if not hasattr(engine, "_canonical_findings"):
            engine._canonical_findings = {}
        if finding.finding_id in engine._canonical_findings:
            return False
        engine._canonical_findings[finding.finding_id] = finding

    _bridge_to_legacy(finding, engine)
    return True


def _register_finding(finding: CanonicalFinding, engine) -> None:
    """Backward-compatible wrapper around atomic registration."""
    _register_finding_if_new(finding, engine)


def _bridge_to_legacy(finding: CanonicalFinding, engine) -> None:
    """Bridge a canonical record to the legacy reporting list."""
    try:
        from core.engine import Finding as LegacyFinding
        legacy = LegacyFinding(
            technique=finding.technique,
            url=finding.url,
            method=finding.method,
            param=finding.param,
            payload=finding.payload,
            evidence=finding.evidence.raw_response_snippet if finding.evidence else "",
            severity=finding.severity,
            confidence=finding.confidence,
            cvss=finding.cvss,
            mitre_id=finding.mitre_id,
            cwe_id=finding.cwe_id,
            remediation=finding.remediation,
            signals=finding.signals,
        )
        engine.add_finding(legacy)
    except Exception as exc:
        logger.debug("Legacy bridge add_finding failed: %s", exc)
