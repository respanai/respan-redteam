"""Serialize a `CampaignResult` into the JSON report the frontend renders."""
from __future__ import annotations

from .models import CampaignResult, Severity, SEVERITY_RANK

# OWASP LLM Top 10 (2025) display names for the report-card spine.
CATEGORY_NAMES = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM02b": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data & Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector & Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
    "BRAND": "Brand Safety / Competitors",
    "TOX": "Toxicity",
}

# Categories a black-box scan can only partially reach -> greyed-out gateway upsell.
GATEWAY_ONLY_INFO = {
    "LLM05": "Requires response-side instrumentation to verify unsafe output handling.",
    "LLM08": "Requires access to the retrieval / embedding layer.",
    "LLM04": "Requires training-data & model-provenance visibility.",
}



def _finding_dict(f) -> dict:
    return {
        "category": f.category,
        "category_name": CATEGORY_NAMES.get(f.category, f.category),
        "title": f.title,
        "technique": f.technique,
        "severity": f.severity.value,
        "evidence_span": f.evidence_span,
        "owasp": f.owasp,
        "atlas": f.atlas,
        "prompt": (f.prompt or "")[:1200],
        "response": (f.response or "")[:2000],
    }


def build_report(result: CampaignResult) -> dict:
    findings = result.all_findings
    findings_sorted = sorted(
        findings, key=lambda f: SEVERITY_RANK.get(f.severity, 0), reverse=True
    )
    worst = findings_sorted[0] if findings_sorted else None

    # Per-category tiles (merge LLM02b into LLM02 for the card spine).
    tiles: dict[str, dict] = {}
    for c in result.categories:
        base_cat = "LLM02" if c.category == "LLM02b" else c.category
        gw = c.status.startswith("skipped")
        t = tiles.setdefault(base_cat, {
            "category": base_cat,
            "name": CATEGORY_NAMES.get(base_cat, base_cat),
            "sub_grade": "A",
            "findings": 0,
            "probes_used": 0,
            "refused": 0,
            "gateway_only": False,
            "gateway_note": GATEWAY_ONLY_INFO.get(base_cat, ""),
        })
        if gw:
            t["gateway_only"] = True
            continue
        t["probes_used"] += c.probes_used
        t["refused"] += c.refused
        t["findings"] += len(c.findings)
        # worst (lowest) sub-grade wins for the merged tile
        order = ["A", "B", "C", "D", "F", "n/a"]
        if order.index(c.sub_grade) > order.index(t["sub_grade"]):
            t["sub_grade"] = c.sub_grade

    severity_counts = {s.value: 0 for s in Severity if s != Severity.NONE}
    for f in findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    prof = result.profile
    return {
        "target_label": result.target_label,
        "grade": result.grade(),
        "score": result.score(),
        "resistance_rate": round(result.resistance_rate, 3),
        "probes_sent": result.probes_sent,
        "probes_total": result.probes_total,
        "cost_usd": result.cost_usd,
        "duration_s": round((result.finished_at or 0) - (result.started_at or 0), 1),
        "severity_counts": severity_counts,
        "findings_count": len(findings),
        "profile": {
            "target_type": prof.target_type.value,
            "domain": prof.domain,
            "persona": prof.persona,
            "guardrail_strength": prof.guardrail_strength,
            "extraction_confidence": round(prof.extraction_confidence, 2),
            "reconstructed_system_prompt": prof.reconstructed_system_prompt or "",
            "detected_tools": [{"name": t.name, "params": t.params_guess}
                               for t in prof.detected_tools],
            "refusal_signature": prof.refusal_signature,
            "suggested_attack_angles": prof.suggested_attack_angles,
            "notes": prof.notes,
        },
        "category_tiles": sorted(tiles.values(), key=lambda t: t["category"]),
        "findings": [_finding_dict(f) for f in findings_sorted],
        "worst_finding": _finding_dict(worst) if worst else None,
    }
