"""Output formats: terminal text, JSON, SARIF 2.1.0 (GitHub code scanning) and Markdown (PR summary)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import __version__
from .rules import RULES, Finding
from .waivers import Waiver

ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}
SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def text(findings: list[Finding], expired: list[Waiver], blocking: list[Finding]) -> str:
    lines = []
    for f in findings:
        tag = "WAIVED " if f.waived else ""
        lines.append(f"{tag}{f.rule.severity:<8} {f.rule.id:<12} {f.resource}: {f.message}")
        if f.waived:
            lines.append(f"         waiver: {f.waived_reason}")
    for w in expired:
        lines.append(f"EXPIRED waiver {w.rule} {w.resource} (expired {w.expires}): no longer applied")
    lines.append(
        f"\n{len(findings)} finding(s), {sum(f.waived for f in findings)} waived, {len(blocking)} blocking"
        + (" -> FAIL" if blocking else " -> PASS")
    )
    return "\n".join(lines)


def as_json(findings: list[Finding], expired: list[Waiver], blocking: list[Finding]) -> str:
    return json.dumps(
        {
            "passed": not blocking,
            "blocking": len(blocking),
            "findings": [
                {
                    "rule": f.rule.id,
                    "severity": f.rule.severity,
                    "resource": f.resource,
                    "type": f.resource_type,
                    "message": f.message,
                    "waived": f.waived_reason,
                }
                for f in findings
            ],
            "expired_waivers": [{"rule": w.rule, "resource": w.resource, "expired": str(w.expires)} for w in expired],
        },
        indent=2,
    )


def markdown(findings: list[Finding], expired: list[Waiver], blocking: list[Finding]) -> str:
    head = "### ❌ Terraform guardrails: blocked" if blocking else "### ✅ Terraform guardrails: passed"
    out = [head, "", f"{len(findings)} finding(s), {len(blocking)} blocking.", ""]
    if findings:
        out += ["| | Rule | Resource | Problem | Fix |", "|---|---|---|---|---|"]
        for f in findings:
            sev = f"{ICON[f.rule.severity]} {f.rule.severity}" + (" (waived)" if f.waived else "")
            out.append(f"| {sev} | `{f.rule.id}` | `{f.resource}` | {f.message} | {f.rule.remediation} |")
    for w in expired:
        out.append(f"\n> ⚠️ Waiver for `{w.rule}` on `{w.resource}` expired on {w.expires} and is no longer applied.")
    return "\n".join(out) + "\n"


def _locate(resource_address: str, source_root: Path | None) -> tuple[str, int] | None:
    """Find `resource "type" "name"` in the .tf files so code scanning can annotate the right line."""
    if source_root is None:
        return None
    parts = [p for p in resource_address.split(".") if not p.startswith("module")]
    rtype, rname = parts[-2], parts[-1].split("[")[0]
    pattern = re.compile(rf'^\s*resource\s+"{re.escape(rtype)}"\s+"{re.escape(rname)}"')
    for tf in sorted(source_root.rglob("*.tf")):
        if ".terraform" in tf.parts:
            continue
        for i, line in enumerate(tf.read_text(encoding="utf-8").splitlines(), start=1):
            if pattern.match(line):
                return tf.as_posix(), i
    return None


def sarif(findings: list[Finding], source_root: str | None = None) -> str:
    root = Path(source_root) if source_root else None
    results = []
    for f in findings:
        if f.waived:
            continue
        result = {
            "ruleId": f.rule.id,
            "level": SARIF_LEVEL[f.rule.severity],
            "message": {"text": f"{f.resource}: {f.message}. Fix: {f.rule.remediation}"},
            "partialFingerprints": {"resourceAddress": f"{f.rule.id}:{f.resource}"},
        }
        loc = _locate(f.resource, root)
        if loc:
            result["locations"] = [
                {"physicalLocation": {"artifactLocation": {"uri": loc[0]}, "region": {"startLine": loc[1]}}}
            ]
        results.append(result)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tfguard",
                        "version": __version__,
                        "informationUri": "https://github.com/Subhamsharm25/tf-guardrails",
                        "rules": [
                            {
                                "id": r.id,
                                "shortDescription": {"text": r.title},
                                "help": {"text": r.remediation},
                                "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
                                "properties": {"severity": r.severity, "cloud": r.cloud},
                            }
                            for r in RULES
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)
