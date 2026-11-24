"""Time-boxed exceptions.

Real teams need exceptions ("the legacy bucket is public until the CDN migration"), but a
permanent exception is how guardrails rot. Every waiver needs a reason and an expiry date;
an expired waiver stops applying and is reported, so the finding blocks the pipeline again.

tfguard-waivers.json:
[
  {"rule": "TAG-001", "resource": "aws_s3_bucket.legacy", "reason": "JIRA-123 migration", "expires": "2027-01-31"}
]
"resource" may end with "*" to match a prefix (e.g. "module.legacy.*").
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, replace
from pathlib import Path

from .rules import Finding


@dataclass(frozen=True)
class Waiver:
    rule: str
    resource: str
    reason: str
    expires: dt.date

    def matches(self, f: Finding) -> bool:
        if self.rule != f.rule.id:
            return False
        if self.resource.endswith("*"):
            return f.resource.startswith(self.resource[:-1])
        return f.resource == self.resource


def load_waivers(path: str | Path | None) -> list[Waiver]:
    if not path or not Path(path).exists():
        return []
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for i, w in enumerate(raw):
        missing = [k for k in ("rule", "resource", "reason", "expires") if not w.get(k)]
        if missing:
            raise ValueError(f"waiver #{i + 1} is missing {', '.join(missing)}")
        out.append(Waiver(w["rule"], w["resource"], w["reason"], dt.date.fromisoformat(w["expires"])))
    return out


def apply_waivers(
    findings: list[Finding], waivers: list[Waiver], today: dt.date | None = None
) -> tuple[list[Finding], list[Waiver]]:
    """Returns (findings with waived_reason set where an active waiver matches, expired waivers)."""
    today = today or dt.date.today()
    active = [w for w in waivers if w.expires >= today]
    expired = [w for w in waivers if w.expires < today]
    out = []
    for f in findings:
        w = next((w for w in active if w.matches(f)), None)
        out.append(replace(f, waived_reason=f"{w.reason} (until {w.expires})") if w else f)
    return out, expired
