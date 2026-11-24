"""tfguard: policy gate for Terraform plans on AWS, Azure and GCP.

    terraform plan -out tfplan && terraform show -json tfplan > plan.json
    python -m tfguard plan.json [--waivers tfguard-waivers.json] [--fail-on HIGH]
                                [--sarif out.sarif] [--markdown summary.md] [--json out.json]

Exit codes: 0 passed, 1 blocking findings, 2 usage or input error.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .plan import read_plan
from .report import as_json, markdown, sarif, text
from .rules import RULES, SEVERITIES, evaluate
from .waivers import apply_waivers, load_waivers


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tfguard", description="Policy gate for Terraform plans (AWS, Azure, GCP)")
    p.add_argument("plans", nargs="*", help="plan JSON files from `terraform show -json`")
    p.add_argument("--waivers", default="tfguard-waivers.json")
    p.add_argument("--fail-on", default="HIGH", choices=SEVERITIES, help="lowest severity that fails the run")
    p.add_argument("--sarif")
    p.add_argument("--markdown", help="write a Markdown summary (also appended to $GITHUB_STEP_SUMMARY if set)")
    p.add_argument("--json", dest="json_out")
    p.add_argument("--source-root", default=".", help="where the .tf files live, for SARIF line numbers")
    p.add_argument("--list-rules", action="store_true")
    args = p.parse_args(argv)

    if args.list_rules:
        for r in RULES:
            print(f"{r.id:<12} {r.severity:<8} {r.cloud:<6} {r.title}")
        return 0
    if not args.plans:
        p.error("at least one plan file is required")

    try:
        findings = [f for path in args.plans for f in evaluate(read_plan(path))]
        findings, expired = apply_waivers(findings, load_waivers(args.waivers))
    except (OSError, ValueError) as exc:
        print(f"tfguard: {exc}", file=sys.stderr)
        return 2

    threshold = SEVERITIES.index(args.fail_on)
    blocking = [f for f in findings if not f.waived and SEVERITIES.index(f.rule.severity) <= threshold]

    print(text(findings, expired, blocking))
    md = markdown(findings, expired, blocking)
    try:
        if args.sarif:
            Path(args.sarif).write_text(sarif(findings, args.source_root), encoding="utf-8")
        if args.json_out:
            Path(args.json_out).write_text(as_json(findings, expired, blocking), encoding="utf-8")
        if args.markdown:
            Path(args.markdown).write_text(md, encoding="utf-8")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
                fh.write(md)
    except OSError as exc:
        # Never let an I/O failure look like a policy verdict (exit 1 means "blocked").
        print(f"tfguard: could not write report: {exc}", file=sys.stderr)
        return 2
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
