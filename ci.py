#!/usr/bin/env python3
"""Single source of truth for the pipeline (Jenkinsfile, GitHub Actions and laptops run these).

python ci.py lint        ruff lint + format check
python ci.py unit        unit tests, coverage >= 90%
python ci.py plan        terraform fmt; offline plans for the AWS+GCP examples; validate the Azure examples
python ci.py policy      run tfguard on every example and require exactly the findings in examples/expected.json;
                         check waivers (active one unblocks, expired one blocks again)
python ci.py build       container image
python ci.py scan        Trivy: fail on fixable HIGH/CRITICAL CVEs
python ci.py container   run the image against a real plan: must block and write SARIF
python ci.py all         everything above, in order
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable
EX = ROOT / "examples"
REPORTS = ROOT / "reports"
IMAGE = "tf-guardrails:local"
TRIVY = "aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb"
PLANNED = ["aws-gcp/noncompliant", "aws-gcp/compliant"]  # planned offline with real providers
FIXTURES = ["azure/noncompliant", "azure/compliant"]  # azurerm needs a login to plan: validated + fixture
ENV = {**os.environ, "TF_PLUGIN_CACHE_DIR": str(ROOT / ".terraform-cache"), "TF_IN_AUTOMATION": "1"}


def run(*cmd: str, cwd: Path = ROOT, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    print(f"\n$ {' '.join(cmd)}", flush=True)
    res = subprocess.run(cmd, cwd=cwd, env=ENV, text=True, capture_output=capture)
    if check and res.returncode != 0:
        if capture:
            print(res.stdout, res.stderr, sep="\n")
        raise SystemExit(f"command failed ({res.returncode}): {' '.join(cmd)}")
    return res


def plan_file(example: str) -> Path:
    d = EX / example
    return d / ("plan.json" if example in PLANNED else "plan.fixture.json")


# ------------------------------------------------------------------ stages
def lint() -> None:
    run(PY, "-m", "ruff", "check", "src", "tests", "ci.py")
    run(PY, "-m", "ruff", "format", "--check", "src", "tests", "ci.py")


def unit() -> None:
    run(
        PY,
        "-m",
        "pytest",
        "-q",
        "--cov=tfguard",
        "--cov-report=term-missing",
        "--cov-fail-under=90",
        "--junitxml=reports/unit.xml",
    )


def plan() -> None:
    (ROOT / ".terraform-cache").mkdir(exist_ok=True)
    run("terraform", "fmt", "-check", "-recursive", "examples")
    for ex in PLANNED + FIXTURES:
        d = EX / ex
        run("terraform", "init", "-backend=false", "-input=false", "-no-color", cwd=d)
        run("terraform", "validate", "-no-color", cwd=d)
    for ex in PLANNED:
        d = EX / ex
        run("terraform", "plan", "-input=false", "-no-color", "-refresh=false", "-lock=false", "-out=tfplan", cwd=d)
        shown = run("terraform", "show", "-json", "tfplan", cwd=d, capture=True)
        (d / "plan.json").write_text(shown.stdout, encoding="utf-8")
        print(f"wrote {d.relative_to(ROOT) / 'plan.json'} ({len(shown.stdout)} bytes)")


def _tfguard(plan_path: Path, *extra: str) -> tuple[int, dict]:
    out = REPORTS / f"{plan_path.parent.name}-{plan_path.parent.parent.name}.json"
    res = run(
        PY, "-m", "tfguard", str(plan_path), "--json", str(out), "--waivers", "none", *extra, check=False, capture=True
    )
    print(res.stdout)
    if res.returncode == 2:
        raise SystemExit(f"tfguard input error: {res.stderr}")
    return res.returncode, json.loads(out.read_text(encoding="utf-8"))


def policy() -> None:
    expected = {k: v for k, v in json.loads((EX / "expected.json").read_text()).items() if not k.startswith("_")}
    assert set(expected) == set(PLANNED + FIXTURES), "expected.json must cover every example"
    for ex, want in expected.items():
        code, report = _tfguard(plan_file(ex))
        got: dict[str, list[str]] = {}
        for f in report["findings"]:
            got.setdefault(f["rule"], []).append(f["resource"])
        got = {k: sorted(v) for k, v in got.items()}
        want = {k: sorted(v) for k, v in want.items()}
        if got != want:
            raise SystemExit(f"{ex}: findings drifted\n  expected {want}\n  got      {got}")
        should_block = ex.endswith("noncompliant")
        if (code == 1) != should_block:
            raise SystemExit(f"{ex}: exit code {code}, expected {'1 (blocked)' if should_block else '0 (pass)'}")
        print(f"policy: {ex} -> {sum(len(v) for v in got.values())} findings as expected, exit {code}")

    # Waivers: an active waiver unblocks its finding; an expired one is reported and blocks again.
    code, report = _tfguard(plan_file("azure/noncompliant"), "--waivers", str(EX / "waivers.demo.json"))
    waived = {f["rule"] for f in report["findings"] if f["waived"]}
    expired = {w["rule"] for w in report["expired_waivers"]}
    assert waived == {"AZ-ST-001"} and expired == {"AZ-NSG-001"} and code == 1, report
    print("policy: active waiver applied, expired waiver reported and still blocking")


def build() -> None:
    run("docker", "build", "-t", IMAGE, ".")


def scan() -> None:
    cache = ROOT / ".trivy-cache"
    cache.mkdir(exist_ok=True)
    run(
        "docker",
        "run",
        "--rm",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        f"{cache}:/root/.cache/trivy",
        TRIVY,
        "image",
        "--quiet",
        "--exit-code",
        "1",
        "--severity",
        "HIGH,CRITICAL",
        "--ignore-unfixed",
        "--scanners",
        "vuln",
        IMAGE,
    )


def container() -> None:
    REPORTS.mkdir(exist_ok=True)
    sarif = REPORTS / "container.sarif"
    sarif.unlink(missing_ok=True)
    res = run(
        "docker",
        "run",
        "--rm",
        "--memory",
        "256m",
        "-v",
        f"{ROOT}:/work",
        IMAGE,
        "examples/aws-gcp/noncompliant/plan.json",
        "--waivers",
        "none",
        "--sarif",
        "reports/container.sarif",
        "--source-root",
        "examples/aws-gcp/noncompliant",
        check=False,
        capture=True,
    )
    print(res.stdout)
    assert res.returncode == 1, f"container should block the noncompliant plan, exit {res.returncode}: {res.stderr}"
    results = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"]
    located = [r for r in results if r.get("locations")]
    assert len(results) == 9 and len(located) == 9, f"{len(results)} results, {len(located)} with file locations"
    print("container: blocked the plan and wrote SARIF with a file/line for every finding")


STAGES = {
    "lint": lint,
    "unit": unit,
    "plan": plan,
    "policy": policy,
    "build": build,
    "scan": scan,
    "container": container,
}


def main(argv: list[str]) -> int:
    names = list(STAGES) if argv in ([], ["all"]) else argv
    unknown = [n for n in names if n not in STAGES]
    if unknown:
        print(f"unknown stage(s) {unknown}; choose from {list(STAGES)} or all")
        return 2
    REPORTS.mkdir(exist_ok=True)
    for n in names:
        t0 = time.monotonic()
        print(f"\n===== stage: {n} =====", flush=True)
        STAGES[n]()
        print(f"===== {n} passed in {time.monotonic() - t0:.1f}s =====", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
