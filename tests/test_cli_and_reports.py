import datetime as dt
import json

import pytest
from helpers import plan, res

from tfguard.__main__ import main
from tfguard.plan import load_plan
from tfguard.rules import evaluate
from tfguard.waivers import Waiver, apply_waivers, load_waivers

BAD = plan(
    res("aws_db_instance.db", {"storage_encrypted": False, "tags": {"owner": "a", "cost-center": "b"}}),
    res("aws_iam_role.r", {"tags": {}}),
)


@pytest.fixture
def bad_plan(tmp_path):
    p = tmp_path / "plan.json"
    p.write_text(json.dumps(BAD))
    return p


def test_exit_codes_and_threshold(bad_plan, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main([str(bad_plan)]) == 1  # HIGH RDS finding blocks
    assert main([str(bad_plan), "--fail-on", "CRITICAL"]) == 0
    assert main([str(tmp_path / "missing.json")]) == 2


def test_waivers_unblock_until_they_expire(bad_plan, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    waivers = tmp_path / "w.json"
    waivers.write_text(
        json.dumps(
            [
                {
                    "rule": "AWS-RDS-001",
                    "resource": "aws_db_instance.*",
                    "reason": "JIRA-1 migration",
                    "expires": "2099-01-01",
                }
            ]
        )
    )
    assert main([str(bad_plan), "--waivers", str(waivers)]) == 0
    assert "WAIVED" in capsys.readouterr().out
    waivers.write_text(
        json.dumps(
            [{"rule": "AWS-RDS-001", "resource": "aws_db_instance.db", "reason": "old", "expires": "2020-01-01"}]
        )
    )
    assert main([str(bad_plan), "--waivers", str(waivers)]) == 1
    assert "EXPIRED waiver" in capsys.readouterr().out


def test_waiver_validation(tmp_path):
    w = tmp_path / "w.json"
    w.write_text(json.dumps([{"rule": "X", "resource": "y"}]))
    with pytest.raises(ValueError, match="reason, expires"):
        load_waivers(w)
    assert load_waivers(tmp_path / "none.json") == []


def test_apply_waivers_matches_exactly_or_by_prefix():
    findings = evaluate(load_plan(BAD))
    out, expired = apply_waivers(
        findings,
        [
            Waiver("TAG-001", "aws_iam_role.r", "ok", dt.date(2030, 1, 1)),
            Waiver("AWS-RDS-001", "aws_db_instance.other", "no match", dt.date(2030, 1, 1)),
        ],
        today=dt.date(2026, 1, 1),
    )
    assert [f.waived for f in out] == [False, True] and expired == []


def test_sarif_markdown_json_outputs(bad_plan, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "main.tf").write_text('resource "aws_db_instance" "db" {\n}\n')
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    main([str(bad_plan), "--sarif", "out.sarif", "--markdown", "pr.md", "--json", "out.json", "--source-root", "."])
    sarif = json.loads((tmp_path / "out.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert {r["ruleId"] for r in results} == {"AWS-RDS-001", "TAG-001"}
    db = next(r for r in results if r["ruleId"] == "AWS-RDS-001")
    assert db["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert db["level"] == "error"
    report = json.loads((tmp_path / "out.json").read_text())
    assert report["passed"] is False and report["blocking"] == 1
    md = (tmp_path / "pr.md").read_text(encoding="utf-8")
    assert "blocked" in md and "AWS-RDS-001" in md
    assert summary.read_text(encoding="utf-8") == md


def test_unwritable_report_is_an_error_not_a_verdict(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    good = tmp_path / "good.json"
    good.write_text(json.dumps(plan()))
    # The target is a directory, so writing fails: exit 2, even though the plan itself passes.
    assert main([str(good), "--sarif", str(tmp_path)]) == 2


def test_list_rules(capsys):
    assert main(["--list-rules"]) == 0
    assert "AWS-S3-001" in capsys.readouterr().out
