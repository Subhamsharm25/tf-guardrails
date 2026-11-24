import pytest
from helpers import TAGS, plan, res

from tfguard.plan import load_plan
from tfguard.rules import RULES, _ports, evaluate


def ids(p: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for f in evaluate(load_plan(p)):
        out.setdefault(f.rule.id, []).append(f.resource)
    return out


def test_rule_ids_are_unique_and_documented():
    assert len({r.id for r in RULES}) == len(RULES)
    assert all(r.title and r.remediation for r in RULES)


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("22", {22}),
        ("20-25", {22}),
        ("3000-4000", {3389}),
        ("443", set()),
        ("*", None),
        (["80", "22"], {22}),
        (None, None),
    ],
)
def test_port_parsing(spec, expected):
    assert _ports(spec) == expected


def test_s3_bucket_needs_public_access_block_found_through_references():
    bucket = res("aws_s3_bucket.b", {"bucket": "b", **TAGS})
    full = {
        f: True for f in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
    }
    pab = res("aws_s3_bucket_public_access_block.b", full, {"bucket": True})
    ver = res("aws_s3_bucket_versioning.b", {"versioning_configuration": [{"status": "Enabled"}]}, {"bucket": True})
    refs = {
        "aws_s3_bucket_public_access_block.b": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"],
        "aws_s3_bucket_versioning.b": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"],
    }
    assert ids(plan(bucket, pab, ver, refs=refs)) == {}
    assert ids(plan(bucket)) == {"AWS-S3-001": ["aws_s3_bucket.b"], "AWS-S3-002": ["aws_s3_bucket.b"]}
    partial = res("aws_s3_bucket_public_access_block.b", {**full, "block_public_policy": False})
    assert "AWS-S3-001" in ids(plan(bucket, partial, ver, refs=refs))


def test_counted_buckets_follow_references_without_index():
    b0 = res("aws_s3_bucket.b[0]", {"bucket": "b0", **TAGS})
    ver = res("aws_s3_bucket_versioning.v[0]", {"versioning_configuration": [{"status": "Enabled"}]})
    p = plan(b0, ver, refs={"aws_s3_bucket_versioning.v": ["aws_s3_bucket.b"]})
    assert "AWS-S3-002" not in ids(p)


@pytest.mark.parametrize(
    "ingress,flagged",
    [
        ({"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}, True),
        ({"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]}, True),  # all traffic
        ({"from_port": 22, "to_port": 22, "protocol": "tcp", "ipv6_cidr_blocks": ["::/0"]}, True),
        ({"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"]}, False),
        ({"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}, False),
    ],
)
def test_aws_security_group_inline_ingress(ingress, flagged):
    sg = res("aws_security_group.s", {"ingress": [ingress], **TAGS})
    assert ("AWS-SG-001" in ids(plan(sg))) is flagged


def test_aws_separate_rule_resources():
    old = res(
        "aws_security_group_rule.r",
        {"type": "ingress", "from_port": 3389, "to_port": 3389, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]},
    )
    new = res("aws_vpc_security_group_ingress_rule.n", {"cidr_ipv4": "0.0.0.0/0", "ip_protocol": "-1", **TAGS})
    egress = res(
        "aws_security_group_rule.e",
        {"type": "egress", "from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]},
    )
    found = ids(plan(old, new, egress))["AWS-SG-001"]
    assert found == ["aws_security_group_rule.r", "aws_vpc_security_group_ingress_rule.n"]


def test_rds_encryption_and_exposure():
    ok = res("aws_db_instance.ok", {"storage_encrypted": True, "publicly_accessible": False, **TAGS})
    bad = res("aws_db_instance.bad", {"storage_encrypted": False, "publicly_accessible": True, **TAGS})
    assert ids(plan(ok, bad)) == {"AWS-RDS-001": ["aws_db_instance.bad"]}


def test_azure_storage_and_nsg():
    good_sa = res(
        "azurerm_storage_account.g",
        {
            "min_tls_version": "TLS1_2",
            "https_traffic_only_enabled": True,
            "allow_nested_items_to_be_public": False,
            **TAGS,
        },
    )
    bad_sa = res("azurerm_storage_account.b", {"min_tls_version": "TLS1_0", **TAGS})
    nsg = res(
        "azurerm_network_security_group.n",
        {
            **TAGS,
            "security_rule": [
                {
                    "name": "ssh",
                    "direction": "Inbound",
                    "access": "Allow",
                    "source_address_prefix": "*",
                    "destination_port_ranges": ["22", "443"],
                },
                {
                    "name": "deny",
                    "direction": "Inbound",
                    "access": "Deny",
                    "source_address_prefix": "*",
                    "destination_port_range": "3389",
                },
            ],
        },
    )
    rule = res(
        "azurerm_network_security_rule.r",
        {"direction": "Inbound", "access": "Allow", "source_address_prefix": "Internet", "destination_port_range": "*"},
    )
    found = ids(plan(good_sa, bad_sa, nsg, rule))
    assert found["AZ-ST-001"] == ["azurerm_storage_account.b"]
    assert found["AZ-NSG-001"] == ["azurerm_network_security_group.n", "azurerm_network_security_rule.r"]


def test_gcp_bucket_and_firewall():
    bucket = res(
        "google_storage_bucket.b",
        {
            "uniform_bucket_level_access": True,
            "public_access_prevention": "inherited",
            "labels": {"owner": "a", "cost-center": "b"},
        },
    )
    fw_all = res(
        "google_compute_firewall.all",
        {"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": []}]},
    )
    fw_web = res(
        "google_compute_firewall.web",
        {
            "direction": "INGRESS",
            "source_ranges": ["0.0.0.0/0"],
            "allow": [{"protocol": "tcp", "ports": ["80", "443"]}],
        },
    )
    fw_off = res(
        "google_compute_firewall.off",
        {
            "direction": "INGRESS",
            "disabled": True,
            "source_ranges": ["0.0.0.0/0"],
            "allow": [{"protocol": "tcp", "ports": ["22"]}],
        },
    )
    found = ids(plan(bucket, fw_all, fw_web, fw_off))
    assert found == {"GCP-GCS-001": ["google_storage_bucket.b"], "GCP-FW-001": ["google_compute_firewall.all"]}


def test_tags_use_merged_view_and_skip_computed():
    defaults = res("aws_s3_bucket.d", {"tags": None, "tags_all": {"Owner": "a", "cost-center": "b"}})
    computed = res("aws_iam_role.c", {"tags": None}, {"tags": True, "tags_all": True})
    fallback = res("aws_iam_role.f", {"tags": {"owner": "a"}}, {"tags_all": True})
    not_taggable = res("aws_iam_policy_attachment.x", {"roles": ["r"]})
    found = ids(plan(defaults, computed, fallback, not_taggable)).get("TAG-001")
    assert found == ["aws_iam_role.f"]


def test_deleted_and_unchanged_resources_are_ignored():
    gone = res("aws_db_instance.old", {}, actions=("delete",))
    same = res("aws_db_instance.same", {"storage_encrypted": False}, actions=("no-op",))
    assert ids(plan(gone, same)) == {}


def test_rejects_non_plan_input():
    with pytest.raises(ValueError, match="terraform show -json"):
        load_plan({"hello": "world"})
