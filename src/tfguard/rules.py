"""Guardrail rules. Each rule looks at the planned state and yields Findings.

Rule IDs are stable (they appear in waivers, SARIF and PR comments). Severity decides
whether the pipeline fails: CRITICAL and HIGH block a merge by default, MEDIUM warns.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from .plan import Plan, Resource

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
OPEN_SOURCES = {"0.0.0.0/0", "::/0", "*", "internet", "any"}


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    cloud: str
    title: str
    remediation: str
    check: Callable[[Plan], Iterator[tuple[Resource, str]]]


@dataclass(frozen=True)
class Finding:
    rule: Rule
    resource: str
    resource_type: str
    message: str
    waived_reason: str | None = None

    @property
    def waived(self) -> bool:
        return self.waived_reason is not None


RULES: list[Rule] = []


def rule(id: str, severity: str, cloud: str, title: str, remediation: str):
    def register(fn: Callable[[Plan], Iterator[tuple[Resource, str]]]):
        RULES.append(Rule(id, severity, cloud, title, remediation, fn))
        return fn

    return register


# ---------------------------------------------------------------- helpers
def _ports(spec) -> set[int] | None:
    """Port spec -> set of admin ports it exposes. None means 'all ports'."""
    if spec in (None, "", "*", "-1", -1, [], "0-65535"):
        return None
    if isinstance(spec, list):
        out: set[int] = set()
        for item in spec:
            sub = _ports(item)
            if sub is None:
                return None
            out |= sub
        return out
    text = str(spec)
    lo, _, hi = text.partition("-")
    lo_i, hi_i = int(lo), int(hi or lo)
    return {p for p in ADMIN_PORTS if lo_i <= p <= hi_i}


def _exposed(ports: set[int] | None) -> list[str]:
    if ports is None:
        return ["all ports"]
    return [f"{ADMIN_PORTS[p]} ({p})" for p in sorted(ports)]


def _is_open(sources) -> bool:
    if isinstance(sources, str):
        sources = [sources]
    return any(str(s).strip().lower() in OPEN_SOURCES for s in sources or [])


# ---------------------------------------------------------------- AWS
@rule(
    "AWS-S3-001",
    "HIGH",
    "aws",
    "S3 bucket must have a public access block with all four settings enabled",
    "Add aws_s3_bucket_public_access_block for the bucket with block_public_acls, block_public_policy, "
    "ignore_public_acls and restrict_public_buckets set to true.",
)
def _s3_public_access(plan: Plan):
    for bucket in plan.by_type("aws_s3_bucket"):
        blocks = plan.referencing(bucket, "aws_s3_bucket_public_access_block")
        flags = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
        if not blocks:
            yield bucket, "no aws_s3_bucket_public_access_block references this bucket"
        elif not any(all(b.after.get(f) is True for f in flags) for b in blocks):
            yield bucket, "public access block exists but not all four settings are true"


@rule(
    "AWS-S3-002",
    "MEDIUM",
    "aws",
    "S3 bucket should have versioning enabled",
    'Add aws_s3_bucket_versioning with status = "Enabled" (protects against overwrites and ransomware).',
)
def _s3_versioning(plan: Plan):
    for bucket in plan.by_type("aws_s3_bucket"):
        versions = plan.referencing(bucket, "aws_s3_bucket_versioning")
        enabled = any((v.after.get("versioning_configuration") or [{}])[0].get("status") == "Enabled" for v in versions)
        if not enabled:
            yield bucket, "versioning is not enabled"


@rule(
    "AWS-SG-001",
    "CRITICAL",
    "aws",
    "Security groups must not allow SSH/RDP from the whole internet",
    "Restrict the CIDR to your VPN/bastion range, or use AWS Systems Manager Session Manager instead of SSH.",
)
def _aws_sg(plan: Plan):
    for sg in plan.by_type("aws_security_group"):
        for ing in sg.after.get("ingress") or []:
            if _is_open((ing.get("cidr_blocks") or []) + (ing.get("ipv6_cidr_blocks") or [])):
                exposed = (
                    _ports(f"{ing.get('from_port')}-{ing.get('to_port')}") if ing.get("protocol") != "-1" else None
                )
                if exposed != set():
                    yield sg, f"ingress from the internet to {', '.join(_exposed(exposed))}"
    for r in plan.by_type("aws_security_group_rule"):
        if r.after.get("type") == "ingress" and _is_open(
            (r.after.get("cidr_blocks") or []) + (r.after.get("ipv6_cidr_blocks") or [])
        ):
            exposed = (
                _ports(f"{r.after.get('from_port')}-{r.after.get('to_port')}")
                if r.after.get("protocol") != "-1"
                else None
            )
            if exposed != set():
                yield r, f"ingress from the internet to {', '.join(_exposed(exposed))}"
    for r in plan.by_type("aws_vpc_security_group_ingress_rule"):
        if _is_open([r.after.get("cidr_ipv4"), r.after.get("cidr_ipv6")]):
            proto = r.after.get("ip_protocol")
            exposed = None if proto == "-1" else _ports(f"{r.after.get('from_port')}-{r.after.get('to_port')}")
            if exposed != set():
                yield r, f"ingress from the internet to {', '.join(_exposed(exposed))}"


@rule(
    "AWS-RDS-001",
    "HIGH",
    "aws",
    "RDS instances must be encrypted and not publicly accessible",
    "Set storage_encrypted = true and publicly_accessible = false; reach the database through private subnets.",
)
def _rds(plan: Plan):
    for db in plan.by_type("aws_db_instance"):
        problems = []
        if db.after.get("storage_encrypted") is not True:
            problems.append("storage is not encrypted")
        if db.after.get("publicly_accessible") is True:
            problems.append("instance is publicly accessible")
        if problems:
            yield db, "; ".join(problems)


# ---------------------------------------------------------------- Azure
@rule(
    "AZ-ST-001",
    "HIGH",
    "azure",
    "Storage accounts must enforce HTTPS, TLS 1.2 and no public blob access",
    'Set https_traffic_only_enabled = true, min_tls_version = "TLS1_2" and allow_nested_items_to_be_public = false.',
)
def _az_storage(plan: Plan):
    for sa in plan.by_type("azurerm_storage_account"):
        a = sa.after
        problems = []
        if a.get("https_traffic_only_enabled") is False:
            problems.append("HTTP allowed")
        if a.get("min_tls_version", "TLS1_2") != "TLS1_2":
            problems.append(f"min TLS {a.get('min_tls_version')}")
        if a.get("allow_nested_items_to_be_public") is not False:
            problems.append("public blob access allowed")
        if problems:
            yield sa, "; ".join(problems)


@rule(
    "AZ-NSG-001",
    "CRITICAL",
    "azure",
    "Network security groups must not allow SSH/RDP from the internet",
    "Restrict source_address_prefix to a trusted range, or use Azure Bastion.",
)
def _az_nsg(plan: Plan):
    def check(res: Resource, r: dict, label: str):
        if str(r.get("direction", "")).lower() != "inbound" or str(r.get("access", "")).lower() != "allow":
            return None
        if not _is_open([r.get("source_address_prefix")] + list(r.get("source_address_prefixes") or [])):
            return None
        spec = r.get("destination_port_ranges") or r.get("destination_port_range")
        exposed = _ports(spec)
        if exposed != set():
            return res, f"{label}allows the internet to {', '.join(_exposed(exposed))}"
        return None

    for nsg in plan.by_type("azurerm_network_security_group"):
        for r in nsg.after.get("security_rule") or []:
            hit = check(nsg, r, f"rule '{r.get('name')}' ")
            if hit:
                yield hit
    for r in plan.by_type("azurerm_network_security_rule"):
        hit = check(r, r.after, "")
        if hit:
            yield hit


# ---------------------------------------------------------------- GCP
@rule(
    "GCP-GCS-001",
    "HIGH",
    "gcp",
    "Cloud Storage buckets must use uniform access and enforce public access prevention",
    'Set uniform_bucket_level_access = true and public_access_prevention = "enforced".',
)
def _gcs(plan: Plan):
    for b in plan.by_type("google_storage_bucket"):
        problems = []
        if b.after.get("uniform_bucket_level_access") is not True:
            problems.append("uniform bucket-level access is off")
        if b.after.get("public_access_prevention") != "enforced":
            problems.append("public access prevention is not enforced")
        if problems:
            yield b, "; ".join(problems)


@rule(
    "GCP-FW-001",
    "CRITICAL",
    "gcp",
    "Firewall rules must not allow SSH/RDP from the internet",
    "Restrict source_ranges, or use Identity-Aware Proxy TCP forwarding (35.235.240.0/20) for admin access.",
)
def _gcp_fw(plan: Plan):
    for fw in plan.by_type("google_compute_firewall"):
        a = fw.after
        if str(a.get("direction", "INGRESS")).upper() != "INGRESS" or a.get("disabled"):
            continue
        if not _is_open(a.get("source_ranges")):
            continue
        for allow in a.get("allow") or []:
            proto = allow.get("protocol", "")
            if proto not in ("tcp", "all"):
                continue
            exposed = _ports(allow.get("ports") or None)
            if exposed != set():
                yield fw, f"allows the internet to {', '.join(_exposed(exposed))}"
                break


# ---------------------------------------------------------------- all clouds
REQUIRED_TAGS = ("owner", "cost-center")


@rule(
    "TAG-001",
    "MEDIUM",
    "all",
    "Taggable resources must carry owner and cost-center tags/labels",
    "Add the tags (AWS/Azure) or labels (GCP), ideally once via provider default_tags / default_labels.",
)
def _tags(plan: Plan):
    for r in plan.resources:
        keys = [k for k in ("tags_all", "tags", "effective_labels", "labels") if k in r.after or k in r.after_unknown]
        if not keys:
            continue  # not taggable
        # Prefer the merged view (tags_all / effective_labels include provider defaults). When the
        # provider reports it as "known after apply" (AWS does this when no default_tags exist),
        # fall back to the resource's own tags, which are known at plan time.
        known = [k for k in keys if r.after_unknown.get(k) is not True]
        if not known:
            continue  # everything computed at apply time; cannot judge
        key = known[0]
        values = {k.lower() for k in (r.after.get(key) or {})}
        missing = [t for t in REQUIRED_TAGS if t not in values]
        if missing:
            yield r, f"missing {', '.join(missing)}"


def evaluate(plan: Plan) -> list[Finding]:
    findings = [
        Finding(rule=r, resource=res.address, resource_type=res.type, message=msg)
        for r in RULES
        for res, msg in r.check(plan)
    ]
    order = {s: i for i, s in enumerate(SEVERITIES)}
    return sorted(findings, key=lambda f: (order[f.rule.severity], f.rule.id, f.resource))
