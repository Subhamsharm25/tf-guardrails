"""Load a Terraform plan (`terraform show -json tfplan`) into simple Resource objects.

Besides each planned resource's attribute values, the loader records which resources
reference which. Many controls are expressed as a separate resource that points at the
one it protects (aws_s3_bucket_public_access_block -> aws_s3_bucket), and in a plan the
pointer is usually still "(known after apply)". The `configuration` section of the plan
keeps the static references, so rules can follow them anyway.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROVIDERS = {"aws": "aws", "azurerm": "azure", "google": "gcp"}


@dataclass
class Resource:
    address: str
    type: str
    name: str
    actions: tuple[str, ...]
    after: dict[str, Any]
    after_unknown: dict[str, Any] = field(default_factory=dict)
    referenced_by: set[str] = field(default_factory=set)

    @property
    def cloud(self) -> str:
        return PROVIDERS.get(self.type.split("_", 1)[0], "other")

    def known(self, key: str) -> bool:
        return key in self.after and not self.after_unknown.get(key)


@dataclass
class Plan:
    resources: list[Resource]
    terraform_version: str = ""

    def by_type(self, *types: str) -> list[Resource]:
        return [r for r in self.resources if r.type in types]

    def referencing(self, target: Resource, *types: str) -> list[Resource]:
        """Resources of the given types whose configuration references `target`."""
        return [r for r in self.resources if r.address in target.referenced_by and (not types or r.type in types)]


def _collect_refs(expressions: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(expressions, dict):
        for key, value in expressions.items():
            if key == "references" and isinstance(value, list):
                refs.update(v for v in value if isinstance(v, str))
            else:
                refs |= _collect_refs(value)
    elif isinstance(expressions, list):
        for item in expressions:
            refs |= _collect_refs(item)
    return refs


def _walk_config(module: dict[str, Any], prefix: str, edges: list[tuple[str, str]]) -> None:
    for res in module.get("resources", []):
        source = prefix + res["address"]
        for ref in _collect_refs(res.get("expressions", {})):
            parts = ref.split(".")
            if len(parts) >= 2 and not ref.startswith(("var.", "local.", "module.", "data.", "each.", "count.")):
                edges.append((source, prefix + ".".join(parts[:2])))
    for name, call in module.get("module_calls", {}).items():
        _walk_config(call.get("module", {}), f"{prefix}module.{name}.", edges)


def _strip_index(address: str) -> str:
    """aws_s3_bucket.logs[0] -> aws_s3_bucket.logs (references in configuration have no index)."""
    return address.split("[", 1)[0] if "[" in address.rsplit(".", 1)[-1] else address


def load_plan(data: dict[str, Any]) -> Plan:
    if "resource_changes" not in data and "planned_values" not in data:
        raise ValueError("not a Terraform JSON plan (run: terraform show -json tfplan > plan.json)")
    resources: list[Resource] = []
    for rc in data.get("resource_changes", []):
        if rc.get("mode", "managed") != "managed":
            continue
        change = rc.get("change", {})
        actions = tuple(change.get("actions", []))
        if actions in (("delete",), ("no-op",), ("read",)):
            continue  # only evaluate what will exist after apply and is being changed
        resources.append(
            Resource(
                address=rc["address"],
                type=rc["type"],
                name=rc.get("name", ""),
                actions=actions,
                after=change.get("after") or {},
                after_unknown=change.get("after_unknown") or {},
            )
        )
    edges: list[tuple[str, str]] = []
    _walk_config(data.get("configuration", {}).get("root_module", {}), "", edges)
    by_base: dict[str, list[Resource]] = {}
    for r in resources:
        by_base.setdefault(_strip_index(r.address), []).append(r)
    for source, target in edges:
        for r in by_base.get(target, []):
            r.referenced_by.add(source)
    # referenced_by holds config addresses; map them to planned instance addresses too
    for r in resources:
        expanded = set()
        for src in r.referenced_by:
            expanded |= {x.address for x in by_base.get(src, [])}
        r.referenced_by |= expanded
    return Plan(resources=resources, terraform_version=data.get("terraform_version", ""))


def read_plan(path: str | Path) -> Plan:
    return load_plan(json.loads(Path(path).read_text(encoding="utf-8")))
