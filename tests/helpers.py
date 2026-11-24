"""Build minimal Terraform JSON plans for rule tests."""

from __future__ import annotations

from typing import Any


def res(address: str, after: dict[str, Any], unknown: dict[str, Any] | None = None, actions=("create",)) -> dict:
    rtype, name = address.split(".")[-2], address.split(".")[-1]
    return {
        "address": address,
        "mode": "managed",
        "type": rtype,
        "name": name,
        "change": {"actions": list(actions), "after": after, "after_unknown": unknown or {}},
    }


def plan(*resources: dict, refs: dict[str, list[str]] | None = None) -> dict:
    """refs: {source_address: [referenced addresses]} -> configuration section."""
    config = [{"address": a, "expressions": {"bucket": {"references": targets}}} for a, targets in (refs or {}).items()]
    return {
        "format_version": "1.2",
        "resource_changes": list(resources),
        "configuration": {"root_module": {"resources": config}},
    }


TAGS = {"tags": {"owner": "x", "cost-center": "y"}}
