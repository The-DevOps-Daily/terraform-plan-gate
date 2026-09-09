"""Deterministic rules over a Terraform plan.

Every pass or fail decision in this tool is made here, from the plan JSON
alone. No model is consulted: the same plan always produces the same verdict,
and the rules are readable by whoever has to approve the pull request.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

Severity = str  # "block" | "warn" | "note"

BLOCK: Severity = "block"
WARN: Severity = "warn"
NOTE: Severity = "note"

#: Resource types whose deletion loses data that a re-apply does not bring back.
STATEFUL_TYPES = {
    "aws_db_instance", "aws_rds_cluster", "aws_dynamodb_table", "aws_s3_bucket",
    "aws_efs_file_system", "aws_elasticache_cluster", "aws_ebs_volume",
    "digitalocean_database_cluster", "digitalocean_volume", "digitalocean_spaces_bucket",
    "google_sql_database_instance", "google_storage_bucket", "google_compute_disk",
    "azurerm_postgresql_flexible_server", "azurerm_storage_account", "azurerm_managed_disk",
    "kubernetes_persistent_volume_claim", "kubernetes_stateful_set",
    "aws_elasticache_replication_group", "aws_redshift_cluster", "aws_docdb_cluster",
    "postgresql_database", "mysql_database", "mongodbatlas_cluster",
}

#: Attributes that decide who may reach a resource, or what it may reach.
EXPOSURE_KEYS = {
    "cidr_blocks", "ipv6_cidr_blocks", "source_ranges", "sources", "allowed_cidr_blocks",
    "publicly_accessible", "public_access", "public_network_access_enabled",
    "acl", "public_access_block", "block_public_acls", "block_public_policy",
    "ingress", "inbound_rule", "security_rule", "firewall_rules", "rule", "rules",
    "inbound_rules", "allow", "source_addresses",
    "assume_role_policy", "policy", "policy_arn", "role", "iam_role", "members", "bindings",
    "ssh_keys", "authorized_keys", "allow_ssh",
}

#: Attributes that change the identity or version of a managed service.
VERSION_KEYS = {"engine_version", "version", "node_version", "kubernetes_version", "image", "size", "instance_class", "machine_type"}

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


@dataclass
class Finding:
    rule: str
    severity: Severity
    address: str
    resource_type: str
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "address": self.address,
            "type": self.resource_type,
            "summary": self.summary,
            "detail": self.detail,
        }


def _actions(change: dict[str, Any]) -> list[str]:
    return list(change.get("change", {}).get("actions", []))


def _values(change: dict[str, Any], side: str) -> dict[str, Any]:
    value = change.get("change", {}).get(side) or {}
    return value if isinstance(value, dict) else {}


def _flatten(value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    """Every leaf in a nested plan value, keyed by a dotted path."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _flatten(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _flatten(v, f"{prefix}[{i}]")
    else:
        yield prefix, value


def _cidrs_in_access(values: dict[str, Any]) -> set[str]:
    """CIDRs under the keys that decide who may reach a resource.

    Scanning the whole resource would read a CIDR out of a tag and call it
    exposure, and would count an egress rule as an inbound one.
    """
    scoped = {k: v for k, v in values.items() if k in EXPOSURE_KEYS}
    return _cidrs_in(scoped)


def _cidrs_in(value: Any) -> set[str]:
    found: set[str] = set()
    for _, leaf in _flatten(value):
        if isinstance(leaf, str) and "/" in leaf:
            try:
                ipaddress.ip_network(leaf, strict=False)
            except ValueError:
                continue
            found.add(leaf)
    return found


def _opens_to_world(before: dict[str, Any], after: dict[str, Any]) -> set[str]:
    """World-reachable CIDRs under access keys that were not there before."""
    return (_cidrs_in_access(after) & OPEN_CIDRS) - (_cidrs_in_access(before) & OPEN_CIDRS)


def _changed_keys(before: dict[str, Any], after: dict[str, Any], keys: set[str]) -> list[str]:
    changed = []
    for key in keys:
        if key in before or key in after:
            if before.get(key) != after.get(key):
                changed.append(key)
    return sorted(changed)


#: A name heuristic for types not in the list above. It is deliberately narrow,
#: because a false "this holds data" on something like aws_route_table trains
#: people to ignore the gate. Anything it gets wrong belongs in STATEFUL_TYPES.
STATEFUL_PATTERN = re.compile(
    r"(_database|database_|_db_instance|_db_cluster|_rds_|_bucket|_volume|_disk$|_filesystem|_efs_|dynamodb_table|bigquery_table)"
)


def _is_stateful(resource_type: str) -> bool:
    return resource_type in STATEFUL_TYPES or bool(STATEFUL_PATTERN.search(resource_type))


class NotAPlan(ValueError):
    """The file is not Terraform plan JSON, so nothing was evaluated."""


def evaluate(plan: dict[str, Any]) -> list[Finding]:
    """Every finding in a plan, worst first. Pure: no I/O, no model.

    Raises NotAPlan when the document is not plan JSON, so that state files,
    an empty object or a truncated download cannot pass as a clean plan.
    """
    if not isinstance(plan, dict) or "format_version" not in plan or "resource_changes" not in plan:
        raise NotAPlan("expected Terraform plan JSON with format_version and resource_changes")
    findings: list[Finding] = []
    for change in plan.get("resource_changes", []) or []:
        actions = _actions(change)
        if actions in ([], ["no-op"], ["read"]):
            continue
        address = change.get("address", "?")
        rtype = change.get("type", "?")
        before = _values(change, "before")
        after = _values(change, "after")
        after_unknown = change.get("change", {}).get("after_unknown") or {}
        stateful = _is_stateful(rtype)
        deleting = "delete" in actions
        replacing = deleting and "create" in actions
        # A resource that did not exist before has nothing to compare against,
        # so its attributes are not "changes". Exposure is still checked
        # against an empty baseline: a new rule open to the world is the same
        # hole as an old one widened to it.
        creating_only = set(actions) == {"create"}
        baseline: dict[str, Any] = {} if creating_only else before

        if deleting and stateful:
            findings.append(Finding(
                "stateful-destroy", BLOCK, address, rtype,
                "replaces a stateful resource, which loses its data" if replacing
                else "destroys a stateful resource, which loses its data",
                {"actions": actions, "reasons": change.get("change", {}).get("replace_paths", [])},
            ))
        elif replacing:
            findings.append(Finding(
                "replace", WARN, address, rtype,
                "is replaced, so it is destroyed and recreated",
                {"actions": actions, "reasons": change.get("change", {}).get("replace_paths", [])},
            ))
        elif deleting:
            findings.append(Finding("destroy", WARN, address, rtype, "is destroyed", {"actions": actions}))

        opened = _opens_to_world(baseline, after)
        # An ACL that names the public is an exposure change, not a spelling one.
        acl_before, acl_after = str(before.get("acl", "")), str(after.get("acl", ""))
        # private -> public-read and public-read -> public-read-write are both
        # widenings; only a move away from public is not.
        acl_before = "" if creating_only else acl_before
        public_acl = acl_after.startswith("public") and acl_after != acl_before
        if opened:
            findings.append(Finding(
                "opens-to-the-internet", BLOCK, address, rtype,
                f"becomes reachable from {', '.join(sorted(opened))}",
                {"cidrs": sorted(opened)},
            ))

        if public_acl:
            findings.append(Finding(
                "public-acl", BLOCK, address, rtype,
                f"changes its ACL from {acl_before or 'unset'} to {acl_after}, which anyone can read",
                {"before": acl_before, "after": acl_after},
            ))

        exposure = _changed_keys(baseline, after, EXPOSURE_KEYS) if not creating_only else (
            ["publicly_accessible"] if after.get("publicly_accessible") is True else []
        )
        if exposure and not opened and not public_acl:
            severity = BLOCK if {"publicly_accessible", "public_access", "public_network_access_enabled"} & set(exposure) and any(
                after.get(k) is True for k in exposure
            ) else WARN
            findings.append(Finding(
                "access-change", severity, address, rtype,
                "changes who can reach it or what it may do: " + ", ".join(exposure),
                {"keys": exposure, "before": {k: before.get(k) for k in exposure}, "after": {k: after.get(k) for k in exposure}},
            ))

        version = [] if creating_only else _changed_keys(before, after, VERSION_KEYS)
        if version and not deleting:
            findings.append(Finding(
                "version-or-size-change", NOTE if not stateful else WARN, address, rtype,
                "changes " + ", ".join(version),
                {"keys": version, "before": {k: before.get(k) for k in version}, "after": {k: after.get(k) for k in version}},
            ))

    order = {BLOCK: 0, WARN: 1, NOTE: 2}
    findings.sort(key=lambda f: (order[f.severity], f.address, f.rule))
    return findings


def verdict(findings: list[Finding], fail_on: Severity = BLOCK) -> tuple[bool, dict[str, int]]:
    """Whether the plan passes, and the count per severity."""
    counts = {BLOCK: 0, WARN: 0, NOTE: 0}
    for f in findings:
        counts[f.severity] += 1
    threshold = {BLOCK: [BLOCK], WARN: [BLOCK, WARN], NOTE: [BLOCK, WARN, NOTE]}[fail_on]
    passed = not any(counts[s] for s in threshold)
    return passed, counts
