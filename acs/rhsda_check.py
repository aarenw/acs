"""RHSDA dual-track vulnerability matching."""

from __future__ import annotations

import csv
import json
import logging
import re
from pathlib import Path
from typing import Any

from acs.common import (
    SUMMARY_COLUMNS,
    build_rhsda_container_ids,
    component_package_matches,
    container_package_matches,
    is_go_module_component,
    normalize_rpm_package_name,
    product_entry_score,
    rpm_compare,
    derive_product_context,
    timestamp_utc,
)
from acs.config import Settings
from acs.http_client import RhsdaClient

log = logging.getLogger(__name__)


def _decision_from_fix_state(fix_state: str) -> str:
    if fix_state == "Not affected":
        return "candidate_fp"
    if fix_state in ("Fix deferred", "Will not fix"):
        return "candidate_defer"
    return "skipped"


def _split_container_ids(container_ids: str) -> list[str]:
    return [c for c in container_ids.split("|") if c]


def _find_package_state_match(
    settings: Settings,
    detail: dict[str, Any],
    track: str,
    match_key: str,
    ctx: dict[str, Any],
) -> dict[str, Any] | None:
    norm_pkg = normalize_rpm_package_name(match_key) if track == "component" else ""
    cids = _split_container_ids(match_key)
    matches: list[tuple[int, int, dict[str, Any]]] = []

    for ps in detail.get("package_state") or []:
        score = product_entry_score(
            settings, ps.get("product_name", ""), ps.get("cpe", ""), ctx
        )
        if score <= 0:
            continue
        pkg = ps.get("package_name", "")
        if track == "container":
            if not any(container_package_matches(pkg, cid) for cid in cids):
                continue
        elif not component_package_matches(pkg, match_key):
            continue
        fix_rank = 0 if ps.get("fix_state") == "Not affected" else 1
        matches.append((score, fix_rank, ps))

    if not matches:
        return None
    matches.sort(key=lambda x: (-x[0], x[1]))
    return matches[0][2]


def _find_container_affected_release(
    settings: Settings,
    detail: dict[str, Any],
    container_ids: str,
    ctx: dict[str, Any],
    image_tag: str,
) -> dict[str, Any] | None:
    if not re.fullmatch(r"[0-9]+", image_tag or ""):
        return None
    cids = _split_container_ids(container_ids)
    matches: list[tuple[int, dict[str, Any]]] = []

    for ar in detail.get("affected_release") or []:
        score = product_entry_score(
            settings, ar.get("product_name", ""), ar.get("cpe", ""), ctx
        )
        if score <= 0:
            continue
        pkg = ar.get("package", "")
        if ":" not in pkg:
            continue
        pkg_base, fix_build = pkg.split(":", 1)
        if not re.fullmatch(r"[0-9]+", fix_build):
            continue
        if not any(container_package_matches(pkg_base, cid) for cid in cids):
            continue
        if int(image_tag) < int(fix_build):
            continue
        matches.append((score, ar))

    if not matches:
        return None
    matches.sort(key=lambda x: -x[0])
    return matches[0][1]


def _find_rpm_affected_release(
    settings: Settings,
    detail: dict[str, Any],
    component: str,
    version: str,
    ctx: dict[str, Any],
) -> tuple[dict[str, Any], str] | None:
    if not version:
        return None
    norm = normalize_rpm_package_name(component)
    prefix = f"{norm}-"
    packages = sorted(
        {
            ar.get("package", "")
            for ar in detail.get("affected_release") or []
            if ar.get("package", "").startswith(prefix) and ":" not in ar.get("package", "")
            and product_entry_score(
                settings, ar.get("product_name", ""), ar.get("cpe", ""), ctx
            )
            > 0
        }
    )
    for ar_pkg in packages:
        cmp, method = rpm_compare(version, ar_pkg)
        if cmp >= 0:
            entry = next(
                ar for ar in detail.get("affected_release") or [] if ar.get("package") == ar_pkg
            )
            return entry, method
    return None


def _result(
    cve: str,
    component: str,
    version: str,
    decision: str,
    reason: str,
    match_track: str,
    summary: dict[str, Any],
    evidence: dict[str, Any],
    compare_method: str = "",
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "cve": cve,
        "component": component,
        "version": version,
        "decision": decision,
        "reason": reason,
        "match_track": match_track,
        "rhsda_summary": summary,
        "rhsda_evidence": evidence,
    }
    if compare_method:
        out["compare_method"] = compare_method
    return out


def evaluate_vuln_row(
    settings: Settings,
    client: RhsdaClient,
    row: dict[str, str],
) -> dict[str, Any]:
    cve = row.get("cve", "")
    component = row.get("component", "")
    version = row.get("version", "")
    registry = row.get("registry", "")
    remote = row.get("remote", "")
    tag = row.get("tag", "")
    product_cpe = row.get("product_cpe", "")
    label_name = row.get("label_name", "")
    container_ids = row.get("rhsda_container_ids") or build_rhsda_container_ids(remote, label_name)
    ctx = derive_product_context(settings, product_cpe, remote)

    decision = "skipped"
    reason = "no matching RHSDA data"
    match_track = ""
    summary: dict[str, Any] = {}
    evidence: dict[str, Any] = {}

    detail = client.get_cve(cve, quiet=True)
    if not detail or not isinstance(detail, dict):
        return _result(cve, component, version, decision, reason, match_track, summary, evidence)

    # Track A: container
    ps = _find_package_state_match(settings, detail, "container", container_ids, ctx)
    if ps:
        fix_state = ps.get("fix_state", "")
        decision = _decision_from_fix_state(fix_state)
        if decision != "skipped":
            match_track = "container"
            reason = f"RHSDA package_state {fix_state} (container track)"
            summary = {**ps, "cve": cve, "match_track": match_track, "match_kind": "package_state"}
            evidence = {"package_state": [ps]}
            return _result(cve, component, version, decision, reason, match_track, summary, evidence)
        if fix_state == "Affected":
            reason = "RHSDA package_state Affected for container"
            evidence = {"package_state": [ps]}
            if is_go_module_component(component):
                return _result(
                    cve, component, version, decision, reason, "container", summary, evidence
                )

    ar_container = _find_container_affected_release(settings, detail, container_ids, ctx, tag)
    if ar_container:
        match_track = "container"
        decision = "candidate_fp"
        reason = "RHSDA affected_release: container fix satisfied"
        summary = {
            **ar_container,
            "cve": cve,
            "match_track": match_track,
            "match_kind": "affected_release",
            "fix_state": "fixed",
            "package_name": ar_container.get("package"),
        }
        evidence = {"affected_release": [ar_container]}
        return _result(cve, component, version, decision, reason, match_track, summary, evidence)

    if is_go_module_component(component):
        reason = "Go module CVE: no container-level RHSDA match"
        evidence = {
            "package_state": detail.get("package_state") or [],
            "affected_release": detail.get("affected_release") or [],
        }
        return _result(cve, component, version, decision, reason, "container", summary, evidence)

    # Track B: component
    ps = _find_package_state_match(settings, detail, "component", component, ctx)
    if ps:
        fix_state = ps.get("fix_state", "")
        decision = _decision_from_fix_state(fix_state)
        if decision != "skipped":
            match_track = "component"
            reason = f"RHSDA package_state {fix_state} (component track)"
            summary = {**ps, "cve": cve, "match_track": match_track, "match_kind": "package_state"}
            evidence = {"package_state": [ps]}
            return _result(cve, component, version, decision, reason, match_track, summary, evidence)

    rpm_fix = _find_rpm_affected_release(settings, detail, component, version, ctx)
    if rpm_fix:
        ar_entry, compare_method = rpm_fix
        match_track = "component"
        decision = "candidate_fp"
        reason = "RHSDA affected_release: installed RPM version >= fix"
        summary = {
            **ar_entry,
            "cve": cve,
            "match_track": match_track,
            "match_kind": "affected_release",
            "fix_state": "fixed",
            "package_name": ar_entry.get("package"),
        }
        evidence = {"affected_release": [ar_entry]}
        return _result(
            cve,
            component,
            version,
            decision,
            reason,
            match_track,
            summary,
            evidence,
            compare_method,
        )

    reason = "no Not affected, deferral, or fix match for product context"
    evidence = {
        "package_state": detail.get("package_state") or [],
        "affected_release": detail.get("affected_release") or [],
    }
    return _result(cve, component, version, decision, reason, match_track, summary, evidence)


def check_summary(settings: Settings, summary_path: Path, output_path: Path) -> Path:
    settings.ensure_dirs()
    client = RhsdaClient(settings)
    seen: set[str] = set()
    results: list[dict[str, Any]] = []

    log.info("checking RHSDA for entries in %s", summary_path)
    with summary_path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh, delimiter="\t")
        for i, row in enumerate(reader, start=1):
            if not row.get("cve"):
                continue
            key = "|".join(
                row.get(k, "")
                for k in ("cve", "registry", "remote", "tag", "component", "version")
            )
            if key in seen:
                continue
            seen.add(key)
            result = evaluate_vuln_row(settings, client, row)
            result.update(
                {
                    k: row.get(k, "")
                    for k in (
                        "cluster",
                        "namespace",
                        "deployment",
                        "image",
                        "registry",
                        "remote",
                        "tag",
                        "severity",
                        "image_id",
                        "product_cpe",
                        "rhsda_container_ids",
                    )
                }
            )
            results.append(result)
            if i % 20 == 0:
                log.info("processed %d unique vulnerability rows...", len(seen))

    report = {
        "generated_at": timestamp_utc(),
        "source_summary": str(summary_path),
        "product_regex": settings.rhsda_product_regex,
        "results": results,
    }
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    fp = sum(1 for r in results if r["decision"] == "candidate_fp")
    defer = sum(1 for r in results if r["decision"] == "candidate_defer")
    skipped = sum(1 for r in results if r["decision"] == "skipped")
    log.info(
        "RHSDA check complete: %d false-positive, %d deferral, %d skipped -> %s",
        fp,
        defer,
        skipped,
        output_path,
    )
    return output_path
