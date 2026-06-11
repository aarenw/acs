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
    is_ocp_major_umbrella_product,
    is_rhsda_cve_not_found,
    normalize_rpm_package_name,
    parse_container_fix_version,
    parse_ocp_version_from_cpe,
    product_entry_score,
    rpm_compare,
    derive_product_context,
    timestamp_utc,
    version_compare,
    version_gte,
    version_tuple,
)
from acs.config import Settings
from acs.http_client import RhsdaClient

log = logging.getLogger(__name__)

_INHERENT_NOT_AFFECTED_REASON = "Inherently not affected, Not Affected"
_VERSIONED_PRODUCT_MIN_SCORE = 2
_ADVERSIVE_FIX_STATES = frozenset({"Affected", "Under investigation"})
DECISION_TOBEUPGRADE = "tobeupgrade"


def _decision_from_fix_state(fix_state: str) -> str:
    if fix_state == "Not affected":
        return "candidate_fp"
    if fix_state in ("Fix deferred", "Will not fix"):
        return "candidate_defer"
    return "skipped"


def _split_container_ids(container_ids: str) -> list[str]:
    return [c for c in container_ids.split("|") if c]


def _ocp_minor_version(ocp_version: str) -> str:
    parts = version_tuple(ocp_version)
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return ocp_version


def _entry_matches_target(
    entry_kind: str,
    entry: dict[str, Any],
    *,
    container_ids: str,
    component: str,
    is_go_module: bool,
) -> bool:
    if entry_kind == "package_state":
        pkg = entry.get("package_name", "")
        if is_go_module or container_ids:
            return any(
                container_package_matches(pkg, cid)
                for cid in _split_container_ids(container_ids)
            )
        return component_package_matches(pkg, component)

    pkg = entry.get("package", "")
    if ":" in pkg:
        pkg_base = pkg.split(":", 1)[0]
        if is_go_module or container_ids:
            return any(
                container_package_matches(pkg_base, cid)
                for cid in _split_container_ids(container_ids)
            )
    if component and not is_go_module:
        norm = normalize_rpm_package_name(component)
        return pkg.startswith(f"{norm}-") and ":" not in pkg
    return False


def _has_versioned_target_match_in_section(
    settings: Settings,
    detail: dict[str, Any],
    ctx: dict[str, Any],
    section: str,
    *,
    container_ids: str,
    component: str,
    is_go_module: bool,
) -> bool:
    entry_kind = "package_state" if section == "package_state" else "affected_release"
    for entry in detail.get(section) or []:
        score = product_entry_score(
            settings,
            entry.get("product_name", ""),
            entry.get("cpe", ""),
            ctx,
            entry_kind=entry_kind,
        )
        if score < _VERSIONED_PRODUCT_MIN_SCORE:
            continue
        if _entry_matches_target(
            entry_kind,
            entry,
            container_ids=container_ids,
            component=component,
            is_go_module=is_go_module,
        ):
            return True
    return False


def _has_adverse_package_state_for_target(
    settings: Settings,
    detail: dict[str, Any],
    ctx: dict[str, Any],
    *,
    container_ids: str,
    component: str,
    ocp_version: str,
    is_go_module: bool,
) -> bool:
    row_minor = _ocp_minor_version(ocp_version or ctx.get("ocp_version") or "")
    if not row_minor:
        return False
    minor_ctx = {**ctx, "ocp_version": row_minor}
    for ps in detail.get("package_state") or []:
        score = product_entry_score(
            settings,
            ps.get("product_name", ""),
            ps.get("cpe", ""),
            minor_ctx,
            entry_kind="package_state",
        )
        if score < 3:
            continue
        if ps.get("fix_state") not in _ADVERSIVE_FIX_STATES:
            continue
        if _entry_matches_target(
            "package_state",
            ps,
            container_ids=container_ids,
            component=component,
            is_go_module=is_go_module,
        ):
            return True
    return False


def _should_mark_inherently_not_affected(
    settings: Settings,
    detail: dict[str, Any],
    ctx: dict[str, Any],
    *,
    container_ids: str,
    component: str,
    ocp_version: str,
) -> bool:
    is_go = is_go_module_component(component)
    if _has_versioned_target_match_in_section(
        settings, detail, ctx, "package_state",
        container_ids=container_ids, component=component, is_go_module=is_go,
    ):
        return False
    if _has_versioned_target_match_in_section(
        settings, detail, ctx, "affected_release",
        container_ids=container_ids, component=component, is_go_module=is_go,
    ):
        return False
    if _has_adverse_package_state_for_target(
        settings, detail, ctx,
        container_ids=container_ids, component=component, ocp_version=ocp_version, is_go_module=is_go,
    ):
        return False
    return True


def _package_state_sort_key(
    entry: dict[str, Any],
    product_score: int,
) -> tuple[int, int, int]:
    is_major = int(is_ocp_major_umbrella_product(entry.get("product_name", "")))
    fix_rank = 0 if entry.get("fix_state") == "Not affected" else 1
    return (-is_major, -product_score, fix_rank)


def _find_package_state_match(
    settings: Settings,
    detail: dict[str, Any],
    track: str,
    match_key: str,
    ctx: dict[str, Any],
) -> dict[str, Any] | None:
    cids = _split_container_ids(match_key)
    matches: list[tuple[tuple[int, int, int], dict[str, Any]]] = []

    for ps in detail.get("package_state") or []:
        score = product_entry_score(
            settings,
            ps.get("product_name", ""),
            ps.get("cpe", ""),
            ctx,
            entry_kind="package_state",
        )
        if score <= 0:
            continue
        pkg = ps.get("package_name", "")
        if track == "container":
            if not any(container_package_matches(pkg, cid) for cid in cids):
                continue
        elif not component_package_matches(pkg, match_key):
            continue
        matches.append((_package_state_sort_key(ps, score), ps))

    if not matches:
        return None
    matches.sort(key=lambda x: x[0])
    return matches[0][1]


def _container_fix_satisfied(
    fix_tag: str,
    image_tag: str,
    row_ocp: str,
    fix_ocp: str,
) -> bool:
    if row_ocp and fix_ocp and version_gte(row_ocp, fix_ocp):
        return True
    if re.fullmatch(r"[0-9]+", fix_tag) and re.fullmatch(r"[0-9]+", image_tag or ""):
        return int(image_tag) >= int(fix_tag)
    return False


def _find_container_affected_release(
    settings: Settings,
    detail: dict[str, Any],
    container_ids: str,
    ctx: dict[str, Any],
    image_tag: str,
    ocp_version: str,
) -> tuple[dict[str, Any], str] | None:
    cids = _split_container_ids(container_ids)
    row_ocp = ocp_version or ctx.get("ocp_version") or ""
    matches: list[tuple[int, tuple[int, ...], dict[str, Any], str]] = []

    for ar in detail.get("affected_release") or []:
        score = product_entry_score(
            settings,
            ar.get("product_name", ""),
            ar.get("cpe", ""),
            ctx,
            entry_kind="affected_release",
        )
        if score <= 0:
            continue
        pkg = ar.get("package", "")
        if ":" not in pkg:
            continue
        pkg_base, fix_tag = pkg.split(":", 1)
        if not any(container_package_matches(pkg_base, cid) for cid in cids):
            continue
        fix_ocp = parse_container_fix_version(
            pkg,
            ar.get("product_name", ""),
            ar.get("cpe", ""),
        )
        if not _container_fix_satisfied(fix_tag, image_tag, row_ocp, fix_ocp):
            continue
        matches.append(
            (
                score,
                tuple(int(x) for x in fix_ocp.split(".") if x.isdigit()) if fix_ocp else (0,),
                ar,
                fix_ocp or fix_tag,
            )
        )

    if not matches:
        return None
    best = max(matches, key=lambda x: (x[0], version_tuple(x[3])))
    return best[2], best[3]


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
                settings,
                ar.get("product_name", ""),
                ar.get("cpe", ""),
                ctx,
                entry_kind="affected_release",
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


def _affected_release_summary(
    ar_entry: dict[str, Any],
    *,
    cve: str,
    match_track: str,
    fixed_in_version: str,
) -> dict[str, Any]:
    return {
        **ar_entry,
        "cve": cve,
        "match_track": match_track,
        "match_kind": "affected_release",
        "fix_state": "fixed",
        "package_name": ar_entry.get("package"),
        "fixed_in_version": fixed_in_version,
    }


def _log_affected_release_match(
    cve: str,
    component: str,
    ar_entry: dict[str, Any],
    fixed_in_version: str,
    match_track: str,
) -> None:
    log.info(
        "%s %s: RHSDA affected_release match — fixed in OCP %s "
        "(product=%s, advisory=%s, package=%s, track=%s)",
        cve,
        component,
        fixed_in_version,
        ar_entry.get("product_name", "n/a"),
        ar_entry.get("advisory", "n/a"),
        ar_entry.get("package", "n/a"),
        match_track,
    )


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
    ocp_version = row.get("ocp_version", "") or parse_ocp_version_from_cpe(product_cpe)
    container_ids = row.get("rhsda_container_ids") or build_rhsda_container_ids(remote, label_name)
    ctx = derive_product_context(settings, product_cpe, remote)
    if ocp_version and not ctx.get("ocp_version"):
        ctx = {**ctx, "ocp_version": ocp_version}

    decision = "skipped"
    reason = "no matching RHSDA data"
    match_track = ""
    summary: dict[str, Any] = {}
    evidence: dict[str, Any] = {}

    detail = client.get_cve(cve, quiet=True)
    fetch_error = detail.get("_rhsda_fetch_error") if isinstance(detail, dict) else None
    if fetch_error:
        reason = f"RHSDA fetch failed: {fetch_error}"
        return _result(cve, component, version, decision, reason, match_track, summary, evidence)
    if is_rhsda_cve_not_found(detail):
        match_track = "rhsda_lookup"
        reason = "CVE not found in Red Hat Security database"
        summary = {
            "cve": cve,
            "match_track": match_track,
            "match_kind": "not_found",
            "fix_state": "not_in_rhsda",
        }
        evidence = {"rhsda_lookup": "not_found"}
        log.info(
            "%s %s: RHSDA CVE not found — marking candidate_fp (does not affect Red Hat software)",
            cve,
            component,
        )
        return _result(
            cve,
            component,
            version,
            "candidate_fp",
            reason,
            match_track,
            summary,
            evidence,
        )
    if not detail or not isinstance(detail, dict):
        log.warning("%s: RHSDA CVE detail empty or unavailable (no fetch error recorded)", cve)
        return _result(cve, component, version, decision, reason, match_track, summary, evidence)

    # Track A: container package_state (major umbrella product_name/CPE first)
    ps = _find_package_state_match(settings, detail, "container", container_ids, ctx)
    if ps:
        fix_state = ps.get("fix_state", "")
        decision = _decision_from_fix_state(fix_state)
        match_track = "container"
        summary = {**ps, "cve": cve, "match_track": match_track, "match_kind": "package_state"}
        evidence = {"package_state": [ps]}
        if decision != "skipped":
            reason = f"RHSDA package_state {fix_state} (container track)"
        else:
            reason = f"RHSDA package_state {fix_state} for container (no exception action)"
        log.info(
            "%s %s: RHSDA package_state %s — product=%s, package=%s, decision=%s",
            cve,
            component,
            fix_state,
            ps.get("product_name", "n/a"),
            ps.get("package_name", "n/a"),
            decision,
        )
        if decision != "skipped" or is_go_module_component(component):
            return _result(cve, component, version, decision, reason, match_track, summary, evidence)

    ar_container_match = _find_container_affected_release(
        settings, detail, container_ids, ctx, tag, ocp_version
    )
    if ar_container_match:
        ar_container, fixed_in_version = ar_container_match
        match_track = "container"
        decision = DECISION_TOBEUPGRADE
        reason = f"RHSDA affected_release: fixed in OCP {fixed_in_version}"
        summary = _affected_release_summary(
            ar_container,
            cve=cve,
            match_track=match_track,
            fixed_in_version=fixed_in_version,
        )
        evidence = {"affected_release": [ar_container]}
        _log_affected_release_match(cve, component, ar_container, fixed_in_version, match_track)
        return _result(cve, component, version, decision, reason, match_track, summary, evidence)

    is_go = is_go_module_component(component)
    if not is_go:
        # Track B: component package_state
        ps = _find_package_state_match(settings, detail, "component", component, ctx)
        if ps:
            fix_state = ps.get("fix_state", "")
            decision = _decision_from_fix_state(fix_state)
            if decision != "skipped":
                match_track = "component"
                reason = f"RHSDA package_state {fix_state} (component track)"
                summary = {**ps, "cve": cve, "match_track": match_track, "match_kind": "package_state"}
                evidence = {"package_state": [ps]}
                log.info(
                    "%s %s: RHSDA package_state %s — product=%s, package=%s",
                    cve,
                    component,
                    fix_state,
                    ps.get("product_name", "n/a"),
                    ps.get("package_name", "n/a"),
                )
                return _result(cve, component, version, decision, reason, match_track, summary, evidence)

        rpm_fix = _find_rpm_affected_release(settings, detail, component, version, ctx)
        if rpm_fix:
            ar_entry, compare_method = rpm_fix
            fixed_in_version = parse_container_fix_version(
                ar_entry.get("package", ""),
                ar_entry.get("product_name", ""),
                ar_entry.get("cpe", ""),
            )
            match_track = "component"
            decision = DECISION_TOBEUPGRADE
            reason = (
                f"RHSDA affected_release: installed RPM version >= fix "
                f"(fixed in OCP {fixed_in_version or 'n/a'})"
            )
            summary = _affected_release_summary(
                ar_entry,
                cve=cve,
                match_track=match_track,
                fixed_in_version=fixed_in_version or ar_entry.get("package", ""),
            )
            evidence = {"affected_release": [ar_entry]}
            _log_affected_release_match(cve, component, ar_entry, fixed_in_version, match_track)
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

    if _should_mark_inherently_not_affected(
        settings,
        detail,
        ctx,
        container_ids=container_ids,
        component=component,
        ocp_version=ocp_version,
    ):
        match_track = "product_context"
        reason = _INHERENT_NOT_AFFECTED_REASON
        row_minor = _ocp_minor_version(ocp_version or ctx.get("ocp_version") or "")
        summary = {
            "cve": cve,
            "component": component,
            "match_track": match_track,
            "match_kind": "inherent_not_affected",
            "fix_state": "Not affected",
            "cluster_ocp_version": row_minor,
        }
        evidence = {
            "package_state_version_match": False,
            "affected_release_version_match": False,
        }
        log.info("%s %s: %s (no versioned RHSDA match in package_state or affected_release)", cve, component, reason)
        return _result(
            cve,
            component,
            version,
            "candidate_fp",
            reason,
            match_track,
            summary,
            evidence,
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
    tobeupgrade = sum(1 for r in results if r["decision"] == DECISION_TOBEUPGRADE)
    skipped = sum(1 for r in results if r["decision"] == "skipped")
    log.info(
        "RHSDA check complete: %d false-positive, %d deferral, %d to-be-upgrade, %d skipped -> %s",
        fp,
        defer,
        tobeupgrade,
        skipped,
        output_path,
    )
    return output_path
