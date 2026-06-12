"""Create and approve ACS false-positive and deferral exceptions."""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

from acs.common import (
    acs_image_scope_tag,
    defer_expires_on,
    defer_expiry_fields,
    format_rhsda_exception_comment,
    timestamp_utc,
)
from acs.config import Settings
from acs.http_client import AcsClient

log = logging.getLogger(__name__)


def _log_post(path: str, body: dict[str, Any]) -> None:
    log.info("POST %s\nrequest body:\n%s", path, json.dumps(body, indent=2, ensure_ascii=False))


def _log_response(label: str, resp: Any) -> None:
    if isinstance(resp, dict):
        log.info(
            "%s response:\n%s",
            label,
            json.dumps(resp, indent=2, ensure_ascii=False),
        )
    else:
        log.info("%s response: %s", label, resp)


def _exception_exists(
    existing: dict[str, Any],
    registry: str,
    remote: str,
    tag: str,
    cve: str,
    target_state: str,
) -> bool:
    for exc in existing.get("exceptions") or []:
        if exc.get("targetState") != target_state and exc.get("target_state") != target_state:
            continue
        if exc.get("status") not in ("PENDING", "APPROVED", "APPROVED_PENDING_UPDATE"):
            continue
        scope = exc.get("scope", {}).get("imageScope") or exc.get("scope", {}).get("image_scope") or {}
        if (
            scope.get("registry") == registry
            and scope.get("remote") == remote
            and scope.get("tag") == tag
            and cve in (exc.get("cves") or [])
        ):
            return True
    return False


def _pick_group_summary(
    results: list[dict[str, Any]],
    registry: str,
    remote: str,
    tag: str,
    decision: str,
    reason: str,
) -> dict[str, Any]:
    for row in results:
        if (
            row.get("decision") == decision
            and row.get("registry") == registry
            and row.get("remote") == remote
            and row.get("tag") == tag
            and row.get("reason", "") == reason
        ):
            return row.get("rhsda_summary") or {}
    return {}


def _process_group(
    settings: Settings,
    client: AcsClient,
    existing: dict[str, Any],
    results: list[dict[str, Any]],
    exception_type: str,
    target_state: str,
    registry: str,
    remote: str,
    tag: str,
    reason: str,
    cves: list[str],
    expires_on: str = "",
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    decision = "candidate_defer" if exception_type == "deferral" else "candidate_fp"
    summary = _pick_group_summary(results, registry, remote, tag, decision, reason)
    comment = format_rhsda_exception_comment(settings, summary, exception_type)
    if len(cves) > 1:
        comment = f"{comment} | CVEs={','.join(cves)}"
    approve_comment = f"{comment} (auto-approved)"

    new_cves: list[str] = []
    for cve in cves:
        if _exception_exists(
            existing, registry, remote, acs_image_scope_tag(tag), cve, target_state
        ):
            actions.append(
                {
                    "status": "skipped",
                    "reason": "existing exception",
                    "exception_type": exception_type,
                    "registry": registry,
                    "remote": remote,
                    "tag": tag,
                    "cve": cve,
                }
            )
        else:
            new_cves.append(cve)

    if not new_cves:
        return actions

    if settings.dry_run:
        scope_tag = acs_image_scope_tag(tag)
        dry_body: dict[str, Any] = {
            "cves": new_cves,
            "scope": {"imageScope": {"registry": registry, "remote": remote, "tag": scope_tag}},
            "comment": comment,
        }
        dry_path = (
            "/v2/vulnerability-exceptions/deferral"
            if exception_type == "deferral"
            else "/v2/vulnerability-exceptions/false-positive"
        )
        if exception_type == "deferral":
            dry_body.update(defer_expiry_fields(settings))
        _log_post(f"{dry_path} (dry_run)", dry_body)
        actions.append(
            {
                "status": "dry_run",
                "exception_type": exception_type,
                "registry": registry,
                "remote": remote,
                "tag": tag,
                "image_scope_tag": acs_image_scope_tag(tag),
                "check_reason": reason,
                "cves": new_cves,
                "comment": comment,
            }
        )
        return actions

    scope_tag = acs_image_scope_tag(tag)
    body: dict[str, Any] = {
        "cves": new_cves,
        "scope": {"imageScope": {"registry": registry, "remote": remote, "tag": scope_tag}},
        "comment": comment,
    }
    path = (
        "/v2/vulnerability-exceptions/deferral"
        if exception_type == "deferral"
        else "/v2/vulnerability-exceptions/false-positive"
    )
    if exception_type == "deferral":
        body.update(defer_expiry_fields(settings))

    status = "failed"
    err_msg: str | None = None
    approved_id = ""
    created: dict[str, Any] = {}

    try:
        _log_post(path, body)
        created = client.request("POST", path, body=body)
        _log_response(f"POST {path}", created)
        approved_id = (
            created.get("exception", {}).get("id")
            or created.get("id")
            or ""
        )
        if approved_id:
            approve_path = f"/v2/vulnerability-exceptions/{approved_id}/approve"
            approve_body = {"id": approved_id, "comment": approve_comment}
            _log_post(approve_path, approve_body)
            approve_resp = client.request(
                "POST",
                approve_path,
                body=approve_body,
            )
            _log_response(f"POST {approve_path}", approve_resp)
            approved_status = approve_resp.get("exception", {}).get("status") or approve_resp.get(
                "status"
            )
            if approved_status == "APPROVED":
                status = "approved"
            else:
                status = "created_pending"
                err_msg = f"approve returned status: {approved_status or 'unknown'}"
        else:
            status = "created_unknown_id"
            err_msg = "missing exception id in response"
    except Exception as exc:
        err_msg = str(exc)
        log.error("POST %s failed: %s", path, err_msg)

    action: dict[str, Any] = {
        "status": status,
        "exception_type": exception_type,
        "registry": registry,
        "remote": remote,
        "tag": tag,
        "image_scope_tag": acs_image_scope_tag(tag),
        "check_reason": reason,
        "cves": new_cves,
        "comment": comment,
        "approved_id": approved_id or None,
        "error": err_msg,
    }
    if created:
        action["response"] = created
    actions.append(action)
    return actions


def build_apply_groups(
    results: list[dict[str, Any]],
) -> dict[tuple[str, str, str, str, str], list[str]]:
    groups: dict[tuple[str, str, str, str, str], list[str]] = defaultdict(list)
    for row in results:
        decision = row.get("decision")
        if decision not in ("candidate_fp", "candidate_defer"):
            continue
        key = (
            decision,
            row.get("registry", ""),
            row.get("remote", ""),
            row.get("tag", ""),
            row.get("reason", ""),
        )
        groups[key].append(row["cve"])
    return groups


def apply_results(settings: Settings, results_path: Path, output_path: Path) -> Path:
    settings.ensure_dirs()
    settings.require_acs()
    client = AcsClient(settings)

    if settings.dry_run:
        log.warning("DRY_RUN=true: skipping ACS create/approve operations")

    data = json.loads(results_path.read_text(encoding="utf-8"))
    results: list[dict[str, Any]] = data.get("results") or []
    existing: dict[str, Any] = {"exceptions": []}
    if not settings.dry_run:
        existing = client.request(
            "GET", "/v2/vulnerability-exceptions?pagination.limit=1000"
        )

    expires_on = defer_expires_on(settings)
    groups = build_apply_groups(results)

    actions: list[dict[str, Any]] = []
    for (decision, registry, remote, tag, reason), cves in groups.items():
        unique_cves = sorted(set(cves))
        if decision == "candidate_fp":
            actions.extend(
                _process_group(
                    settings,
                    client,
                    existing,
                    results,
                    "false_positive",
                    "FALSE_POSITIVE",
                    registry,
                    remote,
                    tag,
                    reason,
                    unique_cves,
                )
            )
        else:
            actions.extend(
                _process_group(
                    settings,
                    client,
                    existing,
                    results,
                    "deferral",
                    "DEFERRED",
                    registry,
                    remote,
                    tag,
                    reason,
                    unique_cves,
                    expires_on=expires_on,
                )
            )

    report = {
        "generated_at": timestamp_utc(),
        "source_results": str(results_path),
        "dry_run": settings.dry_run,
        "defer_expires_on": expires_on,
        "actions": actions,
    }
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log.info("exception apply log -> %s", output_path)
    return output_path
