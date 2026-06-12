"""Remove pending or approved false-positive and deferral vulnerability exceptions."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from acs.common import timestamp_utc
from acs.config import Settings
from acs.http_client import AcsClient

log = logging.getLogger(__name__)

_ACTIVE_STATUSES = frozenset({"PENDING", "APPROVED", "APPROVED_PENDING_UPDATE"})
_FP_DEFER_TARGETS = frozenset({"FALSE_POSITIVE", "DEFERRED"})
_LIST_PAGE_SIZE = 500


def _exc_field(exc: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in exc and exc[key] not in (None, ""):
            return exc[key]
    return ""


def _image_scope_summary(exc: dict[str, Any]) -> str:
    scope = exc.get("scope", {}).get("imageScope") or exc.get("scope", {}).get("image_scope") or {}
    registry = scope.get("registry", "")
    remote = scope.get("remote", "")
    tag = scope.get("tag", "")
    return f"{registry}/{remote}:{tag or '<digest>'}"


def list_vulnerability_exceptions(client: AcsClient) -> list[dict[str, Any]]:
    all_exc: list[dict[str, Any]] = []
    offset = 0
    while True:
        path = (
            f"/v2/vulnerability-exceptions?pagination.limit={_LIST_PAGE_SIZE}"
            f"&pagination.offset={offset}"
        )
        page = client.request("GET", path)
        batch = page.get("exceptions") or []
        if not isinstance(batch, list):
            break
        all_exc.extend(batch)
        if len(batch) < _LIST_PAGE_SIZE:
            break
        offset += _LIST_PAGE_SIZE
    return all_exc


def should_purge_exception(exc: dict[str, Any]) -> bool:
    target = _exc_field(exc, "targetState", "target_state")
    status = _exc_field(exc, "status")
    return target in _FP_DEFER_TARGETS and status in _ACTIVE_STATUSES


def purge_action_for_status(status: str) -> str:
    if status == "APPROVED":
        return "cancel"
    return "delete"


def _purge_one(
    client: AcsClient,
    exc: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    exc_id = _exc_field(exc, "id")
    target = _exc_field(exc, "targetState", "target_state")
    status = _exc_field(exc, "status")
    action = purge_action_for_status(status)
    summary = {
        "id": exc_id,
        "target_state": target,
        "status": status,
        "action": action,
        "image_scope": _image_scope_summary(exc),
        "cves": exc.get("cves") or [],
    }
    if dry_run:
        log.info(
            "DRY_RUN: would %s exception %s (%s, %s, %d CVEs, %s)",
            action,
            exc_id,
            target,
            status,
            len(summary["cves"]),
            summary["image_scope"],
        )
        return {**summary, "result": "dry_run"}

    path = f"/v2/vulnerability-exceptions/{exc_id}"
    try:
        if action == "cancel":
            log.info("POST %s/cancel — %s %s (%s)", path, target, status, summary["image_scope"])
            resp = client.request("POST", f"{path}/cancel", body={"id": exc_id})
            log.info(
                "POST %s/cancel response:\n%s",
                path,
                json.dumps(resp, indent=2, ensure_ascii=False) if isinstance(resp, dict) else resp,
            )
        else:
            log.info("DELETE %s — %s %s (%s)", path, target, status, summary["image_scope"])
            resp = client.request("DELETE", path)
            log.info(
                "DELETE %s response:\n%s",
                path,
                json.dumps(resp, indent=2, ensure_ascii=False) if isinstance(resp, dict) else resp,
            )
        return {**summary, "result": "ok", "response": resp}
    except Exception as exc_err:
        err = str(exc_err)
        log.error("%s %s failed: %s", action.upper(), exc_id, err)
        return {**summary, "result": "failed", "error": err}


def purge_fp_defer_exceptions(settings: Settings, output_path: Path) -> Path:
    settings.ensure_dirs()
    settings.require_acs()
    client = AcsClient(settings)

    if settings.dry_run:
        log.warning("DRY_RUN=true: listing exceptions only; no cancel/delete calls")

    all_exc = list_vulnerability_exceptions(client)
    targets = [exc for exc in all_exc if should_purge_exception(exc)]
    log.info(
        "found %d false-positive/deferral exceptions to purge (of %d total)",
        len(targets),
        len(all_exc),
    )

    actions: list[dict[str, Any]] = []
    for exc in targets:
        actions.append(_purge_one(client, exc, dry_run=settings.dry_run))

    ok = sum(1 for a in actions if a.get("result") == "ok")
    failed = sum(1 for a in actions if a.get("result") == "failed")
    dry = sum(1 for a in actions if a.get("result") == "dry_run")
    report = {
        "generated_at": timestamp_utc(),
        "dry_run": settings.dry_run,
        "total_exceptions": len(all_exc),
        "purge_candidates": len(targets),
        "summary": {"ok": ok, "failed": failed, "dry_run": dry},
        "actions": actions,
    }
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log.info("purge log -> %s (ok=%d, failed=%d, dry_run=%d)", output_path, ok, failed, dry)
    return output_path
