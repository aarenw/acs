"""ACS export, JSONL parsing, and summary TSV generation."""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote

from acs.common import (
    SUMMARY_COLUMNS,
    build_rhsda_container_ids,
    parse_image_name,
    parse_ocp_version_from_cpe,
    timestamp_utc,
)
from acs.config import Settings
from acs.http_client import AcsClient

log = logging.getLogger(__name__)


def _image_tag(img: dict[str, Any]) -> str:
    name = img.get("name")
    if not isinstance(name, dict):
        return ""
    if name.get("tag"):
        return str(name["tag"])
    full = name.get("fullName", "")
    if "@" in full:
        return full.split("@", 1)[1]
    return ""


def _image_name(img: dict[str, Any]) -> str:
    name = img.get("name")
    if not isinstance(name, dict):
        return str(img.get("name") or img.get("image") or "")
    if name.get("fullName"):
        return str(name["fullName"])
    if name.get("tag"):
        return f"{name.get('registry', '')}/{name.get('remote', '')}:{name['tag']}"
    return f"{name.get('registry', '')}/{name.get('remote', '')}"


def _image_registry(img: dict[str, Any]) -> str:
    name = img.get("name")
    return str(name.get("registry", "")) if isinstance(name, dict) else ""


def _image_remote(img: dict[str, Any]) -> str:
    name = img.get("name")
    return str(name.get("remote", "")) if isinstance(name, dict) else ""


def _image_meta(img: dict[str, Any]) -> dict[str, str]:
    labels = (
        img.get("metadata", {})
        .get("v1", {})
        .get("labels", {})
    )
    if not isinstance(labels, dict):
        labels = {}
    return {
        "image_id": str(img.get("id", "")),
        "product_cpe": str(labels.get("cpe", "")),
        "ocp_version": str(labels.get("version", "")),
        "label_name": str(labels.get("name", "")),
        "redhat_component": str(labels.get("com.redhat.component", "")),
    }


def _emit_row(
    cluster: str,
    namespace: str,
    deployment: str,
    img: dict[str, Any],
    cve: str,
    severity: str,
    component: str,
    version: str,
) -> dict[str, str]:
    meta = _image_meta(img)
    return {
        "cluster": cluster,
        "namespace": namespace,
        "deployment": deployment,
        "image": _image_name(img),
        "registry": _image_registry(img),
        "remote": _image_remote(img),
        "tag": _image_tag(img),
        "cve": cve,
        "severity": str(severity),
        "component": component,
        "version": version,
        **meta,
        "rhsda_container_ids": "",
    }


def _deployment_fields(record: dict[str, Any]) -> tuple[str, str, str]:
    dep = record.get("result", {}).get("deployment", {})
    cluster = dep.get("cluster") or dep.get("clusterName") or "unknown"
    namespace = dep.get("namespace") or "unknown"
    deployment = dep.get("name") or dep.get("deploymentName") or "unknown"
    return str(cluster), str(namespace), str(deployment)


def _extract_legacy_rows(record: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    cluster, namespace, deployment = _deployment_fields(record)
    for img in record.get("result", {}).get("images", []) or []:
        for vuln in img.get("vulnerabilities", []) or []:
            cve = vuln.get("cve") or vuln.get("cveBaseInfo", {}).get("cve") or vuln.get("name") or ""
            severity = vuln.get("severity") or vuln.get("cvss") or ""
            components = vuln.get("components") or []
            if components:
                for comp in components:
                    name = comp.get("name") if isinstance(comp, dict) else str(comp)
                    ver = comp.get("version", "") if isinstance(comp, dict) else ""
                    rows.append(_emit_row(cluster, namespace, deployment, img, cve, severity, name, ver))
            else:
                rows.append(_emit_row(cluster, namespace, deployment, img, cve, severity, "", ""))
    return rows


def _extract_scan_rows(record: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    result = record.get("result", record)
    cluster = (
        result.get("deployment", {}).get("cluster")
        or result.get("deployment", {}).get("clusterName")
        or record.get("clusterName")
        or "unknown"
    )
    namespace = (
        result.get("deployment", {}).get("namespace")
        or record.get("namespace")
        or "unknown"
    )
    deployment = (
        result.get("deployment", {}).get("name")
        or result.get("deployment", {}).get("deploymentName")
        or record.get("deploymentName")
        or "unknown"
    )
    images = result.get("images")
    if images is None and "scan" in record:
        images = [record]
    elif images is None:
        images = []

    for img in images:
        scan = img.get("scan")
        if not scan:
            continue
        for vuln in scan.get("imageVulnerabilities", []) or []:
            cve = vuln.get("cve") or vuln.get("cveBaseInfo", {}).get("cve") or vuln.get("name") or ""
            severity = vuln.get("severity") or vuln.get("cvss") or ""
            comp = vuln.get("imageComponent") or vuln.get("component") or {}
            rows.append(
                _emit_row(
                    str(cluster),
                    str(namespace),
                    str(deployment),
                    img,
                    cve,
                    severity,
                    comp.get("name") or comp.get("packageName") or "",
                    comp.get("version") or "",
                )
            )
        for comp in scan.get("imageComponents") or scan.get("components") or []:
            for vuln in comp.get("vulns") or comp.get("vulnerabilities") or comp.get("imageVulnerabilities") or []:
                rows.append(
                    _emit_row(
                        str(cluster),
                        str(namespace),
                        str(deployment),
                        img,
                        vuln.get("cve") or vuln.get("name") or "",
                        vuln.get("severity") or vuln.get("cvss") or "",
                        comp.get("name") or comp.get("packageName") or "",
                        comp.get("version") or "",
                    )
                )
        for vuln in scan.get("vulnerabilities", []) or []:
            cve = vuln.get("cve") or vuln.get("name") or ""
            severity = vuln.get("severity") or vuln.get("cvss") or ""
            components = vuln.get("components") or []
            if components:
                for comp in components:
                    rows.append(
                        _emit_row(
                            str(cluster),
                            str(namespace),
                            str(deployment),
                            img,
                            cve,
                            severity,
                            comp.get("name") or "",
                            comp.get("version") or "",
                        )
                    )
            else:
                rows.append(_emit_row(str(cluster), str(namespace), str(deployment), img, cve, severity, "", ""))
    return rows


def _extract_fallback_rows(record: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    cluster, namespace, deployment = _deployment_fields(record)
    for img in record.get("result", {}).get("images", []) or []:
        for vuln in img.get("vulnerabilities", []) or []:
            comps = vuln.get("components") or [{}]
            comp = comps[0] if comps else {}
            rows.append(
                _emit_row(
                    cluster,
                    namespace,
                    deployment,
                    img,
                    vuln.get("cve") or vuln.get("name") or "",
                    vuln.get("severity") or "",
                    comp.get("name") or "",
                    comp.get("version") or "",
                )
            )
    return rows


def _collect_enrichment_candidates(jsonl_path: Path) -> list[str]:
    ids: set[str] = set()
    with jsonl_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            for img in record.get("result", {}).get("images", []) or []:
                img_id = img.get("id")
                if not img_id:
                    continue
                labels = img.get("metadata", {}).get("v1", {}).get("labels", {}) or {}
                if (
                    img.get("scan") is None
                    or not labels.get("name")
                    or not labels.get("cpe")
                ):
                    ids.add(str(img_id))
    return sorted(ids)


def _image_metadata_from_api(payload: dict[str, Any]) -> tuple[str, dict[str, str]]:
    img_id = str(payload.get("id") or payload.get("result", {}).get("id") or "")
    labels = (
        payload.get("metadata", {})
        .get("v1", {})
        .get("labels", {})
    )
    if not isinstance(labels, dict):
        labels = {}
    return img_id, {
        "product_cpe": str(labels.get("cpe", "")),
        "ocp_version": str(labels.get("version", "")),
        "label_name": str(labels.get("name", "")),
        "redhat_component": str(labels.get("com.redhat.component", "")),
    }


def _finalize_row(row: dict[str, str], meta_cache: dict[str, dict[str, str]]) -> dict[str, str]:
    if not row.get("registry") or not row.get("remote"):
        reg, rem, tag = parse_image_name(row["image"])
        row["registry"] = reg
        row["remote"] = rem
        if not row.get("tag"):
            row["tag"] = tag
    image_id = row.get("image_id", "")
    if image_id and image_id in meta_cache:
        cached = meta_cache[image_id]
        for key in ("product_cpe", "ocp_version", "label_name", "redhat_component"):
            if not row.get(key) and cached.get(key):
                row[key] = cached[key]
    if not row.get("ocp_version") and row.get("product_cpe"):
        row["ocp_version"] = parse_ocp_version_from_cpe(row["product_cpe"])
    row["rhsda_container_ids"] = build_rhsda_container_ids(
        row.get("remote", ""), row.get("label_name", "")
    )
    return row


def _read_jsonl_export(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def build_summary_tsv(settings: Settings, jsonl_path: Path, summary_path: Path) -> int:
    client = AcsClient(settings)
    rows: list[dict[str, str]] = []
    meta_cache: dict[str, dict[str, str]] = {}

    for record in _read_jsonl_export(jsonl_path):
        rows.extend(_extract_legacy_rows(record))
        rows.extend(_extract_scan_rows(record))

    if settings.acs_enrich_scans or settings.acs_enrich_labels:
        candidates = _collect_enrichment_candidates(jsonl_path)
        if len(candidates) > settings.acs_enrich_max_images:
            log.warning(
                "skipping image enrichment for %d images (limit: %d)",
                len(candidates),
                settings.acs_enrich_max_images,
            )
        else:
            log.info("enriching up to %d images from /v1/images", len(candidates))
            for img_id in candidates:
                try:
                    fetched = client.request("GET", f"/v1/images/{img_id}")
                except Exception as exc:
                    log.debug("enrich failed for %s: %s", img_id, exc)
                    continue
                mid, meta = _image_metadata_from_api(fetched if isinstance(fetched, dict) else {})
                if mid:
                    meta_cache[mid] = meta
                if settings.acs_enrich_scans and isinstance(fetched, dict):
                    rows.extend(_extract_scan_rows(fetched))

    if not rows:
        log.warning("still no rows after enrichment; trying legacy fallback parser")
        for record in _read_jsonl_export(jsonl_path):
            rows.extend(_extract_fallback_rows(record))

    unique: dict[tuple[str, ...], dict[str, str]] = {}
    for row in rows:
        if not row.get("cve"):
            continue
        key = tuple(row.get(col, "") for col in SUMMARY_COLUMNS)
        unique[key] = row

    finalized = [_finalize_row(dict(row), meta_cache) for row in unique.values()]

    with summary_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=SUMMARY_COLUMNS, delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(finalized)

    if not finalized:
        log.warning("no image CVE rows extracted from platform export")

    log.info("summary TSV rows: %d -> %s", len(finalized), summary_path)
    return len(finalized)


def export_and_summarize(settings: Settings) -> tuple[Path, Path]:
    settings.ensure_dirs()
    settings.require_acs()
    ts = timestamp_utc()
    slug = settings.cluster_slug()
    jsonl = settings.reports_dir / f"platform-vulns-{slug}-{ts}.jsonl"
    summary = settings.reports_dir / f"platform-vulns-{slug}-{ts}.summary.tsv"

    query = settings.build_export_query()
    encoded = quote(query, safe="")
    path = (
        f"/v1/export/vuln-mgmt/workloads?query={encoded}"
        f"&timeout={settings.acs_export_server_timeout}"
    )
    url = f"{settings.rox_endpoint.rstrip('/')}{path}"
    log.info("exporting platform vulnerabilities (query: %s)", query)

    from acs.http_client import http_get_text

    raw = http_get_text(
        settings,
        url,
        timeout=settings.acs_export_timeout,
        bearer_token=settings.rox_api_token,
        insecure=settings.rox_insecure_skip_tls_verify,
    )
    jsonl.write_text(raw, encoding="utf-8")
    log.info("saved raw export to %s (%d bytes)", jsonl, jsonl.stat().st_size)
    build_summary_tsv(settings, jsonl, summary)
    return jsonl, summary
