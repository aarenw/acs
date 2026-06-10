"""Shared helpers: image parsing, RHSDA container IDs, product context, comments."""

from __future__ import annotations

import re
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Any

from acs.config import Settings

GO_MODULE_RE = re.compile(
    r"^(golang\.org/|github\.com/|google\.golang\.org/|stdlib$|stdlib/)"
)
OCP_VERSION_RE = re.compile(r"openshift:([0-9]+\.[0-9]+)")
OCP_MAJOR_RE = re.compile(r"openshift:([0-9]+)(?:::|:|$)")
RPM_BASE_RE = re.compile(r"^([a-zA-Z0-9_.+-]+)-[0-9]")
ARCH_SUFFIXES = (".src", ".x86_64", ".aarch64", ".noarch", ".i686", ".ppc64le", ".s390x")

SUMMARY_COLUMNS = [
    "cluster",
    "namespace",
    "deployment",
    "image",
    "registry",
    "remote",
    "tag",
    "cve",
    "severity",
    "component",
    "version",
    "image_id",
    "product_cpe",
    "ocp_version",
    "label_name",
    "redhat_component",
    "rhsda_container_ids",
]


def timestamp_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def parse_image_name(image_ref: str) -> tuple[str, str, str]:
    if "@" in image_ref:
        tag = image_ref.rsplit("@", 1)[1]
        rest = image_ref.rsplit("@", 1)[0]
    elif ":" in image_ref:
        tag = image_ref.rsplit(":", 1)[1]
        rest = image_ref.rsplit(":", 1)[0]
    else:
        tag = "latest"
        rest = image_ref

    if "/" in rest:
        registry, remote = rest.split("/", 1)
    else:
        registry, remote = "docker.io", rest

    if (
        "." not in registry
        and ":" not in registry
        and registry != "localhost"
    ):
        remote = f"{registry}/{remote}"
        registry = "docker.io"

    return registry, remote, tag


def normalize_rpm_package_name(name: str) -> str:
    for suffix in ARCH_SUFFIXES:
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    if re.match(r"^[0-9]+:", name):
        name = name.split(":", 1)[1]
    m = RPM_BASE_RE.match(name)
    return m.group(1) if m else name


def is_go_module_component(component: str) -> bool:
    return bool(GO_MODULE_RE.match(component))


def label_name_to_rhsda_container(label_name: str) -> str:
    if not label_name:
        return ""
    if label_name.startswith("openshift/"):
        return f"openshift4/{label_name[len('openshift/'):]}"
    return label_name


def build_rhsda_container_ids(remote: str, label_name: str) -> str:
    ids: list[str] = []
    seen: set[str] = set()
    for candidate in (remote, label_name_to_rhsda_container(label_name)):
        key = candidate.lower()
        if candidate and key not in seen:
            seen.add(key)
            ids.append(candidate)
    return "|".join(ids)


def container_package_matches(rhsda_pkg: str, candidate: str) -> bool:
    if not rhsda_pkg or not candidate:
        return False
    a, b = rhsda_pkg.lower(), candidate.lower()
    pairs = (
        (a, b),
        (a, f"{b}-operator"),
        (b, f"{a}-operator"),
        (a, f"{b}-rhel8"),
        (b, f"{a}-rhel8"),
        (a, f"{b}-rhel9"),
        (b, f"{a}-rhel9"),
        (a, f"{b}-rhel8-operator"),
        (b, f"{a}-rhel8-operator"),
        (a, f"{b}-rhel9-operator"),
        (b, f"{a}-rhel9-operator"),
    )
    return any(x == y for x, y in pairs)


def parse_ocp_version_from_cpe(cpe: str) -> str:
    m = OCP_VERSION_RE.search(cpe)
    if m:
        return m.group(1)
    m = OCP_MAJOR_RE.search(cpe)
    return m.group(1) if m else ""


def derive_product_context(settings: Settings, product_cpe: str, remote: str) -> dict[str, Any]:
    ocp_version = parse_ocp_version_from_cpe(product_cpe) if product_cpe else ""
    specific_regex = ""
    broad_regex = ""
    if ocp_version:
        specific_regex = f"OpenShift Container Platform {re.escape(ocp_version)}"
        minor = ocp_version.split(".", 1)[1] if "." in ocp_version else ocp_version
        broad_regex = (
            rf"OpenShift Container Platform 4(\.{re.escape(minor)})?"
            r"|OpenShift Container Platform 4[^0-9]|OpenShift Container Platform 4$"
        )
    elif remote.startswith("openshift4/"):
        broad_regex = r"OpenShift Container Platform 4|OpenShift"
    return {
        "env_regex": settings.rhsda_product_regex,
        "specific_regex": specific_regex or None,
        "broad_regex": broad_regex or None,
        "ocp_version": ocp_version or None,
        "product_cpe": product_cpe or None,
    }


def product_entry_score(
    settings: Settings, product_name: str, entry_cpe: str, ctx: dict[str, Any]
) -> int:
    score = 0
    if settings.product_regex.search(product_name):
        score = 1
    specific = ctx.get("specific_regex")
    broad = ctx.get("broad_regex")
    row_cpe = ctx.get("product_cpe") or ""
    if specific and re.search(specific, product_name):
        score = 3
    elif broad and re.search(broad, product_name):
        score = 2
    elif score == 0 and row_cpe and entry_cpe:
        if entry_cpe.startswith(row_cpe) or row_cpe.startswith(entry_cpe):
            score = 1
    return score


def component_package_matches(rhsda_pkg: str, component: str) -> bool:
    norm = normalize_rpm_package_name(component)
    return rhsda_pkg == norm or rhsda_pkg == component or rhsda_pkg.lower() == norm.lower()


def format_rhsda_exception_comment(
    settings: Settings, summary: dict[str, Any], exception_type: str
) -> str:
    prefix = settings.exception_comment_prefix
    if not summary:
        return f"{prefix}: auto platform-fp-check ({exception_type})"
    if exception_type == "deferral":
        return (
            f"{prefix} fix_state {summary.get('fix_state', 'unknown')} | "
            f"product={summary.get('product_name', 'n/a')} | "
            f"package={summary.get('package_name', 'n/a')} | "
            f"match_track={summary.get('match_track', 'n/a')} | "
            f"CVE={summary.get('cve', 'n/a')}"
        )
    if summary.get("match_kind") == "affected_release":
        return (
            f"{prefix}: affected_release fixed | "
            f"product={summary.get('product_name', 'n/a')} | "
            f"package={summary.get('package_name', 'n/a')} | "
            f"match_track={summary.get('match_track', 'n/a')} | "
            f"CVE={summary.get('cve', 'n/a')}"
        )
    return (
        f"{prefix}: package_state {summary.get('fix_state', 'Not affected')} | "
        f"product={summary.get('product_name', 'n/a')} | "
        f"package={summary.get('package_name', 'n/a')} | "
        f"match_track={summary.get('match_track', 'n/a')} | "
        f"CVE={summary.get('cve', 'n/a')}"
    )


def defer_expires_on(settings: Settings) -> str:
    dt = datetime.now(timezone.utc) + timedelta(days=settings.defer_expiry_days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def rpm_parse_evr(pkg: str) -> tuple[str, str, str]:
    epoch = "0"
    rest = pkg
    if re.match(r"^[0-9]+:", rest):
        epoch, rest = rest.split(":", 1)
    if "-" in rest:
        ver, rel = rest.rsplit("-", 1)
    else:
        ver, rel = rest, ""
    return epoch, ver, rel


def rpm_compare(a: str, b: str) -> tuple[int, str]:
    ae, av, ar = rpm_parse_evr(a)
    be, bv, br = rpm_parse_evr(b)
    try:
        result = subprocess.run(
            [
                "rpm",
                "--eval",
                f"%{{lua: print(rpm.vercmp('{ae}:{av}-{ar}', '{be}:{bv}-{br}'))}}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0 and re.match(r"^-?[0-9]+$", result.stdout.strip()):
            return int(result.stdout.strip()), "rpm_compare"
    except FileNotFoundError:
        pass
    left = f"{ae}:{av}-{ar}"
    right = f"{be}:{bv}-{br}"
    if left == right:
        return 0, "string_fallback"
    return (0 if left >= right else -1), "string_fallback"
