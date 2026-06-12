"""Shared helpers: image parsing, RHSDA container IDs, product context, comments."""

from __future__ import annotations

import calendar
import re
import subprocess
from datetime import datetime, timezone
from typing import Any

from acs.config import Settings

GO_MODULE_RE = re.compile(
    r"^(golang\.org/|github\.com/|google\.golang\.org/|stdlib$|stdlib/)"
)
OCP_VERSION_RE = re.compile(r"openshift:([0-9]+\.[0-9]+)")
OCP_MAJOR_RE = re.compile(r"openshift:([0-9]+)(?:::|:|$)")
OCP_PRODUCT_MINOR_RE = re.compile(r"OpenShift Container Platform (4\.\d+)")
CONTAINER_FIX_VERSION_RE = re.compile(r"v?(4\.\d+\.\d+)")
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


def acs_image_scope_tag(tag: str) -> str:
    """Return the tag field for ACS v2 imageScope.

    ACS does not accept digest strings (``sha256:...``) as imageScope.tag.
    Export/summary may store the digest in ``tag`` for grouping; API calls
    must send an empty tag for digest-pinned images.
    """
    if tag.startswith("sha256"):
        return ""
    return tag


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


def is_ocp_major_umbrella_product(product_name: str) -> bool:
    if OCP_PRODUCT_MINOR_RE.search(product_name):
        return False
    return "OpenShift Container Platform 4" in product_name


def parse_openshift_version_from_product(product_name: str) -> str:
    m = OCP_PRODUCT_MINOR_RE.search(product_name)
    if m:
        return m.group(1)
    if is_ocp_major_umbrella_product(product_name):
        return "4"
    return ""


def version_tuple(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in version.split("."):
        if piece.isdigit():
            parts.append(int(piece))
    return tuple(parts) if parts else (0,)


def version_compare(left: str, right: str) -> int:
    a = version_tuple(left)
    b = version_tuple(right)
    width = max(len(a), len(b))
    a = a + (0,) * (width - len(a))
    b = b + (0,) * (width - len(b))
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def version_gte(left: str, right: str) -> bool:
    return version_compare(left, right) >= 0


def version_lte(left: str, right: str) -> bool:
    return version_compare(left, right) <= 0


def cpe_product_score(
    row_cpe: str,
    entry_cpe: str,
    *,
    allow_minor_compat: bool = False,
) -> int:
    """Score RHSDA entry CPE against the workload product CPE.

    package_state often uses the major umbrella ``openshift:4`` while
    affected_release uses minor streams like ``openshift:4.19::el9``.
    """
    if not row_cpe or not entry_cpe:
        return 0
    row_v = parse_ocp_version_from_cpe(row_cpe)
    entry_v = parse_ocp_version_from_cpe(entry_cpe)
    if row_v and entry_v:
        if row_v == entry_v:
            return 3
        if entry_v == "4" and row_v.startswith("4."):
            return 2
        if (
            allow_minor_compat
            and row_v.startswith("4.")
            and entry_v.startswith("4.")
            and version_lte(entry_v, row_v)
        ):
            return 2
    if row_cpe.startswith(entry_cpe) or entry_cpe.startswith(row_cpe):
        return 1
    return 0


def parse_container_fix_version(
    package: str,
    product_name: str = "",
    entry_cpe: str = "",
) -> str:
    if ":" in package:
        tag = package.split(":", 1)[1]
        m = CONTAINER_FIX_VERSION_RE.search(tag)
        if m:
            major, minor, *_rest = m.group(1).split(".")
            return f"{major}.{minor}"
    return parse_openshift_version_from_product(product_name) or parse_ocp_version_from_cpe(
        entry_cpe
    )


def derive_product_context(settings: Settings, product_cpe: str, remote: str) -> dict[str, Any]:
    ocp_version = parse_ocp_version_from_cpe(product_cpe) if product_cpe else ""
    return {
        "env_regex": settings.rhsda_product_regex,
        "ocp_version": ocp_version or None,
        "product_cpe": product_cpe or None,
    }


def product_entry_score(
    settings: Settings,
    product_name: str,
    entry_cpe: str,
    ctx: dict[str, Any],
    *,
    entry_kind: str = "package_state",
) -> int:
    row_cpe = ctx.get("product_cpe") or ""
    row_ocp = ctx.get("ocp_version") or ""
    allow_minor_compat = entry_kind == "affected_release"
    entry_ocp = parse_openshift_version_from_product(product_name) or parse_ocp_version_from_cpe(
        entry_cpe
    )

    score = cpe_product_score(row_cpe, entry_cpe, allow_minor_compat=allow_minor_compat)
    if row_ocp and entry_ocp == row_ocp:
        score = max(score, 3)
    elif is_ocp_major_umbrella_product(product_name) and row_ocp:
        score = max(score, 2)
    elif (
        allow_minor_compat
        and entry_ocp
        and row_ocp
        and entry_ocp.startswith("4.")
        and version_lte(entry_ocp, row_ocp)
    ):
        score = max(score, 2)
    elif settings.product_regex.search(product_name):
        score = max(score, 1)
    return score


def component_package_matches(rhsda_pkg: str, component: str) -> bool:
    norm = normalize_rpm_package_name(component)
    return rhsda_pkg == norm or rhsda_pkg == component or rhsda_pkg.lower() == norm.lower()


def is_rhsda_cve_not_found(detail: dict[str, Any] | None) -> bool:
    """True when RHSDA returns ``{"message": "Not Found"}`` for a CVE lookup."""
    if not detail or not isinstance(detail, dict):
        return False
    if detail.get("message") != "Not Found":
        return False
    return not detail.get("name") and not detail.get("package_state")


def format_rhsda_exception_comment(
    settings: Settings, summary: dict[str, Any], exception_type: str
) -> str:
    prefix = settings.exception_comment_prefix
    if not summary:
        return f"{prefix}: auto platform-fp-check ({exception_type})"
    if summary.get("match_kind") == "inherent_not_affected":
        cluster = summary.get("cluster_ocp_version", "n/a")
        return (
            f"{prefix}: Inherently not affected, Not Affected (no versioned RHSDA match on OCP {cluster}) | "
            f"component={summary.get('component', 'n/a')} | "
            f"CVE={summary.get('cve', 'n/a')}"
        )
    if summary.get("match_kind") == "http_404":
        return (
            f"{prefix}: This CVE does not affect Red Hat software, return 404. | "
            f"CVE={summary.get('cve', 'n/a')}"
        )
    if summary.get("match_kind") == "not_found":
        return (
            f"{prefix}: CVE not found in Red Hat Security database | "
            f"CVE={summary.get('cve', 'n/a')}"
        )
    if exception_type == "deferral":
        return (
            f"{prefix} fix_state {summary.get('fix_state', 'unknown')} | "
            f"product={summary.get('product_name', 'n/a')} | "
            f"package={summary.get('package_name', 'n/a')} | "
            f"match_track={summary.get('match_track', 'n/a')} | "
            f"CVE={summary.get('cve', 'n/a')}"
        )
    if summary.get("match_kind") == "affected_release":
        fixed_in = summary.get("fixed_in_version", "n/a")
        return (
            f"{prefix}: affected_release fixed in {fixed_in} | "
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


DEFER_EXPIRY_TYPE = "TIME"


def add_months(dt: datetime, months: int) -> datetime:
    month_index = dt.month - 1 + months
    year = dt.year + month_index // 12
    month = month_index % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def defer_expires_on(settings: Settings) -> str:
    dt = add_months(datetime.now(timezone.utc), settings.defer_expiry_months)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def defer_expiry_fields(settings: Settings) -> dict[str, Any]:
    return {
        "exceptionExpiry": {
            "expiryType": DEFER_EXPIRY_TYPE,
            "expiresOn": defer_expires_on(settings),
        }
    }


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
