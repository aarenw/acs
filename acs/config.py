"""Environment and path configuration."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.environ.get(name, str(default)).lower()
    return val in ("1", "true", "yes", "on")


def load_env_file(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def load_default_env() -> Path | None:
    for candidate in (
        PROJECT_ROOT / "config" / "local.env",
        PROJECT_ROOT / "config" / ".env",
        PROJECT_ROOT / ".env",
    ):
        if candidate.is_file():
            load_env_file(candidate)
            return candidate
    return None


@dataclass
class Settings:
    rox_endpoint: str = ""
    rox_api_token: str = ""
    rox_insecure_skip_tls_verify: bool = False
    acs_cluster_name: str = ""
    acs_export_query: str = "Platform Component:true"
    rhsda_base_url: str = "https://access.redhat.com/hydra/rest/securitydata"
    rhsda_product_regex: str = "OpenShift|RHCOS|Red Hat Enterprise Linux CoreOS"
    rhsda_timeout: int = 30
    output_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "data")
    dry_run: bool = False
    acs_enrich_scans: bool = True
    acs_enrich_labels: bool = True
    acs_enrich_max_images: int = 200
    acs_api_timeout: int = 300
    acs_export_timeout: int = 900
    acs_export_server_timeout: int = 600
    defer_expiry_days: int = 90
    exception_comment_prefix: str = "RHSDA"
    https_proxy: str = ""
    http_proxy: str = ""

    @property
    def reports_dir(self) -> Path:
        return self.output_dir / "reports"

    @property
    def results_dir(self) -> Path:
        return self.output_dir / "results"

    @property
    def product_regex(self) -> re.Pattern[str]:
        return re.compile(self.rhsda_product_regex)

    @classmethod
    def from_env(cls) -> Settings:
        output = os.environ.get("OUTPUT_DIR", str(PROJECT_ROOT / "data"))
        return cls(
            rox_endpoint=os.environ.get("ROX_ENDPOINT", ""),
            rox_api_token=os.environ.get("ROX_API_TOKEN", ""),
            rox_insecure_skip_tls_verify=_env_bool("ROX_INSECURE_SKIP_TLS_VERIFY"),
            acs_cluster_name=os.environ.get("ACS_CLUSTER_NAME", ""),
            acs_export_query=os.environ.get("ACS_EXPORT_QUERY", "Platform Component:true"),
            rhsda_base_url=os.environ.get(
                "RHSDA_BASE_URL", "https://access.redhat.com/hydra/rest/securitydata"
            ),
            rhsda_product_regex=os.environ.get(
                "RHSDA_PRODUCT_REGEX",
                "OpenShift|RHCOS|Red Hat Enterprise Linux CoreOS",
            ),
            rhsda_timeout=int(os.environ.get("RHSDA_TIMEOUT", "30")),
            output_dir=Path(output),
            dry_run=_env_bool("DRY_RUN"),
            acs_enrich_scans=_env_bool("ACS_ENRICH_SCANS", True),
            acs_enrich_labels=_env_bool("ACS_ENRICH_LABELS", True),
            acs_enrich_max_images=int(os.environ.get("ACS_ENRICH_MAX_IMAGES", "200")),
            acs_api_timeout=int(os.environ.get("ACS_API_TIMEOUT", "300")),
            acs_export_timeout=int(os.environ.get("ACS_EXPORT_TIMEOUT", "900")),
            acs_export_server_timeout=int(os.environ.get("ACS_EXPORT_SERVER_TIMEOUT", "600")),
            defer_expiry_days=int(os.environ.get("DEFER_EXPIRY_DAYS", "90")),
            exception_comment_prefix=os.environ.get("EXCEPTION_COMMENT_PREFIX", "RHSDA"),
            https_proxy=os.environ.get("HTTPS_PROXY", ""),
            http_proxy=os.environ.get("HTTP_PROXY", ""),
        )

    def ensure_dirs(self) -> None:
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def require_acs(self) -> None:
        if not self.rox_endpoint:
            raise SystemExit("ROX_ENDPOINT is required")
        if not self.rox_api_token:
            raise SystemExit("ROX_API_TOKEN is required")

    def build_export_query(self) -> str:
        query = self.acs_export_query
        if self.acs_cluster_name:
            query = f"{query}+Cluster:{self.acs_cluster_name}"
        return query

    def cluster_slug(self) -> str:
        name = self.acs_cluster_name or "all"
        return re.sub(r"[ /:]", "_", name)
