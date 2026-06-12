"""HTTP clients for ACS Central and RHSDA."""

from __future__ import annotations

import json
import logging
import ssl
import urllib.error
import urllib.request
from typing import Any

log = logging.getLogger(__name__)

from acs.config import Settings

# Red Hat CDN blocks the default Python-urllib User-Agent (HTTP 403).
RHSDA_USER_AGENT = "acs-platform-fp-check/1.0"
RHSDA_HTTP_404 = "_rhsda_http_404"



def _build_opener_for(settings: Settings, insecure: bool | None) -> urllib.request.OpenerDirector:
    handlers: list[Any] = []
    proxy = settings.https_proxy or settings.http_proxy
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    if insecure or settings.rox_insecure_skip_tls_verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def http_request(
    settings: Settings,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: int = 30,
    bearer_token: str | None = None,
    insecure: bool | None = None,
) -> Any:
    req_headers = {"Accept": "application/json", **(headers or {})}
    if bearer_token:
        req_headers["Authorization"] = f"Bearer {bearer_token}"
    data = None
    if body is not None:
        req_headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    opener = _build_opener_for(settings, insecure)
    log.info("%s %s", method, url)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} {url}: {err_body}") from exc

    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def http_get_text(
    settings: Settings,
    url: str,
    *,
    timeout: int = 30,
    bearer_token: str | None = None,
    insecure: bool | None = None,
) -> str:
    req_headers = {"Accept": "application/json", "Authorization": f"Bearer {bearer_token}"}
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    opener = _build_opener_for(settings, insecure)
    log.info("GET %s", url)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} {url}: {err_body}") from exc


class AcsClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.base = settings.rox_endpoint.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> Any:
        return http_request(
            self.settings,
            method,
            f"{self.base}{path}",
            body=body,
            timeout=timeout or self.settings.acs_api_timeout,
            bearer_token=self.settings.rox_api_token,
            insecure=self.settings.rox_insecure_skip_tls_verify,
        )


class RhsdaClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.base = settings.rhsda_base_url.rstrip("/")
        self._cache: dict[str, dict[str, Any]] = {}

    def get_cve(self, cve: str, *, quiet: bool = False) -> dict[str, Any]:
        if cve in self._cache:
            return self._cache[cve]
        url = f"{self.base}/cve/{cve}.json"
        detail: dict[str, Any] = {}
        fetch_error: str | None = None
        try:
            detail = http_request(
                self.settings,
                "GET",
                url,
                timeout=self.settings.rhsda_timeout,
                headers={"User-Agent": RHSDA_USER_AGENT},
            )
            if not detail:
                fetch_error = "empty response"
        except RuntimeError as exc:
            if quiet and "HTTP 404" in str(exc):
                detail = {RHSDA_HTTP_404: True}
            elif quiet:
                fetch_error = str(exc)
            else:
                raise
        except Exception as exc:
            if quiet:
                fetch_error = f"{type(exc).__name__}: {exc}"
            else:
                raise
        if not isinstance(detail, dict):
            detail = {}
        if fetch_error:
            detail = {"_rhsda_fetch_error": fetch_error}
            log.warning("%s: RHSDA fetch failed: %s", cve, fetch_error)
        self._cache[cve] = detail
        return detail
