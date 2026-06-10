#!/usr/bin/env bash
# =============================================================================
# rhsda.sh — Red Hat Security Data API 轻量封装
#
# 提供 get-cve 查询 CVE 详情（供 rhsda-check.sh 调用）。
# 可独立运行: ./scripts/lib/rhsda.sh get-cve CVE-2014-0160
#
# 环境变量: RHSDA_BASE_URL, RHSDA_TIMEOUT, HTTPS_PROXY
# =============================================================================
set -euo pipefail

RHSDA_BASE_URL="${RHSDA_BASE_URL:-https://access.redhat.com/hydra/rest/securitydata}"
RHSDA_PER_PAGE="${RHSDA_PER_PAGE:-1000}"
RHSDA_TIMEOUT="${RHSDA_TIMEOUT:-30}"

require_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required" >&2
    exit 1
  fi
}

curl_api() {
  local path="$1"
  local url="${RHSDA_BASE_URL}${path}"
  local -a curl_args=(
    -sS
    --fail-with-body
    --max-time "${RHSDA_TIMEOUT}"
    -H "Accept: application/json"
  )
  if [[ -n "${HTTPS_PROXY:-}" ]]; then
    curl_args+=(--proxy "${HTTPS_PROXY}")
  elif [[ -n "${HTTP_PROXY:-}" ]]; then
    curl_args+=(--proxy "${HTTP_PROXY}")
  fi
  curl "${curl_args[@]}" "${url}"
}

append_param() {
  local key="$1"
  local value="$2"
  if [[ -n "${value}" ]]; then
    if [[ -n "${QUERY_STRING}" ]]; then
      QUERY_STRING+="&"
    else
      QUERY_STRING="?"
    fi
    QUERY_STRING+="${key}=$(printf '%s' "${value}" | jq -sRr @uri)"
  fi
}

cmd_get_cve() {
  local cve="$1"
  require_jq
  curl_api "/cve/${cve}.json"
}

# 静默版 get-cve，失败时返回 {} 而不中断流水线
# 注意：--fail-with-body 在 HTTP 错误时会先把响应体写入 stdout 再以非零码退出；
# 必须先用变量捕获输出，失败时丢弃响应体，否则错误体会与 {} 拼接导致 jq 报错。
cmd_get_cve_quiet() {
  local cve="$1"
  local result
  result="$(curl_api "/cve/${cve}.json" 2>/dev/null)" || { echo "{}"; return 0; }
  printf '%s' "${result}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [[ $# -lt 1 ]]; then
    echo "usage: rhsda.sh get-cve <CVE-ID>" >&2
    exit 1
  fi
  case "$1" in
    get-cve)
      cmd_get_cve "$2"
      ;;
    *)
      echo "only get-cve is exposed in standalone mode" >&2
      exit 1
      ;;
  esac
fi
