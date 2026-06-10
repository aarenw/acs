#!/usr/bin/env bash
# =============================================================================
# common.sh — 公共工具库
#
# 提供: 日志、目录、环境变量加载、镜像/RPM 名解析、ACS 查询串构建
# 被所有 lib 模块和主脚本 source 引用
# =============================================================================
set -euo pipefail

SCRIPT_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT_DIR="$(cd "${SCRIPT_LIB_DIR}/.." && pwd)"
PROJECT_ROOT_DIR="$(cd "${SCRIPT_ROOT_DIR}/.." && pwd)"

OUTPUT_DIR="${OUTPUT_DIR:-${PROJECT_ROOT_DIR}/data}"
REPORTS_DIR="${OUTPUT_DIR}/reports"
RESULTS_DIR="${OUTPUT_DIR}/results"

RHSDA_PRODUCT_REGEX="${RHSDA_PRODUCT_REGEX:-OpenShift|RHCOS|Red Hat Enterprise Linux CoreOS}"
ACS_EXPORT_QUERY="${ACS_EXPORT_QUERY:-Platform Component:true}"
DRY_RUN="${DRY_RUN:-false}"
DEFER_EXPIRY_DAYS="${DEFER_EXPIRY_DAYS:-90}"
ACS_ENRICH_LABELS="${ACS_ENRICH_LABELS:-true}"
EXCEPTION_COMMENT_PREFIX="${EXCEPTION_COMMENT_PREFIX:-RHSDA}"

log_info() {
  echo "[INFO] $*" >&2
}

log_warn() {
  echo "[WARN] $*" >&2
}

log_error() {
  echo "[ERROR] $*" >&2
}

timestamp_utc() {
  date -u +"%Y%m%dT%H%M%SZ"
}

require_commands() {
  local cmd
  for cmd in "$@"; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      log_error "required command not found: ${cmd}"
      exit 1
    fi
  done
}

ensure_output_dirs() {
  mkdir -p "${REPORTS_DIR}" "${RESULTS_DIR}"
}

load_env_file() {
  local env_file="$1"
  if [[ -f "${env_file}" ]]; then
    # shellcheck disable=SC1090
    source "${env_file}"
    log_info "loaded env from ${env_file}"
  fi
}

# 按优先级自动加载 config/local.env、config/.env 或项目根 .env
load_default_env() {
  local candidate
  for candidate in \
    "${PROJECT_ROOT_DIR}/config/local.env" \
    "${PROJECT_ROOT_DIR}/config/.env" \
    "${PROJECT_ROOT_DIR}/.env"; do
    if [[ -f "${candidate}" ]]; then
      load_env_file "${candidate}"
      return 0
    fi
  done
}

require_acs_env() {
  if [[ -z "${ROX_ENDPOINT:-}" ]]; then
    log_error "ROX_ENDPOINT is required"
    exit 1
  fi
  if [[ -z "${ROX_API_TOKEN:-}" ]]; then
    log_error "ROX_API_TOKEN is required"
    exit 1
  fi
}

cluster_slug() {
  local name="${ACS_CLUSTER_NAME:-all}"
  printf '%s' "${name}" | tr ' /:' '___'
}

# 组装 ACS export 查询串，默认 "Platform Component:true"，可追加 Cluster 过滤
build_export_query() {
  local query="${ACS_EXPORT_QUERY}"
  if [[ -n "${ACS_CLUSTER_NAME:-}" ]]; then
    query="${query}+Cluster:${ACS_CLUSTER_NAME}"
  fi
  printf '%s' "${query}"
}

urlencode() {
  jq -nr --arg v "$1" '$v|@uri'
}

# 解析完整镜像引用为 registry / remote / tag（制表符分隔）
# 支持 digest 引用（tag 为空）及 docker.io 简写形式
parse_image_name() {
  local image_ref="$1"
  local registry="" remote="" tag="" rest=""

  if [[ "${image_ref}" == *"@"* ]]; then
    # digest reference - use digest as tag
    tag="${image_ref##*@}"
    rest="${image_ref%@*}"
  elif [[ "${image_ref}" == *":"* ]]; then
    tag="${image_ref##*:}"
    rest="${image_ref%:*}"
  else
    tag="latest"
    rest="${image_ref}"
  fi

  if [[ "${rest}" == */* ]]; then
    registry="${rest%%/*}"
    remote="${rest#*/}"
  else
    registry="docker.io"
    remote="${rest}"
  fi

  # docker.io official images: nginx -> library/nginx
  if [[ "${registry}" != *"."* && "${registry}" != *":"* && "${registry}" != "localhost" ]]; then
    remote="${registry}/${remote}"
    registry="docker.io"
  fi

  printf '%s\t%s\t%s' "${registry}" "${remote}" "${tag}"
}

# 从 RPM 全名提取 base package，如 openssl-1.1.1k-7.el8_5.x86_64 -> openssl
normalize_rpm_package_name() {
  local name="$1"
  name="${name%.src}"
  name="${name%.x86_64}"
  name="${name%.aarch64}"
  name="${name%.noarch}"
  name="${name%.i686}"
  name="${name%.ppc64le}"
  name="${name%.s390x}"

  if [[ "${name}" =~ ^[0-9]+: ]]; then
    name="${name#*:}"
  fi

  # Strip epoch:version-release suffix to base package name.
  if [[ "${name}" =~ ^([a-zA-Z0-9_.+-]+)-[0-9] ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi

  printf '%s' "${name}"
}

# Go/stdlib 模块路径 — 此类 CVE 仅走容器直配（轨迹 A）
is_go_module_component() {
  local component="$1"
  [[ "${component}" =~ ^(golang\.org/|github\.com/|google\.golang\.org/|stdlib$|stdlib/) ]]
}

# label name="openshift/foo" -> RHSDA package openshift4/foo
label_name_to_rhsda_container() {
  local label_name="$1"
  if [[ -z "${label_name}" ]]; then
    return 0
  fi
  if [[ "${label_name}" =~ ^openshift/ ]]; then
    printf 'openshift4/%s' "${label_name#openshift/}"
    return 0
  fi
  printf '%s' "${label_name}"
}

# 从 remote + label 生成 RHSDA 容器候选 ID 列表（| 分隔）
build_rhsda_container_ids() {
  local remote="$1"
  local label_name="$2"
  local -a ids=()
  local from_label id

  if [[ -n "${remote}" ]]; then
    ids+=("${remote}")
  fi
  from_label="$(label_name_to_rhsda_container "${label_name}")"
  if [[ -n "${from_label}" ]]; then
    ids+=("${from_label}")
  fi

  printf '%s\n' "${ids[@]}" | awk '!seen[tolower($0)]++ && NF' | paste -sd'|' -
}

# RHSDA package_name 与容器候选 ID 匹配（精确、大小写、-rhel8/9、-operator 后缀）
container_package_matches() {
  local rhsda_pkg="$1"
  local candidate="$2"
  local a b

  [[ -z "${rhsda_pkg}" || -z "${candidate}" ]] && return 1

  a="$(printf '%s' "${rhsda_pkg}" | tr '[:upper:]' '[:lower:]')"
  b="$(printf '%s' "${candidate}" | tr '[:upper:]' '[:lower:]')"

  [[ "${a}" == "${b}" ]] && return 0
  [[ "${a}" == "${b}-operator" || "${b}" == "${a}-operator" ]] && return 0
  [[ "${a}" == "${b}-rhel8" || "${b}" == "${a}-rhel8" ]] && return 0
  [[ "${a}" == "${b}-rhel9" || "${b}" == "${a}-rhel9" ]] && return 0
  [[ "${a}" == "${b}-rhel8-operator" || "${b}" == "${a}-rhel8-operator" ]] && return 0
  [[ "${a}" == "${b}-rhel9-operator" || "${b}" == "${a}-rhel9-operator" ]] && return 0
  return 1
}

# 从 CPE 提取 OCP 版本，如 cpe:/a:redhat:openshift:4.20::el9 -> 4.20
parse_ocp_version_from_cpe() {
  local cpe="$1"
  if [[ "${cpe}" =~ openshift:([0-9]+\.[0-9]+) ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "${cpe}" =~ openshift:([0-9]+)(::|:|$) ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

# 输出 JSON：产品上下文（供 jq 使用）
derive_product_context_json() {
  local product_cpe="${1:-}"
  local remote="${2:-}"
  local ocp_version="" specific_regex="" broad_regex=""

  if [[ -n "${product_cpe}" ]]; then
    ocp_version="$(parse_ocp_version_from_cpe "${product_cpe}" 2>/dev/null || true)"
  fi

  if [[ -n "${ocp_version}" ]]; then
    specific_regex="OpenShift Container Platform ${ocp_version//./\\.}"
    broad_regex="OpenShift Container Platform 4(\\.${ocp_version#*.})?|OpenShift Container Platform 4[^0-9]|OpenShift Container Platform 4$"
  elif [[ "${remote}" == openshift4/* ]]; then
    broad_regex="OpenShift Container Platform 4|OpenShift"
  fi

  jq -n \
    --arg env_re "${RHSDA_PRODUCT_REGEX}" \
    --arg specific "${specific_regex}" \
    --arg broad "${broad_regex}" \
    --arg ocp_version "${ocp_version}" \
    --arg cpe "${product_cpe}" \
    '{
      env_regex: $env_re,
      specific_regex: (if $specific != "" then $specific else null end),
      broad_regex: (if $broad != "" then $broad else null end),
      ocp_version: (if $ocp_version != "" then $ocp_version else null end),
      product_cpe: (if $cpe != "" then $cpe else null end)
    }'
}

# 从 rhsda_summary 对象渲染 ACS exception comment
format_rhsda_exception_comment() {
  local summary_json="$1"
  local exception_type="$2"
  local prefix="${EXCEPTION_COMMENT_PREFIX}"

  echo "${summary_json}" | jq -r \
    --arg prefix "${prefix}" \
    --arg type "${exception_type}" \
    '
      if . == null or . == {} then
        "\($prefix): auto platform-fp-check (\($type))"
      elif $type == "deferral" then
        "\($prefix) fix_state \(.fix_state // "unknown") | product=\(.product_name // "n/a") | package=\(.package_name // "n/a") | match_track=\(.match_track // "n/a") | CVE=\(.cve // "n/a")"
      elif .match_kind == "affected_release" then
        "\($prefix): affected_release fixed | product=\(.product_name // "n/a") | package=\(.package_name // "n/a") | match_track=\(.match_track // "n/a") | CVE=\(.cve // "n/a")"
      else
        "\($prefix): package_state \(.fix_state // "Not affected") | product=\(.product_name // "n/a") | package=\(.package_name // "n/a") | match_track=\(.match_track // "n/a") | CVE=\(.cve // "n/a")"
      end
    '
}

# deferral expires_on（UTC ISO8601）
defer_expires_on() {
  local days="${DEFER_EXPIRY_DAYS}"
  if date -u -v+"${days}"d +"%Y-%m-%dT%H:%M:%SZ" >/dev/null 2>&1; then
    date -u -v+"${days}"d +"%Y-%m-%dT%H:%M:%SZ"
  else
    date -u -d "+${days} days" +"%Y-%m-%dT%H:%M:%SZ"
  fi
}
