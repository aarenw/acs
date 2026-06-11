#!/usr/bin/env bash
# =============================================================================
# acs-api.sh — ACS Central API 封装
#
# 职责:
#   1. 调用 GET /v1/export/vuln-mgmt/workloads 导出 Platform Component 漏洞
#   2. 将 JSONL 解析为扁平化 summary TSV（含 image 产品 label 与 RHSDA 容器 ID）
#   3. 支持 ACS 4.9+ scan.imageVulnerabilities 与旧版 vulnerabilities[] 格式
#   4. 按镜像从 /v1/images/{id} 补全 scan 与 label（受 ACS_ENRICH_MAX_IMAGES 限制）
#
# 关键环境变量:
#   ROX_ENDPOINT, ROX_API_TOKEN, ACS_EXPORT_QUERY, ACS_EXPORT_TIMEOUT
# =============================================================================
set -euo pipefail

ACS_API_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${ACS_API_LIB_DIR}/common.sh"

ACS_ENRICH_SCANS="${ACS_ENRICH_SCANS:-true}"
ACS_ENRICH_LABELS="${ACS_ENRICH_LABELS:-true}"
ACS_ENRICH_MAX_IMAGES="${ACS_ENRICH_MAX_IMAGES:-200}"
ACS_EXPORT_TIMEOUT="${ACS_EXPORT_TIMEOUT:-900}"
ACS_EXPORT_SERVER_TIMEOUT="${ACS_EXPORT_SERVER_TIMEOUT:-600}"

ACS_SUMMARY_HEADER=$'cluster\tnamespace\tdeployment\timage\tregistry\tremote\ttag\tcve\tseverity\tcomponent\tversion\timage_id\tproduct_cpe\tocp_version\tlabel_name\tredhat_component\trhsda_container_ids'

# 通用 ACS API curl 封装，支持自定义超时（export 使用更长的 ACS_EXPORT_TIMEOUT）
acs_curl() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  local timeout="${4:-${ACS_API_TIMEOUT:-300}}"

  local url="${ROX_ENDPOINT%/}${path}"
  local -a curl_args=(
    -sS
    --fail-with-body
    --max-time "${timeout}"
    -X "${method}"
    -H "Authorization: Bearer ${ROX_API_TOKEN}"
    -H "Accept: application/json"
    -H "Content-Type: application/json"
  )

  if [[ "${ROX_INSECURE_SKIP_TLS_VERIFY:-false}" == "true" ]]; then
    curl_args+=(-k)
  fi

  if [[ -n "${data}" ]]; then
    curl_args+=(-d "${data}")
  fi

  curl "${curl_args[@]}" "${url}"
}

# 流式下载 platform workload 漏洞数据，保存为 JSONL（每行一个 deployment+images）
acs_export_platform_vulns() {
  local output_file="$1"
  local query
  query="$(build_export_query)"
  local encoded_query
  encoded_query="$(urlencode "${query}")"

  log_info "exporting platform vulnerabilities (query: ${query}, client timeout: ${ACS_EXPORT_TIMEOUT}s)"
  acs_curl GET "/v1/export/vuln-mgmt/workloads?query=${encoded_query}&timeout=${ACS_EXPORT_SERVER_TIMEOUT}" \
    "" "${ACS_EXPORT_TIMEOUT}" >"${output_file}"

  if [[ "${DRY_RUN}" == "true" ]]; then
    local total_lines first_line
    total_lines="$(grep -c '[^[:space:]]' "${output_file}" 2>/dev/null || echo 0)"
    first_line="$(grep -m1 '[^[:space:]]' "${output_file}" || true)"
    printf '%s\n' "${first_line}" >"${output_file}"
    log_warn "DRY_RUN=true: using only first export line (${total_lines} total lines fetched)"
  fi

  log_info "saved raw export to ${output_file} ($(wc -c <"${output_file}" | tr -d ' ') bytes)"
}

# Shared jq helpers for legacy + ACS 4.9+ denormalized scan model.
acs_jq_image_defs='
  def image_tag($img):
    if ($img.name | type) == "object" then
      if (($img.name.tag // "") != "") then $img.name.tag
      else (($img.name.fullName // "") | if test("@") then split("@")[1] else "" end)
      end
    else "" end;
  def image_name($img):
    if ($img.name | type) == "object" then
      if (($img.name.fullName // "") != "") then $img.name.fullName
      elif (($img.name.tag // "") != "") then
        (($img.name.registry // "") + "/" + ($img.name.remote // "") + ":" + $img.name.tag)
      else (($img.name.registry // "") + "/" + ($img.name.remote // ""))
      end
    else ($img.name // $img.image // "")
    end;
  def image_registry($img):
    if ($img.name | type) == "object" then ($img.name.registry // "") else "" end;
  def image_remote($img):
    if ($img.name | type) == "object" then ($img.name.remote // "") else "" end;
  def image_meta($img):
    ($img.metadata.v1.labels // {}) as $labels
    | {
        image_id: ($img.id // ""),
        product_cpe: ($labels.cpe // ""),
        ocp_version: ($labels.version // ""),
        label_name: ($labels.name // ""),
        redhat_component: ($labels["com.redhat.component"] // "")
      };
  def emit_row($cluster; $namespace; $deployment; $img; $cve; $severity; $component; $version):
    image_meta($img) as $meta
    | [
        $cluster, $namespace, $deployment, image_name($img),
        image_registry($img), image_remote($img), image_tag($img),
        $cve, $severity, $component, $version,
        $meta.image_id, $meta.product_cpe, $meta.ocp_version,
        $meta.label_name, $meta.redhat_component, ""
      ] | @tsv;
'

# 从旧版 images[].vulnerabilities[] 结构提取 TSV 行
acs_jq_extract_rows() {
  jq -r "${acs_jq_image_defs}"'
    .result as $r
    | ($r.deployment.cluster // $r.deployment.clusterName // "unknown") as $cluster
    | ($r.deployment.namespace // "unknown") as $namespace
    | ($r.deployment.name // $r.deployment.deploymentName // "unknown") as $deployment
    | $r.images[]? as $img
    | $img.vulnerabilities[]? as $vuln
    | ($vuln.cve // $vuln.cveBaseInfo.cve // $vuln.name // "") as $cve
    | ($vuln.severity // $vuln.cvss // "") as $severity
    | if ($vuln.components // []) | length > 0 then
        ($vuln.components // [])[] as $comp
        | emit_row($cluster; $namespace; $deployment; $img; $cve; $severity;
            ($comp.name // $comp // ""); ($comp.version // ""))
      else
        emit_row($cluster; $namespace; $deployment; $img; $cve; $severity; ""; "")
      end
  '
}

# 从 scan 结构提取 TSV 行（含 components[].vulns、imageVulnerabilities、scan.vulnerabilities）
acs_jq_extract_scan_rows() {
  jq -r "${acs_jq_image_defs}"'
    .result as $r
    | ($r.deployment.cluster // $r.deployment.clusterName // .clusterName // "unknown") as $cluster
    | ($r.deployment.namespace // .namespace // "unknown") as $namespace
    | ($r.deployment.name // $r.deployment.deploymentName // .deploymentName // "unknown") as $deployment
    | ($r.images[]? // .) as $img
    | $img.scan as $scan
    | select($scan != null)
    | (
        ($scan.imageVulnerabilities // [])[] as $vuln
        | ($vuln.cve // $vuln.cveBaseInfo.cve // $vuln.name // "") as $cve
        | ($vuln.severity // $vuln.cvss // "") as $severity
        | ($vuln.imageComponent // $vuln.component // {}) as $comp
        | emit_row($cluster; $namespace; $deployment; $img; $cve; $severity;
            ($comp.name // $comp.packageName // ""); ($comp.version // ""))
      ),
      (
        ($scan.imageComponents // $scan.components // [])[] as $comp
        | ($comp.vulns // $comp.vulnerabilities // $comp.imageVulnerabilities // [])[] as $vuln
        | emit_row($cluster; $namespace; $deployment; $img;
            ($vuln.cve // $vuln.name // "");
            ($vuln.severity // $vuln.cvss // "");
            ($comp.name // $comp.packageName // "");
            ($comp.version // ""))
      ),
      (
        ($scan.vulnerabilities // [])[] as $vuln
        | ($vuln.cve // $vuln.name // "") as $cve
        | if ($vuln.components // []) | length > 0 then
            ($vuln.components // [])[] as $comp
            | emit_row($cluster; $namespace; $deployment; $img; $cve;
                ($vuln.severity // $vuln.cvss // "");
                ($comp.name // ""); ($comp.version // ""))
          else
            emit_row($cluster; $namespace; $deployment; $img; $cve;
                ($vuln.severity // $vuln.cvss // ""); ""; "")
          end
      )
  '
}

acs_build_summary_tsv_fallback() {
  jq -r "${acs_jq_image_defs}"'
    .result as $r
    | ($r.deployment.cluster // $r.deployment.clusterName // "unknown") as $cluster
    | ($r.deployment.namespace // "unknown") as $namespace
    | ($r.deployment.name // $r.deployment.deploymentName // "unknown") as $deployment
    | $r.images[]? as $img
    | $img.vulnerabilities[]? as $vuln
    | emit_row($cluster; $namespace; $deployment; $img;
        ($vuln.cve // $vuln.name // "");
        ($vuln.severity // "");
        (($vuln.components // [])[0].name // "");
        (($vuln.components // [])[0].version // ""))
  '
}

acs_extract_rows_from_jsonl() {
  local jsonl_file="$1"
  local tmp_rows="$2"
  local line

  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line}" ]] && continue
    echo "${line}" | acs_jq_extract_rows >>"${tmp_rows}" 2>/dev/null || true
    echo "${line}" | acs_jq_extract_scan_rows >>"${tmp_rows}" 2>/dev/null || true
  done <"${jsonl_file}"
}

# 收集需要 /v1/images 补全的镜像 id（scan 为空或 label 缺失）
acs_collect_enrichment_candidates() {
  local jsonl_file="$1"
  local output_file="$2"
  local line

  : >"${output_file}"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line}" ]] && continue
    echo "${line}" | jq -r '
      .result.images[]? as $img
      | ($img.id // empty) as $id
      | select($id != "")
      | select(
          ($img.scan == null)
          or (($img.metadata.v1.labels.name // "") == "")
          or (($img.metadata.v1.labels.cpe // "") == "")
        )
      | $id
    ' 2>/dev/null >>"${output_file}" || true
  done <"${jsonl_file}"
  sort -u -o "${output_file}" "${output_file}"
}

# 从 /v1/images/{id} 响应提取 metadata TSV 行（id -> fields）
acs_jq_image_metadata_tsv() {
  jq -r '
    (.id // .result.id // "") as $id
    | (.metadata.v1.labels // {}) as $labels
    | [
        $id,
        ($labels.cpe // ""),
        ($labels.version // ""),
        ($labels.name // ""),
        ($labels["com.redhat.component"] // "")
      ] | @tsv
  '
}

# 按镜像补全 scan 与 label
acs_enrich_images_from_api() {
  local jsonl_file="$1"
  local tmp_rows="$2"
  local meta_cache="$3"
  local image_ids id fetched total enriched=0

  if [[ "${ACS_ENRICH_SCANS}" != "true" && "${ACS_ENRICH_LABELS}" != "true" ]]; then
    return 0
  fi

  image_ids="$(mktemp)"
  acs_collect_enrichment_candidates "${jsonl_file}" "${image_ids}"

  total="$(wc -l <"${image_ids}" | tr -d ' ')"
  if [[ "${total}" -eq 0 ]]; then
    rm -f "${image_ids}"
    return 0
  fi

  if [[ "${total}" -gt "${ACS_ENRICH_MAX_IMAGES}" ]]; then
    log_warn "skipping image enrichment for ${total} images (limit: ${ACS_ENRICH_MAX_IMAGES}); set ACS_ENRICH_MAX_IMAGES to increase"
    rm -f "${image_ids}"
    return 0
  fi

  log_info "enriching up to ${total} images from /v1/images (scan and/or labels)"
  : >"${meta_cache}"

  while IFS= read -r id; do
    [[ -z "${id}" ]] && continue
    fetched="$(acs_curl GET "/v1/images/${id}" 2>/dev/null || echo '{}')"
    echo "${fetched}" | acs_jq_image_metadata_tsv >>"${meta_cache}" 2>/dev/null || true
    if [[ "${ACS_ENRICH_SCANS}" == "true" ]]; then
      echo "${fetched}" | acs_jq_extract_scan_rows >>"${tmp_rows}" 2>/dev/null || true
    fi
    enriched=$((enriched + 1))
  done <"${image_ids}"

  log_info "enriched ${enriched} images from API"
  rm -f "${image_ids}"
}

# 无 CVE 行时输出告警（常见于镜像尚未被 Scanner 扫描）
acs_warn_if_empty_summary() {
  local summary_file="$1"
  local count
  count=$(( $(wc -l <"${summary_file}" | tr -d ' ') - 1 ))

  if [[ "${count}" -gt 0 ]]; then
    return 0
  fi

  log_warn "no image CVE rows extracted from platform export"
  log_warn "common causes: images not yet scanned by Central/Scanner, or no IMAGE CVEs in cluster"
  log_warn "check RHACS: Vulnerability Management -> Platform -> ensure Scanner is healthy"
  log_warn "this cluster has OPENSHIFT_CVE and NODE_CVE data, but IMAGE_CVE may be empty until scans complete"
}

# 补全 summary 中缺失的 registry/remote/tag 与 metadata、rhsda_container_ids
acs_finalize_summary_rows() {
  local summary_file="$1"
  local meta_cache="$2"
  local tmp
  tmp="$(mktemp)"

  printf '%s\n' "${ACS_SUMMARY_HEADER}" >"${tmp}"

  while IFS=$'\t' read -r cluster namespace deployment image registry remote tag cve severity component version \
      image_id product_cpe ocp_version label_name redhat_component rhsda_container_ids; do
    if [[ -z "${registry}" || -z "${remote}" ]]; then
      IFS=$'\t' read -r registry remote tag < <(parse_image_name "${image}")
    fi

    if [[ -n "${image_id}" && -f "${meta_cache}" && -s "${meta_cache}" ]]; then
      local meta_line mcpe mocp mlabel mcomp
      meta_line="$(grep -F "${image_id}"$'\t' "${meta_cache}" 2>/dev/null | head -1 || true)"
      if [[ -n "${meta_line}" ]]; then
        IFS=$'\t' read -r _ mcpe mocp mlabel mcomp <<<"${meta_line}"
        [[ -z "${product_cpe}" && -n "${mcpe}" ]] && product_cpe="${mcpe}"
        [[ -z "${ocp_version}" && -n "${mocp}" ]] && ocp_version="${mocp}"
        [[ -z "${label_name}" && -n "${mlabel}" ]] && label_name="${mlabel}"
        [[ -z "${redhat_component}" && -n "${mcomp}" ]] && redhat_component="${mcomp}"
      fi
    fi

    if [[ -z "${ocp_version}" && -n "${product_cpe}" ]]; then
      ocp_version="$(parse_ocp_version_from_cpe "${product_cpe}" 2>/dev/null || true)"
    fi

    rhsda_container_ids="$(build_rhsda_container_ids "${remote}" "${label_name}")"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "${cluster}" "${namespace}" "${deployment}" "${image}" \
      "${registry}" "${remote}" "${tag}" \
      "${cve}" "${severity}" "${component}" "${version}" \
      "${image_id}" "${product_cpe}" "${ocp_version}" "${label_name}" \
      "${redhat_component}" "${rhsda_container_ids}" >>"${tmp}"
  done < <(tail -n +2 "${summary_file}")

  mv "${tmp}" "${summary_file}"
}

# 主解析入口: JSONL -> summary TSV（export 解析 -> API 补全 -> legacy 回退）
acs_build_summary_tsv() {
  local jsonl_file="$1"
  local summary_file="$2"
  local tmp_rows meta_cache
  tmp_rows="$(mktemp)"
  meta_cache="$(mktemp)"

  require_commands jq

  printf '%s\n' "${ACS_SUMMARY_HEADER}" >"${summary_file}"

  acs_extract_rows_from_jsonl "${jsonl_file}" "${tmp_rows}"
  acs_enrich_images_from_api "${jsonl_file}" "${tmp_rows}" "${meta_cache}"

  if [[ ! -s "${tmp_rows}" ]]; then
    log_warn "still no rows after enrichment; trying legacy fallback parser"
    while IFS= read -r line || [[ -n "${line}" ]]; do
      [[ -z "${line}" ]] && continue
      echo "${line}" | acs_build_summary_tsv_fallback >>"${tmp_rows}" 2>/dev/null || true
    done <"${jsonl_file}"
  fi

  if [[ -s "${tmp_rows}" ]]; then
    sort -u "${tmp_rows}" >>"${summary_file}"
  fi
  rm -f "${tmp_rows}"

  acs_finalize_summary_rows "${summary_file}" "${meta_cache}"
  rm -f "${meta_cache}"

  acs_warn_if_empty_summary "${summary_file}"

  local count
  count=$(( $(wc -l <"${summary_file}" | tr -d ' ') - 1 ))
  log_info "summary TSV rows: ${count} -> ${summary_file}"
}

# export 子命令的完整实现，返回 jsonl 与 summary 两个文件路径（各一行）
acs_export_and_summarize() {
  local ts slug jsonl summary
  ts="$(timestamp_utc)"
  slug="$(cluster_slug)"
  jsonl="${REPORTS_DIR}/platform-vulns-${slug}-${ts}.jsonl"
  summary="${REPORTS_DIR}/platform-vulns-${slug}-${ts}.summary.tsv"

  ensure_output_dirs
  require_acs_env
  require_commands curl jq

  acs_export_platform_vulns "${jsonl}"
  acs_build_summary_tsv "${jsonl}" "${summary}"

  printf '%s\n%s\n' "${jsonl}" "${summary}"
}
