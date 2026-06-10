#!/usr/bin/env bash
# =============================================================================
# rhsda-check.sh — RHSDA 漏洞校验逻辑（产品容器双轨匹配）
#
# 轨迹 A: 容器 remote/label -> RHSDA package_name（优先，尤其 Go 模块 CVE）
# 轨迹 B: 产品上下文内 component -> package_name（非 Go 模块）
#
# 决策:
#   candidate_fp    — Not affected 或已修复 -> false positive
#   candidate_defer — Fix deferred / Will not fix -> deferral
#   skipped         — 其他
# =============================================================================
set -euo pipefail

RHSDA_CHECK_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${RHSDA_CHECK_LIB_DIR}/common.sh"
# shellcheck source=rhsda.sh
source "${RHSDA_CHECK_LIB_DIR}/rhsda.sh"

CVE_CACHE_DIR=""

rpm_parse_evr() {
  local pkg="$1"
  local epoch="0" ver rel rest

  if [[ "${pkg}" =~ ^([0-9]+):(.+)$ ]]; then
    epoch="${BASH_REMATCH[1]}"
    rest="${BASH_REMATCH[2]}"
  else
    rest="${pkg}"
  fi

  if [[ "${rest}" =~ ^(.+)-([^-]+)$ ]]; then
    ver="${BASH_REMATCH[1]}"
    rel="${BASH_REMATCH[2]}"
  else
    ver="${rest}"
    rel=""
  fi

  printf '%s\t%s\t%s' "${epoch}" "${ver}" "${rel}"
}

rpm_compare() {
  local a="$1"
  local b="$2"
  local ae av ar be bv br

  IFS=$'\t' read -r ae av ar < <(rpm_parse_evr "${a}")
  IFS=$'\t' read -r be bv br < <(rpm_parse_evr "${b}")

  if command -v rpm >/dev/null 2>&1; then
    local result
    result="$(rpm --eval "%{lua: print(rpm.vercmp('${ae}:${av}-${ar}', '${be}:${bv}-${br}'))}" 2>/dev/null || echo "error")"
    if [[ "${result}" =~ ^-?[0-9]+$ ]]; then
      printf '%s' "${result}"
      return 0
    fi
  fi

  if [[ "${ae}" -lt "${be}" ]]; then echo -1; return; fi
  if [[ "${ae}" -gt "${be}" ]]; then echo 1; return; fi
  if [[ "${av}" == "${bv}" && "${ar}" == "${br}" ]]; then echo 0; return; fi
  if [[ "${av}" == "${bv}" ]]; then
    [[ "${ar}" < "${br}" ]] && echo -1 || echo 1
    return
  fi
  [[ "${av}" < "${bv}" ]] && echo -1 || echo 1
}

init_cve_cache() {
  if [[ -z "${CVE_CACHE_DIR}" ]]; then
    CVE_CACHE_DIR="$(mktemp -d)"
  fi
}

cleanup_cve_cache() {
  if [[ -n "${CVE_CACHE_DIR}" && -d "${CVE_CACHE_DIR}" ]]; then
    rm -rf "${CVE_CACHE_DIR}"
    CVE_CACHE_DIR=""
  fi
}

fetch_cve_detail() {
  local cve="$1"
  init_cve_cache
  local cache_file="${CVE_CACHE_DIR}/${cve}"
  if [[ -f "${cache_file}" ]]; then
    cat "${cache_file}"
    return 0
  fi
  local detail
  detail="$(cmd_get_cve_quiet "${cve}")"
  printf '%s' "${detail}" >"${cache_file}"
  printf '%s' "${detail}"
}

# jq 内嵌：产品上下文评分与包名匹配
RHSda_JQ_MATCH_FILTER='
  def product_score($entry; $ctx):
    if (($ctx.specific_regex // "") != "") and ($entry.product_name | test($ctx.specific_regex)) then 3
    elif (($ctx.broad_regex // "") != "") and ($entry.product_name | test($ctx.broad_regex)) then 2
    elif ($entry.product_name | test($ctx.env_regex)) then 1
    elif (($ctx.product_cpe // "") != "") and (($entry.cpe // "") != "")
         and ((($entry.cpe | startswith($ctx.product_cpe)) or ($ctx.product_cpe | startswith($entry.cpe)))) then 1
    else 0 end;

  def norm_lc($s): ($s // "") | ascii_downcase;

  def container_match($pkg; $candidate):
    (norm_lc($pkg)) as $p | (norm_lc($candidate)) as $c
    | ($p == $c)
      or ($p == ($c + "-operator")) or ($c == ($p + "-operator"))
      or ($p == ($c + "-rhel8")) or ($c == ($p + "-rhel8"))
      or ($p == ($c + "-rhel9")) or ($c == ($p + "-rhel9"))
      or ($p == ($c + "-rhel8-operator")) or ($c == ($p + "-rhel8-operator"))
      or ($p == ($c + "-rhel9-operator")) or ($c == ($p + "-rhel9-operator"));

  def container_match_any($pkg; $candidates):
    any($candidates[]?; container_match($pkg; .));

  def component_match($pkg; $component; $norm):
    (norm_lc($pkg)) as $p
    | ($p == norm_lc($component)) or ($p == norm_lc($norm));
'

# 在 package_state 中查找最佳匹配（单次 jq，避免大 CVE 文件 bash 循环）
find_package_state_match() {
  local detail="$1"
  local track="$2"
  local match_key="$3"
  local product_ctx="$4"
  local norm_pkg=""
  local result

  if [[ "${track}" == "component" ]]; then
    norm_pkg="$(normalize_rpm_package_name "${match_key}")"
  fi

  result="$(echo "${detail}" | jq -c \
    --argjson ctx "${product_ctx}" \
    --arg track "${track}" \
    --arg match_key "${match_key}" \
    --arg norm_pkg "${norm_pkg}" \
    --arg containers "${match_key}" \
    "${RHSda_JQ_MATCH_FILTER}
    (\$containers | split(\"|\") | map(select(. != \"\"))) as \$cids
    | [.package_state[]?
      | . as \$ps
      | (product_score(\$ps; \$ctx)) as \$score
      | select(\$score > 0)
      | select(
          if \$track == \"container\" then container_match_any(\$ps.package_name; \$cids)
          else component_match(\$ps.package_name; \$match_key; \$norm_pkg)
          end
        )
      | \$ps + {_product_score: \$score}
    ]
    | sort_by(-._product_score, (if .fix_state == \"Not affected\" then 0 else 1 end))
    | if length > 0 then .[0] | del(._product_score) else empty end
    ")"

  printf '%s' "${result}"
}

find_container_affected_release() {
  local detail="$1"
  local container_ids="$2"
  local product_ctx="$3"
  local image_tag="$4"
  local result

  result="$(echo "${detail}" | jq -c \
    --argjson ctx "${product_ctx}" \
    --arg containers "${container_ids}" \
    --arg tag "${image_tag}" \
    "${RHSda_JQ_MATCH_FILTER}
    (\$containers | split(\"|\") | map(select(. != \"\"))) as \$cids
    | [.affected_release[]?
      | . as \$ar
      | (product_score(\$ar; \$ctx)) as \$score
      | select(\$score > 0)
      | select((\$ar.package // \"\") | contains(\":\"))
      | select(container_match_any((\$ar.package | split(\":\")[0]); \$cids))
      | select(
          (\$tag | test(\"^[0-9]+$\"))
          and ((\$ar.package | split(\":\")[1]) | test(\"^[0-9]+$\"))
          and ((\$tag | tonumber) >= (\$ar.package | split(\":\")[1] | tonumber))
        )
      | \$ar + {_product_score: \$score}
    ]
    | sort_by(-._product_score)
    | if length > 0 then .[0] | del(._product_score) else empty end
    ")"

  printf '%s' "${result}"
}

find_rpm_affected_release() {
  local detail="$1"
  local component="$2"
  local version="$3"
  local product_ctx="$4"
  local norm_pkg compare_method="rpm_compare"
  local candidates_json result entry ar_pkg cmp

  [[ -n "${version}" ]] || return 1

  norm_pkg="$(normalize_rpm_package_name "${component}")"

  candidates_json="$(echo "${detail}" | jq -c \
    --argjson ctx "${product_ctx}" \
    --arg norm "${norm_pkg}" \
    --arg prefix "${norm_pkg}-" \
    "${RHSda_JQ_MATCH_FILTER}
    [.affected_release[]?
      | select((.package // \"\") | startswith(\$prefix))
      | select((.package // \"\") | contains(\":\") | not)
      | select(product_score(.; \$ctx) > 0)
      | .package
    ] | unique
    ")"

  while IFS= read -r ar_pkg; do
    [[ -z "${ar_pkg}" ]] && continue
    cmp="$(rpm_compare "${version}" "${ar_pkg}" 2>/dev/null || echo "error")"
    if [[ "${cmp}" == "error" ]]; then
      compare_method="string_fallback"
      if [[ "${version}" == "${ar_pkg}" ]] || [[ "${version}" > "${ar_pkg}" ]]; then
        cmp="0"
      else
        cmp="1"
      fi
    fi
    if [[ "${cmp}" -ge 0 ]]; then
      entry="$(echo "${detail}" | jq -c --arg pkg "${ar_pkg}" '[.affected_release[]? | select(.package == $pkg)][0]')"
      printf '%s\t%s' "${entry}" "${compare_method}"
      return 0
    fi
  done < <(echo "${candidates_json}" | jq -r '.[]')

  return 1
}

build_result_json() {
  local cve="$1" component="$2" version="$3"
  local decision="$4" reason="$5" match_track="$6"
  local summary_json="$7" evidence_json="$8" compare_method="${9:-}"

  jq -n \
    --arg cve "${cve}" --arg component "${component}" --arg version "${version}" \
    --arg decision "${decision}" --arg reason "${reason}" --arg match_track "${match_track}" \
    --arg compare_method "${compare_method}" \
    --argjson summary "${summary_json}" --argjson evidence "${evidence_json}" \
    '{
      cve: $cve,
      component: $component,
      version: $version,
      decision: $decision,
      reason: $reason,
      match_track: $match_track,
      rhsda_summary: $summary,
      rhsda_evidence: $evidence
    }
    + (if $compare_method != "" then {compare_method: $compare_method} else {} end)'
}

decision_from_fix_state() {
  local fix_state="$1"
  case "${fix_state}" in
    "Not affected") printf '%s' "candidate_fp" ;;
    "Fix deferred"|"Will not fix") printf '%s' "candidate_defer" ;;
    *) printf '%s' "skipped" ;;
  esac
}

evaluate_vuln_row() {
  local cve="$1" component="$2" version="$3"
  local registry="$4" remote="$5" tag="$6"
  local product_cpe="$7" ocp_version="$8" label_name="$9" redhat_component="${10}" rhsda_container_ids="${11}"

  local detail decision="skipped" reason="no matching RHSDA data" match_track=""
  local summary_json='{}' evidence_json='{}' compare_method=""
  local product_ctx container_ids

  if [[ -z "${rhsda_container_ids}" ]]; then
    rhsda_container_ids="$(build_rhsda_container_ids "${remote}" "${label_name}")"
  fi
  container_ids="${rhsda_container_ids}"
  product_ctx="$(derive_product_context_json "${product_cpe}" "${remote}")"

  detail="$(fetch_cve_detail "${cve}")"
  if [[ -z "${detail}" || "${detail}" == "{}" || "${detail}" == "null" ]]; then
    build_result_json "${cve}" "${component}" "${version}" "${decision}" "${reason}" "${match_track}" "${summary_json}" "${evidence_json}"
    return 0
  fi
  if ! echo "${detail}" | jq -e 'type == "object"' >/dev/null 2>&1; then
    reason="RHSDA returned non-object response"
    build_result_json "${cve}" "${component}" "${version}" "${decision}" "${reason}" "${match_track}" "${summary_json}" "${evidence_json}"
    return 0
  fi

  # --- 轨迹 A: 容器直配 ---
  local ps_match fix_state
  ps_match="$(find_package_state_match "${detail}" "container" "${container_ids}" "${product_ctx}")"
  if [[ -n "${ps_match}" ]]; then
    fix_state="$(echo "${ps_match}" | jq -r '.fix_state // ""')"
    decision="$(decision_from_fix_state "${fix_state}")"
    if [[ "${decision}" != "skipped" ]]; then
      match_track="container"
      reason="RHSDA package_state ${fix_state} (container track)"
      summary_json="$(echo "${ps_match}" | jq --arg cve "${cve}" --arg track "${match_track}" \
        '. + {cve: $cve, match_track: $track, match_kind: "package_state"}')"
      evidence_json="$(jq -n --argjson ps "${ps_match}" '{package_state: [$ps]}')"
      build_result_json "${cve}" "${component}" "${version}" "${decision}" "${reason}" "${match_track}" "${summary_json}" "${evidence_json}"
      return 0
    fi
    if [[ "${fix_state}" == "Affected" ]]; then
      reason="RHSDA package_state Affected for container"
      evidence_json="$(jq -n --argjson ps "${ps_match}" '{package_state: [$ps]}')"
      build_result_json "${cve}" "${component}" "${version}" "${decision}" "${reason}" "container" "${summary_json}" "${evidence_json}"
      if is_go_module_component "${component}"; then
        return 0
      fi
    fi
  fi

  local ar_container
  ar_container="$(find_container_affected_release "${detail}" "${container_ids}" "${product_ctx}" "${tag}")"
  if [[ -n "${ar_container}" ]]; then
    match_track="container"
    decision="candidate_fp"
    reason="RHSDA affected_release: container fix satisfied"
    summary_json="$(echo "${ar_container}" | jq --arg cve "${cve}" --arg track "${match_track}" \
      '. + {cve: $cve, match_track: $track, match_kind: "affected_release", fix_state: "fixed", package_name: .package}')"
    evidence_json="$(jq -n --argjson ar "${ar_container}" '{affected_release: [$ar]}')"
    build_result_json "${cve}" "${component}" "${version}" "${decision}" "${reason}" "${match_track}" "${summary_json}" "${evidence_json}"
    return 0
  fi

  if is_go_module_component "${component}"; then
    reason="Go module CVE: no container-level RHSDA match"
    evidence_json="$(echo "${detail}" | jq '{package_state: (.package_state // []), affected_release: (.affected_release // [])}')"
    build_result_json "${cve}" "${component}" "${version}" "${decision}" "${reason}" "container" "${summary_json}" "${evidence_json}"
    return 0
  fi

  # --- 轨迹 B: 产品上下文组件匹配 ---
  ps_match="$(find_package_state_match "${detail}" "component" "${component}" "${product_ctx}")"
  if [[ -n "${ps_match}" ]]; then
    fix_state="$(echo "${ps_match}" | jq -r '.fix_state // ""')"
    decision="$(decision_from_fix_state "${fix_state}")"
    if [[ "${decision}" != "skipped" ]]; then
      match_track="component"
      reason="RHSDA package_state ${fix_state} (component track)"
      summary_json="$(echo "${ps_match}" | jq --arg cve "${cve}" --arg track "${match_track}" \
        '. + {cve: $cve, match_track: $track, match_kind: "package_state"}')"
      evidence_json="$(jq -n --argjson ps "${ps_match}" '{package_state: [$ps]}')"
      build_result_json "${cve}" "${component}" "${version}" "${decision}" "${reason}" "${match_track}" "${summary_json}" "${evidence_json}"
      return 0
    fi
  fi

  local ar_rpm_result ar_rpm compare_m=""
  if ar_rpm_result="$(find_rpm_affected_release "${detail}" "${component}" "${version}" "${product_ctx}")"; then
    IFS=$'\t' read -r ar_rpm compare_m <<< "${ar_rpm_result}"
    match_track="component"
    decision="candidate_fp"
    reason="RHSDA affected_release: installed RPM version >= fix"
    summary_json="$(echo "${ar_rpm}" | jq --arg cve "${cve}" --arg track "${match_track}" \
      '. + {cve: $cve, match_track: $track, match_kind: "affected_release", fix_state: "fixed", package_name: .package}')"
    evidence_json="$(jq -n --argjson ar "${ar_rpm}" '{affected_release: [$ar]}')"
    build_result_json "${cve}" "${component}" "${version}" "${decision}" "${reason}" "${match_track}" "${summary_json}" "${evidence_json}" "${compare_m}"
    return 0
  fi

  reason="no Not affected, deferral, or fix match for product context"
  evidence_json="$(echo "${detail}" | jq '{package_state: (.package_state // []), affected_release: (.affected_release // [])}')"
  build_result_json "${cve}" "${component}" "${version}" "${decision}" "${reason}" "${match_track}" "${summary_json}" "${evidence_json}"
}

# 向后兼容别名
evaluate_cve_component() {
  evaluate_vuln_row "$1" "$2" "$3" "" "" "" "" "" "" "" ""
}

# 读取 summary TSV，去重后批量校验，汇总为 rhsda-check JSON 报告
rhsda_check_summary() {
  local summary_file="$1"
  local output_file="$2"

  require_commands jq
  ensure_output_dirs

  local tmp_results seen_file
  tmp_results="$(mktemp)"
  seen_file="$(mktemp)"
  local count=0
  local cluster namespace deployment image registry remote tag cve severity component version
  local image_id product_cpe ocp_version label_name redhat_component rhsda_container_ids
  local key result

  log_info "checking RHSDA for entries in ${summary_file}"

  while IFS=$'\t' read -r cluster namespace deployment image registry remote tag cve severity component version \
      image_id product_cpe ocp_version label_name redhat_component rhsda_container_ids; do
    [[ "${cluster}" == "cluster" ]] && continue
    [[ -z "${cve}" ]] && continue

    key="${cve}|${registry}|${remote}|${tag}|${component}|${version}"
    if grep -Fxq "${key}" "${seen_file}" 2>/dev/null; then
      continue
    fi
    printf '%s\n' "${key}" >>"${seen_file}"

    result="$(evaluate_vuln_row "${cve}" "${component}" "${version}" \
      "${registry}" "${remote}" "${tag}" \
      "${product_cpe}" "${ocp_version}" "${label_name}" "${redhat_component}" "${rhsda_container_ids}")"
    echo "${result}" | jq -c \
      --arg cluster "${cluster}" --arg namespace "${namespace}" \
      --arg deployment "${deployment}" --arg image "${image}" \
      --arg registry "${registry}" --arg remote "${remote}" --arg tag "${tag}" \
      --arg severity "${severity}" \
      --arg image_id "${image_id}" --arg product_cpe "${product_cpe}" \
      --arg rhsda_container_ids "${rhsda_container_ids}" \
      '. + {
        cluster: $cluster, namespace: $namespace, deployment: $deployment, image: $image,
        registry: $registry, remote: $remote, tag: $tag, severity: $severity,
        image_id: $image_id, product_cpe: $product_cpe, rhsda_container_ids: $rhsda_container_ids
      }' \
      >>"${tmp_results}"

    count=$((count + 1))
    if ((count % 20 == 0)); then
      log_info "processed ${count} unique vulnerability rows..."
    fi
  done <"${summary_file}"

  local generated_at
  generated_at="$(timestamp_utc)"
  jq -s \
    --arg generated_at "${generated_at}" \
    --arg source_summary "${summary_file}" \
    --arg product_regex "${RHSDA_PRODUCT_REGEX}" \
    '{
      generated_at: $generated_at,
      source_summary: $source_summary,
      product_regex: $product_regex,
      results: .
    }' "${tmp_results}" >"${output_file}"
  rm -f "${tmp_results}" "${seen_file}"
  cleanup_cve_cache

  local fp defer skipped
  fp="$(jq '[.results[] | select(.decision == "candidate_fp")] | length' "${output_file}")"
  defer="$(jq '[.results[] | select(.decision == "candidate_defer")] | length' "${output_file}")"
  skipped="$(jq '[.results[] | select(.decision == "skipped")] | length' "${output_file}")"
  log_info "RHSDA check complete: ${fp} false-positive candidates, ${defer} deferral candidates, ${skipped} skipped -> ${output_file}"
  printf '%s\n' "${output_file}"
}
