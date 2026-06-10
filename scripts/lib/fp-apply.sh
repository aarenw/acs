#!/usr/bin/env bash
# =============================================================================
# fp-apply.sh — ACS 漏洞例外创建与审批（false positive + deferral）
#
# 使用 ACS 4.10 v2 API:
#   POST /v2/vulnerability-exceptions/false-positive
#   POST /v2/vulnerability-exceptions/deferral
#   POST /v2/vulnerability-exceptions/{id}/approve
#
# comment 由 RHSDA rhsda_summary 动态生成
# =============================================================================
set -euo pipefail

FP_APPLY_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${FP_APPLY_LIB_DIR}/common.sh"
# shellcheck source=acs-api.sh
source "${FP_APPLY_LIB_DIR}/acs-api.sh"

list_existing_exceptions() {
  acs_curl GET "/v2/vulnerability-exceptions?pagination.limit=1000"
}

# 检查是否已有同 image scope + CVE 的例外（FP 或 deferral）
exception_already_exists() {
  local registry="$1"
  local remote="$2"
  local tag="$3"
  local cve="$4"
  local target_state="$5"
  local existing_json="$6"

  echo "${existing_json}" | jq -e --arg reg "${registry}" --arg rem "${remote}" --arg tg "${tag}" \
    --arg cve "${cve}" --arg target "${target_state}" '
    .exceptions[]?
    | select(.targetState == $target or .target_state == $target)
    | select(.status == "PENDING" or .status == "APPROVED" or .status == "APPROVED_PENDING_UPDATE")
    | select(
        (.scope.imageScope.registry // .scope.image_scope.registry // "") == $reg
        and (.scope.imageScope.remote // .scope.image_scope.remote // "") == $rem
        and (.scope.imageScope.tag // .scope.image_scope.tag // "") == $tg
      )
    | select(.cves[]? == $cve)
  ' >/dev/null 2>&1
}

create_false_positive() {
  local registry="$1"
  local remote="$2"
  local tag="$3"
  local cves_json="$4"
  local comment="$5"

  local body
  body="$(jq -n \
    --argjson cves "${cves_json}" \
    --arg registry "${registry}" \
    --arg remote "${remote}" \
    --arg tag "${tag}" \
    --arg comment "${comment}" \
    '{
      cves: $cves,
      scope: { imageScope: { registry: $registry, remote: $remote, tag: $tag } },
      comment: $comment
    }')"

  acs_curl POST "/v2/vulnerability-exceptions/false-positive" "${body}"
}

create_deferral() {
  local registry="$1"
  local remote="$2"
  local tag="$3"
  local cves_json="$4"
  local comment="$5"
  local expires_on="$6"

  local body
  body="$(jq -n \
    --argjson cves "${cves_json}" \
    --arg registry "${registry}" \
    --arg remote "${remote}" \
    --arg tag "${tag}" \
    --arg comment "${comment}" \
    --arg expires_on "${expires_on}" \
    '{
      cves: $cves,
      scope: { imageScope: { registry: $registry, remote: $remote, tag: $tag } },
      comment: $comment,
      expiresOn: $expires_on
    }')"

  acs_curl POST "/v2/vulnerability-exceptions/deferral" "${body}"
}

approve_exception() {
  local id="$1"
  local comment="$2"
  local body
  body="$(jq -n --arg id "${id}" --arg comment "${comment}" '{id:$id, comment:$comment}')"
  acs_curl POST "/v2/vulnerability-exceptions/${id}/approve" "${body}"
}

# 从同组结果行选取代表性 rhsda_summary 用于 batch comment
pick_group_rhsda_summary() {
  local results_file="$1"
  local registry="$2"
  local remote="$3"
  local tag="$4"
  local decision="$5"

  jq -c --arg reg "${registry}" --arg rem "${remote}" --arg tg "${tag}" --arg dec "${decision}" '
    [.results[]
      | select(.decision == $dec)
      | select(.registry == $reg and .remote == $rem and .tag == $tg)
      | .rhsda_summary // {}
    ][0] // {}
  ' "${results_file}"
}

process_exception_group() {
  local exception_type="$1"
  local target_state="$2"
  local registry="$3"
  local remote="$4"
  local tag="$5"
  local cves_csv="$6"
  local results_file="$7"
  local existing_json="$8"
  local expires_on="${9:-}"

  local -a actions=()
  local cves_json action comment approve_comment
  cves_json="$(printf '%s' "${cves_csv}" | tr ',' '\n' | jq -R . | jq -s .)"

  local summary_json
  if [[ "${exception_type}" == "deferral" ]]; then
    summary_json="$(pick_group_rhsda_summary "${results_file}" "${registry}" "${remote}" "${tag}" "candidate_defer")"
  else
    summary_json="$(pick_group_rhsda_summary "${results_file}" "${registry}" "${remote}" "${tag}" "candidate_fp")"
  fi
  comment="$(format_rhsda_exception_comment "${summary_json}" "${exception_type}")"
  if [[ "${cves_csv}" == *","* ]]; then
    comment="${comment} | CVEs=${cves_csv}"
  fi
  approve_comment="${comment} (auto-approved)"

  local new_cves=()
  local cve
  for cve in $(echo "${cves_csv}" | tr ',' ' '); do
    if exception_already_exists "${registry}" "${remote}" "${tag}" "${cve}" "${target_state}" "${existing_json}"; then
      action="$(jq -n \
        --arg registry "${registry}" --arg remote "${remote}" --arg tag "${tag}" --arg cve "${cve}" \
        --arg exception_type "${exception_type}" \
        '{status:"skipped", reason:"existing exception", exception_type:$exception_type, registry:$registry, remote:$remote, tag:$tag, cve:$cve}')"
      actions+=("${action}")
    else
      new_cves+=("${cve}")
    fi
  done

  if ((${#new_cves[@]} == 0)); then
    printf '%s\n' "${actions[@]}"
    return 0
  fi

  cves_json="$(printf '%s\n' "${new_cves[@]}" | jq -R . | jq -s .)"

  if [[ "${DRY_RUN}" == "true" ]]; then
    action="$(jq -n \
      --arg registry "${registry}" --arg remote "${remote}" --arg tag "${tag}" \
      --arg exception_type "${exception_type}" --arg comment "${comment}" \
      --argjson cves "${cves_json}" \
      '{status:"dry_run", exception_type:$exception_type, registry:$registry, remote:$remote, tag:$tag, cves:$cves, comment:$comment}')"
    actions+=("${action}")
    printf '%s\n' "${actions[@]}"
    return 0
  fi

  local created="" approved_id="" status="failed" err_msg=""
  if [[ "${exception_type}" == "deferral" ]]; then
    if created="$(create_deferral "${registry}" "${remote}" "${tag}" "${cves_json}" "${comment}" "${expires_on}" 2>&1)"; then
      :
    else
      err_msg="${created}"
      action="$(jq -n \
        --arg registry "${registry}" --arg remote "${remote}" --arg tag "${tag}" \
        --argjson cves "${cves_json}" --arg error "${err_msg}" --arg exception_type "${exception_type}" \
        '{status:"failed", exception_type:$exception_type, registry:$registry, remote:$remote, tag:$tag, cves:$cves, error:$error}')"
      actions+=("${action}")
      printf '%s\n' "${actions[@]}"
      return 0
    fi
  else
    if created="$(create_false_positive "${registry}" "${remote}" "${tag}" "${cves_json}" "${comment}" 2>&1)"; then
      :
    else
      err_msg="${created}"
      action="$(jq -n \
        --arg registry "${registry}" --arg remote "${remote}" --arg tag "${tag}" \
        --argjson cves "${cves_json}" --arg error "${err_msg}" --arg exception_type "${exception_type}" \
        '{status:"failed", exception_type:$exception_type, registry:$registry, remote:$remote, tag:$tag, cves:$cves, error:$error}')"
      actions+=("${action}")
      printf '%s\n' "${actions[@]}"
      return 0
    fi
  fi

  approved_id="$(echo "${created}" | jq -r '.exception.id // .id // empty')"
  if [[ -n "${approved_id}" ]]; then
    local approve_resp
    if approve_resp="$(approve_exception "${approved_id}" "${approve_comment}" 2>&1)"; then
      local approved_status
      approved_status="$(echo "${approve_resp}" | jq -r '.exception.status // .status // empty')"
      if [[ "${approved_status}" == "APPROVED" ]]; then
        status="approved"
      else
        status="created_pending"
        err_msg="approve returned status: ${approved_status:-unknown}"
      fi
    else
      status="created_pending"
      err_msg="approve failed: ${approve_resp}"
    fi
  else
    status="created_unknown_id"
    err_msg="missing exception id in response"
  fi

  action="$(echo "${created}" | jq \
    --arg status "${status}" --arg err_msg "${err_msg}" --arg approved_id "${approved_id}" \
    --arg registry "${registry}" --arg remote "${remote}" --arg tag "${tag}" \
    --arg exception_type "${exception_type}" --arg comment "${comment}" \
    --argjson cves "${cves_json}" \
    '{status:$status, exception_type:$exception_type, registry:$registry, remote:$remote, tag:$tag, cves:$cves, comment:$comment, approved_id:$approved_id, response:., error:(if $err_msg == "" then null else $err_msg end)}')"
  actions+=("${action}")
  printf '%s\n' "${actions[@]}"
}

# 读取 rhsda-check 结果，创建并审批 false positive / deferral，写审计日志
fp_apply_results() {
  local results_file="$1"
  local output_file="$2"

  require_commands jq
  require_acs_env
  ensure_output_dirs

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_warn "DRY_RUN=true: skipping ACS create/approve operations"
  fi

  local existing_json='{"exceptions":[]}'
  if [[ "${DRY_RUN}" != "true" ]]; then
    existing_json="$(list_existing_exceptions)"
  fi

  local expires_on
  expires_on="$(defer_expires_on)"

  local fp_groups defer_groups
  fp_groups="$(mktemp)"
  defer_groups="$(mktemp)"

  jq -r '
    [.results[] | select(.decision == "candidate_fp")]
    | group_by(.registry + "|" + .remote + "|" + .tag)
    | .[]
    | [.registry, .remote, .tag, ([.[].cve] | unique | join(","))] | @tsv
  ' "${results_file}" >"${fp_groups}"

  jq -r '
    [.results[] | select(.decision == "candidate_defer")]
    | group_by(.registry + "|" + .remote + "|" + .tag)
    | .[]
    | [.registry, .remote, .tag, ([.[].cve] | unique | join(","))] | @tsv
  ' "${results_file}" >"${defer_groups}"

  local -a actions=()
  local registry remote tag cves_csv group_actions action line

  while IFS=$'\t' read -r registry remote tag cves_csv; do
    [[ -z "${registry}" ]] && continue
    while IFS= read -r line; do
      [[ -z "${line}" ]] && continue
      actions+=("${line}")
    done < <(process_exception_group "false_positive" "FALSE_POSITIVE" \
      "${registry}" "${remote}" "${tag}" "${cves_csv}" "${results_file}" "${existing_json}")
  done <"${fp_groups}"

  while IFS=$'\t' read -r registry remote tag cves_csv; do
    [[ -z "${registry}" ]] && continue
    while IFS= read -r line; do
      [[ -z "${line}" ]] && continue
      actions+=("${line}")
    done < <(process_exception_group "deferral" "DEFERRED" \
      "${registry}" "${remote}" "${tag}" "${cves_csv}" "${results_file}" "${existing_json}" "${expires_on}")
  done <"${defer_groups}"

  rm -f "${fp_groups}" "${defer_groups}"

  local generated_at
  generated_at="$(timestamp_utc)"
  {
    echo "{"
    echo "  \"generated_at\": \"${generated_at}\","
    echo "  \"source_results\": \"${results_file}\","
    echo "  \"dry_run\": $([[ "${DRY_RUN}" == "true" ]] && echo true || echo false),"
    echo "  \"defer_expires_on\": \"${expires_on}\","
    echo "  \"actions\": ["
    local i
    for i in "${!actions[@]}"; do
      echo "    ${actions[$i]}$([[ $i -lt $((${#actions[@]} - 1)) ]] && echo ',')"
    done
    echo "  ]"
    echo "}"
  } | jq '.' >"${output_file}"

  log_info "exception apply log -> ${output_file}"
  printf '%s\n' "${output_file}"
}

# 别名
exception_apply_results() {
  fp_apply_results "$@"
}
