# ACS

ACS - Red Hat Advanced Cluster Security for Kubernetes  
Documentation: https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.10

## 开发原则

- **Python 3.11+** 实现主逻辑（标准库，无第三方依赖）
- Bash 脚本 [`scripts/platform-fp-check.sh`](scripts/platform-fp-check.sh) 为薄包装，内部调用 `python3 -m acs`
- 通过环境变量配置多 cluster（见 [`config/example.env`](config/example.env)）

## Platform CVE 例外自动化（False Positive + Deferral）

从 ACS 导出 **Platform Component** 漏洞，用 [Red Hat Security Data API](https://access.redhat.com/hydra/rest/securitydata/)（RHSDA）按**产品容器双轨匹配**校验 OpenShift 平台镜像 CVE，并自动创建 ACS 例外：

- **False positive**：RHSDA `Not affected` 或已修复
- **Deferral**：RHSDA `Fix deferred` 或 `Will not fix`（comment 中说明 RHSDA fix_state）

> **说明**：本工具处理 Platform Component **workload 镜像 CVE**，不是 Vulnerability Management → Platform CVEs 页面中的集群级 K8s/OpenShift CVE。

### 工作流程

```
ACS Central                          RHSDA                         ACS Central
    │                                  │                              │
    │  1. export platform vulns         │                              │
    ├─────────────────────────────────►│                              │
    │  data/reports/*.jsonl/.tsv        │                              │
    │                                  │  2. dual-track check         │
    │                                  │◄─────────────────────────────┤
    │                                  │  data/results/rhsda-check.*  │
    │                                  │                              │
    │                                  │  3. FP + deferral + approve  │
    │◄─────────────────────────────────────────────────────────────────┤
    │                                  │  data/results/exception-actions.* │
```

1. **export** — workloads 流式导出为主，`/v1/images/{id}` 按镜像补全 scan 与 Red Hat label
2. **check** — 轨迹 A（容器 remote/label → RHSDA package_name）优先；轨迹 B（产品上下文组件匹配）
3. **apply** — `candidate_fp` → false positive；`candidate_defer` → deferral（含 RHSDA 摘要 comment）

### 项目结构

```
acs/
├── acs/                          # Python 包
│   ├── cli.py                    # 主入口（export | check | apply | run）
│   ├── config.py                 # 环境变量与路径
│   ├── common.py                 # 镜像/RHSDA 匹配辅助函数
│   ├── acs_api.py                # ACS export + summary TSV
│   ├── rhsda_check.py            # RHSDA 双轨校验
│   └── apply.py                  # FP + deferral 创建与审批
├── scripts/
│   └── platform-fp-check.sh      # 调用 python3 -m acs 的包装脚本
├── config/
│   └── example.env
└── data/
```

### 依赖

- **Python 3.11+**（必需）
- `rpm`（可选，Linux 上用于更准确的 RPM 版本比较）

### 快速开始

```bash
cp config/example.env config/local.env
# 编辑 config/local.env，填入 ROX_ENDPOINT 和 ROX_API_TOKEN

source config/local.env

# 任选其一
python3 -m acs run
./scripts/platform-fp-check.sh run

# 首次建议 dry-run
DRY_RUN=true python3 -m acs run
```

也可通过 `--env` 指定配置文件：

```bash
./scripts/platform-fp-check.sh --env config/local.env run
```

### 命令说明

| 命令 | 说明 |
|------|------|
| `export` | 从 ACS 导出 Platform Component 漏洞，生成 JSONL 和 summary TSV |
| `check --report FILE` | 对 summary TSV（或 JSONL）中的 CVE 执行 RHSDA 校验 |
| `apply --results FILE` | 根据校验结果创建并审批 false positive 与 deferral |
| `run` | 依次执行 export → check → apply |

### 分步执行

```bash
# 1. 从 ACS 导出 platform 漏洞
./scripts/platform-fp-check.sh export
# 输出:
#   data/reports/platform-vulns-<cluster>-<timestamp>.jsonl   # 原始流
#   data/reports/platform-vulns-<cluster>-<timestamp>.summary.tsv  # 扁平化摘要

# 2. RHSDA 校验
./scripts/platform-fp-check.sh check \
  --report data/reports/platform-vulns-all-20260101T120000Z.summary.tsv
# 输出: data/results/rhsda-check-<timestamp>.json

# 3. 在 ACS 标记例外并审批
./scripts/platform-fp-check.sh apply \
  --results data/results/rhsda-check-<timestamp>.json
# 输出: data/results/exception-actions-<timestamp>.json
```

### ACS 导出说明

ACS 通过内置 namespace 规则识别 **Platform Component**（如 `openshift-*`、`stackrox`、`rhacs-operator`、`multicluster-engine` 等），详见 [RHACS 漏洞管理文档](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_security_for_kubernetes/4.8/html/operating/managing-vulnerabilities)。

使用的 API：

```bash
GET /v1/export/vuln-mgmt/workloads?query=Platform+Component%3Atrue
```

可选过滤（通过环境变量或修改 `ACS_EXPORT_QUERY`）：

- `+Cluster:<name>` — 限定 cluster（`ACS_CLUSTER_NAME` 会自动追加）
- `+CVE:<id>` — 限定单个 CVE（适合小范围测试）
- `+Severity:Critical Vulnerability` — 限定严重级别

summary TSV 列：`cluster`, `namespace`, `deployment`, `image`, `registry`, `remote`, `tag`, `cve`, `severity`, `component`, `version`, `image_id`, `product_cpe`, `ocp_version`, `label_name`, `redhat_component`, `rhsda_container_ids`

**数据源策略**：以 `GET /v1/export/vuln-mgmt/workloads` 为主（Platform Component 过滤 + deployment 上下文）；当镜像 `scan` 为空或缺少 Red Hat label 时，按镜像调用 `GET /v1/images/{id}` 补全（受 `ACS_ENRICH_MAX_IMAGES` 限制，默认 200）。

解析支持 ACS 4.9+ 的 `scan.imageVulnerabilities` / `scan.imageComponents` 结构，以及旧版 `vulnerabilities[]` 格式。

### RHSDA 校验逻辑（双轨匹配）

对每个唯一的 `(CVE, registry, remote, tag, component, version)` 调用 `GET /cve/<CVE-ID>.json`：

**轨迹 A — 容器直配（优先）**

- 用 `remote` 与 label `name`（`openshift/foo` → `openshift4/foo`）匹配 RHSDA `package_state.package_name` / 容器格式 `affected_release.package`
- Go 模块 CVE（`golang.org/*`、`github.com/*`、`stdlib`）**仅**走轨迹 A

**轨迹 B — 产品上下文组件匹配**

- 轨迹 A 无结论且非 Go 模块时，在产品上下文内用 RPM 组件名匹配（如 `cri-o`）

**产品上下文**：从镜像 CPE（如 `cpe:/a:redhat:openshift:4.20::el9`）推导，回退 `RHSDA_PRODUCT_REGEX`（默认含 OpenShift、RHCOS、CoreOS）。

| RHSDA 条件 | 决策 | ACS 动作 |
|-----------|------|----------|
| `Not affected` 或已修复 | `candidate_fp` | false positive |
| `Fix deferred` 或 `Will not fix` | `candidate_defer` | deferral |
| `Affected` / 无匹配 / 版本不确定 | `skipped` | 不写入 |

校验结果 JSON 含 `decision`、`rhsda_summary`（用于 ACS comment）、`rhsda_evidence`、`match_track`（`container` / `component`）。

### 例外应用逻辑

使用 ACS 4.10 v2 API：

- False positive：`POST /v2/vulnerability-exceptions/false-positive`
- Deferral：`POST /v2/vulnerability-exceptions/deferral`（`expiresOn` 由 `DEFER_EXPIRY_DAYS` 控制，默认 90 天）
- 审批：`POST /v2/vulnerability-exceptions/{id}/approve`

**Comment 规范**：create/approve 的 `comment` 由 `rhsda_summary` 自动生成，例如：

```
RHSDA fix_state Will not fix | product=Red Hat OpenShift Container Platform 4 | package=openshift4/ose-foo-rhel9 | match_track=container | CVE=CVE-2026-33186
```

策略：

- 按 image 聚合：同一 `(registry, remote, tag)` 的多个 CVE 合并为一次请求
- 提交前检查是否已有同 scope + CVE 的 PENDING/APPROVED 例外
- `DRY_RUN=true` 时只生成操作计划

### 环境变量

| 变量 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `ROX_ENDPOINT` | 是 | — | Central API 地址，如 `https://central.example.com:443` |
| `ROX_API_TOKEN` | 是 | — | API Token（见下方权限要求） |
| `ROX_INSECURE_SKIP_TLS_VERIFY` | 否 | `false` | 测试环境跳过 TLS 验证 |
| `ACS_CLUSTER_NAME` | 否 | — | 按 cluster 过滤导出 |
| `ACS_EXPORT_QUERY` | 否 | `Platform Component:true` | ACS 导出查询条件 |
| `RHSDA_BASE_URL` | 否 | `https://access.redhat.com/hydra/rest/securitydata` | RHSDA API 地址 |
| `RHSDA_PRODUCT_REGEX` | 否 | `OpenShift\|RHCOS\|...` | 产品匹配回退正则 |
| `DEFER_EXPIRY_DAYS` | 否 | `90` | deferral 过期天数 |
| `EXCEPTION_COMMENT_PREFIX` | 否 | `RHSDA` | ACS 例外 comment 前缀 |
| `ACS_ENRICH_LABELS` | 否 | `true` | 从 `/v1/images/{id}` 补全 Red Hat label |
| `ACS_ENRICH_MAX_IMAGES` | 否 | `200` | 补全镜像数量上限 |
| `RHSDA_TIMEOUT` | 否 | `30` | RHSDA 请求超时（秒） |
| `OUTPUT_DIR` | 否 | `./data` | 报告与结果输出目录 |
| `DRY_RUN` | 否 | `false` | `true` 时跳过 ACS 写操作 |
| `ACS_ENRICH_SCANS` | 否 | `true` | export 无 scan 时从 `/v1/images/{id}` 补全 |
| `ACS_API_TIMEOUT` | 否 | `300` | 普通 ACS API 超时（秒） |
| `ACS_EXPORT_TIMEOUT` | 否 | `900` | export 流式下载客户端超时（秒） |
| `ACS_EXPORT_SERVER_TIMEOUT` | 否 | `600` | export API 服务端 `timeout` 参数 |
| `HTTPS_PROXY` | 否 | — | 企业代理 |

完整模板见 [config/example.env](config/example.env)。脚本会自动加载 `config/local.env`（若存在）。

### 测试环境（Red Hat Workshops）

RHACS Console: `https://central-stackrox.apps.cluster-nfkmf.dynamic2.redhatworkshops.io`  
OpenShift API: `https://api.cluster-nfkmf.dynamic2.redhatworkshops.io:6443`

```bash
export ROX_ENDPOINT="https://central-stackrox.apps.cluster-nfkmf.dynamic2.redhatworkshops.io"
export ROX_INSECURE_SKIP_TLS_VERIFY="true"

# 用 admin 账号生成 API Token（勿写入 git）
curl -sk -u 'admin:<password>' -X POST "$ROX_ENDPOINT/v1/apitokens/generate" \
  -H 'Content-Type: application/json' \
  -d '{"name":"platform-fp-check","roles":["Admin"]}' | jq -r '.token'

export ROX_API_TOKEN="<上一步输出的 token>"
DRY_RUN=true ./scripts/platform-fp-check.sh run
```

**实测结果（2026-06-09）**

| 步骤 | 状态 | 说明 |
|------|------|------|
| export | 成功 | 223 条 platform workload 导出至 JSONL |
| summary | 0 条 CVE | 所有镜像 `scan: null`，Central 尚无 IMAGE CVE |
| check | 成功 | 0 candidates（无数据可校验） |
| apply API | 已验证 | `POST /v2/vulnerability-exceptions/false-positive` + approve 可用 |

该集群存在 **OPENSHIFT_CVE**（217 条）和 **NODE_CVE**（58 条），但 **IMAGE_CVE 为空**。需等待 Scanner 完成镜像扫描后，脚本才能提取 CVE 并执行完整流程。可在 RHACS UI 确认 Scanner 健康并等待扫描完成后再运行。

### API 权限

API Token 需包含：

- `Deployment`、`Image` 的 **view** 权限（导出漏洞）
- `VulnerabilityManagementRequests` **write**（创建 false positive 请求）
- `VulnerabilityManagementApprovals` **write**（自动审批）

建议使用 Admin 角色，或创建包含上述权限的自定义角色。

### 输出目录

```
data/
├── reports/
│   ├── platform-vulns-<cluster>-<timestamp>.jsonl       # ACS 原始导出
│   └── platform-vulns-<cluster>-<timestamp>.summary.tsv   # 扁平化摘要
└── results/
    ├── rhsda-check-<timestamp>.json    # RHSDA 校验结果
    └── exception-actions-<timestamp>.json  # FP/deferral 操作审计日志
```

`data/` 和 `config/*.env`（除 `example.env`）已加入 `.gitignore`，不会提交到仓库。

### 验证建议

1. `DRY_RUN=true ./scripts/platform-fp-check.sh run` — 检查导出条数与 `candidate_fp` / `candidate_defer` 分布
2. 用 `ACS_EXPORT_QUERY="Platform Component:true+CVE:<id>"` 做小范围实测
3. 在 ACS UI → Exception Management 确认 FP 与 Deferral 均为 **Approved**
4. 确认例外 comment 含 RHSDA product/package/fix_state 摘要

### 风险与边界

- **容器修复版本**：RHSDA 容器 fix 使用 internal build ID，digest tag 无法可靠比较时会 `skipped`
- **Go CVE**：仅容器直配；避免组件级 `grpc: Affected` 误匹配
- **Will not fix / Fix deferred**：创建 deferral（非 false positive），comment 说明 RHSDA fix_state
- **审批生效**：例外须经审批后才从报告和策略中排除
- **范围限定**：仅处理 Platform Component workload 镜像 CVE

## Red Hat Security Data API

**Red Hat Security Data API** 是红帽官方提供的 RESTful 接口，用于获取 RHEL、OpenShift 等产品的 CVE 与补丁信息。

Base URL:

```
https://access.redhat.com/hydra/rest/securitydata/
```

文档: https://docs.redhat.com/en/documentation/red_hat_security_data_api/1.0/html-single/red_hat_security_data_api/index

本仓库通过 `scripts/lib/rhsda.sh` 调用该 API。也可单独使用：

```bash
./scripts/lib/rhsda.sh get-cve CVE-2014-0160
```
