# CLAUDE.md

本文件为 Claude Code 在此代码库中工作时提供指引。

## 概述

**Python 3.11+** 实现的 ACS 平台 CVE 例外自动化。从 ACS Central 导出 Platform Component 镜像 CVE，经 RHSDA **产品容器双轨匹配**校验后，创建 false-positive（不受影响/已修复）或 deferral（Fix deferred / Will not fix）。ACS 例外 comment 附带 RHSDA 证据摘要。

遗留 Bash 实现位于 `scripts/lib/`；**主入口为 Python**。

## 配置

```bash
cp config/example.env config/local.env
# 编辑 config/local.env：ROX_ENDPOINT、ROX_API_TOKEN
```

自动加载 `config/local.env`（或 `config/.env`、`.env`）。

## 运行

```bash
python3 -m acs run                              # 完整流水线
DRY_RUN=true python3 -m acs run               # 试运行
python3 -m acs export
python3 -m acs check --report data/reports/....summary.tsv
python3 -m acs apply --results data/results/rhsda-check-....json

# 等价包装脚本
./scripts/platform-fp-check.sh run
```

安装后可：`platform-fp-check run`（`pip install -e .`）

## 架构

```
acs/
  cli.py           export | check | apply | run
  config.py        Settings、env 加载
  common.py        容器 ID、产品上下文、comment、RPM 比较
  http_client.py   ACS / RHSDA HTTP（urllib）
  acs_api.py       workloads export → summary TSV
  rhsda_check.py   轨迹 A 容器直配 + 轨迹 B 组件匹配
  apply.py         POST false-positive / deferral + approve
```

**决策**：`candidate_fp` | `candidate_defer` | `skipped`

**去重键**：`(CVE, registry, remote, tag, component, version)`

## 必需环境变量

| 变量 | 用途 |
|---|---|
| `ROX_ENDPOINT` | ACS Central URL |
| `ROX_API_TOKEN` | Bearer 令牌 |

详见 `config/example.env`（`DEFER_EXPIRY_DAYS`、`ACS_ENRICH_LABELS` 等）。

## 依赖

- Python 3.11+（标准库 only）
- 可选：`rpm`（Linux 精确 EVR 比较）
