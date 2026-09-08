# Phase 3.4.5-G2 — Production Version Evidence

> **状态：REVIEWED — Evidence Inventory** — 取证盘点已复核；记录证据、版本结论、缺口与后续 Gate 依赖。
> **本文档非 FROZEN。** 三侧 Target Runtime 全部 UNKNOWN；**取证工作完成 ≠ 生产版本认证完成**（未取得任何目标实例版本证据）。

## 0. 文档控制区（Document Control）

| 字段 | 值 |
| --- | --- |
| 文档状态 | **REVIEWED — Evidence Inventory**（取证盘点已复核；非 FROZEN；生产版本认证未完成） |
| 收口授权 | M1 里程碑 §2（G2 DOC CLOSURE）：DRAFT → REVIEWED，单独本地前向文档提交，NO PUSH |
| G2 原始授权范围 | READ-ONLY EVIDENCE + ONE DRAFT DOCUMENT · NO CODE · NO COMMIT |
| 授权基线提交 | `7210f610dbdd0b4db9e55f161c9d79fb6cbfcf60`（G1-D） |
| 采集日期 | 2026-09-08 |
| 采集方式 | 只读：`git`（只读子命令）+ 文件读取/grep + 目录列举；**无任何网络请求、无写入、无提交** |
| 覆盖对象 | Wazuh、Shuffle、TheHive 三侧 Adapter 的目标版本证据 |
| 唯一交付物 | 本文件（新增），路径 `docs/design/phase3.4.5-g2-production-version-evidence.md` |
| 保护约束 | 不修改 Consolidation / G1-A / G1-B 或任何已封板历史文档；不修改代码/测试/mapping/migration/配置 |

**本轮目标（What this Gate IS）**：确认“实际目标环境运行什么版本”，建立三域版本证据矩阵，为 G3/G4/G5 及未来真实 Reader 的独立设计提供可靠输入。

**本轮非目标（What this Gate IS NOT）**：
- 不证明任何 API 语义“已经可用”；
- 不开发真实外部闭环、不创建 Reader；
- 不认证 FINISHED/SUCCESS/FAILURE/ABORTED 等效果语义；
- 不修复 TheHive `case_id`/`_id`/`id`/`caseId`/409 幂等 reference 缺陷；
- 不为填满矩阵而临时部署生产系统、猜测版本或以本地源码冒充实际运行版本；
- 不索取 API key / password / JWT / callback token 等任何凭据。

---

## 1. 基线只读确认（Baseline Confirmation）

开始前已只读确认仓库现状，与授权基线一致，**未发现偏移**，因此继续取证。

| 核验项 | 只读命令 | 结果 |
| --- | --- | --- |
| HEAD | `git -C <repo> rev-parse HEAD` | `7210f610dbdd0b4db9e55f161c9d79fb6cbfcf60` ✅ 与授权基线一致 |
| branch | `git -C <repo> rev-parse --abbrev-ref HEAD` | `main` |
| ahead/behind | `git -C <repo> rev-list --left-right --count origin/main...HEAD` | `0`（behind） / `24`（ahead）→ ahead 24, behind 0 |
| 工作树 | `git -C <repo> status --porcelain` | 空（clean，无未跟踪/未暂存改动） |
| 分支追踪 | `git -C <repo> status -sb` | `## main...origin/main [ahead 24]` |
| 三份 G1 文档 | `Get-ChildItem docs/design` | `phase3.4.5-external-adapter-evidence-consolidation.md`、`...-g1-a-...-evidence-report.md`、`...-g1-b-...-remediation-design.md` 均在位 |
| 近 3 提交 | `git -C <repo> log --oneline -3` | `7210f61` G1-D / `0c372aa` G1-C / `73b9c8b` B0.1 |
| G2 目标文件 | `Test-Path ...g2-production-version-evidence.md` | 采集前 `ABSENT`（本文件为唯一新增） |

> 基线一致性结论：**PASS**。未触发“若基线不一致则停止并报告”的中止条件。未执行任何清理/重置/修改。

---

## 2. 证据优先级与三域隔离（Evidence Priority & Domain Isolation）

### 2.1 证据优先级（高 → 低，严格遵守）

1. 目标实例实际契约证据（version 端点响应 / 镜像 digest / 权威运行时报告）
2. 对应精确版本的权威源码 / 规范
3. 对应版本的官方文档
4. 部署模板（compose / Dockerfile / image tag / 部署配置）
5. 本地源码推断
6. 历史设计假设

### 2.2 三域定义（每个 Adapter 独立记录，不得互相冒充）

| 域 | 含义 | 本项目可用证据来源 |
| --- | --- | --- |
| **Source Version** | 本地被审计源码的版本 / commit / build / 依赖证据 | in-tree 版本文件（`VERSION.json` / `package.json` / `build.sbt` / `go.mod`） |
| **Deployment Template Version** | compose / Dockerfile / image tag / digest / 部署配置等**模板**证据 | 各仓库 `docker-compose.yml`、`build-images.sh`、`docker.sbt` |
| **Target Runtime Version** | 实际目标环境的版本 / build / 镜像 digest / 权威运行时报告 | **本项目当前无此域证据**（见 §3） |

### 2.3 隔离规则（硬约束）

- README、`latest` tag、`go.mod`、源码 `VERSION` 文件、历史测试**不能单独证明真实部署版本**。
- **不得因为 Source / Template 已确认，就将 Target Runtime 标记 CONFIRMED。**
- Wazuh 的 **Manager 与 Indexer 必须分别核对**，不得视为同一版本。

---

## 3. 目标环境确认（Target Environment Confirmation）

### 3.1 只读核查结论

对 `sentinelflow` 本仓库进行了目标运行环境 / 部署清单 / 已授权测试环境 / 生产实例的只读核查，结论为：

> **本轮未识别到明确目标实例，且未取得目标实例证据。** 三侧 Adapter 均无环境名称、无部署方式、无版本证据来源、无责任人可记录。

据此，按授权 §4 明确标记（三侧一致）：

> **`Target Runtime = UNKNOWN — no target instance evidence available`**

### 3.2 支撑证据（全部只读，无敏感配置外泄）

| 证据 ID | 证据路径 | 只读观察 | 对命题的作用 |
| --- | --- | --- | --- |
| ENV-01 | `sentinelflow/docker-compose.yml` | 服务仅 `postgres:16-alpine`（`sf-postgres`）；**无 wazuh / shuffle / thehive 任何服务** | 无本地编排的适配器目标实例 |
| ENV-02 | `sentinelflow/backend/app/core/config.py:46` | `EXECUTION_ADAPTER: str = "mock"`（默认；`shuffle/wazuh/thehive` 为保留注册值，未实现前触发 `ConfigError`） | 默认走离线 DryRun，不指向任何真实实例 |
| ENV-03 | `config.py:93-102` | `SHUFFLE_BASE_URL="" / SHUFFLE_API_KEY="" / WAZUH_BASE_URL="" / WAZUH_API_USER="" / WAZUH_API_PASSWORD="" / THEHIVE_BASE_URL="" / THEHIVE_API_KEY=""`（全空，fail-closed） | 无任何已配置的目标端点 |
| ENV-04 | `config.py:143-145` | `SHUFFLE_CALLBACK_TOKEN="" / WAZUH_CALLBACK_TOKEN="" / THEHIVE_CALLBACK_TOKEN=""`（全空） | 无入站回调身份配置 |
| ENV-05 | `sentinelflow/.env`（活动配置） | 仅 `DATABASE_URL`（本地）、`VITE_API_BASE_URL=http://localhost:8000`、`AI_PROVIDER=ollama`、`AI_BASE_URL=http://localhost:11434`；**无 `EXECUTION_ADAPTER`、无任何 `*_BASE_URL` 适配器覆盖** | `.env` 未覆盖 mock 默认；无真实适配器端点 |
| ENV-06 | `sentinelflow/.env.example`（模板） | `EXECUTION_ADAPTER=mock`；`SHUFFLE_BASE_URL=` / `WAZUH_BASE_URL=` / `THEHIVE_BASE_URL=` 均为空 | 模板亦未提供任何目标版本/端点 |
| ENV-07 | `infrastructure/{compose,docker,scripts}` | 三目录**仅含 `.gitkeep`**，无任何部署清单/编排文件 | 无部署模板落地 |
| ENV-08 | `integrations/{ai,shuffle,thehive,wazuh}` | 四目录**仅含 `.gitkeep`**，无集成实现 | 无适配器实例化配置 |
| ENV-09 | `workflows/` | **仅含 `.gitkeep`** | 无真实 workflow 定义 |

### 3.3 合规声明

本轮**未**为填满矩阵而临时部署生产系统、未猜测版本、未以本地源码代替实际运行版本、未索取任何 API key / password / JWT / callback token，**未**对任何真实实例发起网络请求。

---

## 4. 跨侧共性限制：Sibling 仓库溯源缺失（Provenance Limitation）

| 证据 ID | 只读命令 | 结果 |
| --- | --- | --- |
| PROV-01 | `git -C <sibling> rev-parse --short HEAD`（对 `wazuh-main` / `wazuh-docker-main` / `Shuffle-main` / `TheHive-main` / `ollama-main`） | **五个仓库全部** `fatal: not a git repository` |

**结论与影响（作为对全部 Source Version 主张的常设限制条件）**：

- 四个（含 ollama 共五个）外部仓库均为 GitHub `-main` 分支的**源码快照（ZIP drop）**，本地**无 `.git`**。
- 因此本地**无法取得 commit hash / tag / 镜像 digest 级别的溯源**；`git describe`、`git log`、tag 校验均不可用。
- **Source Version 只能由 in-tree 版本文件确立**（`VERSION.json` / `package.json` / `build.sbt` / `go.mod`），其证明力上限为“该源码快照自述的版本号”，**不等于**精确 commit 或可复现 build。
- 该限制适用于 §5/§6/§7 中每一条 Source Version 记录，并在 §8 矩阵的“限制条件”列逐条复述。

---

## 5. Wazuh 取证（Manager 与 Indexer 分离）

### 5.1 Source Version

| 证据 ID | 证据路径 | 只读观察 |
| --- | --- | --- |
| WAZ-SRC-01 | `wazuh-main/VERSION.json` | `{ "version": "5.1.0", "stage": "alpha0" }` |
| WAZ-SRC-02 | `wazuh-docker-main/VERSION.json` | `{ "version": "5.1.0", "stage": "alpha0" }`（与源码仓库一致） |

- **Source Version 结论**：`5.1.0-alpha0`（预发布 stage）。
- **限制条件**：受 §4 PROV-01 约束——无 commit/tag 溯源；`VERSION.json` 为源码快照自述值，非精确 build。
- **认证状态**：**PARTIAL**（源码自述版本明确，但无 commit/digest 级溯源，且非目标运行时）。

### 5.2 Deployment Template Version（Manager / Indexer / Dashboard / Agent 分列）

| 证据 ID | 证据路径 | 组件 | image 行 |
| --- | --- | --- | --- |
| WAZ-TPL-01 | `wazuh-docker-main/single-node/docker-compose.yml:4` | **Manager** | `wazuh/wazuh-manager:5.1.0` |
| WAZ-TPL-02 | `single-node/docker-compose.yml:47` | **Indexer** | `wazuh/wazuh-indexer:5.1.0` |
| WAZ-TPL-03 | `single-node/docker-compose.yml:84` | Dashboard | `wazuh/wazuh-dashboard:5.1.0` |
| WAZ-TPL-04 | `wazuh-docker-main/multi-node/docker-compose.yml:4,47` | **Manager**（×2 节点） | `wazuh/wazuh-manager:5.1.0` |
| WAZ-TPL-05 | `multi-node/docker-compose.yml:86,124,162` | **Indexer**（×3 节点） | `wazuh/wazuh-indexer:5.1.0` |
| WAZ-TPL-06 | `multi-node/docker-compose.yml:200` | Dashboard | `wazuh/wazuh-dashboard:5.1.0` |
| WAZ-TPL-07 | `wazuh-docker-main/wazuh-agent/docker-compose.yml:4` | Agent | `wazuh/wazuh-agent:5.1.0` |
| WAZ-TPL-08 | `wazuh-docker-main/build-docker-images/build-images.sh:11-12,18,47,67-81` | 构建脚本 | `WAZUH_IMAGE_VERSION=5.1.0`、`IMAGE_TAG=5.1.0`、`WAZUH_DEV_STAGE=""`、`WAZUH_STAGE=$(jq -r '.stage' ../VERSION.json)`；据 v5.1.0 GitHub release 是否存在选择 production / pre-release(alpha0) artifact |

- **Template Version 结论**：全部组件使用 **`5.1.0` 浮动 tag（无 digest pin）**。
- **关键歧义**：模板 tag `5.1.0` 语义上指向 GA，而源码 `VERSION.json` 为 `5.1.0-alpha0`；`build-images.sh` 表明**同一 `5.1.0` tag 可对应 production 或 pre-release(alpha0) 两种 artifact**，取决于构建时 release 是否存在。
- **Manager vs Indexer**：二者在模板中同为 `:5.1.0`，但为**不同镜像、不同组件**，运行时版本须**分别**核对，不得合并。
- **限制条件**：浮动 tag 无 digest → 无法从模板确定被拉取镜像的精确 build；模板 tag ≠ 目标运行时实际版本。
- **认证状态**：**PARTIAL**（模板 tag 明确，但无 digest，且非目标运行时）。

### 5.3 Target Runtime Version

> **`Target Runtime = UNKNOWN — no target instance evidence available`**

- 无目标 Wazuh Manager / Indexer 实例（§3）；无 `GET /` 版本端点响应、无 `docker inspect` digest、无 `wazuh-control -V` / indexer 版本输出。
- **认证状态**：**UNKNOWN**。
- **缺失证据**：目标实例的 Manager 版本/build、Indexer 版本/build、镜像 digest（三者须分别提供）。

### 5.4 B0 / B0.1 历史版本结论复核

| 复核项 | 历史结论（`phase3.4-wazuh-mapping-amendment.md` §38-49, B0/B0.1） | 本轮所见证据 | 是否仍适用 |
| --- | --- | --- | --- |
| Source | `5.1.0-alpha0`（仅证明仓库源码） | WAZ-SRC-01/02 = `5.1.0`/`alpha0` | **仍适用** ✅ |
| Template | `5.1.0` GA tag，与审计对象 stage 不一致 | WAZ-TPL-01..08 = `:5.1.0` 浮动 tag | **仍适用** ✅ |
| Production | UNKNOWN | §3 无目标实例 | **仍适用** ✅ |
| 版本确认路径 | live API `GET /` / `docker inspect` / `wazuh-control -V` + indexer 版本，仅需 version/build，绝不索取凭据 | 与本轮 §13 请求一致 | **仍适用** ✅ |

- **结论**：B0/B0.1 版本结论对本轮所见证据**仍然成立，无需前向更新**。本轮**未发现与该文档冲突的新证据**；如后续 Review 认为需要，可由 Review 决定是否前向更新（本轮仅在 G2 登记，不改历史文档）。

### 5.5 Wazuh 冲突登记

- **WAZ-CONFLICT-01（source vs template stage）**：源码 `5.1.0-alpha0` ↔ 模板 tag `5.1.0`（GA 语义）；且 `build-images.sh` 允许同一 tag 对应 production 或 alpha0 artifact。**状态：CONFLICT（尚未由目标实例证据解释）**。
- 影响：在取得目标实例 Manager/Indexer 的真实 build/digest 前，**无法判定**目标运行的是 GA 还是 alpha0，也无法判定 Manager 与 Indexer 是否同 build。

### 5.6 G1-C 状态词表不变声明

- 本轮**未触碰** `reconciliation.py` 的 `ADAPTER_STATE_VOCABULARIES["wazuh"]`；G1-C 的四集清空（fail-closed）**保持不变**。
- 按授权 §5：**不得**将 agent liveness、Active Response 触发记录、内部 task ID、派发受理结果认证为“命令效果”。本轮**未**做任何此类认证。

---

## 6. Shuffle 取证

### 6.1 Source Version

| 证据 ID | 证据路径 | 只读观察 |
| --- | --- | --- |
| SHF-SRC-01 | `Shuffle-main/frontend/package.json:2,4` | `"name": "shuffler"`, `"version": "2.0.0"` |
| SHF-SRC-02 | `Shuffle-main/backend/go-app/go.mod:1,3,27` | `module shuffle`、`go 1.25.0`、`github.com/shuffle/shuffle-shared v1.2.51`；第 5 行有**被注释**的 `//replace ... => ../../../shuffle-shared` |
| SHF-SRC-03 | `Shuffle-main/functions/onprem/worker/go.mod:1,3,12,13` | `module worker`、`go 1.25.0`、`shuffle-shared v1.2.45`、`github.com/shuffle/singul v0.0.32`；第 5-6 行有**被注释**的 replace 指令 |

- **Source Version 结论**：frontend `2.0.0`；backend 依赖 `shuffle-shared v1.2.51`；worker 依赖 `shuffle-shared v1.2.45` + `singul v0.0.32`。
- **限制条件**：受 §4 PROV-01 约束——无 commit/tag 溯源；`shuffle-shared` 未 vendored（工作区无该目录，replace 指令均被注释）→ 无法在本地核对其精确源码。
- **认证状态**：**PARTIAL**。

### 6.2 Deployment Template Version

| 证据 ID | 证据路径 | 只读观察 |
| --- | --- | --- |
| SHF-TPL-01 | `Shuffle-main/docker-compose.yml:3` | `ghcr.io/shuffle/shuffle-frontend:latest` |
| SHF-TPL-02 | `docker-compose.yml:17` | `ghcr.io/shuffle/shuffle-backend:latest` |
| SHF-TPL-03 | `docker-compose.yml:36` | `ghcr.io/shuffle/shuffle-orborus:latest` |
| SHF-TPL-04 | `docker-compose.yml:64` | `opensearchproject/opensearch:3.2.0`（**唯一 pinned** 版本） |
| SHF-TPL-05 | `docker-compose.yml:98,115,129` | `cadvisor:latest` / `memcached:latest` / `tecnativa/docker-socket-proxy` 均**被注释**（未启用） |

- **Template Version 结论**：三个 Shuffle 组件（frontend/backend/orborus）全部使用 **`latest` 浮动 tag（无版本号、无 digest）**；仅 OpenSearch 固定为 `3.2.0`。
- **精确更正**：`docker-compose.yml` **不含独立的 `shuffle-worker` image 服务**——worker 在源码树中存在（`functions/onprem/worker`），但在编排中由 **orborus 运行时派生**，非独立 compose 服务。
- **限制条件**：`latest` 无版本/无 digest → **模板无法确立任何精确版本**；README/latest tag 不得单独证明部署版本（§2.3）。
- **认证状态**：**UNKNOWN**（模板仅提供 `latest`，无版本维度可确认）。

### 6.3 Target Runtime Version

> **`Target Runtime = UNKNOWN — no target instance evidence available`**

- 无目标 Shuffle 实例（§3）；无镜像 digest、无 `/api/v1/...` 版本响应、无 commit 溯源。
- **认证状态**：**UNKNOWN**。

### 6.4 shuffle-shared 依赖关系与冲突

- **SHF-CONFLICT-01（shuffle-shared 版本分叉）**：backend `go.mod` 依赖 **`v1.2.51`**，worker `go.mod` 依赖 **`v1.2.45`** —— 同一仓库内两个 Go 模块引用**不同 shuffle-shared 版本**。**状态：CONFLICT（尚未解释）**。
- 影响：`shuffle-shared` 承载数据模型（含 WorkflowExecution 等 schema）；backend 与 worker 若运行在不同 shared 版本，其 schema/序列化契约**可能不一致**。在未取得目标实例实际运行版本前，无法判定目标环境使用的是哪一个 shared 版本。

### 6.5 权威 WorkflowExecution schema 可定位性

- **可定位性结论：无法在当前证据下定位到与目标运行时对应的精确 schema 版本。**
- 依据：(a) `shuffle-shared` 未 vendored（工作区无源码），无法本地读取 `WorkflowExecution` 结构定义；(b) 源码内 shared 版本分叉（v1.2.51 vs v1.2.45，SHF-CONFLICT-01）；(c) 模板与目标运行时均为 `latest`/UNKNOWN，无 digest 锚定。
- **缺失证据**：目标实例实际运行的 `shuffle-shared` 版本 + 对应 tag/commit 的权威 schema 定义（`WorkflowExecution` 字段集与状态枚举）。

### 6.6 Shuffle 非目标声明

按授权 §5，本轮**仅确认版本与证据来源**：
- **不**认证 FINISHED / SUCCESS / FAILURE / ABORTED 等效果语义；
- **不**设计组合 reference；
- **不**创建 Reader。

---

## 7. TheHive 取证

### 7.1 Source Version

| 证据 ID | 证据路径 | 只读观察 |
| --- | --- | --- |
| THV-SRC-01 | `TheHive-main/build.sbt:5` | `val thehiveVersion = "4.1.24-1"`（所有模块 `version := thehiveVersion`，见 :85,156,181,192,206,263,278,289,301,317） |
| THV-SRC-02 | `build.sbt:6,10,11` | `scala212 = "2.12.13"`、`organization in ThisBuild := "org.thp"`、`scalaVersion := scala212` |
| THV-SRC-03 | `TheHive-main/CHANGELOG.md:3` | 顶部条目 `## [4.1.24] (2022-09-12)`（与 build.sbt 版本一致） |
| THV-SRC-04 | `TheHive-main/debian.sbt` | 打包名 `thehive4`（4.x 系列） |

- **Source Version 结论**：`4.1.24-1`（Scala 2.12.13，`org.thp`）。
- **限制条件**：受 §4 PROV-01 约束——无 commit/tag 溯源；`4.1.24-1` 为源码快照自述值。
- **认证状态**：**PARTIAL**。

### 7.2 Deployment Template Version

| 证据 ID | 证据路径 | 只读观察 |
| --- | --- | --- |
| THV-TPL-01 | `TheHive-main/docker.sbt:14` | `dockerRepository := Some("thehiveproject")`（镜像仓库 `thehiveproject/thehive`） |
| THV-TPL-02 | `docker.sbt:4-12` | `version in Docker` 由 `version.value` 推导（stable/beta/snapshot 分支）→ 与 `thehiveVersion=4.1.24-1` 绑定 |
| THV-TPL-03 | `docker.sbt:15` | `dockerUpdateLatest := !RC && !SNAPSHOT`（稳定版会同时更新 `latest`） |
| THV-TPL-04 | `docker.sbt:27,51` | `FROM openjdk:8`、`EXPOSE 9000` |

- **Template Version 结论**：Docker 镜像由 sbt 从 `thehiveVersion=4.1.24-1` 构建，仓库 `thehiveproject`，基座 `openjdk:8`，端口 `9000`；稳定版会更新 `latest` tag。
- **限制条件**：仓库内**无独立的 TheHive `docker-compose.yml`**（模板证据来自 sbt 构建定义，而非可直接部署的编排清单）；`latest` 更新策略意味着**镜像 tag 不可单独锚定精确版本**。
- **认证状态**：**PARTIAL**（构建定义可推 tag 语义，但无 digest、无编排清单、非目标运行时）。

### 7.3 Target Runtime Version

> **`Target Runtime = UNKNOWN — no target instance evidence available`**

- 无目标 TheHive 实例（§3）；无镜像 digest、无版本端点响应、无 build 号。
- **认证状态**：**UNKNOWN**。

### 7.4 框架依赖版本（ScalliGraph）

| 证据 ID | 证据路径 | 只读观察 |
| --- | --- | --- |
| THV-DEP-01 | `TheHive-main/.gitmodules:2-4` | `[submodule "ScalliGraph"] path=ScalliGraph url=../scalligraph.git branch=develop` —— **跟踪 `develop` 分支，无 commit pin** |
| THV-DEP-02 | `TheHive-main/ScalliGraph/`（目录） | **空（未初始化）**——子模块内容不在本地快照中 |

- **框架依赖结论**：TheHive 依赖 ScalliGraph（`org.thp` 数据/图框架），但快照中该子模块**未 pin commit 且未初始化**。
- **限制条件**：无法确定与 `4.1.24-1` 对应的 ScalliGraph 精确版本/commit；`branch=develop` 是浮动引用。
- **认证状态**：**UNKNOWN**（框架依赖精确版本无法定位）。

### 7.5 权威 v0 case creation 响应契约可定位性

- **可定位性结论：可在源码层定位到 `4.1.24-1` 的 v0 契约实现，但无法确认其与目标运行时版本一致。**
- 依据：(a) 源码版本明确为 `4.1.24-1`（THV-SRC-01），可据此查阅**对应精确版本**的 `case creation` v0 响应契约与错误处理实现（DTO/路由位于 `dto/` 与 `thehive/` 模块）；(b) 但目标运行时 UNKNOWN（§7.3），若目标实例为 **5.x**，其 API 契约与 4.x **不同**（见 THV-RISK-01），4.1.24-1 源码将**不适用**。
- **THV-RISK-01（目标版本可能跨大版本）**：源码为 `4.x`；TheHive 5.x 已发布且 API 与 4.x 存在契约差异。在未取得目标实例版本前，**不得假定**目标为 4.1.24-1，也不得据 4.x 源码推断 5.x 契约。**状态：CONFLICT/UNKNOWN（待目标实例证据裁决）**。
- **缺失证据**：目标实例 TheHive 版本/build + 镜像 digest；据此才能选定**对应精确版本**的权威 v0 case creation 响应契约与错误处理实现。

### 7.6 TheHive 非目标声明

按授权 §5，本轮**仅登记 G3 所需的目标版本证据**：
- **不**修复 `case_id` / `_id` / `id` / `caseId` 或 409 幂等 reference 缺陷；
- **不**把案件生命周期（case lifecycle）或 Cortex 相邻任务直接解释为“响应动作效果”。

---

## 8. 交付矩阵（Delivery Matrix）

采集时间统一为 **2026-09-08**；采集方式统一为**只读**（无网络、无写入、无提交）。

### 8.1 汇总矩阵（glanceable）

| Adapter（组件） | 目标环境 | Source Version | Template Version | Target Runtime Version | 认证状态 |
| --- | --- | --- | --- | --- | --- |
| **Wazuh — Manager** | 无实例 | `5.1.0-alpha0`（VERSION.json） | `wazuh/wazuh-manager:5.1.0`（浮动 tag，无 digest） | **UNKNOWN** — no target instance evidence available | **PARTIAL**（源/模板）· **UNKNOWN**（运行时）· **CONFLICT**（stage） |
| **Wazuh — Indexer** | 无实例 | `5.1.0-alpha0`（VERSION.json，与 Manager 同源快照） | `wazuh/wazuh-indexer:5.1.0`（浮动 tag，无 digest） | **UNKNOWN** — no target instance evidence available | **PARTIAL**（源/模板）· **UNKNOWN**（运行时） |
| **Shuffle — frontend** | 无实例 | `2.0.0`（package.json） | `ghcr.io/shuffle/shuffle-frontend:latest` | **UNKNOWN** — no target instance evidence available | **PARTIAL**（源）· **UNKNOWN**（模板/运行时） |
| **Shuffle — backend** | 无实例 | `module shuffle` + `shuffle-shared v1.2.51` | `ghcr.io/shuffle/shuffle-backend:latest` | **UNKNOWN** — no target instance evidence available | **PARTIAL**（源）· **UNKNOWN**（模板/运行时）· **CONFLICT**（shared） |
| **Shuffle — worker/orborus** | 无实例 | `module worker` + `shuffle-shared v1.2.45` + `singul v0.0.32` | `ghcr.io/shuffle/shuffle-orborus:latest`（worker 由 orborus 运行时派生，无独立 image 服务） | **UNKNOWN** — no target instance evidence available | **PARTIAL**（源）· **UNKNOWN**（模板/运行时）· **CONFLICT**（shared） |
| **TheHive** | 无实例 | `4.1.24-1`（build.sbt / CHANGELOG） | `thehiveproject/thehive`（sbt 构建，`FROM openjdk:8`，稳定版更新 `latest`；无独立 compose） | **UNKNOWN** — no target instance evidence available | **PARTIAL**（源/模板）· **UNKNOWN**（运行时）· **CONFLICT/RISK**（4.x vs 可能 5.x） |
| **TheHive — ScalliGraph（框架依赖）** | 无实例 | 子模块 `branch=develop`，**无 commit pin**，目录**未初始化** | — | **UNKNOWN** | **UNKNOWN** |

> 三侧 **Target Runtime 一律 UNKNOWN**。**未**因 Source/Template 已确认而将任何 Target Runtime 升级为 CONFIRMED（遵守 §2.3 硬约束）。

### 8.2 Wazuh 明细属性块（Manager 与 Indexer 分列）

| 属性 | Wazuh — Manager | Wazuh — Indexer |
| --- | --- | --- |
| Adapter | `wazuh`（Manager 组件） | `wazuh`（Indexer 组件） |
| 目标环境 | 无实例（§3） | 无实例（§3） |
| Source Version | `5.1.0-alpha0` | `5.1.0-alpha0`（同一快照 VERSION.json） |
| Deployment Template Version | `wazuh/wazuh-manager:5.1.0` | `wazuh/wazuh-indexer:5.1.0` |
| Target Runtime Version | **UNKNOWN** — no target instance evidence available | **UNKNOWN** — no target instance evidence available |
| build / commit / digest | 无 commit（非 git，PROV-01）；tag 无 digest；stage=`alpha0` | 无 commit；tag 无 digest；stage=`alpha0` |
| 证据 ID | WAZ-SRC-01/02、WAZ-TPL-01/04/08、ENV-01..09、PROV-01 | WAZ-SRC-01/02、WAZ-TPL-02/05/08、ENV-01..09、PROV-01 |
| 证据路径 / 权威来源 | `wazuh-main/VERSION.json`；`wazuh-docker-main/{single-node,multi-node}/docker-compose.yml`；`build-images.sh` | 同左（Indexer 镜像行） |
| 采集时间 | 2026-09-08 | 2026-09-08 |
| 证明命题 | “本地源码快照自述 Manager 版本为 5.1.0-alpha0；部署模板以 `:5.1.0` 浮动 tag 引用 Manager 镜像” | “本地源码快照自述版本 5.1.0-alpha0；模板以 `:5.1.0` 浮动 tag 引用 Indexer 镜像；Indexer 与 Manager 为不同镜像/组件” |
| 限制条件 | 非 git→无 commit/digest；`5.1.0` tag 可对应 production 或 alpha0 artifact（build-images.sh）；非目标运行时 | 同左；且 Indexer 版本须**独立**核对，不得由 Manager 版本代替 |
| 认证状态 | Source **PARTIAL** / Template **PARTIAL** / Runtime **UNKNOWN** / stage **CONFLICT**（WAZ-CONFLICT-01） | Source **PARTIAL** / Template **PARTIAL** / Runtime **UNKNOWN** |
| 缺失证据 | 目标 Manager 的版本端点响应 / `wazuh-control -V` / 镜像 digest | 目标 Indexer 的版本端点响应 / 镜像 digest（与 Manager 分别提供） |
| 责任人 | 运维（目标 Wazuh 实例持有方）— **当前未指派** | 运维 — **当前未指派** |
| 下一步解阻 | 由运维提供脱敏 Manager 版本/build 或 digest（见 §13） | 由运维提供脱敏 Indexer 版本/build 或 digest（见 §13） |

### 8.3 Shuffle 明细属性块

| 属性 | 值 |
| --- | --- |
| Adapter | `shuffle` |
| 目标环境 | 无实例（§3） |
| Source Version | frontend `2.0.0`；backend `module shuffle` + `shuffle-shared v1.2.51`；worker `module worker` + `shuffle-shared v1.2.45` + `singul v0.0.32`；`go 1.25.0` |
| Deployment Template Version | `ghcr.io/shuffle/shuffle-{frontend,backend,orborus}:latest`（全浮动）；`opensearch:3.2.0`（唯一 pinned）；**无独立 worker image 服务** |
| Target Runtime Version | **UNKNOWN** — no target instance evidence available |
| build / commit / digest | 无 commit（非 git，PROV-01）；镜像全 `latest` 无版本/无 digest；`shuffle-shared` 未 vendored |
| 证据 ID | SHF-SRC-01/02/03、SHF-TPL-01..05、ENV-01..09、PROV-01 |
| 证据路径 / 权威来源 | `Shuffle-main/frontend/package.json`；`backend/go-app/go.mod`；`functions/onprem/worker/go.mod`；`docker-compose.yml` |
| 采集时间 | 2026-09-08 |
| 证明命题 | “源码快照自述 frontend 2.0.0，backend/worker 分别依赖 shuffle-shared v1.2.51 / v1.2.45；部署模板仅以 `latest` 引用镜像” |
| 限制条件 | 非 git→无 commit/digest；`latest` 无版本维度；`shuffle-shared` 本地不可读（未 vendored）；backend 与 worker shared 版本分叉 |
| 认证状态 | Source **PARTIAL** / Template **UNKNOWN**（仅 latest）/ Runtime **UNKNOWN** / 依赖 **CONFLICT**（SHF-CONFLICT-01） |
| 缺失证据 | 目标实例的镜像 digest / 精确 tag；目标实际运行的 `shuffle-shared` 版本；对应 tag/commit 的权威 `WorkflowExecution` schema |
| 责任人 | 运维（目标 Shuffle 实例持有方）— **当前未指派** |
| 下一步解阻 | 由运维提供脱敏镜像 tag/digest 与 backend/worker 的 shuffle-shared 版本（见 §13） |

### 8.4 TheHive 明细属性块

| 属性 | 值 |
| --- | --- |
| Adapter | `thehive` |
| 目标环境 | 无实例（§3） |
| Source Version | `4.1.24-1`（build.sbt:5 / CHANGELOG [4.1.24] 2022-09-12 / debian 包名 `thehive4`）；Scala `2.12.13`；`org.thp` |
| Deployment Template Version | 镜像仓库 `thehiveproject/thehive`；`version in Docker` 由 `4.1.24-1` 推导；`FROM openjdk:8`、`EXPOSE 9000`；稳定版 `dockerUpdateLatest`；**仓库内无独立 compose** |
| Target Runtime Version | **UNKNOWN** — no target instance evidence available |
| build / commit / digest | 无 commit（非 git，PROV-01）；无 digest；ScalliGraph 子模块无 commit pin 且未初始化 |
| 证据 ID | THV-SRC-01..04、THV-TPL-01..04、THV-DEP-01/02、ENV-01..09、PROV-01 |
| 证据路径 / 权威来源 | `TheHive-main/build.sbt`；`CHANGELOG.md`；`debian.sbt`；`docker.sbt`；`.gitmodules`；`ScalliGraph/`（空） |
| 采集时间 | 2026-09-08 |
| 证明命题 | “源码快照自述 TheHive 4.1.24-1，可据此定位**对应精确版本**的 v0 case creation 契约；镜像由 sbt 构建于 `thehiveproject`” |
| 限制条件 | 非 git→无 commit/digest；无独立 compose；`latest` 更新策略使 tag 不可单独锚定；ScalliGraph 精确版本不可定位；**目标可能为 5.x，契约与 4.x 不同** |
| 认证状态 | Source **PARTIAL** / Template **PARTIAL** / Runtime **UNKNOWN** / 框架依赖 **UNKNOWN** / 跨大版本 **CONFLICT-RISK**（THV-RISK-01） |
| 缺失证据 | 目标实例 TheHive 版本/build + 镜像 digest；对应 ScalliGraph 精确版本；据目标版本选定的权威 v0 case creation 响应契约与错误处理实现 |
| 责任人 | 运维（目标 TheHive 实例持有方）— **当前未指派** |
| 下一步解阻 | 由运维提供脱敏 TheHive 版本/build 与 digest（见 §13），据此判定 4.x/5.x 并选定对应契约 |

---

## 9. 冲突登记（Consolidated Conflict Register）

| 冲突 ID | 侧 | 冲突内容 | 证据 | 状态 | 解释/裁决所需 |
| --- | --- | --- | --- | --- | --- |
| WAZ-CONFLICT-01 | Wazuh | 源码 `5.1.0-alpha0` ↔ 模板 tag `5.1.0`（GA 语义）；同一 tag 可对应 production 或 alpha0 artifact | WAZ-SRC-01/02、WAZ-TPL-01..08 | **CONFLICT（未解释）** | 目标 Manager/Indexer 的真实 build/digest |
| SHF-CONFLICT-01 | Shuffle | backend `shuffle-shared v1.2.51` ↔ worker `shuffle-shared v1.2.45`（同仓两模块分叉） | SHF-SRC-02、SHF-SRC-03 | **CONFLICT（未解释）** | 目标实例实际运行的 shared 版本 + 镜像 digest |
| THV-RISK-01 | TheHive | 源码 `4.x` ↔ 目标可能 `5.x`（API 契约不同）；ScalliGraph 无 pin | THV-SRC-01、THV-DEP-01/02 | **CONFLICT/UNKNOWN（待裁决）** | 目标 TheHive 版本/build + digest |
| PROV-01（限制） | 全部 | 五个 sibling 仓库非 git，本地无 commit/tag/digest 溯源 | PROV-01 | **限制条件（常设）** | 需目标实例 digest 或权威 release 对应 commit |

> 按授权 §2：本轮**仅登记**冲突，**不**前向更新 Consolidation / G1-A / G1-B 或任何历史文档；是否前向更新由 G2 Final Review 决定。

---

## 10. 决策结论（Decision Conclusions，对应授权 §8 六项）

### 10.1 三侧目标实例是否存在，是否有明确责任人与环境范围

- **本轮未识别到明确目标实例，且未取得目标实例证据。** `sentinelflow` 无生产实例、无已授权测试环境、无部署清单（ENV-01..09：compose 仅 `postgres`；config.py 默认 `mock`、所有 `*_BASE_URL`/`*_API_KEY`/`*_CALLBACK_TOKEN` 为空；`.env` 无适配器覆盖；`infrastructure/`/`integrations/`/`workflows/` 仅 `.gitkeep`）。
- **无明确责任人**：三侧目标实例持有方/运维**当前未指派**。
- **无环境范围**：无环境名称、用途、部署方式可记录。
- 结论：**Target Runtime = UNKNOWN — no target instance evidence available**（三侧一致）。

### 10.2 哪些版本已确认，哪些仍 UNKNOWN，及每项缺口如何解阻

| 维度 | 状态 | 说明 / 解阻 |
| --- | --- | --- |
| Wazuh Source | **PARTIAL** | `5.1.0-alpha0`（VERSION.json），但无 commit/digest。解阻：取得对应 release 的权威 commit/tag |
| Wazuh Template | **PARTIAL** | `:5.1.0` 浮动 tag（Manager/Indexer/Dashboard/Agent）。解阻：取得目标 digest |
| Wazuh Target Runtime（Manager / Indexer） | **UNKNOWN** | 解阻：运维提供脱敏版本端点响应 / `wazuh-control -V` / 镜像 digest（两者分别） |
| Shuffle Source | **PARTIAL** | frontend `2.0.0`；shared `v1.2.51`/`v1.2.45`。解阻：取得 commit + 权威 shared 源码 |
| Shuffle Template | **UNKNOWN** | 仅 `latest`（frontend/backend/orborus），无版本维度。解阻：取得目标精确 tag/digest |
| Shuffle Target Runtime | **UNKNOWN** | 解阻：运维提供镜像 digest + 实际 shared 版本 |
| TheHive Source | **PARTIAL** | `4.1.24-1`（build.sbt/CHANGELOG）。解阻：取得 commit；确认目标是否同版本 |
| TheHive Template | **PARTIAL** | sbt 构建 `thehiveproject/thehive`，无独立 compose、无 digest。解阻：取得目标镜像 tag/digest |
| TheHive Target Runtime | **UNKNOWN** | 解阻：运维提供版本/build + digest，判定 4.x/5.x |
| TheHive ScalliGraph（框架依赖） | **UNKNOWN** | 子模块无 pin 且未初始化。解阻：取得对应版本的 ScalliGraph commit |

> **无任何一侧 Target Runtime 达到 CONFIRMED。** 取证工作完成 ≠ 三侧版本全部 CONFIRMED（符合授权 §8 末段）。

### 10.3 Wazuh Manager/Indexer、Shuffle 依赖与 TheHive 目标契约是否存在版本冲突

- **Wazuh**：存在 **WAZ-CONFLICT-01**（源 `alpha0` ↔ 模板 `5.1.0` GA 语义；同 tag 可对应 production/pre-release）。Manager 与 Indexer 在模板中同为 `:5.1.0` 但为**不同镜像**，需分别确认；本轮**无证据**判定二者是否同 build。
- **Shuffle**：存在 **SHF-CONFLICT-01**（backend `shuffle-shared v1.2.51` ↔ worker `v1.2.45`），可能导致 schema/序列化契约不一致。
- **TheHive**：存在 **THV-RISK-01**（源 `4.x` ↔ 目标可能 `5.x`，契约不同），叠加 ScalliGraph 无 pin。
- 三类冲突**均尚未被目标实例证据解释**，状态为 CONFLICT/UNKNOWN。

### 10.4 G3 / G4 / G5 各自已具备的版本输入与缺少的权威证据

| Gate | 已具备的版本输入 | 缺少的权威证据 |
| --- | --- | --- |
| **G3**（TheHive Write Contract） | TheHive 源版本 `4.1.24-1` 明确，可定位对应精确版本的 v0 case creation 响应契约/错误处理（THV-SRC-01..04） | 目标实例版本/build + digest（判定 4.x/5.x）；对应 ScalliGraph 精确版本；据目标版本选定的权威契约 |
| **G4**（Shuffle Semantic Auth） | frontend `2.0.0`；backend/worker shared 版本（v1.2.51/v1.2.45）已知（SHF-SRC-01..03） | 目标镜像 digest/精确 tag；实际运行 shared 版本；对应版本的权威 `WorkflowExecution` schema |
| **G5**（TheHive Resource-Effect Design） | 同 G3 的源版本输入 | 同 G3；额外需目标运行时资源效果语义的版本锚定（本轮不认证） |
| **（Wazuh 后续 Gate）** | `5.1.0-alpha0` 源 + `:5.1.0` 模板（Manager/Indexer 分列）；B0/B0.1 结论仍适用 | 目标 Manager/Indexer 真实 build/digest（分别） |

### 10.5 下一道最合理 Gate 的条件优先级（不以实现容易程度排序）

按“解阻价值 / 依赖前置”排序（非难度）：

1. **最高优先：取得任一侧目标实例的最小非敏感版本证据（§13）。** 这是所有三域从 PARTIAL/UNKNOWN 迈向 CONFIRMED 的**唯一硬前置**；无此证据，任何 Adapter 设计冻结都缺乏运行时锚定。
2. **其次：TheHive 目标大版本判定（4.x vs 5.x）。** 直接决定 G3/G5 契约选型；跨大版本误判将导致契约全面失效（THV-RISK-01）。
3. **再次：Shuffle 目标 `shuffle-shared` 版本与 digest。** 解 SHF-CONFLICT-01，并为 G4 的 `WorkflowExecution` schema 锚定精确版本。
4. **最后：Wazuh Manager/Indexer 分别的 build/digest。** 解 WAZ-CONFLICT-01；因 G1-C 已 fail-closed（词表清空），Wazuh 运行时安全**不依赖**版本确认即可保持安全，故解阻紧迫性**低于**前三项。

> 优先级依据：TheHive/Shuffle 的契约/schema 选型**直接受版本支配**；而 Wazuh 已由 G1-C fail-closed 解耦了“版本未知”与“运行时安全”，故排序靠后。

### 10.6 是否需要用户/运维提供额外版本信息（仅最小必要、非敏感）

- **需要。** 三侧 Target Runtime 均 UNKNOWN，无法仅凭本地只读证据解阻。
- 仅请求**最小必要、非敏感**的版本证据（见 §13）；**绝不**索取 API key / password / JWT / callback token 或任何凭据。
- 若需主动访问真实实例的版本端点，将**先列出目标/请求方法/URL 路径/认证需求/风险**并等待**单独批准**；**本轮默认不执行任何真实实例网络请求**。

---

## 11. G3 / G4 / G5 版本输入清单（交付给下游 Gate）

- **G3（TheHive Write Contract）可用输入**：`thehiveVersion=4.1.24-1`、Scala `2.12.13`、`org.thp`、CHANGELOG `[4.1.24] 2022-09-12`、镜像仓库 `thehiveproject`、`FROM openjdk:8`/`EXPOSE 9000`。**阻塞项**：目标大版本未定（THV-RISK-01）。
- **G4（Shuffle Semantic Auth）可用输入**：frontend `2.0.0`、backend `shuffle-shared v1.2.51`、worker `shuffle-shared v1.2.45` + `singul v0.0.32`、`go 1.25.0`、模板 `latest` + `opensearch:3.2.0`。**阻塞项**：shared 版本分叉（SHF-CONFLICT-01）+ 无 digest + `WorkflowExecution` schema 不可定位。
- **G5（TheHive Resource-Effect Design）可用输入**：同 G3。**阻塞项**：同 G3，且本轮**不**认证资源效果语义。

---

## 12. 本轮允许/禁止的外部证据方式（合规声明）

- **已执行（允许）**：读取本地仓库、现有部署文件、已有审计文档（`phase3.4-wazuh-mapping-amendment.md`）；只读 `git` 子命令；目录列举。
- **未执行（禁止，本轮全部规避）**：接入生产凭据、触发外部执行、调用有状态业务写接口、扫描目标系统、运行 Active Response、创建 case/workflow、自动轮询、重试、补偿、任何真实实例网络请求。
- **未索取**：API key / password / JWT / callback token 等任何凭据。

---

## 13. 最小必要、非敏感版本信息请求（待 Review 批准后由运维提供）

> 仅版本/build/digest 维度；**不含**任何凭据、主机名、IP、租户标识或敏感配置。

| 侧 | 请求项（最小集） | 权威来源示例 | 用途 |
| --- | --- | --- | --- |
| Wazuh Manager | 版本/build（如 `wazuh-control -V` 或版本端点响应的 version 字段）或镜像 digest | 运维脱敏输出 | 解 WAZ-CONFLICT-01，锚定 Manager 运行时 |
| Wazuh Indexer | 版本/build 或镜像 digest（**与 Manager 分别**） | 运维脱敏输出 | 锚定 Indexer 运行时 |
| Shuffle | 镜像精确 tag/digest + backend/worker 实际 `shuffle-shared` 版本 | `docker inspect` digest / 运维脱敏 | 解 SHF-CONFLICT-01，锚定 `WorkflowExecution` schema 版本 |
| TheHive | 版本/build（判定 4.x/5.x）+ 镜像 tag/digest | 运维脱敏 / 版本端点 | 解 THV-RISK-01，选定对应 v0 case creation 契约 |

**若需主动访问真实实例版本端点**：将先提交“目标 / 请求方法 / URL 路径 / 认证需求 / 风险”清单，等待**单独批准**；本轮**未**执行。

---

## 14. Git 与停止纪律（Git & Stop Discipline）

- 本轮**唯一改动** = 新增本 DRAFT Markdown：`docs/design/phase3.4.5-g2-production-version-evidence.md`。
- **未**修改代码 / 测试 / mapping / migration / 配置 / 历史文档；**未** commit；**未** push；**未**创建 Reader；**未**进入 G3/G4/G5；**未**运行真实外部联调；**未**发布版本。
- 本文件状态 **REVIEWED — Evidence Inventory**，**非 FROZEN**（生产版本认证未完成）。
- **收口记录（M1 里程碑 §2）**：本 G2 文档经复核后由 DRAFT 收口为 REVIEWED，作为**单独的本地前向文档提交**；上文“未 commit”为 G2 取证轮次的当时状态，收口提交在 M1 里程碑授权下执行，仍**不 push**、**不**修改 G1 历史文档。
- 本授权仅限 G2 版本证据阶段，**不授予任何 Adapter 设计冻结或实现权限**。

---

## 附录 A：只读命令与结果（Evidence Provenance）

> 全部为只读命令；无网络、无写入、无提交。`<repo>` = `D:\edge\github\sentinelflow`。

| # | 命令（只读） | 关键结果 |
| --- | --- | --- |
| A1 | `git -C <repo> rev-parse HEAD` | `7210f610dbdd0b4db9e55f161c9d79fb6cbfcf60` |
| A2 | `git -C <repo> rev-parse --abbrev-ref HEAD` | `main` |
| A3 | `git -C <repo> rev-list --left-right --count origin/main...HEAD` | `0<TAB>24`（behind 0 / ahead 24） |
| A4 | `git -C <repo> status --porcelain` | 空（clean） |
| A5 | `git -C <repo> log --oneline -3` | `7210f61` / `0c372aa` / `73b9c8b` |
| A6 | `Get-ChildItem docs/design -Name` | 10 份文档，含三份 G1；采集前无 G2 |
| A7 | `Test-Path ...g2-production-version-evidence.md` | 采集前 `ABSENT` |
| A8 | `git -C <sibling> rev-parse --short HEAD`（×5 仓库） | 全部 `fatal: not a git repository`（PROV-01） |
| A9 | `Read wazuh-main/VERSION.json` + `wazuh-docker-main/VERSION.json` | 均 `5.1.0` / `alpha0` |
| A10 | `Grep image: wazuh/wazuh`（wazuh-docker-main） | single/multi-node + agent 均 `:5.1.0` |
| A11 | `Grep image: Shuffle-main/docker-compose.yml` | frontend/backend/orborus `:latest` + opensearch `3.2.0`；cadvisor/memcached/socket-proxy 被注释 |
| A12 | `Grep shuffle-shared backend/go-app/go.mod` | `module shuffle`、`go 1.25.0`、`shuffle-shared v1.2.51` |
| A13 | `Grep shuffle-shared functions/onprem/worker/go.mod` | `module worker`、`go 1.25.0`、`shuffle-shared v1.2.45`、`singul v0.0.32` |
| A14 | `Read Shuffle-main/frontend/package.json:1-6` | `name shuffler`、`version 2.0.0` |
| A15 | `Grep thehiveVersion build.sbt` | `4.1.24-1`、`scala212 2.12.13`、`org.thp` |
| A16 | `Read TheHive-main/CHANGELOG.md:1-25` | 顶 `[4.1.24] (2022-09-12)` |
| A17 | `Read TheHive-main/docker.sbt` + `.gitmodules` | `thehiveproject`、`FROM openjdk:8`、`EXPOSE 9000`；ScalliGraph `branch=develop` 无 pin |
| A18 | `Read sentinelflow/backend/app/core/config.py:40-105,135-150` | `EXECUTION_ADAPTER="mock"`；`*_BASE_URL`/`*_API_KEY`/`*_CALLBACK_TOKEN` 全空 |
| A19 | `Read sentinelflow/docker-compose.yml` | 仅 `postgres:16-alpine` |
| A20 | `Grep sentinelflow/.env` + `.env.example` | `.env` 无适配器覆盖；`.env.example` `EXECUTION_ADAPTER=mock`、`*_BASE_URL=` 空 |
| A21 | `Get-ChildItem infrastructure/integrations/workflows -Recurse -Force` | 全 `.gitkeep`（无部署/集成/workflow 实体） |
| A22 | `Grep phase3.4-wazuh-mapping-amendment.md`（B0/B0.1） | 三域矩阵与版本确认路径仍适用（§5.4） |

> **附录 A 说明**：以上为本文档所有版本结论的证据来源。所有 Source/Template 结论均可回溯到具体文件行；所有 Target Runtime 结论均为 UNKNOWN（无目标实例证据）。
