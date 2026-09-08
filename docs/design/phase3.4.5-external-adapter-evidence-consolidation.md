# Phase 3.4.5 — External Adapter Evidence Consolidation

## §0 Document Control

| 项 | 值 |
|---|---|
| **标题** | Phase 3.4.5 External Adapter Evidence Consolidation |
| **状态** | **REVIEWED — Evidence Baseline**（用户 G1-D Final Review 裁决 PASS，2026-09-08）。G1-C/G1-D 安全收口记录见 §0.1；修复前 `NOT VERIFIED` 与修复后 `VERIFIED — scoped` 双时点判定保留于 §8.2；作为三侧 Adapter 后续 Gate（G2–G5）的证据基线。本次经 **G1-D Final Documentation Commit** 授权本地提交（THREE DOCUMENTS ONLY · LOCAL COMMIT · NO PUSH） |
| **适用 Phase** | 3.4.5 External Adapter Evidence Consolidation（三次 Evidence Audit 的决策基线整合） |
| **编制日期** | 2026-09-08 |
| **基线 HEAD** | 原编制基线 `73b9c8b`（ahead `origin/main` **22**，编制前工作树 CLEAN）；**G1-D 修订基线 `0c372aa`**（G1-C 安全修复提交后，ahead **23** / behind 0，见 §0.1） |
| **授权** | DOCUMENTATION ONLY · NO COMMIT（本轮唯一允许新建本文件；不 commit / 不 push / 不改生产代码 / 不建 Reader / 不改 mapping / 不改 migration / 不跑外部执行 / 不接入生产凭据） |

**输入审计及对应 commit / 载体：**

| 输入 | 载体 / commit | 状态 |
|---|---|---|
| 3.4.5-A 平台契约冻结 | `fd3ac34` + `docs/design/phase3.4-manual-reconcile.md` | 封板 |
| 3.4.5-A1 Adapter Read Contract | `3a35e1c` | 封板 |
| 3.4.5-A2-A..F | `4b09d18`/`4057ae2`/`bd61288`/`6759140`/`9bfe13b`/`abf26a7` | 封板 |
| 3.4.3-A 契约类型 | `7be4dcf` + `docs/design/phase3.4-reconciliation-contract.md`（`a125f1e`） | 封板 |
| 3.4.3-B 原始状态映射 | `8b89fe7`（`reconciliation.py`，**禁改 / 禁 amend / 禁 force-push**） | 冻结 |
| 3.4.4 Webhook Inbound（A..F） | `f35852b`/`716a152`/`b3753b5`/`192f615`/`9119036`/`fb56bf3` | 封板 |
| 3.4.5-B Wazuh Evidence Audit | 对话交付（结论 NOT READY + Mapping Conflict） | 已接受 |
| 3.4.5-B0 Wazuh Mapping Amendment Design | `b0a5962` + `docs/design/phase3.4-wazuh-mapping-amendment.md` | DESIGN ONLY |
| 3.4.5-B0.1 Production Version Confirmation | `73b9c8b`（并入上文件 §1） | 已接受 |
| 3.4.5-C Shuffle Evidence Audit | 对话交付 + 记忆 `4b5f1a44`（含三项措辞修正） | PASS |
| 3.4.5-D TheHive Evidence Audit | 对话交付 + 记忆 `a3835c86`（含 Review 效果范围限定） | PASS |
| TheHive Write Contract Defect Candidate | 记忆 `bc2ca709`（独立登记） | 已登记 |

### §0.1 G1-C / G1-D 安全收口修订记录（2026-09-08）

> 本节记录**原编制基线 `73b9c8b` 之后**发生的安全处置进展，**不重写**任何原始取证结论；所有历史判定（CONFIRMED UNSAFE / NOT VERIFIED）作为**修复前基线**原样保留，仅在相应位置追加 G1-C/G1-D 前向更新。

| 事件 | commit / 载体 | 状态 |
|---|---|---|
| **G1-A** Wazuh Runtime Safety 只读取证 | `phase3.4.5-g1-a-...`（DRAFT） | 取证性质保留（CONFIRMED UNSAFE / NOT VERIFIED 为**修复前**判定，不倒写） |
| **G1-B** 最小安全修复设计（C2 清空词表） | `phase3.4.5-g1-b-...`（用户 Review PASS + 5 处强制修订） | **FROZEN · Design Freeze** |
| **G1-C** C2 最小安全修复落地（代码 + 测试迁移） | **`0c372aa`**（parent `73b9c8b`；8 files，+988/−457；单一前向原子提交） | **已实施 · 已接受**（完整回归 2494 passed / 0 failed / 3 deselected / 0 skipped；`git diff --check` clean） |
| **G1-D** 安全收口与文档核对（本轮） | 本修订记录 + §1/§4/§5.1/§6/§8/§9/§10/§12 前向更新 | **DOCUMENTATION + READ-ONLY · NO CODE · NO COMMIT** |

**Wazuh Runtime Safety Gate 状态更新（用户 G1-C Final Review 裁决，2026-09-08）：**

- **修复前基线（`73b9c8b`，保留不重写）：** `NOT VERIFIED`（§8.2 历史判定；G1-A CONFIRMED UNSAFE 取证事实原样保留）。
- **G1-C 后当前判定（`0c372aa`）：** **`VERIFIED — scoped to the audited inbound mapping paths and isolated regression environment. Production deployment and historical data safety remain unverified.`**

**五态区分（必须始终分列，不得混为单一发布结论）：**

| # | 维度 | 当前状态 |
|---|---|---|
| 1 | 源码修复（清空 Wazuh 入站词表，fail-closed） | ✅ **已完成**（`0c372aa`，唯一生产改动 = `reconciliation.py` wazuh 词表块） |
| 2 | 隔离回归（HTTP 全栈 + 跨层 + 完整后端） | ✅ **已通过**（2494 passed / 0 failed / 3 deselected / 0 skipped） |
| 3 | 真实生产部署验收 | ❌ **未验证**（本仓库未配置 / 未 co-deploy 真实 Wazuh；无生产实例证据） |
| 4 | 历史数据污染 | ❓ **未知**（append-only 历史不改；当前无可用真实数据库查询结果，历史污染状态 UNKNOWN；其他部署须由部署负责人独立只读核查） |
| 5 | 真实 Wazuh Reader（命令级效果读取） | ❌ **尚未实现**（无 `WazuhReadAdapter`；词表再填充须版本限定证据 + 独立 Design Freeze） |

> **关键纪律：** 「安全修复已完成」（维度 1-2）**不等于**「生产级 Outcome 闭环已完成」（维度 3-5）。当前修复阻止旧词表在**已查明映射路径**产生不可信 Outcome；**不**意味所有未来 Wazuh 版本都不支持结果读取，也**不**意味真实生产环境已验收。

**审计范围（本文档做什么）：** 只读整合 Wazuh / Shuffle / TheHive 三次 Evidence Audit 的已接受结论，统一为可追溯决策基线；区分已证实事实、未知项、契约冲突；登记缺陷与风险；提出后续独立候选 Gate 的优先级建议。

**非目标（本文档不做什么）：**
- ❌ 不证明三个 Adapter 都能实现；不宣布任何 Adapter 一定落地。
- ❌ 不重新设计 3.4.5-A 平台；不修改任何已封板契约。
- ❌ 不授权任何 Reader / Design Freeze / Implementation / mapping amendment。
- ❌ 不修改 `8b89fe7`；不修复任何缺陷（含 TheHive 写入契约缺陷）。
- ❌ 不声称真实外部效果已联调、已验证生产部署或已通过测试。

---

## §1 Executive Decision Summary

> 本页为决策摘要，**非发布说明**；不声称任何真实外部效果已联调通过。

**三次 Evidence Audit 全部 PASS，但暴露三类性质不同的缺口，无一具备 Implementation 授权：**

1. **Wazuh — 存在性/版本缺口 + 运行时安全风险（已由 G1-C 在限定映射路径收口）。** 审计源码 `5.1.0-alpha0` 无可信 command-level Active Response 结果 REST 读契约；生产版本 UNKNOWN。**修复前基线（`73b9c8b`，保留）：** 3.4.3-B 的 Wazuh 非空词表（`{completed,confirmed,done,success,ok}→confirmed_success`）曾是 LIVE 生产代码（`8b89fe7`），经 3.4.4 webhook 入站路径可达；`test_webhook_persistence.py:311-336`（修复前）已证明自称 `success/ok/completed` 的回调映射为 `confirmed_success`（B0 §4 证伪的不可信映射），故 **Wazuh Runtime Safety Gate 曾判 `NOT VERIFIED`**（§8.2 历史判定）。**G1-C 后当前状态（`0c372aa`）：** 该四组未认证词表已**前向清空**（`8b89fe7` 未改写），任何 Wazuh 入站态经既有 `UnrecognizedExternalState` 契约一律 refused（webhook 422 / manual refused，零 fact），**Wazuh Runtime Safety Gate = `VERIFIED — scoped`**（限已查明入站映射路径 + 隔离回归环境；生产部署与历史数据安全仍未验证，§8.2）。manual-reconcile 的空 registry 结构门 + webhook 的 token 配置门**依旧保留**，但现在**叠加了 mapping 层语义 fail-closed 门**（不再仅靠运维可逆的 token 默认值）。

2. **Shuffle — 认证/语义缺口（最有希望闭合）。** 真实 workflow-execution 读路径存在（Read Endpoint SUPPORTED，限已审计源码），但权威 `WorkflowExecution` schema、状态语义与生产版本均在外部 `shuffle-shared` 依赖 + UNKNOWN，含义无法认证（Read Semantics EVIDENCE-GAPPED）。单独 `external_execution_id` 不足以定位 workflow-scoped 读取（Reference PARTIAL）。空词表保持不变。

3. **TheHive — 效果范围缺口（EFFECT-SCOPE GAP）+ 独立写入契约缺陷。** case 读取接口真实存在（Read Endpoint SUPPORTED），但 CaseStatus `{Open,Resolved,Duplicated}` 是人工调查判断，**不能认证隔离/封禁等响应动作效果**；TheHive 非响应引擎，Cortex job/analyzer/responder 属相邻组件。**限定裁决：用 case lifecycle 认证响应动作效果不可行；通过权威资源读取验证 case creation 是未来独立 Design Candidate（尚未获语义与关联契约认证）。** 另发现 **TheHive Write Contract Defect Candidate**：写适配器读 `case_id`，真实 v0 响应为 `_id`/`id`/`caseId`（无 `case_id`）。

**已确认的契约问题：** ①Wazuh 旧非空词表与权威证据 Mapping Conflict = YES（B0 已裁 INVALID）——**G1-C（`0c372aa`）已前向清空词表消除该 LIVE 冲突**（`8b89fe7` 未改写；历史 CONFLICT 判定保留于 §3.2/§6）；②TheHive 写入响应 key 不匹配（独立缺陷，非 Mapping Conflict，**未修**）；③三侧生产版本全 UNKNOWN（**未变**）。

**下一道建议 Gate（优先级详见 §9/§10）：** **P1 = G1 Wazuh Runtime Safety** 的**安全处置已由 G1-A→G1-B→G1-C→G1-D 收口**（`0c372aa`，VERIFIED-scoped）；**尚存的 G1 尾项**（版本限定词表再填充 / 真实 Wazuh Reader）依赖 **P2 = Production Version Evidence Gate**，仍为 EVIDENCE REQUIRED。安全阻塞已越过，下一道 Gate 的优先级决策**恢复到 G2–G5**（真实外部契约认证），但**不得**因此自动宣布任何真实 Adapter 已获实现授权（§9/§10）。

---

## §2 Frozen Platform Invariants

以下为必须继承的 3.4.5-A / 3.4.3 已封板契约，本 Consolidation **不修改、不弱化**任何一条：

| # | 不变量 | 一手证据 |
|---|---|---|
| I-1 | `execution_log` = **Dispatch Fact**（8 词状态机；adapter 终态 `{succeeded,failed}`） | `executions/models.py:20-22`；`manual-reconcile.md:295` |
| I-2 | `execution_outcome` = **External Outcome Fact**，**append-only**（5 词） | `models/execution_outcome.py:25-33`；`reconciliation-contract.md:138` |
| I-3 | Dispatch succeeded/failed **≠** 外部效果成功/失败（O5/D3.4-04）；`dispatch=succeeded`+`outcome=confirmed_failure` 合法 | `manual-reconcile.md:293-296` |
| I-4 | Outcome 五态语义不变：`unknown｜pending｜confirmed_success｜confirmed_failure｜reconciliation_failed` | `execution_outcome.py:25-33`；`reconciliation-contract.md:17-32,159-164` |
| I-5 | Webhook **只接收事实，不触发执行**（无 executor / retry / compensation / 出站 HTTP） | `webhook.py:79-81` |
| I-6 | Manual reconcile 是**显式读取**，ONE `read()` per POST，**不自动重试 / 补偿 / 轮询** | `manual_reconcile.py:108-115,353` |
| I-7 | 不识别的外部状态**必须拒绝**（`UnrecognizedExternalState`），**NEVER 降级为 `unknown`** | `reconciliation.py:43-44,699-705` |
| I-8 | Read failure **不得伪造 external_state**；事实时间用 server-observation，不伪装为外部事件时间 | `manual_reconcile.py:380-393` |
| I-9 | 读取失败 / 404 / 401 / 403 / timeout **不得自动等价于 `confirmed_failure`**；transport 失败 → `reconciliation_failed` | `manual_reconcile.py:113-115,337-338`；`reconciliation.py:615-623` |
| I-10 | **能力拒绝 ≠ 传输失败**：`UnsupportedAdapterRead`（无 reader，404，零 fact）与 `reconciliation_failed`（reader 存在但传输失败，200，+1 fact）是**永久分离**语义 | `manual_reconcile.py:349-354`；`registry.py:49-63` |
| I-11 | `reconciliation_failed` 可为**当前 derived state**，但**永不解释为"外部效果失败"**；历史 fact 不改 | `manual-reconcile.md:46`；`derivation.py:118-122` |
| I-12 | 不修改现有 `execution_log` 状态机、历史记录或已封板接口；**绝不建第二套 mapping，绝不偷改 `8b89fe7`** | `manual-reconcile.md:200-201`；`mapping.py`（NO second mapping table） |

---

## §3 Evidence Provenance & Version Matrix

**证据优先级（严格降序，继承 Spec §1）：** 目标生产实例实际契约 > 精确版本权威源码/规范 > 版本官方文档 > 部署模板 > 本地源码推断 > 历史设计假设/注释。生产版本未知时保留 UNKNOWN，不以源码/Docker tag/README/依赖版本/历史测试冒充生产证明。

### 3.1 三域版本矩阵（每个 Adapter 独立展示 Source / Deployment / Production）

| Adapter | Source 域（仓库源码） | Deployment 域（部署模板） | Production 域（真实实例） |
|---|---|---|---|
| **Wazuh** | `5.1.0-alpha0` — `wazuh-main/VERSION.json` + `wazuh-docker-main/VERSION.json` 双证 `{"version":"5.1.0","stage":"alpha0"}` | `5.1.0`（**GA tag，无 `-alpha0`**）— `wazuh-docker-main/{single,multi}-node/docker-compose.yml`（B0 §1 记录，与 source 不同 build） | **UNKNOWN** — `.env.example:42 WAZUH_BASE_URL=`（空）；`config.py:95`；`sentinelflow/docker-compose.yml` 无 wazuh 服务 |
| **Shuffle** | 前端 `frontend/package.json:version=2.0.0`（**仅前端**）；无单一权威平台/后端版本常量；workflow-execution schema 在**外部 `shuffle-shared`** | **浮动 `:latest`**（无版本 pin）— `Shuffle-main/docker-compose.yml`：`shuffle-frontend/backend/orborus:latest` + `opensearch:3.2.0` | **UNKNOWN** — `.env.example:40 SHUFFLE_BASE_URL=`（空）；`config.py:93`；`sentinelflow/docker-compose.yml` 无 shuffle 服务 |
| **TheHive** | `4.1.24-1` — `TheHive-main/build.sbt:5`（Scala 2.12.13/2.13.1）；`ScalliGraph` submodule 目录**空**（框架层依赖缺失） | sbt 派生（`docker.sbt`：`thehiveproject`，tag 由 `version.value` 推导，`FROM openjdk:8`，`EXPOSE 9000`）；仓库无独立 compose pin | **UNKNOWN** — `.env.example:45 THEHIVE_BASE_URL=`（空）；`config.py:101`；`sentinelflow/docker-compose.yml` 无 thehive/cortex 服务 |

> **三域分离结论：** 三侧 Production 域**全部 UNKNOWN**，且 `sentinelflow/docker-compose.yml` 仅部署 `postgres`（无任一外部 Adapter co-deploy）。因此**所有关于"真实实例行为"的结论均不成立**，只能对各自 Source 域版本限定成立。

### 3.2 证据登记表（Evidence Register）

| 证据 ID | Adapter | 证据域 | 精确版本/commit | 文件:行 / 规范位置 | 证明的命题 | 限制条件 | 认证状态 |
|---|---|---|---|---|---|---|---|
| EV-W-01 | Wazuh | Source | 5.1.0-alpha0 | `wazuh-main/VERSION.json` | 审计源码版本 | 仅源码域，≠生产 | CONFIRMED（源码域） |
| EV-W-02 | Wazuh | Source | 5.1.0-alpha0 | `api/api/spec/spec.yaml`（B0 S1：AgentStatus L920-927；`command_id` 0 匹配；JWT L11-14） | 无 command-status REST read；`command_id` 无对应 | 版本限定 | CONFIRMED（源码域） |
| EV-W-03 | Wazuh | Source | 5.1.0-alpha0 | `framework/wazuh/core/indexer/active_response.py`（B0 S2：AR_SCHEMA 无 result；`"ok"`=task 受理 L519） | AR 索引=触发事实，非命令效果 | 版本限定 | CONFIRMED（源码域） |
| EV-W-04 | Wazuh | Repo（最低优先级） | `8b89fe7`（历史）→ `0c372aa`（G1-C 已清空） | `reconciliation.py` wazuh 词表块（原 `:487-527`） | **修复前：** Wazuh 非空词表 LIVE；**G1-C 后：** 四集全空（fail-closed） | **B0 已裁证据 INVALID** | 历史 CONFLICT（保留）→ **G1-C 已消除 LIVE 冲突**（见 §6） |
| EV-W-05 | Wazuh | Repo/Deploy | 当前 | `config.py:95`；`.env.example:42`；`docker-compose.yml`（仅 postgres） | 生产未配置/未部署 Wazuh | 缺省≠强制门 | CONFIRMED（缺省态） |
| EV-W-06 | Wazuh | Repo/Test | `9119036`（修复前取证） | `test_webhook_persistence.py:311-336`（修复前锚点） | **修复前：**token 配置后 `success/ok/completed→confirmed_success` LIVE 可达 | 证明**不安全映射可达**（G1-C 前取证事实，保留） | CONFIRMED（历史风险证据）→ **G1-C 已反转该锚点为 422 零 fact**（`0c372aa`） |
| EV-S-01 | Shuffle | Source | 前端 2.0.0 | `Shuffle-main/frontend/package.json` | 前端版本 | 非平台/后端权威版本 | PARTIAL |
| EV-S-02 | Shuffle | Deploy | `:latest` | `Shuffle-main/docker-compose.yml:3,17,36` | 部署模板浮动 tag，无 pin | 无法据此定版 | CONFIRMED（无 pin） |
| EV-S-03 | Shuffle | Repo | `8b89fe7` | `reconciliation.py:528-549` | Shuffle 词表全空 + GAP | trigger-only，无 read 词表 | CONFIRMED |
| EV-S-04 | Shuffle | Repo | 3.2.x 封板 | `shuffle.py:84,254-255` | `external_execution_id` **可选**；`workflow_id`=模板 id | reference 可能缺失 | CONFIRMED |
| EV-S-05 | Shuffle | External | UNKNOWN | 外部 `shuffle-shared`（不在工作区） | WorkflowExecution schema/状态语义 | **无法在工作区认证** | EVIDENCE-GAPPED |
| EV-H-01 | TheHive | Source | 4.1.24-1 | `build.sbt:5` | 审计源码版本 | 仅源码域 | CONFIRMED（源码域） |
| EV-H-02 | TheHive | Source | 4.1.24-1 | `dto/v0/Case.scala:29-87`（OutputCase `_id`/`id`/`caseId:Int`，无 `case_id`） | 真实 v0 case 响应字段 | 版本限定 | CONFIRMED（源码域） |
| EV-H-03 | TheHive | Source | 4.1.24-1 | `models/Case.scala:10-11`（CaseStatus `{Open,Resolved,Duplicated}`） | case 生命周期=人工判断 | 版本限定 | CONFIRMED（源码域） |
| EV-H-04 | TheHive | Source | 4.1.24-1 | `controllers/v0/Router.scala`（`GET /case/$caseId`）+ `CaseCtrl.get` | case read endpoint 存在 | 版本限定 | CONFIRMED（源码域） |
| EV-H-05 | TheHive | Repo | 3.2.5 封板 | `thehive.py:241-254`（读 `case_id`）+ `:341-345`（409 无 case_id） | 写入契约假设 `case_id` | **与 EV-H-02 冲突** | DEFECT（见 §6） |
| EV-H-06 | TheHive | Repo | `8b89fe7` | `reconciliation.py:550-568` | TheHive 词表全空 + GAP | created≠resolved | CONFIRMED |
| EV-H-07 | TheHive | Source | 4.1.24-1 | `ScalliGraph/` submodule **空**（0 scala 文件） | 框架层 ErrorHandler/auth 中间件不在工作区 | 401/403/404 HTTP 映射 EVIDENCE-GAPPED | EVIDENCE-GAPPED |
| EV-P-01 | 平台 | Repo | `fd3ac34`..`abf26a7` | `registry.py:74-82`；`manual_reconcile.py:366`；`webhooks.py:172-184` | 空 registry + 空 token 双缺省门 | 见 §8 核验 | CONFIRMED |

---

## §4 Cross-Adapter Capability Matrix

> 每个状态附**适用版本**与**适用效果范围**。`SUPPORTED` 均版本+范围限定；`UNSUPPORTED` 非永久/跨版本绝对结论。

| 维度 | Wazuh（For 5.1.0-alpha0） | Shuffle（限已审计源码） | TheHive（For 4.1.24-1） |
|---|---|---|---|
| **Read Endpoint** | `UNSUPPORTED`（无 command-status REST read；EV-W-02） | `SUPPORTED`（workflow-execution 查询路径存在） | `SUPPORTED`（`GET /api/case/{id}`→`CaseCtrl.get`；EV-H-04） |
| **Read Semantics** | `UNSUPPORTED`（agent liveness/触发时间≠命令效果） | `EVIDENCE-GAPPED`（schema/语义在外部 shuffle-shared；EV-S-05） | `EFFECT-SCOPE GAP`（case lifecycle=人工判断，非响应效果） |
| **Reference** | `FAIL`（`command_id` 0 匹配；`task_id` 非 REST read） | `PARTIAL`（单 `external_execution_id` 不足 workflow-scoped；EV-S-04） | `FAIL`（`case_id` key 不匹配 EV-H-05；且仅达人工生命周期资源） |
| **Response Schema** | 无命令结果 schema（AR_SCHEMA 无 result；EV-W-03） | 权威 WorkflowExecution schema 不在工作区（EV-S-05） | OutputCase 权威一手（`_id`/`id`/`caseId:Int`/`status`；EV-H-02） |
| **Success States** | **修复前**词表 `{completed,confirmed,done,success,ok}` **INVALID**（B0 §8 证据链断裂）；**G1-C 后 = ∅**（`0c372aa` 已清空，一律 refused） | ∅（无 verifiable terminal-state；EV-S-03） | ∅（created≠resolved；EV-H-06） |
| **Failure States** | ∅（真实无 terminal-failure 命令词；维持 fail-closed） | ∅ | ∅ |
| **Pending States** | **修复前**旧 `{running}` **INVALID**（真实无 running；pending 是连接态假朋友）；**G1-C 后 = ∅** | ∅ | ∅ |
| **Unknown States** | **修复前**旧 `{unknown}` **INVALID**（真实 enum 无 unknown）；**G1-C 后 = ∅** | ∅（词表外一律 refused） | ∅（词表外一律 refused） |
| **Timestamp** | `FAIL`（仅 trigger time，无 effect time；禁伪装） | 未认证（外部 schema） | 无外部效果完成时间（startDate/endDate=人工；createdAt=记录 CRUD） |
| **Auth** | `FAIL`（真实 JWT vs write Basic 不一致；read auth 未设计） | Bearer/apikey（write 侧）；read 认证未在权威 schema 层核验 | Bearer apikey（`Authentication.scala`）；server-side 强制在空 ScalliGraph（EV-H-07） |
| **HTTP 404/401/403** | N/A（无 read path） | 未认证 | `EVIDENCE-GAPPED`（ErrorHandler 在空 ScalliGraph；org-visibility 使跨租户与不存在或不可区分） |
| **Timeout** | 平台 transport→`reconciliation_failed`（adapter-agnostic，I-9） | 同左 | 同左 |
| **Mapping Conflict** | **修复前 YES**（旧非空词表与权威证据冲突；B0 裁 INVALID）；**G1-C 后 = NO**（`0c372aa` 四集已清空，LIVE 冲突消除） | **NO**（四集空） | **NO**（四集空） |
| **Implementation Blocker** | `BLOCKED`（存在性缺口 + 版本门；**LIVE 不安全映射已由 G1-C 处置**，`0c372aa`；真实 Reader 仍 BLOCKED） | `BLOCKED`（reason: semantic authentication） | `BLOCKED`（reason: external-effect-scope gap）+ 独立 Write Contract Defect |

---

## §5 Adapter-Specific Decision Records

### 5.1 Wazuh

- **已证实事实：** 审计源码 = `5.1.0-alpha0`（EV-W-01）；该版本无可信 command-level AR 结果 REST 读契约（EV-W-02/03）；`command_id` 在 `spec.yaml` 0 匹配；真实 `"ok"` = Task Manager 任务受理态（假朋友）；生产版本 UNKNOWN、未 co-deploy（EV-W-05）。
- **未证实假设（禁止采信）：** 旧词表 `{completed,confirmed,done,success,ok}/running/unknown` 来自 write 适配器虚构同步 dispatch 响应（`wazuh.py:94-99` + 注释），**B0 §4 已逐项证伪**；`reconciliation.py:489-495` 的"agent_status IS the effect status"注释前提为虚构。
- **当前阻塞（G1-D 更新）：** ①Mapping Conflict 历史 = YES，**G1-C（`0c372aa`）已前向清空词表消除 LIVE 冲突**（版本限定词表再填充仍受版本门约束）；②无生产版本证据（**未变**）；③**Runtime Safety Gate：修复前 NOT VERIFIED → G1-C 后 VERIFIED-scoped**（§8.2）；④真实 Wazuh Reader 尚未实现（**未变**）。
- **禁止的推断：** 不得把 agent liveness / dispatch acceptance / trigger timestamp / 内部 task ID 猜为命令效果证据。**（G1-D 更新）** 原「不得写成'词表已清空'/'Amendment 已实施'」的禁令针对**修复前**状态；**G1-C（`0c372aa`）已合法前向清空词表**，故现在**必须**如实记为「已清空（fail-closed 安全修复）」——但**清空 ≠ 已获真实读取能力**，也**≠ 生产已验证**，不得据此写成"Wazuh 结果读取已支持"或"生产 Outcome 闭环已完成"。
- **可行性候选（G1-D 更新）：** B0 Amendment Implementation（forward commit 清空词表 + 去锚定）**已由 G1-C（`0c372aa`）完成**（安全理由、版本独立）；**尚存路径：** 生产版本确认（G2）→ 版本化 Evidence Audit → 未来若获真实命令级 read 证据，再经独立 Design Freeze 重新填充词表 / 设计 WazuhReadAdapter（**不因清空而自动重开**）。
- **解阻所需证据：** 真实生产实例版本（live `GET /` / 镜像 tag / `wazuh-control -V`，**仅版本信息，绝不索取凭据**）；对应版本命令级效果读契约的权威证据。

### 5.2 Shuffle

- **已证实事实：** workflow-execution 读路径存在（Read Endpoint SUPPORTED，限已审计源码）；词表四集全空 + 诚实 GAP（EV-S-03）；`external_execution_id` 可选、`workflow_id` 为模板 id（EV-S-04）；部署模板浮动 `:latest`（EV-S-02）。
- **未证实假设（禁止采信）：** 真实候选状态 `FINISHED/SUCCESS/FAILURE/ABORTED/EXECUTING/WAITING` 的**来源与层级**未认证；`FINISHED`≠效果成功、`ABORTED`≠效果失败；不得因 UI 颜色 / terminal 分类 / action 级结果赋予 execution-level `confirmed_success/failure`；未知态不用前端 fallback 猜测。
- **当前阻塞：** Read Semantics EVIDENCE-GAPPED——权威 `WorkflowExecution` schema、精确版本、状态语义在**外部 `shuffle-shared`**（EV-S-05，不在工作区）；组合 reference 契约未认证；生产版本 UNKNOWN。
- **禁止的推断：** 不得把"真实候选读路径存在"写成"已具备可用 Reader"；不得提前开放终态映射。
- **可行性候选：** 三侧中**最有希望率先获得 command-level outcome evidence** 的候选（读路径已存在，缺的是权威 schema/语义认证）。
- **解阻所需证据：** `shuffle-shared` 对应精确版本的权威 `WorkflowExecution` handler/schema/状态语义；workflow-scoped 读取所需的组合 reference 契约；生产版本确认。

### 5.3 TheHive

- **已证实事实：** 当前写入动作 = `escalate_to_incident`，机器目标 = 创建 case（`thehive.py`；THEHIVE_ACTIONS 仅此）；case read endpoint 真实存在（EV-H-04）；CaseStatus `{Open,Resolved,Duplicated}` 权威一手（EV-H-03）；词表四集全空（EV-H-06）；源码 `4.1.24-1`（EV-H-01）。
- **效果范围区分（Review 限定，必须固化）：**
  1. **Case 创建事实** — 对 `escalate_to_incident` 而言，资源是否真实创建是其目标效果的**候选证据**，不否认其所有未来 Outcome Reconciliation 可能性。
  2. **Case 人工生命周期** — `Open/Resolved/Duplicated/resolutionStatus/impactStatus` 反映案件管理/调查语义，**不能证明隔离/封禁等响应动作生效**。
  3. **Cortex 执行结果** — 相邻组件 job/analyzer/responder **不能自动归属 TheHive-core**，且当前 execution 无相应 jobId 关联。
- **当前阻塞：** Read Semantics EFFECT-SCOPE GAP；Reference FAIL（`case_id` key 不匹配 + 仅达人工生命周期资源）；另有独立 Write Contract Defect（§6）。
- **禁止的推断：** 不得写成"TheHive 永远无 Outcome Reconciliation 能力"；不得反推 `GET case 200 → confirmed_success`；不得拿 UI 颜色/fallback/2xx 当权威。
- **可行性候选：** 通过权威资源读取验证 **case creation** = 未来独立 **Resource-Effect Design Candidate**（尚未获语义与关联契约认证）。
- **解阻所需证据/前置：** 精确 resource ID（`_id` vs `caseId` 语义选定）、原始 execution 关联、组织/租户上下文、幂等重复、资源删除/不可见歧义、时间戳与状态语义。

---

## §6 Contract Conflict & Defect Register

> 分类登记，**不得混为一个"Adapter 不支持"**。

| 类别 | 条目 | Adapter | 证据 | 当前处置 | 隔离声明 |
|---|---|---|---|---|---|
| **Mapping Conflict** | MC-01：旧非空词表 `{completed,confirmed,done,success,ok}→confirmed_success`、`running→pending`、`unknown→unknown` 与真实 5.1.0-alpha0 权威证据冲突 | Wazuh | `reconciliation.py`（原 `:487-527`，EV-W-04）vs `spec.yaml`/`active_response.py`（EV-W-02/03）；B0 §4 | **修复前 YES**；B0 裁 INVALID；**G1-C（`0c372aa`）已前向清空词表消除 LIVE 冲突**（`8b89fe7` 未改写；版本限定再填充仍受版本门约束） | 与 DC-01 严格隔离 |
| **Write Contract Defect** | DC-01：写适配器读 `payload.get("case_id")`，真实 v0 OutputCase 为 `_id`(String)/`id`(String)/`caseId`(Int)，**无 `case_id`** | TheHive | `thehive.py:241-254`（EV-H-05）vs `dto/v0/Case.scala:29-87`（EV-H-02） | **Independent Write Contract Defect Candidate**；高优先级；本轮不修 | **非 Mapping Conflict**（见下） |
| **Write Contract Defect** | DC-02：409 幂等重复成功路径 `detail` 无 `case_id`，reference 未持久化 | TheHive | `thehive.py:341-345` | 并入 DC-01 独立复核 | 非 Mapping Conflict |
| **Reference Gap** | RG-01：`command_id` 无真实对应（`task_id` 非 REST read） | Wazuh | `spec.yaml` 0 匹配（EV-W-02）；B0 §7 | FAIL；无 read path 故不进一步设计 | — |
| **Reference Gap** | RG-02：单 `external_execution_id` 不足 workflow-scoped 读取；且可选/可能缺失 | Shuffle | `shuffle.py:84,254-255`（EV-S-04） | PARTIAL；需组合 reference 契约认证 | — |
| **Semantic Gap** | SG-01：WorkflowExecution 状态语义在外部 shuffle-shared，无法在工作区认证 | Shuffle | EV-S-05 | EVIDENCE-GAPPED | — |
| **Semantic Gap** | SG-02：case lifecycle=人工调查域，非机器响应效果 | TheHive | `models/Case.scala:10-11`（EV-H-03） | EFFECT-SCOPE GAP | — |
| **Version Gap** | VG-01：三侧 Production 域全 UNKNOWN；Wazuh source(alpha0)≠deploy(GA)；Shuffle deploy `:latest` 无 pin；TheHive ScalliGraph submodule 空 | 全部 | §3.1（EV-W-05/EV-S-02/EV-H-07） | 保留 UNKNOWN；需 Production Version Evidence Gate | — |

**DC-01 与 MC-01 的明确隔离：** MC-01 是**外部状态→outcome 词表**的证据冲突（reconciliation 层）；DC-01 是**写入响应字段解析**的契约不匹配（write adapter 层，`case_id` 提取）。二者层级不同、成因不同、修复路径不同，**不得合并登记**。`caseId`（数字案号）与 `_id`（字符串资源标识）语义不同，**不得简单 `case_id`→`caseId` 替换**。

---

## §7 Outcome Semantics & Effect-Scope Boundary

**必须严格区分的效果范畴（不得跨界归属）：**

| 范畴 | 定义 | 归属 | 认证边界 |
|---|---|---|---|
| **Command Effect** | 某条命令/响应动作在外部系统真实生效（隔离/封禁成功） | Wazuh AR / Shuffle workflow 执行结果 | 需命令级 terminal-effect 权威证据；Wazuh 当前无（§5.1），Shuffle 未认证（§5.2） |
| **Resource Creation** | 目标资源被真实创建（case 已存在） | TheHive `escalate_to_incident` 的机器目标 | 创建事实=目标效果候选证据；需精确 resource ID + 原始 execution 关联（未来 Design Candidate） |
| **Business Lifecycle** | 资源后续业务状态流转 | — | 不等于创建效果，也不等于响应效果 |
| **Human Investigation** | 人工调查判断（case Open/Resolved/Duplicated、resolutionStatus、impactStatus） | TheHive case 生命周期 | **禁止**用其认证响应动作效果（SG-02） |
| **Dispatch Receipt** | 外部系统受理了请求（202/accepted/task 受理 `"ok"`） | 各 write 适配器 dispatch 层 | **受理 ≠ 效果成功**（I-3；Wazuh `"ok"`=task 受理假朋友，EV-W-03） |

**TheHive 限定性裁决（固化）：** 使用 case lifecycle 状态认证响应动作效果的方案**不可行**；通过权威资源读取验证 case creation 是**未来独立 Design Candidate**，尚未获得语义及关联契约认证。**不写成"TheHive 永远无 Outcome Reconciliation"，也不反推 `GET case 200 → confirmed_success`。**

**Shuffle 状态词语义约束（固化）：** `FINISHED` 不自动=效果成功；`ABORTED` 不自动=效果失败；`EXECUTING/WAITING` 不自动=pending；未知状态不允许前端 fallback 猜测；execution-level 终态不得由 action 级结果或 UI 分类推导。

**Wazuh 状态词语义约束（固化）：** `agent_status {active,pending,never_connected,disconnected}` 是连接/生命周期态，**非命令结果**；`"ok"` 是 Task Manager 受理态；`@timestamp` 是 trigger time——三者**均不得**映射为 confirmed_success/failure。**（G1-D 更新）G1-C（`0c372aa`）已将 Wazuh 四组词表清空，使上述语义约束不再仅依赖注释/纪律，而由 mapping 层结构性 fail-closed 强制（任何 Wazuh 态一律 refused）。**

---

## §8 Risk & Blast-Radius Assessment

### 8.1 已有生产代码中的不安全假设

| 风险 | 位置 | 性质 | 实际验证状态 |
|---|---|---|---|
| **R-1（修复前最高）：Wazuh 非空词表 LIVE，经 webhook 可将自称 success 的回调映射为 `confirmed_success`** | `reconciliation.py`（原 `:487-527`，`8b89fe7`）→ `webhook.py:149 map_external_state` | **修复前：** 不可信映射（B0 §4 已证伪）在生产代码未清空；**G1-C（`0c372aa`）已前向清空四集** | 修复前 **NOT VERIFIED** → **G1-C 后 VERIFIED-scoped**（见 8.2） |
| R-2：TheHive 写入对真实 v0 实例将成功创建误判为 `ExecutorOutcomeViolation`，reference 无法持久化 | `thehive.py:241-254` | 契约不匹配（DC-01） | 源码级 CONFIRMED（EV-H-02 vs EV-H-05）；生产未部署故当前潜伏 |
| R-3：`reconciliation.py:489-495` 注释曾声称"agent_status IS the effect status" | `reconciliation.py`（原 `:489-495`） | 虚构证据注释残留，可能误导后续实现 | 修复前 CONFIRMED（注释存在）→ **G1-C（`0c372aa`）已将该注释替换为证伪说明（RESOLVED）** |

### 8.2 Wazuh Runtime Safety Gate Verification（Spec §4 强制单列）

**区分：设计要求（"应当通过部署门保持 fail-closed"）vs 已验证事实（"实际部署门已存在且有效"）。**

> **本节含两个时点的判定，均予保留（不倒写历史）：**
> - **§8.2.A 修复前判定（基线 `73b9c8b`，历史）：`NOT VERIFIED`。**
> - **§8.2.B G1-C 后当前判定（基线 `0c372aa`）：`VERIFIED — scoped`。**

#### §8.2.A 修复前判定（历史保留，基线 `73b9c8b`）

Wazuh 非空词表（R-1）修复前有**两条**可达路径，各自的门性质不同：

| 路径 | 门机制 | 证据 | 门性质 | 修复前核验结论 |
|---|---|---|---|---|
| **Manual Reconcile** | 空 registry → `registry.get("wazuh")` → `UnsupportedAdapterRead` → 404 / 零 fact | `registry.py:74-82`；`manual_reconcile.py:366`；`test_manual_reconcile_crosslayer.py`（`TestProductionRegistryEmpty` + Case A） | **结构性**（无 WazuhReadAdapter；激活需改代码=未来 Gate） | **VERIFIED**（源码 + 测试） |
| **Webhook Inbound** | `WAZUH_CALLBACK_TOKEN=""` 默认 → `if not expected … raise 401` | `webhooks.py:172-184`；`config.py:144`；`test_webhook_authentication.py`（`no_tokens` + default-empty） | **配置默认**（运维可逆；真实集成的预期动作即配置该 token） | 缺省态 fail-closed **VERIFIED**；**但非语义安全门** |

**修复前判定：Wazuh Runtime Safety Gate = `NOT VERIFIED`。** 理由（不以设计要求代替实测）：①webhook 防护**仅**依赖运维可逆的 `WAZUH_CALLBACK_TOKEN=""`，非强制语义拦截；②`test_webhook_persistence.py:311-336`（修复前）实测证明 token 配置后 `{success,completed,confirmed,done,ok}→confirmed_success` 落 fact（HTTP 200），LIVE 且可达；③B0 Amendment 当时未实施；④无部署门主动阻止运维配置该 token。**（此判定作为历史基线保留，不倒写。）**

#### §8.2.B G1-C 后当前判定（基线 `0c372aa`，2026-09-08）

**G1-C 变更：** 唯一生产改动 = 清空 `ADAPTER_STATE_VOCABULARIES["wazuh"]` 四集 + `case_insensitive=False` + `state_key=None`（`0c372aa`；`8b89fe7` 未改写）。因 `mapping.py:103`「NO second mapping table」，该单点清空**同时**封住 webhook（`webhook.py:149`）+ manual（`manual_persist.py:204`）+ 任何直接调用 `map_external_state` 的内部代码。

| 路径 | 门机制（G1-C 后） | 证据 | 门性质 | 当前核验结论 |
|---|---|---|---|---|
| **Webhook Inbound** | **mapping 层语义 fail-closed**：任何 Wazuh 态 → `UnrecognizedExternalState` → 422 / 零 fact（**不再依赖 token 默认值**）；token 配置门叠加保留 | `reconciliation.py` wazuh 词表块（四集空）；`webhook.py:149`；反转后 `test_webhook_persistence.py`（旧 success/running/unknown 锚点 → 422 零 fact） | **语义**（结构性，与 token/reader/版本无关） | **VERIFIED**（源码 + 隔离 HTTP 全栈回归） |
| **Manual Reconcile** | 空 registry 结构门（保留）**+ mapping 层语义 fail-closed**（新增覆盖） | `registry.py:74-82`；`manual_persist.py:204`；`test_manual_reconcile_crosslayer.py`（注入 fake reader 后 Wazuh 态仍 refused） | **结构性 + 语义**（即便未来注册 reader，空词表仍 refused） | **VERIFIED**（源码 + 跨层回归） |

**当前判定（用户 G1-C Final Review 裁决原文）：**

> **`VERIFIED — scoped to the audited inbound mapping paths and isolated regression environment. Production deployment and historical data safety remain unverified.`**

**判定理由（以实测为据，非设计要求）：**
1. **隔离回归实测：** 完整后端 **2494 passed / 0 failed / 3 deselected / 0 skipped**；focused 6 文件 611 passed；跨层 74 passed；`git diff --check` clean。旧 Wazuh success/running/unknown 锚点已**反转为 422 / refused / 零 fact**（不删测，平台成功管线证明迁 test-only fake adapter 保留）。
2. **语义门取代配置门：** webhook 路径现在由 mapping 层空词表强制 fail-closed，**不再仅靠运维可逆的 token 默认值**；无论 token 是否配置、是否注册 reader、是否配置生产版本，Wazuh 态一律 refused。
3. **无 auto-reopen：** 清空后无任何机制因配置版本或注册 reader 自动重开词表；再填充须独立命令级效果证据 + 独立 Design Freeze（B0 版本限定纪律）。

**范围限定（scoped 的边界，不得越界宣称）：**
- ✅ **已验证：** 已查明的入站映射业务路径（webhook / manual / 直接 `map_external_state` 调用）在**隔离回归环境**（TestClient + 内存 SQLite）中不再产生不可信 Outcome。
- ❌ **未验证（仍属五态 3-5）：** 真实生产部署未验收；历史数据污染未知（append-only 历史不改，当前无可用真实数据库查询结果、历史污染状态 UNKNOWN，其他部署须独立只读核查）；真实 Wazuh Reader（命令级效果读取）尚未实现。
- **不得**宣称"运行时已全面安全"或"生产 Outcome 闭环已完成"；本判定**仅**覆盖限定映射路径 + 隔离回归。

### 8.3 可能受影响的路径与需要的防护门（G1-D 更新）

- **Webhook 入站（3.4.4-D/E，已封板）：** 曾是 R-1 的 LIVE 暴露面；需要的防护门 = 清空 Wazuh 词表使其无论 token 配置均 refused。**该防护门已由 G1-C（`0c372aa`）落地，并在隔离回归中 VERIFIED-scoped（§8.2.B）；不再是"计划中"。**
- **Manual Reconcile（A2，已封板）：** 空 registry 结构性门有效（VERIFIED）；**G1-C 后叠加 mapping 层语义门**——即便未来注册 Wazuh reader，空词表仍使 Wazuh 态 refused。
- **Write Adapter（`thehive.py`，3.2.5 封板）：** R-2 的暴露面；需要的防护门 = 目标版本响应契约认证 + 契约修复（DC-01 独立 Gate）。**当前潜伏（TheHive 未部署），本轮未处置。**

> **诚实声明（G1-D 更新）：** Wazuh webhook/manual 入站的 mapping 层防护门**已由 G1-C 落地并在隔离回归验证生效（VERIFIED-scoped）**；但**真实生产部署未验收**，TheHive 写入契约门（DC-01）仍为**计划/未验证**。不得将 Wazuh 的隔离验证越界描述为生产验证，也不得将 TheHive 的计划门描述为已验证。

---

## §9 Prioritized Candidate Gates

> 仅提出候选，**不授权执行**。优先级依据：**安全风险 > 现有代码冲突 > 对后续 Gate 依赖 > 证据可获得性 > 最小改动**，**不以"哪个 Adapter 最容易先做出来"排序**。事实不足处给**条件优先级**，不伪造确定性。

| 优先级 | Gate ID | 名称 | 必须解决的问题 | 依赖前置 | 解阻证据 | 当前权限 |
|---|---|---|---|---|---|---|
| **P1** | **G1** | Wazuh Runtime Safety / Mapping Gate | R-1 LIVE 不安全映射处置；旧非空词表 Mapping Conflict；实际防护门验证 | **安全处置无版本前置**（已与 G2 解耦）；版本限定词表再填充 / 真实 Reader 仍依赖 G2 | **安全 remediation 已落地**（G1-C `0c372aa`：forward commit 清空词表 + 去锚定 + 测试反转/迁移）；**尚存尾项** = 版本限定再填充 / 真实 WazuhReadAdapter（须 G2 + 独立 Design Freeze） | **安全处置：已收口**（G1-A→G1-D，VERIFIED-scoped）；尾项：仅证据/设计候选 |
| **P2** | **G2** | Production Version Evidence Gate | 三侧目标实例精确版本与契约基线（Wazuh alpha0 vs GA vs 4.x；Shuffle `:latest`；TheHive 4.1.x） | 无（根证据门） | 真实生产实例版本证据（live API 版本端点 / 镜像 tag / 版本命令，**仅版本，绝不凭据**） | 仅证据候选 |
| **P3** | **G3** | TheHive Write Contract Gate | DC-01/DC-02：响应 ID（`_id` vs `caseId`）、409 幂等 reference、真实版本兼容 | 依赖 G2（TheHive 目标版本响应契约） | 目标版本真实响应契约 + 200/201·缺失 ID·错误类型·409·reference 持久化测试矩阵 | 仅独立修复候选 |
| **P4** | **G4** | Shuffle Semantic Authentication Gate | SG-01：shuffle-shared schema、状态语义、组合 reference（RG-02） | 依赖 G2（Shuffle 精确版本） | 对应版本权威 `WorkflowExecution` handler/schema/状态语义 + workflow-scoped 组合 reference 契约 | 仅证据候选 |
| **P5** | **G5** | TheHive Resource-Effect Design Gate | case creation 的独立效果验证语义（resource-existence ↔ 原始 execution 关联） | 依赖 G3（精确 resource ID）+ G2 | 关联/幂等/删除不可见/时间戳/状态语义的完整设计证据 | 仅设计候选 |

**优先级理由（可审查）：**
- **G1 = P1（已收口）**：曾是唯一 **LIVE 运行时安全风险**（不可信映射经 webhook 可达 confirmed_success）+ 现有代码冲突（`8b89fe7` 非空词表）。**该安全风险已由 G1-C（`0c372aa`）前向清空词表消除**，G1-A→G1-D 完成安全收口（VERIFIED-scoped）；G1 尚存尾项（版本限定再填充 / 真实 Reader）降为证据/设计候选，依赖 G2。
- **G2 = P2**：G1 **尾项**（版本限定词表再填充 / 真实 Reader）、G3、G4 均依赖生产版本基线；是**依赖链根节点**，但需外部/用户证据（可获得性受限于生产访问）。**（G1-D 更新）G1 的安全 remediation 已与 G2 解耦并先行落地（G1-C），不再阻塞于版本门。**
- **G3 = P3**：真实缺陷（成功创建被误判 + reference 丢失），但生产未部署 TheHive → 当前**潜伏**，blast radius 低于 G1。
- **G4 = P4**：可行性收益最高（Shuffle 最有望闭合），但纯属**证据获取**（外部 shuffle-shared），无 LIVE 风险，依赖 G2。
- **G5 = P5**：纯设计候选，前置最多（依赖 G3 解决 resource ID + 关联/幂等语义），**最后**。

> **条件优先级说明（G1-D：已裁决）：** G1 的"安全处置"与"版本限定 Amendment"的张力**已由用户 Review Gate 裁决解耦**——R-1 的不可信性对**任何** Wazuh 版本成立（B0 已证伪词表语义），故**安全 remediation 从 G2 版本门解耦并先行落地**（G1-C `0c372aa`，版本独立）；B0 的版本限定纪律**仍保留**，治理**未来**任何基于真实命令级证据的词表再填充。原 §12 OQ-2 据此关闭（见 §12.1）。

---

## §10 Decision Matrix

> 建议裁决 ∈ `{PROCEED TO DESIGN CANDIDATE, EVIDENCE REQUIRED, BLOCKED, DEFERRED}`。**此处仅为 Consolidation 建议，不是 Implementation 放行。**

| Gate | 建议裁决 | 依据 | 明确声明 |
|---|---|---|---|
| **G1 Wazuh Runtime Safety / Mapping** | **安全处置：CLOSED（G1-C `0c372aa`，VERIFIED-scoped）**；尾项（版本限定再填充 / 真实 Reader）：**EVIDENCE REQUIRED**（依赖 G2） | R-1 LIVE 暴露已由 G1-C 前向清空词表消除；G1-A→G1-D 完成安全收口 | 非 Implementation 放行；`8b89fe7` 未改写；**不授权真实 Wazuh Reader** |
| **G2 Production Version Evidence** | **EVIDENCE REQUIRED** | 本身即证据门；需真实生产实例版本，工作区无法自证（B0.1 已证） | 非 Implementation 放行；仅版本信息，绝不凭据 |
| **G3 TheHive Write Contract** | **PROCEED TO DESIGN CANDIDATE** | 缺陷已源码级 CONFIRMED（EV-H-02 vs EV-H-05）；可申请设计修复契约（先取目标版本响应契约） | 非 Implementation 放行；不改 3.2.5 冻结件；不简单换字段 |
| **G4 Shuffle Semantic Authentication** | **EVIDENCE REQUIRED** | 权威 schema/语义在外部 shuffle-shared，工作区不可认证 | 非 Implementation 放行；不建 ShuffleReadAdapter |
| **G5 TheHive Resource-Effect Design** | **DEFERRED** | 依赖 G3（resource ID）+ 关联/幂等/删除/时间戳语义前置未解 | 非 Implementation 放行；未来设计候选，暂缓 |

---

## §11 Acceptance Checklist（Spec §10 逐项自检）

| # | 验收项 | 结果 | 证据/说明 |
|---|---|---|---|
| 1 | 三次 Evidence Audit 已接受结论均纳入，无遗漏 Review 限定 | ✅ | §5 三条决策记录；TheHive 效果范围限定（§5.3/§7）；Shuffle 三修正（§5.2 状态词约束） |
| 2 | 所有关键事实附可追溯源码/版本/规范/审计位置 | ✅ | §3.2 证据登记表 EV-*；全文 file:line 引用 |
| 3 | Source/Deployment/Production 三域严格分离 | ✅ | §3.1 三域版本矩阵 |
| 4 | Wazuh 旧 mapping 状态如实记录；运行时防护宣称与验证层级一致 | ✅ | **修复前**：§6 MC-01（未实施）+ §8.2.A NOT VERIFIED（原样保留）；**G1-C 后**：§6 MC-01（`0c372aa` 已清空）+ §8.2.B **VERIFIED-scoped**（隔离回归实测，非生产验证）——五态分列见 §0.1 |
| 5 | Shuffle Read Endpoint 与 Read Semantics 分层，未提前开放终态映射 | ✅ | §4（SUPPORTED vs EVIDENCE-GAPPED）；§5.2 禁止推断 |
| 6 | TheHive case creation 与人工生命周期分离，保留资源效果验证候选 | ✅ | §5.3 三分；§7 限定裁决；§9 G5 |
| 7 | TheHive 写入契约缺陷独立登记，不混入 Mapping Conflict | ✅ | §6 DC-01/DC-02 + 隔离声明 |
| 8 | 所有 UNKNOWN/PARTIAL/EVIDENCE-GAPPED 均有明确解阻证据 | ✅ | §5 各"解阻所需证据"；§9 各 Gate 解阻证据列 |
| 9 | 决策矩阵≥5 项候选 Gate，优先级理由可审查 | ✅ | §9（G1-G5 + 理由）；§10 |
| 10 | 无新增 Reader / mapping 修改 / migration / 外部执行 / 自动重试轮询 | ✅ | 本轮仅新建本 `.md`；§0 非目标；git status 见交付 |
| 11 | 不声称未执行的测试通过；不声称已验证生产部署或外部效果 | ✅ | §1 非发布声明；§8.2.B 以隔离回归实测为据（G1-C 2494 passed），**明确区分**隔离验证 ≠ 生产验收（五态 3-5 未验证） |
| 12 | 文档完成后停止，等待正式 Review | ✅ | §12 停止条件；交付后停止，不 commit/push |
| 13 | **（G1-D 新增）** G1-C 安全收口如实记录，历史 CONFIRMED UNSAFE / NOT VERIFIED 未被倒写 | ✅ | §0.1 修订记录；§8.2.A（历史保留）/ §8.2.B（当前 VERIFIED-scoped）；G1-A 取证性质保留；G1-B FROZEN + §15 闭环记录 |

---

## §12 Open Questions & Stop Condition

### 12.1 未决问题（需谁提供何种证据）

| # | Open Question | 需谁 / 何种证据 |
|---|---|---|
| OQ-1 | 三侧真实生产实例的精确版本？（Wazuh alpha0/GA/4.x；Shuffle `:latest` 实际 tag；TheHive 4.1.x） | **用户/运维**在真实生产部署上提供版本信息（live 版本端点 / 镜像 tag / 版本命令）——**仅版本，绝不凭据** |
| OQ-2 | ~~G1 的安全 remediation（清空 Wazuh 词表使 webhook 也 fail-closed）是否应与 G2 版本门**解耦**优先处置？~~ **已裁决（RESOLVED，2026-09-08）** | **用户 Review Gate 已裁决：解耦**。安全 remediation 先行落地（G1-C `0c372aa`，版本独立）；B0 版本限定纪律保留治理未来词表再填充（见 §9 条件优先级说明） |
| OQ-3 | TheHive 目标版本真实 case 创建响应契约？（`_id`/`caseId` 哪个是可 reconcile 的权威 handle；409 幂等响应体字段） | **G3** 取目标版本权威响应契约 + 测试矩阵 |
| OQ-4 | Shuffle 对应版本 `shuffle-shared` 的权威 WorkflowExecution schema/状态语义？workflow-scoped 读取所需组合 reference？ | **G4** 取外部 shuffle-shared 对应版本权威证据 |
| OQ-5 | TheHive 401/403/404 的真实 HTTP 映射（ErrorHandler 在空 ScalliGraph submodule，EV-H-07）？ | 需 TheHive 对应版本 ScalliGraph 权威源码/规范（当前工作区缺失） |

### 12.2 停止条件

本 Consolidation 文档完成后**立即停止**：
- **不 commit、不 push**（保留未提交文档改动，等待 Review Gate 决定是否接受及提交）；
- **不进入任何候选 Gate（G1-G5）的执行**；
- **不修改任何生产代码 / mapping / migration / 配置 / 测试**；
- **不创建任何 Reader（WazuhReadAdapter / ShuffleReadAdapter / TheHiveReadAdapter）**；
- **不自行宣布本文档 `FROZEN`**。

等待用户对 Consolidation 进行正式 Review，决定是否冻结文档及下一步授权。

### 12.3 G1-D 安全收口停止条件（本轮）

本轮 G1-D 安全收口**仅**修改三份既有 DRAFT 文档（Consolidation / G1-A / G1-B），完成后**立即停止**：
- **不 commit、不 push**（三份文档保持未跟踪 DRAFT，等待用户最终 Review 决定提交范围）；
- **不改生产代码 / 测试 / 配置 / migration / 历史提交**（G1-C `0c372aa` 仅只读复核，不改写）；
- **不新增第四份仓库文件**（G1-C Closure Report 若需要，仅输出建议结构供 Review）；
- **不创建 Reader、不进入 G2–G5、不运行真实外部执行**。

---

> **文档状态：DRAFT（G1-D 安全收口修订中，待用户最终 Review）。原编制于 2026-09-08，基线 HEAD `73b9c8b`；G1-D 修订基线 `0c372aa`（G1-C 安全修复后）。本轮 DOCUMENTATION + READ-ONLY · NO CODE · NO COMMIT。**
