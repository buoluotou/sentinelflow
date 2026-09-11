# SentinelFlow M5 — 全仓代码审计（CODE AUDIT）

> 范围：真实全仓 `D:\edge\github\sentinelflow`（后端 `backend/app` 130 个 .py + 迁移 + 前端 `frontend/src` 49 个 ts/tsx + 配置/依赖/构建），**非**仅 M4 文件。
> 方法：入口→Outcome 全链只读追踪 + 三份并行子代理证据（后端链/前端/配置依赖）+ 本人对将修改项的逐条 `文件:行` 复核。
> 基线（审计时）：HEAD `5545de0`（main，ahead 63），Alembic head `0012`。M5 后续本地前向提交：`34799e2`(audit) → `f0085df`(logic-refactor)，现 HEAD `f0085df`（ahead 65）；quickstart/docker/docs/tests 阶段提交见 §20。
> 原则（§3）：**删重复 > 抽小函数 > 明确边界 > 最后才考虑架构重构**；**不为代码漂亮大规模重写稳定模块**；所有优化保持 §2 安全不变量。
> 回归：全量后端 `pytest tests -q` → **2869 passed / 14 deselected / 0 failed**（external 默认 deselect）。native smoke（Windows，SQLite，Demo mock）→ **exit 0**，业务链 12/17 步过真实 HTTP，执行步 fail-closed（见 H-3）。

**处置图例**：`FIXED(M5)`=本轮已修并回归 · `FIX(M5 §x)`=本轮后续阶段修（见对应交付） · `DEFERRED`=有意推迟并给出理由与修复方向（不属本轮 release-readiness 范围或触碰冻结安全架构）。

---

## 0. 业务链调用图与事务边界（§1）

两入口汇入同一去重管道：

```
POST /api/v1/alerts ─┐
POST /api/v1/normalize ─┤→ normalization → deduplication/engine.process
                        │      → risk/service.recalculate → risk/engine.calculate(factors)
                        │      → incidents/service.auto_create_from_risk (幂等: group.incident is None)
                        ↓
   AI: events/{id}/ai-analysis | ai-risk-summary | response-recommendation (三条结构对称路由)
                        ↓
   Approval: /approvals (GET, pending 派生) · /response-recommendations/{id}/approve|reject (一次性 INSERT)
                        ↓
   Execution(前向): POST /executions → executions/service.execute_response
        Guard(G2/G3/G4) → Policy(B-3) → build_dispatch_binding
        → ★Durable 门: recognized adapter & store=None → DurableStoreRequired/503
        → durable_dispatch.record (独立 Session commit) → executor.execute → append terminal
   Execution(补偿): POST /executions/compensate → compensate_response → executor.compensate  ← ✗无 Durable 门
                        ↓
   External Outcome:
     PUSH  POST /webhooks/{adapter} → outcomes/webhook.persist_callback_outcome (Service 自持 commit)
     PULL  POST /executions/{id}/reconcile → outcomes/manual_reconcile.reconcile_execution (Service 自持 commit)
                        ↓
   Dashboard: GET /dashboard/summary → 7 条聚合查询（纯读）
```

**事务纪律三态并存**（`get_db` 只 yield+close，不 commit/rollback）：
- Service 自持 commit：`risk/service.py:42`、`dedup/engine.py:83`、`outcomes/webhook.py:178`、`manual_reconcile.py`、`durable_dispatch.py`（独立 Session）。
- Service flush + API 层 commit：incidents / AI×3 / approval / execution（前向+补偿）。
- 边界缺陷见 HIGH-1。

**API endpoint 全量**：31 条（`/health` + `/ready`(M5 新增) 根级；其余 `/api/v1/*`）。无完全重复路由；`/executions/metrics`、`/executions/health` 必须先于 `/executions/{id}` 注册（依赖声明顺序，已在 docstring 标注）。

---

## 1. CRITICAL

### C-1 补偿路径绕过 Durable Dispatch 门 — `DEFERRED`（post-M5 安全里程碑 #1）
- **问题**：前向 `execute_response` 有 Durable 门（recognized adapter 且 store=None → `DurableStoreRequired`/503 fail-closed），但 `compensate_response`（`services/executions/service.py` 补偿分支）**无** `dispatch_attempt_store` 参数、**无** Durable 门、**无** `build_dispatch_binding` 预提交；`POST /executions/compensate`（`api/v1/response_execution.py`）也未注入 store。`wazuh.compensate` / `shuffle.compensate` 会发起**真实外部调用**。
- **影响**：配置真实 wazuh/shuffle 后，补偿外部动作无耐久预约记录；崩溃/终端写失败即丢失（正是 M4-F 为前向修复的"flush≠持久提交"问题，补偿侧未覆盖）。违反 §2「真实外部 Adapter 必须经 Durable Dispatch」。
- **位置**：`services/executions/service.py`（`compensate_response`）· `api/v1/response_execution.py`（`compensate_execution` 端点）· 对照前向门 `execute_response` 的 `DurableStoreRequired` 分支。
- **是否修复**：**否（本轮）**。
- **为何**：修复=把 M4 耐久派发架构**扩展到补偿路径**（新增 binding、独立提交、恢复关联、补偿侧 fail-closed 测试），属 M5 §0 明确排除的「继续创造新的安全架构」；且正确性依赖 PostgreSQL MVCC/崩溃验证（本机无授权 PG → UNVERIFIED）。**默认/演示配置 `EXECUTION_ADAPTER=mock`（零外呼），Demo 不受影响**；真实 Adapter 本就标记 LAB/EXPERIMENTAL/NOT-PRODUCTION-CERTIFIED（§4）。此为**预存**缺口，非 M5 引入，M5 不使其退化。
- **回归/建议**：列为 M5 之后**首个安全里程碑 #1**：把前向 Durable 门 + binding 对称应用到 `compensate_response`，端点注入 store，补 `test_dispatch_durable_integration` 补偿侧 fail-closed 断言（当前 `DurableStoreRequired` 仅测前向）。

---

## 2. HIGH

### H-1 Alert→Risk→Incident 非原子 — `DEFERRED`
- **问题**：`risk/service.py:42` `recalculate` **无条件 `db.commit()`**，早于 `dedup/engine.py:82` 的 `auto_create_from_risk` 与 `:83` 的最终 commit；`engine.py:75-77` 注释称三者在 "same transaction"、`risk/service.py` docstring 称 "commits on its own only when invoked standalone"，均与 `:42` 事实矛盾。
- **影响**：风险行先落库；若建案或最终提交失败，留下"已提交风险但无案"的中间态（非常规路径，单线程演示不触发）。
- **位置**：`services/risk/service.py:42` · `services/deduplication/engine.py:75-83`。
- **是否修复**：**否**。
- **为何**：改动核心稳定的摄取管道事务边界，release-readiness 里程碑前应冻结；需并发/崩溃 TDD + PG 验证。
- **回归/建议**：`recalculate` 改 `flush`，提交权收敛到 `engine.process` 单一边界；修正矛盾 docstring；补"建案失败回滚风险行"测试。

### H-2 审计时间戳进程级全局无锁 — `DEFERRED`
- **问题**：`services/executions/service.py` 的 `_LAST_AUDIT_STAMP` 模块全局 + `_next_audit_timestamp` 用 `global` 读改写，无锁。
- **影响**：多 worker/线程并发下 `created_at` 高水位可竞争，威胁 `derive_execution_state` 依赖的 `created_at DESC, id DESC` 单调派生序。
- **位置**：`services/executions/service.py`（`_LAST_AUDIT_STAMP` / `_next_audit_timestamp`）。
- **是否修复**：**否**（并发问题，需多 worker + PG 验证；单进程演示不触发）。
- **回归/建议**：改为 per-session 高水位或依赖 DB 序列，去 `global` 竞态；补并发派生序测试。

### H-3 SQLite 下 durable-dispatch 执行步 fail-closed（**平台边界，非缺陷**） — `DOCUMENTED`（Demo Mode 数据库须 PostgreSQL）
- **问题**：`services/executions/durable_dispatch.py` 的 `DurableDispatchAttemptStore.record()`（63-99）**故意**开独立 `Session`/连接，并在发起外部调用**之前**独立 `commit()`（M4-F 冻结的「flush ≠ durable commit」契约：预约记录必须先于外呼落盘，才能跨调用方 rollback / 终端写失败 / 崩溃存活）。PostgreSQL（MVCC）下，调用方开放的写事务与该独立连接的提交可并存；**SQLite 数据库级单一写锁**下形成同线程自死锁（调用方事务不提交直到 `record()` 返回，`record()` 的独立连接又拿不到写锁）→ `sqlalchemy.exc.OperationalError: database is locked`（`INSERT INTO dispatch_attempt`）→ `POST /api/v1/executions` 返回 500。
- **影响**：**仅 SQLite**。Demo 业务链在 human approval 之前（alert→event→risk→incident→AI mock→approval）全部正常；执行步 fail-closed（500，无 `dispatch_attempt` 提交、无外部调用、无伪造 outcome）。**PostgreSQL 不受影响**——这正是 §1「SQLite 与 PostgreSQL 行为差异」的实质发现，也是 **Demo Mode 数据库必须是 PostgreSQL** 的根本原因。
- **位置**：`services/executions/durable_dispatch.py:63-99`（`record()` 独立 Session/commit）· 属平台并发语义边界，非某一处可点修的 bug。
- **是否修复**：**否（不改冻结契约）**。`StaticPool`/单连接共享会让 `record()` 的 `commit()` 顺带提前提交调用方事务，**破坏 durability 契约**（M4-F 核心不变量）；`busy_timeout` / WAL 无法解决同线程自死锁。正确处置 = **Demo Mode 用 PostgreSQL(MVCC)**（`docker-compose.yml` 默认即 `postgres:16-alpine`），SQLite 仅用于「到审批为止」的零依赖核心链开发。
- **回归/证据**：native smoke（Windows，SQLite，Demo mock）实测——业务链 12 步 PASS，执行步 fail-closed；`GET /api/v1/executions/metrics` 断言 `total_chains == 0 and succeeded == 0`（无伪造链），`scripts/smoke.py` 以 driver-aware 分支将其如实报告为 `SentinelFlow core smoke test (SQLite): PASS`（**不**冒充 full-demo PASS）。全量 `pytest 2869 passed`：测试用自有 `StaticPool` 单连接 in-memory engine（`conftest.py`），从不构造「调用方开放事务 + 独立连接提交」的真实并发形态 → 测试从未捕获此边界，故本轮以 native smoke 补齐运行期证据。
- **§2 不变量**：DB 写锁失败下 fail-closed 成立——Dispatch Fact ≠ External Outcome Fact 未混淆、Outcome 未被伪造、无自动 retry/compensation。**安全不变量在该平台边界下未退化**（详见 `docs/TROUBLESHOOTING.md` 与 `docs/audit/M5-FEASIBILITY-MATRIX.md`）。

---

## 3. MEDIUM

### M-1 GET /approvals N+1 — `DEFERRED`
- **问题**：`services/ai/response_approval_service.py:44-65` `get_pending_approvals` 未 eager-load `alert_group`，而 `api/v1/response_approval.py` 的 `_to_pending` 逐行访问 `record.alert_group.title` → 1+N 次 SELECT；service docstring 却称 "without a second query per row"。
- **影响**：审批队列随待审条数线性放大查询；演示数据量小无感。
- **位置**：`services/ai/response_approval_service.py:51-64` · `api/v1/response_approval.py`（`_to_pending`）。
- **是否修复**：**否**（冻结审批路径；一行修复留待性能专项）。
- **回归/建议**：`select(AIResponseRecommendation).options(selectinload(AIResponseRecommendation.alert_group))`；修正误导注释；补查询计数测试。

### M-2 全表载入内存分页/聚合 — `DEFERRED`
- **问题**：`api/v1/response_execution.py` 的 `list_executions` 把全部 `ExecutionLog` 读进内存再 Python 分组/过滤/分页，无 DB 级 LIMIT；`services/executions/metrics.py`、`health.py` 同样全表 `list(scalars(...))`。
- **影响**：审计日志增长后 O(N) 内存+CPU 退化。
- **位置**：`api/v1/response_execution.py`（`list_executions`）· `services/executions/metrics.py` · `services/executions/health.py`。
- **是否修复**：**否**（改写聚合/分页风险高于收益，演示规模无感）。
- **回归/建议**：DB 级 `GROUP BY` + `LIMIT/OFFSET`；补大数据量分页测试。

### M-3 两个同名异义 `OUTCOME_STATUSES` — `DEFERRED`（触碰冻结词表）
- **问题**：`services/executions/models.py` 的 `OUTCOME_STATUSES={succeeded,failed}`（2 态 DTO）与 `models/execution_outcome.py` 的 `OUTCOME_STATUSES={unknown,pending,confirmed_success,confirmed_failure,reconciliation_failed}`（5 态 ORM）同名异义；`COMPENSATABLE_STATES` 又={succeeded,failed}。
- **影响**：import 错模块即静默用错 5 态 Outcome 词表（fail-closed 核心）。
- **位置**：`services/executions/models.py` · `models/execution_outcome.py`。
- **是否修复**：**否**。5 态 Outcome 词表是 §2 冻结不变量，重命名有引入静默语义错误的风险，release 前不动。
- **回归/建议**：把 DTO 侧重命名为 `DISPATCH_OUTCOME_STATUSES`（不改 5 态 ORM 词表），补 import 守卫测试。

### M-4 Incident 自动建案 TOCTOU 未兜底 — `DEFERRED`
- **问题**：`dedup/engine.py:82` → `incidents/service.py` 读 `group.incident is None` 后 create，无锁；并发同组双请求可都过应用层幂等，靠 DB 唯一约束 `uq_incidents_alert_group_id` 在 flush 兜底，但 `engine.process` **未捕获 IntegrityError** → 竞态下裸 500。
- **影响**：并发下非优雅 500（**唯一约束保证不产生重复案，不变量守住**）。
- **位置**：`services/deduplication/engine.py`（`auto_create_from_risk` 调用）· `services/incidents/service.py`。
- **是否修复**：**否**（摄取热路径；对照 `response_approval_service.py:125-132` 已有正确 IntegrityError 兜底，留待一致性专项）。
- **回归/建议**：仿审批服务捕获 `IntegrityError`→优雅跳过/typed error；补并发建案测试。

### M-5 三条 AI 服务 + 三条 AI 路由结构性重复 — `DEFERRED`
- **问题**：`ai/service.py`、`ai/risk_summary_service.py`、`ai/response_recommendation_service.py` 的 `__init__`/provider/group 加载/`AIEventNotFound`/`sorted(alerts)` 重复；`ai_analysis.py`、`ai_risk_summary.py`、`response_recommendation.py` 的 `_validate_event`/`_to_uuid`/错误映射（404/503/503/502）重复。**错误语义已统一（正面）**，但代码三重复制。
- **影响**：维护成本高；`latest_*` 取法不一致（模块级 vs 内联）。
- **位置**：`services/ai/*service.py` · `api/v1/ai_*.py` · `response_recommendation.py`。
- **是否修复**：**否**（抽公共基类=较大重构，违反"不大规模重写稳定模块"）。
- **回归/建议**：抽 AI service base + 共享错误映射依赖；保持三态输出契约不变。

### M-6 分页契约不一致 — `DEFERRED`（前端契约）
- **问题**：`alerts.py` 用 `skip/limit`，`events.py`/`incidents.py`/`response_execution.py` 用 `page/size`（均默认 20、max 100）。
- **影响**：前端需分别适配两种风格。
- **位置**：`api/v1/alerts.py:22-24` vs `events.py:25-26` 等。
- **是否修复**：**否**（统一=破坏性 API 变更，影响前端契约）。
- **回归/建议**：统一到 `page/size`，前端 client 同步；作为一次带契约测试的专项。

### M-7 异常吞掉不记日志 / 全仓 logging 近乎缺失 — `PARTIAL FIXED(M5 §14)`
- **问题**：`main.py` health `except Exception→unavailable`（静默）、`wazuh.py`/`shuffle.py` 错误体读取 `except→""`（静默）；全仓仅 `secrets.py` 有 `SecretRedactionFilter`，几乎无结构化 logging。
- **影响**：故障不可观察（§14 首屏排障困难）。
- **位置**：`main.py`（health）· `services/executions/*`（adapter 错误体）· 全仓。
- **是否修复**：**部分**。M5 已加：启动脱敏配置摘要 + `DEBUG`→日志级别接线（见 §11/L-3）。adapter best-effort 错误体读取的静默 except 属可接受（非关键路径，且 `ExecutorOutcomeViolation` 会正确 re-raise）。
- **回归/建议**：为关键失败路径（Guard 拒绝、Durable 门 503、webhook 认证失败）补 `logger.warning/error` 且带 execution/request correlation；ERROR 不打印 token（已有 redaction filter 兜底）。

---

## 4. LOW

### L-1 `require_execution_token` 死代码 — `FIXED(M5)`
- **问题**：`api/v1/response_execution.py` 的 `require_execution_token`（void-form 认证依赖）**无任何 endpoint 使用**（写路径统一用 `authenticate_operator`），全仓仅 1 处引用=其自身定义。
- **影响**：死代码 + 误用面（看似可用的旧认证入口）。
- **位置**：`api/v1/response_execution.py`（原 `require_execution_token`）。
- **是否修复**：**是**，已删除。
- **为何**：`Grep require_execution_token` 全仓仅命中定义本身，无 import/依赖；`authenticate_operator` 保留完整认证+角色门。删重复/死代码，零行为变更。
- **回归**：全量 `2869 passed`。

### L-2 `events/service.py` `MAX_PAGE_SIZE` 死常量 — `FIXED(M5)`
- **问题**：`services/events/service.py:17` 定义 `MAX_PAGE_SIZE=100` 但 `list_events` 从不使用（`incidents/service.py:160` 同名常量则被使用）。
- **影响**：死常量 + events 服务层缺分页封顶（仅 API 层 `Query(le=100)` 兜底）。
- **位置**：`services/events/service.py`（`list_events`）。
- **是否修复**：**是**，在 `list_events` 加 `size = min(size, MAX_PAGE_SIZE)`。
- **为何**：与 incidents 服务层一致的 defense-in-depth；API 层已 `le=100`，故行为等价、零破坏，同时消除死常量。
- **回归**：全量 `2869 passed`。

### L-3 `DEBUG` 默认 True 且从未被消费 — `FIXED(M5)`
- **问题**：`core/config.py:26` `DEBUG: bool = True`，但 `settings.DEBUG` 在 `app/` 全仓**无任何消费者**（死配置），且生产默认开调试=不安全/含糊默认。
- **影响**：不安全默认 + 死配置。
- **位置**：`core/config.py`（`DEBUG`）· `main.py`（新增消费）。
- **是否修复**：**是**：默认改 `False`，并在 `main.py` 接线到日志级别（DEBUG→`logging.DEBUG`，否则 `INFO`）。
- **为何**：安全默认（§11「Boolean 必须明确」）；接线后 `DEBUG` 有意义（支撑 §14「异常 stack 仅在 debug」）。测试仅用 `logging.DEBUG` 常量、不依赖 `settings.DEBUG` 默认，故零破坏。
- **回归**：全量 `2869 passed`。

### L-4 `operator` 字段：后端接受但忽略 / 前端强制收集 — `FIX(M5 §13)`
- **问题**：`schemas/response_execution.py` 的 `ExecuteRequest.operator`/`CompensateRequest.operator` 自 RBAC 起**接受但服务端忽略**（身份只取自 Bearer token）；前端 `ResponseExecutionPanel` 却把 Operator 设为**必填**并纳入 `ready` 门禁 → 误导性 UI。
- **影响**：用户被迫填一个被丢弃的字段；易误以为可指定执行者身份。
- **位置**：`schemas/response_execution.py` · `frontend/src/components/ResponseExecutionPanel.tsx` · `frontend/src/types/responseExecution.ts`。
- **是否修复**：**前端侧修（§13）**——移除误导性必填 Operator 输入（或改为只读提示"身份由令牌决定"）。**后端保持忽略**（正确的安全行为：身份绝不来自客户端字段，§2 不变量）。
- **回归**：前端 `build`（tsc 类型检查）+ 演示 smoke。

### L-5 `VITE_API_BASE_URL` 孤儿配置 — `FIX(M5 §13)`
- **问题**：`.env`/`.env.example` 声明 `VITE_API_BASE_URL`，但**全前端代码无任何引用**；真实 base 是 `api/client.ts` 硬编码相对 `/api/v1${path}`（dev 靠 vite proxy、生产靠同源反代）。
- **影响**：误导性死配置（改了不生效）。
- **位置**：`frontend/src/api/client.ts:21` · `frontend/vite.config.ts` · `.env.example:15`。
- **是否修复**：**是（§13）**——让 `client.ts` 以 `import.meta.env.VITE_API_BASE_URL ?? ""`（空→相对）为**单一权威来源**，变量获得真实消费者（支持前后端异源部署），并在 `.env.example` 说明。
- **回归**：前端 `build` + dev proxy 演示 smoke。

### L-6 Dashboard 严重度计数可合并 — `DEFERRED`
- **问题**：`services/dashboard/service.py` `_active_by_severity` 调 3 次=3 条 COUNT，可 1 条 `GROUP BY` 完成（**常数因子，非 N+1**）。
- **是否修复**：**否**（微优化）。**建议**：合并为单 `GROUP BY`。

### L-7 仓库残留构建日志 — `FIX(M5 §1)`（本地清理，gitignored 不入库）
- **问题**：`backend/*.log`（`final_backend_335.log` 等 10+）、`frontend/*.log`（`final_build_337.log` 等 4）散落工作树。
- **影响**：污染（`.gitignore` 已含 `*.log`，**不入版本库、不随 clone 分发**）。
- **是否修复**：这些是历史本地运行产物、已被 gitignore；本轮不纳入交付树（fresh clone 不含）。记录为本地卫生项。

---

## 5. TECH-DEBT

### T-1 生产不可达的 fail-closed 代码（**勿删**） — `DOCUMENTED`
- `read_adapters/registry.py` 的 `create_read_adapter_registry`（生产未接线，路由用 sealed 空 registry）、`durable_dispatch.py` 的 `find_unreconciled_attempts`/`classify_attempt_recovery`（仅测试可达）、`outcomes/verified_proof`（仅 docstring）。这是 Reader registry 空、TheHive 门⑤ UNKNOWN 的**故意 fail-closed 结果**，不应作为死代码删除；需 LAB 标记与文档说明。

### T-2 DTO/Schema/Model 多层镜像 — `DOCUMENTED`（刻意隔离）
- `schemas/response_execution.py` 的 `ExecutionMetricsRead`/`ObservedHealthRead` 是 `metrics.py`/`health.py` dataclass 的逐字段镜像；`events.py` 用 `model_validate().model_copy(update=...)` 二次拼装。属**刻意的读模型隔离（正面）**，字段重复维护成本记为债。

### T-3 后端依赖未 pin、无 lockfile — `DEFERRED`（记录）
- `requirements/base.txt`+`dev.txt` 全为 `>=` 下限、无 `==`、无锁文件 → 可复现性弱。前端 `package.json` 为 caret/tilde 范围**但有 `package-lock.json`（已入库）**，可复现性由 lockfile 保障。运行时 HTTP 全走 stdlib `urllib`（`httpx` 仅 dev），无未用运行时依赖、无版本冲突。
- **是否修复**：**否**（改 pin 有破坏现有可用 `.venv` 的风险；§12 只升级有明确理由者）。**建议**：后续引入 `pip-tools`/`uv` 生成 `requirements.lock`。

### T-4 配置集中（**健康基线，防回退**） — `DOCUMENTED`
- 单一 `Settings`（`core/config.py`），`app/` 生产代码 **0 处** 直读 `os.environ`（仅 `tests/**` 为设 lab ENV）；`__repr__/__str__` 对 `*_API_KEY/*_TOKEN/*_PASSWORD/DATABASE_URL/OPERATORS_JSON` 掩码 `***`。记录为健康基线。

### T-5 URL 字段缺格式校验 — `DEFERRED`
- `AI_BASE_URL`/`*_BASE_URL` 为裸 `str`，未用 `AnyUrl`/`field_validator`。**是否修复**：**否**——空串默认是**故意的 fail-closed**（未配置=拒绝），`AnyUrl` 会拒绝空串，反而破坏语义。**建议**：仅在值非空时校验 scheme（`field_validator` 条件校验）。

---

## 6. 配置 / .env.example 治理（§11） — `FIX(M5 §11)`

| 项 | 现状 | 处置 |
| --- | --- | --- |
| `DATABASE_URL` 默认内嵌 `change_me` 弱口令 | 唯一带非空 secret 的默认 | quickstart **自动生成随机本地 secret** 写 `.env`；默认值保留为**本地开发占位**并文档化（不入 Git 真实密钥） |
| `.env.example` 缺 `SHUFFLE/WAZUH/THEHIVE_CALLBACK_TOKEN`、`DEDUP_WINDOW_SECONDS` | Settings 有、示例缺 | **补齐**（入站 webhook 第三信任域凭据必须可见） |
| `.env.example` 注释充斥 `Phase 3.x / §4 / v1.3.0` 研发编号 | 面向用户无意义 | **重写**为功能性说明（研发编号留在 `docs/design/` 与代码注释） |
| 配置分类 | 松散 | 重组为 **CORE / DATABASE / AI / EXECUTION / THEHIVE / WAZUH / SHUFFLE / OBSERVABILITY** 八段 |
| 启动配置摘要 | 无（当前不打印→无泄露） | **已加**（`main.py` `_safe_config_summary`，仅 driver scheme+enum+configured 布尔，**绝不打印 secret**；`test_health.py` 加 no-leak 断言） |
| `POSTGRES_*`（compose 消费）与 `VITE_API_BASE_URL`（前端）混在后端 .env.example | 归属易误解 | 分段并注明归属 |

---

## 7. 容器化 / 健康检查（§6） — `FIX(M5 §6)`

| 项 | 现状 | 处置 |
| --- | --- | --- |
| `backend/Dockerfile`、`frontend/Dockerfile` | **均不存在** | **新建**（backend: python slim + uvicorn `app.main:app`；frontend: node build → nginx 静态 + `/api` 反代） |
| `docker-compose.yml` | **仅 postgres 一个服务** | **重写**：`postgres`+`migrate`(one-shot)+`backend`+`frontend`，可选 profile `ollama`/`integration`；healthcheck + `depends_on: condition: service_healthy` |
| Alembic 迁移竞争 | 无独立迁移服务 | **独立 `migrate` one-shot**（postgres healthy → migrate → backend → frontend），不用 `create_all`（生产路径已 0 处 `create_all`，仅测试用） |
| readiness 端点 | **不存在**；`/health` DB 故障仍 200 | **已加 `/ready`**（DB `SELECT 1` 成功才 200，否则 503）；`/health` 保留为 liveness（compose backend healthcheck 用 `/ready`） |
| 前端反代配置 | 无 nginx/caddy | **新建** frontend nginx conf（同源 `/api`→backend，规避 CORS） |

---

## 8. 前端 / API 一致性（§13）与依赖构建（§12）

- **前端 API 层健康**：统一 `api/client.ts`（无散落 fetch/axios、无悬空 endpoint、types 集中、nullable/status 基本对齐）。
- `FIX(M5 §13)`：L-4 operator UI 漂移、L-5 VITE_API_BASE_URL 单一权威、approve/reject 返回类型建模（`Promise<unknown>`→`AIResponseApproval`）。
- `DEFERRED`：缺集中式 HTTP 状态码处理层（多数页面不区分 401/403/404/409/422/5xx，仅 3 个组件特化）——建议后续加统一响应拦截层。
- `FIX(M5 §12)`：`package.json` **无 `lint`/独立 `typecheck` script、无 eslint 配置**（typecheck 隐含在 `build` 的 `tsc`）。本轮补 `typecheck`(`tsc --noEmit`) 脚本；eslint 引入较大（可能大量告警），**记录为 TECH-DEBT**，本轮不强行引入以免噪声。

---

## 9. 安全不变量核验（§2）— 全部 **保持/未退化**

Dispatch Fact ≠ External Outcome Fact · Outcome append-only · Outcome 五态 · Webhook/Manual Reconcile 信任域隔离 · 共享外部状态词表 fail-closed（空）· Wazuh G1-C · 不可经 verified/source/类型/客户端字段/config 绕过证明 · 真实 Adapter 经 Durable Dispatch（**前向**门在位；补偿见 C-1）· 无自动 retry/polling/compensation · 不绕过人工审批 · 生产 Reader registry 空 · TheHive 门⑤ UNKNOWN/fail-closed。**M5 未削弱任一项**；L-1/L-2/L-3 与 §6/§7 变更均为纯读/死代码/配置/编排层，不触碰上述生产安全路径。

---

## 10. 处置汇总

| 严重度 | 计数 | FIXED(M5) | FIX(M5 后续阶段) | DEFERRED |
| --- | --- | --- | --- | --- |
| CRITICAL | 1 | 0 | 0 | 1（C-1，post-M5 安全 #1） |
| HIGH | 3 | 0 | 0 | 2 + 1（H-3 = SQLite 平台边界，`DOCUMENTED`，Demo 须 PostgreSQL） |
| MEDIUM | 7 | 0（M-7 部分） | 1（M-7 §14） | 6 |
| LOW | 7 | 3（L-1/L-2/L-3） | 2（L-4/L-5 §13） | 2（L-6；L-7 本地卫生） |
| TECH-DEBT | 5 | 0 | 0 | 5（记录/防回退） |
| 配置/容器/前端专项 | — | 启动摘要+`/ready` | §11/§6/§12/§13 | URL 校验/eslint |

**结论**：架构 fail-closed 骨架健全（配置集中、Outcome append-only+derive-on-read、信任域隔离、前向 Durable 门、无 bare-except 关键路径）。**最高风险 C-1（补偿耐久缺口）** 属预存、非演示阻塞、修复=新安全架构，明确推迟至 M5 之后的安全里程碑并给出对称修复方案。本轮 release-readiness 只做**零风险死代码清理 + 配置/可观察性/健康检查加固**，其余以证据+修复方向归档，不重写稳定模块。
