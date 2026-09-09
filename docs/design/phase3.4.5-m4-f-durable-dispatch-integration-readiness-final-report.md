# Phase 3.4.5-M4-F — Durable Dispatch & Integration Readiness 最终报告

> **状态：派发前 durable PASS（隔离）· 异常恢复 PASS（隔离）· 目标绑定安全 PASS（隔离）· 证明入口 PASS（内部隔离）· 门⑤ UNKNOWN（fail-closed，保持）· 真实 Lab LAB BLOCKED · PostgreSQL 生产语义 UNVERIFIED · 生产认证 UNKNOWN / 未授权**
> 本文件是 **M4-F 一次性收口任务**的最终交付报告：修复 M4 Final Review 的关键发现①（**flush ≠ 持久提交**）、
> 收紧发现②（写适配器目标绑定/重定向）与发现③（封印非授权机制），并完成隔离回归。
> **缺证据的能力保持其真实状态，绝不合并为「全部通过」。** 本轮**不接生产 router、不进 Shuffle/Wazuh Reader、不发布版本**。

## 0. 文档控制区（Document Control）

| 字段 | 值 |
| --- | --- |
| 文档状态 | **隔离范围 PASS · 门⑤ UNKNOWN fail-closed · 真实 Lab LAB BLOCKED · PG 生产语义 UNVERIFIED · 生产认证 UNKNOWN** |
| 授权 | M4-F（ONE AGENT · TRANSACTION HARDENING + TARGET BINDING + PROOF INTEGRATION TESTS · LOCAL COMMITS · NO PUSH） |
| 审查基线 | M4 Final Review（部分通过，需一项关键整改）；复核基线提交 `33e5d34` |
| M4-F HEAD | `5f88925`（ahead **55**，工作树干净） |
| 采集日期 | 2026-09-09 |
| 执行纪律 | TDD（RED→GREEN，Iron Law）；文档与代码分离提交；本地前向提交，**不 amend/rebase/reset/force-push/移动 tag/push** |
| 关联交付物 | 本文档 + `phase3.4.5-m4-f-durable-dispatch-lab-execution-plan.md`（§5 Lab 方案）+ 脱敏审查 ZIP |
| 保护约束 | 不改冻结通用契约/DB 模型/历史 Outcome；不改 Wazuh G1-C 空词表；不恢复共享 `case_created` 词表；不接生产 router；不进 Shuffle/Wazuh Reader；无授权主机则不安装/不启动/不连接真实外部系统 |

---

## 1. M4-F 里程碑摘要（审查反馈 → 修复 → 验收）

| 审查者发现 | 严重度 | M4-F 处置 | 提交 | 隔离验收 |
| --- | --- | --- | --- | --- |
| **① flush ≠ 持久提交**：派发前绑定仅 `flush`，caller 回滚/崩溃/终态写入失败时随事务消失 | **阻断** | 新增 **独立事务** durable 提交（`DurableDispatchAttemptStore` 用独立 Session commit）+ `dispatch_attempt` 表 + 迁移 `0011`；外部请求发出**前**已提交不可变派发意图+目标绑定 | `03e8e6e`/`32e5df0`/`d15b7fd` | **PASS** |
| **② 写适配器目标绑定需加强**：默认 `urlopen` 跟随重定向，Authorization 可能跨主机转发，实际目标可能偏离绑定 endpoint | **安全** | 写适配器采用 `_NoRedirectHandler` + `_build_opener()`（3xx → HTTPError → fail-closed）；绑定 endpoint == 请求 target origin；响应读取中断 fail-closed | `1abe5e6` | **PASS** |
| **③ 封印是内部防误用，非独立授权机制** | 说明 | `_VERIFIER_SEAL` 注释明确「ANTI-MISUSE, NOT AUTHORIZATION」；未来可信入口须复用 operator/RBAC/Manual Reconcile + 可信注册工厂；门⑥缺证据 fail-closed 锁 | `c1c74c3` | **PASS** |
| **门⑤处理正确**（真实绑定保持 UNKNOWN） | — | **不改写**门⑤；整理真实 Lab 最小可执行方案 | `5f88925` | **UNKNOWN 保持** |

---

## 2. Git 提交链（Commit Chain — 全部本地前向，NO PUSH）

```
33e5d34  (M4 复核基线) docs(3.4.5-M4): forward dispatch binding & proof channel closure final report
   └─ 03e8e6e  M4-F 1: durable pre-dispatch attempt store (TDD Cycle 1)
   └─ 32e5df0  M4-F 2: durable dispatch wiring + recovery (TDD Cycle 2)
   └─ d15b7fd  M4-F 2.5: §2 emitted-then-abandoned acceptance + PostgreSQL interleaving
   └─ 1abe5e6  M4-F 3: TheHive write adapter no-redirect + target binding + response hardening
   └─ c1c74c3  M4-F 4: proof-entry seal documented as anti-misuse + gate 6 absent-evidence locks
   └─ 5f88925  M4-F 5: gate 5 UNKNOWN fail-closed kept + minimal real-Lab execution plan (docs only)  ← HEAD
```

`git status`：`On branch main · ahead of 'origin/main' by 55 commits · nothing to commit, working tree clean`。
**未** amend / rebase / reset / force-push；**未**移动任何 tag；**未** push。

### 2.1 关键 diff（`git diff --stat 33e5d34..HEAD`，17 文件，+1899 / -7）

| 文件 | 变更 | 角色 |
| --- | --- | --- |
| `app/models/dispatch_attempt.py` | **+99 NEW** | 追加式 `DispatchAttempt` 模型（`attempt_id`/`execution_id` 唯一索引/`recorded_at`） |
| `migrations/versions/0011_add_dispatch_attempt.py` | **+112 NEW** | 限定范围 Alembic 迁移（head `0011`） |
| `app/services/executions/durable_dispatch.py` | **+139 NEW** | `DurableDispatchAttemptStore`（独立 Session commit）+ `find_unreconciled_attempts`（恢复读） |
| `app/services/executions/service.py` | +32 | `execute_response` 在外部请求**前** durable 提交；终态引用同一 `attempt_id` |
| `app/api/v1/response_execution.py` | +30 | DI seam `get_dispatch_attempt_store`（生产 = `db.get_bind()`；测试可 override） |
| `app/services/executions/thehive.py` | +84 | `_NoRedirectHandler` + `_build_opener` + 响应读取中断 fail-closed |
| `app/services/read_adapters/verified.py` | +12 | `_VERIFIER_SEAL` = ANTI-MISUSE, NOT AUTHORIZATION 文档 |
| `app/models/__init__.py` | +2 | 导出 `DispatchAttempt` |
| `tests/conftest.py` | +7 | `client` fixture override store=None（内存 StaticPool 保持既有旅程逐字节不变） |
| `tests/test_dispatch_attempt_durability.py` | **+343 NEW** | Cycle 1：store 独立提交/回滚存活/重复 execution_id |
| `tests/test_dispatch_durable_integration.py` | **+198 NEW** | Cycle 2：服务接线 + 恢复 |
| `tests/test_dispatch_endpoint_durability.py` | **+151 NEW** | 端点 seam（file-backed 真实 store） |
| `tests/test_dispatch_durable_postgres.py` | **+178 NEW** | **PG 专项（`@pytest.mark.external`，默认 deselect）** |
| `tests/test_execution_thehive_adapter.py` | +252 | §3：无重定向/目标绑定/响应中断/durable 存活 6 分类 |
| `tests/test_verified_creation_proof.py` | +38 | §4：门⑥缺证据 fail-closed 锁 |
| `tests/test_execution_service.py` | +9 | store=None 路径逐字节不变 |
| `docs/design/phase3.4.5-m4-f-durable-dispatch-lab-execution-plan.md` | **+220 NEW** | §5 Lab 方案 |

---

## 3. 事务时序图（Transaction Sequence — §6 核心交付）

### 3.1 派发前 durable 提交时序（`execute_response`，service.py L532-611）

```
API 层 (create_execution)          Execution Service               DurableDispatchAttemptStore        外部 TheHive
  |  Depends(get_dispatch_attempt_store)  |                          (独立 Session/连接)                 (真实 HTTP)
  |-------------------------------------->|                                    |                              |
  |  execute_response(db, ..., store)     |                                    |                              |
  |                                       | 1. dispatch_started_at = now()     |                              |
  |                                       | 2. contributor_facts =             |                              |
  |                                       |    executor.dispatch_binding_facts |  (endpoint=config-declaration,|
  |                                       |                                    |   version_assertion_kind=CONFIG,|
  |                                       |                                    |   target_instance/tenant=None) |
  |                                       | 3. binding = build_dispatch_binding(...)  ← 不可变 DispatchBinding |
  |                                       |                                    |                              |
  |                                       | 4. store.record(binding) --------->| ★ DURABLE PRE-DISPATCH COMMIT|
  |                                       |                                    |  Session(bind) [独立]        |
  |                                       |                                    |  add(DispatchAttempt)        |
  |                                       |                                    |  flush()                     |
  |                                       |                                    |  COMMIT  ← 已提交，跨连接可见 |
  |                                       |                                    |  close()                     |
  |                                       |    (IntegrityError→typed 409;      |                              |
  |                                       |     任何其他失败→传播，绝不调用适配器) |                              |
  |                                       |                                    |                              |
  |                                       | 5. _append(dispatched) + session.flush()  ← caller 事务，仅 flush  |
  |                                       |                                    |                              |
  |                                       | 6. outcome = executor.execute(dispatch) ----------------------->| ★ 外部请求发出
  |                                       |                                    |                              |  POST /api/case
  |                                       |<---------------------------------------------------------------|  (无重定向)
  |                                       | 7. detail[TERMINAL_REFERENCE]=binding.attempt_id  ← 引用同一 attempt，不覆盖绑定
  |                                       | 8. _append(terminal: succeeded/failed) + session.flush()          |
  |<--------------------------------------|  return result                       |                              |
  |  COMMIT caller 事务 (execution_log)   |                                    |                              |
  |  ← 步骤 5/8 的 flush 此时才提交        |                                    |                              |
```

**关键不变量**：步骤 **4（durable COMMIT，独立 Session）发生在步骤 6（外部请求）之前**。因此即使步骤 5–8 所在的 caller 事务回滚、终态写入失败、或进程在步骤 6 之后崩溃，**步骤 4 已提交的 `DispatchAttempt` 仍存活**（独立事务，不随 caller 事务回滚）。

### 3.2 崩溃 / 回滚后的恢复语义（`find_unreconciled_attempts`）

```
已提交 DispatchAttempt (execution_id=X)  ──┐
                                          ├─ 关联 NOT EXISTS：execution_id=X 是否有 terminal(succeeded/failed) execution_log 行？
caller 事务的 terminal 行 (可能从未提交) ──┘
   ├─ 有 terminal  → 已和解（正常）
   └─ 无 terminal  → 「已发出但无可靠终态」→ 人工核查候选（MANUAL reconciliation）
                     ★ 绝不自动重试/补偿/重新派发（constraint 5）
                     ★ 缺失终态 ≠ 外部调用确定失败（外部效果 UNKNOWN）
```

---

## 4. 持久化边界（Persistence Boundary — §6 核心交付）

| 边界 | 归属 | 提交时机 | 崩溃/回滚后 |
| --- | --- | --- | --- |
| **`DispatchAttempt`（派发意图+目标绑定）** | `DurableDispatchAttemptStore` 的**独立 Session** | **外部请求前 COMMIT** | **存活**（独立事务） |
| `execution_log`（requested/dispatched/terminal） | caller（API 层）业务事务 | 外部请求**返回后** API 层 COMMIT | caller 回滚则消失（**但 attempt 已存活**） |

**冻结契约安全性**：`service.py` 的「Service 绝不 commit()」条款保护的是 **caller 的业务事务**；durable store 拥有**独立 Session**，只提交它自己那一个——这正是 outcomes 服务（webhook/manual_reconcile/manual_persist/verified_proof）已确立的先例。caller 的 execution_log 事务边界**仍留在 API 层**，未被触碰。

**DI seam（response_execution.py L188-202）**：生产 `get_dispatch_attempt_store(db)` 返回 `DurableDispatchAttemptStore(db.get_bind())`（绑定 caller 引擎，但 store 开自己的独立 Session）。测试 override 此 seam：内存 `StaticPool` harness 共享单一连接，真实独立提交无法在其上交错，故 conftest `client` fixture override 为 `None`（既有端点旅程逐字节不变），专门的 **file-backed** 测试驱动真实 store。

---

## 5. 独立连接 / 故障注入测试（§2 验收 — 不以同一 Session flush 冒充 durable）

| 测试 | 文件 | 证明 |
| --- | --- | --- |
| 派发前提交失败 → **零外部调用** | `test_dispatch_attempt_durability.py` | store.record 失败传播，适配器从未调用 |
| 提交后**独立连接**读回可见 | `test_dispatch_attempt_durability.py` | 新 Session/连接 SELECT 到已提交行（非同一 Session flush） |
| 外部发出后 **caller rollback** → attempt 存活 | `test_dispatch_durable_integration.py` | 回滚 caller 事务后独立连接仍读到 attempt |
| 外部副作用后**终态写入异常** | `test_dispatch_durable_integration.py` | 终态失败，attempt 存活 |
| **进程中断等效**故障注入 | `test_dispatch_durable_integration.py` | 模拟崩溃后恢复读 |
| 重复 `execution_id`/`approval_id` | `test_dispatch_attempt_durability.py` | 唯一索引 → IntegrityError → typed 409 |
| 恢复未决尝试**无自动第二次外部调用** | `test_dispatch_durable_integration.py` | `find_unreconciled_attempts` 纯读，零重试 |
| **6 分类失败**每种保留已提交尝试 | `test_execution_thehive_adapter.py::TestDurableAttemptSurvivesFailures` | 409/5xx/timeout/read-interrupted/non-json/missing-resource-id，各恰好一次外部调用 + 独立连接读回 1 行 |
| **PostgreSQL 真实交错**（生产锁/崩溃语义） | `test_dispatch_durable_postgres.py` | **`@pytest.mark.external`，默认 DESELECT**（见 §8） |

> **审查者 §2 纪律遵守**：「如使用 SQLite 无法可靠模拟生产锁或崩溃语义，必须补充 PostgreSQL 专项集成测试或明确保持对应能力未验证。不能以 SQLite 全绿宣称 PostgreSQL 事务与并发已认证。」→ PG 专项测试**已编写但默认 deselect**，**明确保持 PG 生产锁/崩溃语义 UNVERIFIED**，直到在获授权主机以真实 PostgreSQL 运行。

---

## 6. 目标绑定与 HTTP 安全（§3 验收）

| 项 | 实现 | 测试 |
| --- | --- | --- |
| **无重定向** | `_NoRedirectHandler.redirect_request → None`（3xx 抛 HTTPError，不跟随）；`_build_opener()` 保留默认验证 TLS 的 handler，仅替换重定向 handler | `TestWriteNoRedirectCredentialLeak`（默认 transport 非裸 urlopen / 装了 no-redirect handler / redirect_request 返回 None） |
| **Authorization 不跨主机转发**（CWE-522） | 3xx → fail-closed `adapter_error`，恰好一次调用 | `test_a_3xx_fails_closed_and_is_never_followed_to_another_host` |
| **目标绑定一致** | 绑定 `endpoint` == 请求 target origin（`{endpoint}/api/case`） | `TestWriteTargetBindingConsistency` |
| **版本仅 config-declaration** | `version_assertion_kind=VERSION_ASSERTION_CONFIG`；`target_instance`/`target_tenant`=None（**绝不**把 base URL 当实例身份） | `test_binding_is_config_declaration_never_an_instance_identity` |
| **响应读取中断 fail-closed** | `response.read()` try/except：`TimeoutError`→timeout；`(OSError, http.client.HTTPException)`→adapter_unavailable；**绝不推断成功**，零重试，错误文本脱敏 | `TestResponseReadInterruption`（IncompleteRead/ConnectionReset/读超时/密钥脱敏） |
| **TLS/URL 校验不变** | `validate_base_url` + 默认 HTTPSHandler（验证 TLS）**未改**；**未**通过关闭安全检查解决问题 | 既有 `TestSecurity` |

---

## 7. 证明入口与审批一致性（§4 验收）

- **封印 = 防误用，非授权**：`_VERIFIER_SEAL` 注释新增「ANTI-MISUSE, NOT AUTHORIZATION」段——封印 + 私有 persist 仅阻止**意外**的普通对象持久化，**不是**认证/授权机制，**绝不**替代之。当前**无生产 router** 在此通道（sealed registry 保持空，隔离套件已证明）。未来可信证明入口**必须**复用既有 operator 身份 + RBAC + Manual Reconcile 权限，Reader **必须**来自可信注册工厂，**绝不**由请求体或任意调用者注入；Python 类型/布尔标志/seal **绝非**外部身份凭据，授权始终是**服务层**职责（在 `is_sealed()` 上游）。
- **门⑥审批一致性**（`verified.py` L553-572，本轮核验完整）：6a `approved_action==escalate_to_incident`；6b `bound_action`/`bound_target`/`bound_approval_id` 与链的 `approved_action`/`chain_target`/`chain_approval_id` 交叉核对；6c `approval_status_at_dispatch==approved`（**派发时快照**，绝不用 reconcile 时重读的 live status）；6d `reference_from_terminal_success is True`。
- **门⑥缺证据 fail-closed 锁**（`TestVerifierGate6AbsentEvidenceFailsClosed`，4 测试）：`approval_status_at_dispatch=None`→`approval_not_approved`（**绝不**当作 approved）；`bound_approval_id`/`bound_action`/`bound_target`=None→`approval_snapshot_inconsistent`；**绝不**从 live status/config 倒填（派生 `verified_proof.py` L281-286 仅从 binding 取快照）。
- **本轮不接生产 router、不恢复共享 `case_created` 词表、不修改 Wazuh G1-C 空词表。**

---

## 8. 门⑤与真实 Lab（§5 验收）

- **门⑤ UNKNOWN fail-closed（保持，未改写）**：`GATE_INSTANCE_TENANT`（verified.py L109/L554-558）；TheHive 4.1.24-1 `OutputCase` 无实例/租户 → 所有真实历史 fail-closed（Amendment §12）；**读取者 organisation ≠ 案件所属 organisation**。证据：`test_verified_creation_proof.py -k "Gate5 or instance or tenant or binding"` → **11 passed**。
- **真实 Lab 方案文档化**：`phase3.4.5-m4-f-durable-dispatch-lab-execution-plan.md`（镜像 digest `thehiveproject/thehive4:4.1.24-1` + `sha256:c8b6…6811`、资源 ≥8 GB + PostgreSQL ≥12、loopback 网络隔离、临时凭据、身份认证边界、创建+读取测试矩阵 T1-T7、PG 专项锁/崩溃语义、精确匹配清理范围）。
- **本机 LAB BLOCKED（本 session 只读再探测）**：docker/podman/nerdctl 均 ABSENT；WSL 零分发版；空闲内存仅 **2.0 GB**（低于 M2 的 3.35 GB）。
- **无用户明确授权的实验主机 → 不安装、不启动、不连接真实外部系统**（仅文档化方案）。

---

## 9. 完整回归与测试日志（§6 验收 — external 默认 deselect）

| 回归面 | 命令 | 结果 |
| --- | --- | --- |
| **完整后端** | `pytest tests -q` | **2849 passed, 7 deselected, 1 warning in 74.32s** |
| **M4-F 定向**（绑定事务/执行并发/TheHive 写入/可信证明/Webhook/Manual Reconcile/审批/Outcome/跨层） | `pytest <27 定向文件> -q` | **1127 passed, 4 deselected, 1 warning in 30.20s** |

- **deselected** = `@pytest.mark.external` 真实外部测试（conftest L51-67：默认 **DESELECT**，非 skip，保持 0 skipped；须 `-m external` + 真实环境 env 才解锁）。完整后端 7 deselected 含 PG 专项 + 真实 TheHive 读写；定向 4 deselected 为 PG 专项。
- 唯一 warning = 预先存在的 `StarletteDeprecationWarning`（httpx/testclient），与本轮无关。
- **跨层回归**：`test_execution_cross_layer_regression` / `test_execution_policy_cross_layer` / `test_incident_ai_cross_layer_regression` / `test_manual_reconcile_crosslayer` / `test_observability_cross_layer` / `test_thehive_write_read_closure` 均在 `backend/tests` 内，已含于完整后端 2849。

---

## 10. 分能力验收（Evidence Matrix — 缺证据保持未完成，绝不合并「全部通过」）

| 能力项 | 状态 | 证据 |
| --- | --- | --- |
| **派发前 durable**（外部请求前已提交不可变意图+绑定） | **PASS（隔离）** | §3 时序图 + §4 边界 + §5 独立连接测试（`03e8e6e`/`32e5df0`） |
| **异常恢复**（崩溃/回滚/终态失败后 attempt 存活，零自动重试） | **PASS（隔离）** | §3.2 恢复语义 + §5（`d15b7fd`） |
| **目标绑定安全**（无重定向/Authorization 不跨主机/endpoint 一致） | **PASS（隔离）** | §6（`1abe5e6`） |
| **证明入口**（封印=防误用非授权；门⑥缺证据 fail-closed） | **PASS（内部隔离）** | §7（`c1c74c3`） |
| **门⑤**（实例/租户 UNKNOWN fail-closed，保持） | **UNKNOWN（保持，未改写）** | §8（11 passed；`5f88925`） |
| **真实 Lab**（TheHive 4.1.24-1 真实闭环） | **LAB BLOCKED** | §8 + Lab 方案文档（本机无运行时/零 WSL 分发版/2 GB 空闲） |
| **PostgreSQL 生产锁/崩溃语义** | **UNVERIFIED（默认 deselect）** | §5（PG 专项已编写，未以真实 PG 运行） |
| **生产认证与接线** | **UNKNOWN / 未授权** | 本轮不接生产 router；门⑤ UNKNOWN；无真实运行时证据 |

---

## 11. 剩余阻断与生产授权边界（Remaining Blockers — 绝不自动放开）

1. **真实 Lab Runtime = LAB BLOCKED**：本机无容器运行时 + 零 WSL 分发版 + 2 GB 空闲内存；需用户明确授权资源充足（≥8 GB + 容器运行时 + PostgreSQL + 管理员授权）的专用隔离主机方可复现（Lab 方案已文档化）。
2. **PostgreSQL 生产锁/崩溃语义 = UNVERIFIED**：PG 专项测试默认 deselect；不以 SQLite 全绿冒充 PG 认证。
3. **门⑤ = UNKNOWN**：TheHive 4.1.24-1 无权威派发时实例/租户来源；不改写门⑤，不把读取者 organisation 当案件所属 organisation。
4. **证明入口无生产 router**：封印是防误用非授权；未来接线须由认证服务控制 Reader 选择/证明校验/持久化（复用 operator/RBAC/Manual Reconcile + 可信注册工厂）。
5. **生产认证与接线 = UNKNOWN / 未授权**：本轮完成后**停止，等待 Final Review**；**不**自动进入生产接线、Shuffle/Wazuh Reader 或版本发布。

---

## 12. 交付物清单（Deliverables）

- [x] 实际事务时序图（§3）
- [x] 持久化边界（§4）
- [x] 独立连接/故障注入测试（§5）
- [x] 关键 diff（§2.1，17 文件 +1899/-7）
- [x] 完整测试日志（§9：完整后端 2849 passed / 7 deselected；定向 1127 passed / 4 deselected）
- [x] Git 提交链（§2：33e5d34 → 5f88925，ahead 55，tree clean，NO PUSH）
- [x] §5 Lab 方案文档（`phase3.4.5-m4-f-durable-dispatch-lab-execution-plan.md`）
- [x] 脱敏审查 ZIP（`_m4f_review_bundle/` → 归档于仓库外）
- [x] 分能力报告（§10：派发前 durable/异常恢复/目标绑定安全/证明入口/门⑤/真实 Lab/PG/生产认证，分别列状态）

> **本轮明确：派发前 durable / 异常恢复 / 目标绑定安全 / 证明入口 = 隔离范围 PASS；门⑤ = UNKNOWN 保持；真实 Lab = LAB BLOCKED；PostgreSQL 生产语义 = UNVERIFIED；生产认证 = UNKNOWN / 未授权。** 完成后停止，等待 Final Review。
