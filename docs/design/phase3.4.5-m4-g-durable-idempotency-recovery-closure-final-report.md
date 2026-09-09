# Phase 3.4.5-M4-G — Durable Idempotency & Recovery Closure 最终报告

> **状态：审批槽位幂等 PASS（隔离）· 强制真实派发用 Durable Store PASS（隔离）· 恢复按 attempt_id 关联 + 只读三态 PASS（隔离）· PostgreSQL 专项并发/崩溃语义 UNVERIFIED（代码/测试就绪，默认 deselect）· 安全词表/Wazuh G1-C/门⑤/registry/router 全部保持 · 真实 Lab LAB BLOCKED · 生产认证 UNKNOWN / 未授权**
> 本文件是 **M4-G 一次性收口任务**的最终交付报告：修复 M4-F Final Review 的三项关键发现（**审批并发派发**、**真实派发强制持久化**、**durable 恢复关联**），补充 PostgreSQL 专项并发/故障测试，并完成隔离回归与迁移验证。
> **缺证据的能力保持其真实状态，绝不合并为「全部通过」。** 本轮**不接生产 router、不进 Shuffle/Wazuh Reader、不发布版本、不 push。**

## 0. 文档控制区（Document Control）

| 字段 | 值 |
| --- | --- |
| 文档状态 | **§1/§2/§3 隔离范围 PASS · §4 PostgreSQL UNVERIFIED（默认 deselect）· §5 安全面保持 · 真实 Lab LAB BLOCKED · 生产认证 UNKNOWN** |
| 授权 | M4-G（ONE AGENT · ONE MILESTONE · LOCAL FORWARD COMMITS · NO PUSH） |
| 审查基线 | M4-F Final Review（发现①审批并发派发、②真实派发可降级 flush-only、③恢复按 execution_id 关联）；复核基线提交 `188e69e` |
| M4-G 代码 HEAD | `c5dea57`（4 个代码提交，ahead **60**，工作树干净）；本报告 docs-only 提交为第 **5** 个 M4-G 提交（ahead **61**） |
| 采集日期 | 2026-09-09 |
| 执行纪律 | TDD（RED→GREEN，Iron Law）；文档与代码分离提交；本地前向提交，**不 amend/rebase/reset/force-push/移动 tag/push** |
| 关联交付物 | 本文档 + 脱敏审查 ZIP（`_m4g_review_bundle/`，归档于仓库外） |
| 保护约束 | 不改冻结通用契约/历史 Outcome；**不覆盖或删除现有 attempt**；**不重写历史 Outcome**；不改 Wazuh G1-C 空词表；不恢复共享 `case_created` 词表；不接生产 router；不进 Shuffle/Wazuh Reader；不发布；不 push；无授权主机则不安装系统级依赖/不启动真实服务/不连接第三方或生产实例 |

---

## 1. M4-G 里程碑摘要（审查反馈 → 修复 → 验收）

| 审查者发现 | 严重度 | M4-G 处置 | 提交 | 隔离验收 |
| --- | --- | --- | --- | --- |
| **① 审批并发派发**：同一 `approval_id`、两个不同 `execution_id` 均通过 G3 pre-check（各读空 `prior_approval_rows`），各自独立提交 durable attempt（此前仅 `execution_id` 唯一），双双发出外部请求；`execution_log` 部分审批唯一索引仅在 caller-commit 时才咬合，**晚于** wire call，D14 最后一线到得太迟 | **阻断** | **§1** 在 `dispatch_attempt` 新增 `ux_dispatch_attempt_approval_id` **全唯一**预约（每个 attempt 皆 execute 方向，等价 D14「一 approval 一 execute」语义）；迁移 `0012` **先冲突预检、拒绝静默删除**；IntegrityError 在独立 commit（外部请求**前**）裁决 → 同一 typed 409 `ApprovalAlreadyExecuted` | `a3cf527` | **PASS** |
| **② 真实派发可降级 flush-only**：`store=None`（DI 缺失/配置错误/测试默认值）时，真实外部适配器仍会发出**未被 durable 提交**的请求 | **阻断** | **§2** 生产执行路径新增 **fail-closed 门**：`executor.name in RECOGNIZED_ADAPTER_NAMES and dispatch_attempt_store is None → raise DurableStoreRequired`（503），置于外部请求**前**；mock 豁免；隔离测试显式注入 store 以区分 legacy/mock 与真实 durable 路径；**commit 结果不确定**时只读核查、保持不确定，绝不用新 `execution_id`/新 approval 预约自动重试外部动作 | `0a028d1` | **PASS** |
| **③ 恢复按 execution_id 关联**：终态仅按 `execution_id` 判定和解，错误/陈旧 attempt 的终态可掩盖仍未决尝试；`failed` terminal 有被当作 `confirmed_failure` 的风险 | **阻断** | **§3** 恢复读改为**按 `attempt_id` 关联**（终态 `detail["dispatch_attempt_id"]` 引用，M4-F 已 stamping）；新增只读三态 `RecoveryDisposition`（TERMINAL_AUDIT_PRESENT / DISPATCH_STATUS_UNKNOWN / EXTERNAL_EFFECT_CONFIRMED）；`classify_attempt_recovery` **绝不**产生 EXTERNAL_EFFECT_CONFIRMED，**绝不**把 `failed` 审计当 `confirmed_failure`；恢复身份取自**不可变** attempt，绝不从当前配置倒填 | `212b778` | **PASS** |
| **④ PostgreSQL 专项并发/故障语义未验证** | — | **§4** `test_dispatch_durable_postgres.py` 从 2 能力扩展为 **9 场景矩阵**（8 个 external 测试）；`@pytest.mark.external` + env guard + conftest 默认 deselect；无授权专用 PG 实例 → **保持 PG UNVERIFIED**，绝不以 SQLite 全绿宣称 PG 并发已认证；测试用专用临时库，`create_all(checkfirst)` 幂等，**绝不** `drop_all`/truncate/破坏性清理 | `c5dea57` | **PG UNVERIFIED**（代码/测试就绪） |
| **⑤ 安全与范围保持** | — | **§5** 只读核验：15 文件爆炸半径**不交**安全面（`reconciliation.py` 词表、reader registry、router 均**未**在 diff 内）；共享状态词表全空、Wazuh G1-C 不变、门⑤ fail-closed、生产 Reader registry 空、router 未接线；281 seal tests passed | 本轮只读 | **保持** |

---

## 2. Git 提交链（Commit Chain — 全部本地前向，NO PUSH）

```
188e69e  (M4-G 审查基线 = M4-F §6 docs) M4-F 6: durable-dispatch integration-readiness final report (docs only)
   └─ a3cf527  M4-G §1: durable approval-slot reservation (unique approval_id)
   └─ 0a028d1  M4-G §2: fail-closed durable-store gate for real external dispatch
   └─ 212b778  M4-G §3: recovery correlates by attempt_id + read-only three-state class
   └─ c5dea57  M4-G §4: PostgreSQL-specific concurrency/fault tests (PG UNVERIFIED)   ← 代码 HEAD (ahead 60)
   └─ [本报告]  M4-G §6: durable idempotency & recovery closure final report (docs only)  ← ahead 61
```

`git status`：`On branch main · ahead of 'origin/main' by 60 commits（代码 HEAD）· nothing to commit, working tree clean`。
**未** amend / rebase / reset / force-push；**未**移动任何 tag；**未** push。

### 2.1 关键 diff（`git diff --stat 188e69e..c5dea57`，15 文件，+1237 / -121）

**生产代码（5 文件）**

| 文件 | 变更 | 角色 |
| --- | --- | --- |
| `app/services/executions/durable_dispatch.py` | 199 | **§3** `RecoveryDisposition` 三态 + `AttemptRecovery` + `_terminal_audit_by_attempt`（按 `attempt_id` 关联）+ `_committed_attempts` + `find_unreconciled_attempts`（改按 `attempt_id`）+ `classify_attempt_recovery`（只读，绝不产生 EXTERNAL_EFFECT_CONFIRMED） |
| `app/services/executions/service.py` | 38 | **§1** `_CONFLICT_MARKERS` 加 `dispatch_attempt.approval_id` / `ux_dispatch_attempt_approval_id` → `ApprovalAlreadyExecuted`；**§2** `DurableStoreRequired`(http 503) + fail-closed 门（外部请求前，recognized adapter + `store=None`） |
| `app/models/dispatch_attempt.py` | 17 | **§1** 表级 `ux_dispatch_attempt_approval_id` 全唯一预约；`approval_id` 由 `index=True` 改 `nullable=False`（唯一性移交表级 Index） |
| `app/api/v1/response_execution.py` | 14 | **§2** `except DurableStoreRequired → db.rollback() + 503`（静态脱敏 detail；适配器从未调用，回滚已 flush 的 intent 行，无半写链） |
| `app/services/executions/__init__.py` | 2 | **§2** 导出 `DurableStoreRequired` |

**迁移（1 文件）**

| 文件 | 变更 | 角色 |
| --- | --- | --- |
| `migrations/versions/0012_dispatch_attempt_approval_unique.py` | 89 NEW | **§1** head `0011`→`0012`；先冲突预检（`GROUP BY approval_id HAVING COUNT(*)>1` → `RuntimeError` 拒绝，**绝不静默删除**）；drop `ix_` + create `ux_` unique；downgrade 反转 |

**测试（9 文件）**

| 文件 | 变更 | 角色 |
| --- | --- | --- |
| `tests/test_dispatch_durable_postgres.py` | 591 | **§4** 9 场景 PG 矩阵（8 external，默认 deselect；见 §5.2） |
| `tests/test_dispatch_attempt_durability.py` | 208 | **§1** store 级：同 approval/不同 execution 唯一预约、重放、conflict markers |
| `tests/test_dispatch_durable_integration.py` | 124 | **§2/§3** 服务接线：fail-closed 门、恢复按 `attempt_id`、只读三态 |
| `tests/test_thehive_write_read_closure.py` | 16 | **§2/§5** 注入 FakeStore 区分 legacy/mock 与真实 durable 路径 |
| `tests/test_execution_policy_cross_layer.py` | 15 | **§2** 跨层：门在真实路径 fail-closed |
| `tests/test_observability_cross_layer.py` | 15 | **§2** 跨层观测：503 门 |
| `tests/test_execution_thehive_adapter.py` | 11 | **§2** 纯 additive FakeStore 注入（既有 mock 旅程逐字节不变） |
| `tests/test_execution_wazuh_adapter.py` | 11 | **§2** 纯 additive FakeStore 注入 |
| `tests/test_execution_shuffle_adapter.py` | 8 | **§2** 纯 additive FakeStore 注入 |

> **爆炸半径核验**：15 文件中**无** `reconciliation.py`（安全词表）、**无** reader registry、**无** router、**无** 冻结通用契约模型、**无**历史 Outcome 重写。`git diff --check 188e69e..HEAD` **EXIT=0**（无空白错误、无冲突标记）。

---

## 3. 事务时序图（Transaction Sequence — §6 核心交付）

### 3.1 §1 审批槽位竞态闭合（唯一约束在外部请求**前**裁决）

```
两个 API 请求，同一 approval_id=A，不同 execution_id=X1/X2（真实并发）

请求1 (execution_id=X1)                       请求2 (execution_id=X2)
  |                                             |
  | G3 pre-check: 读 prior_approval_rows(A)=空 → 通过
  |                                             | G3 pre-check: 读 prior_approval_rows(A)=空 → 通过
  |  （第一线 READ-then-WRITE：两请求都通过，因为彼此都还未提交）
  |                                             |
  | §2 门: thehive recognized + store≠None → 通过 | §2 门: 通过
  | binding1 = build_dispatch_binding(X1, A)    | binding2 = build_dispatch_binding(X2, A)
  |                                             |
  | store.record(binding1)                      | store.record(binding2)
  |  独立 Session1:                              |  独立 Session2:
  |   INSERT dispatch_attempt(X1, A)            |   INSERT dispatch_attempt(X2, A)
  |   COMMIT ★ 成功                              |   COMMIT ✗ IntegrityError
  |   (ux_dispatch_attempt_approval_id 唯一:     |   (ux_dispatch_attempt_approval_id 唯一:
  |    A 已被请求1的独立提交占用)                  |    A 已被占用 → 独立提交被拒 → rollback)
  |                                             |   → _CONFLICT_MARKERS 命中
  | 唯一获准 → 继续                              |     "ux_dispatch_attempt_approval_id"
  |                                             |     → ApprovalAlreadyExecuted (typed 409)
  | executor.execute() ─────► 外部请求           |   ✗ 适配器从未调用（外部请求前已裁决）
  |  (恰好一次外部动作)                           |
  ▼ 请求1: 终态 succeeded/failed                 ▼ 请求2: 既有兼容 409（外部调用前收到）
```

**关键不变量**：第二个同 approval 的 attempt 在**它自己的独立 commit** 处被拒（`ux_dispatch_attempt_approval_id` 全唯一），而该独立 commit **发生在 `executor.execute()`（外部请求）之前**。因此**并发下绝无第二次外部动作**；失败者在外部调用前收到既有兼容的 typed 409。**不以最后 `execution_log` 的唯一约束代替派发前 reservation**（后者只在 caller-commit 才咬合，晚于 wire call）。

### 3.2 §2 fail-closed 门位置（`execute_response`，外部请求前）

```
execute_response(db, ..., executor, dispatch_attempt_store):
  1. dispatch_started_at = now()
  2. contributor_facts = executor.dispatch_binding_facts()
  3. binding = build_dispatch_binding(...)              ← 不可变 DispatchBinding
  ┌────────────────────────────────────────────────────────────────────┐
  │ 4. §2 FAIL-CLOSED 门 (M4-G NEW，外部请求前):                          │
  │    if executor.name in RECOGNIZED_ADAPTER_NAMES                       │
  │       and dispatch_attempt_store is None:                             │
  │         raise DurableStoreRequired  ──► API: db.rollback() + 静态 503  │
  │    (RECOGNIZED_ADAPTER_NAMES = ("shuffle","wazuh","thehive");         │
  │     离线 mock 豁免：无外部调用，无 durable 事实需保护)                   │
  └────────────────────────────────────────────────────────────────────┘
  5. store.record(binding)   ★ DURABLE 独立 Session COMMIT (M4-F)
  6. _append(dispatched) + session.flush()      ← caller 事务，仅 flush
  7. outcome = executor.execute(dispatch) ─────► ★ 外部请求发出
  8. detail[TERMINAL_REFERENCE_KEY] = binding.attempt_id   (M4-F baseline L597 → 现 L637)
  9. _append(terminal: succeeded/failed) + session.flush()
```

门位于步骤 **3（binding 构建）之后、步骤 5（durable commit）之前**：recognized 真实适配器若 `store=None`，**绝不**进入 durable commit，更**绝不**发出步骤 7 的外部请求；已 flush 的 intent 行由 API 层 `db.rollback()` 回滚，不留半写链。生产 `get_dispatch_attempt_store(db)` 恒返回真实 store（`DurableDispatchAttemptStore(db.get_bind())`），门在生产**永不误触发**；隔离测试通过 override seam 显式注入 store 走真实 durable 路径。

### 3.3 §3 恢复按 `attempt_id` 关联（只读三态）

```
已提交 DispatchAttempt(attempt_id=A, execution_id=X)  ──┐
                                                        ├─ 关联判据: 是否存在 terminal(succeeded/failed)
execution_log terminal 行 (caller 事务，可能从未提交) ──┘   其 detail["dispatch_attempt_id"] 规范化后 == str(A) ?

   ├─ 有 terminal 且引用 == A          → TERMINAL_AUDIT_PRESENT (audit_decision = succeeded | failed)
   │                                     ★ failed 审计 ≠ confirmed_failure（外部效果可能已落地：
   │                                       效果应用后超时、响应丢失）
   ├─ 有 terminal 但引用 ≠ A / 无引用 / malformed
   │                                    → 该 terminal 不和解 A（malformed fail-closed，settle nothing）
   │                                    → A 仍 DISPATCH_STATUS_UNKNOWN（陈旧/错引用不能掩盖未决尝试）
   └─ 无 terminal 引用 A                → DISPATCH_STATUS_UNKNOWN → 只读人工核查候选
                                          ★ 绝不自动重试 / 补偿 / 重新派发 / 伪造 succeeded 行
                                          ★ 恢复读绝不产生 EXTERNAL_EFFECT_CONFIRMED
```

---

## 4. 幂等约束与持久化边界（§1/§2 核心交付）

### 4.1 §1 三重唯一预约（`dispatch_attempt`，append-only，correlation-only，**无 FK**）

| 唯一索引 | 列 | 语义 | 来源 |
| --- | --- | --- | --- |
| `ux_dispatch_attempt_attempt_id` | `attempt_id` | 一 attempt 一身份 | M4-F（0011） |
| `ux_dispatch_attempt_execution_id` | `execution_id` | **一 `execution_id` 至多一个派发尝试** | M4-F（0011） |
| `ux_dispatch_attempt_approval_id` | `approval_id` | **一 `approval_id` 至多一个 execute 派发尝试**（D14 语义） | **M4-G §1（0012）** |

> 每个 `dispatch_attempt` 行皆 execute 方向（`compensate_response` 从不记录），故 `approval_id` **全唯一**索引携带与 D14「一 approval 一 execute」完全一致的语义，无需方向限定符。三索引在**独立 commit** 处裁决，均在外部请求前。

### 4.2 持久化边界（M4-F 继承，本轮**未改**）

| 边界 | 归属 | 提交时机 | 崩溃/回滚后 |
| --- | --- | --- | --- |
| **`DispatchAttempt`（派发意图 + 目标绑定）** | `DurableDispatchAttemptStore` 的**独立 Session** | **外部请求前 COMMIT** | **存活**（独立事务） |
| `execution_log`（requested/dispatched/terminal） | caller（API 层）业务事务 | 外部请求**返回后** API 层 COMMIT | caller 回滚则消失（**但 attempt 已存活**） |

**冻结契约安全性**：`service.py`「Service 绝不 `commit()`」条款保护 caller 业务事务；durable store 拥有**独立 Session**，只提交它自己那一个。caller 的 `execution_log` 事务边界**仍留在 API 层**，未被触碰。

### 4.3 迁移 0012 安全性（§1，frozen）

- **先冲突预检**：`SELECT approval_id, COUNT(*) GROUP BY approval_id HAVING COUNT(*)>1`；若有重复 → `raise RuntimeError("Migration 0012 refused: ... NEVER ... Reconcile ... manually")`，**绝不静默删除或覆盖** durable append-only 证据。
- **仅改索引形状**：drop `ix_dispatch_attempt_approval_id`（非唯一恢复查找）+ create `ux_dispatch_attempt_approval_id`（唯一预约）；**无任何行 UPDATE/DELETE**。
- `execution_log` 形状与其决策词**不变**（D3.4-05）；downgrade 精确反转。

---

## 5. 独立连接 / 故障注入测试 + PostgreSQL 专项矩阵（§2/§4 验收）

### 5.1 隔离故障注入（SQLite，全绿；含于完整回归 2861）

| 测试面 | 文件 | 证明 |
| --- | --- | --- |
| **§1** 同 approval / 不同 execution 唯一预约（store 级） | `test_dispatch_attempt_durability.py` | 第二个同 approval attempt 独立提交被拒 → typed 409，rows==1 |
| **§1** 同 execution_id 重放 | `test_dispatch_attempt_durability.py` | 唯一索引 → IntegrityError → `ExecutionIdAlreadyBound` |
| **§2** recognized adapter + `store=None` → fail-closed 503 | `test_dispatch_durable_integration.py` / `test_execution_policy_cross_layer.py` / `test_observability_cross_layer.py` | 门在外部请求前拒绝；适配器从未调用；静态脱敏 503 |
| **§2** mock 豁免 / 真实 durable 路径注入区分 | `test_execution_{thehive,wazuh,shuffle}_adapter.py` / `test_thehive_write_read_closure.py` | 纯 additive FakeStore 注入，既有 mock 旅程逐字节不变 |
| **§2** commit 不确定 → 只读核查、保持不确定、零自动重试 | `test_dispatch_durable_integration.py` | 绝不用新 execution_id/新 approval 预约重试外部动作 |
| **§3** 恢复按 `attempt_id` 关联（错/陈旧引用不掩盖未决） | `test_dispatch_durable_integration.py` | 终态引用 ≠ attempt_id → 仍 unreconciled |
| **§3** 只读三态 / `failed ≠ confirmed_failure` | `test_dispatch_durable_integration.py` | `classify_attempt_recovery` 绝不产生 EXTERNAL_EFFECT_CONFIRMED |

### 5.2 §4 PostgreSQL 9 场景专项矩阵（`@pytest.mark.external`，**默认 deselect**）

| # | 用户 §4 场景 | PG 测试（external） | 断言要点 |
| --- | --- | --- | --- |
| 1 | 同一 approval、不同 execution_id 的并发预约 | `TestPostgresApprovalSlotRace::test_same_approval_different_execution_commits_exactly_one` | 2 线程同 approval / 不同 execution → `sorted(outcomes)==["committed","conflict"]`，rows==1 |
| 2 | 同一 execution_id 的并发重放 | `TestPostgresDurableInterleaving::test_concurrent_replay_commits_exactly_one_attempt` | 2 线程同 execution → 恰一 committed，rows==1 |
| 3 | caller 未提交事务与独立 Store commit 的真实交错 | `TestPostgresDurableInterleaving::test_open_caller_write_transaction_does_not_block_the_independent_commit` | caller 开写事务未提交，独立 Store commit 不被阻塞 |
| 4 | commit 成功但客户端确认丢失 | `TestPostgresCommitConfirmationLost::test_lost_confirmation_is_recovered_and_naive_retry_is_rejected` | record 后只读 re-check → `DISPATCH_STATUS_UNKNOWN` |
| 5 | 终态写入失败、caller rollback 和进程中断 | `TestPostgresTerminalFailureSurvival::test_attempt_survives_caller_rollback_and_is_flagged` | caller flush dispatched 后 rollback → attempt 存活，logs==[]，recovery flags |
| 6 | 重启后 orphan attempt 恢复 | `TestPostgresRestartRecovery::test_orphan_attempt_survives_restart_and_is_recovered` | record 后 `engine.dispose()`，新引擎重开 → 仍 flags；身份取自不可变 attempt |
| 7 | 错误 attempt_id 的终态不能掩盖未决尝试 | `TestPostgresAttemptIdCorrelation::test_wrong_attempt_id_terminal_does_not_mask_the_pending_attempt` | 终态引用 `uuid4()` 错误 attempt_id → 目标 attempt 仍 unreconciled |
| 8 | failed dispatch 不等于 confirmed_failure | `TestPostgresAttemptIdCorrelation::test_failed_terminal_is_audit_present_never_confirmed_failure` | failed 终态引用 attempt_id → `TERMINAL_AUDIT_PRESENT(audit="failed")` ≠ `EXTERNAL_EFFECT_CONFIRMED`；`ExecutionOutcome` 查询==[] |
| 9 | 零自动第二次外部调用 | `TestPostgresCommitConfirmationLost::…`（naive-retry 分支，与 #4 合测） | naive retry（同 approval / 新 execution）被拒 IntegrityError，rows==1，**零第二次外部动作** |

> **§4 纪律遵守（PG UNVERIFIED）**：本机**无授权的专用 PostgreSQL 实例**。上述 8 个 PG 测试以 `@pytest.mark.external` + env guard（`SENTINELFLOW_PG_TEST_URL` 未设则 `pytest.skip`）+ conftest 默认 **deselect**（非 skip，保持 0 skipped）三重锁定，本轮**未**以真实 PostgreSQL 运行 → **明确保持 PG 生产并发/崩溃语义 UNVERIFIED**，**绝不以 SQLite 全绿宣称 PostgreSQL 事务与并发已认证**。测试设计仅用**专用临时数据库**，`Base.metadata.create_all(checkfirst=True)` 幂等，**绝不**对生产或共享库运行 `create_all`/`drop_all`/truncate/破坏性清理；每测试 scoped 断言 + FK-safe targeted `_cleanup`（先 `execution_log`→`execution_outcome`/`dispatch_attempt`，最后 `alert_groups` CASCADE）。

---

## 6. 恢复关联与只读三态语义（§3 验收）

| 三态（`RecoveryDisposition`） | 触发条件 | 授权力 |
| --- | --- | --- |
| `TERMINAL_AUDIT_PRESENT` | 存在 terminal(succeeded/failed) 且 `detail["dispatch_attempt_id"]` 规范化后 == `str(attempt_id)` | **仅审计事实**（SERVICE 记录了什么）；`audit_decision` = succeeded/failed；**绝非**外部效果确认 |
| `DISPATCH_STATUS_UNKNOWN` | 已提交 attempt，无 terminal 引用其 `attempt_id`（"emitted but no reliable terminal"） | 外部效果 **UNKNOWN**；只读人工核查候选；**绝不**自动重试/重新派发/补偿/伪造 succeeded 行 |
| `EXTERNAL_EFFECT_CONFIRMED` | 外部效果被权威确认 | **仅存在于 Outcome 层**（`confirmed_success`/`confirmed_failure`），**仅**由权威 Manual Reconcile / trusted-reader 证明路径（`verify_creation_effect`）凭已验证外部 reference 产生；**恢复读绝不产生此态** |

- **`failed` terminal ≠ `confirmed_failure`**：`failed` 审计只表明 SERVICE 记录了失败终态，外部动作仍可能已落地（效果应用后超时、响应丢失）；恢复读把它归为 `TERMINAL_AUDIT_PRESENT(audit="failed")`，**绝不**升格为外部效果确认。
- **恢复身份来自不可变 attempt**：`AttemptRecovery`（`frozen=True, slots=True`）的 `adapter`/`action`/`target` 取自 durable attempt 的**不可变快照**，**绝不**从当前配置倒填。
- **只读人工恢复复用既有权威面**：operator 认证 + RBAC + Manual Reconcile + Outcome append-only + 白名单审计。`AttemptRecovery` **无任何授权力**——外部 JSON、普通内部对象、durable attempt、terminal 审计**均不能**在此直接授权 `confirmed_success`。
- **malformed 引用 fail-closed**：`_terminal_audit_by_attempt` 对非 `str`/无法 `uuid.UUID()` 规范化的引用 **settle nothing**（attempt 保持 UNKNOWN，安全方向）。

---

## 7. 强制真实派发用 Durable Store（§2 验收）

- **fail-closed 门**：`DurableStoreRequired(ExecutionServiceError)`，`http_status = 503`；判据 `executor.name in RECOGNIZED_ADAPTER_NAMES and dispatch_attempt_store is None`；`RECOGNIZED_ADAPTER_NAMES = ("shuffle", "wazuh", "thehive")`（registry.py L54）。
- **API 映射（response_execution.py）**：`except DurableStoreRequired → db.rollback()` + `HTTPException(503, "Execution adapter requires a durable dispatch store")`——**静态脱敏** detail（内部消息绝不到达客户端，沿用 PolicyViolation/ExecutorConfigError 先例）；rollback 确保被拒于派发前的执行**不留半写链**；适配器**从未调用**，无外部效果需和解。
- **不破坏既有 Mock 测试**：离线 mock 豁免（`executor.name` 不在 recognized 集合）；既有内存 `StaticPool` 端点旅程 conftest override `store=None` **逐字节不变**；真实 durable 路径由隔离测试**显式注入** FakeStore/file-backed store 驱动，测试因此**清楚区分 legacy/mock 与真实 durable 路径**。
- **生产永不误触发**：生产 `get_dispatch_attempt_store(db)` 恒返回真实 `DurableDispatchAttemptStore(db.get_bind())`；门只在真实 wiring 故障（DI 缺失/配置错误）时 fail-closed。
- **commit 结果不确定**：若数据库可能已提交但客户端未收到确认，**绝不**自动用新 `execution_id` 或新 approval reservation 重试外部动作；通过**只读**方式核查 durable 记录（`classify_attempt_recovery` → `DISPATCH_STATUS_UNKNOWN`），并**保持不确定性**（§5.2 #4/#9 PG 测试正是此语义）。

---

## 8. 安全与范围核验（§5 验收 — 全部只读，未改安全面）

| 安全面 | 状态 | 证据 |
| --- | --- | --- |
| **共享状态词表全空** | **保持** | `reconciliation.py` `ADAPTER_STATE_VOCABULARIES`：wazuh/shuffle/thehive/mock 四适配器 × terminal_success/terminal_failure/pending/ambiguous 四集合**全 `frozenset()`**；该文件**不在** 15 文件爆炸半径内 |
| **Wazuh G1-C 不变** | **保持** | wazuh 词表 evidence "G1-B/G1-C: no trusted command-level effect vocabulary for ANY verified Wazuh version; fail-closed"；`reconciliation.py` 未触碰 |
| **门⑤ fail-closed** | **UNKNOWN 保持** | TheHive 4.1.24-1 `OutputCase` 无实例/租户 → 真实历史 fail-closed；门⑤**未改写**（M4-F §8 继承） |
| **生产 Reader registry 空** | **保持** | sealed registry 无生产 Reader；281 seal tests passed |
| **router 未接线** | **保持** | 无生产 router 在证明/派发通道；diff 内**无** router 文件 |
| **不进入 Shuffle/Wazuh Reader** | **保持** | 本轮仅 dispatch/durability/recovery 面 |

- **281 seal tests passed**（`test_thehive_write_read_closure` / `test_read_adapter_thehive` / `test_verified_creation_proof` / `test_observability_cross_layer` / `test_mapping` 等只读核验，2 deselected 为真实 Lab external）。
- **3 个 adapter 测试改动纯 additive**：`test_execution_{thehive,wazuh,shuffle}_adapter.py` 仅新增 FakeStore 注入（+11/+11/+8），既有 mock 断言逐字节不变。
- **TheHive 4.1.24-1 仅用于隔离兼容性实验**；**无用户明确授权的实验主机** → 不安装系统级依赖、不启动真实服务、不连接第三方或生产实例。

---

## 9. 完整回归与测试日志（§6 验收 — external 默认 deselect）

| 回归面 | 命令 | 结果 |
| --- | --- | --- |
| **完整后端** | `pytest tests -q` | **2861 passed, 13 deselected, 1 warning in 70.88s (0:01:10)** |
| **M4-G 定向**（dispatch/durability/recovery/approval/execution/outcome/webhook/manual-reconcile/adapters/seal） | `pytest tests -k "dispatch or approval or execution or outcome or webhook or reconcile or thehive or wazuh or shuffle or observability or mapping or verified_creation or binding or durable or recovery" -q` | **2171 passed, 703 deselected, 1 warning in 44.97s** |
| **迁移验证**（独立 throwaway alembic，临时 SQLite，**绝不触碰生产 PG**） | `base→head(0012)→downgrade(base)→re-upgrade→downgrade(0011)` + `0012` 冲突预检 | **15/15 checks PASS** |
| **空白 / 冲突标记** | `git diff --check 188e69e..HEAD` | **EXIT=0** |

- **完整回归恒等式**：2861 passed + 13 deselected = **2874** collected；定向 2171 passed + 703 deselected = **2874**（703 = 690 非匹配 + 13 external）。**0 failed / 0 error**。
- **deselected = 13 `@pytest.mark.external`**（conftest 默认 **DESELECT**，非 skip，保持 0 skipped；须 `-m external` + 真实环境 env 才解锁）：**8 个 §4 PG 专项** + **5 个真实外部**（shuffle/thehive/wazuh 写 + thehive 读 + verified creation proof 读）。完整枚举见审查 ZIP `05-EXTERNAL-ENUM.txt`。
- **迁移验证 15/15 PASS 明细**：`base→head` rc==0 且 `heads==['0012']`；`ux_dispatch_attempt_approval_id` UNIQUE 存在、旧 `ix_` 消失、`execution_id`/`attempt_id` UNIQUE 保持；`downgrade base` rc==0 版本空；`re-upgrade head`==0012；`downgrade 0011`；插入 2 同 approval 行后 `upgrade 0012` **被拒** rc!=0 且 `RuntimeError "Migration 0012 refused"`、版本停留 `0011`、**2 行保留**（count=2，绝不静默删除）。
- 唯一 warning = 预先存在的 `StarletteDeprecationWarning`（httpx/testclient），与本轮无关。
- **e2e 浏览器套件**被 `tests/conftest.py` L24 `collect_ignore_glob = ["e2e/*"]` **冻结设计排除**，`pytest tests` 从不收集 → **不在**上述 2861/0 failed 之内（详见 §11.4 预存失败披露）。

---

## 10. 分能力验收（Evidence Matrix — 缺证据保持未完成，绝不合并「全部通过」）

| 能力项 | 状态 | 证据 |
| --- | --- | --- |
| **§1 审批槽位幂等**（同 execution_id / 同 approval_id 各至多一 execute 派发；并发在唯一约束裁决前无第二次外部动作） | **PASS（隔离）** | §3.1 时序 + §4.1 三重唯一预约 + 迁移 0012 冲突预检 + `test_dispatch_attempt_durability.py`（`a3cf527`） |
| **§2 强制真实派发用 Durable Store**（recognized adapter `store=None` → 外部请求前 fail-closed 503；mock 豁免；commit 不确定只读核查不重试） | **PASS（隔离）** | §3.2 门位置 + §7 + `test_dispatch_durable_integration.py` / 跨层（`0a028d1`） |
| **§3 恢复按 attempt_id 关联 + 只读三态**（错/陈旧终态不掩盖未决；`failed ≠ confirmed_failure`；身份取自不可变 attempt；只读人工恢复复用既有权威面） | **PASS（隔离）** | §3.3 关联 + §6 三态 + `durable_dispatch.py`（`212b778`） |
| **§4 PostgreSQL 专项并发/故障**（9 场景矩阵，8 external 测试就绪） | **UNVERIFIED（代码/测试就绪，默认 deselect）** | §5.2 矩阵；无授权专用 PG 实例，未以真实 PG 运行（`c5dea57`） |
| **§5 安全与范围**（词表全空 / G1-C / 门⑤ / registry 空 / router 未接线） | **保持（未改安全面）** | §8；15 文件爆炸半径不交安全面；281 seal tests passed |
| **迁移链完整性**（base↔head 0012 双向 + 0012 冲突预检拒绝静默删除） | **PASS（临时 SQLite）** | §9 迁移验证 15/15 PASS |
| **真实 Lab**（TheHive 4.1.24-1 真实闭环） | **LAB BLOCKED** | 本机无容器运行时 / 零 WSL 分发版 / 空闲内存不足（M4-F §8 继承） |
| **生产认证与接线** | **UNKNOWN / 未授权** | 本轮不接生产 router；门⑤ UNKNOWN；无真实运行时证据 |

---

## 11. 剩余阻断与生产授权边界（Remaining Blockers — 绝不自动放开）

1. **PostgreSQL 生产并发/崩溃语义 = UNVERIFIED**：§4 的 8 个 PG 专项测试默认 deselect；本机无授权的专用 PostgreSQL 实例；**不以 SQLite 全绿冒充 PG 认证**。需在获授权主机以**专用临时** PG 库运行方可解锁（测试已就绪，`SENTINELFLOW_PG_TEST_URL` + `-m external`）。
2. **真实 Lab Runtime = LAB BLOCKED**：本机无容器运行时 + 零 WSL 分发版 + 空闲内存不足；需用户明确授权资源充足（≥8 GB + 容器运行时 + PostgreSQL + 管理员授权）的专用隔离主机（Lab 方案见 M4-F `phase3.4.5-m4-f-durable-dispatch-lab-execution-plan.md`）。
3. **门⑤ = UNKNOWN**：TheHive 4.1.24-1 无权威派发时实例/租户来源；**不改写门⑤**，不把读取者 organisation 当案件所属 organisation。
4. **预存 e2e 陈旧迁移测试失败（非 M4-G 引入，显著披露）**：`tests/e2e/test_execution_browser.py::test_k_migration_up_down_base_up` L1114 在 `alembic upgrade head` 后断言 `facts["versions"] == ["0009"]`，实测 `AssertionError: assert ['0012'] == ['0009']`（1 failed, 11.65s）。**定性与非归因证据**：
   - **被排除**：`tests/conftest.py` L24 `collect_ignore_glob = ["e2e/*"]` → 权威 `pytest tests`（2861 passed, **0 failed**）从不收集该文件；仅在显式指名路径时才运行。
   - **预存**：基线 `188e69e` 时迁移为 `0009/0010/0011`（head=**0011**，无 0012）→ 彼时 `upgrade head` 已 → `['0011'] != ['0009']`，**该断言在基线即已陈旧失败**（自 head 越过 0009 起）。
   - **非 M4-G 归因**：`git diff 188e69e..HEAD -- backend/tests/e2e/` **为空**，`git diff --quiet … test_execution_browser.py` **exit=0**（与基线逐字节相同）；M4-G 从未触碰 e2e。
   - **处置**：依 §0 严格范围（"只修复三项发现，不重新规划项目"），该失败属**排除套件的预存陈旧断言**，**不在授权修复范围**，故**不静默修改**；在此**显著披露**并附**推荐修法**供 Final Review 授权：将 L1114（及 L1097 之后 `upgrade head` 分支）的硬编码 `["0009"]` 改为动态读取当前 alembic head（或断言 `execution_log` 形状 + `PARTIAL_UNIQUE_INDEXES` 而不断言具体版本号）。**迁移链本身健全**（§9 独立 throwaway alembic 15/15 PASS 已证 base↔head 0012 双向 + 冲突预检）。
5. **生产认证与接线 = UNKNOWN / 未授权**：本轮完成后**停止，等待 Final Review**；**不**自动接线生产 Reader、**不**进入 Shuffle/Wazuh Reader、**不**发布版本、**不** push GitHub。

---

## 12. 交付物清单（Deliverables）

- [x] 事务时序图（§3：§1 审批槽位竞态闭合 / §2 fail-closed 门位置 / §3 恢复按 attempt_id 关联）
- [x] 幂等约束与持久化边界（§4：三重唯一预约 / 独立 Session 边界 / 迁移 0012 安全性）
- [x] 独立连接 / 故障注入测试（§5.1 隔离全绿）+ §5.2 PostgreSQL 9 场景专项矩阵（8 external，PG UNVERIFIED）
- [x] 恢复关联与只读三态语义（§6：`failed ≠ confirmed_failure`；恢复读绝不产生 EXTERNAL_EFFECT_CONFIRMED）
- [x] 强制真实派发门（§7：`DurableStoreRequired`/503；commit 不确定只读核查不重试）
- [x] 安全与范围核验（§8：词表全空 / G1-C / 门⑤ / registry 空 / router 未接线 / 281 seal tests）
- [x] 关键 diff（§2.1，15 文件 +1237/-121；`git diff --check` EXIT=0）
- [x] 完整测试日志（§9：完整后端 2861 passed / 13 deselected / 70.88s；定向 2171 passed / 703 deselected / 44.97s；迁移验证 15/15 PASS）
- [x] Git 提交链（§2：`188e69e` → `c5dea57` 代码 ahead 60 → 本报告 docs ahead 61，tree clean，NO PUSH）
- [x] 分能力报告（§10：§1/§2/§3 隔离 PASS；§4 PG UNVERIFIED；§5 保持；迁移 PASS；Lab BLOCKED；生产认证 UNKNOWN）
- [x] 预存 e2e 陈旧迁移测试失败披露（§11.4：排除机制 + 预存性 + 非归因证据 + 推荐修法）
- [x] 脱敏审查 ZIP（`_m4g_review_bundle/` → 归档于仓库外：00-06 + 10-FINAL-REPORT + `src/` 关键源码）

> **本轮明确：§1 审批槽位幂等 / §2 强制真实派发用 Durable Store / §3 恢复按 attempt_id 关联 + 只读三态 = 隔离范围 PASS；§4 PostgreSQL 专项并发/崩溃语义 = UNVERIFIED（代码/测试就绪，默认 deselect）；§5 安全词表/G1-C/门⑤/registry/router = 保持；迁移链 = PASS（临时 SQLite 15/15）；真实 Lab = LAB BLOCKED；生产认证 = UNKNOWN / 未授权。** 完成后停止，等待 Final Review。**不自动接线生产 Reader、不发布版本、不 push GitHub。**
