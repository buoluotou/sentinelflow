# Phase 3.4.5 — M4-GR · Recovery Correlation Final Fix · 最终报告

> **状态横幅**：Fix 1 恢复三重关联 隔离 **PASS** · Fix 2 e2e 陈旧 head **CLOSED** · PostgreSQL 并发/崩溃 **UNVERIFIED**（默认 deselect，无授权实例）· TheHive 真实 Lab **LAB BLOCKED** · 门⑤ **UNKNOWN** · 生产接线 **未授权/未接线** · 未 push。
>
> 本轮是 M4-G Final Review「部分通过、剩 1 个代码级阻塞」的**最小收口**：只修两个明确问题（恢复关联跨 execution 缺口、预存 e2e 陈旧迁移断言），不扩大功能范围。

---

## 0. 文档控制区

| 项 | 值 |
| --- | --- |
| 里程碑 | M4-GR — Recovery Correlation Final Fix |
| 审查基线 | `cee093eae2c0d6ec9c6e3c5f59b14928770585c1`（M4-G docs HEAD） |
| 本轮 HEAD | `5545de0`（M4-GR §2） |
| 前向提交 | `d841f6e`（§1 恢复关联 + 测试）→ `5545de0`（§2 e2e 迁移断言） |
| 分支 / 领先 | `main` / ahead of origin **63**（本轮 +2） |
| 改动范围 | 4 文件 `+366 / -53`：生产 1（`durable_dispatch.py`）+ 测试 3 |
| 迁移 head | `0012`（未新增迁移；本轮无 schema 变更） |
| 完整回归 | **2867 passed / 14 deselected / 0 failed / 0 skipped / 72.53s** |
| `git diff --check` | **EXIT=0** |
| 授权边界 | 1–2 本地前向提交；禁 amend/rebase/reset/force-push/tag/push；不接生产 router；不进 Shuffle/Wazuh Reader |

---

## 1. Final Review 结论与本轮范围

Final Review 判定 §1 审批槽位幂等、§2 强制 Durable Store **已真正修好**，唯 §3 恢复关联差「最后一个完整性条件」。

| 能力 | Final Review | M4-GR 后 |
| --- | --- | --- |
| 同 execution_id 幂等 | PASS（隔离） | 保持 PASS |
| 同 approval_id 并发预约 | PASS（隔离） | 保持 PASS |
| 真实 Adapter 无 Durable Store → 503 | PASS | 保持 PASS |
| 0012 迁移冲突预检 | PASS（SQLite 迁移范围） | 保持 PASS |
| **attempt_id 恢复关联** | **PARTIAL — 跨 execution 误关联缺口** | **Fix 1 → PASS（隔离）** |
| failed ≠ confirmed_failure | PASS | 保持 PASS |
| PostgreSQL 并发/崩溃 | UNVERIFIED（正确保持） | 仍 UNVERIFIED（+1 跨 execution 场景，默认 deselect） |
| TheHive 真实 Lab | LAB BLOCKED | 保持 LAB BLOCKED |
| 生产接线 | UNKNOWN / 未授权 | 保持未接线 |
| **e2e 陈旧迁移断言** | 披露正确，批准顺手修复 | **Fix 2 → CLOSED** |

本轮**只**修这两点，其余能力面原样保持。

---

## 2. Fix 1 — 恢复关联必须 execution_id + attempt_id + approval_id 三重一致

### 2.1 缺陷（Final Review 复现）

M4-G 的 `_terminal_audit_by_attempt()` 扫描全部 `succeeded/failed` terminal，**仅**以 `detail["dispatch_attempt_id"]` 为关联键（`attempt_id -> decision`），从不校验该 terminal 的 `execution_id`/`approval_id` 是否等于该 `DispatchAttempt` 的对应不可变事实。

隔离复现：① 真实 durable attempt：execution A / attempt X；② 插入属于 execution B 的 `failed` terminal；③ 让该错误 terminal 的 `detail` 引用 attempt X。**旧结果**：attempt X 从 unreconciled 列表消失，被误分类为 `TERMINAL_AUDIT_PRESENT / failed`——一条跨 execution 的异常历史「消掉」了一个未决 attempt。

> 说明：正常 Service 不会主动生成这种错引用，故这不是可远程攻击漏洞；但恢复模块的**存在目的**就是处理崩溃、损坏、错序与异常历史，它不能在异常历史里被误关联。

### 2.2 正确语义（三重一致，fail-closed）

一条 terminal 只有在**全部**满足时才可 settle 一个 attempt：

- `terminal.execution_id == attempt.execution_id`
- `terminal.detail["dispatch_attempt_id"] == attempt.attempt_id`
- `terminal.approval_id == attempt.approval_id`（committed `execution_log` 行的 `approval_id` 为 **non-null**，故实际恒需校验；代码对存在值做条件校验以对齐指令措辞）

任何**缺失、非法（malformed）、跨 execution、跨 approval、错误 attempt_id** → fail-closed：`DISPATCH_STATUS_UNKNOWN`。关联事实**只**取自不可变 attempt 与已提交 terminal 行，**绝不**从当前配置或其他日志倒填。正确关联的 `failed` terminal 仍**只**是 `TERMINAL_AUDIT_PRESENT`（审计事实），**绝不** `confirmed_failure` / `EXTERNAL_EFFECT_CONFIRMED`。

### 2.3 机制

`_terminal_audit_by_attempt`（`attempt_id -> decision`）→ 拆为：

- `_terminal_refs_by_attempt(session)`：按被引用 `attempt_id` 分组，每条 terminal 记录其 `execution_id / approval_id / decision`（`_TerminalRef` frozen dataclass）；malformed/非 str 引用跳过（fail-closed）；oldest-first。
- `_settling_decision(attempt, refs)`：对候选逐条校验三重一致——`execution_id` 不等则跳过（跨 execution），`approval_id` 存在且不等则跳过（跨 approval），全部一致才采纳；latest matching wins；无匹配返回 `None`。

`find_unreconciled_attempts` / `classify_attempt_recovery` 改用 `_settling_decision`。**公开 API 与三态语义完全不变**（`RecoveryDisposition` / `AttemptRecovery` / `DurableDispatchAttemptStore` 签名不动）。

### 2.4 负向测试矩阵（TDD RED → GREEN）

新增 `TestImmutableFactCorrelation`（file-backed SQLite，`test_dispatch_attempt_durability.py`）：

| # | 场景 | 期望 disposition | 修前 | 修后 |
| --- | --- | --- | --- | --- |
| 1 | 其他 execution 的 terminal 引用本 attempt_id（reviewer 场景，`failed`） | `DISPATCH_STATUS_UNKNOWN`，仍在 unreconciled | **RED（误 settle）** | GREEN |
| 2 | 相同 execution、**错误 approval_id** | `DISPATCH_STATUS_UNKNOWN` | **RED（误 settle）** | GREEN |
| 3 | 相同 execution + approval、**错误 attempt_id** | `DISPATCH_STATUS_UNKNOWN` | PASS | PASS |
| 4 | **malformed** attempt_id 引用 | `DISPATCH_STATUS_UNKNOWN` | PASS | PASS |
| 5 | execution + approval + attempt_id **全一致**（正向对照，`succeeded`） | `TERMINAL_AUDIT_PRESENT`，unreconciled 空 | PASS | PASS |
| 6 | 全一致但 `failed` | `TERMINAL_AUDIT_PRESENT`（audit=failed），**非** `EXTERNAL_EFFECT_CONFIRMED` | PASS | PASS |

场景 1、2 在修前被确认为 **RED**（`assert [] == [UUID(...)]`——未决 attempt 被误消），修后 **GREEN**；3–6 为回归护栏/正向对照。

**PostgreSQL external（Fix 1b）**：`TestPostgresAttemptIdCorrelation` 新增 `test_cross_execution_terminal_referencing_the_attempt_does_not_settle`——两条真实 FK-seeded approval 链（A/B），execution B 的 `failed` terminal 错引用 attempt X（属 A）；断言 X 仍 `DISPATCH_STATUS_UNKNOWN`。该测试仍 `@pytest.mark.external` + `SENTINELFLOW_PG_TEST_URL` env-guard，**默认 deselect，PG 保持 UNVERIFIED**（无授权专用实例，绝不对生产/共享库运行）。external 节点由 13 → **14**。

---

## 3. Fix 2 — e2e 陈旧 migration head 断言

### 3.1 缺陷与预存性

`tests/e2e/test_execution_browser.py::test_k_migration_up_down_base_up` 在 `alembic upgrade head` 后断言 `facts["versions"] == ["0009"]`。该断言在 **M4-G 之前即已陈旧**（M4-G 基线 head 已是 `0011`，现为 `0012`），实测 `assert ['0012'] == ['0009']` FAILED。此失败在 M4-G 报告 §11.4 已诚实披露：**非 M4-G 引入**、被 `collect_ignore_glob=["e2e/*"]` 排除、逐字节等同基线。Final Review 批准顺手修复。

### 3.2 修法（不写死版本号）

- **动态读取当前 head**：新增 `_alembic_current_head()`，用 `ScriptDirectory.get_current_head()` 从迁移脚本目录读取（`script_location` 钉到 backend/migrations 绝对路径，cwd 无关）；断言改为 `facts["versions"] == [_alembic_current_head()]`——**绝不**硬编码 `0009/0011/0012`。
- **验证最终 schema/index 不变量**（reviewer 的「更好」选项）：`_migration_facts` 新增 `dispatch_attempt_indexes` 键；`upgrade head` 后除既有 `execution_log` 分区唯一索引外，再断言 M4-F/M4-G 的 durable `dispatch_attempt` 三重唯一预约（`ux_dispatch_attempt_attempt_id / _execution_id / _approval_id`）齐备。
- in-process 读取 alembic 配置触发的 benign `path_separator` DeprecationWarning 就地静默，保持显式运行 warning 摘要干净。
- L1097（`upgrade 0009` 后 `["0009"]`）是**显式定向升级**断言，正确，原样保留。

### 3.3 显式运行证明（失败已关闭）

```
pytest tests/e2e/test_execution_browser.py::test_k_migration_up_down_base_up
→ 1 passed, 1 warning in 11.75s   （修前：FAILED assert ['0012'] == ['0009']）
```

显式路径**绕过** `tests/conftest.py` 的 `collect_ignore_glob=["e2e/*"]`（conftest L21 明确「explicit paths still work」）。`tests/e2e/` 仍**不**进入默认 `pytest tests` 收集。

---

## 4. 回归证据

| 回归项 | 命令要点 | 结果 |
| --- | --- | --- |
| durable/recovery 专项 | 3 个 dispatch durability 文件 | **37 passed** / 6.20s |
| migration 专项 | `-k migration` | **7 passed** / 2874 deselected |
| 显式 e2e migration | `test_execution_browser.py::test_k_...` | **1 passed** / 11.75s |
| 完整 backend | `pytest tests -q` | **2867 passed / 14 deselected / 0 failed / 0 skipped** / 72.53s |
| 空白/冲突标记 | `git diff --check` | **EXIT=0** |

计数核对：完整收集 2881 = 2867 非 external + 14 external；较 M4-G（2861 + 13 = 2874）新增 6 个 SQLite 关联测试（Fix 1）+ 1 个 external PG 测试（Fix 1b）= +7。真实 external 测试**默认 deselect**；PG 未运行 → **UNVERIFIED**。

---

## 5. 能力验收矩阵（对照 Final Review）

| 能力 | 结论 | 依据 |
| --- | --- | --- |
| 恢复三重关联（execution + attempt + approval） | **PASS（隔离）** | Fix 1；`TestImmutableFactCorrelation` 6 场景 + 既有 recovery 全绿 |
| failed ≠ confirmed_failure | **PASS** | 场景 6：audit=failed 仍 `TERMINAL_AUDIT_PRESENT`，非 `EXTERNAL_EFFECT_CONFIRMED` |
| 恢复读只读、不倒填、不重派 | **PASS** | 公开 API 未变；`test_classification_is_read_only_no_new_rows` / `test_recovery_identity_comes_from_the_immutable_attempt_not_config` 全绿 |
| e2e 陈旧迁移断言 | **CLOSED** | Fix 2；显式运行 1 passed（动态 head + schema 不变量） |
| §1 审批槽位幂等 / §2 强制 Durable Store / 0012 冲突预检 | **保持 PASS** | 本轮未触碰其生产路径；完整回归全绿 |
| PostgreSQL 并发/崩溃 | **UNVERIFIED** | external 默认 deselect；无授权专用实例 |
| TheHive 真实 Lab | **LAB BLOCKED** | 无授权实验主机 |
| 门⑤ / 生产接线 | **UNKNOWN / 未接线** | 未授权 |

---

## 6. 安全与范围核验（保持不变）

- 生产变更**仅** `durable_dispatch.py` 恢复读侧关联逻辑（纯读、无新写、无 schema 变更、无新迁移）；不触碰审批/执行/Outcome/Webhook/Manual Reconcile 生产路径与安全词表。
- 共享状态词表保持全空；Wazuh G1-C fail-closed 不变；TheHive 门⑤ fail-closed 不变；生产 Reader registry 保持空；router **未接线**；未进入 Shuffle/Wazuh Reader。
- 未安装系统级依赖、未启动真实服务、未连接第三方/生产实例；未发布版本；**未 push**（本地 ahead 63）。
- 提交纪律：2 个本地前向提交，**未** amend/rebase/reset/force-push/移动 tag。

---

## 7. 剩余阻断与下一步

**剩余外部阻断（均非本轮代码问题，需授权资源）**：

1. **PostgreSQL UNVERIFIED**：14 个 external 测试（含新增跨 execution 错引用场景）需在**授权的专用临时 PG**上以 `SENTINELFLOW_PG_TEST_URL` + `-m external` 运行方可认证真实 MVCC/并发/崩溃/FK 语义。
2. **TheHive 真实 Lab LAB BLOCKED**：需授权隔离实验主机。
3. **门⑤ / 生产接线 UNKNOWN**：未授权。

**收口判断**：若 Final Review 确认三重关联与陈旧 e2e 均已修净，则 M4 这一长串内部 durability/recovery 架构可正式收口。**不再**新增 M4-H/M4-I 之类内部设计阶段。下一件有价值的事（需另行授权）：**准备一台资源足够的隔离实验主机 → 真 PostgreSQL → 真 TheHive → 跑第一条真实闭环**。

---

## 8. Git 证据、交付物与复现

**提交链**（`cee093e..HEAD`，本地，NO PUSH）：

```
5545de0  M4-GR §2: fix pre-existing e2e stale migration-head assertion (dynamic head + schema invariants)
d841f6e  M4-GR §1: recovery correlates by execution_id + attempt_id + approval_id (fail-closed)
cee093e  (M4-G 基线)
```

**改动文件（4，`+366/-53`）**：

- `backend/app/services/executions/durable_dispatch.py`（Fix 1 生产：`_TerminalRef` + `_terminal_refs_by_attempt` + `_settling_decision`）
- `backend/tests/test_dispatch_attempt_durability.py`（Fix 1：`TestImmutableFactCorrelation` 6 场景）
- `backend/tests/test_dispatch_durable_postgres.py`（Fix 1b：跨 execution 错引用 external 场景）
- `backend/tests/e2e/test_execution_browser.py`（Fix 2：动态 head + `dispatch_attempt` schema 不变量）

**交付物**：本报告 + 仓库外脱敏审查 ZIP `phase3.4.5-m4-gr-review-bundle.zip`（含关键源码、完整 patch、事务/关联说明、负向与并发测试、恢复查询、e2e 迁移证明、密扫描 attestation）。

> 提交说明：为严格遵守「允许创建一个或两个本地前向提交」（两个已用于两处代码修复），本报告作为交付文档写入 `docs/design/` 但**未**追加第 3 个提交；工作树对**已跟踪文件干净**，本报告为唯一新增未跟踪文档，同时收录于审查 ZIP。如需入库，接受时补一个 docs-only 提交即可。

**复现命令**（Windows / pwsh，backend 目录）：

```
# Fix 1 隔离（含 RED→GREEN 的 6 关联场景）
.\.venv\Scripts\python.exe -m pytest tests/test_dispatch_attempt_durability.py -q
# Fix 2 显式 e2e（绕过 collect_ignore_glob）
.\.venv\Scripts\python.exe -m pytest tests/e2e/test_execution_browser.py::test_k_migration_up_down_base_up -q
# 完整回归（external 默认 deselect）
.\.venv\Scripts\python.exe -m pytest tests -q
# PG external（仅在有授权专用实例时；否则 skip → UNVERIFIED）
$env:SENTINELFLOW_PG_TEST_URL="<dedicated-throwaway-pg>"; .\.venv\Scripts\python.exe -m pytest -m external -q
```
