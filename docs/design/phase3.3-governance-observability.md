# Phase 3.3 设计：治理与可观测性（Governance & Observability）

> 状态：**设计冻结**（2026-09-01；冻结后不得再改设计，只允许按 §8 拆步实施）
> 范围：Phase 3.3 —— 把执行能力从"能执行"升级为"能管好执行"；回答三个问题：**谁有资格执行 × 什么条件下允许执行 × 执行表现如何**
> 基线：`v1.2.0`（commit `2be74f8`，tag 冻结，本文档不修改该提交，不修改 v1.1.0 / `0f6e3fc`）
> 前置：`docs/design/phase3-response-execution.md`（Phase 3.1 设计，已冻结；D1–D14 全部继续有效）+ `docs/design/phase3.2-external-adapters.md`（Phase 3.2 设计，已冻结；E1–E5 全部继续有效）
> 日期：2026-09-01

---

## 1. 定位

Phase 3.2 回答了 **"怎么安全地把动作送出去"**。
Phase 3.3 回答 **"怎么管好执行"** —— 三个子问题形成治理三角：

| 子问题 | 议题 | 一句话 |
|---|---|---|
| **谁有资格执行？** | A — Operator Identity & RBAC | 把 `operator` 从客户端自报字符串升级为已认证身份 |
| **什么条件下允许执行？** | B — Execution Policy Architecture | 在 Guard 之后（或之中）引入策略决策层 |
| **执行表现如何？** | C — Adapter Health & Metrics | 从现有 `execution_log` 事实派生度量，不改基础模型 |

三者构成：**Operator × Policy × Metrics = 治理层**。

## 2. 安全边界冻结（铁律）

Phase 3.3 **不修改**以下任何已冻结内容：

- v1.1.0（`0f6e3fc`）和 v1.2.0（`2be74f8`）的任何已提交代码
- AI advisory-only 定位（AI 不升级、不参与 RBAC、不产生执行副作用）
- 四条核心安全边界：No automatic approval / No automatic retry / No internal adapter fan-out / No hidden execution
- D1–D14 冻结设计（Phase 3.1）+ E1–E5 裁决（Phase 3.2）
- `execution_log` 现有 8 个合法状态语义（`requested` / `guard_rejected` / `dispatched` / `succeeded` / `failed` / `compensation_requested` / `compensation_succeeded` / `compensation_failed`）
- `EXECUTABLE_ACTIONS` 四词（`block_source_ip` / `isolate_host` / `disable_account` / `escalate_to_incident`）
- `NON_COMPENSATABLE_ACTIONS` 冻结集
- 密钥边界（`.env → Settings → AdapterCredentials → Authorization header`，URL 形状闸，日志脱敏）
- Single-Active-Adapter 不变式
- Append-only 审计模型（`execution_log` 只追加，不 UPDATE / DELETE）

## 3. 议题 A：Operator Identity & RBAC（冻结范围）

### 3.1 现状

- `EXECUTION_TOKEN` 是一个共享 Bearer secret，不区分操作者身份
- Execute Intent 中的 `operator` 字段是客户端自报字符串，无认证
- 前端 Execute Console 不显示当前操作者身份

### 3.2 目标

- 引入 **Operator** 概念：真实操作者身份，静态注册表（`.env` 或配置文件）
- 每个 Operator 拥有角色：`viewer`（只读）/ `reviewer`（approve/reject）/ `executor`（触发执行/补偿）/ `admin`（配置变更）
- `EXECUTION_TOKEN` 从"一个全局 secret"升级为 **per-operator token**（至少 token → operator 绑定）
- 执行链中 `operator` 字段从"客户端自报"升级为"从 token 解析的已认证身份"
- 前端 Execute Console 显示当前操作者身份

### 3.3 冻结边界

- **不做** SSO / LDAP / OIDC（那是 v2.0 级别）
- **不做** 动态角色管理 UI（第一版静态配置）
- **不修改** AI 层（AI Provider / AI Analysis / AI Risk Summary / Response Recommendation 不涉及 Operator 身份）
- **不修改** Approval 层（approve/reject 的 `reviewer` 字段暂不绑定 Operator，保持现有语义）

### 3.4 开放点（需裁决）

| 编号 | 问题 | 候选方案 |
|---|---|---|
| **G1** | Operator 注册表存储位置 | (a) `.env` 平铺（`OPERATOR_1_TOKEN=xxx, OPERATOR_1_NAME=alice, OPERATOR_1_ROLE=executor`）vs (b) 独立配置文件（`operators.yaml`）vs (c) 数据库表 |
| **G2** | 向后兼容性：现有 `EXECUTION_TOKEN` 如何处理 | (a) 保留为"匿名 operator"的 fallback vs (b) 强制迁移到 per-operator token（breaking change） |
| **G3** | 前端身份传递方式 | (a) 登录页选择 operator + token 绑定 vs (b) 纯 header token（前端不感知身份选择） |

---

## 4. 议题 B：Execution Policy Architecture（冻结范围）

### 4.1 现状

Guard 检查五件事：`action_not_executable` / `approval_not_found` / `approval_already_executed` / `executor_unsupported` / `adapter_misconfigured`。没有更高层策略（如"夜间禁止隔离主机"、"某类事件必须双人审批"）。

### 4.2 核心设计问题（冻结前必须裁决）

**Policy 到底属于 Guard 的扩展，还是 Guard 之后的独立决策层？**

这个问题直接决定：
- 是否新增 `execution_log` 状态（如 `policy_rejected`）
- Policy 拒绝的审计语义（与 `guard_rejected` 的关系）
- 是否需要新的数据库列 / 迁移

### 4.3 候选方案

| 方案 | 描述 | 是否新增状态 | 影响面 |
|---|---|---|---|
| **B-1: Guard 扩展** | Policy 检查作为 Guard 的新拒绝码（如 `policy_violation`），拒绝后落 `guard_rejected` | 否 | 只改 Guard，不改状态机 / 迁移 / 前端 |
| **B-2: 独立层** | Guard 之后、Dispatch 之前插入独立 Policy 检查点；拒绝落新状态 `policy_rejected` | **是** | 改状态机 / CHECK / 迁移 / API / 前端 / 测试 / D1–D14 兼容性审查 |
| **B-3: 混合** | Policy 作为独立层设计，但拒绝后复用 `guard_rejected` 状态（在 `detail` 中区分 guard vs policy 拒绝原因） | 否 | Guard 不改，Policy 层独立，`detail` 字段区分原因 |

### 4.4 用户裁决约束（2026-09-01）

> **"不要在实施阶段临时加一个 `policy_rejected`。"**
> **"Phase 3.3 B 应该先做 Policy Architecture / Decision Semantics，再决定是否新增状态。"**

**冻结结论**：Phase 3.3 B 的第一步是 **设计决策**（选 B-1 / B-2 / B-3），而非直接实施。在裁决 B 方案之前，不新增任何 `execution_log` 状态、不新增迁移、不修改 D1–D14。

### 4.5 策略类型（第一版，冻结）

无论选哪个方案，第一版策略类型硬编码在 Python 侧（不做 DSL / 规则编辑器）：

| 策略类型 | 描述 | 配置方式 |
|---|---|---|
| 时间窗口约束 | 某些动作只允许在特定时间窗口执行 | `.env` 或配置文件 |
| 事件严重度门槛 | 某些动作要求事件达到特定严重度才允许执行 | `.env` 或配置文件 |
| 双人审批（可选） | 某些动作要求两个不同 reviewer 的批准 | 第一版可选，不强制 |

### 4.6 冻结边界

- **不做** 动态策略引擎 / DSL / 规则编辑器
- **不做** 策略管理 UI
- **不修改** `execution_log` 基础事实模型（除非裁决 B-2）
- **不修改** 现有 Guard 五拒绝码语义（除非裁决 B-1）

---

## 5. 议题 C：Adapter Health & Metrics（冻结范围）

### 5.1 现状

- 执行是同步的，超时即失败
- 没有健康检查、没有成功率追踪、没有执行延迟统计
- `execution_log.detail` 包含适配器返回的原始信息，但无结构化度量字段

### 5.2 核心设计原则（用户裁决 2026-09-01）

> **"不要为了 Metrics 修改 `execution_log` 的基础事实模型。"**
> **"执行事实不变，指标从事实派生。"**

**冻结结论**：Metrics 服务从现有 `execution_log` 行**只读派生**，不新增列、不新增表、不修改 `execution_log` 模型。

### 5.3 目标

| 度量 | 派生来源 | 描述 |
|---|---|---|
| 执行计数 | `execution_log` 行数按 adapter_name 分组 | 每适配器总执行次数 |
| 成功率 | `status IN ('succeeded') / total` | 按适配器聚合 |
| 失败率 | `status IN ('failed') / total` | 按适配器聚合 |
| 延迟 | `execution_log.created_at` 差值（请求→终态） | P50 / P95 / P99（如果时间精度足够） |
| 最近失败 | `status = 'failed' ORDER BY created_at DESC LIMIT N` | 最近 N 次失败摘要 |
| 适配器可用性 | 最近 N 次执行的成功率 + 最后一次执行时间 | 健康指示器 |

### 5.4 API 设计

- `GET /api/v1/executions/metrics` — 聚合度量端点（按适配器分组）
- 纯只读，不需要 Bearer token（与现有 GET `/executions` 一致）
- 返回结构化 JSON：`{adapter_name: {total, succeeded, failed, success_rate, last_execution_at, recent_failures[]}}`

### 5.5 前端

- Execution Audit 页面增加度量摘要区域（可选，不强制）
- 适配器健康指示器（Execute Console 中显示适配器可用性）

### 5.6 冻结边界

- **不修改** `execution_log` 模型（不加 latency 字段、不加 provider_status 字段、不加 metrics 表）
- **不做** Prometheus / OpenTelemetry 集成（可以留接口，但不实施）
- **不做** 自动降级 / 熔断
- **不做** 实时推送（轮询即可）

---

## 6. 与 Phase 3.4 / v2.0 的边界

| 议题 | 归属 | 理由 |
|---|---|---|
| External Outcome Reconciliation | **Phase 3.4** | 第一次改变同步执行模型（同步 + 异步结果），复杂度明显高于 3.3 |
| Webhook / Callback | **Phase 3.4** | 依赖 Reconciliation 的异步基础设施 |
| Long-running Execution | **Phase 3.5 / v2.0** | 需要执行调度架构升级（pending → callback → reconcile → terminal），不是简单功能增加 |

---

## 7. 实施步骤（冻结）

| 步骤 | 内容 | 依赖 |
|---|---|---|
| **3.3.1** | Operator Identity & RBAC | 无（基座） |
| **3.3.2** | Execution Policy Architecture | 3.3.1（需要 Operator 身份才能做策略决策） |
| **3.3.3** | Adapter Health & Metrics | 无（可并行，但建议在 3.3.1/3.3.2 之后以便统一测试） |
| **3.3.4** | Cross-layer Regression | 3.3.1 + 3.3.2 + 3.3.3 |
| **3.3.5** | Browser E2E | 3.3.4 |
| **3.3.6** | Final Regression | 3.3.5 |
| **3.3.7** | Release | 3.3.6 |

---

## 8. 待裁决开放点汇总

| 编号 | 议题 | 问题 | 建议 |
|---|---|---|---|
| **G1** | A — Operator | 注册表存储位置 | 建议 (a) `.env` 平铺（与现有配置风格一致） |
| **G2** | A — Operator | `EXECUTION_TOKEN` 向后兼容 | 建议 (a) 保留为 fallback（不 breaking） |
| **G3** | A — Operator | 前端身份传递方式 | 建议 (a) 登录页选择 + token 绑定 |
| **B-?** | B — Policy | Guard 扩展 vs 独立层 vs 混合 | **必须先裁决再实施**；建议 B-3（混合：独立层设计 + 复用 `guard_rejected` 状态 + `detail` 区分原因） |

---

## 9. 测试策略（冻结）

- 每步全量回归 `pytest tests -q`，数字必须单调递增
- Operator 相关测试：静态注册表 + token 绑定 + 角色权限
- Policy 相关测试：策略拒绝路径 + 审计可追溯
- Metrics 相关测试：派生聚合正确性 + 空数据边界
- Cross-layer regression：全链（Approve → Execute → Guard → Policy → Adapter → Audit）端到端
- Browser E2E：Operator 身份显示 + Execute Console + Execution Audit + Metrics 摘要
- 默认套件保持零外部请求（external marker opt-in 不变）

---

## 10. 版本演进图谱（冻结）

```
Phase 1        Core SOC
  ↓
Phase 2        AI + Approval
  ↓
Phase 3.1      Controlled Execution
  ↓
Phase 3.2      External Adapters
  ↓
Phase 3.3      Governance + Observability    ← 本轮
  ↓
Phase 3.4      Reconciliation + Webhook      ← 下一轮
  ↓
v2.0           Long-running / Advanced Orchestration
```

对应版本 tag：

```
v1.0.0-phase1  → Phase 1
v1.1.0         → Phase 2
v1.2.0         → Phase 3.1 + 3.2
v1.3.0 (?)     → Phase 3.3
v1.4.0 (?)     → Phase 3.4
v2.0.0         → Long-running / Advanced
```
