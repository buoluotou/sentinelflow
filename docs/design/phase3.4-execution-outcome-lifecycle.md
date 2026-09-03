# Phase 3.4 设计：执行效果生命周期（Execution Outcome Lifecycle）

> 状态：**设计冻结（完整版）**（2026-09-01 冻结；2026-09-03 用户裁决 O1–O5 全部落定，§11 从开放点转为裁决记录；冻结后不得再改设计，只允许按 §10 拆步实施）
> 范围：Phase 3.4 —— 把平台能力从"执行请求有没有成功送出去"升级为"**这次执行最终在外部世界产生了什么效果，平台能不能持续知道**"
> 基线：`v1.3.0`（commit `48fbe41`，tag 冻结；其后的文档提交 `28dc16a` / `459e8bf` / `0bfdd9d` 不属于功能代码）。本文档不修改该提交，不修改 v1.1.0（`0f6e3fc`）/ v1.2.0（`2be74f8`）
> 前置：`phase3-response-execution.md`（D1–D14 有效）+ `phase3.2-external-adapters.md`（E1–E5 有效）+ `phase3.3-governance-observability.md`（3.3 全部裁决有效）
> 日期：2026-09-01

---

## 1. 定位

v1.3.0 的四个适配器在代码中一致声明 **synchronous terminal states**：`succeeded` / `failed` 记录的是 **Dispatch Outcome**（外部系统是否同步接受了请求），不是 **External Effect Outcome**（真实世界是否被遏制 / 隔离 / 关闭）。

Phase 3.4 的三个议题是一个不可拆分的整体（用户裁决：A + B + C ✅）：

| 议题 | 角色 | 一句话 |
|---|---|---|
| **A — Outcome Reconciliation** | 业务目标 | 平台持续知道执行的最终效果 |
| **B — Webhook / Callback** | 事实输入 | 外部世界把效果事实送回平台的通道 |
| **C — Long-running Execution** | 生命周期模型 | 执行语义突破"30 秒同步预算"的限制 |

只做 A：对账没有可靠的长耗时生命周期与入站事实通道，最终退回同步请求或人工轮询。
只做 B：有了门，却没有统一的执行生命周期语义。
只做 C：把"30 秒同步请求"换成"等待"，却没解决"等待什么、谁告诉平台完成了什么"。

因此：**3.4 = Outcome Lifecycle**（A = 业务目标，B = 事实输入，C = 生命周期模型）。

**本阶段不进入核心（用户裁决暂缓）**：

- **D（更完整 RBAC / SSO / OIDC / LDAP）**：3.3 的 token → operator → role 对当前阶段已足够；身份基础设施升级不与 Outcome Lifecycle 混做
- **E（Analytics / Reporting）**：缺的不是更多图表，而是执行效果事实；没有 3.4 的对账，报表只会是"漂亮的派发统计"而非"真实响应效果统计"。E 建立在 3.4 之后
- **F（策略 / 审批编排）**：编排条件分支（成功→B，失败→C）以可靠的 Outcome Truth 为前提。自然顺序：**3.4 Outcome Lifecycle → 3.5 Execution Orchestration / Policy**，不可倒置

---

## 2. 安全边界冻结（铁律）

### 2.1 继承（不可退让）

- v1.1.0 / v1.2.0 / v1.3.0 的任何已提交代码语义
- 四条核心安全边界：No automatic approval / No automatic retry / No adapter fan-out / No hidden execution
- D1–D14（Phase 3.1）+ E1–E5（Phase 3.2）+ 3.3 全部裁决
- `execution_log` 现有 8 个状态语义、`EXECUTABLE_ACTIONS` 四词、`NON_COMPENSATABLE_ACTIONS` 冻结集
- 密钥边界（`.env → Settings → AdapterCredentials → Authorization header`，日志脱敏）
- Single-Active-Adapter 不变式；Append-only 审计模型
- 固定口径：Observed Health ≠ Live Health Probe；四种 Adapter 已实现 ≠ 默认连接真实外部系统；治理定性不被改写

### 2.2 Phase 3.4 冻结条款（D3.4-01 ～ D3.4-08）

| 编号 | 条款 |
|---|---|
| **D3.4-01** | Outcome fact ≠ execution intent（效果事实永远不是执行意图） |
| **D3.4-02** | Webhook 只写 Outcome fact，不触发 execution / retry / compensate |
| **D3.4-03** | Manual reconcile 可以读外部状态，但不能自动 retry（必须由操作者显式触发） |
| **D3.4-04** | Dispatch outcome ≠ External effect outcome（两层语义永不合并） |
| **D3.4-05** | 旧 `execution_log` 历史语义不改变（`succeeded` / `failed` 永远是 Dispatch Outcome） |
| **D3.4-06** | Outcome 层 append-only（只追加，不 UPDATE / DELETE） |
| **D3.4-07** | External callback credential ≠ Operator credential（两个信任域） |
| **D3.4-08** | Mock 默认继续完全离线（默认套件零外部请求不变） |
| **D3.4-09** | Outcome fact 永不改写 Dispatch fact（O5）：`dispatch=succeeded + outcome=confirmed_failure` 是合法状态（命令成功送达但效果未达成）；`dispatch=failed` **不自动**产生 `confirmed_success`，但人工 reconcile 得到的外部事实**允许**记录为 `confirmed_success`（网络断裂 / 响应丢失可能使两层不一致）—— Outcome 层只记录事实，不替 Dispatch 改写历史 |

---

## 3. 两层事实语义（整个 3.4 的设计地基）

```
Dispatch Outcome（v1.3.0 既有，语义冻结）
    平台请求 → Adapter → 外部系统同步响应 → succeeded / failed

External Effect Outcome（3.4 新增层）
    accepted / dispatched  ≠  effect achieved
```

**禁止**把现有 `succeeded` / `failed` 重新解释为"效果成功 / 失败"（D3.4-05）——那会破坏全部历史语义与 3.3 Metrics 的派生基座。

### 三层事实模型（项目审计模型的最终形态）

```
Layer 1 — Decision     Approval / Policy           "为什么允许做"
            ↓
Layer 2 — Dispatch     ExecutionLog                "我们到底发出了什么"
            ↓
Layer 3 — Outcome      External Outcome Facts      "外面最终发生了什么"
```

---

## 4. Outcome Fact Layer（独立事实层）

**裁决（用户）**：Outcome 成为**独立的 append-only fact layer**，**不**扩展 `execution_log.decision`。

理由：`execution_log` 描述"执行请求发生了什么"（平台视角），Outcome 描述"外部世界后来发生了什么"（外部视角）。两种事实来源不同，混入同一套 `decision` 会让状态机退化为毛线团（`requested / dispatched / succeeded / failed / pending / reconciled / …`）。

冻结约束：

- Outcome 事实通过 `execution_id` 只读关联执行链，**绝不回写** `execution_log`
- 同一执行允许多条 outcome 事实（时序追加，D3.4-06）；**派生态** = 最新有效事实（能派生就不改核心状态 —— 3.3 原则延续）
- 治理拒绝链（`guard_rejected`）与补偿链不产生 outcome 语义（无外部效果可言）

**冻结词表（O1 裁决 ✅ 2026-09-03）**：

```
unknown → pending → confirmed_success / confirmed_failure / reconciliation_failed
```

边界定义（O1 裁决）：

- `reconciliation_failed` = **对账动作本身失败**（读不到外部状态，事实来源是对账过程）
- `confirmed_failure` = **确认外部效果失败**（事实来源是外部世界）
- 两者事实来源不同，永不合并

**两层共存合法性（O5 / D3.4-09）**：

| Dispatch | Outcome | 语义 |
|---|---|---|
| `succeeded` | `confirmed_failure` | ✅ 合法：命令送达但效果未达成 |
| `failed` | `confirmed_success` | ⚠ 异常/不一致场景：不允许**自动**产生；人工 reconcile 得到外部事实时**允许**如实记录（Outcome 层负责记录事实，不负责改写 Dispatch 历史） |

---

## 5. Webhook / Callback 入站（事实入口，不是执行入口）

```
External System → Webhook → Authenticate → Validate → Normalize → Outcome Fact → Audit
```

绝对禁止（D3.4-01 / D3.4-02）：

```
Webhook → Execute        ✗
Webhook → Retry          ✗
Webhook → Compensate     ✗
```

**Inbound callback 只产生事实，不产生意图。** 这是对四条安全边界（No automatic retry / No hidden execution）的直接继承。

入站验证闸（沿用 3.3.2 Policy 先例）：

- 身份闸：适配器回调凭据认证失败 → 拒绝（不落 outcome 事实，仅安全审计记录）
- Schema 闸：必须携带可映射到已存在 `execution_id` 的关联键；未知字段拒绝（extra=forbid）
- 归一化闸：外部私有状态 → §4 冻结词表；无法归一化 → 拒绝并审计
- 乱序 / 重放（O2 裁决 ✅ 冻结）：全部追加时序事实（append-only 不删除），派生态取“最新观察时间（`observed_at`）”的有效事实；重放因不产生新事实而无副作用

---

## 6. Reconciliation Contract（Push first, Pull on demand）

**裁决（用户）**：Hybrid，但职责严格区分 —— **不是** "Webhook + 自动轮询"：

```
Webhook / Callback  = 首选实时事实来源（push）
Manual Reconcile    = 兜底 / 主动校验（pull，操作者显式触发）
```

- **不做**后台轮询、定时任务、自动对账循环（D3.4-03；No hidden execution）
- Manual reconcile 是认证操作者（RBAC：executor / admin）显式发起的动作：读外部系统状态 → 归一化 → 写 outcome 事实
- Reconcile 与 Webhook 写同一种 outcome 事实（同一词表、同一审计形状），来源字段区分（`source = webhook | manual_reconcile`）

---

## 7. Long-running 生命周期（不动旧状态机）

**裁决（用户）**：不把 `pending` 塞进 `execution_log` 旧状态机。正确形态是两层正交：

```
Dispatch state:    succeeded        ← 派发事实，语义冻结
External outcome:  pending          ← 效果事实，独立层
        ↓ （Webhook / Manual Reconcile）
External outcome:  confirmed_success / confirmed_failure
```

推论：

- 3.3 Metrics 的 `success_rate` 等指标**保持派发口径不变**（历史语义与报表连续性）
- Observed Health 口径不变（终局链窗口 = 派发口径）；效果维度是**新增派生视图**，不替换现有视图
- 固定口径延续：Observed Health ≠ Live Health Probe（对账是事实记录，不是探测）

---

## 8. 入站认证（独立信任域）

**裁决（用户）**：直接否决复用既有凭据体系：

```
Webhook → EXECUTION_TOKEN      ✗
Webhook → OPERATORS_JSON       ✗
```

两个信任域永不合并（D3.4-07）：

```
Human            → Operator credential（人 → 平台）
External adapter → Adapter callback credential（外部系统 → 平台）
```

后续可由统一的 `AdapterCredentials` 结构管理（与出站凭据并列），但身份语义、配置项、校验路径必须分离。凭据空配置 = 该适配器入站通道关闭（fail-closed，与 3.2 出站凭据同规则）。

**凭据形状（O3 裁决 ✅ 冻结）**：第一版静态 secret（`<ADAPTER>_CALLBACK_TOKEN`，与 3.2 出站凭据同风格：env 平铺、fail-closed、日志脱敏）；HMAC 签名留 v2。

---

## 9. Metrics / Health 演进

- 派发口径指标（3.3 现状）：**冻结，一字不改**
- 效果口径指标（O4 裁决 ✅ 冻结为最小集）：确认率 + confirmed_success / confirmed_failure 分布 + 未确认执行积压数；零写路径，纯派生
- 前端 Observability 页**扩展**（新增效果区块），不重写既有区块；字段级镜像 API 响应的原则不变

---

## 10. 实施拆步（冻结顺序）

用户裁决的关键顺序：**生命周期语义必须先稳定，传输机制围绕它设计** —— Outcome Model → Reconciliation Contract → Inbound Webhook → Long-running，**绝不先写异步执行**。

**实施门槛（用户裁决 2026-09-03）**：3.4.1–3.4.3 全部完成前，不得提前写 Webhook（3.4.4），也不得提前把执行服务改成长任务（3.4.6）。Outcome 数据模型、派生规则、Reconciliation Contract 未冻结落地前，后续子步一律不开工。

| 子步 | 内容 | 依赖 |
|---|---|---|
| **3.4.1** | Outcome Fact Model（模型 / 迁移 / 词表落地） | 无（基座；O1/O5 已裁决） |
| **3.4.2** | Outcome Derivation / State（派生态 + 只读 API） | 3.4.1 |
| **3.4.3** | Reconciliation Contract（归一化 + 来源区分） | 3.4.1 |
| **3.4.4** | Webhook / Callback Inbound（凭据 + 验证闸 + 审计） | 3.4.3（O2/O3 已裁决） |
| **3.4.5** | Manual Reconcile（操作者显式触发 + RBAC） | 3.4.3 |
| **3.4.6** | Long-running Execution（生命周期正交化 + Mock 确定性模拟） | 3.4.2 + 3.4.4 |
| **3.4.7** | Outcome Metrics（效果派生视图 + UI 扩展） | 3.4.2（O4 已裁决） |
| **3.4.8** | Cross-layer Regression | 3.4.1–3.4.7 |
| **3.4.9** | Browser E2E | 3.4.8 |
| **3.4.10** | Final Regression | 3.4.9 |
| **3.4.11** | Atomic Release（v1.4.0） | 3.4.10 |

---

## 11. 裁决记录（2026-09-03，全部落定）

| 编号 | 议题 | 裁决结果 |
|---|---|---|
| **O1** | Outcome 五词词表 | ✅ 原样冻结；`reconciliation_failed` = 对账动作本身失败（读不到外部状态），`confirmed_failure` = 确认外部效果失败，两者事实来源不同（§4） |
| **O2** | 乱序 / 重放 | ✅ 冻结：全部追加（append-only），派生态取“最新观察时间”的有效事实；重放无副作用（§5） |
| **O3** | 回调凭据形状 | ✅ 冻结：第一版静态 secret `<ADAPTER>_CALLBACK_TOKEN`（与 3.2 出站凭据同风格）；HMAC 留 v2（§8） |
| **O4** | 效果指标范围 | ✅ 冻结最小集：确认率 + confirmed 分布 + 未确认积压数；零写路径（§9） |
| **O5** | Outcome 不改写 Dispatch 历史 | ✅ 写入冻结条款 D3.4-09：`succeeded + confirmed_failure` 合法；`failed` 不自动产生 `confirmed_success`，但人工 reconcile 得到的外部事实允许如实记录（§2.2 / §4） |

另：Dispatch ≠ Outcome（D3.4-04）与既有 `execution_log` + 新 Outcome Fact Layer 的分层结构（§3/§4）继续冻结不变。

---

## 12. 测试策略（冻结）

- 每步全量回归，测试数字单调递增；默认套件零外部请求（`-m external` opt-in 不变，D3.4-08）
- Mock 适配器提供**确定性效果模拟**（延迟确认 / 确认失败可编程），离线验证全生命周期
- Webhook 路径：认证失败 / Schema 违规 / 未知字段 / 乱序事实 —— 四类拒绝路径全覆盖
- 不变量专项：`execution_log` 历史语义字节级不变（3.3 基线快照对比）；Metrics 派发口径数值不变
- Cross-layer：Approve → Execute → Dispatch → Outcome（webhook + manual）→ 派生视图全链
- Browser E2E：效果事实在 Observability / Audit 视图的只读呈现（零写流量原则延续）

---

## 13. 版本演进图谱（更新）

```
Phase 1        Core SOC                          v1.0.0-phase1
  ↓
Phase 2        AI + Approval                     v1.1.0 → 0f6e3fc
  ↓
Phase 3.1+3.2  Controlled Execution + Adapters   v1.2.0 → 2be74f8
  ↓
Phase 3.3      Governance + Observability        v1.3.0 → 48fbe41（已发布）
  ↓
Phase 3.4      Execution Outcome Lifecycle       ← 本轮（v1.4.0 ?）
  ↓
Phase 3.5      Execution Orchestration / Policy  （依赖 3.4 的 Outcome Truth）
  ↓
v2.0           Identity infra / Advanced reporting / HMAC 回调
```
