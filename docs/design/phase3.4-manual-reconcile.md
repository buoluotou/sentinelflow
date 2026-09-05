# Phase 3.4.5-A 设计：Manual Reconcile 平台侧契约 + Adapter Read Contract

> 状态：**设计冻结（Design Freeze）**（2026-09-05 用户裁决 Implementation Audit=PASS 后冻结 3.4.5-A；本文档冻结后不得再改契约语义，只允许按 §17 拆步实施）
> 范围：Phase 3.4.5-A —— 只冻结 **Manual Reconcile 平台侧 Contract + Architecture**（数据流 / 身份 / 关联 / external_reference 提取 / Adapter Read Contract / 读失败语义 / append 语义 / observed_at / reconciliation_failed 派生 / RBAC / 凭据隔离 / Mock / 读写隔离 / B-C-D 证据门 / Migration / 测试要求）
> **不实现**：Shuffle read / Wazuh read / TheHive read —— 三家外部 read API 仍属 Evidence Gap（§16），分别留 3.4.5-B / C / D。
> 基线：3.4.4-F（commit `fb56bf3`，Phase 3.4.4 Webhook Inbound 全链封板完成）；3.4.3-B（commit `8b89fe7`，词表冻结）；`v1.3.0`（commit `48fbe41`，tag 冻结）
> 前置：`phase3.4-execution-outcome-lifecycle.md`（D3.4-01~09 + O1/O3/O5 全部有效）+ `phase3.4-reconciliation-contract.md`（§7 读失败语义 / §9 external_reference / RC-05~RC-10 全部有效）
> 日期：2026-09-05
> 命名：遵现有目录规范 `phase3.4-*`。3.4.5 是 **Phase 3.4（Execution Outcome Lifecycle）的子步骤**，不是新的 Phase 3.5；与 `phase3.4-reconciliation-contract.md`（标题为"Phase 3.4.3 设计"）保持一致。
> **性质：DESIGN ONLY。本文档不实现任何代码。** 不新增 `read/base.py`、`read/shuffle.py`、`read/wazuh.py`、`read/thehive.py`、`reconcile.py`、schema、API、tests 实现。落地拆步见 §17。

---

## 0. 冻结摘要（TL;DR）

3.4.5 是 Phase 3.4 中**第一次允许 SentinelFlow 主动向外部系统读取状态**的阶段。本轮（A）只冻结**平台侧管线与读契约**，把"操作者显式触发 → 关联历史执行 → 提取 adapter 身份与 external_reference → 经统一 Read Contract 读取外部状态 / 或遭遇读失败 → 复用 3.4.3-B 归一化 → append Outcome Fact → 3.4.2 派生"这条链定义清楚；**三家 adapter 的具体 read 实现因证据缺口全部延后**（B/C/D）。

**冻结的数据流（§2 完整）：**

```
Authenticated Human Operator
        ↓
Manual Reconcile（显式 Pull，非 Execution）
        ↓
Execution Correlation（复用 3.4.4-C correlate_execution）
        ↓
Extract Adapter（detail["executor"]）+ External Reference（detail[...]）
        ↓
AdapterReadContract（纯 read 抽象；禁 execute/compensate/dispatch/trigger）
        ↓
External State（合法）/ Read Failure（transport 级）
        ↓
Mapping（复用 3.4.3-B normalize_external_state，绝不建第二套）
        ↓
Outcome Fact（source=manual_reconcile，append-only）
        ↓
Derivation（复用 3.4.2，observed_at DESC / id DESC，不改）
```

**五条灵魂铁律（任何实现不得违反）：**

1. **Manual Reconcile ≠ Execution**（§3）：只能 GET/query 外部状态，绝不 Execute/Retry/Compensate/Approve/Fan-out/Background-Poll。
2. **Operator 信任域 ≠ Adapter 信任域 ≠ Callback 信任域**（§4/§9/§13）：三者凭据完全分离；callback token 与 adapter callback 身份**不可**用于 Manual Reconcile。
3. **`reconciliation_failed` ≠ `confirmed_failure`**（§7/§10/§11）：前者=最近一次合法对账**拿不到可靠 external state**（事实来源=对账过程）；后者=外部**真实返回** terminal failure（事实来源=外部世界）。transport 失败（timeout/连接拒绝/DNS/5xx/adapter 不可达）**只能** → `reconciliation_failed`，**绝不** → `confirmed_failure`。
4. **`rejected`（不落 fact）≠ 任何 outcome 词**（§6/§7）：operator 鉴权失败 / correlation 失败 / missing external_reference / unsupported external state / mock / 无 read adapter → **rejected，不请求外部、不落 fact，仅审计**。
5. **append-only + 派生不改**（§10/§13/§14）：`reconciliation_failed` 可成为**当前 derived state**，但**永远不被解释为"外部效果失败"**；历史 `confirmed_success` 完整保留、不可修改、可审计。**不重新打开已封板的 3.4.2。**

---

## 1. Scope（范围）

3.4.5-A 冻结 **Manual Reconcile 的平台侧契约与架构**，回答：

1. **入口语义**：Manual Reconcile 是什么、不是什么（§3）。
2. **身份**：谁能触发、用哪个信任域（§4/§9/§12/§13）。
3. **关联**：如何定位历史执行链、关联证明什么（§5）。
4. **external_reference 提取**：从哪读、按哪个键路由 adapter、缺失怎么办（§6）。
5. **Read Contract**：统一读抽象的输入/输出形状、被禁止的动词（§7）。
6. **读写隔离**：Read adapter 与 Write adapter 的物理职责边界（§8/§15）。
7. **失败语义**：`reconciliation_failed` / `confirmed_failure` / `pending` / `unknown` / `rejected` 的严格边界（§7/§10/§11）。
8. **事实与时间戳**：append 语义（§8/§14）、observed_at（§9/§12）、reconciliation_failed 派生（§10/§13）。
9. **边界与门禁**：Mock 行为（§14/§15）、B/C/D 证据门（§16）、Migration（§17/§19）、测试要求（§18）。

**冻结产物**：本设计文档 + 设计验收（§19 的 15 条）。**不含任何代码实现**（§20）。

---

## 2. Non-goals（非目标 — 本轮明确不做）

- ❌ **不实现 Shuffle / Wazuh / TheHive 的任何 read endpoint 客户端**（§16 Evidence Gap，留 B/C/D）。
- ❌ **不在设计中写"未来使用某某 endpoint"**，除非已有可信证据；只能写"待外部证据确定"（§16）。
- ❌ **不把 read() 加到 `ResponseExecutor`**；**不把 execute()/compensate() 加到 Read Contract**（§8）。
- ❌ **不重新实现 correlation**（复用 3.4.4-C）、**不建第二套 state mapping**（复用 3.4.3-B）、**不新增第二套 derivation**（复用 3.4.2）（§5/§7-Mapping/§13）。
- ❌ **不修改 `execution_log` schema**；**不修改 3.4.2 derivation**；**不修改 8b89fe7 词表**（§6/§13）。
- ❌ **不做 background polling / scheduled / automatic / callback-triggered reconciliation**（§3）。
- ❌ **不为 Mock 创建 read adapter，不创建 mock external outcome**（§14/§15）。
- ❌ **不新增 DB migration / 0011**（§17/§19）。
- ❌ **不创建新 RBAC role**（§12）。
- ❌ **本轮不创建任何 .py / schema / API / tests 实现**（§20）。

---

## 3. Trust Domains（三信任域 — 继承 3.4.4-A，RC-07 永不合并）

| 信任域 | 凭据来源（server config） | 用途 | 可否用于 Manual Reconcile |
|---|---|---|---|
| **Human Operator** | `EXECUTION_TOKEN`（legacy）/ `OPERATORS_JSON`（`{token:name:role}`） | "谁有权触发 Reconcile"（§9/§12） | ✅ **唯一允许的触发身份** |
| **Outbound Adapter API** | `SHUFFLE_API_KEY` / `WAZUH_API_USER`+`WAZUH_API_PASSWORD` / `THEHIVE_API_KEY` | "SentinelFlow 是否能读取外部系统"（§9/§13） | ✅ 由 server 用于 read 调用；**绝不由 client 提供** |
| **Inbound Adapter Callback** | `SHUFFLE_CALLBACK_TOKEN` / `WAZUH_CALLBACK_TOKEN` / `THEHIVE_CALLBACK_TOKEN` | 3.4.4 Webhook 入站认证 | ❌ **绝对不可**用于 Manual Reconcile |

**铁律（RC-07）**：三域凭据结构性隔离、永不合并、永不互换。Manual Reconcile 同时使用前两域（Operator 决定"谁能读"，Adapter credential 决定"能不能读到外部"），但**两者职责完全分离**（§9）；**第三域（callback）与本阶段无关，明确禁用**。

---

## 4. Manual Reconcile API Contract（入口契约）

> 路径与响应在本 Design Freeze 冻结（原 3.4.5 §20/§21 授权本轮决定）。具体响应字段名可在实现期最终确定，但**语义、状态码类别、信任域、append/reject 边界在此冻结**。

### 4.1 端点

- **`POST /api/v1/executions/{execution_id}/reconcile`**
  - 语义：对一个**已存在的执行链**发起一次**显式、操作者触发**的对账读取。
  - 与现有 `/executions` 家族一致；`{execution_id}` 为 chain key（UUID）。
  - **幂等**：允许重复调用；每次都是一次新的 observation（§8/§14），**不用 unique/UPSERT 实现幂等**（原 3.4.5 §22）。
  - **一次调用最多一次 external read attempt**；系统**不自动 retry**（原 3.4.5 §23）。

### 4.2 认证 / 授权

- 复用 `authenticate_operator(authorization: Header) -> Operator`（`response_execution.py`，已内建 `can_execute` 403）。
- 允许：`executor` / `admin`（§12）。拒绝：`viewer` / `reviewer` → 403。缺失/畸形/错误/未配置 token → 401。
- **不接受 callback token**（§3/§4）。

### 4.3 结果类别 → HTTP 语义（冻结）

| 情形 | 是否落 fact | HTTP（建议） | 说明 |
|---|---|---|---|
| 合法 external state（成功/失败/pending/unknown） | ✅ append | `200` | `outcome_status` ∈ 4 可映射词 + derived state |
| 合法 reconcile context 已建立后 transport 失败 | ✅ append `reconciliation_failed` | `200` | 读到了"读不到"这一事实（§7/§10） |
| operator 鉴权失败 | ❌ | `401` | rejected（§7） |
| viewer/reviewer | ❌ | `403` | rejected（§12） |
| execution correlation 失败（链不存在） | ❌ | `404` | rejected；与现有 `GET /executions/{id}` 一致（§5/§7） |
| missing `external_reference` | ❌ | `422` | rejected；`MissingExternalReference`（§6/§7，RC-05） |
| unsupported external state（词表外） | ❌ | `422` | rejected；`UnrecognizedExternalState`（§7，3.4.3-B） |
| mock execution / 无 read adapter | ❌ | `422` | rejected；`UnsupportedAdapterRead`（§14/§15/§16） |

**冻结要点**：只有前两类落 fact（`source=manual_reconcile`）；其余全部 **rejected，不请求外部、不落 fact、仅审计**（§6/§7）。

### 4.4 响应 envelope（语义冻结，字段名实现期定）

成功（落 fact）至少表达：`execution_id`、`adapter`、是否 append、`outcome_status`（本 observation）、`observed_at`、`source="manual_reconcile"`、`derived_outcome_status`（3.4.2 派生）、以及 `observed_at_kind`（external / server-observation，§9/§12）。rejected 至少表达：`rejected=true` + `reason`（枚举：auth/correlation/missing_reference/unsupported_state/unsupported_adapter_read），**绝不泄露凭据/内部异常细节**（§13）。

---

## 5. Correlation（关联 — 复用 3.4.4-C，不重实现）

- **复用** `correlate_execution(session, execution_id) -> CorrelatedExecution(execution_id, row_count)`（`services/outcomes/correlation.py`）。
- 0 行 → `UnmappableExecutionId`（`ContractValidationFailure`）→ **rejected，不落 fact**（§4.3 的 404）。
- **关联成功只证明：execution chain exists**（存在 `requested→…→succeeded/failed` 审计链）。
- **关联成功绝不证明：external effect success**（原 3.4.5 §5）。Dispatch ≠ External Outcome（O5/D3.4-04）。
- **补充只读提取**：`CorrelatedExecution` 不暴露 `detail`；external_reference 与 adapter 身份的提取是**对 `execution_log` 的额外只读 SELECT**（§6），**不修改 `execution_log`，不重新实现 correlation**。

---

## 6. External Reference 提取（从历史 Dispatch Fact 只读提取）

**不修改 `execution_log` schema**（原 3.4.5 §6/§18）。从历史 Dispatch Fact 的 `detail`（JSONVariant）只读提取：

### 6.1 Adapter 身份（统一键）

- **`detail["executor"]`** —— 由 `service._intent_detail()` 写在**每条 `requested`/`dispatched` 行**，四家 adapter（mock/shuffle/wazuh/thehive）一致。这是**唯一的统一 adapter 身份键**（`execution_log` 无 adapter 专列）。
- 读取路径据此**路由到对应 adapter 的 read client**（B/C/D）。

### 6.2 external_reference（三家键名不同 — 冻结）

| adapter | external_reference 键 | 写入条件（现状，来自审计） |
|---|---|---|
| **Shuffle** | `detail["external_execution_id"]` | **可选**（trigger 响应体可能不含 id；`_EXTERNAL_ID_KEYS`） |
| **Wazuh** | `detail["command_id"]` | **条件**（`if command_id:`，响应体可能不含） |
| **TheHive** | `detail["case_id"]` | **强制**（缺失即 `ExecutorOutcomeViolation`） |

### 6.3 缺失语义（RC-05，冻结）

- 若目标执行链**没有可用的 external_reference**：
  - → `MissingExternalReference`（`ContractValidationFailure`）
  - → **rejected**（§4.3 的 422）
  - → **不请求外部系统**
  - → **不生成任何 Outcome Fact**
- **明令禁止**：`missing external_reference → reconciliation_failed`（RC-05）。reconcile 动作**根本没资格运行**，谈不上"对账失败"。

---

## 7. 统一 Adapter Read Contract（纯 read 抽象 — 冻结）

冻结一个**纯 read 抽象**，表达"读取外部状态"，**且仅此**。

### 7.1 AdapterReadRequest（输入，至少表达）

- `execution_id`（chain key）
- `adapter`（来自 `detail["executor"]`，§6.1）
- `external_reference`（来自 §6.2）
- （可选）未来只读上下文：如 `action` / `target`（仅用于只读查询定位，**绝不用于触发任何外部副作用**）

### 7.2 AdapterReadResult（输出，至少表达）

- `external_state`（外部系统返回的、待归一化的状态值）
- `observed_at`（外部可靠 state timestamp，或缺失标记 → 由平台补 server observation time，§9/§12）
- `raw_evidence`（只读证据快照，**经 `redact_detail` 脱敏后**方可入 detail，§13）

> 具体字段名可在最终实现确定；**形状与"只读"性质在此冻结**。

### 7.3 被禁止的动词（结构性 — §8 AST 证明）

Read Contract **绝不拥有**：`execute` / `compensate` / `dispatch` / `trigger` / `create_case` / `send_command`（原 3.4.5 §7/§24）。Read Contract 只能 `read`/`query`/`get`。

### 7.4 与 3.4.3-B 的关系（Mapping，复用不重建）

- `AdapterReadResult.external_state` → **复用** `normalize_external_state`（`services/outcomes/reconciliation.py`，8b89fe7 冻结）→ 五词之一（`MAPPABLE_OUTCOME_STATUSES`，即排除 `reconciliation_failed` 的 4 词）。
- **绝不建第二套 mapping，绝不偷改 8b89fe7**（原 3.4.5 §10）。
- 词表扩展（Wazuh failure 侧 / Shuffle / TheHive）**必须先有 read-path 证据**，属 B/C/D（§16），**A 不猜、不填**。

---

## 8. Read / Write 物理隔离（§8 + 原 3.4.5 §24 — 结构性证明）

| 维度 | Write 侧（已封板，3.2/3.4.4） | Read 侧（3.4.5-A 冻结，B/C/D 实现） |
|---|---|---|
| 抽象 | `ResponseExecutor`（`services/executions/base.py`） | `AdapterReadContract`（新，read 侧包） |
| 动词 | `execute` / `compensate` | `read` / `query`（**仅此**） |
| 出站 | WRITE POST（Shuffle execute / Wazuh active-response / TheHive create case） | **只能 GET / query** |
| 信任域 | Outbound Adapter API（write） | Outbound Adapter API（read，同凭据不同动作） |

**冻结铁律：**

- **不把 `read()` 加到 `ResponseExecutor`**（Write 抽象保持不变）。
- **不把 `execute()`/`compensate()` 加到 `AdapterReadContract`**（Read 抽象纯读）。
- **物理包隔离（建议）**：Write 侧在 `app/services/executions/`；Read 侧在新包 `app/services/manual_reconcile/`（与 `services/outcomes/reconciliation.py` 的"状态映射契约"明确区分：后者是归一化契约层，前者是读管线 + read adapter）。
- **AST 测试证明**（§18）：read 侧包**不定义/不导入** execute/compensate/dispatch/trigger；`ResponseExecutor` **不定义** read/query。读写隔离是**结构性**的，不靠约定。

---

## 9. Credential Isolation（凭据隔离 — §9/§13/§14 冻结）

- **Operator token**：决定"**谁有权进行 Reconcile**"（Human Operator 信任域，§3/§4/§12）。
- **Adapter credential**：决定"**SentinelFlow 是否能读取外部系统**"（Outbound Adapter API 信任域，§3）。
- **两者完全分离**：Operator token **绝不**用于访问外部系统；Adapter credential **绝不**作为触发权限。

**Adapter API credential 铁律：**

- ✅ 来自 **server config**（`credentials_from_settings(adapter)` → `AdapterCredentials`，复用 3.2.2 `secrets.py`）。
- ❌ **绝对禁止 client 提供 API key**（请求体/header/query 中的任何 adapter 凭据一律忽略并视为非法）。
- ❌ **绝对禁止写入 Outcome `detail`**（经 `redact_detail` 单点脱敏；`current_secret_values()` 覆盖 `*_API_KEY`/`WAZUH_API_PASSWORD`/`EXECUTION_TOKEN`）。
- ❌ **绝对禁止日志 / response 泄露**（`SecretRedactionFilter` + `AdapterCredentials.__repr__/__str__` 掩码 `***`；响应 envelope 不含凭据，§4.4）。

---

## 10. Read Failure 语义 + reconciliation_failed 派生（冻结）

### 10.1 读失败 → outcome 的严格映射（§10/§11）

**前提：合法 reconcile context 已建立**（operator 已认证、correlation 成功、external_reference 存在、read adapter 可用）。在此之后：

| 读失败情形 | outcome_status | 落 fact？ |
|---|---|---|
| timeout | `reconciliation_failed` | ✅ |
| connection refused | `reconciliation_failed` | ✅ |
| DNS failure | `reconciliation_failed` | ✅ |
| HTTP 5xx transport | `reconciliation_failed` | ✅ |
| adapter unavailable（外部系统不可达） | `reconciliation_failed` | ✅ |
| **外部系统真实返回 terminal failure state** | `confirmed_failure` | ✅ |
| 外部真实返回 terminal success | `confirmed_success` | ✅ |
| 外部真实返回仍在处理 | `pending` | ✅ |
| 外部合法状态但语义无法判断 | `unknown` | ✅ |

**在此之前的失败一律 rejected（不落 fact，§4.3/§6/§7）：**

| 情形 | 结果 |
|---|---|
| operator authentication failure | **rejected**（401） |
| execution correlation failure | **rejected**（404） |
| missing external_reference | **rejected**（422，RC-05） |
| unsupported / unrecognized external state | **rejected**（422） |
| mock / 无 read adapter | **rejected**（422，§14/§15/§16） |

### 10.2 confirmed_failure 的严格来源（§11）

- **只有外部系统真实返回的 terminal failure state** 才能 → `confirmed_failure`。
- **绝不能**把 timeout / adapter_error / connection error / HTTP 5xx 直接变成 `confirmed_failure`。
- 依据 O1：`confirmed_failure` 事实来源=**外部世界**；`reconciliation_failed` 事实来源=**对账过程**。两来源永不合并。

### 10.3 reconciliation_failed 与 Derivation（§13 — 用户正式裁决）

- **继续使用 3.4.2**：`derive_outcome_state` = max by（`observed_at DESC`, `id DESC`）。**不修改 3.4.2，不新增第二套 derivation。**
- 因此合法时序：

  ```
  confirmed_success（历史，外部真实成功）
        ↓
  later manual reconcile timeout（合法 context 后 transport 失败）
        ↓
  append reconciliation_failed（server observation time，较新）
        ↓
  current derived state = reconciliation_failed
  ```

- **用户裁决（冻结）**：`reconciliation_failed` **可以成为当前 derived state**，但**永远不能被解释成"外部效果失败"**；历史 `confirmed_success` **不受影响、完整保留、不可修改、可审计**。**这样不用重新打开已封板的 3.4.2。**
- **必须明确记录**：`reconciliation_failed` = "**最近一次合法 Reconciliation 无法取得可靠 external state**"，**不是** "external effect failed"。
- 派生层**无需**为 `reconciliation_failed` 增加特殊处理：它就是一个合法的、可由"最新胜"派生出的当前状态；其语义边界由**词表定义 + O1 + 本节**保证，而非由派生逻辑保证。

---

## 11. O5（Dispatch ≠ External Outcome — 继承，冻结）

- Dispatch（`execution_log`，8 词）与 External Outcome（`execution_outcome`，5 词）**永不互相改写**（D3.4-04/O5）。
- `dispatch=succeeded` + `outcome=confirmed_failure` **合法**（外部接受了请求但效果未达成）。
- `dispatch=failed` **不自动** `confirmed_success`；但**人工 reconcile 可如实记录**外部真实状态（O5 注释）。
- Manual Reconcile **只读 `execution_log`、只写 `execution_outcome`**（§14/§18-原 3.4.5 §18）：绝不 UPDATE/改写 `execution_log`。

---

## 12. RBAC（§12/§19 — 复用，不新建 role）

- 复用 `OperatorRole.can_execute = {EXECUTOR, ADMIN}`（`services/executions/operators.py`）。
- **允许**：`executor` / `admin`。**拒绝**：`viewer`（及 `reviewer`）→ 403。
- **不创建新 RBAC role**（原 3.4.5 §19）。Manual Reconcile 复用执行权限语义：能执行响应者即能对其发起对账读取。
- 鉴权入口复用 `authenticate_operator`（§4.2），**不新写一套鉴权**。

---

## 13. Credential / Secret 边界（§9/§13 — 复用 3.2.2，冻结）

- 复用 `AdapterCredentials`（frozen，`__repr__/__str__` 掩码）、`credentials_from_settings(adapter)`、`auth_headers()`（Bearer/Basic）、`redact_detail`、`redact_text`、`SecretRedactionFilter`、`validate_base_url`（拒 query/fragment/userinfo）。
- read 出站请求的 URL 经 `validate_base_url`；凭据经 `auth_headers()` 注入 header，**绝不入 URL/query/body/detail/log/response**。
- `raw_evidence`（§7.2）入 `detail` 前**必须经 `redact_detail`**（与 write 侧 `_append` 单点脱敏一致）。

---

## 14. Mock 行为（§15 — 冻结）

- Mock **没有真实 external system**。
- Manual Reconcile 对**历史 mock execution**（`detail["executor"] == "mock"`）：**必须明确为 Unsupported / Rejected**（§4.3 的 422，`UnsupportedAdapterRead`），**不落 fact**。
- **不能创建 MOCK read adapter**；**不能创建 mock external outcome**。
- 与 `ADAPTER_STATE_VOCABULARIES["mock"]`（四集全空，PERMANENT，offline，never receives facts）一致：mock 永远不产出外部事实。

---

## 15. Read/Write Adapter 分离（§8 的 adapter 级细化 — 冻结）

- 每个真实 adapter 的 **read client（B/C/D）与现有 write executor 物理分离**：write 在 `services/executions/{shuffle,wazuh,thehive}.py`（`ResponseExecutor` 子类）；read 在 `services/manual_reconcile/read/{shuffle,wazuh,thehive}.py`（`AdapterReadContract` 实现）。
- **ReadAdapterRegistry**（与 write 的 `create_executor` 平行）按 `detail["executor"]` 解析对应 read client。
- **3.4.5-A 冻结时，ReadAdapterRegistry 无任何生产 concrete read adapter**（B/C/D blocked，§16）。因此 A 的生产运行时：
  - 对 shuffle/wazuh/thehive 的 reconcile → **无 read adapter 注册 → rejected（`UnsupportedAdapterRead`，422），不落 fact**（**不是** `reconciliation_failed`，因为根本未发生读尝试）。
  - 对 mock → rejected（§14）。
- **A 的管线与 `reconciliation_failed` 语义通过注入的 test-only fake read adapter 完整验证**（§18），与 3.4.4-E 用 `FakeWebhookMapper` 验证持久化缝的做法一致；**生产可达性随 B/C/D 落地**。
- 这是 fail-closed、证据门控的诚实行为：A **不伪造**任何外部读取结果。

---

## 16. B/C/D 证据门（§16 — 冻结 Evidence Gap）

**Design Freeze 明确记录（不臆造 endpoint）：**

| 子步骤 | adapter | Read endpoint | 状态 |
|---|---|---|---|
| **3.4.5-B** | Wazuh | **Evidence Gap** | blocked by evidence（成功侧 `agent_status` 词表来自 write 响应体，**非 read/poll endpoint**；read endpoint + failure 侧词表待外部证据） |
| **3.4.5-C** | Shuffle | **Evidence Gap** | blocked by evidence（workflow terminal state 无可靠 read path；`external_execution_id` 可选） |
| **3.4.5-D** | TheHive | **Evidence Gap** | blocked by evidence（case lifecycle state 无可靠 read path；`case_id` 强制但仅是 REFERENCE 非 STATE） |

**铁律（原 3.4.5 §16 + 最高纪律）**：

- **不要在设计里写"未来使用某某 endpoint"**，除非已有可信证据。
- 只能描述：**待外部证据确定**。
- **宁可报"官方 API / 当前代码证据不足"，也绝不按字段名猜状态。**
- 词表填充（`ADAPTER_STATE_VOCABULARIES` 的 shuffle/thehive 全空、wazuh failure 侧空）**必须先有 read-path 证据**，属 B/C/D；**A 不填、不猜**。空集是 DELIBERATE DOCUMENTED GAP。

---

## 17. Migration + 子步骤拆步（§17/§19 — 冻结）

### 17.1 Migration：**NO**

- **0010 已支持**：`manual_reconcile` source（`OUTCOME_SOURCES` + `ck_execution_outcome_source`）、`reconciliation_failed` status（`OUTCOME_STATUSES` + `ck_execution_outcome_status`）。
- `ix_execution_outcome_execution_id_observed_at`（non-unique）已存在，支持 append-only 重复 observation。
- **无需 0011**。**不改 `execution_log` schema**（§6）。

### 17.2 3.4.5 子步骤（冻结）

| 子步骤 | 内容 | 状态 |
|---|---|---|
| **3.4.5-A** | Read Contract + Manual Reconcile Platform Pipeline（本文档） | ✅ Design Freeze（本轮）；Implementation 待放行 |
| **3.4.5-B** | Wazuh Read Adapter + failure-state evidence | ⛔ blocked by evidence |
| **3.4.5-C** | Shuffle Read Adapter + workflow state evidence | ⛔ blocked by evidence |
| **3.4.5-D** | TheHive Read Adapter + case lifecycle evidence | ⛔ blocked by evidence |

---

## 18. Test Requirements（§18 — 冻结验收测试矩阵；A 实现期落地，本轮不写）

> 本轮**不创建 tests 实现**（§20）。以下为 3.4.5-A Implementation 放行时**必须覆盖**的测试要求。

1. **Manual Reconcile ≠ Execution（§3）**：reconcile 路径**绝不**调用 execute/compensate/dispatch/trigger；AST 断言 read 侧包无这些动词、`ResponseExecutor` 无 read/query（§8/§15）。
2. **身份（§4/§12）**：executor/admin → 允许；viewer/reviewer → 403；缺失/畸形/错误/未配置 token → 401；**callback token → 拒绝**（不可触发 reconcile）。
3. **关联（§5）**：correlation 成功只证明链存在；0 行 → 404 rejected 不落 fact；关联成功**不**产出 confirmed_success。
4. **external_reference（§6）**：三家键名提取正确；缺失 → `MissingExternalReference` → 422 rejected、**不请求外部**、不落 fact（RC-05）。
5. **Read Contract（§7）**：`AdapterReadRequest/Result` 形状；fake read adapter 注入验证管线；**禁动词** AST。
6. **读失败语义（§10）**：timeout/连接拒绝/DNS/5xx/adapter 不可达 →（合法 context 后）`reconciliation_failed` 落 fact；auth/correlation/missing-ref/unsupported-state/mock/无-read-adapter → rejected 不落 fact。
7. **confirmed_failure 来源（§11）**：只有外部真实 terminal failure → `confirmed_failure`；transport 失败**绝不** → `confirmed_failure`。
8. **unknown（§21-7）**：合法但语义不明 external state → `unknown`（复用 3.4.3-B），**绝不**把 unrecognized state 降级为 unknown。
9. **observed_at（§9/§12）**：外部可靠 timestamp 优先；缺失 → server observation time 且 detail 标记为 **fact observation time（非 external event time）**；全部过 `validate_observation()`（含 MAX_FUTURE_SKEW）。
10. **append-only（§14）**：禁 UPDATE/UPSERT/DELETE；重复 reconcile 各产生新 observation；`execution_log` 不被修改（只读）。
11. **reconciliation_failed 派生（§10.3/§13）**：confirmed_success → 后续 reconcile timeout → append reconciliation_failed → derived state = reconciliation_failed；**历史 confirmed_success 完整保留、不可修改**；派生层**无**特殊处理（复用 3.4.2）。
12. **O5（§11）**：dispatch 与 outcome 互不改写；`dispatch=succeeded`+`outcome=confirmed_failure` 合法。
13. **凭据隔离（§9/§13）**：client 提供的 API key 被忽略；凭据不入 detail/log/response；`redact_detail` 生效。
14. **Mock（§14/§15）**：mock execution → rejected（`UnsupportedAdapterRead`）；无 MOCK read adapter；无 mock external outcome。
15. **无 read adapter（§15/§16）**：A 生产运行时对 shuffle/wazuh/thehive reconcile → rejected（非 reconciliation_failed）；生产 registry 空。
16. **Migration（§17）**：断言无新 migration；0010 约束已覆盖 manual_reconcile + reconciliation_failed。
17. **回归**：full backend 全绿；封板层（8b89fe7 / 192f615 / 9119036 / fb56bf3）byte-frozen。

---

## 19. 设计验收条件（§21 — 15 条，本轮 Design Review 逐条确认）

| # | 验收项 | 依据 | 判定 |
|---|---|---|---|
| 1 | Manual Reconcile ≠ Execution | §3/§8/§18-1 | ✅ |
| 2 | Operator ≠ Adapter credential | §3/§9/§13 | ✅ |
| 3 | correlation 只证明 execution existence | §5 | ✅ |
| 4 | external_reference 缺失 → rejected | §6.3（RC-05） | ✅ |
| 5 | transport failure → reconciliation_failed | §10.1 | ✅ |
| 6 | external terminal failure → confirmed_failure | §10.2/§11 | ✅ |
| 7 | unknown legitimate state → unknown | §10.1/§18-8 | ✅ |
| 8 | append-only | §14/§18-10 | ✅ |
| 9 | execution_log immutable | §6/§11/§18-10 | ✅ |
| 10 | derivation 不修改 | §10.3/§13 | ✅ |
| 11 | reconciliation_failed ≠ confirmed_failure | §0-铁律3/§10/§11 | ✅ |
| 12 | Mock 不可 reconcile | §14/§15 | ✅ |
| 13 | Read adapter 与 Write adapter 分离 | §8/§15 | ✅ |
| 14 | B/C/D 明确 Evidence Gap | §16 | ✅ |
| 15 | No migration | §17.1/§19 | ✅ |

**全部 15 条 PASS。** 本轮只产出设计文档 + 设计验收，**无任何代码实现**（§20）。

---

## 20. Design Freeze 禁止提前实现（本轮边界）

本轮**只有**：Design Document（本文件）+ Design Review checks（§19）。

**禁止创建**：`read/base.py`、`read/shuffle.py`、`read/wazuh.py`、`read/thehive.py`、`reconcile.py`、schema、API、tests implementation。

**禁止**：coding / commit 代码 / migration / API implementation。Design Freeze 完成后**停止**，等待放行进入 3.4.5-A Implementation。

---

> 冻结人：用户裁决（2026-09-05，Implementation Audit=PASS → 进入 3.4.5-A Design Freeze）
> 冻结范围：Manual Reconcile 平台侧 Contract + Architecture（不含 B/C/D adapter read 实现）
> 解冻条件：仅当发现与已封板契约（3.4.2 / 3.4.3-B / 3.4.4）冲突，或 B/C/D 外部证据到达需调整 read contract 形状时，经用户裁决方可修订；语义铁律（§0）不得削弱。
