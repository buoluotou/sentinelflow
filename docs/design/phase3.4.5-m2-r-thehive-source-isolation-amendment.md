# Phase 3.4.5-M2-R — TheHive 可信来源隔离 · 最小 Amendment（设计提案）

> 状态：**设计提案（Design Proposal）** —— M2 Final Review（部分通过、完整里程碑未通过）三项 P1 整改中，§2/§3 触及**冻结通用契约**的部分依授权「先 fail-closed，再提交最小 Amendment 供审查」开立。**本轮 DESIGN ONLY**，待用户 Review 后再进入独立的 **Amendment Implementation Gate**（届时才落生产代码）。
> 范围：只重新裁定 **TheHive 合成成功信号 `case_created` 的来源门（§2）** 与 **创建效果第三重证据门的严格关联（§3）**；给出去锚定后的**可信 Reader 来源隔离通道**设计与**不可变派发关联**设计。
> **不实现**：不改 `normalize_external_state` 签名、不改 `map_external_state` 封板、不改 `AdapterReadRequest`/`AdapterReadResult` 冻结 DTO、不改 DB 模型、不接线 router、不建第二张映射表、不加任何可由请求体提交的 `verified` 标志。
> 基线：HEAD `3b23520`（M2 Final Report，**保留、不重写历史**）；`117ab6b`（M2 §5 reader+mapping，**只读历史**）；`0c372aa`（**G1-C Wazuh fail-closed 先例**，保持不变）；`8b89fe7`（3.4.3-B 词表冻结）。
> 前置：M2 Final Review 裁决（G5 Reader = **NEEDS FIX**）+ `phase3.4.5-m2-thehive-lab-evidence-and-deployment-plan.md` §5.2（冻结三重合取门）+ `phase3.4-wazuh-mapping-amendment.md`（B0 先例结构）。
> 日期：2026-09-09
> 命名：遵现有目录规范 `phase3.4.5-m2-r-*`；M2-R 是 M2 之后的**安全整改门**，不是新 Phase。
> **性质：DESIGN ONLY。本文档不实现任何代码**：当前生产态是 §3 描述的 **fail-closed 空词表（已落地的前向修复）**，本设计描述的是**未来 Implementation Gate** 的落地方案。

---

## 0. 冻结摘要（TL;DR）

**M2 Final Review 三项 P1（阻塞接线）与本 Amendment 的关系：**

1. **P1-1 · 合成成功状态进入共享入站词表**：`reconciliation.py` 曾把 `case_created` 直接加入 TheHive 全局成功词表；纯映射 `normalize_external_state(adapter, external_state)` 只有两个参数，**无法区分**该词来自可信 Reader 还是 Webhook 请求体。审查者独立执行归档纯映射实现，确认原始字符串 `case_created` 可直接映射为 `confirmed_success`。
2. **P1-2 · 创建效果第三重证据门被放宽**：设计 §5.2 把缺失 `createdAt` 列为 `case_unverified`，但 M2 实际 Reader 允许 `createdAt` 缺失/非法时继续确认成功，也不核对创建时间与原始派发时间。审查者隔离探针确认：缺 `createdAt` 仍返回 `case_created`；十年前创建、仅带匹配标签的案件也返回 `case_created`。
3. **本 Amendment 只处理 P1-1 / P1-2 中「需要触碰冻结契约」的残余部分**；其余（Reader gate3 强制、版本/凭据门、HTTP 无重定向、测试严格化）已在 M2-R §3/§4/§5 的**前向修复提交**中落地，不在本设计范围。

**核心结论（本设计最重要的一句话）：**

> **冻结的 2 参数 path-agnostic 映射契约 + 封板的单委托 `map_external_state`，在结构上无法表达「来源隔离」。** 任何在共享词表内区分「可信 Reader vs 外部 JSON」的尝试，都必然违反以下至少一道封板：给 `normalize_external_state` 加 source 参数（违反冻结签名）、在 `map_external_state` 加 `if` 分支（违反 `test_mapping.py` 单委托封板）、加调用者可控 `verified=true`（审查者明确否决）、或建第二张映射表（违反 G1-C「NO second mapping table」）。

**因此本轮采取的动作（已落地，非本设计）：**

- **Selected Interim Strategy = G1-C 先例（fail-closed）**：`ADAPTER_STATE_VOCABULARIES["thehive"]` 四集**全部清空**（与 wazuh/shuffle/mock 结构一致）。`case_created` 现在在**任何路径**都映射为 `Nothing`（`UnrecognizedExternalState` → 422 / 零 Outcome Fact）。合成成功信号**不再可被任何入口伪造**——因为它根本不在词表里。
- **Reader 仍在 READER 层发出 `case_created`**（identity ∧ correlation ∧ creation 三重合取，隔离测试覆盖），但**映射层拒绝接受来自任何来源的该词**，直到本 Amendment 设计的**可信 Reader 来源隔离通道**获批。
- **P1-2 已落地的部分**：Reader `_verify` gate3 现强制 `createdAt`（缺失/非法/absurd → `case_unverified` reason=`missing_created_at`），代码已统一到冻结设计 §5.2。
- **P1-2 未落地的部分（本设计 §6）**：`createdAt` 与**不可变派发时间/目标实例/租户**的严格关联，需要把派发记录带到读取上下文——而冻结的 `AdapterReadRequest` DTO 只携带 `execution_id`/`adapter`/`external_reference`，**结构上不携带派发记录**。扩展该 DTO 是**冻结契约变更**，依授权 §3「若严格来源关联需要修改冻结 DTO 或 DB 模型，停止该部分并提交最小 Amendment」→ **本设计**。

**本轮零生产代码（除已落地的 fail-closed 前向修复外）**：Amendment 的实际落地（来源隔离通道 + 派发关联 + DTO 扩展）是**独立后续 Gate**，需用户授权 + 真实 Lab 证据；本轮只交付本设计文档（§10）。

---

## 1. Version Scope（版本域分离）

**铁律：仓库审计对象 ≠ Lab 运行时 ≠ 生产部署版本。三者分开记录，绝不混同。**

| 版本域 | 值 | 证据 | 状态 |
|---|---|---|---|
| **Source Version（源码审计对象）** | TheHive **4.1.24-1** = git tag `4.1.24` = commit `b6649bb`；ScalliGraph gitlink pin = `2c2a7a4` | 仓库外权威 checkout `git ls-tree`/`git rev-parse` 双证 | **CERTIFIED**（仅对源码成立）|
| **Lab Runtime Version** | 本地隔离实例实际运行的镜像 tag + digest | **未取得** — 本机无容器运行时（LAB BLOCKED，见 lab-evidence §6）| **LAB BLOCKED** |
| **Production Runtime Version** | 未来真实目标实例运行的版本 + digest | 未知 | **UNKNOWN**（本里程碑不触碰生产）|

**版本门已落地（M2-R §4，非本设计）**：`read_adapters/thehive.py:CERTIFIED_THEHIVE_VERSION = "4.1.24-1"`；工厂 `_thehive_readers` 只在 `THEHIVE_EXPECTED_VERSION` **精确等于**该串时授权 Reader，未设/不匹配一律 fail-closed。这保证 4.1.24-1 的读语义（`GET /api/case/{id}`、`EntityIdOrName`、epoch-millis `createdAt`、`OutputCase._id`）**不会被一行接线 silently 应用到其他服务器版本**。

**约束**：本设计所有关于「真实 TheHive 行为」的结论**仅对 4.1.24-1 源码成立**。换一个 TheHive 版本/build 时，正确动作是**针对该版本重做 Evidence Audit**，而不是反向解冻本设计（继承 B0 §18.2 版本边界纪律）。

---

## 2. Evidence Sources（证据来源与优先级）

**Evidence Hierarchy（严格降序）：**

1. 官方**版本对应**源码（TheHive `b6649bb` / ScalliGraph `2c2a7a4` DTO 与 Ctrl/Srv）
2. **冻结契约源码**（`manual_reconcile/read/base.py`、`outcomes/reconciliation.py`、`outcomes/mapping.py` 及其封板测试）
3. 审查者**独立隔离探针**（M2 Final Review：纯映射 `case_created`→`confirmed_success`；`_verify` 缺 `createdAt`/十年前案件仍 `case_created`）
4. 实际真实实例返回（生产/staging 实测 —— 本轮**无**，LAB BLOCKED）
5. 当前仓库 Reader/工厂实现（**最低优先级**）

**本设计采信的关键一手来源：**

| 源 | 文件 | 关键证据 | 优先级 |
|---|---|---|---|
| **S1 冻结读取 DTO** | `manual_reconcile/read/base.py` L43-65 | `AdapterReadRequest` 只携带 `execution_id`/`adapter`/`external_reference`；docstring 明载「deliberately carries NO operator credential, NO callback token, NO write intent」→ **不携带派发记录/实例/租户/派发时间** | 2 |
| **S2 冻结映射契约** | `outcomes/reconciliation.py` `normalize_external_state(adapter, external_state)` | 2 参数纯函数；per-adapter 词表 path-agnostic；被 webhook PUSH 与 manual_reconcile PULL **两路共享** | 2 |
| **S3 封板委托** | `outcomes/mapping.py` + `test_mapping.py` | `map_external_state` 封板为**单条 return 瘦委托**：函数体无 `if`、`called=={normalize_external_state}`、`funcs=={map_external_state}` | 2 |
| **S4 官方 DTO** | ScalliGraph `2c2a7a4` `dto/v0/Case.scala` | `InputCase.tags:Set[String]`、`severity:Option[Int]`；`OutputCase._id/id:String`、`caseId:Int`、`createdAt:Date`（epoch millis）| 1 |
| **S5 G1-C 先例** | `reconciliation.py` wazuh 词表（`0c372aa`）+ B0 Amendment §0/§8 | 「四集全空 fail-closed」「NO second mapping table」「path-agnostic 单一语义映射被 LIVE webhook 复用」 | 2 |

**冲突处理**：S1-S3（冻结契约）与「让 `case_created` 可被 Reader 独占产出」的目标冲突时，**以冻结契约为准**——不改契约，而是设计一条**不经过共享词表**的隔离通道（§5）。

---

## 3. P1-1 缺陷 · 合成成功状态进入共享入站词表

**缺陷链（全部以 S2/S3/S5 坐实）：**

1. **词表是 path-agnostic 的单一语义映射。** `ADAPTER_STATE_VOCABULARIES["thehive"]` 经 `mapping.py → normalize_external_state(adapter, external_state)` 被**两条收敛路径共享**：
   - **PUSH**：`webhook.py`（source=`webhook`）——外部系统主动回调；
   - **PULL**：`manual_reconcile.py`（source=`manual_reconcile`）——平台显式对账，经可信 Reader 读取。
2. **`normalize_external_state` 只有 2 个参数**（`adapter`、`external_state`），**没有 source / trust_domain 参数**。它在结构上**看不到**这个词是从可信 Reader 来的，还是从 Webhook 请求体来的。
3. **`map_external_state` 被封板为单委托**（S3）：函数体单条 `return normalize_external_state(...)`，无 `if`、无分支、无额外被调函数。任何在此处加来源判断的改动都会**打破封板测试**。
4. **因此**：一旦 `case_created ∈ terminal_success_states`，则**任何**能到达 `normalize_external_state("thehive", "case_created")` 的入口都得到 `confirmed_success`。审查者已独立验证：在配置**有效** `THEHIVE_CALLBACK_TOKEN` 后，一个符合 schema + execution correlation 的 webhook body 携带裸串 `case_created`，**无需经过任何 Reader** 即映射为 `confirmed_success`。

**为何 M2 的安全理由不成立（审查者裁定，本设计采信）：**

> M2 Final Report §5 以「`case_created` 是 reader 合成词、真实 TheHive webhook 不原生发出、`THEHIVE_CALLBACK_TOKEN` 默认空 → webhook uniform 401 fail-closed」作为安全理由。审查者裁定：**这不构成不可绕过的语义门**——它依赖的是「运维永不配置有效 callback token」这一**部署假设**，而非**结构保证**。一旦启用有效回调凭据（生产常见），该词即可被请求体伪造。这正是 **G1-A 缺陷类**（一个不安全映射被证明 LIVE 可达）。

**已落地的前向修复（G1-C 先例，非本设计）：**

```python
# reconciliation.py（M2-R §2 前向提交；117ab6b 只读历史，未 amend）
"thehive": AdapterStateVocabulary(
    adapter="thehive",
    terminal_success_states=frozenset(),   # ← case_created 已移除（原 M2 §5 唯一新增词）
    terminal_failure_states=frozenset(),
    pending_states=frozenset(),
    ambiguous_states=frozenset(),
    case_insensitive=False,
    state_key=None,
    evidence="M2-R §2 FAIL-CLOSED ... the frozen 2-param mapping contract cannot "
             "express source isolation ... REFUSES case_created on EVERY path "
             "(zero fact) until a trusted-reader source-isolation channel is "
             "approved (M2-R Amendment) ...",
)
# wazuh（G1-C 0c372aa）/ shuffle / mock 词表【数据未改】
```

**修复后的不变量（已被测试 pin）：** `case_created` 在**任何路径**都 → `UnrecognizedExternalState` → 422 / 零 fact。全平台**无任何** adapter 拥有 evidenced 外部状态词表（wazuh/shuffle/thehive/mock 四集皆空），与 B0 §0 的去锚定结论一致。

---

## 4. 冻结契约为何无法表达来源隔离（四选项全违反封板）

审查者要求：「必须建立不可由外部 JSON 冒充的可信来源门，或者在完成来源隔离前将该合成词恢复为 fail-closed。**不能仅添加一个可由请求体提交的 `verified=true` 标志**。」逐一检验在**共享词表内**表达来源隔离的四种途径：

| 选项 | 做法 | 为何不可行 |
|---|---|---|
| **A. 加 source 参数** | `normalize_external_state(adapter, external_state, source)` | 违反**冻结 2 参数签名**（S2）；`map_external_state` 单委托封板被迫同步改（S3）；波及全部既有 adapter 映射测试 |
| **B. 加 `if` 分支** | 在 `map_external_state` 内 `if source=="reader": ...` | 直接违反 `test_mapping.py` 封板：函数体必须单条 return、无 `if`、`funcs=={map_external_state}`（S3）|
| **C. `verified=true` 标志** | 请求体/external_state 携带 `verified` 字段 | **审查者明确否决**：任何可由请求体提交的标志都能被伪造，等于没有门 |
| **D. 第二张映射表** | 建 `TRUSTED_READER_VOCABULARIES` 与共享表并存 | 违反 G1-C「**NO second mapping table**」先例（S5）；两张表 = 两个真源 = 漂移风险 |

**结论**：在**不违反任一冻结封板**的前提下，**共享 path-agnostic 词表内无法表达来源隔离**。故来源隔离**必须**活在**共享词表之外**的一条独立通道里——这是 §5 的设计出发点，也是本 Amendment 存在的理由（授权 §2「若现有冻结通用契约无法安全表达该隔离…提交最小 Amendment」）。

---

## 5. 提议的可信 Reader 来源隔离通道（DESIGN）

**设计原则**：合成成功信号只能由**受信任的 Reader 验证路径**产生，且该信号**从不被序列化为一个共享词表里的裸字符串**——因为任何裸字符串都能被 webhook 请求体伪造。

**提议：把「已验证创建效果」表达为 READ 结果上的结构化来源证明（provenance），由一条 PULL-only、webhook 物理不可达的读取侧通道消费。**

### 5.1 通道分层（trust-domain separation）

```
WRITE 域（executions/）        共享映射域（outcomes/reconciliation.py）      READ 域（manual_reconcile/ + read_adapters/）
TheHiveExecutor.execute        normalize_external_state(adapter, state)      TheHiveReadAdapter.read
  POST /api/case                 ↑ path-agnostic，2 参数，封板                  GET /api/case/{id}
                                 ↑ thehive 词表 = ∅（fail-closed）              → AdapterReadResult
                                 ↑ 拒绝 case_created（422/零 fact）               (external_state, observed_at,
webhook.py（PUSH）──────────────┘                                                 raw_evidence + 【新增】
  外部 JSON 携带 case_created                                        VerifiedCreationEffect provenance)
  → 共享词表 → ∅ → 422 零 fact                                              │
                                                                            ↓ 【新增】READ-side 隔离映射
                                              manual_reconcile 信任域内的 read-effect mapper
                                              （物理上 webhook.py 不可 import / 不可达）
                                                → confirmed_success（仅当 provenance 由可信 Reader 产出）
```

### 5.2 关键设计点

1. **来源证明不进入共享词表。** `case_created` 作为**共享 external_state 字符串**永远被 `normalize_external_state` 拒绝（词表 ∅）。已验证创建效果改由 `AdapterReadResult` 上一个**结构化、来源受限**的证明承载（例如一个 `VerifiedCreationEffect` 值对象，绑定 resource_id + execution_id + 创建时间 + 目标实例/租户），**不是**一个可被 JSON 复刻的裸词。
2. **隔离映射活在 READ 信任域。** 新增的 read-effect mapper 位于 `manual_reconcile`/`read_adapters` 信任域，**只有 PULL 路径（`reconcile_execution`）可达**；`webhook.py`（PUSH）在物理上**无法 import** 它（可加 sealed 纯度审计 pin：read-effect mapper 的 import surface 不含 webhook/fastapi 请求体解析）。因此「外部 JSON 冒充」在结构上不可能——PUSH 路径根本到不了这条通道。
3. **冻结通用契约零改动。** `normalize_external_state` 保持 2 参数 + path-agnostic + 拒绝 `case_created`；`map_external_state` 封板不动；共享词表 thehive 四集保持 ∅。来源隔离**完全**活在共享词表**之外**的独立通道（避开 §4 四选项的全部封板冲突）。
4. **provenance 由 Reader 内部产生，不可外部注入。** `VerifiedCreationEffect` 只能由 `TheHiveReadAdapter._verify` 在三重合取（+ §6 严格关联）全过时构造；它**不是** `AdapterReadRequest` 的输入字段（否则又变成调用者可控标志，重蹈选项 C）。

### 5.3 与「不改冻结 DTO」的张力

`AdapterReadResult` 是冻结 DTO（S1，携带 `external_state`/`observed_at`/`raw_evidence`）。承载 `VerifiedCreationEffect` 有两种途径，**均需用户裁决**：

- **途径 1（推荐，最小侵入）**：复用既有 `raw_evidence: Mapping` 字段承载结构化证明（`raw_evidence` 已是只读快照，且 `manual_persist` 当前**丢弃**它——需改为「READ-side mapper 消费 raw_evidence 的 provenance，但仍不持久化原始证据」）。**不改 DTO 结构**，只改 `raw_evidence` 的语义与消费点。
- **途径 2（更强类型，但改冻结 DTO）**：给 `AdapterReadResult` 增加一个 typed `provenance` 字段。**这是冻结 DTO 变更**，依授权 §3 必须停在本 Amendment，不得擅自扩大通用契约。

> **本设计倾向途径 1**（不改 DTO 结构），但它要求 `manual_persist`/read-effect mapper 的持久化边界重新裁定（哪些 provenance 字段可进入 Outcome detail、哪些必须丢弃），这一裁定属 Implementation Gate。

---

## 6. 提议的严格创建关联（strict dispatch / instance / tenant / time）

**审查者 P1-2 裁定（本设计采信）**：「当前只要求 ID 相等、存在 execution tag；这些条件**不足以**在所有历史、跨实例或标签可修改场景下独立证明『本次执行创建了这个案件』。」已落地的 gate3（强制 `createdAt` 存在）只堵住了「缺失创建时间」，**未堵住**：

- **历史案件被补加标签**：一个十年前创建的案件，事后被补加 `sentinelflow:execution:<id>` 标签 → identity ✓ + correlation ✓ + createdAt 存在 ✓ → 仍误判 `case_created`（审查者探针已复现）。
- **跨实例/跨租户同 id**：另一 TheHive 实例/租户的同 `_id` 案件带匹配标签 → 三门全过 → 误判。

**根因（S1）**：冻结的 `AdapterReadRequest` **只携带** `execution_id`/`adapter`/`external_reference`，**不携带不可变派发记录**（派发时间、目标实例/租户、经审批的 action/target）。Reader 因此**无法**把 `createdAt` 与「本次派发」在时间/实例/租户上对齐。

**提议的完整合取门（在 §5.2 三重门上追加，需派发记录）：**

| 门 | 校验 | 数据来源 | 不满足时 |
|---|---|---|---|
| 1. IDENTITY | `resource_id == external_reference`（非空 str）| 已落地 | `case_unverified`（no_string_resource_id / resource_id_mismatch）|
| 2. CORRELATION | `tags` 含 `sentinelflow:execution:<id>`（精确）| 已落地 | `case_unverified`（missing_execution_correlation_tag）|
| 3. CREATION-TIME | `createdAt` 存在且合法（epoch millis → observed_at）| 已落地（gate3）| `case_unverified`（missing_created_at）|
| **4. TIME-ORDER（新增）** | `createdAt >= dispatch_time`（案件不可能早于派发被本次执行创建）且落在派发后**有界窗口**内（无 absurd future/past skew 取得排序优势）| **不可变派发记录**（历史 `ExecutionLog` dispatched 行的 server 时间戳）| `case_unverified`（created_before_dispatch / created_out_of_window）|
| **5. INSTANCE/TENANT（新增）** | 读取命中的目标实例/租户身份 == 派发时认证的实例/租户 | **不可变派发记录** + 认证实例身份（§7）| `case_unverified`（instance_mismatch / tenant_mismatch）|

**门 4 直接杀死「十年前补标签」探针**：十年前 `createdAt` << 本次 `dispatch_time` → `created_before_dispatch` → REFUSED。**门 5 杀死跨实例/租户同 id**。

### 6.1 observed_at 语义（保留，不伪造）

- **读取发生时间（server observation）≠ 外部创建发生时间（external creation）。** 门 3/4 用的是 `createdAt`（外部权威创建时间）→ `observed_at`，`observed_at_kind="external"`。
- **绝不用服务器「now」伪造历史创建时间**；**绝不让缺失/过早时间取得不可信排序优势**（门 4 的有界窗口 + `created_before_dispatch` 拒绝即为此）。
- server observation time 仅可用于**记录「读取动作何时发生」**（审计），不参与创建效果的排序判定。

### 6.2 派发记录的来源（不改 DB 模型的前提下）

派发时间/目标实例/租户**已存在于历史 `ExecutionLog` 链**（`requested`/`dispatched` 行的 server 时间戳 + `detail`）。`reconcile_execution` 在 PULL 路径**已经读取**该链以提取 `adapter`（`detail["executor"]`）与 `external_reference`（`detail["case_id"]`）。因此门 4/5 所需的派发事实**可从既有链行派生**，**不必新增 DB 列**——但必须把它们**带到 Reader 的读取上下文**，而冻结的 `AdapterReadRequest` 不携带它们。

**两条途径（均需用户裁决，属冻结 DTO 边界）：**

- **途径 1（推荐）**：扩展 `AdapterReadRequest`（或引入一个 reconcile-side 的 `ReadCorrelationContext` 值对象，包裹 `AdapterReadRequest` + 派发事实），把 `dispatch_time`/`instance_id`/`tenant_id` 作为**只读、平台派生**（非调用者可控）字段带给 Reader。**扩展 `AdapterReadRequest` 是冻结 DTO 变更** → 停在本 Amendment。
- **途径 2**：门 4/5 在 **READ-side mapper（§5.2）** 内执行，而非 Reader 内——mapper 从 `reconcile_execution` 已加载的链行取派发事实，与 `AdapterReadResult.observed_at`（=createdAt）比对。**不改 `AdapterReadRequest`**，但要求 mapper 能访问链行（PULL 路径本就持有 session 与链行，可行）。

> **本设计倾向途径 2**（门 4/5 落在 READ-side mapper，不改冻结 DTO），与 §5.3 途径 1 组合后，**整个 P1-1/P1-2 整改可在不改任何冻结 DTO 结构、不建第二张共享词表、不加调用者可控标志的前提下完成**——来源隔离与严格关联都活在 PULL-only 的 READ 信任域内。最终途径选择属 Implementation Gate 的用户裁决。

---

## 7. 版本 / 实例 / 租户绑定（Fix A 扩展）

**已落地（M2-R §4，非本设计）**：工厂三道 fail-closed 门——(1) `THEHIVE_BASE_URL` 合法；(2) `THEHIVE_READ_API_KEY` **独立只读钥**（绝不回退到 create-capable 的 `THEHIVE_API_KEY`，最小权限）；(3) `THEHIVE_EXPECTED_VERSION == CERTIFIED_THEHIVE_VERSION`（精确版本）。`_NoRedirectHandler` 拒绝任何 3xx，`Authorization` 绝不跨主机转发（CWE-522）。TLS 校验与 base-URL 校验**未放松**。

**本设计追加（门 5 的前置）：**

| 项 | 现状 | 提议 |
|---|---|---|
| **目标实例身份** | 仅 base URL 隐式绑定 | 认证一个**显式实例身份**（如 org/instance id），门 5 校验读取命中的实例 == 派发认证实例 |
| **租户一致性** | 404 故意合并 absent/deleted/跨租户不可见 | 门 5 要求租户身份匹配；跨租户同 id → `tenant_mismatch` REFUSED（不依赖 404 的歧义）|
| **版本活性证明** | 工厂 build 时**零 HTTP**（pinned invariant），仅配置断言 | 接线前**必须**在真实 Lab 对运行服务器**重新认证版本**（live probe），配置断言 ≠ 活性证明 |
| **只读权限范围** | 独立钥已隔离写权限 | Lab 认证该只读钥**确无** create/update/delete 权限（最小权限实证，非仅命名）|

**纪律**：registry 默认保持空（sealed `default_read_adapter_registry()` 不动）；router **不接线**；真实 Lab + 完整安全验收通过前**不开放**真实 Reader（授权 §4）。

---

## 8. 与冻结契约 / 历史的关系（Relationship）

| 对象 | 本 Amendment 的处置 |
|---|---|
| `normalize_external_state(adapter, external_state)` | **不改**（保持 2 参数 + path-agnostic + thehive 词表 ∅ 拒绝 `case_created`）|
| `map_external_state` 封板（`test_mapping.py`）| **不改**（单委托、无 `if`、无 source 分支）|
| `ADAPTER_STATE_VOCABULARIES` 共享词表 | **不建第二张**；thehive 四集保持 ∅（已落地 fail-closed）|
| `AdapterReadRequest` / `AdapterReadResult` 冻结 DTO | **本轮不改**；§5.3/§6.2 的扩展途径**停在本设计**，Implementation Gate 由用户裁决（倾向不改结构的途径）|
| sealed `default_read_adapter_registry()` | **不改**（保持空；`TestEvidenceGap` 不变量不动）|
| router（`api/v1/reconcile.py`）| **不接线**（仍 `reconcile_execution(db, id, operator)` 无 registry → 空 registry → 404 零 fact）|
| Wazuh G1-C（`0c372aa`）四集清空 | **不改**（先例，保持一致）|
| shuffle / mock 词表 | **不改**（保持 ∅）|
| `117ab6b`（M2 §5 reader+mapping）/ `3b23520`（M2 Final Report）| **只读历史，不 amend/rebase/reset**；整改经**新前向提交** |
| DB 模型 / 历史 Outcome / 审批规则 | **不改**；不增自动重试/轮询/补偿；不重开未认证外部状态 |

---

## 9. 测试变更（proposed — Implementation Gate 落地）

**已落地（M2-R §2/§3/§5，非本设计）：**

- **来源门（P1-1）**：`test_webhook_persistence.py::test_thehive_forged_case_created_callback_is_refused_zero_facts`——有效 callback token + schema/correlation-valid body 携带裸串 `case_created` → **422 零 fact**；`test_reconciliation.py` pin thehive 四集 ∅ + 每个状态被拒；`test_thehive_write_read_closure.py::TestHttpRouteChain`——真实 HTTP 执行→对账路由命中空生产 registry → 404 零 fact（三入口均无法伪造 `confirmed_success`）。
- **创建门（P1-2）**：`test_read_adapter_thehive.py` gate3 负向（缺 `createdAt`/非法/absurd → `case_unverified`）；`TestRealLabRead` 严格断言 `CASE_CREATED`（`@pytest.mark.external`，LAB BLOCKED 时 skip，不接受 `case_unverified` 冒充成功）。

**本设计追加（Implementation Gate）：**

- **来源隔离通道**：PULL 路径经可信 Reader 产出 `VerifiedCreationEffect` provenance → READ-side mapper → `confirmed_success` + 独立持久化 Outcome；**同一 provenance 经 PUSH 路径不可达**（sealed 纯度审计 pin：webhook.py 无法 import read-effect mapper）。
- **严格关联负向**：门 4（`created_before_dispatch` 十年前补标签 / `created_out_of_window` 未来时间）；门 5（`instance_mismatch` 跨实例同 id / `tenant_mismatch` 跨租户）；不匹配 reference / 缺失时间（已有）。
- **真实 HTTP 平台链**：经审批 + HTTP 路由的隔离平台测试（已有 `TestHttpRouteChain` 证明未接线 404；接线后门 4/5 的 HTTP 级验证）。
- **测试分层诚实标注**：单元 / service 集成 / HTTP 集成 / 真实外部 E2E 四级分明，**不以手工 seed 日志的测试冒充完整 E2E**（审查者 P1-3）。

---

## 10. Final Decision（裁定汇总 + 实施边界 + 停止声明）

### 10.1 裁定汇总

| 项 | 裁定 | 依据 |
|---|---|---|
| **P1-1 来源门** | **已 fail-closed 修复（前向提交）**：thehive 四集 ∅，`case_created` 任何路径 → 422 零 fact | §3 |
| **共享词表内来源隔离** | **结构上不可行**（四选项全违反封板）| §4 |
| **可信 Reader 来源隔离通道** | **PROPOSED（DESIGN ONLY）**：provenance 走 PULL-only READ 信任域，webhook 物理不可达 | §5 |
| **P1-2 创建门 gate3（createdAt 强制）** | **已落地（前向提交）**，统一到冻结设计 §5.2 | §6 |
| **P1-2 严格关联（time-order / instance / tenant）** | **PROPOSED（DESIGN ONLY）**：需不可变派发记录；倾向落在 READ-side mapper，不改冻结 DTO | §6 |
| **冻结 DTO 扩展** | **STOP — 停在本 Amendment**，Implementation Gate 由用户裁决途径 | §5.3/§6.2 |
| **版本/凭据门（Fix A）** | **已落地**（精确版本 + 独立只读钥 + 无重定向）；实例/租户绑定 + 活性版本证明 **PROPOSED** | §7 |
| **registry / router** | **保持空 / 不接线**（真实 Lab + 完整安全验收前不开放真实 Reader）| §7/§8 |
| **Wazuh G1-C / shuffle / mock** | **不改**（四集保持 ∅）| §8 |
| **历史（`117ab6b`/`3b23520`）** | **只读，不 amend/rebase/reset**；整改经新前向提交 | §8 |

### 10.2 实施边界（本轮 → 独立后续 Gate）

- **本轮（M2-R）**：已落地 fail-closed 前向修复（§3 空词表 + §6 gate3 + §7 版本/凭据门 + §9 已列测试）+ 交付本设计文档。**不改任何冻结契约/DTO/DB**；不接线 router；不开放真实 Reader。
- **后续（Amendment Implementation Gate，需用户授权 + 真实 Lab 证据）**：按 §5/§6/§7 落地来源隔离通道 + 严格关联 + 实例/租户绑定；用户裁决 §5.3/§6.2 的 DTO 途径；全量回归。**禁改 `8b89fe7`/`0c372aa`/`117ab6b`/`3b23520`；禁 amend/rebase/reset/force-push；禁 push。**
- **再后续**：真实 Lab 接线（解除 LAB BLOCKED）→ 生产版本认证（解除 UNKNOWN）。均需**另行单独授权**。

### 10.3 停止声明

本 Amendment 设计到此完成，**DESIGN ONLY**。在用户 Review 本设计并授权 Amendment Implementation Gate 之前：**不改** `normalize_external_state`/`map_external_state`/`AdapterReadRequest`/`AdapterReadResult`/DB 模型；**不建**第二张共享词表；**不加**调用者可控 `verified` 标志；**不接线** router。当前生产态保持 §3 的 **fail-closed 空词表**（`case_created` 任何路径零 fact）——这是**安全的 interim 状态**，合成成功信号在来源隔离通道获批前**不可被任何入口伪造**，亦**不被任何入口接受**。

> **本设计的核心不是否定 M2 已做的工作，而是阻止一个与 G1-A/G1-C 同类的问题重新出现**：不能让「经过验证的效果信号」退化成任何入口都能提交的普通成功字符串。修复这两处证据门（来源门已 fail-closed、严格关联已设计）后，Reader 才有资格进入真实 Lab 验收。
