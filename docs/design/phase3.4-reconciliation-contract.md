# Phase 3.4.3 设计：Reconciliation Contract（对账契约）

> 状态：**设计冻结（Design Freeze）**（2026-09-03 用户裁决 Audit=PASS 后冻结；本文档冻结后不得再改契约语义，只允许按 §15 拆步实施）
> 范围：Phase 3.4.3 —— 把"平台如何把外部系统**已存在**的状态，转换成一个**可信的 External Outcome Fact**"定义为一个**纯契约层**（归一化 + 来源区分 + 失败语义 + 身份语义 + 时间戳语义）
> 基线：3.4.2 Outcome Derivation（commit `63556e6`）；其前 3.4.1 + Migration 0010（commit `9dc7135`）；`v1.3.0`（commit `48fbe41`，tag 冻结）
> 前置：`phase3.4-execution-outcome-lifecycle.md`（§4 词表 / §5 入站验证闸 / §6 Reconciliation Contract / §8 身份 + D3.4-01~09 + O1/O3/O5 全部有效）
> 日期：2026-09-03
> **性质：CONTRACT ONLY。本文档不实现任何代码。** 不新增 `reconciliation.py`、service、repository、API、Pydantic endpoint、Webhook、adapter client、DB migration、React、tests 实现。落地拆步见 §15（3.4.4 / 3.4.5）。

---

## 0. 冻结摘要（TL;DR — 三态语义绝不混淆）

本契约的存在理由，是把下面**三种彼此独立、永不合并**的结果严格区分开。混掉任何一种都会污染整个 Outcome Lifecycle 的数据质量：

| # | 情形 | 结果类别 | 是否落 `execution_outcome` fact | `outcome_status` |
|---|---|---|---|---|
| 1 | 拿到**合法** external state，外部效果**明确成功** | 归一化成功 | ✅ 落 | `confirmed_success` |
| 2 | 拿到**合法** external state，外部效果**明确失败** | 归一化成功 | ✅ 落 | `confirmed_failure` |
| 3 | 拿到**合法** external state，外部**仍在处理中** | 归一化成功 | ✅ 落 | `pending` |
| 4 | 拿到**合法** external state，但**语义上无法判断**真实效果 | 归一化成功 | ✅ 落 | `unknown` |
| 5 | **执行了对账，但拿不到可靠 external state**（adapter 不可访问 / 超时 / 连接失败） | 对账动作失败 | ✅ 落 | `reconciliation_failed` |
| 6 | **missing `external_reference`** | **Contract Validation Failure** | ❌ **不落**（仅审计） | —（拒绝，无词） |
| 7 | **unrecognized `external_state`**（词表外、无法归一化的私有状态） | **Mapping / Contract Validation Failure** | ❌ **不落**（仅审计） | —（拒绝，无词） |

**三条铁律（本契约的灵魂，任何实现不得违反）：**

- **`unknown` ≠ `reconciliation_failed`**：`unknown` = **已经拿到合法 external state**，但该状态在语义上无法判断真实效果（事实来源=外部世界）；`reconciliation_failed` = **根本拿不到可靠 external state**（事实来源=对账过程本身，O1）。二者事实来源不同，永不合并。
- **`rejected`（不落 fact）≠ 任何 outcome 词**：missing reference / unrecognized state / 非法 timestamp 属于**契约校验失败**，**不生成任何 Outcome Fact**，只留审计记录。
- **两个被明令禁止的错误映射**：
  - ❌ `missing external_reference → reconciliation_failed`（禁止；应是 rejected，不落 fact）
  - ❌ `unrecognized external_state → unknown`（禁止；应是 rejected，不落 fact。`unknown` 只保留给"合法但语义不明"的 external state）

---

## 1. Scope（范围）

3.4.3 冻结**一个纯契约层**，描述"外部已存在状态 → 可信 External Outcome Fact"的转换规则。它回答四个问题：**输入是什么、输出是什么、失败怎么表达、谁负责确认（身份）**。

冻结内容：

1. **Input Contract**：`ExternalObservation` 的字段形状与约束（§4）。
2. **Output Contract**：归一化产物 —— 五词之一的一条 append-only fact，**或**一个不落 fact 的 Contract Validation Failure（§5、§13）。
3. **External state mapping**：外部效果语义 → 五词的映射规则（§6）。
4. **Failure semantics**：`confirmed_failure` / `reconciliation_failed` / `pending` / `unknown` / `rejected` 的严格边界（§7）。
5. **Identity semantics**：`webhook` 与 `manual_reconcile` 两个永不合并的信任域（§8）。
6. **`external_reference` semantics**：统一契约字段与 adapter 私有键的关系（§9）。
7. **`observed_at` semantics**：fact time 的 timezone / naive-aware / UTC / 拒绝 / 未来时间 / 精度规则（§10）。
8. **Append-only / O5 / 与 3.4.2 / 与 3.4.4-3.4.5 的关系**（§11、§12、§14、§15）。
9. **Test requirements**（§16，仅定义，不实现）。

本契约是 **3.4.4 Webhook（push）与 3.4.5 Manual Reconcile（pull）共用的归一化契约层**：两条来源最终都构造一个 `ExternalObservation` 喂给本契约，产出同一种 fact（同一词表、同一审计形状），仅 `source` 字段区分（§6 父文档）。

---

## 2. Non-goals（非目标）

本 Step **明确不进入**（发现即记录为后续 Step，不顺手实现）：

- ❌ Webhook / Callback 的 HTTP 传输实现、endpoint、路由（→ 3.4.4）
- ❌ `<ADAPTER>_CALLBACK_TOKEN` 配置项落地、身份闸的运行时认证（→ 3.4.4；本文档只冻结身份**形状**）
- ❌ Manual Reconcile 的操作者触发 API、RBAC（executor/admin）（→ 3.4.5）
- ❌ **adapter read path**：如何回查外部系统、如何取得 external state（→ 3.4.5；当前四个 adapter **均无**"回查外部效果"的读路径）
- ❌ background worker / automatic polling / 定时对账循环（D3.4-03 永久禁止，非"后续"）
- ❌ retry / compensation / approval / fan-out / 任何 execution（D3.4-01/02/03 永久禁止）
- ❌ 修改 adapter（Shuffle/TheHive/Wazuh/Mock）以统一 external reference 键名（§9：3.4.3 只规定统一 Contract，不改 adapter）
- ❌ 修改 `execution_outcome` model / Migration 0010 / `derivation.py` / `execution_log` / Executor / Guard / Policy / React
- ❌ Long-running 生命周期正交化、Mock 确定性效果模拟（→ 3.4.6）
- ❌ Outcome Metrics 效果派生视图 + UI（→ 3.4.7）

---

## 3. Trust boundaries（信任边界）

```
Layer 1 — Decision     Approval / Policy           "为什么允许做"
Layer 2 — Dispatch     ExecutionLog                "我们到底发出了什么"   ← 平台视角，8 词，语义冻结
Layer 3 — Outcome      External Outcome Facts      "外面最终发生了什么"   ← 外部视角，5 词，本契约的产物
```

**Reconciliation 是 Layer 3 的事实确认机制（Fact Confirmation），不是 Layer 2 的执行机制（Execution）。**

信任域划分（D3.4-07，两个域永不合并）：

```
Human            → Operator credential        （人 → 平台）   → source=manual_reconcile 的 recorder 身份
External adapter → Adapter callback credential（外部系统 → 平台）→ source=webhook 的 recorder 身份
```

绝对禁止（继承四条核心安全边界 + D3.4-01/02/03）：

```
Reconcile → Execute        ✗
Reconcile → Retry          ✗
Reconcile → Compensate     ✗
Reconcile → Approval       ✗
Reconcile → Fan-out        ✗
```

**Inbound observation 只产生事实，不产生意图。** 本契约的任何输出都不可能成为任何写动作（execution/retry/compensation）的输入。

---

## 4. Input Contract（输入契约 — `ExternalObservation`）

冻结输入形状（字段名、类型、必填性、约束）：

```
ExternalObservation {
    execution_id       : UUID            # 必填。只读关联键，须可映射到"已存在"的 execution 链
    adapter            : str             # 必填。adapter identity：shuffle | thehive | wazuh | mock
    external_reference : str             # 必填。统一契约字段（§9）。missing → Contract Validation Failure（不落 fact）
    external_state     : str | dict      # 必填。外部系统私有状态（未归一化）。unrecognized → Mapping Failure（不落 fact）
    observed_at        : datetime        # 必填。fact time（非 ingest time），timezone-aware（§10）。非法 → Contract Validation Failure
    source             : str             # 必填。webhook | manual_reconcile（§8）。决定 recorder 身份域
}
```

字段约束（契约级，先于任何存储 CHECK）：

- **`execution_id`**：必填且必须能映射到**已存在**的 execution 链（§6 父文档 Schema 闸）。无法映射 → Contract Validation Failure（不落 fact，防错误归属，§9 Q3）。它是 plain 链键、**非 FK**（与 model 一致），本契约对它**只读**，绝不回写 `execution_log`。
- **`adapter`**：必须是已知适配器身份之一。未知 adapter → Contract Validation Failure。它决定 §6 使用哪张 per-adapter 归一化词表。
- **`external_reference`**：统一字段，吸收 adapter 私有键差异（Shuffle `external_execution_id` / TheHive `case_id` / Wazuh `command_id`，§9）。**missing / 空 → Contract Validation Failure（不落 fact）**。
- **`external_state`**：外部私有状态。**无法归一化到五词（词表外的未知状态）→ Mapping / Contract Validation Failure（不落 fact）**；能归一化但语义不明 → `unknown`（§0 铁律）。
- **`observed_at`**：见 §10（aware-only、UTC、拒绝非法、未来时间有界、精度保留）。
- **`source`**：二词冻结，决定 §8 身份域；非法 source → Contract Validation Failure。

> 输入契约是**纯数据形状**，不含传输（HTTP body / 回调签名属 3.4.4），不含读取（如何取得 external_state 属 3.4.5 adapter read path）。

---

## 5. Output Contract（输出契约）

本契约的输出**有且只有两类**，互斥：

**A. 归一化成功 → 一条新的 `execution_outcome` fact（append-only）**

- `outcome_status` ∈ 五词：`unknown | pending | confirmed_success | confirmed_failure | reconciliation_failed`
- `source` = 输入的 `source`
- `operator` = §8 身份域解析出的 recorder（webhook→adapter callback identity；manual_reconcile→authenticated operator）
- `observed_at` = 输入 `observed_at`（经 §10 UTC 归一化）
- `execution_id` = 输入 `execution_id`
- `detail` = 归一化证据：source-system raw status、mapping notes、reconcile diagnostics、归一化后的 `external_reference`。**绝不含 callback credential**（继承 `execution_log.detail` 脱敏纪律）。

**B. 契约校验失败 → Contract Validation Failure（不落 fact，仅审计）**

- missing `external_reference` / unrecognized `external_state` / 非法 `observed_at` / 未知 adapter / 非法 source / `execution_id` 无法映射。
- **不生成任何 Outcome Fact**，只产生一条契约/安全审计记录（§13）。

**输出绝不是 Dispatch Result**（§12 / O5）：本契约**永不**写 `execution_log`、**永不**修改 dispatch decision、**永不**修改历史 outcome fact。输出也**绝不是执行意图**（§3）：不触发 execution/retry/compensation/approval/fan-out。

---

## 6. External state mapping（外部状态映射）

冻结**语义映射**（5 条规则，用户裁决 2026-09-03）：

| 外部效果语义 | → `outcome_status` | 事实来源 |
|---|---|---|
| 外部效果**明确成功** | `confirmed_success` | 外部世界 |
| 外部效果**明确失败** | `confirmed_failure` | 外部世界 |
| 外部**仍在处理中** | `pending` | 外部世界 |
| **拿不到可靠 external state**（执行了对账但读取失败） | `reconciliation_failed` | 对账过程（O1） |
| **合法** external state，但**语义上无法判断**真实效果 | `unknown` | 外部世界 |

**归一化闸规则（§5 父文档）：**

- 每个 adapter 有**私有状态词表**；契约要求把**已识别**的私有状态确定性地映射到上表五词之一。
- **词表外的未知私有状态** → **不归一化、不猜测、不落 fact** → Mapping / Contract Validation Failure（§13）。**禁止**把"无法识别"降级成 `unknown`。
- `unknown` 只保留给"**已识别为合法、但语义上确实无法判断效果**"的外部状态（例如外部系统返回一个有效但信息不足、既非成功/失败/处理中的中间语义）。

**per-adapter 具体词表（契约占位，read path 落地时填充）：**

> 3.4.3 **不修改 adapter**、**不实现 read path**（§2 / §9）。当前四个 adapter 只产出 dispatch 结果，**没有回查外部效果的读路径**。因此"某 adapter 的某个私有状态词具体映射到哪个 outcome 词"这张**具体词表**，随 3.4.5 adapter read path 一起落地；本契约**在此冻结的是映射的规则与目标词表（上表），以及归一化函数的输入/输出契约**，而非每个私有词的枚举。

**dispatch 词表与 outcome 词表刻意不相交（D3.4-04，回应"不要模糊使用成功/失败"）：**

- Dispatch 词表 = `{succeeded, failed}` + 失败分类 `{adapter_unavailable, timeout, adapter_error, protocol_violation}`（`app/services/executions/models.py`）。
- Outcome 词表 = `{unknown, pending, confirmed_success, confirmed_failure, reconciliation_failed}`（`app/models/execution_outcome.py`）。
- **`dispatch=succeeded` 只表示"外部系统同步接受了请求"，绝不表示"外部效果达成"**（Shuffle E4：`succeeded == workflow trigger confirmed`，NOT `workflow fully completed`）。因此 dispatch 词**永不**直接等价映射为 outcome 词；`execution_outcome` 的 CHECK 约束主动拒绝 dispatch 词入库。

---

## 7. Failure semantics（失败语义）

严格区分四种"负面"结果 + 一种"拒绝"，**绝不混淆**：

| 代号 | 情形 | 结果 | 落 fact? | `outcome_status` | 事实来源 |
|---|---|---|---|---|---|
| **A** | 外部系统**明确报告效果失败** | 归一化成功 | ✅ | `confirmed_failure` | 外部世界 |
| **B** | **无法读取**外部状态（adapter 不可访问 / 超时 / 连接失败 / 读取异常） | 对账动作失败 | ✅ | `reconciliation_failed` | 对账过程（O1） |
| **C** | 外部系统**仍在处理中** | 归一化成功 | ✅ | `pending` | 外部世界 |
| **D** | 拿到**合法** external state，但**语义无法判断**真实效果 | 归一化成功 | ✅ | `unknown` | 外部世界 |
| **R** | missing reference / unrecognized state / 非法 timestamp / 未知 adapter / 非法 source / execution_id 无法映射 | **Contract Validation Failure** | ❌ | —（拒绝，仅审计） | 契约校验 |

**明令禁止的错误转换（用户裁决 2026-09-03）：**

- ❌ 把 **B（查询失败 / 读不到）** 转换成 **A（`confirmed_failure`）**：读不到外部状态**不等于**外部效果失败。读不到 → `reconciliation_failed`。
- ❌ 把 **R（missing reference）** 转换成 **B（`reconciliation_failed`）**：缺关联键是契约校验失败，对账动作**根本没资格执行**，不落 fact。
- ❌ 把 **R（unrecognized state）** 转换成 **D（`unknown`）**：无法识别的私有词是契约校验失败（不落 fact）；`unknown` 只给"合法但语义不明"。

**`reconciliation_failed` 的专属定义（O1）：**"执行了 reconciliation，但**无法获得可靠 external state**"。它的前提是**对账动作真的发生了**（有合法 execution_id、有 external_reference、adapter 身份已知），只是读取外部状态这一步失败了。若连对账动作的**输入契约**都不满足（缺 reference / 状态无法识别 / 时间戳非法），那不是 `reconciliation_failed`，而是 **R（拒绝，不落 fact）**。

---

## 8. Identity semantics（身份语义）

`source` 字段决定 recorder 身份所属的**信任域**，两域**永不合并**（D3.4-07）：

| `source` | recorder（写入 `execution_outcome.operator`） | 信任域 | 凭据形状 |
|---|---|---|---|
| `webhook` | **adapter callback identity**（适配器回调身份） | 外部系统 → 平台 | `<ADAPTER>_CALLBACK_TOKEN`（O3 冻结：第一版静态 secret，与 3.2 出站凭据同风格；HMAC 留 v2）。**配置项 3.4.4 落地**，本契约只冻结身份形状 |
| `manual_reconcile` | **authenticated operator identity**（认证操作者：token → operator → role） | 人 → 平台 | 复用 3.3 既有 operator 认证链（RBAC executor/admin 属 3.4.5） |

**铁律：**

- `operator` 字段对 `manual_reconcile` 必须是**认证得到的人类操作者**，**绝非** client 自声明字符串。
- `operator` 字段对 `webhook` 必须是**适配器回调身份**，与人类操作者可区分（审计轨迹中人/机身份永不混淆，正如 `execution_log.operator` 之于 dispatch）。
- **禁止复用** `EXECUTION_TOKEN` / `OPERATORS_JSON` 作为 webhook 入站凭据（§8 父文档明确否决）。
- **callback credential 绝不变成 operator credential**，反之亦然。
- 凭据**空配置 = 该适配器入站通道 fail-closed**（与 3.2 出站凭据同规则）——但配置落地属 3.4.4，本契约只冻结"空配置即关闭"的语义。

---

## 9. external_reference semantics

**统一契约字段：`external_reference`（§4 必填）。** 它是"防止一个外部结果被错误归属到另一个 execution"的关键句柄。

adapter 内部**已有**的私有键（**3.4.3 不修改 adapter**，只规定统一 Contract）：

| Adapter | 私有键（现存于 `execution_log.detail` JSON，非冻结列） | 真实代码位置 |
|---|---|---|
| Shuffle | `external_execution_id`（取自 `_EXTERNAL_ID_KEYS=("execution_id","workflow_execution_id","id")` 首个命中） | `shuffle.py:84, 246-255` |
| TheHive | `case_id`（str） | `thehive.py:241-252` |
| Wazuh | `command_id` | `wazuh.py:255-257` |
| Mock | **无**（无出站、无 external reference） | — |

**契约规则：**

1. **归一化到统一字段**：无论 adapter 私有键叫什么，进入本契约时统一表达为 `external_reference`。三家键名差异由**调用方**（3.4.4 webhook 解析 / 3.4.5 read path）在构造 `ExternalObservation` 时吸收，**契约本身只认 `external_reference`**。
2. **missing / 空 → Contract Validation Failure（R，不落 fact）**。禁止降级为 `reconciliation_failed`（§7）。
3. **防错误归属（§8 父文档 Q3）**：`external_reference` + `execution_id` 必须一致地指向同一条已存在执行链；`execution_id` 无法映射到已存在链 → R（拒绝）。所有真实 adapter 出站 body 均内嵌 `sentinelflow_execution_id`，这是 webhook 回传时反向映射回 `execution_id` 的物理前提。
4. **adapter read path 留给 3.4.5**：如何**取得** `external_reference`、如何用它**回查**外部系统读取 external state —— 当前 adapter **均无此读路径**，属 3.4.5 Manual Reconcile 的 adapter 扩展。3.4.3 只冻结"**假设**已拿到 external_reference 与 external_state 时如何归一化"。
5. **存储**：归一化后的 `external_reference` 落入 fact 的 `detail` JSON（model 无 external_reference 冻结列，detail = "Normalized evidence"，与 model docstring 一致）。

---

## 10. observed_at semantics

`observed_at` = **fact time（外部世界被观察到的时刻）**，**不是 ingest time（平台收到事实的时刻）**。model docstring 明确点名："Validation / normalization rules for this timestamp belong to the Reconciliation Contract (3.4.3)"。本契约正式冻结这些规则：

1. **timezone 规则**：`observed_at` **必须是 timezone-aware** datetime。存储列为 `DateTime(timezone=True)`。
2. **naive / aware 处理**：**naive datetime（无 tzinfo）→ Contract Validation Failure（R，不落 fact）**。理由：naive 时间语义歧义（本地？UTC？），fail-closed 拒绝，绝不含糊解释（与项目"Service 先拒"哲学一致）。**禁止**把 naive 默默当作 UTC 或本地时间。
3. **UTC normalization**：所有 aware `observed_at` 在参与推导/存储前**统一归一化为 UTC**。归一化只改变表示（astimezone(UTC)），**不改变时刻语义**。
4. **非法 timestamp 拒绝**：非 datetime 类型、naive、超出合理范围（如早于纪元/明显荒谬的历史时间）→ Contract Validation Failure（R，不落 fact）。
5. **未来时间**：`observed_at` **不得晚于** `server_now + 有界时钟偏移容忍（bounded skew tolerance）`。超出容忍 → Contract Validation Failure（R，不落 fact）。理由：derivation 按 `observed_at DESC` 取最新，一条未来时间戳的 fact 会**错误地永久压制**真实事实。**冻结规则**：有界偏移容忍（proposed default `300s`，精确常量在实现时确认，但"有界 + 超出即拒绝"的规则在此冻结）。
6. **精度处理**：`observed_at` 保留来源提供的**完整精度（至微秒）**，契约**不做截断**。推导 tie-break 为 `(observed_at DESC, id DESC)`（3.4.2 已实现），因此即便 SQLite `CURRENT_TIMESTAMP` 为秒精度、或外部时间戳同秒，`id DESC` 保证确定性——**精度不足由 id 兜底，而非由契约制造伪精度**。

> 上述 6 条是**契约规则**，不是实现。校验/归一化的**运行时落地**（在 3.4.4 webhook 解析或 3.4.5 read path 构造 `ExternalObservation` 时执行）随对应 Step 实现；本 Step 只冻结规则本身。

---

## 11. Append-only rule

- `execution_outcome` 层 **INSERT only**：**no UPDATE、no DELETE**（D3.4-06）。
- **允许重复 reconcile / 重复观察**：同一 `execution_id` 可追加多条 fact，形成时序审计轨迹。
- **绝不通过 UPDATE 覆盖旧事实**：新的观察追加为新行；旧行永久保留。
- **派生态取最新**：`observed_at DESC, id DESC` 的第一条（3.4.2 `derive_outcome_state` / `latest_observation` 已实现，本契约**复用不改**）。
- **重放（replay）惰性**：重放一条**已存在**的旧观察，因其 `observed_at` 不更新、不产生"更晚"的事实，故**不改变派生态**（append-only + 取最新的自然结果）。
- model **无 unique 索引**（晚到/乱序事实一律追加，不拒绝、不覆盖）；组合索引 `(execution_id, observed_at)` **非唯一**，仅服务推导查询路径（O2）。

---

## 12. O5 compatibility（与 Dispatch 历史的关系）

Reconciliation 的结果**不是 Dispatch Result**（D3.4-09 / O5）。两层共存合法性：

| Dispatch（`execution_log`，语义冻结） | Reconcile（`execution_outcome`，本契约产物） | 合法性 |
|---|---|---|
| `succeeded` | `confirmed_failure` | ✅ **合法**：命令送达但外部效果未达成 |
| `failed` | `confirmed_success` | ⚠ **合法，当且仅当**有**真实 external observation**（网络断裂/响应丢失使两层不一致）；人工 reconcile 得到外部事实时如实记录 |
| `failed` | `confirmed_success`（**靠猜测**） | ❌ **禁止**：没有真实外部事实，绝不能臆造 `confirmed_success` |

**铁律：**

- 本契约**永不回写** `execution_log`、**永不改写** dispatch decision、**永不修改**历史 outcome fact（§5 / §6 数据边界）。
- `dispatch=failed` **不因对账而自动变好**：只有拿到真实 external state 并归一化为 `confirmed_success` 才记录该词。
- Outcome 层**只记录事实，不替 Dispatch 改写历史**。

---

## 13. Error / rejection semantics（Contract Validation Failure 家族）

所有契约校验失败**统一归为 Contract Validation Failure（R）**，其共同后果是 **不生成任何 Outcome Fact，只产生审计记录**。建议的失败子族（命名供实现参考，语义在此冻结）：

| 失败子族 | 触发条件 | 落 fact? |
|---|---|---|
| `MissingExternalReference` | `external_reference` 缺失 / 为空 | ❌ |
| `UnrecognizedExternalState` | `external_state` 无法归一化到五词（词表外私有状态） | ❌ |
| `InvalidObservedAt` | naive / 非 datetime / 超范围 / 未来超出有界偏移 | ❌ |
| `UnknownAdapter` | `adapter` 不是已知适配器身份 | ❌ |
| `InvalidSource` | `source` 不是 `webhook` / `manual_reconcile` | ❌ |
| `UnmappableExecutionId` | `execution_id` 无法映射到已存在执行链 | ❌ |

**拒绝语义铁律：**

- **R 绝不是 outcome 词**：拒绝**不落** `reconciliation_failed`、**不落** `unknown`、**不落任何** fact（§0 / §7）。
- **R 只审计**：产生契约/安全审计记录（审计落地形状随 3.4.4/3.4.5），**不写** `execution_outcome`、**不写** `execution_log`。
- **R 与 `reconciliation_failed` 的分界**：`reconciliation_failed` 是**对账动作合格地执行了、但读不到外部状态**（落 fact）；R 是**对账动作的输入契约就不合格**（根本不执行归一化，不落 fact）。
- **先拒哲学**：契约层对非法输入**主动拒绝**，DB 层 CHECK 约束（`ck_execution_outcome_status` / `ck_execution_outcome_source`）是**最后防线**，二者不互相替代。

---

## 14. Relationship with 3.4.2（Pure Derivation）

**3.4.2 `derivation.py` 无需修改，一字不动。** 二者是流水线的相邻两级：

```
External State
      ↓  [3.4.3 Reconciliation Contract]  归一化 + 来源区分 + 失败语义 + 身份 + 时间戳
Outcome Fact（append-only，execution_outcome）
      ↓  [3.4.2 Pure Derivation]  observed_at DESC, id DESC 取首条
Derived Outcome State（五词之一，空集→unknown）
```

- **职责切分**：3.4.3 负责"**外部状态 → 一条可信 fact**"（含拒绝语义）；3.4.2 负责"**多条 fact → 当前派生态**"（纯函数，无副作用）。
- **复用而非改动**：3.4.3 产出的 fact 直接喂给 3.4.2 已冻结的 `derive_outcome_state` / `latest_observation`；本契约**不新增派生逻辑、不修改排序规则**。
- **空集语义一致**：3.4.2 空集 → `unknown`（第 5 个冻结词，非 None）；3.4.3 的 `unknown` 是"有合法 fact 但语义不明"，二者是**不同层面**的 `unknown`（一个是"无 fact"，一个是"有 fact 但不明"），但**共用同一个冻结词**，派生时自然统一。
- **词表单一来源**：3.4.3 与 3.4.2 都只从 `app.models.execution_outcome` 取五词词表，**绝不**与 dispatch DTO（`app.services.executions.models`）的 `{succeeded, failed}` 混淆。

---

## 15. Relationship with 3.4.4 / 3.4.5

本契约是 **push 与 pull 两条来源共用的归一化层**；3.4.4 与 3.4.5 分别是它的两个**调用方**，各自实现"如何构造一个 `ExternalObservation`"：

```
                    ┌─────────────────────────────────────────┐
3.4.4 Webhook (push)│ HTTP endpoint + <ADAPTER>_CALLBACK_TOKEN │ source=webhook
External Callback → │ 身份闸 + Schema 闸 + 归一化闸 + 乱序/重放 │────┐
                    └─────────────────────────────────────────┘    │
                                                                    ▼
                                              ┌──────────────────────────────────┐
                                              │ 3.4.3 Reconciliation Contract     │
                                              │ ExternalObservation → 五词 fact   │→ execution_outcome
                                              │ 或 → Contract Validation Failure  │   (append-only)
                                              └──────────────────────────────────┘
                                                                    ▲
                    ┌─────────────────────────────────────────┐    │
3.4.5 Manual Reconcile│ 操作者触发 API + RBAC(executor/admin)  │ source=manual_reconcile
(pull)              → │ + adapter READ PATH（回查外部系统）     │────┘
                    └─────────────────────────────────────────┘
```

**3.4.4 Webhook / Callback Inbound（依赖本契约）：**

- 实现入站传输：HTTP endpoint、`<ADAPTER>_CALLBACK_TOKEN` 身份闸、Schema 闸（pydantic extra=forbid）、四道入站验证闸的 HTTP 落地、安全审计记录。
- 把回调 payload 解析为一个 `source=webhook` 的 `ExternalObservation`，**调用本契约**归一化。
- 本契约**不含**任何 HTTP / endpoint / 凭据配置落地。

**3.4.5 Manual Reconcile（依赖本契约）：**

- 实现操作者显式触发 API、RBAC（executor/admin）。
- **实现 adapter read path**：新增"回查外部系统、取得 external state"的能力（当前四个 adapter **均无**此读路径，是本契约审计发现的最大缺口）。
- 把读到的外部状态构造为一个 `source=manual_reconcile` 的 `ExternalObservation`，**调用本契约**归一化。
- 本契约**不含**任何 read path / API / RBAC 落地。

**冻结顺序门槛（§10 父文档，用户裁决 2026-09-03）：** 3.4.1–3.4.3 全部完成前，不得提前写 Webhook（3.4.4）。本 Design Freeze 是 3.4.3 的交付；实现（domain types）待用户确认后另行拆步。

---

## 16. Test requirements（测试要求 — 仅定义，本 Step 不实现）

落地实现时**至少**覆盖以下 14 项（对应用户 section 十一）：

| # | 测试要求 | 断言要点 |
|---|---|---|
| 1 | `confirmed_success` mapping | 合法外部"明确成功"状态 → fact `confirmed_success` |
| 2 | `confirmed_failure` mapping | 合法外部"明确失败"状态 → fact `confirmed_failure` |
| 3 | `pending` mapping | 合法外部"处理中"状态 → fact `pending` |
| 4 | `unknown` mapping | **合法**但语义不明的外部状态 → fact `unknown` |
| 5 | `reconciliation_failed` mapping | 对账执行了但**读不到**外部状态 → fact `reconciliation_failed` |
| 6 | unreadable external state | adapter 不可访问/超时 → `reconciliation_failed`（**不是** `confirmed_failure`） |
| 7 | **unrecognized** external state | 词表外私有状态 → **Contract Validation Failure，不落 fact**（**不是** `unknown`） |
| 8 | **missing** external reference | 缺 reference → **Contract Validation Failure，不落 fact**（**不是** `reconciliation_failed`） |
| 9 | mismatched execution identity | `execution_id` 无法映射到已存在链 → 拒绝，不落 fact（防错误归属） |
| 10 | repeated reconciliation | 重复对账 → append 多条 fact，派生取最新（`observed_at DESC, id DESC`） |
| 11 | outcome append-only | 无 UPDATE / 无 DELETE；旧 fact 逐条不变 |
| 12 | `execution_log` 不变 | 对账前后 dispatch 行逐条快照不变（O5） |
| 13 | reconciliation 不触发 execution | 无 executor/adapter/retry/compensation 调用（纯归一化，零执行副作用） |
| 14 | human identity 与 external identity 隔离 | `webhook`→adapter callback identity；`manual_reconcile`→authenticated operator；两域不合并、不复用 `EXECUTION_TOKEN`/`OPERATORS_JSON` |

**补充（本契约特有，建议纳入）：**

- 15 `observed_at` naive → 拒绝（不落 fact）
- 16 `observed_at` 未来超出有界偏移 → 拒绝（不落 fact）
- 17 dispatch 词表与 outcome 词表不相交（`succeeded`/`failed` 不能作为 outcome 归一化目标）
- 18 `unknown`（有 fact 语义不明）与 3.4.2 空集 `unknown`（无 fact）共用同一冻结词但来源不同

---

## 附录 A：Design Freeze 验收前检查（用户 section 十一，10 项）

| # | 检查项 | 结论 | 依据 |
|---|---|---|---|
| 1 | Dispatch vocabulary 与 Outcome vocabulary 不混淆 | ✅ | §6 末（D3.4-04，两词表刻意不相交，CHECK 主动拒绝 dispatch 词） |
| 2 | missing reference 不落 fact | ✅ | §0 行6 / §7 R / §9.2 / §13 `MissingExternalReference` |
| 3 | unknown external state（unrecognized）不落 fact | ✅ | §0 行7 / §6 归一化闸 / §7 R / §13 `UnrecognizedExternalState` |
| 4 | `unknown` 与 `reconciliation_failed` 语义严格区分 | ✅ | §0 铁律 / §7（D vs B，事实来源不同）/ §13 分界 |
| 5 | O5 保持 | ✅ | §12（succeeded+confirmed_failure 合法；failed 不臆造 confirmed_success；永不回写 dispatch） |
| 6 | webhook 与 manual_reconcile 身份域分离 | ✅ | §8（两信任域永不合并；禁复用 EXECUTION_TOKEN/OPERATORS_JSON） |
| 7 | reconcile 不会执行 | ✅ | §3（Reconcile→Execute/Retry/Compensate/Approval/Fan-out 全 ✗）/ §5（输出非执行意图） |
| 8 | external read path 留给 3.4.5 | ✅ | §2 / §9.4 / §15（当前 adapter 无读路径，3.4.5 落地） |
| 9 | `observed_at` 语义完整 | ✅ | §10（timezone/naive-aware/UTC/拒绝/未来时间/精度 六条齐全） |
| 10 | 3.4.2 derivation 无需修改 | ✅ | §14（复用 `derive_outcome_state`/`latest_observation`，一字不动） |

---

## 附录 B：冻结条款索引（本文档新增编号 RC-01 ~ RC-10）

| 编号 | 条款 |
|---|---|
| **RC-01** | Reconciliation 是 Fact Confirmation，不是 Execution；`Reconcile → Execute/Retry/Compensate/Approval/Fan-out` 绝对禁止 |
| **RC-02** | 输入契约 = `ExternalObservation{execution_id, adapter, external_reference, external_state, observed_at, source}`，六字段全必填 |
| **RC-03** | 输出二选一：一条 append-only 五词 fact，**或**一个不落 fact 的 Contract Validation Failure |
| **RC-04** | `unknown`（合法但语义不明，落 fact）≠ `reconciliation_failed`（读不到外部状态，落 fact）≠ `rejected`（契约校验失败，不落 fact）——三态永不合并 |
| **RC-05** | 禁止 `missing reference → reconciliation_failed`；禁止 `unrecognized state → unknown` |
| **RC-06** | dispatch 词表 `{succeeded,failed}` 永不直接等价映射为 outcome 五词（D3.4-04） |
| **RC-07** | `webhook`→adapter callback identity；`manual_reconcile`→authenticated operator；两信任域永不合并；禁复用 `EXECUTION_TOKEN`/`OPERATORS_JSON`（D3.4-07） |
| **RC-08** | `external_reference` 为统一契约字段，吸收 adapter 私有键差异；3.4.3 不改 adapter，read path 留 3.4.5 |
| **RC-09** | `observed_at` = fact time（非 ingest time）；aware-only、UTC 归一化、naive/非法/未来超界一律拒绝、精度不截断 |
| **RC-10** | Outcome 层 append-only（INSERT only，no UPDATE/DELETE）；允许重复观察；派生取 `observed_at DESC, id DESC`；O5 永不回写 dispatch |

---

> **本文档为 3.4.3 Design Freeze 交付物，CONTRACT ONLY，不含任何实现。** 实现（domain contract / types）待用户确认后按 §15 另行拆步；3.4.4 Webhook 与 3.4.5 Manual Reconcile 在各自 Step 落地传输与读取，本契约保持冻结。
