# Phase 3.4.5-B0 设计：Wazuh Mapping Amendment（3.4.3-B Wazuh 词表证据重裁）

> 状态：**设计提案（Design Proposal）** —— 2026-09-07 用户三项裁决后开立的独立 Mapping Amendment Gate；本轮 **DESIGN ONLY**，待用户 Review 后再进入独立的 **Amendment Implementation Gate**（届时才落生产代码）。
> 范围：Phase 3.4.5-B0 —— 只重新裁定 **3.4.3-B 中 Wazuh 外部状态词表的证据基础**（success / failure / pending / unknown / reference / timestamp / auth），并给出 **去锚定（de-anchoring）策略** 与 **跨门 blast radius**。
> **不实现**：WazuhReadAdapter（§九）、任何 read endpoint 客户端、任何生产代码修改（§十七）。
> 基线：HEAD `abf26a7`（A2-F 封板）；**3.4.3-B `8b89fe7`（词表冻结，§四 禁止直接修改 / amend / force-push）**；3.4.4-D `192f615`；3.4.4-E `9119036`；3.4.4-F `fb56bf3`；A2-E `9bfe13b`；3.2.4 Wazuh write adapter（`executions/wazuh.py`，已封板）。
> 前置：`3.4.5-B Wazuh Evidence Audit`（上一轮交付，结论 **NOT READY + §二十三 Mapping Conflict**）+ `phase3.4-manual-reconcile.md` §16（Wazuh 已记为 Evidence Gap）+ `phase3.4-reconciliation-contract.md`（§6 归一化闸 / §13 拒绝语义）。
> 日期：2026-09-07
> 命名：遵现有目录规范 `phase3.4-*`；B0 是 3.4.5-B 之前的 **前置证据修正门**，不是新的 Phase。
> **性质：DESIGN ONLY。本文档不实现任何代码**（§十七）：不新增 `WazuhReadAdapter`、不修改 `reconciliation.py` / `mapping.py` / `executions/wazuh.py` / 任何测试 / migration。落地拆步见 §15 与 §18。

---

## 0. 冻结摘要（TL;DR）

**用户三项裁决（2026-09-07）：**

1. **生产 Wazuh 版本先不假定**：本次审计对象 = 仓库 `5.1.0-alpha0`，**不等于**生产部署版本已确认；两者必须分开记录（§1）。
2. **Read Path 选 Option 3**：Wazuh 命令级 external effect 当前 **Evidence-Gapped**，保持 fail-closed；**不**用 `GET /agents`（agent 连接态 ≠ 命令结果）、**不**用 Indexer 触发记录直接产生 confirmed_success/failure（§5/§6）。
3. **Mapping Amendment 批准，独立进行**：3.4.3-B 的 Wazuh 词表证据基础已被证伪，必须重裁；**禁止直接改 `8b89fe7`**，另立本 B0 门（§16）。

**本设计的核心结论：**

- **Selected Strategy = Option 3**：Wazuh command-level reconciliation **unsupported / Evidence-Gapped**；`ADAPTER_STATE_VOCABULARIES["wazuh"]` 四集 **全部裁定为 ∅**（§8-§11），与 shuffle/thehive/mock 结构一致。
- **Previous Mapping = INVALID**：`{completed,confirmed,done,success,ok}→confirmed_success`、`running→pending`、`unknown→unknown` 的原始证据（`wazuh.py:94-99` 常量 + 注释）来自 **write 适配器的虚构同步 dispatch 响应**，非真实 Wazuh command-lifecycle 状态（§4）。
- **关键架构发现（本门最重要的新认知）**：`ADAPTER_STATE_VOCABULARIES["wazuh"]` 是 **path-agnostic 的单一语义映射**，经 `mapping.py:103 → normalize_external_state` 被 **LIVE 的 webhook 入站路径（3.4.4-D/E，已封板）** 复用，**不是** 仅供未来 read path 的 dormant 词表。**因此无法"只空 read 不空 webhook"**：清空 Wazuh 词表必然同时改变已封板 3.4.4 webhook 的 LIVE 行为（§15）。
- **Blast radius = 六道已封板门**：3.4.3-B / 3.4.4-D / 3.4.4-E / 3.4.4-F / A2-E / A2-F 的测试均 pin 了 Wazuh success 词表；其中 `test_reconciliation.py:1126 test_only_wazuh_has_an_evidenced_vocabulary` 的**前提会被反转**（清空后**无任何** adapter 拥有 evidenced 词表）（§15）。
- **去锚定不削弱安全（§十二）**：把 `terminal_success_states == _CONFIRMED_AGENT_STATUSES` 的交叉锚定，**替换为更强的 fail-closed pin**（Wazuh 四集全空 + 每个 Wazuh 状态被 refused）；平台管线的 confirmed_success 端到端证明 **迁移到一个显式 test-only fake adapter+vocabulary**（诚实 test double，不做任何生产 adapter 声明），**不删测**（§15）。
- **本轮零生产代码**：Amendment 的实际落地（改词表 + 去锚定 + 重定向测试）是 **独立后续 Gate**，需用户授权；本轮只交付本设计文档 + 验收报告（§17/§18）。

---

## 1. Version Scope（§一 — 版本域分离）

**铁律：仓库审计对象 ≠ 生产部署版本。二者分开记录，绝不混同。**

| 版本域 | 值 | 证据 | 状态 |
|---|---|---|---|
| **仓库审计对象** | Wazuh **5.1.0-alpha0** | `wazuh-main/VERSION.json` + `wazuh-docker-main/VERSION.json` 双证 `{"version":"5.1.0","stage":"alpha0"}` | CONFIRMED（仅对仓库源码成立） |
| **生产部署版本** | **UNKNOWN** | 无部署环境 / 生产 VERSION.json / `GET /` API info 证据 | **未确认** |

**约束：**

- 本文档所有关于"真实 Wazuh 行为"的结论 **仅对 5.1.0-alpha0 成立**。5.x 是 Indexer-based AR + comms-agent 新架构，与 4.x 有实质差异。
- **官方当前在线文档展示的是另一条版本线**（用户裁决①）：不得拿当前官网页面字段直接替换 5.1.0-alpha0 的结论；官方在线文档只能作为**交叉印证**，不能反证仓库版本。
- **若生产环境确为 5.1.0-alpha0** → 本 Audit 可作为正式版本基线；**若为 4.x / 其它 5.x** → 必须重做**版本化 Evidence Audit**，本 B0 结论不自动适用。
- **Production Version 确认路径**（进入 Implementation Gate 前必须完成）：部署环境实测 / 生产 `VERSION.json` / `GET /`（API info endpoint）三选一明确确认。

---

## 2. Evidence Sources（§二 / §六 — 证据来源与优先级）

**Evidence Hierarchy（§六，严格降序）：**

1. 官方**版本对应** API documentation（5.1.0 对应线，非当前官网通用页）
2. 官方源码（`wazuh-main/framework`、`wazuh-main/api`）
3. 官方 response schema / OpenAPI（`api/api/spec/spec.yaml`）
4. 实际真实实例返回（生产/ staging 实测 —— 本轮**无**）
5. 当前仓库代码（`sentinelflow/backend` —— **最低优先级**，且已被证伪为虚构证据来源）

**禁止来源（§六）：** 博客 / 经验贴 / **字段名称推断** / **HTTP status 猜测** / **write response 推断 read state**。

**本设计采信的四个一手来源（均本轮或上一轮 Evidence Audit 直接 Read/Grep 验证）：**

| 源 | 文件 | 关键证据 | 优先级 |
|---|---|---|---|
| **S1 官方 OpenAPI** | `wazuh-main/api/api/spec/spec.yaml` | `AgentStatus` enum（L920-927）；真实 `agent_status` 响应示例 = 连接汇总（L8863-8869）；无 `/alerts`、无 `/tasks`、无 command-status read、`command_id` 0 匹配；JWT auth（L11-14） | 3 |
| **S2 官方源码** | `wazuh-main/framework/wazuh/core/indexer/active_response.py` | `AR_INDEX="wazuh-active-responses*"`（L24）；`AR_SCHEMA` 无 status/result 字段（L25-77）；dispatch 经 Task Manager socket 返回 `{"status":"ok","task_id":...}`（L516-522） | 2 |
| **S3 仓库 write 适配器** | `sentinelflow/backend/app/services/executions/wazuh.py` | `_CONFIRMED_AGENT_STATUSES`（L94-99）；虚构 endpoint `POST /api/v1/agents/{target}/active-response`（L190）；`command_id` 可选（L255-257） | 5（**最低，且为虚构证据根源**） |
| **S4 已封板映射** | `sentinelflow/backend/app/services/outcomes/reconciliation.py` | Wazuh 词表（L487-527）；anchor docstring（L82-83） | 5 |

**冲突处理（§二十六）**：S1/S2（官方）与 S3/S4（仓库）冲突时，**以官方为准**，明确报告冲突，**不自行选"看起来合理"的**。本 B0 的全部裁定均以 S1/S2 推翻 S3/S4。

---

## 3. Previous Mapping（§三 — 3.4.3-B 旧词表全貌）

**`reconciliation.py:487-527`（8b89fe7 冻结，禁改）：**

```python
"wazuh": AdapterStateVocabulary(
    adapter="wazuh",
    terminal_success_states=frozenset({"completed","confirmed","done","success","ok"}),
    terminal_failure_states=frozenset(),          # 已 EMPTY（fail-closed，正确）
    pending_states=frozenset({"running"}),
    ambiguous_states=frozenset({"unknown"}),
    case_insensitive=True,                         # 证据: wazuh.py:246 lower-case
    state_key="agent_status",                      # 证据: wazuh.py:243
    evidence="wazuh.py _CONFIRMED_AGENT_STATUSES (L97-99) + agent_status comment (L94-96)",
)
```

**旧证据出处（唯一来源 = write 适配器）：**

- `wazuh.py:94-99`：`_CONFIRMED_AGENT_STATUSES = frozenset({"completed","confirmed","done","success","ok"})`，注释 *"agent_status values that still count as an unambiguous synchronous confirmation"*。
- `wazuh.py:94-96` 注释举例 `"unknown"` / `"running"` —— **pending/unknown 词表的"证据"其实只是一句代码注释**。
- `reconciliation.py:82-83` anchor docstring：*"a test cross-checks the Wazuh set against `wazuh._CONFIRMED_AGENT_STATUSES` so the link can never silently drift"*。
- Anchor test：`test_reconciliation.py:754-759` `assert vocab.terminal_success_states == _CONFIRMED_AGENT_STATUSES`。

**旧词表的语义定位（3.4.3-B 自己的注释 reconciliation.py:489-495）**：声称 *"Wazuh active-response is SYNCHRONOUS ... so agent_status IS the effect status"*。**本 B0 §4 将证明这个"SYNCHRONOUS effect status"前提本身是虚构的。**

---

## 4. Evidence Failure（§四 — 旧证据为何不可信）

**四重冲突（继承 Evidence Audit 的 §二十三 Mapping Conflict，全部以 S1/S2 坐实）：**

**冲突 1 — dispatch endpoint 不存在。** `wazuh.py:190` 的 `POST /api/v1/agents/{target}/active-response` 在真实 5.1.0 `spec.yaml` 的 `/agents*` 路径全集中**不存在**；`active-response` 在 spec.yaml 里**仅是一个 config `section` 查询参数枚举值**，不是命令下发 REST 路径。真实 AR 下发经 **Indexer 索引 + Task Manager TCP socket**（S2），非 REST。

**冲突 2 — reference `command_id` 无真实对应（§六停止条件）。** `spec.yaml` 全库 `command_id` **0 匹配**。真实 AR dispatch 返回的是 Task Manager 内部 `task_id`（`active_response.py:520`），且经 socket 而非 REST，**没有可供外部命令级 outcome read 的 reference**。

**冲突 3 — success/pending/unknown 词表非真实 command-lifecycle 状态（本门核心）：**

- 真实 `AgentStatus` enum（`spec.yaml:920-927`）= **{active, pending, never_connected, disconnected}**，官方描述 *"calculated based on the last keepalive and the Wazuh version"* —— 这是 **agent 连接/生命周期状态**，与"某条 Active Response 命令是否成功执行"**无关**。
- 真实响应里字面名为 `agent_status` 的字段（`spec.yaml:8863-8869`）是一个 **连接状态汇总**（active/disconnected/never_connected/pending 计数），**不是命令结果**。
- 旧 success 词表 `{completed,confirmed,done,success,ok}` **无一** 出现在真实 `AgentStatus` enum 中。
- 真实 `AR_SCHEMA`（`active_response.py:25-77`）字段 = {agent_id, executable, extra_arguments, location, name, stateful_timeout, type}，**无任何 status/result/success 字段** —— AR 索引记录描述"**要执行什么响应**"（触发事实），**不描述"执行结果"**。
- **"ok" 的假朋友陷阱**：真实 AR 代码里确有一处 `"ok"`（`active_response.py:519` `response.get("status")=="ok"`），但它是 **Task Manager 对 `create_task` 的受理状态**（任务已创建），**不是命令 terminal effect**。这正是 B 规格 §四 "**Command Accepted ≠ Command Completed Successfully**" 的活体反例 —— 按字段名/词匹配 "ok" 会把"任务已受理"误判为"命令已成功"。
- **"pending" 的假朋友陷阱**：真实 `AgentStatus` 有 `pending`，但其语义 = **已注册但从未首次连接的 agent**（`never_connected` 同族），**≠ 命令执行中**。旧词表把 `running→pending` 建立在注释臆想上，与真实 `pending` 语义完全错位。

**冲突 4 — auth 模型不一致。** 真实 5.1.0 = **JWT**（`POST /security/user/authenticate` 用 basicAuth 换 token，后续 `Authorization: Bearer`，`spec.yaml:11-14`）；`wazuh.py` write 适配器用**每次请求直接 Basic**（非 JWT）。

**根因（Design Freeze 自身已承认）**：`phase3.4-manual-reconcile.md:346` §16 已记录 *"成功侧 `agent_status` 词表来自 write 响应体，**非 read/poll endpoint**"*。本 B0 用 S1/S2 把这句"待外部证据"的悬置**坐实为证伪**：write 响应体所依赖的同步 active-response REST 契约**在真实 5.1.0 根本不存在**，因此从它派生的一切 read 状态词表**都是虚构证据**。

**结论：Previous Mapping = INVALID。** 旧词表**不得**继续视为有效证据（用户裁决③），除非本 B0 重新获得可信证明 —— 而 B0 未能获得（§5-§13 逐项 FAIL）。

---

## 5. Candidate Read Paths（§五.1 / §七 / §八 — 候选读路径）

**§七 四类 read capability 必须严格区分，四者都不能混为 external effect confirmation：**

| 类 | 能力 | 真实 5.1.0 是否存在 | 能否证明"命令最终效果" |
|---|---|---|---|
| **A. dispatch endpoint** | 下发命令 | Indexer + Task Manager socket（非 REST）；write 适配器假设的 REST 路径**不存在** | ❌ 下发 ≠ 效果 |
| **B. read endpoint** | 查询某次命令结果 | **不存在**（spec.yaml 无 command-status / `/tasks` / `/alerts` REST read） | —— |
| **C. Indexer/event observation** | 观测 AR 索引记录 | 存在（`wazuh-active-responses*`），但记录 = **触发事实**，AR_SCHEMA 无 result 字段 | ❌ 触发 ≠ terminal effect |
| **D. agent liveness** | 查询 agent 连接态 | 存在（`GET /agents`，AgentStatus enum） | ❌ 连接态 ≠ 命令结果 |

**三个候选 outcome read path 的评估（§八）：**

- **Option A — `GET /agents`（agent liveness）**：**拒绝**（用户裁决②）。agent status {active/pending/never_connected/disconnected} 是连接/生命周期态，**不能证明某条 Active Response 命令已成功执行**。结构上不得据此产出 confirmed_success/failure。
- **Option B — Indexer `wazuh-active-responses*` 直查（event observation）**：**拒绝**。AR 索引记录描述"响应任务/触发事实"（AR_SCHEMA 无 status/result），**不是可靠的 terminal effect result**；其 `@timestamp` 是 trigger time（§12）。
- **Option C — 命令级 read endpoint**：**不存在**（§4 冲突 1/2）。真实 5.1.0 无 REST 命令结果读回。

**§八 三选一裁定：**

- Option 1（存在可信 command-result read path）：**否**（Option C 不存在）。
- Option 2（存在可验证的 external effect evidence aggregation）：**否**（Indexer 记录无 result 字段，agent liveness 非命令态，无可靠聚合源）。
- **Option 3（command-level reconciliation unsupported）：✔ 选中**（默认值，且无新的可靠证据推翻）。

---

## 6. Selected Read Path（§六 / §九 — 裁定）

**Selected Strategy = Option 3：Wazuh command-level reconciliation unsupported / Evidence-Gapped。**

```
Manual Reconcile
      ↓
Wazuh
      ↓
No trustworthy command-effect read capability
      ↓
UnsupportedAdapterRead / Evidence-Gapped（fail-closed，不落 fact）
```

**裁定细则（§九）：**

- **不创建 `WazuhReadAdapter`**；**不创建 fake production reader**。
- 保留平台侧已封板的 `UnsupportedAdapterRead` 行为（A2 已实现：无 reader → rejected，不请求外部、不落 fact、仅审计）。
- **不得**为了"把 Wazuh 做出来"而用 Agent status / HTTP 200 / Indexer 触发记录去猜成功（用户裁决②原文）。
- Wazuh `confirmed_failure` **继续 fail-closed**（词表本就 EMPTY，§9）。

---

## 7. Reference（§五.2 — external_reference 重裁）

| 项 | 旧假设 | 真实 5.1.0 证据 | 裁定 |
|---|---|---|---|
| external reference | `command_id`（`wazuh.py:255-257` 可选，取自虚构同步响应；`reconciliation` 侧 `_EXTERNAL_REFERENCE_KEYS["wazuh"]="command_id"`） | `spec.yaml` `command_id` **0 匹配**；真实 AR dispatch 返回 Task Manager 内部 `task_id`（`active_response.py:520`），经 socket 非 REST，**无命令级 read 可引用** | **FAIL** |

**结论**：不存在可用于命令级 outcome read 的真实 external reference。`command_id` 是 write 适配器虚构契约的产物；`task_id` 是内部 Task Manager 句柄，**无 REST read 语义**。既然 Selected Strategy = Option 3（无 read path），reference 问题在本门**判定为 FAIL 且不再进一步设计**（无 read path → 无需 reference）。

---

## 8. Success Mapping（§五.4 / §十 / §十一 — 四段证据链）

**§十一 要求：任何保留的状态必须建立 `state → evidence → semantic meaning → outcome` 四段证据链，不能只写词表。** 对旧 success 词逐段检验：

| state | evidence（真实来源） | semantic meaning | outcome | 裁定 |
|---|---|---|---|---|
| `completed` | 仅 `wazuh.py:97` 常量（虚构同步响应） | 真实 5.1.0 无此 AgentStatus / 无 AR result 字段 | —— | **证据链断裂** |
| `confirmed` | 同上 | 同上 | —— | **断裂** |
| `done` | 同上 | 同上 | —— | **断裂** |
| `success` | 同上 | 真实 AgentStatus 无 `success`；AR_SCHEMA 无 result | —— | **断裂** |
| `ok` | 同上 | 真实 `"ok"` = Task Manager **任务受理**态（`active_response.py:519`），**非命令效果** | —— | **断裂（假朋友）** |

**§十 铁律**：不得仅因旧代码存在这些词就保留 `success→confirmed_success`。五词的 evidence 段**全部指向虚构的 write 响应体**，semantic 段**全部无法对应真实命令效果**。

**裁定：`terminal_success_states = ∅`。** Wazuh 无任何可信 terminal-success 证据。

---

## 9. Failure Mapping（§五.5 / §十三 — B 最大新任务）

- 旧词表 `terminal_failure_states` **本就 EMPTY**（`reconciliation.py:505`），且注释明确 Wazuh 的 failure 词（adapter_unavailable/timeout/adapter_error）是 **DISPATCH 层 transport 分类，非 external agent_status**。
- 本轮重新在 S1/S2 中寻找真实的 external terminal-failure command vocabulary：**未找到**。真实 5.1.0 无 REST 命令结果读，AR_SCHEMA 无 result/failure 字段，AgentStatus enum 无 failure 语义。
- **§十三 铁律**：没有官方 API / 真实 response 证据证明某状态代表 external execution failure，**继续 fail-closed**，**绝不虚构** confirmed_failure。

**裁定：`terminal_failure_states = ∅`（维持 EMPTY）。** `confirmed_failure` 继续 fail-closed。

---

## 10. Pending Mapping（§五.6）

| state | 旧 evidence | 真实语义 | 裁定 |
|---|---|---|---|
| `running` | `wazuh.py:94-96` **注释**（"leaves the fact undecided"） | 真实 AgentStatus enum **无 `running`**；真实 `pending` = 已注册未首连（≠ 命令执行中） | **断裂** |

**§十 铁律**：不得仅因旧代码注释存在 `running` 就保留 `running→pending`。

**裁定：`pending_states = ∅`。**

---

## 11. Unknown Mapping（§五.7）

| state | 旧 evidence | 真实语义 | 裁定 |
|---|---|---|---|
| `unknown` | `wazuh.py:94-96` **注释** | 真实 AgentStatus enum **无 `unknown`**；无 AR result 字段可表达 unknown | **断裂** |

**注意**：此处清空的是"**把 `unknown` 作为一个 in-vocabulary 合法 Wazuh 状态**"的映射；平台侧 `UnrecognizedExternalState`（词表外一律 refused，NEVER 降级为 unknown）的 §0 铁律**不受影响、继续生效** —— 清空后 Wazuh 的**任何**状态（含字面 `unknown`）都走 refused 路径，比旧行为**更 fail-closed**。

**裁定：`ambiguous_states = ∅`。**

---

## 12. Timestamp（§五.8 / §十三）

- 真实 AR 索引记录带 `@timestamp`，其语义 = **触发时间（trigger time）**，即"规则/事件触发了这条 active-response"的时刻。
- **不存在**代表"命令 terminal effect 完成时刻"的可靠外部 timestamp（AR_SCHEMA 无 result/completed_at 字段；无命令结果 read）。
- **§十三 铁律**：**不得把 trigger time 伪装成 effect completion time**。

**裁定：Timestamp = FAIL。** 无可靠 effect time；即便未来走 Indexer observation，其 `@timestamp` 也**只能**标注为 trigger/observation 语义，**绝不**得作为 confirmed_success 的 effect 时间。既然 Option 3 无 read path，本门不进一步设计 observed_at 来源（平台侧 `validate_observation` 的 UTC/skew 规则已封板，adapter-agnostic）。

---

## 13. Auth（§五.11 / §十四）

**§十四 铁律：Operator Auth ≠ Wazuh API Auth。**

| 信任域 | 凭据 | 与本门关系 |
|---|---|---|
| Human Operator | `EXECUTION_TOKEN` / `OPERATORS_JSON` | 决定"谁能触发 Reconcile"；**与 Wazuh API 无关** |
| Wazuh API（真实 5.1.0） | **JWT**（`POST /security/user/authenticate` basicAuth 换 token） | write 适配器用的是 **Basic**（不一致）；read path 若存在须用 JWT |
| Inbound Callback | `WAZUH_CALLBACK_TOKEN` | **绝不可**用于 Manual Reconcile / read（RC-07） |

**裁定：Auth = FAIL（就命令级 outcome read 而言）。**

- 真实 5.1.0 read（若未来存在）需 **JWT**，须**单独记录/设计**，**不得复用** `WAZUH_CALLBACK_TOKEN`、**不得复用** operator token。
- 既然 Option 3 = 无 read path，本门**不设计** Wazuh read auth；仅记录"未来若开 read path，auth 必须 JWT + server-side credential 单独设计"作为约束。
- write 适配器 Basic vs 真实 JWT 的不一致属 **dispatch 层**问题，**超出 B0 范围**（§15 coherence caveat）。

---

## 14. Security（§五.9 / §五.10 / §十五）

**read failure / not found（§五.9 / §五.10）：** 既然无 read path，二者对 Wazuh outcome read 均 **N/A**。平台侧已封板的 adapter-agnostic 语义**继续有效、不因本门改变**：

- transport 失败（timeout / 连接拒绝 / DNS / 5xx / 不可达）→ `ReadTransportError` → `reconciliation_failed`（A2-D 封板），**绝不** confirmed_failure。
- 无 reader / unsupported → `UnsupportedAdapterRead` → rejected（不落 fact）。

**credential（§十五）：**

- 若未来 Indexer/API read path 需要 credential：**先做 Design，不 coding，不写入 repo，不默认 secret**。
- 本轮**不新增** `WAZUH_INDEXER_*` / JWT token 交换等任何 credential 配置。
- raw_evidence：未来若有 read，必须经 `redact_detail()`，禁止保存 API key / Authorization / password / token（继承 §十五 / A2 已封板纪律）。

**Security 裁定：PASS（就本门"零代码、不引入新凭据、不扩大攻击面"而言）。** 本门不新增任何 secret / endpoint / 出站调用。

---

## 15. Mapping Test Changes（§十二 — 去锚定 + blast radius，本门最关键的工程约束）

### 15.1 关键架构发现：词表是 path-agnostic 单一映射

`webhook.py:147-149 persist_callback_outcome → map_external_state`（`mapping.py:103`）`→ normalize_external_state → ADAPTER_STATE_VOCABULARIES["wazuh"]`。**同一条链**既是 3.4.4 webhook 入站的 Gate 4，也是未来 3.4.5 read path 的映射。`mapping.py:23-25` 明确"**NO second mapping table**"。

**因此：无法"只空 read 不空 webhook"。** 清空 Wazuh 词表**必然**改变已封板 3.4.4 webhook 的 LIVE 行为：

- **BEFORE**：`POST /webhook/wazuh` `{external_state:"success"}` → 200 `{accepted:true}`，append 一条 `confirmed_success` fact。
- **AFTER**：同一请求 → `UnrecognizedExternalState` → **不落 fact** → router 映射为 4xx（依 rejected matrix，unsupported external state → **422**）。
- 这是**更 fail-closed、且正确**的行为（一个自称 "success" 的 Wazuh callback 不是可信命令效果证据）。**本门明确披露此 LIVE 行为变化**，它正是 §四 禁止把 amendment 偷偷塞进 B、必须独立成门的原因。

### 15.2 完整 blast radius（六道已封板门 + 生产常量）

| 门 | commit | 文件:行 | pin 内容 | 清空后 |
|---|---|---|---|---|
| 3.4.3-B | 8b89fe7 | `test_reconciliation.py:743-752` | 5 success 词 → confirmed_success | **反转为 refused** |
| 3.4.3-B | 8b89fe7 | `test_reconciliation.py:754-759` | **ANCHOR** `vocab.terminal_success_states == _CONFIRMED_AGENT_STATUSES` | **去锚定（见 15.3）** |
| 3.4.3-B | 8b89fe7 | `test_reconciliation.py:771-785` | `running→pending`、`unknown→unknown` | **反转为 refused** |
| 3.4.3-B | 8b89fe7 | `test_reconciliation.py:796-816` | agent_status key form / case-insensitive / no-trim | **反转/移除（无词可折叠）** |
| 3.4.3-B | 8b89fe7 | `test_reconciliation.py:1018-1024` | test_20 isolation（wazuh 词可映射，他家 refused） | **反转（wazuh 亦 refused）** |
| 3.4.3-B | 8b89fe7 | `test_reconciliation.py:1121-1124` | `set(VOCAB) == set(ADAPTER_NAMES)` | **保留**（表仍在，只是空） |
| 3.4.3-B | 8b89fe7 | `test_reconciliation.py:1126` | `test_only_wazuh_has_an_evidenced_vocabulary` | **前提反转 → 改为 no adapter has evidenced vocab** |
| 3.4.4-D | 192f615 | `test_mapping.py:136-160` | TestWazuhEvidencedMapping（5 词 + running + unknown + case + key） | **全部反转为 refused** |
| 3.4.4-E | 9119036 | `test_webhook_persistence.py:311-350` | Wazuh callback → confirmed_success fact（HTTP 200） | **重定向到 test double（见 15.4）+ Wazuh 专项反转为 refused/422** |
| 3.4.4-F | fb56bf3 | `test_webhook_security.py:243-366` | `_body`/`_observation` 默认 `external_state="success"`、`adapter="wazuh"`（依赖成功 persist 做 redaction 断言） | **fixture 重定向到 test double** |
| A2-E | 9bfe13b | `test_manual_reconcile_mapping.py:20-45,175-178,432-435` | `FakeReadAdapter("wazuh", "success")` → confirmed_success；O5 dispatch 独立性 | **重定向到 test double** |
| A2-F | abf26a7 | `test_manual_reconcile_crosslayer.py:21-22,184-186,455-475` | 全 HTTP 栈 Wazuh success → confirmed_success in DB | **重定向到 test double** |
| 3.2.4 write | （封板） | `wazuh.py:94-99 _CONFIRMED_AGENT_STATUSES` | dispatch 响应解析（execution_log Dispatch Fact） | **UNTOUCHED（§十七）** |

### 15.3 去锚定策略（§十二 — 替换过时证据来源，不削弱安全）

**旧 anchor 的问题**：`test_reconciliation.py:754-759` 把 outcome 词表锁到 dispatch 常量 `_CONFIRMED_AGENT_STATUSES`，其**前提**是"该常量是有效 command-lifecycle 证据"。§4 已证伪该前提 —— anchor 实际把 outcome 词表锁到了**虚构证据**。

**去锚定 = 用更强的 fail-closed pin 替换（安全只增不减）：**

1. **删除** `test_reconciliation.py:81` 的 `from ...wazuh import _CONFIRMED_AGENT_STATUSES` —— outcome 词表**不再引用** dispatch 常量。
2. **替换** anchor test 为：`ADAPTER_STATE_VOCABULARIES["wazuh"]` **四集全空**（mirror 现有 shuffle/thehive/mock 的 empty-pin：`test_reconciliation.py:834-839 / 903-908 / 958-963`）。
3. **新增** pin：Wazuh 的**每一个** external_state（含旧 5 success 词、`running`、`unknown`）都被 `UnrecognizedExternalState` refused。
4. **反转** `test_only_wazuh_has_an_evidenced_vocabulary`（L1126）→ `test_no_adapter_has_an_evidenced_vocabulary`（四家全空），反映诚实的 post-amendment 状态。

**安全性对比**：BEFORE 一个虚构词可流向 confirmed_success；AFTER 每个 Wazuh 状态被 refused 且空集被 pin 死，**无法被静默重新虚构**。"link can never silently drift" 的性质**保留**，只是 link 从"outcome vocab == dispatch 常量"变为"outcome vocab 恒空且被 pin"。**§十二 满足：替换过时证据来源，不削弱测试安全性。**

### 15.4 平台管线 confirmed_success 证明的保留（不删测）

**问题**：清空 Wazuh 后，**无任何生产 adapter 拥有 evidenced success 词表**。而 webhook（3.4.4-E）与 manual reconcile（A2-E/A2-F）的测试**当前正是用 Wazuh "success"** 证明"`external_state → confirmed_success → persist → 200`"这条平台管线端到端可用。

**裁定：这些管线证明必须保留（删测 = 削弱安全），但证据来源必须从"虚构 Wazuh 词表"迁移到"显式 test double"：**

- 引入一个 **test-only fake adapter identity + test-only evidenced vocabulary**，经 `monkeypatch` 临时注入 `ADAPTER_STATE_VOCABULARIES`（及管线需要校验 adapter 身份时的 `ADAPTER_NAMES`），**仅供管线测试使用**，**不做任何生产 adapter 声明**；monkeypatch 自动回滚，生产态四家恒空，`set(VOCAB)==set(ADAPTER_NAMES)` pin 在**未 monkeypatch 的生产态**上运行，无冲突。
- A2-E/A2-F 的 `FakeReadAdapter` 从 `name="wazuh"` **重定向**到该 test-only fake adapter；其 `_result("success")` 经 test-only 词表映射，继续证明 read → validate → map → confirmed_success → persist → 200 全链。
- webhook 3.4.4-E 的"成功 persist"管线证明**同样重定向**到 test double；**Wazuh 专项** webhook 测试**反转**为断言 Wazuh callback → refused（422，不落 fact）。
- 如此**两个性质都被证明**：(a) 平台管线对**可映射状态**端到端可用；(b) **Wazuh 具体**是 Evidence-Gapped、被 refused。

> **实现细节边界**：test double 的**确切机制**（专用 fake adapter 名 vs. monkeypatch 现有 adapter 词表）在 **Implementation Gate** 最终确定；本 B0 只冻结**要求**（管线证明必须保留 + 不得依赖任何虚构生产词表 + 生产四家恒空）与**推荐方案**（专用 test-only fake adapter，最诚实、隔离最清晰）。

### 15.5 coherence caveat（明确划出 B0 范围之外）

write 适配器 `wazuh.py` 的 dispatch 层（`_CONFIRMED_AGENT_STATUSES` 用于解析同步 dispatch 响应 → `succeeded`，execution_log Dispatch Fact）**与本门清空的 outcome 词表共享同一批虚构词**。但：

- **B0 范围 = outcome 映射层**（reconciliation 词表），**不含** dispatch 层重裁（§十七 禁改 existing Wazuh adapter）。
- dispatch 层依赖的虚构同步 active-response 契约是否需回溯修正，属**独立议题**（类比 A2-F §三十一"不借当前门重构无关的已封板层"），**另立门**处理，**不在 B0**。
- 本门只做一件事：**切断 outcome 映射对 dispatch 常量的锚定依赖**，使 outcome 层不再继承 dispatch 层的虚构证据。

---

## 16. Relationship to 3.4.3-B（§四 — 禁改纪律）

- **禁止直接修改 `8b89fe7`**；**禁止 amend**；**禁止 force-push**；**禁止在 B implementation 中偷偷改词表**（用户裁决③/§四）。
- Amendment = **一个新的 forward commit**（在独立 Implementation Gate 落地），**不改写历史**。
- **不改** `MAPPABLE_OUTCOME_STATUSES`（`reconciliation.py:450`）、`normalize_external_state` 的结构与拒绝语义（L650-716）、`StateMapping.__post_init__` 的 reconciliation_failed 结构性排除（L606-623）、`UnrecognizedExternalState` 的 §0 铁律。**只改** Wazuh 词表**内容**（四集 → ∅、case_insensitive → False、state_key → None，与 shuffle/thehive/mock 结构对齐）+ evidence 字符串（改引本 B0 裁决）+ 去锚定 + 测试重定向。
- 3.4.3-A（validate_observation）、3.4.2（derivation）**完全不受影响**。

---

## 17. Relationship to WazuhReadAdapter（§九 / §十七）

- **本轮不建 `WazuhReadAdapter`**；不建 fake production reader；保留 `UnsupportedAdapterRead`（§6/§九）。
- Selected Strategy = Option 3 → Wazuh **命令级 read unsupported**；因此**当前不存在** WazuhReadAdapter 的合法实现基础。
- **未来路径**（若生产版本确认 + 获得真实命令级 read 证据）：必须**重做版本化 Evidence Audit → Design Freeze（`phase3.4-wazuh-read-adapter.md`）→ 才实现 reader**；本 B0 的清空裁定是那条路的**前置**（先把虚构证据清干净），**不是** reader 实现。
- **read/write 物理隔离**（继承 §十八 / A1 `read/base.py`）：未来若建 WazuhReadAdapter，**禁止 import `executions/wazuh.py`**；ReadAdapter 唯一动词 `read()`，结构性无 execute/compensate/dispatch。

---

## 18. Final Decision（§十八 — 裁定汇总 + 实施边界）

### 18.1 裁定汇总

| 项 | 裁定 | 依据 |
|---|---|---|
| **Production Version** | **UNKNOWN**（仓库审计对象 = 5.1.0-alpha0，生产未确认） | §1 |
| **Read Capability** | **EVIDENCE-GAPPED**（Option 3） | §5/§6 |
| **Reference** | **FAIL**（command_id 无真实对应；task_id 非 REST read） | §7 |
| **Success Evidence** | **FAIL**（5 词证据链全断裂） | §8 |
| **Failure Evidence** | **FAIL**（真实无 terminal-failure 命令词表；维持 ∅ fail-closed） | §9 |
| **Pending Evidence** | **FAIL**（running 来自注释；真实 pending 是连接态假朋友） | §10 |
| **Unknown Evidence** | **FAIL**（unknown 来自注释；真实 enum 无 unknown） | §11 |
| **Timestamp** | **FAIL**（仅 trigger time，无 effect time；禁伪装） | §12 |
| **Auth** | **FAIL**（真实 JWT vs write Basic 不一致；read auth 未设计） | §13 |
| **Previous Mapping** | **INVALID**（证据 = 虚构 write 响应体，非 command-lifecycle） | §4 |
| **Selected Strategy** | **Option 3 — command-level reconciliation unsupported / Evidence-Gapped；Wazuh 词表四集全空** | §6/§8-§11 |
| **3.4.3-B Amendment Needed** | **YES**（但**本轮不落代码**；独立 Implementation Gate 以 forward commit 执行，禁改 8b89fe7） | §15/§16 |

### 18.2 词表最终裁定（经 B0 Design Review，非先验写死）

```python
"wazuh": AdapterStateVocabulary(
    adapter="wazuh",
    terminal_success_states=frozenset(),   # §8  ∅
    terminal_failure_states=frozenset(),   # §9  ∅（维持）
    pending_states=frozenset(),            # §10 ∅
    ambiguous_states=frozenset(),          # §11 ∅
    case_insensitive=False,                # 无词可折叠，与 shuffle/thehive/mock 对齐
    state_key=None,                        # 无 evidenced state word
    evidence="3.4.5-B0: Wazuh command-level outcome Evidence-Gapped (Option 3); "
             "prior {completed,confirmed,done,success,ok}/running/unknown traced to a "
             "fictional synchronous active-response write contract, refuted by real "
             "5.1.0 spec.yaml AgentStatus + AR_SCHEMA (no command-effect read).",
)
```

> **§八/§十 合规声明**：此"全空"结论**不是先验写死**，而是 §5-§13 逐项证据检验后**推理得出**（每个旧词的 evidence 段均断裂）。若 Implementation Gate 前出现新的可靠证据（真实版本确认 + 真实命令级 read path），本裁定**必须重开**。

### 18.3 实施边界（本轮零代码 → 独立后续 Gate）

- **本轮（B0 Design）**：仅交付本设计文档 + 验收报告；**零生产代码**（§十七）；commit 仅含本 `.md`。
- **后续（Amendment Implementation Gate，需用户授权）**：按 §15 落地 —— 清空 Wazuh 词表（forward commit）+ 去锚定（15.3）+ 平台管线证明迁移到 test double（15.4）+ webhook/Wazuh 专项测试反转（15.2）+ 全量回归。**禁改 8b89fe7 / 禁 amend / 禁 force-push**。
- **再后续（可选，独立议题）**：dispatch 层虚构契约的 coherence 修正（§15.5），**另立门**。
- **Wazuh reader**：仅在"生产版本确认 + 真实命令级 read 证据 + 新 Design Freeze"后（§17），**当前 Evidence-Gapped**。

### 18.4 停止声明

本 B0 设计到此完成。**不进入 WazuhReadAdapter implementation**（§九/§十七/用户裁决）。在用户 Review 本设计并授权 Amendment Implementation Gate 之前：**不修改 `reconciliation.py` / `mapping.py` / `wazuh.py` / 任何测试**；Wazuh `confirmed_failure` 及四侧词表**继续保持 fail-closed**（当前生产态仍是 8b89fe7 冻结的旧词表，本门**未**改动它 —— 改动属 Implementation Gate）。
