# Phase 3.4.5-G1-A — Wazuh Runtime Safety Evidence Report

## §0 Document Control

| 项 | 值 |
|---|---|
| **标题** | Phase 3.4.5-G1-A Wazuh Runtime Safety Evidence Report |
| **状态** | **REVIEWED — Historical Evidence**（用户 G1-D Final Review 裁决 PASS，2026-09-08）。本报告为「修复前」只读安全取证快照，CONFIRMED UNSAFE / NOT VERIFIED / BLOCKED 取证结论原样保留、不倒写；修复后前向引用见 §0.1。本次经 **G1-D Final Documentation Commit** 授权本地提交（THREE DOCUMENTS ONLY · LOCAL COMMIT · NO PUSH） |
| **适用 Phase** | 3.4.5-G1-A Wazuh Runtime Safety Evidence Gate（只读安全取证） |
| **编制日期** | 2026-09-08 |
| **基线 HEAD** | `73b9c8b`（branch `main`；`origin/main` `ffa3087`；ahead **22** / behind 0） |
| **授权** | **READ-ONLY · NO CODE · NO COMMIT**（只读源码/配置/测试/历史设计；隔离 mock 级验证；不修改任何文件；不 commit / 不 push；不进 G1-B/G1-C；不启动真实外部执行；不向真实 Wazuh 发请求；不用生产凭据） |
| **取证方式** | fresh 源码逐行核验 + **本轮隔离 mock 级 runtime 实测**（`.venv` + `-p no:cacheprovider`，TestClient + 内存 SQLite；测试后 Git 零副作用） |
| **上游输入** | Consolidation DRAFT（`phase3.4.5-external-adapter-evidence-consolidation.md` §8.2）；3.4.3-B 原始 mapping（`8b89fe7`，禁改）；B0/B0.1（`phase3.4-wazuh-mapping-amendment.md`，DESIGN ONLY） |

> **三态纪律（严格遵守用户安全裁决）：**
> - **VERIFIED** = 防护/事实已被源码 + runtime 证明存在且有效。
> - **NOT VERIFIED** = 防护未被证明（设计要求 ≠ 已验证事实）。
> - **CONFIRMED UNSAFE** = 实际不安全代码路径已被 runtime 证明可达。
> - **CONFIRMED UNSAFE（代码路径可达）≠「已发生生产事故」**：本仓库 Wazuh 未配置、未 co-deploy（`config.py:144` 空、`sentinelflow/docker-compose.yml` 仅 postgres），**本仓库不存在真实被污染事实**；其他实际部署的暴露与否须由部署负责人核查。
> - **绝不描述为「运行时已安全」。**

### §0.1 G1-C 后续进展前向引用（G1-D 安全收口补充，2026-09-08）

> **本报告为「修复前」只读安全取证快照，取证结论（CONFIRMED UNSAFE / NOT VERIFIED / BLOCKED）原样保留，不倒写为「修复前已安全」。** 本节仅追加**修复后**的前向引用供追溯；**不修改** §1–§12 任何取证判定。

- **本报告取证基线：** `73b9c8b`（ahead 22 / behind 0）。所有 F-1..F-12 裁决（含 F-4 / F-11 的 NOT VERIFIED）、§3.3 runtime 实测、§4 Q3 防护门结论均为**该基线（修复前）**的事实。
- **后续修复（不在本报告范围）：** G1-B 设计（FROZEN）→ **G1-C 落地 commit `0c372aa`**（parent `73b9c8b`；清空 `ADAPTER_STATE_VOCABULARIES["wazuh"]` 四集 + `case_insensitive=False` + `state_key=None`；单一前向原子提交；`8b89fe7` 未改写）。
- **修复后当前状态（用户 G1-C Final Review 裁决）：** Wazuh Runtime Safety Gate = **`VERIFIED — scoped`**（限已审计入站映射路径 + 隔离回归环境；生产部署与历史数据安全仍未验证）。完整闭环记录见 **G1-B §15** 与 **Consolidation §8.2.B**。
- **关键纪律（不倒写）：** 本报告的 **CONFIRMED UNSAFE（F-2/F-7）指「修复前代码路径 runtime 可达」**，是**修复的动因**；G1-C 清空词表**消除**了该可达性，但**不改写**「修复前曾可达」这一取证事实，也**不**意味本报告当时「已安全」。R-1/R-3 在修复前 CONFIRMED，G1-C 后分别 VERIFIED-scoped / RESOLVED（见 Consolidation §8.1）。
- **本轮（G1-D）对本报告的操作：** 仅追加本前向引用；**未修改** §1–§12 取证正文；本报告保持 **DRAFT · READ-ONLY 取证性质**。

---

## §1 三态裁决摘要

| # | 命题 | 裁决 | 承载证据 |
|---|---|---|---|
| F-1 | Wazuh 旧非空词表是 **LIVE 生产代码**（`8b89fe7`，B0 Amendment 未实施） | **CONFIRMED（源码）** | `reconciliation.py:486-527` |
| F-2 | webhook 路径：配置 `WAZUH_CALLBACK_TOKEN` 后，`{completed,confirmed,done,success,ok}→confirmed_success`、`running→pending`、`unknown→unknown` **可达并落 fact（HTTP 200）** | **CONFIRMED UNSAFE（runtime 实测）** | 8 节点 PASSED（§3.3）；`test_webhook_persistence.py:311-336` |
| F-3 | webhook 路径**无 confirmed_failure 可达路径**（`terminal_failure_states=∅`） | **VERIFIED（源码 + runtime）** | `reconciliation.py:505`；无 confirmed_failure 参数化节点 |
| F-4 | webhook 入站**唯一防护门 = `WAZUH_CALLBACK_TOKEN=""` 配置默认**（运维可逆，非语义门） | **NOT VERIFIED（作为语义安全门）** | `webhooks.py:172-184`；`config.py:143-145` |
| F-5 | **无版本门 / 无 feature flag / 无 adapter 门**覆盖入站映射（`normalize:677` 无条件读词表） | **CONFIRMED（源码）** | `reconciliation.py:677`；`config.py:46`（`EXECUTION_ADAPTER` 仅管出站） |
| F-6 | manual reconcile **生产路径**由空 registry 结构性拦截（404、零 fact） | **VERIFIED（源码 + runtime）** | `registry.py:74-82`；`manual_reconcile.py:366`；4 节点 PASSED（§6.3） |
| F-7 | manual 路径安全是**「无 reader 的 absence 门」，非语义门**——注入 `FakeReadAdapter("wazuh")` 后同一不安全映射经全 HTTP 栈亦可达 | **CONFIRMED UNSAFE（runtime 实测，条件性）** | 3 节点 PASSED（§6.3）`TestHttpToDbSuccess` |
| F-8 | `map_external_state` 生产调用点**仅两处**：webhook + manual_persist（path-agnostic 单一映射，无第二套表） | **VERIFIED（源码）** | `webhook.py:149`；`manual_persist.py:204`；`mapping.py:103` |
| F-9 | EXECUTION_TOKEN / operator / callback / api-key **四域凭据隔离**保持 | **VERIFIED（源码 + runtime）** | `config.py:55/64/143-145/93-102`；3 隔离节点 PASSED（§5.2） |
| F-10 | `execution_outcome` **append-only**（INSERT-only、无 unique index、无 UPDATE/DELETE） | **VERIFIED（源码）** | `execution_outcome.py:63/67/141` |
| F-11 | Wazuh **整体 Runtime Safety Gate** | **NOT VERIFIED / BLOCKED** | F-4 + F-5 + F-7：唯一门运维可逆、无语义门、absence 门不覆盖未来注册 |
| F-12 | 本仓库**无真实数据污染证据**（未配置/未部署真实 Wazuh） | **VERIFIED（缺省态）** | `config.py:93-102/143-145`；`docker-compose.yml` 仅 postgres |

**结论：** Wazuh webhook 不安全映射 = **CONFIRMED UNSAFE（隔离 runtime 可达）**；整体 Runtime Safety Gate = **NOT VERIFIED / BLOCKED**。**这不等于已发生生产事故**（本仓库无真实 Wazuh）。修复必须在 **mapping 层单点**（F-7/F-8），而非任一 HTTP handler 表面检查。

---

## §2 Q1 — 实际调用链（HTTP 入口 → outcome persistence）

**逐段（file : function : line），全部 fresh 源码核验：**

| 段 | 文件:行 | 函数 | 作用 |
|---|---|---|---|
| 1. HTTP 路由 | `api/v1/webhooks.py:188` | `receive_adapter_callback`（`@router.post("/{adapter}", status_code=200)`） | Wazuh webhook LIVE 入口 |
| 2. Gate 1 认证（依赖，先跑） | `api/v1/webhooks.py:136-185` | `authenticate_callback` | `:159` allow-list 取 `WAZUH_CALLBACK_TOKEN`；`:172` `expected=getattr(settings,setting_name,"")`；`:179-184` 空/不匹配→401 |
| 3. Gate 2 Schema | `api/v1/webhooks.py:218` | `to_external_observation(payload, adapter=authenticated_adapter)` | 折入**服务端**可信 adapter + 冻结 `source="webhook"`（非 body 字段） |
| 4. 委托持久化 | `api/v1/webhooks.py:220` | `persist_callback_outcome(db, observation)` | **唯一生产调用点**（其余全是测试引用） |
| 5. Gate 2 契约 | `services/outcomes/webhook.py:147` | `validate_observation(observation)` | → `NormalizedObservation`；失败 `ContractValidationFailure`→零 fact |
| 6. Gate 3 关联 | `services/outcomes/webhook.py:148` | `correlate_execution(session, normalized.execution_id)` | SELECT `execution_log`（只读）；失败 `UnmappableExecutionId`→404 |
| 7. **Gate 4 语义映射（不安全点）** | `services/outcomes/webhook.py:149` | `map_external_state(normalized)` | **调用不安全映射** |
| 8. 纯委托 | `services/outcomes/mapping.py:103` | `map_external_state` → `normalize_external_state` | 明确「NO second mapping table/DTO」 |
| 9. 归一化闸 | `services/outcomes/reconciliation.py:650-716` | `normalize_external_state` | `:677` **无条件**读 `ADAPTER_STATE_VOCABULARIES[adapter]`；`:690-697` 成员判定；`:698-705` 词表外→`UnrecognizedExternalState` |
| 10. Wazuh 词表（LIVE 非空） | `services/outcomes/reconciliation.py:486-527` | `ADAPTER_STATE_VOCABULARIES["wazuh"]` | success`{completed,confirmed,done,success,ok}`/pending`{running}`/ambiguous`{unknown}`/failure`∅` |
| 11. 构造 fact | `services/outcomes/webhook.py:165-173` | `ExecutionOutcomeFact(...)` | `:167` `outcome_status=mapping.outcome_status`；`:169` `operator=f"adapter:{normalized.adapter}"` |
| 12. 落库 | `services/outcomes/webhook.py:176-178` | `session.add/flush/commit` | append-only INSERT；`:179-187` 失败→rollback→`OutcomePersistenceError`→500 |
| 13. HTTP 映射 | `api/v1/webhooks.py:221-233` | `receive_adapter_callback` except | `:221-224` 404；`:225-228` `ContractValidationFailure`→**422**；`:229-232` 500；`:233` `{"accepted":true}` |

**关键：第 7→9→10 段是不安全映射的实际链路；第 13 段的 422（`:225-228`）是词表外状态的既有拒绝契约（G1-B 复用点）。**

---

## §3 Q2 — 可达性矩阵

### 3.1 词表→outcome（源码，`reconciliation.py:486-527` + `normalize:690-697`）

| 旧状态词 | 词表集 | 行 | → outcome_status | 分支行 | 可达性 |
|---|---|---|---|---|---|
| `completed` | terminal_success | `:496-498` | `confirmed_success` | `:690-691` | **CONFIRMED UNSAFE（runtime）** |
| `confirmed` | terminal_success | `:496-498` | `confirmed_success` | `:690-691` | **CONFIRMED UNSAFE（runtime）** |
| `done` | terminal_success | `:496-498` | `confirmed_success` | `:690-691` | **CONFIRMED UNSAFE（runtime）** |
| `success` | terminal_success | `:496-498` | `confirmed_success` | `:690-691` | **CONFIRMED UNSAFE（runtime）** |
| `ok` | terminal_success | `:496-498` | `confirmed_success` | `:690-691` | **CONFIRMED UNSAFE（runtime）** |
| `running` | pending | `:509` | `pending` | `:694-695` | **CONFIRMED UNSAFE（runtime）** |
| `unknown` | ambiguous | `:515` | `unknown` | `:696-697` | **CONFIRMED UNSAFE（runtime）** |
| （任何词表外词） | — | — | `UnrecognizedExternalState`→422、零 fact | `:698-705` | **VERIFIED fail-closed** |

### 3.2 confirmed_failure 路径分析

- `terminal_failure_states=frozenset()`（`reconciliation.py:505`）= **空**。
- `normalize:692-693` 的 confirmed_failure 分支**存在但永不命中**（Wazuh failure 集为空）。
- **无 confirmed_failure 参数化测试节点**（§3.3 的 8 节点无 `[...-confirmed_failure]`）——与 `terminal_failure=∅` 一致。
- `test_reconciliation.py:768` pin `terminal_failure_states==frozenset()`；`:761-769` 断言 `failed/error/failure/aborted` 被 **refused**（不映射 confirmed_failure）。
- **结论：不存在 Wazuh confirmed_failure 可达路径（VERIFIED）。** 不安全面仅在 confirmed_success / pending / unknown 三态。

### 3.3 runtime 实测节点（`test_webhook_persistence.py`，8 passed / 52 deselected）

```
TestSuccessfulPersistence::test_wazuh_confirmed_success_appends_one_fact                     PASSED
TestSuccessfulPersistence::test_wazuh_vocabulary_maps_to_outcome[completed-confirmed_success] PASSED
TestSuccessfulPersistence::test_wazuh_vocabulary_maps_to_outcome[confirmed-confirmed_success] PASSED
TestSuccessfulPersistence::test_wazuh_vocabulary_maps_to_outcome[done-confirmed_success]      PASSED
TestSuccessfulPersistence::test_wazuh_vocabulary_maps_to_outcome[success-confirmed_success]   PASSED
TestSuccessfulPersistence::test_wazuh_vocabulary_maps_to_outcome[ok-confirmed_success]        PASSED
TestSuccessfulPersistence::test_wazuh_vocabulary_maps_to_outcome[running-pending]             PASSED
TestSuccessfulPersistence::test_wazuh_vocabulary_maps_to_outcome[unknown-unknown]             PASSED
```

> 经**真实 HTTP POST + 配置 token**（`all_tokens` fixture）→ 200 + `fact.outcome_status` 落库（`test_webhook_persistence.py:311-336`）。这是**本轮 runtime 实测**，非静态断言。

---

## §4 Q3 — 防护门清单

| 门类型 | 是否存在 | 默认值 | 检查位置 | 可绕过路径 | 裁决 |
|---|---|---|---|---|---|
| **版本门** | ❌ 无 | — | `normalize:677` **无条件**读词表，无版本判定 | 不适用（根本不存在） | **CONFIRMED 无版本门** |
| **feature flag** | ❌ 无 | — | 全链路无 flag 分支 | 不适用 | **CONFIRMED 无 flag** |
| **Adapter 门（出站）** | ⚠️ 有但**不覆盖入站** | `EXECUTION_ADAPTER`（`config.py:46`） | 仅管出站 dispatch adapter 选择 | **入站 webhook 不经此门** | **NOT APPLICABLE to webhook** |
| **配置门（callback token）** | ✅ 有（唯一入站门） | `WAZUH_CALLBACK_TOKEN=""`（`config.py:144`） | `webhooks.py:172-184`（空/不匹配→401） | **运维配置该 token 即开启**（真实集成的预期动作） | **NOT VERIFIED（作为语义安全门）** |
| **allow-list 门** | ✅ 有 | wazuh 在列（`webhooks.py:83`） | `webhooks.py:159-165`（不在列→404） | wazuh **已在** allow-list，路由 LIVE | **不拦截 wazuh** |
| **registry 门（manual 专属）** | ✅ 有 | 空 registry（`registry.py:74-82`） | `manual_reconcile.py:366` | **不覆盖 webhook**；未来注册 reader 即失效 | **VERIFIED（仅 manual，absence 门）** |
| **schema 边界门** | ✅ 有 | `extra="forbid"`（`schemas/webhook.py:81`） | Gate 2 | 阻止 body 走私 source/adapter/operator/outcome_status，**不阻止 external_state 词值** | **VERIFIED（边界，非语义）** |

**Q3 结论：** 针对 Wazuh 不安全映射的**唯一入站防护 = `WAZUH_CALLBACK_TOKEN=""` 配置默认门**（运维可逆、非语义）；**无版本门、无 feature flag、无 adapter 门覆盖入站**。→ 整体 **NOT VERIFIED / BLOCKED**（F-11）。

---

## §5 Q4 — 凭据隔离（本轮不修改认证机制）

### 5.1 四域分离（源码，`config.py`）

| 域 | 设置项 | 行 | 用途 | 隔离性 |
|---|---|---|---|---|
| 执行令牌 | `EXECUTION_TOKEN` | `:55` | 人工写路径（执行触发） | 独立 |
| 运营者凭据 | `OPERATORS_JSON` | `:64` | 人工运营者身份 | 独立 |
| **回调令牌** | `*_CALLBACK_TOKEN`（含 `WAZUH_CALLBACK_TOKEN`） | `:143-145` | **入站 adapter 回调**（Gate 1） | 独立 |
| 出站 API 凭据 | `*_BASE_URL` / `*_API_KEY` / `WAZUH_API_USER/PASSWORD` | `:93-102` | 出站 dispatch | 独立 |

- `webhooks.py:17-24` docstring 固化：回调凭据与人工写路径凭据**两个 trust domain 永不合并、永不回退**。
- Gate 1（`authenticate_callback`）自建 constant-time 比对，**不借用**任何人工身份机制（`webhooks.py:22-24`）。

### 5.2 runtime 隔离节点（`test_webhook_authentication.py`，PASSED）

```
TestOperatorIsolation::test_19_no_execution_token_fallback                 PASSED  (回调不回退 EXECUTION_TOKEN)
TestOperatorIsolation::test_20_no_operators_json_dependency                PASSED  (回调不依赖 OPERATORS_JSON)
TestImportSurface::test_source_never_references_operator_trust_domain      PASSED  (源码不引用运营者 trust domain)
```

**Q4 结论：EXECUTION_TOKEN / operator / callback / api-key 四域隔离 VERIFIED（源码 + runtime）。本轮不修改认证机制。**

---

## §6 Q5 — 其他入口是否复用同一不安全映射

### 6.1 生产入口完备性（源码）

- `map_external_state` 生产调用点**仅两处**（Grep 全仓确认，其余全是测试引用）：
  1. `services/outcomes/webhook.py:149`（webhook 路径，§2）。
  2. `services/outcomes/manual_persist.py:204`（**manual reconcile 成功管线**）。
- `mapping.py:103` 是**纯委托** → `normalize_external_state`；明确「NO second mapping table」→ **path-agnostic 单一映射**（B0 §15.1）。
- 两个入站 outcome 路由：`webhooks.py:188`（webhook）+ `reconcile.py:111`（manual reconcile）。**无第三入口、无直接 service 旁路。**

### 6.2 manual reconcile 路径的门顺序（源码，`manual_reconcile.py`）

- `:366` `resolved = registry if registry is not None else default_read_adapter_registry()`（默认 **EMPTY**）。
- wazuh 无 reader → `registry.get("wazuh")` raise `UnsupportedAdapterRead`（`:349-352`，是 `ReadAdapterError` sibling）。
- `:369` transport except **只捕** `ReadTransportError/TimeoutError/ConnectionError/OSError`，**不捕** `UnsupportedAdapterRead` → 传播 **404、零 fact**，**在到达 `manual_persist.py:204` map 之前即被结构性拦截**。
- `:411-419` 读失败路径**内联**建 `reconciliation_failed`，**根本不调 map**。

### 6.3 runtime 双重事实（`test_manual_reconcile_crosslayer.py`，7 passed / 60 deselected）

**A. 生产结构门 VERIFIED（`TestProductionRegistryEmpty`）：**
```
test_default_registry_rejects_every_adapter        PASSED  (空 registry 拒绝每个 adapter)
test_production_http_path_404_without_injection     PASSED  (生产 HTTP 路径无注入→404)
test_injection_does_not_mutate_production_default   PASSED  (注入不改生产默认)
test_no_real_read_adapter_wired                     PASSED  (无真实 reader 接线)
```

**B. 但同一不安全映射经 manual 路径亦可达（`TestHttpToDbSuccess`，注入 test-only `FakeReadAdapter("wazuh")`）：**
```
test_http_wazuh_success_to_confirmed_success_in_db  PASSED  (全 HTTP 栈→confirmed_success in DB)
test_http_wazuh_running_to_pending_in_db            PASSED
test_http_wazuh_unknown_to_unknown_in_db            PASSED
```

**Q5 结论（关键）：** manual 路径的**生产**安全 = **「无 reader 的 absence 门」（VERIFIED），非语义门**。一旦未来 Gate 注册 `WazuhReadAdapter` 而**未先清空词表**，manual 路径同样 LIVE 不安全（B 组已 runtime 证明可达）。→ **修复必须在 mapping 层（path-agnostic 单点清空），而非某个 HTTP handler 表面检查**（正是用户 §3.A 要求）。

---

## §7 Q6 — 历史 Outcome 影响（只读排查方案）

### 7.1 append-only 不变量（源码，`execution_outcome.py`）

- `:63` INSERT-only，**无 UPDATE/DELETE** 方法。
- `:67` **deliberately NO unique index**（时间序列即审计轨迹）。
- `:94-98` 非唯一 Index；`:141` **无 `updated_at`**。
- `operator` 格式 = `adapter:{identity}`（`webhook.py:169`）→ **只读排查键 = `operator='adapter:wazuh'`**。

### 7.2 只读查询方案（仅统计，不修改/删除/重写）

```sql
-- 只读：统计可能由旧 Wazuh mapping 产生的历史事实（按不安全三态）
SELECT outcome_status, count(*)
FROM execution_outcome
WHERE operator = 'adapter:wazuh'
  AND outcome_status IN ('confirmed_success', 'pending', 'unknown')
GROUP BY outcome_status;

-- 只读：明细分页（供人工复核，绝不 UPDATE/DELETE）
SELECT id, execution_id, outcome_status, source, operator, observed_at, created_at
FROM execution_outcome
WHERE operator = 'adapter:wazuh'
  AND outcome_status IN ('confirmed_success', 'pending', 'unknown')
ORDER BY created_at;
```

### 7.3 本仓库实际状态

- `config.py:93-102`（`WAZUH_BASE_URL=""`/`WAZUH_API_USER=""`/`WAZUH_API_PASSWORD=""`）+ `:143-145`（`WAZUH_CALLBACK_TOKEN=""`）→ **未配置真实 Wazuh**。
- `sentinelflow/docker-compose.yml` **仅部署 postgres**（无 wazuh 服务）→ **未 co-deploy**。
- **预期结果：本仓库该查询返回 0 行**（无真实污染事实）。**CONFIRMED UNSAFE（代码路径可达）≠ 已发生生产事故。**
- **其他实际部署**：须由**部署负责人**核查是否暴露该入口，并通过**已验证的入口控制**暂停回调；**不得假定清空 token 或某个尚未验证的开关一定有效**。

**Q6 结论：append-only VERIFIED；提供只读统计/明细查询方案；本仓库预期零污染；撤销/标注/数据修复机制 = 另设独立 Gate（本轮不设计、不执行）。**

---

## §8 Q7 — 最小安全修复候选（不改旧冻结契约）

> 本节为**候选证据**，供 G1-B Design Freeze 采用；**本轮不实施**。

### 8.1 候选方案（B0 Option-3 前向提交）

- **唯一修改点：** `reconciliation.py:486-527` 的 `ADAPTER_STATE_VOCABULARIES["wazuh"]` **内容**——四集全空 + `case_insensitive=False` + `state_key=None`（= B0 §18.2 目标代码）。
- **机制：** 清空后 `normalize:677` 读到空词表 → 任何 Wazuh 词命中 `:698-705` else → `UnrecognizedExternalState`（`:197`，是 `ContractValidationFailure` 子类）→ `webhooks.py:225-228` → **422、零 fact**。
- **path-agnostic 单点覆盖：** 因 `mapping.py:103`「NO second mapping」，单点清空**同时**封住 webhook（`:149`）+ manual_persist（`:204`）+ 任何直接 service 调用（F-7/F-8）。
- **无需新 HTTP 行为：** 完全复用既有 422 拒绝契约（`webhooks.py:51-52` docstring 固化「refused state is a 422」）。
- **不违反铁律：** 不降级 `unknown`（refused=零 fact，非 unknown fact）；不伪装 `reconciliation_failed`（`StateMapping.__post_init__:615-623` 结构性排除）。

### 8.2 禁改纪律（B0 §16）

- **新 forward commit**；**禁改 / 禁 amend / 禁 force-push** `8b89fe7`、B0（`b0a5962`）、B0.1（`73b9c8b`）。
- **只改 Wazuh 词表内容**；**禁改** `MAPPABLE_OUTCOME_STATUSES`（`:450`）、`normalize_external_state` 结构（`:650-716`）、`StateMapping.__post_init__`（`:606-623`）、`UnrecognizedExternalState`（`:197`）、Shuffle/TheHive/Mock 词表（`:528-583`）。

### 8.3 将反转的测试锚点（de-anchor / migrate，**不删测**）

| 测试锚点 | 现状 | 修复后 | 处置 |
|---|---|---|---|
| `test_reconciliation.py:743-752`（5 词→confirmed_success） | 断言映射成功 | **反转为 refused** | 改断言（前向） |
| `test_reconciliation.py:754-759` ANCHOR `==_CONFIRMED_AGENT_STATUSES`（`:81` import） | 锚定旧词表 | **去锚定** | 删 `:81` import → 更强 fail-closed pin（安全只增不减） |
| `test_reconciliation.py:771-777`（running→pending） | 断言 pending | **反转为 refused** | 改断言 |
| `test_reconciliation.py:779-785`（unknown→unknown） | 断言 unknown | **反转为 refused** | 改断言 |
| `test_reconciliation.py:796-811`（key/case 断言） | 部分有效 | **部分反转** | 逐项复核 |
| `test_reconciliation.py:1126 test_only_wazuh_has_an_evidenced_vocabulary`（`:1134-1135` 断言 wazuh 非空） | 前提=wazuh 唯一非空 | **前提反转** | 改为「无任何 adapter 有 evidenced 词表」 |
| `test_webhook_persistence.py:311-336`（wazuh 8 节点） | confirmed_success/pending/unknown | **反转为 422 零 fact** | 改断言（前向） |
| `test_manual_reconcile_crosslayer.py` `TestHttpToDbSuccess`（注入 fake） | 可达 confirmed_success | **反转为 refused** | 平台管线证明**迁 test-only fake adapter**（B0 §15.4，不删测） |
| `test_reconciliation.py:761-769/787-794/813-816/1121-1124` | failure gap / refused / keys==ADAPTER_NAMES | **保持有效** | 不动 |

### 8.4 非回归保证（Shuffle / TheHive / 平台）

- **Shuffle/TheHive/Mock 词表已全空**（`:528-583`）→ 清空 Wazuh **不触碰**它们，行为零变化。
- **平台通用契约不变：** `MAPPABLE`/`normalize` 结构/`StateMapping`/`UnrecognizedExternalState`/四域凭据/append-only/422 拒绝契约**均不改**。
- **blast radius（B0 §15.2）：** 六道已封板门（3.4.3-B / 3.4.4-D/E/F / A2-E/F）中，仅**Wazuh 词表内容**相关断言反转；结构与安全语义**只增不减**。

---

## §9 运行时测试证据（命令 + 结果 + 隔离声明）

### 9.1 实际执行命令（本轮 fresh，`.venv` + `-p no:cacheprovider`）

```
# [1] webhook 持久化 + 认证（计数）
.venv\Scripts\python.exe -m pytest tests/test_webhook_persistence.py tests/test_webhook_authentication.py -p no:cacheprovider -q
# [2] crosslayer 结构门（计数）
.venv\Scripts\python.exe -m pytest tests/test_manual_reconcile_crosslayer.py -p no:cacheprovider -q
# [3] wazuh 可达节点
.venv\Scripts\python.exe -m pytest tests/test_webhook_persistence.py -p no:cacheprovider -v -k wazuh
# [4] auth 门 + 凭据隔离节点
.venv\Scripts\python.exe -m pytest tests/test_webhook_authentication.py -p no:cacheprovider -v -k "valid_wazuh or unconfigured or execution_token or operators_json or trust_domain or writes_no_outcome"
# [5] crosslayer 结构门 + manual 可达节点
.venv\Scripts\python.exe -m pytest tests/test_manual_reconcile_crosslayer.py -p no:cacheprovider -v -k "registry or production or no_real or wazuh"
```

### 9.2 结果

| 运行 | 结果 | 关键节点 |
|---|---|---|
| [1] persistence+auth | **115 passed**（2.26s） | — |
| [2] crosslayer | **67 passed**（2.98s） | — |
| [3] wazuh 可达 | **8 passed / 52 deselected** | §3.3（5 success + running + unknown + 1 fact 计数） |
| [4] auth 门+隔离 | **9 passed / 46 deselected** | `test_5_valid_wazuh_token`（配置 token→门开）、`test_unconfigured_channel_via_http_is_401`（空→401）、`test_endpoint_writes_no_outcome_fact`（拒绝→零 fact）、`test_19/20/trust_domain`（Q4 隔离） |
| [5] crosslayer 门+可达 | **7 passed / 60 deselected** | §6.3（4 结构门 + 3 注入可达） |

### 9.3 隔离声明

- **mock 级隔离：** TestClient + 内存 SQLite；**未连接真实 Wazuh**、**未向真实 Wazuh 发请求**、**未使用生产凭据**、**未修改任何测试文件**、`-p no:cacheprovider` **未写缓存**。
- **测试后 Git 零副作用：** `git status --short` 仍仅那份未跟踪 Consolidation 文档；tracked diff 空；排除该文档后 untracked **全空**（无 `__pycache__`/`.pytest_cache` 泄漏）。
- **未运行的测试：** 除上述 5 条命令外，**未运行**全量测试套件、**未运行**任何真实外部执行/集成测试。

---

## §10 证据位置索引（consolidated）

| 主题 | 文件:行 |
|---|---|
| Wazuh LIVE 非空词表 | `reconciliation.py:486-527`（success `:496-498` / failure ∅ `:505` / pending `:509` / ambiguous `:515` / case `:519` / state_key `:522`） |
| 虚构注释残留（R-3） | `reconciliation.py:489-495`（"agent_status IS the effect status"） |
| 归一化闸（无版本门） | `reconciliation.py:650-716`（`:677` 无条件读词表 / `:690-697` 四分支 / `:698-705` refused） |
| 拒绝异常层级 | `reconciliation.py:134`（`ContractValidationFailure`）← `:197`（`UnrecognizedExternalState`） |
| reconciliation_failed 结构守卫 | `reconciliation.py:606-623`（`StateMapping.__post_init__`） |
| MAPPABLE | `reconciliation.py:450` |
| webhook HTTP 入口 + 门 + 422 | `webhooks.py:81-85/136-185/188/218-233`（`:172` expected / `:179-184` 401 / `:225-228` 422） |
| webhook 持久化 + map 调用 | `webhook.py:147-149/165-173/176-187`（`:149` map / `:167` outcome_status / `:169` operator） |
| mapping 纯委托 | `mapping.py:103`（NO second mapping） |
| manual 第二入口 | `manual_persist.py:204` |
| manual 结构门 | `manual_reconcile.py:366/369/349-352/411-419`；`registry.py:74-82` |
| 配置门 + 四域凭据 | `config.py:46/55/64/93-102/143-145` |
| append-only 模型 | `execution_outcome.py:63/67/94-98/141` |
| schema 边界 | `schemas/webhook.py:81/85/89-120` |
| 平台契约（case_id 强制/Dispatch≠Outcome） | `manual-reconcile.md:146-161/293-296` |
| B0/B0.1 设计 | `phase3.4-wazuh-mapping-amendment.md`（§15.1 path-agnostic / §15.2 blast radius / §15.3 去锚定 / §15.4 迁 fake / §16 禁改 / §18.2 目标代码） |

---

## §11 Git 状态

| 项 | 值 |
|---|---|
| HEAD | `73b9c8b`（未变，= B0.1 提交） |
| branch | `main` |
| origin/main | `ffa3087` |
| ahead / behind | **22** / 0 |
| `git status --short` | 仅 `?? docs/design/phase3.4.5-external-adapter-evidence-consolidation.md`（编制本报告前）→ 落盘本报告后**新增** `?? docs/design/phase3.4.5-g1-a-wazuh-runtime-safety-evidence-report.md` |
| tracked diff `--stat HEAD` | **空**（无任何已跟踪文件改动） |
| 测试运行副作用 | **零**（排除文档后 untracked 全空，无缓存/pycache 泄漏） |
| commit / push | **未 commit、未 push** |

> 说明：Consolidation 与本报告均为**未跟踪 DRAFT 文件**（从未 commit）——这是在「已提交视图」中看不到它们的根因；二者真实存在于磁盘 `docs/design/`。

---

## §12 停止条件

- 本报告为 **READ-ONLY 取证产物**，**DRAFT**，不自行宣布 FROZEN。
- **不修改** mapping / Reader / webhook / 配置 / migration / 测试 / 历史提交；**不 commit、不 push、不自动修复、不进入 G1-B/G1-C。**
- 取证完成，**立即停止**，等待正式 Review 与修复 Design Freeze 授权。
- G1 生产修复需**下一次单独授权**；G2–G5 暂停；Consolidation 保持 DRAFT、未提交。

> **（G1-D 前向引用，2026-09-08）** 上述停止条件为**修复前**取证轮次的约束。其后用户已**单独授权** G1-B（设计 FROZEN）与 G1-C（`MINIMAL SECURITY FIX`，已落地 commit `0c372aa`），并经 G1-C Final Review 接受、G1-D 文档收口。**本报告取证正文（§1–§12）不因后续修复而改写**；修复闭环见 G1-B §15 / Consolidation §8.2.B。
