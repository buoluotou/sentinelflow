# Phase 3.4.5-G1-B — Wazuh Runtime Safety Remediation Design（FROZEN · Design Freeze）

## §0 Document Control

| 项 | 值 |
|---|---|
| **标题** | Phase 3.4.5-G1-B Wazuh Runtime Safety Remediation Design |
| **状态** | **FROZEN — Remediation Design**（Design Freeze；由用户 G1-B 正式 Review **PASS**（附 5 处强制修订，见 §0.1）裁决冻结，2026-09-08；本冻结**仅**授权本次 C2 安全修复（G1-C），**不**意味 Consolidation/G1-A 已全部验收，**不**授权其他 Gate）。**G1-C 已执行并经用户 Final Review 接受**（commit `0c372aa`，见 §15 执行闭环记录）；**FROZEN 设计状态不变**，§15 为只读复核的执行记录，非新设计。本次经 **G1-D Final Documentation Commit** 授权本地提交（THREE DOCUMENTS ONLY · LOCAL COMMIT · NO PUSH） |
| **适用 Phase** | 3.4.5-G1-B（紧急安全修复设计；优先级高于 G2–G5；不以生产版本确认为前置） |
| **编制日期** | 2026-09-08 |
| **基线 HEAD** | `73b9c8b`（branch `main`；`origin/main` `ffa3087`；ahead **22** / behind 0） |
| **授权** | **DESIGN ONLY · NO CODE · NO COMMIT**（G1-B **设计阶段**授权：只设计 + 只读核对；不改生产代码/mapping/测试/配置/migration/历史提交；不 commit/push；不跑真实外部执行；不接生产凭据）。**冻结后 G1-C 已另行单独放行**（MINIMAL SECURITY FIX · ISOLATED REGRESSION · LOCAL COMMIT ONLY，见 §0.1 / §14；**已执行 = commit `0c372aa`，闭环记录见 §15**） |
| **结论标注约定** | 每条结论标注 **[源码证明]** / **[runtime 证明]** / **[待验证假设]** |
| **上游输入** | G1-A 报告（`phase3.4.5-g1-a-wazuh-runtime-safety-evidence-report.md`）；3.4.3-B 原始 mapping（`8b89fe7`，禁改）；B0/B0.1（`phase3.4-wazuh-mapping-amendment.md` §15-18）；Consolidation DRAFT §8.2 |

### §0.1 Review 决策与冻结记录（2026-09-08）

**用户 G1-B 正式 Review 裁决：PASS（附 5 处强制修订）。** C2 最小安全修复方案通过——清空 Wazuh 四组未认证状态词表，保留现有 `UnrecognizedExternalState` 拒绝机制；修复位于共享 mapping 层，覆盖已查明的 Webhook / Manual Reconcile / 直接映射调用路径；**不**增加新 HTTP 状态、异常类型或通用状态机分支。

**取证归属声明：** 115 / 67 等测试节点结果为 **Agent 取证回报**，**非**用户独立复测通过；用户未独立访问 Windows 仓库源码、完整 G1-A 原始报告或重跑测试。

**冻结前已应用的 5 处强制修订（设计精修，不改 C2 选择、不重做 G1-A）：**

| # | 位置 | 修订内容 |
|---|---|---|
| 1 | §1 / §9.1 | 「本仓库无真实数据污染」→「当前仓库未提供真实 Wazuh 部署证据，是否存在历史污染未知」（不得由空配置/compose 推导「无污染」）；0 行保持 **[待核验预期]**；历史排查**不能只依赖** `operator='adapter:wazuh'`，须覆盖已知 manual_reconcile 来源（operator 为认证人类名、adapter 在 `detail`），实际 operator 取值须由**源码 + 只读查询**共同确认 |
| 2 | §10 | T-02 修正为**剩余 4 个** success 词（与 T-01 合计 **5** 词）；T-08 正确凭据**直接期待 422**（删除「401→门开」误述）；T-14 service 层**不**直接宣称 HTTP 500（除非经 HTTP 层验证）；T-01–T-16 **按实际层级标注**（非全部 HTTP/DB 全栈） |
| 3 | §11.2 | **不批准**把 `git revert` 恢复旧不安全词表作为普通/自动回滚；回归时**保持 Wazuh 入站隔离** + 新前向安全修复；任何会恢复不可信映射的回退**须另行安全审批、不得自动执行** |
| 4 | §4.3 / §4.4 / §7 / §12 | 「逐字节不变」「无任何 Wazuh 词能产生 Outcome」等绝对表述**限定为本次已查明的映射业务路径**；真实读取失败产生的合法 `reconciliation_failed` **不受影响**；本设计**不**证明任意内部代码或直接 DB 写入均被拦截 |
| 5 | §12 | 补充**完整后端回归 + 跨层回归 + `git diff --check` + 实际测试数量 + 零失败**；确认未来词表**不会因配置生产版本或注册 Reader 而自动重新开放**，再填充须经独立证据认证 + 独立 Design Freeze |

**冻结范围：** 本 FROZEN **仅**授权本次 C2 安全修复（G1-C）。**G1-B 与 B0 关系成立**：G1-B 为版本独立的当前安全处置，B0 继续约束未来重新启用词表的版本与效果证据。`8b89fe7` / `b0a5962` / `73b9c8b` 均**不得改写**。

---

## §1 问题与证据（Problem & Evidence）

**问题：** Wazuh 旧非空状态词表是 LIVE 生产代码，经 path-agnostic 单一映射被**两条**生产入口可达，在缺乏可信命令级效果契约时产生**不可信 Outcome 事实**（`confirmed_success`/`pending`/`unknown`）。

| 证据 | 裁决 | 承载位置 |
|---|---|---|
| Wazuh 词表 LIVE 非空（success 5 词 / pending `running` / ambiguous `unknown` / failure ∅） | **[源码证明]** | `reconciliation.py:486-527` |
| webhook 路径：配置 token 后 5 success 词→confirmed_success、running→pending、unknown→unknown **落 fact（200）** | **[runtime 证明]** | G1-A §3.3（8 节点 PASSED）；`test_webhook_persistence.py:311-336` |
| manual 路径：注入 `FakeReadAdapter("wazuh")` 后同一映射经全 HTTP 栈可达 | **[runtime 证明]** | G1-A §6.3（`TestHttpToDbSuccess` 3 节点） |
| 唯一入站门 = `WAZUH_CALLBACK_TOKEN=""` 配置默认（运维可逆、非语义门） | **[源码证明]** | `webhooks.py:172-184`；`config.py:143-145` |
| 无版本门 / 无 feature flag / 无 adapter 门覆盖入站（`normalize:677` 无条件读词表） | **[源码证明]** | `reconciliation.py:677`；`config.py:46` |
| `map_external_state` 生产调用点仅两处（path-agnostic 单一映射，无第二套表） | **[源码证明]** | `webhook.py:149`；`manual_persist.py:204`；`mapping.py:103` |
| 旧词表证据基础已被 B0 §4 逐项证伪（agent_status ≠ 命令效果；`"ok"`=task 受理假朋友） | **[源码证明]** | `phase3.4-wazuh-mapping-amendment.md` §4；Consolidation §5.1 |
| 当前仓库**未提供真实 Wazuh 部署证据**（未配置/未 co-deploy）；**是否存在历史污染未知** | **[源码证明]**（严格限于「未提供部署证据」这一事实本身，**不**由此推导「无污染」） | `config.py:93-102/143-145`；`docker-compose.yml` 仅 postgres |

> **措辞纪律：** 上述为 **CONFIRMED UNSAFE（代码路径 runtime 可达）≠ 已发生生产事故**；本修复**不得**描述为「运行时此前已安全」，也**不得**描述为「已发生污染」。

---

## §2 设计目标与非目标

**目标：** 制定**最小、可验证、前向兼容**的安全修复设计，使 Wazuh 在缺乏可信外部效果契约时**不能产生**不可信 `confirmed_success`/`confirmed_failure`/`pending`/`unknown` 或其他伪造 Outcome 事实；覆盖**所有实际可达路径**（非某一 HTTP handler 表面检查）。

**非目标（本轮不做）：**
- ❌ 不实施修复（不改任何生产代码/mapping/测试/配置/migration）。
- ❌ 不创建 `WazuhReadAdapter`/任何 Reader；不扩展任何新外部状态词。
- ❌ 不进行生产版本适配（不与 G2 耦合）；不做其他 Adapter 功能开发。
- ❌ 不改认证机制；不修改/重写/移动 `8b89fe7`/B0/B0.1 历史提交。
- ❌ 不删除/覆盖/重写/自动纠正任何 append-only 历史 Outcome。
- ❌ 不设计历史数据撤销/标注/修复机制（= 另设独立 Gate，§9）。

---

## §3 §A 安全边界（Security Boundary）

**必须覆盖的全部入口（实际可达路径）：**

| 入口 | 生产可达性 | 门现状 | 是否被本修复覆盖 |
|---|---|---|---|
| **Wazuh webhook**（`webhooks.py:188`→`:220`→`webhook.py:149`） | LIVE（配置 token 即开） | 仅 `WAZUH_CALLBACK_TOKEN=""` 配置默认门 **[源码证明]** | ✅ 经 mapping 单点覆盖 |
| **manual reconcile**（`reconcile.py:111`→`manual_persist.py:204`） | 生产被空 registry 结构拦截；**注入 reader 后可达** | absence 门（无 reader），**非语义门** **[runtime 证明]** | ✅ 经 mapping 单点覆盖 |
| **直接 service 调用**（任何调用 `map_external_state`/`normalize_external_state` 的代码） | 无第三生产入口，但函数可被内部复用 | 无 | ✅ 经 mapping 单点覆盖 |
| **共享 mapping**（`mapping.py:103`→`reconciliation.py:650-716`→词表 `:486-527`） | **所有入口的汇聚单点** | 无版本门/无 flag **[源码证明]** | ✅ **修复点** |

**边界结论 [源码证明 + runtime 证明]：** 因 `mapping.py:103`「NO second mapping table」，三条入口**全部汇聚**于 `normalize_external_state:677` 读取的 `ADAPTER_STATE_VOCABULARIES["wazuh"]`。安全约束**必须落在该 mapping 单点**——只在 `webhooks.py` 加表面检查**无法**覆盖 manual_persist/直接 service 调用（G1-A F-7/F-8 已 runtime 证明 manual 路径注入后可达）。**这正是用户 §3.A「不能只在某个 HTTP handler 增加表面检查」的落实。**

---

## §4 §B 最小 Fail-Closed 方案

### 4.1 候选比较

| 候选 | 机制 | 覆盖全部入口? | 复用已封板契约? | 触碰冻结结构? | blast radius | 裁决 |
|---|---|---|---|---|---|---|
| **C1：版本独立 Wazuh 映射拒绝门** | 在 `normalize` 内加 `if adapter=="wazuh": raise` 特例分支 | ✅ | ❌ 新增代码路径 | ❌ **违反 §16 禁改 normalize 结构** | 中（改冻结函数体） | **REJECTED** |
| **C2：禁用未认证 Wazuh 状态词（清空词表）** | `ADAPTER_STATE_VOCABULARIES["wazuh"]` 四集全空 + `case_insensitive=False` + `state_key=None` | ✅ path-agnostic 单点 | ✅ 复用 `UnrecognizedExternalState`→422 | ✅ **只改词表内容** | **最小**（仅 `:486-527` 内容 + 测试锚点） | **SELECTED** |
| **C3a：从 webhook allow-list 移除 wazuh** | 删 `webhooks.py:83` | ❌ **不覆盖 manual_persist/直接 service** | ❌ 改 3.4.4-A 封板 allow-list（结构测试 pin 三 adapter）；404≠422 语义错位 | ❌ 改封板入口契约 | 大（语义错位 + 单入口） | **REJECTED** |
| **C3b：出站 `EXECUTION_ADAPTER` 门禁入站** | 复用 `config.py:46` | ❌ 该门**仅管出站 dispatch**，不门禁入站 webhook | ❌ | ❌ | 无效 | **REJECTED** |

### 4.2 被选方案 C2（= B0 §18.2 Option-3 目标代码，安全语义重述）

**唯一修改点：** `reconciliation.py:486-527` 的 `ADAPTER_STATE_VOCABULARIES["wazuh"]` **内容**——四集全空。**不改**任何其他 adapter、不改任何结构。

### 4.3 为何能阻止旧 success/pending/unknown 词进入不可信 Outcome [源码证明]

清空后，`normalize_external_state`：
- `:677` 读到空词表；
- 任何 Wazuh 词（`success`/`running`/`unknown`/…）经 `:690-697` 四分支**全部落空**（四个集合均空）；
- 命中 `:698-705` else → raise **`UnrecognizedExternalState`**（`:197`，`ContractValidationFailure` 子类）；
- webhook 路径：`webhooks.py:225-228` 捕获 → **422、零 fact**；
- manual 路径：映射在 `manual_persist.py:204` raise → 传播为既有拒绝契约、**零 fact**；
- **结果：在本次已查明的映射业务路径（webhook `webhook.py:149` / manual `manual_persist.py:204` / 任何直接调用 `map_external_state` 的内部代码）上，无任何 Wazuh 词能产生 Outcome 事实**（fail-closed）。**[范围限定]** 本结论**不**证明任意内部代码或**直接数据库写入**均被拦截——它只覆盖经 `normalize_external_state` 读取词表的映射路径（见 §4.4 / §7 / §12）。

### 4.4 为何不破坏 Shuffle / TheHive / 平台通用契约 [源码证明]

- **Shuffle/TheHive/Mock 词表已全空**（`:528-583`）→ 清空 Wazuh **不触碰**它们，**在本次已查明的映射业务路径上**行为**逐字节不变**。
- **平台通用契约不变：** `MAPPABLE_OUTCOME_STATUSES`（`:450`）、`normalize_external_state` 结构（`:650-716`）、`StateMapping.__post_init__`（`:606-623`）、`UnrecognizedExternalState`（`:197`）、四域凭据隔离、append-only 模型、422 拒绝契约**均不改**。
- 修复后**四个 adapter 词表全空** = 一致的 fail-closed 姿态（无任何 adapter 有 evidenced 词表），语义更统一。

### 4.5 铁律遵守（用户 §B 明令）

| 禁令 | 本方案如何遵守 | 证据 |
|---|---|---|
| **不得把所有未知态改成 `unknown`** | 清空词表 → **refused（零 fact）**，而非产出 `unknown` fact；`unknown` 仍仅保留给「已识别但语义模糊」的合法态（当前 Wazuh 无此态） | `reconciliation.py:698-705`；`:204-209` docstring §0 铁律 **[源码证明]** |
| **不得把拒绝伪装成 `reconciliation_failed`** | `StateMapping.__post_init__:615-623` **结构性**拒绝 `reconciliation_failed`（"Enforced structurally, not by comment"）；refused 走 `UnrecognizedExternalState`，**永不**产出 reconciliation_failed | `reconciliation.py:606-623` **[源码证明]** |
| **只有真实读取失败才记 reconciliation_failed** | 本修复**不触碰** manual 读失败路径（`manual_reconcile.py:411-419` 内联建 reconciliation_failed，**不调 map**）——真实读失败语义不变 | `manual_reconcile.py:411-419` **[源码证明]** |
| **无可信状态证据时应拒绝或保持 unsupported** | 清空 = **拒绝**（refused，零 fact）；manual 无 reader 时保持 **unsupported**（404） | §4.3 **[源码证明]** |
| **HTTP 行为沿用已封板契约或另申请 Amendment** | 完全沿用既有 **422** 拒绝契约（`webhooks.py:51-52` docstring「refused state is a 422」）——**无需新 HTTP 行为、无需 Amendment** | `webhooks.py:225-228` **[源码证明]** |

---

## §5 §C B0 与历史兼容

### 5.1 与 B0 版本限定 Amendment 的关系

| 维度 | B0/B0.1（已存在，DESIGN ONLY） | G1-B（本设计） |
|---|---|---|
| 触发理由 | **版本限定**（For 5.1.0-alpha0 无命令级 read 契约） | **安全**（G1-A runtime 证明不安全映射可达；**与版本解耦**） |
| 目标代码 | Wazuh 四集全空（§18.2） | **同一目标代码**（四集全空） |
| 是否依赖生产版本确认 | 是（版本门阻塞落地） | **否**（不以 G2 为前置） |
| 状态 | DESIGN ONLY，未实施 | Design Freeze Candidate，落地 = G1-C（另需授权） |

**收敛点 [源码证明]：** 二者**机制相同**（清空 Wazuh 词表），但 **G1-B 的理由是安全、版本独立**——即使生产版本永远 UNKNOWN，当前可达的不安全路径也必须立即封死。**G1-C 若先落地（安全清空），B0 的版本限定纪律仍保留价值**：它治理**未来任何基于真实命令级证据的词表再填充**（re-population 必须版本限定 + 证据认证）。二者**互补不冲突**。

### 5.2 历史兼容纪律（用户 §C 明令）

- **禁止**修改/重写/移动 `8b89fe7`（3.4.3-B 原始 mapping）、B0（`b0a5962`）、B0.1（`73b9c8b`）。**[设计约束]**
- 修改现有生产 mapping **必须采用新的前向提交**（G1-C = `git commit` 新提交，**非** amend/reset/force-push）。
- **Amendment 范围（明确）：** 仅 `reconciliation.py:486-527` 的 **Wazuh 词表内容**（四集）+ 相应测试锚点（§8.3 de-anchor/migrate）。**不触及**任何冻结结构、其他 adapter、历史提交。

---

## §6 精确修改文件与函数（G1-C 落地清单；本轮不改）

### 6.1 生产代码（唯一文件、唯一块）

**文件：** `backend/app/services/outcomes/reconciliation.py`
**块：** `ADAPTER_STATE_VOCABULARIES["wazuh"]`（`:486-527`）

**BEFORE（现状，LIVE 非空）：**
```python
    "wazuh": AdapterStateVocabulary(
        adapter="wazuh",
        # ...（:489-495 虚构注释 "agent_status IS the effect status" — R-3）
        terminal_success_states=frozenset({"completed", "confirmed", "done", "success", "ok"}),  # :496-498
        terminal_failure_states=frozenset(),   # :505
        pending_states=frozenset({"running"}), # :509
        ambiguous_states=frozenset({"unknown"}),# :515
        case_insensitive=True,                 # :519
        state_key="agent_status",              # :522
        evidence=("wazuh.py _CONFIRMED_AGENT_STATUSES (L97-99) + agent_status comment (L94-96)"),
    ),
```

**AFTER（设计目标，四集全空 + 去锚定 + 安全理由 evidence）：**
```python
    "wazuh": AdapterStateVocabulary(
        adapter="wazuh",
        # G1-B security remediation (forward commit; 8b89fe7 untouched):
        # the former {completed,confirmed,done,success,ok}/running/unknown vocab
        # was fabricated from a fictional synchronous dispatch response and is
        # falsified by B0 §4. G1-A proved it LIVE-reachable via webhook AND
        # manual (injected-reader) paths -> untrusted Outcome facts. Emptied to
        # fail-closed (refuse) INDEPENDENT of production-version confirmation.
        terminal_success_states=frozenset(),
        terminal_failure_states=frozenset(),
        pending_states=frozenset(),
        ambiguous_states=frozenset(),
        case_insensitive=False,
        state_key=None,
        evidence=(
            "G1-B: no trusted command-level effect vocabulary for ANY verified "
            "Wazuh version; fail-closed (refuse) until real command-effect read "
            "evidence exists (G1-A CONFIRMED UNSAFE; decoupled from G2 version)"
        ),
    ),
```

> **不改：** `AdapterStateVocabulary` 定义（`:454`）、`MAPPABLE`（`:450`）、`normalize_external_state`（`:650-716`）、`StateMapping`/`__post_init__`（`:588-623`）、`UnrecognizedExternalState`（`:197`）、Shuffle/TheHive/Mock 词表（`:528-583`）、`mapping.py`、`webhook.py`、`webhooks.py`、`manual_persist.py`、`config.py`、任何 migration。

### 6.2 测试改动（de-anchor / migrate / 改断言，**不删测**）

见 §8.3。核心：`test_reconciliation.py`（去锚 `:81` import + 反转 Wazuh 词表断言）、`test_webhook_persistence.py`（Wazuh 8 节点反转为 422 零 fact）、`test_manual_reconcile_crosslayer.py`（`TestHttpToDbSuccess` 注入路径反转为 refused；平台管线证明迁 test-only fake adapter）。

---

## §7 行为变更矩阵（BEFORE / AFTER）

| 输入（Wazuh external_state） | 路径 | BEFORE（现状） | AFTER（修复后） | 变更性质 |
|---|---|---|---|---|
| `success`/`completed`/`confirmed`/`done`/`ok` | webhook（配置 token） | 200 + `confirmed_success` fact | **422 + 零 fact** | **安全增强（消除不可信 fact）** |
| `running` | webhook | 200 + `pending` fact | **422 + 零 fact** | 安全增强 |
| `unknown` | webhook | 200 + `unknown` fact | **422 + 零 fact** | 安全增强 |
| 任何词表外词 | webhook | 422 + 零 fact | **422 + 零 fact** | **不变** |
| `success` 等（注入 reader） | manual | confirmed_success in DB | **refused + 零 fact** | 安全增强 |
| 无 reader | manual（生产） | 404 + 零 fact | **404 + 零 fact** | **不变** |
| 真实读失败 | manual | `reconciliation_failed` fact | **`reconciliation_failed` fact** | **不变**（不调 map） |
| 任何态 | Shuffle/TheHive/Mock | refused（词表已空） | **refused** | **不变（逐字节）** |
| 无效凭据 | webhook | 401 | **401** | 不变 |
| 无效 schema | webhook | 422 | **422** | 不变 |
| 未知 execution | webhook | 404 | **404** | 不变 |

**净效果 [源码证明]：** 仅**消除** Wazuh 不可信 fact 产出（安全只增不减）；**在本次已查明的映射业务路径上**所有其他行为**不变**；无任何新 HTTP 状态、无新异常类型。**[范围限定]** 真实读取失败产生的合法 `reconciliation_failed`（`manual_reconcile.py:411-419`，**不调 map**）**不受影响**；本设计**不**证明任意内部代码或**直接 DB 写入**均被拦截。

---

## §8 契约兼容性

### 8.1 保持不变的已封板契约

| 契约 | 位置 | 状态 |
|---|---|---|
| 五态 OUTCOME_STATUSES | `execution_outcome.py:25-33` | 不改 |
| MAPPABLE = 五态 − reconciliation_failed | `reconciliation.py:450` | 不改 |
| normalize 结构 + §0 铁律（refused 不降级） | `reconciliation.py:650-716` | 不改 |
| StateMapping.__post_init__ 结构守卫 | `reconciliation.py:606-623` | 不改 |
| path-agnostic 单一映射（NO second mapping） | `mapping.py:103` | 不改 |
| webhook 四门 + 422/404/401/500 映射 | `webhooks.py` | 不改 |
| 能力拒绝 ≠ 传输失败（UnsupportedAdapterRead vs reconciliation_failed） | `manual_reconcile.py:349-354`；`registry.py:49-63` | 不改 |
| 四域凭据隔离 | `config.py:55/64/93-102/143-145` | 不改 |
| append-only Outcome 模型 | `execution_outcome.py:63/67/141` | 不改 |

### 8.2 旧契约的 Amendment 范围

**仅** Wazuh 词表**内容**（`:486-527` 四集）经**新前向提交**清空；这是对 3.4.3-B（`8b89fe7`）Wazuh 词表的**前向安全 Amendment**，**不改** `8b89fe7` 本身（历史提交只读）。

### 8.3 将反转的测试锚点处置（de-anchor / migrate，**不删测**）

| 锚点 | 现状 | AFTER | 处置 |
|---|---|---|---|
| `test_reconciliation.py:743-752`（5 词→confirmed_success） | 映射成功 | refused | **改断言**（前向） |
| `test_reconciliation.py:754-759` ANCHOR `==_CONFIRMED_AGENT_STATUSES`（`:81` import） | 锚定旧词表 | 去锚定 | **删 `:81` import** → 更强 fail-closed pin（安全只增不减） |
| `test_reconciliation.py:771-777`（running→pending） | pending | refused | 改断言 |
| `test_reconciliation.py:779-785`（unknown→unknown） | unknown | refused | 改断言 |
| `test_reconciliation.py:796-811`（key/case 断言） | 部分有效 | 部分反转 | 逐项复核改断言 |
| `test_reconciliation.py:1126`（`:1134-1135` 断言 wazuh 唯一非空） | 前提=wazuh 非空 | 前提反转 | 改为「无任何 adapter 有 evidenced 词表」 |
| `test_webhook_persistence.py:311-336`（Wazuh 8 节点） | confirmed_success/pending/unknown | 422 零 fact | 改断言（前向） |
| `test_manual_reconcile_crosslayer.py::TestHttpToDbSuccess`（注入 fake） | 可达 confirmed_success | refused | 平台管线证明**迁 test-only fake adapter**（B0 §15.4，不删测） |
| `test_reconciliation.py:761-769/787-794/813-816/1121-1124` | failure gap/refused/keys==ADAPTER_NAMES | 保持有效 | **不动** |

---

## §9 §D 历史 Outcome 只读影响排查

### 9.1 只读排查方案（仅统计/识别，绝不修改）

```sql
-- 只读排查（双来源；绝不 UPDATE/DELETE/重写/自动纠正）
-- 来源 A：Wazuh webhook —— operator 由 webhook.py:169 固定为 'adapter:wazuh'
SELECT outcome_status, count(*)
FROM execution_outcome
WHERE source = 'webhook'
  AND operator = 'adapter:wazuh'
  AND outcome_status IN ('confirmed_success', 'pending', 'unknown')
GROUP BY outcome_status;

-- 来源 B：manual_reconcile —— operator 为认证人类操作员名（可变，非 'adapter:wazuh'），
--          adapter 仅存于 detail JSON（manual_persist.py:211/223-230）；故按 source + detail 过滤
SELECT outcome_status, count(*)
FROM execution_outcome
WHERE source = 'manual_reconcile'
  AND detail->>'adapter' = 'wazuh'
  AND outcome_status IN ('confirmed_success', 'pending', 'unknown')
GROUP BY outcome_status;

-- 只读明细（人工复核用；两来源合并，绝不修改）
SELECT id, execution_id, outcome_status, source, operator, observed_at, created_at, detail
FROM execution_outcome
WHERE (source = 'webhook' AND operator = 'adapter:wazuh')
   OR (source = 'manual_reconcile' AND detail->>'adapter' = 'wazuh')
ORDER BY created_at;
```

- **排查键来源（不能只依赖 `operator='adapter:wazuh'`）：** webhook 路径 operator 固定为 `adapter:wazuh`（`webhook.py:169`，`f"adapter:{normalized.adapter}"`）**[源码证明]**；manual_reconcile 路径 `source='manual_reconcile'`、operator 为**认证人类操作员名（可变）**、adapter 仅在 `detail["adapter"]`（`manual_persist.py:211/223-230`）**[源码证明]** —— 故历史排查**必须按 `source` + `detail->>'adapter'` 覆盖 manual_reconcile 来源**，仅查 `operator='adapter:wazuh'` 会**漏掉** manual 来源。
- **实际 operator 取值须由源码 + 只读查询共同确认：** 上述 operator 形态为**源码证明**，但真实历史行的 operator 具体值**须以只读查询结果为准**，不得仅凭源码假定（`detail->>'adapter'` 的 JSON 提取语法亦须按实际数据库方言核对）。
- **当前仓库未提供真实 Wazuh 部署证据**（`config.py:93-102/143-145` 空、`sentinelflow/docker-compose.yml` 仅 postgres）**[源码证明]**（严格限于「未提供部署证据」本身）；**是否存在历史污染未知**——**不得**由空配置/compose 推导「无污染」。
- **由此推断本仓库该只读查询预期返回 0 行**，但此为 **[待核验预期]**、**非数据库实际查询结果**——本轮**未**对任何真实数据库执行该 SQL；**本地为空 ≠ 其他部署无历史数据**（其他实际部署须由部署负责人独立核查，见 §9.3）。

### 9.2 append-only 不可变纪律

- **不得**删除/覆盖/重写/自动纠正任何历史 Outcome（`execution_outcome.py:63` INSERT-only、`:67` 无 unique index）。**[设计约束]**
- 修复**只影响未来**映射行为；**历史 fact 逐字节不变**。

### 9.3 撤销/标注/数据修复 = 另设独立 Gate

- 是否需要额外的**撤销 / 标注 / 数据修复**机制（针对其他真实部署可能已产生的历史 fact）→ **必须另设独立 Gate**（本轮**不设计、不执行**）。
- **其他实际部署**：由**部署负责人**核查暴露情况，并通过**已验证的入口控制**暂停回调；**不得假定清空 token 或某个尚未验证的开关一定有效**。

---

## §10 §E 回归测试矩阵

> 必须含**真实 HTTP→认证→关联→mapping→持久化**的隔离测试（非仅纯函数单测）；**不得**连接真实 Wazuh 或使用生产凭据。

| # | 场景 | 层级 | 期望（AFTER） | 覆盖用户 §E 项 |
|---|---|---|---|---|
| T-01 | `success`→webhook（配置 token） | **HTTP 全栈** | 422 + 零 fact | 五个旧 success 词 |
| T-02 | `completed`/`confirmed`/`done`/`ok`→webhook（**剩余 4 个** success 词） | **HTTP 全栈** | 422 + 零 fact（本项参数化 **4** 词；与 T-01 合计 **5** 词） | 五个旧 success 词 |
| T-03 | `running`→webhook | **HTTP 全栈** | 422 + 零 fact | running |
| T-04 | `unknown`→webhook | **HTTP 全栈** | 422 + 零 fact | unknown |
| T-05 | 未识别词（如 `bogus`）→webhook | **HTTP 全栈** | 422 + 零 fact | 未识别词 |
| T-06 | 无效 schema（extra 字段/缺字段）→webhook | HTTP（Gate 2） | 422 + 零 fact | 无效 schema |
| T-07 | 无效凭据→webhook | HTTP（Gate 1） | 401 + 零 fact | 无效凭据 |
| T-08 | 正确凭据→webhook | HTTP（Gate 1 通过→Gate 4 拒） | **直接 422 + 零 fact**（凭据正确故 Gate 1 通过、**非 401**；随后由 mapping 拒绝） | 正确凭据 |
| T-09 | 未知 execution→webhook | HTTP（Gate 3） | 404 + 零 fact | 未知 execution |
| T-10 | Shuffle/TheHive/Mock 各态→webhook | HTTP 全栈 | refused（与修复前逐字节一致） | 其他 Adapter 不回归 |
| T-11 | manual 生产路径（空 registry，无注入） | HTTP 全栈 | 404 + 零 fact（UnsupportedAdapterRead） | Manual Reconcile 结构门 |
| T-12 | manual 注入 fake reader + Wazuh 词 | HTTP 全栈 | refused + 零 fact（迁移后） | Manual 结构门 + 单点覆盖 |
| T-13 | refused 后持久化计数 | HTTP 全栈 | `execution_outcome` 行数 **+0** | 持久化零事实 |
| T-14 | 持久化层 SQLAlchemyError 注入 | **service 层**（非 HTTP） | rollback + raise `OutcomePersistenceError`；**HTTP 500 仅当另经 HTTP 层验证时才断言**，service 层单测**不**直接宣称 500 | 事务回滚 |
| T-15 | 修复前后既有历史 fact 比对 | DB | 历史行**逐字节不变** | 历史事实不变 |
| T-16 | 修复路径无 executor/retry/compensation/出站 | 全栈 | **无**任何外部执行副作用 | 无执行副作用 |
| T-17 | `normalize_external_state` 纯函数（Wazuh 各词） | **纯函数单测** | 全部 raise `UnrecognizedExternalState` | 补充（非唯一证据） |
| T-18 | confirmed_failure 路径不存在 | 纯函数 + HTTP | Wazuh 无任何词→confirmed_failure | 无 confirmed_failure |

**矩阵纪律（按实际层级标注，非全部 HTTP/DB 全栈）：** **T-01..T-13** 为隔离 **HTTP 全栈**测试（TestClient + 内存 SQLite，覆盖 HTTP→认证→关联→mapping→持久化）；**T-14 为 service 层**（持久化异常注入；HTTP 500 须另经 HTTP 层验证）；**T-15 为 DB 层**（历史行逐字节比对）；**T-16 为全栈副作用核查**；T-17/T-18 为纯函数补充。**不以纯函数单测冒充整体安全**（用户 §E 明令）。全部**不连真实 Wazuh、不用生产凭据**。

---

## §11 风险与回滚方案

### 11.1 风险

| 风险 | 描述 | 缓解 |
|---|---|---|
| R-A | 测试锚点反转若未与生产改动**同一前向提交**，CI 断裂 | G1-C **单提交**内同步更新 §8.3 全部锚点（改断言/去锚/迁移），**不删测** |
| R-B | 未来注册 `WazuhReadAdapter` 但忘记词表 | **本修复已消解**：词表空 → 无论是否有 reader，Wazuh 态一律 refused（F-7 转 VERIFIED-safe） |
| R-C | 过度拒绝影响未来合法 Wazuh 集成 | 再填充由 **B0 版本限定证据纪律**治理（未来独立 Gate），非本修复职责 |
| R-D | 其他真实部署可能已产生历史不可信 fact | §9 只读排查 + **独立修复 Gate**；本轮不改历史 |
| R-E | evidence 字符串措辞被误读为「已验证生产安全」 | evidence 明确标注「no trusted vocabulary for ANY verified version；fail-closed」，不声称生产已安全 |

### 11.2 回滚方案（不批准以 git revert 恢复不安全词表作为普通回滚）

- **禁止**把 `git revert <该提交>`（会恢复旧不安全 Wazuh 词表）作为**普通/自动**回滚方案。**[用户 G1-B Review 明令]**
- 若修复引发回归：**保持 Wazuh 真实回调入站隔离**（运维侧停用回调入口 / 保持 `WAZUH_CALLBACK_TOKEN` 为空），并通过**新的前向安全修复**处理回归——**不得**通过恢复已证实不可信的映射来换取测试通过。
- 任何会**恢复不可信映射**的回退（含 revert 本提交）**必须另行安全审批**，**不得自动执行**。
- 本修复本身为**单一前向提交**，仅改 `reconciliation.py:486-527` 内容 + 授权测试锚点；**不动** `8b89fe7`/B0/B0.1，**不** reset/amend/force-push/push。

---

## §12 验收条件（G1-C 落地时逐项核验）

1. Wazuh 五个 success 词 + `running` + `unknown` 经 **HTTP 全栈**均 → refused（webhook 422 / manual 结构或 refused）、**零 fact**。**[runtime]**
2. **无** confirmed_failure 路径被引入（Wazuh 无任何词→confirmed_failure）。**[runtime]**
3. Shuffle/TheHive/Mock 行为**在本次已查明的映射业务路径上逐字节不变**（**[范围限定]**：不宣称任意内部代码或直接 DB 写入均被拦截）。**[runtime]**
4. 平台契约（MAPPABLE/normalize 结构/StateMapping.__post_init__/UnrecognizedExternalState/四域凭据/append-only/422）**未改**。**[源码]**
5. `8b89fe7`/B0/B0.1 **未被修改/重写/移动**；修复为**单一新前向提交**。**[git]**
6. 完整 **HTTP→认证→关联→mapping→持久化**隔离测试通过，**未连真实 Wazuh、未用生产凭据**。**[runtime]**
7. §8.3 全部反转锚点已**改断言/去锚/迁移**，**无任何测试被删除**。**[源码 + runtime]**
8. 历史 Outcome fact **逐字节不变**（append-only）；§9 只读查询**未**触发任何写。**[源码 + 只读]**
9. 修复路径**无** executor/retry/compensation/出站 HTTP 副作用。**[runtime]**
10. evidence 字符串**不声称**生产已安全/已验证生产版本。**[源码]**
11. **完整后端回归 + 相关跨层回归**通过，报告**实际** passed / failed / deselected / skipped 数量，**零失败**；G1-A 旧测试结果**不**替代 G1-C 修复后结果。**[runtime]**
12. **`git diff --check` 通过**（无空白错误 / 冲突标记）；**无未授权生产文件改动**（仅 `reconciliation.py` 词表块 + 授权测试文件）。**[git]**
13. **未来词表不会因配置生产版本或注册 Reader 而自动重新开放**：清空后 Wazuh 态一律 refused，与是否有 reader / 是否配置版本**无关**；任何再填充**必须**经独立命令级效果证据认证 + 独立 Design Freeze（B0 版本限定纪律），**本轮不加入任何自动重新启用机制**。**[源码 + 设计约束]**

---

## §13 未决问题（Open Questions）

| # | 问题 | 归属 |
|---|---|---|
| OQ-1 | 修复后 B0 版本限定 Amendment 是否需正式 supersession 注记（关系治理）？ | 用户 Review / 未来 Gate |
| OQ-2 | 历史 Outcome 撤销/标注/修复机制的范围与设计（§9.3） | **独立 Gate**（非 G1-B/G1-C） |
| OQ-3 | 其他真实部署的 webhook 入口暴露核查（部署负责人职责，超出本仓库范围） | 部署负责人 |
| OQ-4 | `manual_persist.py:204` 是否需额外显式守卫，抑或 mapping 单点清空即足够？（设计立场：**单点足够**，path-agnostic） | 用户 Review 确认 |
| OQ-5 | G1-C 落地后，未来 Wazuh 词表再填充的证据门槛（B0 版本限定 + 命令级 read 证据） | 未来独立 Gate |

---

## §14 冻结状态与停止条件

- 本文件已由用户 G1-B 正式 Review **PASS**（附 5 处强制修订）裁决 **FROZEN（Design Freeze）**（见 §0.1，2026-09-08）；冻结前 5 处修订已全部应用。
- 本 FROZEN **仅**授权本次 **C2 安全修复（G1-C）**：清空 `reconciliation.py:486-527` Wazuh 四集 + 授权测试锚点迁移（§8.3）+ 单一本地前向原子提交（代码 + 测试，文档不提交、不 push）。
- **不**意味 Consolidation 或 G1-A 文档已全部验收；**不**授权 G2–G5、不创建 Reader、不启动真实外部联调、不发布新版本。
- G1-C 完成后**立即停止**，交付实际代码 diff + 测试报告，等待 **G1-C Final Review**；Wazuh Runtime Safety 是否由 NOT VERIFIED 转为已验证安全状态，由用户在 G1-C Final Review 裁定。**（G1-D 更新：已裁定）** 用户 G1-C Final Review 已**接受** commit `0c372aa`，并将状态更新为 **`VERIFIED — scoped`**（限已审计入站映射路径 + 隔离回归环境；生产部署与历史数据安全仍未验证），详见 §15。
- `8b89fe7` / `b0a5962` / `73b9c8b` 均**不得改写**；Consolidation 与 G1-A 保持 DRAFT、未提交。

---

## §15 G1-C 执行闭环记录（G1-D 安全收口补充，2026-09-08）

> 本节为 **G1-D 文档收口**追加，记录**已冻结设计（本文档 §1–§14）的实际 G1-C 执行结果**。本节**只读复核** commit `0c372aa`，**不改写**任何设计结论，**不修改**生产代码/测试/历史提交。G1-B 的 **FROZEN 设计状态保持不变**；本节是执行闭环记录，非新设计。

### 15.1 实际提交（read-only 复核）

| 项 | 值 |
|---|---|
| **commit** | `0c372aa73d6b73ffc9ac119b3b32fc41c28ca6b1`（`0c372aa`） |
| **parent** | `73b9c8b982863500eccffd6d2b2922dca61de0a8`（`73b9c8b` = 设计基线，未改写） |
| **提交消息** | `fix(reconcile): fail-closed empty Wazuh inbound state vocabulary (3.4.5-G1-C)`（Conventional Commits，ASCII-only） |
| **变更规模** | 8 files changed，988 insertions(+)，457 deletions(-) |
| **提交性质** | 单一本地前向原子提交（代码 + 测试同提交）；**无** amend / rebase / reset / force-push / push；**无** tag 移动 |
| **ahead / behind** | ahead `origin/main` **23**（原 22 + 本提交）/ behind **0**；**未 push** |
| **受保护历史** | `8b89fe7` / `b0a5962` / `73b9c8b` 经 `git cat-file -t` 确认均为 `commit` 对象，**未改写** |

**唯一生产改动：** `backend/app/services/outcomes/reconciliation.py` 的 `ADAPTER_STATE_VOCABULARIES["wazuh"]` 词表块（与 §6.1 设计目标一致）。**未触碰** normalize 结构 / StateMapping / MAPPABLE / 其他 adapter 词表 / mapping.py / webhook.py / webhooks.py / manual_persist.py / config.py / DB 模型 / migration（§3 禁改清单零改动）。

**授权测试迁移（7 文件，不删测）：** conftest.py（三层 fake fixtures）、test_reconciliation.py、test_mapping.py、test_webhook_persistence.py、test_webhook_security.py、test_manual_reconcile_mapping.py、test_manual_reconcile_crosslayer.py。

### 15.2 实际落地的词表块（read-only，与 §6.1 设计目标比对）

```python
    "wazuh": AdapterStateVocabulary(
        adapter="wazuh",
        # G1-B/G1-C SECURITY REMEDIATION (new forward commit; 8b89fe7 / B0 / B0.1
        # untouched -- history is read-only). ... All four sets are EMPTIED to
        # fail-closed (refuse -> UnrecognizedExternalState -> 422 / zero fact)
        # INDEPENDENT of production-version confirmation (decoupled from G2).
        # ... there is NO auto-reopen mechanism -- an empty vocab refuses
        # regardless of whether a Reader is registered or a version is configured.
        terminal_success_states=frozenset(),
        terminal_failure_states=frozenset(),
        pending_states=frozenset(),
        ambiguous_states=frozenset(),
        case_insensitive=False,
        state_key=None,
        evidence=(
            "G1-B/G1-C: no trusted command-level effect vocabulary for ANY "
            "verified Wazuh version; fail-closed (refuse) until real "
            "command-effect read evidence exists (G1-A CONFIRMED UNSAFE; "
            "decoupled from G2 version)"
        ),
    ),
```

**与 §6.1 设计目标的唯一差异（忠实实现，非语义偏离）：** 实际 `evidence` 字符串前缀为 **"G1-B/G1-C:"**（设计稿 §6.1 写作 "G1-B:"），即实现时把执行 Gate 一并署名；四集清空、`case_insensitive=False`、`state_key=None`、去锚定、安全理由均与设计**一致**。R-3 虚构注释（"agent_status IS the effect status"）已按 §6.1 AFTER 替换为**证伪说明**（RESOLVED）。

### 15.3 最终测试数（§12-11 验收项的实际结果）

| 运行 | 命令范围 | 结果 |
|---|---|---|
| **完整后端回归** | `pytest tests/` | **2494 passed / 0 failed / 3 deselected / 0 skipped**（60.82s） |
| focused 6 文件回归 | reconciliation / mapping / webhook_persistence / webhook_security / manual_reconcile_mapping / manual_reconcile_crosslayer | **611 passed** |
| 跨层回归 | test_manual_reconcile_crosslayer.py | **74 passed** |
| `git diff --check` | 空白 / 冲突标记 | **clean（exit 0）** |

- **3 deselected** = `@pytest.mark.external` 标记的真实外部系统测试（TheHive / Wazuh / Shuffle 各 1，位于执行/派发层），经 conftest `pytest_collection_modifyitems` 钩子**默认排除**（非 skipped，故 skipped=0）→ 默认套件**零出站**，满足 §10「不连真实 Wazuh、不用生产凭据」。
- **零删测证明（§12-7）：** HEAD vs 工作树 `def test_*` 名称比对——每个反转/重命名的旧锚点均有 1:1 替代（反转断言或迁 test-only fake adapter），**净 +22 测试、零删除**。
- **取证归属：** 上述测试数为 **Agent 取证回报**（G1-C 执行时实测），非用户独立复测；用户已声明未独立访问 Windows 仓库源码/未重跑测试。

### 15.4 修订后的安全回滚策略（§11.2 的落地确认）

- §11.2「**不批准以 `git revert` 恢复旧不安全词表作为普通/自动回滚**」在 G1-C 后**仍为现行策略**：commit `0c372aa` 是**前向安全修复**，任何会恢复不可信映射的回退（含 revert `0c372aa`）**必须另行安全审批，不得自动执行**。
- 若 G1-C 引发回归：保持 Wazuh 入站隔离 + 新前向安全修复处理，**不得**通过恢复已证伪的映射换取测试通过。
- G1-C 为单一前向提交，**未** reset/amend/force-push/push；`8b89fe7`/`b0a5962`/`73b9c8b` 未改写（§15.1 已核）。

### 15.5 未来词表重新启用门槛（§12-13 的落地确认）

- **无 auto-reopen（已由源码 + 测试 pin）：** 清空后 Wazuh 态一律 refused，**与是否注册 reader、是否配置生产版本无关**；`test_reconciliation.py::test_wazuh_vocabulary_is_entirely_empty` 结构 pin 四集为空、`state_key=None`、`case_insensitive=False`。
- **再填充门槛（须全部满足，缺一不可）：** ①真实生产/目标版本确认（G2）；②对应版本**命令级效果语义**权威证据；③关联契约（reference/correlation）认证；④**独立 Design Freeze**（B0 版本限定纪律）。
- **本提交未加入任何自动重新启用机制**；未来重开须独立证据认证，**不因 G1-C 已清空而降低门槛**。

### 15.6 五态收口声明（与 Consolidation §0.1 一致）

| # | 维度 | 状态 |
|---|---|---|
| 1 | 源码修复（清空 Wazuh 入站词表） | ✅ 已完成（`0c372aa`） |
| 2 | 隔离回归 | ✅ 已通过（2494 passed / 0 failed / 3 deselected / 0 skipped） |
| 3 | 真实生产部署验收 | ❌ 未验证 |
| 4 | 历史数据污染 | ❓ 未知（append-only 不改；当前无可用真实数据库查询结果，历史污染状态 UNKNOWN；其他部署须独立只读核查） |
| 5 | 真实 Wazuh Reader | ❌ 尚未实现 |

> **Wazuh Runtime Safety Gate（用户 G1-C Final Review 裁决）：** **`VERIFIED — scoped to the audited inbound mapping paths and isolated regression environment. Production deployment and historical data safety remain unverified.`** 「安全修复已完成」（1-2）**不等于**「生产级 Outcome 闭环已完成」（3-5）。

### 15.7 G1-D 停止条件

- 本节为 **DOCUMENTATION + READ-ONLY** 收口，**不 commit、不 push**；G1-B 保持 FROZEN、未提交（untracked DRAFT）。
- **不新增第四份仓库文件**（本节即 G1-C 闭环记录，内置于 G1-B，无需独立 Closure Report 文件）。
- **不改**生产代码/测试/配置/migration/历史提交；**不创建** Reader；**不进入** G2–G5；**不运行**真实外部执行。
- 完成后**停止**，等待用户对 Consolidation 与安全文档的最终 Review，再决定文档提交范围及下一道 Gate。
