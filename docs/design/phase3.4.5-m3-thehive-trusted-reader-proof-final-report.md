# Phase 3.4.5-M3 — TheHive 可信 Reader 证明 & 严格创建关联 · 最终交付报告

> **状态：M3 ISOLATED PROOF = PASS — DELIVERED — AWAITING FINAL REVIEW**
> 本文件是 M3 授权轮（`SentinelFlow M3 — Trusted Reader Proof & Strict Correlation`）的**唯一最终交付**：
> 实际 HEAD/提交链、Amendment 前向裁决与实现、不可变派发事实矩阵及缺失字段、可信证明通道调用图/数据流/安全边界、
> 六道合取门、版本/凭据检查、四级测试证据、三入口伪造拒绝、时间/实例/租户负向矩阵、完整回归、Git 状态、剩余阻塞。
>
> **本轮明确结论（分能力验收，绝不合并为「全部通过」）：**
> - **来源隔离（§3）= PASS**：webhook 路径永不触校验器（AST 导入面 + 调用图可达性 + 纯内核 + 运行时 subprocess 四证）；三入口伪造（裸串 `case_created` / 走私 proof 字段 / 伪造 proof Mapping / reconcile 注入）全部 **422 / 零 fact**。
> - **严格创建关联（§4）= PASS（门①②③④⑥ 锚定不可变历史；门④ 以派发时持久化 `createdAt` 精确匹配「更强」；门⑤ 对全部真实历史 fail-closed）**。
> - **隔离回归（§6/§7）= PASS**：完整后端 **2647 passed / 5 deselected / 0 failed**（61.58s）；M3 套件隔离 **79 passed / 1 deselected**（2.92s）。
> - **门⑤ 实例/租户绑定 = 唯一剩余设计阻塞（Amendment §12，§2 STOP）**：现有历史**根本不存在**实例/租户绑定事实，故对全部真实历史 fail-closed（`instance_binding_unknown`），**真实历史无 `confirmed_success`**（正确且安全）；**不虚构、不倒填、不用当前配置替代旧记录**。
> - **真实本地联调（§5/§6）= LAB BLOCKED**（本机无容器运行时/VM 工具/WSL 分发版/充足内存）；`TestRealLabTrustedRead` 保持 `external` marker + 环守 SKIP，诚实断言即便真实 Lab 门⑤ 仍 fail-closed。
> - **生产部署认证 = UNKNOWN**（本里程碑不触碰生产；registry 仍空 / router 未接线；始终单列，不自动升级）。
>
> **`M3 ISOLATED PROOF = PASS` 仅覆盖来源隔离 + 门①②③④⑥ 严格关联 + 隔离回归；真实本地联调与生产认证单独列示，不自动升级为通过。**

## 0. 文档控制区（Document Control）

| 字段 | 值 |
| --- | --- |
| 文档状态 | **M3 ISOLATED PROOF = PASS — DELIVERED — AWAITING FINAL REVIEW**（非 FROZEN；不认证任何生产运行时）|
| 授权 | M3 §0–§8（**ONE AGENT · AMENDMENT IMPLEMENTATION · ISOLATED REGRESSION · LOCAL COMMITS · NO PUSH**）|
| 授权基线提交 | `8248143`（M2-R Final Report，**保留、不重写历史**）；`main` ahead 38（提交本轮前）|
| 采集日期 | 2026-09-09 |
| 采集方式 | **权威源码只读取证 + git 元数据核验 + 隔离测试**；测试用注入 stub transport（零网络）+ 内存 SQLite（`sqlite://` + StaticPool）+ `AI_PROVIDER=mock`；**无镜像拉取、无服务启动、无真实外部写入、无生产凭据、无管理员安装、零外部网络** |
| 唯一交付物（本文档）| `docs/design/phase3.4.5-m3-thehive-trusted-reader-proof-final-report.md`（新增，doc-only 提交）+ 仓库外脱敏审查 ZIP |
| 关联文档（本轮）| `phase3.4.5-m2-r-thehive-source-isolation-amendment.md`（§11 M3 前向 Decision Record + §12 门⑤最小前向绑定 Amendment，`2d53361` 前向追加，**不倒写 §0–§10**）|
| 运行环境 | Windows 10.0.26100（24H2）；`backend\.venv` Python **3.12.2** / pytest **9.1.1**；`sqlite://` 内存库 + StaticPool；`external` marker 默认 deselect |
| 保护约束 | 不改冻结通用契约（`normalize_external_state` 2 参数 / `map_external_state` 单委托 / `AdapterReadRequest`/`AdapterReadResult` 冻结 DTO）；不改 DB 模型；不改历史 Outcome；不改 Wazuh G1-C 空词表；不进 Shuffle/Wazuh Reader；不建第二张外部状态词表；不加客户端可控 `verified` 标志；不接线 router；不 amend/rebase/reset/force-push/移动 tag；**不 push** |

---

## 1. M3 交付摘要（Amendment 裁决 → 实现 → 验收）

| # | 授权节 | 处置 | 状态 |
| --- | --- | --- | --- |
| **§1** | Amendment 前向裁决 | §5.3 内部强类型证明 + §6.2 PULL-only 平台派生 `ReadCorrelationContext` + 单一校验器，作为**前向 Decision Record** 追加（§11/§12，`2d53361`），**不倒写** M2/M2-R | ✅ 已记录 |
| **§2** | 先核验历史事实 | 只读核验 `ExecutionLog`/写适配器/派发事务/Manual Reconcile/config/权威 v0 `Case.scala` → 最小事实矩阵（§4）；门①②③④⑥ 可锚定，**门⑤ 实例/租户绑定不存在** | ✅ 已核验 → 门⑤ §2 STOP |
| **§3** | 可信 Reader 专用通道 | `read_adapters/verified.py`（纯内部类型 + 六门校验器）+ `read_adapters/thehive.py:read_creation`（冻结 `read()` 字节级不变）+ `outcomes/verified_proof.py`（DB 派生 + PULL 编排 + 白名单持久化）；webhook 永不触校验器 | ✅ 已实现（`d08ba5a`+`8d6b63a`）|
| **§4** | 严格创建关联 | 六道合取门（首失败即 `CreationRefusal`）；门④ 时间窗 300s = **defense-in-depth，非权威**，权威是派发时持久化 `createdAt` 精确匹配；门⑤ 真实历史 fail-closed；401/403/404/timeout/5xx 独立 read-failure | ✅ 已实现 |
| **§5** | 版本/实例/租户/凭据 | 独立 `THEHIVE_READ_API_KEY`（绝不回退写钥）+ 无重定向 opener + TLS/URL 校验保留；`EXPECTED_VERSION` 仅 `config-declaration`（约束 #3，非活性证明）；registry 空 / router 不接线 | ✅ 隔离实现 + 模拟验证 |
| **§6** | 测试与验收 | 四级分层（Component/Service/HTTP Integration/Real External E2E）；三入口伪造拒绝；时间/实例/租户负向矩阵；`external` 默认 deselect；完整回归零失败 | ✅ **2647 passed / 5 deselected / 0 failed** |
| **§7** | Git/环境/安全边界 | 单 Agent 串行；4 个本地前向提交 + 本报告；不 amend/rebase/reset/force-push/push；不安装 Docker/WSL/VM；不连生产 | ✅ 合规 |
| **§8** | 一次性交付 | 本报告 + 仓库外脱敏 ZIP（提交链/裁决/事实矩阵/调用图/patch/测试日志/负向矩阵/版本凭据/真实 Lab 结论/剩余阻塞）| ✅ 本文件 |

---

## 2. Git 提交链（Commit Chain — 全部本地前向，NO PUSH）

| 顺序 | 提交 | 类型 | 说明 | 对应节 |
| --- | --- | --- | --- | --- |
| 基线 | `8248143` | docs | M2-R Final Report（**保留，不重写历史**）| 审查对象 |
| 1 | `2d53361` | docs | Amendment 前向 Decision Record §11（M3 裁决）+ §12（门⑤最小前向绑定）| §1/§2 |
| 2 | `d08ba5a` | **code** | 可信 Reader 证明内核 `verified.py`（六门纯校验器 + 内部类型）+ `TheHiveReadAdapter.read_creation` + `read_adapters/__init__` 导出 | §3/§4 |
| 3 | `8d6b63a` | **code** | `outcomes/verified_proof.py`：PULL-only 编排 + 平台派生 context + 白名单持久化（门⑤ fail-closed）| §3/§4 |
| 4 | `a846fee` | **test** | M3 §6 测试套件：`test_verified_creation_proof.py` + `test_verified_proof_isolation.py`（1232 行）| §6 |
| 5 | *(本文档)* | docs | M3 最终交付报告（分能力验收）| §8 |

- **当前 HEAD**：`a846feed2fd10cdc63936b7352963955772f5b16`（本报告提交前）；`main`；`origin/main...HEAD = 0 behind / 42 ahead`；**工作树干净**（`git status --short` 空）。
- **纪律**：全程**未 push**、**未** amend/rebase/reset/force-push、**未**移动任何历史 tag；`8248143`/`2b066af`/`14b37e5`/`e8b3aab`/`f11b477` 等均**只读历史**；文档与代码分离提交；报告提交后 ahead 43。

---

## 3. Amendment 前向裁决与实际实现（§1）

### 3.1 §5.3 / §6.2 裁决采纳（用户正式裁决，Amendment §11.1）

用户**不完全采纳**原设计推荐的两条捷径，理由：「结构化对象」与「READ 域」本身不会自动产生可信来源，信任必须建立在**平台控制的调用链**与**不可由外部请求构造的内部上下文**上。

| 裁决 | 采用 | 明确否决 |
| --- | --- | --- |
| **§5.3 强类型内部证明** | 仅供内部可信读取服务的 typed `VerifiedCreationEffect`/`VerifiedReadResult` | ❌ 不将任意 `raw_evidence` Mapping 当授权凭据；❌ 不扩展冻结公开 `AdapterReadResult`（字段集硬封 `{external_state, observed_at, raw_evidence}`）|
| **§6.2 途径 2 经修订** | 严格关联在 PULL-only 读取编排/证明校验层，用平台从不可变事实派生的 `ReadCorrelationContext` | ❌ 不扩展冻结 `AdapterReadRequest`（硬封 `{execution_id, adapter, external_reference}`）；缺失的实例/租户/派发时间**绝不从当前配置倒推** |
| **组合** | 内部强类型证明 + 平台派生 context + **单一**可信证明校验器 | ❌ 不建第二张外部状态词表；❌ 不恢复共享 `case_created`；❌ 不加 Webhook 可提交的 `verified`/`source`/`provenance` 标志 |

### 3.2 三项约束的实际落地（Amendment §11.2）

1. **内部类型不是魔法安全凭据** → 防线不靠「禁止 import」单点，而是**受控调用链**：校验器 `verify_creation_effect` 唯一 caller == `app.services.outcomes.verified_proof`（调用图测试证实）；`ManualReconcileRequest` 为空且 `extra="forbid"`，客户端无法注入任何 proof/context/verified 字段；无任何路由接受客户端构造的内部类型；webhook 是独立函数图，永不触校验器（AST + 运行时 subprocess 双证）。
2. **历史事实不得凭空补全** → §2 源码核验**部分推翻**原 §6.2 断言：派发时间与 reference 确实存在，但**实例/租户绑定不存在**（§4）；门⑤ 对全部真实历史 fail-closed，触发 §2 STOP（§12），缺失字段保持 `UNKNOWN`。
3. **版本配置不等于活性证明** → 工厂 `_thehive_readers` 只检查 `THEHIVE_EXPECTED_VERSION` 字符串、build 时零 HTTP；持久化 detail 明标 `version_assertion_kind="config-declaration"`；无真实 Lab 只完成隔离实现 + 模拟验证，**不标记真实版本已认证**，registry 继续空、router 不接线。

### 3.3 保留不动的冻结契约（全部沿用，`git status` 确认无修改）

`normalize_external_state` 两参数 + path-agnostic + thehive 词表 ∅；`map_external_state` 单委托封板；`AdapterReadRequest`/`AdapterReadResult` 冻结 DTO；sealed `default_read_adapter_registry()` 空；router 不接线；Wazuh G1-C / shuffle / mock 四集 ∅；`TheHiveReadAdapter.read()` 字节级不变。

---

## 4. 不可变派发事实矩阵及缺失字段（§2 · Amendment §11.3）

只读核验 `app/models/execution_log.py`、`app/services/executions/thehive.py`、`app/services/executions/service.py`、`app/services/outcomes/manual_reconcile.py`、`app/core/config.py`、权威 `TheHive-main/dto/.../dto/v0/Case.scala`：

| 事实 | 不可变历史？ | 证据 |
| --- | --- | --- |
| `execution_id` / `approval_id` | ✅ 不可变列 | `execution_log.py`（append-only，无 `updated_at`）|
| `action`(=`escalate_to_incident`) / `target` | ✅ 不可变**服务器端快照**列 | `execution_log.py`（「never accepted from the request body」）|
| `adapter` | ✅ 不可变（首行 `detail["executor"]`）| `manual_reconcile.py:_extract_adapter`（`rows[0].detail`）|
| 字符串 resource `reference` | ✅ 不可变（终态 `succeeded` 行 `detail["case_id"]`）| 写适配器 `thehive.py` + `_terminal_outcome_detail` |
| **dispatch 服务器时间** | ✅ 不可变（行 `created_at`，`server_default CURRENT_TIMESTAMP`）| `execution_log.py` |
| **派发时持久化的外部创建时间** | ✅ 不可变（终态行 `detail["raw_response"]` = 完整 `OutputCase`，含 `createdAt`）| `service.py:_terminal_outcome_detail`；写适配器 `raw_response=payload` |
| **目标 instance 身份** | ❌ **不存在** | `ExecutionLog` 无 instance 列；`base_url` 仅**当前 config**，非派发时持久化 |
| **目标 tenant / organisation** | ❌ **不存在** | 权威 v0 `OutputCase`（`Case.scala`）**无 `organisation`/无实例身份字段**；读取侧也无法观测 tenant |

**门锚定裁定（对照 §4 六道合取门）：**

| 门 | 可否锚定不可变历史 | 说明 |
| --- | --- | --- |
| ① IDENTITY | ✅ | `reference` = 终态 `detail.case_id`（不可变）|
| ② CORRELATION | ✅ | `execution_id` 不可变 + 读写共享单一真源 `sentinelflow_execution_tag`；标签本身外部**可修改**，故仅作合取项之一 |
| ③ CREATION-TIME | ✅ | 外部权威创建时间（非伪造）|
| ④ TIME-ORDER + 有界窗口 | ✅ **更强** | 除有界窗口外，用**派发时持久化的 `raw_response.createdAt` 精确匹配**读取侧 `createdAt`——**决定性杀死「十年前补标签」探针** |
| ⑥ APPROVED ACTION + reference 来源 | ✅ | `action` 列（服务器快照）+ `approval_id` + 终态 `succeeded` 行 reference |
| **⑤ INSTANCE/TENANT 绑定** | ❌ **不可锚定** | 现有历史**根本不存在**实例/租户绑定事实；补齐须在**派发时**记录新的不可变绑定，**触碰冻结写路径** → **触发 §2 STOP**（§12）|

**结论**：门①②③④⑥ **已立即实现**并锚定不可变历史；门⑤ 是**唯一**无法从现有历史派生的合取项，对全部真实历史 fail-closed（`instance_binding=UNKNOWN` → 无 `confirmed_success`，正确且安全），其前向绑定方案作为**唯一剩余设计阻塞**列入 Amendment §12。

---

## 5. 可信证明通道：调用图 / 数据流 / 安全边界（§3）

### 5.1 三模块落位（Amendment §11.4，遵守封板边界）

| 模块 | 职责 | 封板合规 |
| --- | --- | --- |
| `read_adapters/verified.py`（新，`d08ba5a`）| **纯内部类型** `VerifiedReadResult`/`ReadCorrelationContext`/`VerifiedCreationEffect`/`CreationRefusal` + `TrustedCreationReader` 协议 + 六门校验器 `verify_creation_effect` + 门/原因常量 | 不在 sealed `manual_reconcile/` 包内；仅 import stdlib + 读契约 base（纯度测试证实无 DB/HTTP/write/outcome 导入）|
| `read_adapters/thehive.py`（改，`d08ba5a`）| 增**内部** `read_creation(request) -> VerifiedReadResult`（单次 `GET`，typed 观测；4.1.24-1 `OutputCase` 无实例/租户字段 → `observed_instance/tenant=None` 恒）；**冻结 `read()` 字节级不变** | 动词封板只查**写动词 absence** + `vars(ReadAdapter)` ABC 级；给具体子类加**读**方法两者均不触 |
| `outcomes/verified_proof.py`（新，`8d6b63a`）| 平台派生 `derive_read_correlation_context`（只读 DB）+ 受控编排 `reconcile_verified_execution`（PULL-only）+ 白名单持久化 `persist_verified_creation_outcome`（绕过空词表 mapper，直接授权 `confirmed_success` append）| 在 `outcomes/`（非 sealed 包），可拥有 DB 事务；**不修改** `manual_reconcile.py`/`manual_persist.py` |

### 5.2 调用图（`reconcile_verified_execution` 七步，PULL-only）

```
认证 operator → reconcile_verified_execution(session, execution_id, operator, registry=None)
  1. derive_read_correlation_context(session, execution_id)   # 只读 DB 派生不可变事实
       correlate_execution（存在门）→ _select_chain → _extract_adapter → _extract_reference
       dispatch_time = _aware_utc(terminal.created_at)
       dispatch_created_at_millis = created_at_millis(terminal.detail["raw_response"]["createdAt"])
       instance_binding = None / tenant_binding = None        # §12：恒 UNKNOWN，绝不倒填
  2. registry.get(adapter)  → 缺失 raise UnsupportedAdapterRead（404）
  3. isinstance(reader, TrustedCreationReader) 否则 UnsupportedAdapterRead（404）
  4. reference 短路（None/empty → VerifiedCreationRefused "reference_unknown"，无 GET）
  5. AdapterReadRequest + reader.read_creation(request)
       except (ReadTransportError, TimeoutError, ConnectionError, OSError)
         → _reconciliation_failed_response（read-failure，绝不 confirmed_failure）
  6. verify_creation_effect(observed, context)                # 唯一 caller == 本模块
       CreationRefusal → raise VerifiedCreationRefused（422）
  7. VerifiedCreationEffect → persist_verified_creation_outcome（append-only 白名单）
       → ManualReconcileResponse（confirmed_success，恰一条独立 Outcome）
```

### 5.3 安全边界（约束 #1 的实际防线，四重测试证明）

| 防线 | 测试（`test_verified_proof_isolation.py`）| 结论 |
| --- | --- | --- |
| webhook **服务**无 proof 导入边 | `test_webhook_service_has_no_proof_import_edge` | AST：`services/outcomes/webhook.py` 不导入 verified/verified_proof |
| webhook **路由**无 proof 导入边 | `test_webhook_router_has_no_proof_import_edge` | AST：`api/v1/webhooks.py` 不导入内部证明 |
| 无 API router 接线 verified 通道 | `test_no_api_router_wires_the_verified_channel` | 生产 router 不触 `reconcile_verified_execution` |
| reconcile 路由只接 sealed A2 | `test_reconcile_router_wires_only_the_sealed_a2_path` | `reconcile.py` 仍调封板 `reconcile_execution`（空 registry → 404）|
| 校验器**唯一 caller** | `test_verify_creation_effect_has_exactly_one_caller` | 调用图：== `{app.services.outcomes.verified_proof}` |
| 无 webhook 模块调用校验器 | `test_no_webhook_module_calls_the_verifier` | 调用图：webhook 图与校验器不相交 |
| 纯内核只 import stdlib + 读 shape | `test_verified_kernel_imports_only_stdlib_and_the_pure_read_shape` / `test_verified_kernel_has_no_db_http_write_or_outcome_imports` | `verified.py` 无 DB/HTTP/write/outcome |
| 运行时 webhook 不拉 proof 编排 | `test_webhook_import_never_pulls_the_proof_orchestration` | subprocess：导入 webhook 后 `verified_proof` 不在 `sys.modules` |

### 5.4 持久化白名单（§3 · `persist_verified_creation_outcome`）

`raw_evidence`/`raw_response` **不原样写库**；仅白名单字段经 `redact_detail` 进 `ExecutionOutcome.detail`：`adapter`、`external_reference`、`outcome_status="confirmed_success"`、`proof_scope="verified_creation"`、`source="manual_reconcile"`、`correlation="execution_tag_present"`、`verified_created_at`（外部创建时间 ISO）、`instance_verified`/`tenant_verified`（**布尔，非租户/实例原值**）、`version_assertion_kind="config-declaration"`（约束 #3）、`case_number`（可选审计）。**不写**密钥、原始响应体、租户敏感原值。测试 `test_whitelist_excludes_raw_response_secret_and_tenant_value` 断言 `raw_response`/secret/`TENANT`/`INSTANCE` 原值均不在 detail。

---

## 6. 严格创建关联：六道合取门（§4）

### 6.1 六门 + reason 常量（`verify_creation_effect`，评估顺序 ①→⑥，首失败即 `CreationRefusal`）

| 门 | 校验 | 失败 reason |
| --- | --- | --- |
| ① IDENTITY | `resource_id` 非空 str + `external_reference` 非空 str + 二者相等 | `no_string_resource_id` / `reference_unknown` / `resource_id_mismatch` |
| ② CORRELATION | `correlation_tag_present is True` | `missing_execution_correlation_tag` |
| ③ CREATION-TIME | `external_created_at` 为 aware datetime | `missing_created_at` |
| ④ TIME-ORDER + 有界窗口 + 精确匹配 | `dispatch_time` aware；`created >= dispatch_time - 300s`；`created <= dispatch_time + 300s`；`dispatch_created_at_millis` 非 None；`external_created_at_millis == dispatch_created_at_millis` | `dispatch_time_unknown` / `created_before_dispatch` / `created_out_of_window` / `dispatch_created_at_unknown` / `dispatch_created_at_mismatch` |
| ⑤ INSTANCE/TENANT | `instance_binding` 非 None + `observed_instance == instance_binding`；`tenant_binding` 非 None + `observed_tenant == tenant_binding` | `instance_binding_unknown` / `instance_mismatch` / `tenant_binding_unknown` / `tenant_mismatch` |
| ⑥ APPROVED ACTION | `approved_action == "escalate_to_incident"` + `approval_status == "approved"` + `reference_from_terminal_success is True` | `unapproved_action` / `approval_not_approved` / `reference_not_from_terminal_success` |

### 6.2 时间窗口纪律（§4「不得随意写死一个数字后宣称权威」）

`MAX_DISPATCH_CLOCK_SKEW = MAX_CREATION_WINDOW = timedelta(seconds=300)` **明标为 defense-in-depth，非权威数字**：**权威门④ 检查是对派发时持久化 `dispatch_created_at_millis` 的精确匹配**（不匹配即 `dispatch_created_at_mismatch`，与窗口无关）。300s 仅镜像既有冻结先例 `reconciliation.MAX_FUTURE_SKEW`（design §10.5）：SentinelFlow 在同步 `POST /api/case` 返回后才盖 `succeeded` 行 `created_at`（`dispatch_time`），故合法 `createdAt` 早于 `dispatch_time` 远不到一秒；300s 是跨主机 NTP 偏差的宽松容忍，**绝不宣称是真实创建窗口**，且**绝不为缺失/过早时间取得排序优势**（§6.1）。`created_at_to_datetime` 与冻结读路径 `thehive._created_at_to_datetime` 由 Component 测试 `test_proof_converter_agrees_with_frozen_read_path` 钉住不漂移。

### 6.3 门⑤ fail-closed（真实历史，§12.3）

- `derive_read_correlation_context` 对**所有现有历史**设 `instance_binding=None`/`tenant_binding=None`（`UNKNOWN`）→ 门⑤ fail-closed（`instance_binding_unknown`）→ **绝不** `confirmed_success`。
- 真实 `TheHiveReadAdapter.read_creation` 恒返回 `observed_instance=None`/`observed_tenant=None`（4.1.24-1 不可观测）→ 门⑤ 双重 fail-closed。
- Service 测试 `test_real_history_fails_closed_at_gate5_zero_facts` 用**真实派生 context**断言 `gate == GATE_INSTANCE_TENANT`、`reason == "instance_binding_unknown"`、**零 fact**。
- 正向 `confirmed_success` 隔离测试用**平台构造的完整 context**（含模拟未来前向绑定的 `instance_binding`/`tenant_binding`）+ 测试替身 trusted reader，**明确标注非真实历史链**；门⑤ 前向绑定落地前真实路径不可达 `confirmed_success`。

### 6.4 read-failure 语义（§4 保留独立）

401→`authentication_failure`、403→`authorization_failure`、404→`not_found`、502/503/504→`adapter_unavailable`、timeout→`timeout`、连接失败→`connection_failure`、其它→`transport_error`；全部 `ReadTransportError` → `reconciliation_failed`（**绝不** `confirmed_failure`）。测试 `test_refused_proof_is_never_confirmed_failure`、`test_read_transport_failure_is_reconciliation_failed`。case Resolved / 任务 Completed / Cortex 状态**不**扩展为其它响应动作效果。

---

## 7. 版本 / 实例 / 租户 / 凭据（§5）

| 项 | 落地 | 状态 |
| --- | --- | --- |
| 独立只读钥 | `THEHIVE_READ_API_KEY` **绝不回退** create-capable 写钥；纳入 `current_secret_values()` 脱敏集 | ✅ 保留（M2-R Fix A）|
| 无重定向 opener | `_NoRedirectHandler` 拒任何 3xx，`Authorization` 绝不跨主机转发 | ✅ 保留 |
| TLS / URL 校验 | 默认验证型 `HTTPSHandler`；`validate_base_url` 未改（拒 query/fragment/userinfo/非 http(s)）| ✅ 未放宽 |
| `EXPECTED_VERSION` | 仅 `config-declaration`（约束 #3）；工厂只检查字符串、build 零 HTTP；detail 明标 `version_assertion_kind="config-declaration"` | ⚠️ **配置声明 ≠ 活性证明** |
| registry / router | `default_read_adapter_registry()` 保持 sealed 空；`reconcile.py` 仍调封板 `reconcile_execution`（无 registry → 404）；默认启动不因填入 URL/key/expected_version 自动启用 Reader | ✅ 生产未接线 |
| 运行时版本/实例身份认证 | 设计见 Amendment §12.2-B（live probe / 版本 Evidence Audit）；**无真实 Lab → 只完成隔离实现 + 模拟验证，不标记真实版本已认证** | ⛔ 待真实 Lab |

---

## 8. 测试与验收证据（§6）

### 8.1 四级测试分层（诚实标注，不混称）

| 级别 | 测试文件 / 类 | 范围 | 状态 |
| --- | --- | --- | --- |
| **L1 COMPONENT** | `test_verified_creation_proof.py`：`TestCreatedAtConverters`/`TestVerifierPositive`/`TestVerifierGate1..6`/`TestReadCreationVerb`/`TestDeriveReadCorrelationContext` | 六门校验器纯函数 + read_creation stub 观测 + 转换器漂移钉 + 派生 context，无真实网络 | PASS |
| **L2 SERVICE** | `TestReconcileVerifiedExecution`/`TestPersistVerifiedCreationOutcome` | 真实 DB 派生 + 编排 + 白名单持久化（内存 SQLite）| PASS |
| **L3 ISOLATION（HTTP 集成）** | `test_verified_proof_isolation.py`：`TestWebhookImportIsolation`/`TestVerifierReachability`/`TestProofKernelPurity`/`TestWebhookRuntimeIsolation`/`TestThreeEntryForgeryRejection` | 真实 FastAPI 路由：webhook/reconcile HTTP 三入口伪造拒绝；AST/调用图/运行时隔离 | PASS |
| **真实外部 E2E** | `TestRealLabTrustedRead`（`@pytest.mark.external` + 环守 SKIP）| 真实 `GET /api/case/{id}` | **DESELECTED（LAB BLOCKED）** |

> **HTTP 集成诚实标注（承接用户澄清）**：L3 经真实 HTTP 执行/对账路由，审批记录为**测试 fixture 预置 `approved`**，**非**审批 API 流转；故称「HTTP 执行/对账隔离集成测试」，**不称**完整「告警→AI→审批 HTTP E2E」。

### 8.2 三入口伪造拒绝（§6 实际测试证据，全部 422 / 零 fact）

| 入口 | 测试 | 伪造尝试 | 结果 |
| --- | --- | --- | --- |
| webhook PUSH | `test_entry1_webhook_bare_case_created_refused_zero_fact` | 有效 callback token + 裸串 `case_created` | **422 / 零 fact** |
| webhook PUSH | `test_entry2_webhook_smuggled_proof_shape_fields_rejected` | body 走私 `verified`/`provenance`/`source` 等 proof 形状字段（`extra="forbid"`）| **422 / 零 fact** |
| webhook PUSH | `test_entry2b_webhook_forged_proof_mapping_refused_zero_fact` | 伪造 proof Mapping 于 `external_state` | **422 / 零 fact** |
| reconcile PULL | `test_entry3_reconcile_injected_proof_fields_rejected` | reconcile body 注入 proof 字段（空 `ManualReconcileRequest` `extra="forbid"`）| **422 / 零 fact** |
| reconcile PULL | `test_entry3_reconcile_empty_body_never_reaches_the_verified_channel` | 空 body → 封板 A2 → 空 registry | **404 `UnsupportedAdapterRead` / 零 fact**（从不达 verified 通道）|

### 8.3 正向可信证明（§6「可信 Reader + 完整不可变上下文 → confirmed_success 恰一条独立 Outcome」）

- **Component**：`test_all_six_gates_pass_yields_verified_creation_effect`（六门全过 → `VerifiedCreationEffect`）+ `test_verifier_is_pure_no_mutation_of_inputs`（纯函数不改输入）。
- **Service**：`test_appends_one_confirmed_success_with_whitelisted_detail`（恰一条 `confirmed_success`，白名单 detail）+ `test_persist_is_append_only_no_side_effects`（append-only，无副作用）+ `test_repeat_reconcile_appends_never_overwrites`（重复 reconcile → append，不覆盖历史）。

### 8.4 时间 / 实例 / 租户负向矩阵（§6）

| 维度 | 测试 | 断言 |
| --- | --- | --- |
| 缺失/非法 createdAt | `test_missing_created_at` / `test_naive_created_at_is_refused` / `test_bool_is_never_a_timestamp` / `test_non_number_and_none_are_refused` / `test_out_of_range_is_refused_not_raised` | 拒绝（`missing_created_at` 等）|
| 十年前补标签 | `test_ten_year_old_retagged_case_is_before_dispatch`（Component）+ `test_ten_year_old_retagged_case_refused_zero_facts`（Service）| **决定性拒绝**（`created_before_dispatch` + 精确匹配不符）|
| 未来时间 | `test_future_dated_created_at_is_out_of_window` | 拒绝（`created_out_of_window`）|
| 精确匹配不符 | `test_exact_match_mismatch_is_decisive` / `test_dispatch_created_at_unknown_fails_closed` | 拒绝（`dispatch_created_at_mismatch` / `_unknown`）|
| 跨实例 | `test_resource_id_mismatch_cross_instance` / `test_instance_mismatch` / `test_observed_instance_none_is_a_mismatch` | 拒绝 |
| 跨租户 | `test_tenant_mismatch` / `test_tenant_binding_unknown_fails_closed` | 拒绝 |
| 真实历史门⑤ | `test_instance_binding_unknown_fails_closed_for_real_history` / `test_real_history_fails_closed_at_gate5_zero_facts` | **不得确认 / 零 fact** |
| 跨 execution / 错误 reference | `test_cross_reference_read_refused_zero_facts` / `test_missing_execution_correlation_tag` | 拒绝 |
| 非授权/错误审批/错误动作 | `test_unapproved_action` / `test_approval_not_approved` / `test_reference_not_from_terminal_success` | 不得读取或执行 |
| 非可信 reader / 空 registry | `test_reader_without_read_creation_is_not_trusted` / `test_empty_production_registry_fails_closed` | 404 / fail-closed |
| 无自动重试/轮询/补偿 | `test_one_read_attempt_no_retry` / `test_persist_is_append_only_no_side_effects` | 单次读，零额外写副作用 |

### 8.5 完整回归证据（§6/§7）

环境：`backend\.venv`（Python **3.12.2** / pytest **9.1.1**）；`conftest.py` 强制 `AI_PROVIDER=mock`、`db_session`=`sqlite://` 内存库 + StaticPool、`external` marker 默认 deselect。**无生产凭据、零外部网络。**

| # | 命令（于 `backend/`）| 结果 |
| --- | --- | --- |
| 1 | `pytest tests -q`（**完整后端 + 跨层**）| **2647 passed / 5 deselected / 0 failed**（61.58s）|
| 2 | `pytest tests/test_verified_creation_proof.py tests/test_verified_proof_isolation.py -q`（M3 隔离）| **79 passed / 1 deselected**（2.92s）|
| 3 | `pytest tests -m external --co -q`（真实外部枚举）| **5 collected / 2642 deselected** |

**+79 测试净增（2568→2647）**：M3 两文件 79 用例（Component 六门 + read_creation + Service + 隔离 + 三入口伪造 + 1 external）。

**5 个 deselected external 精确核算（证明零出站、非隐藏失败）**：`TestRealShuffle::test_real_workflow_trigger`、`TestRealTheHive::test_real_thehive_case_creation`、`TestRealWazuh::test_real_active_response`、`test_read_adapter_thehive.py::TestRealLabRead::test_real_get_case_verifies_creation`、**`test_verified_creation_proof.py::TestRealLabTrustedRead::test_real_read_creation_observes_typed_creation_with_none_bindings`（M3 新增）**——正是需真实外部系统的 5 个用例（默认 `pytest` **绝不**自动连接真实系统；真实 Lab 不存在时 `pytest.skip("LAB BLOCKED")`，**绝不让 `case_unverified` 冒充成功**）。

---

## 9. 分能力验收（逐项报告，任一缺证据保持未完成，绝不合并为「全部通过」）

| # | 能力项 | 状态 | 证据 | 缺什么（若未完成）|
| --- | --- | --- | --- | --- |
| 1 | **来源隔离（§3）** | ✅ **PASS** | §5.3：AST 导入面 + 调用图唯一 caller + 纯内核 + 运行时 subprocess 四证；§8.2 三入口伪造全 422/零 fact | — |
| 2 | **严格关联门①②③④⑥（§4）** | ✅ **PASS** | §6：六门 + 精确匹配「更强」杀死十年前探针；负向矩阵（§8.4）全拒绝 | — |
| 3 | **门⑤ 实例/租户绑定（§4）** | ⛔ **§2 STOP — 唯一剩余设计阻塞** | §4/§6.3：真实历史无绑定事实 → fail-closed 零 fact（正确且安全）| Amendment §12：A（派发侧不可变绑定）+ B（读取侧实例/租户观测）须独立 Gate；**不给历史补造事实** |
| 4 | **版本/凭据（§5）** | ✅ **隔离落地**（registry 空 / router 未接线）| §7：独立只读钥 + 无重定向 + TLS/URL 校验保留；`config-declaration` 明标 | 活性版本/实例身份证明（需真实 Lab live probe）|
| 5 | **测试分层（§6）** | ✅ **PASS** | §8.1：Component/Service/HTTP 隔离/Real External E2E 四级；HTTP 集成诚实标注 fixture-approved | 真实外部 E2E 观测（LAB BLOCKED）|
| 6 | **完整后端回归（§6/§7）** | ✅ **PASS** | §8.5：**2647 passed / 5 deselected / 0 failed**（61.58s）| —（隔离范围内完成；**不代表**真实联调通过）|
| 7 | **真实本地联调** | ⛔ **LAB BLOCKED** | 无容器运行时 + 无 VM 工具 + 零 WSL 分发版 + 内存不足；`TestRealLabTrustedRead` 环守 SKIP | 资源充足 VM/远程主机（**用户确认 + 另行授权**）+ 镜像 digest 实拉校验 |
| 8 | **生产部署认证** | ⛔ **UNKNOWN** | 本里程碑不触碰生产；registry 空 / router 未接线 | 真实目标实例契约 + 权威 registry digest + 生产版本取证；**Source/Config ≠ 生产认证** |

> **合并结论被明确禁止**：能力 1/2/4/5/6 在其范围内 **PASS**；能力 3 **§2 STOP（唯一剩余设计阻塞）**；能力 7 **LAB BLOCKED**；能力 8 **UNKNOWN**。**不得**表述为「全部通过」。

---

## 10. 保护约束合规声明（Protection Constraints Compliance）

- ✅ **未改冻结通用契约**：`normalize_external_state`（2 参数）、`map_external_state`（单委托）、`AdapterReadRequest`/`AdapterReadResult`（冻结 DTO）、DB 模型、审批规则**均未动**；`TheHiveReadAdapter.read()` **字节级不变**（新增的是**内部** `read_creation`）。
- ✅ **未建第二张外部状态词表**；**未恢复**共享 `case_created`；**未加**客户端可控 `verified`/`source`/`provenance` 授权标志（`extra="forbid"` 从结构上拒绝注入）。
- ✅ **未改 Wazuh G1-C 空词表**；**未进** Shuffle/Wazuh Reader；**未改** sealed `default_read_adapter_registry()`（保持空）；**未接线** router。
- ✅ **未修改任何历史 Outcome / 历史提交**；`8248143` 及更早均**只读**；实现经**新前向提交**；门⑤ **不给历史记录补造**实例/租户事实。
- ✅ **未增**自动重试/轮询/补偿/额外写入副作用（`test_one_read_attempt_no_retry` + append-only 测试证实）；**未绕过**人工审批（门⑥ 强制 `approval_status=="approved"` + `action=="escalate_to_incident"`）。
- ✅ **未** amend/rebase/reset/force-push；**未**移动历史 tag；**未 push**（全程本地）。
- ✅ **未**管理员安装 Docker/WSL/VM、**未**重启宿主机、**未**拉取/执行镜像、**未**连接生产或第三方、**未**发起真实业务写入。
- ✅ 测试用注入 stub transport（零网络）+ 内存 SQLite；**未用生产凭据**；占位凭据（`LAB_THEHIVE_KEY_DO_NOT_USE`、`thehive-callback-secret`）均**非真实**；`.env` 已 gitignore；本文档/diff/审查 ZIP **不含任何真实 token/密码/私钥/数据库原始敏感数据**（持久化只写布尔 `instance_verified`/`tenant_verified`，绝不写租户/实例原值）。

---

## 11. 剩余阻塞 · 最小后续工作 · 停止声明

### 11.1 唯一剩余设计阻塞：门⑤ 实例/租户绑定（Amendment §12，需独立 Gate）

现有历史**根本不存在**实例/租户绑定事实（§4 源码证实），故本轮依 §2 停在此处，**不凭猜测写成功逻辑**。解除需**全部**：
1. **A 派发侧最小不可变绑定**（推荐 A1：终态 `succeeded` 行 `detail` 增 `dispatch_binding={instance_id, tenant_id, base_url_host, certified_version}`，写入时从**认证后**目标派生，非当前 config 倒推）——**扩大既有执行 detail 契约，触碰冻结写路径 → 须独立 Gate 批准**；
2. **B 读取侧实例/租户观测机制**（B1 接线前 live probe `GET /api/system`；或 B2 目标版本 `OutputCase` 含 `organisation` 时经该版本 Evidence Audit 后启用）——**触碰 reader 能力 → 须独立 Gate 批准**；
3. 真实 Lab 对目标实例完成版本/身份/租户/只读权限**活性认证**（约束 #3）；
4. 全量回归 + 真实外部 E2E（`external` marker）。

### 11.2 真实本地联调 / 生产认证（始终单独列示，不自动升级）

- **真实本地联调 = LAB BLOCKED**：需资源充足（≥8 GB 空闲 + 容器运行时 + 管理员授权）VM/远程主机（**用户确认实验主机 + 另行授权**）+ 镜像 `thehiveproject/thehive4:4.1.24-1` digest `sha256:c8b6c7…` 实拉校验 + 平台架构匹配 → 执行 `TestRealLabTrustedRead`（`-m external`）→ 观测真实 200/401/403/404 + `~<id>` reference + `createdAt`。TheHive 4 已 EOL，仅隔离兼容性实验，**不作新生产部署推荐**。
- **生产部署认证 = UNKNOWN**：本里程碑不触碰生产；**Source/Config CERTIFIED ≠ 生产认证**。

### 11.3 停止声明

M3 授权范围内的可交付项已完成并取证：**§1 Amendment 前向裁决（§11/§12）+ §2 事实矩阵核验 + §3 可信 Reader 内部通道（三模块）+ §4 六道合取门（门①②③④⑥ 锚定不可变历史，门④ 精确匹配「更强」，门⑤ 真实历史 fail-closed）+ §5 版本/凭据隔离实现 + §6 四级测试分层 + 三入口伪造拒绝 + 完整回归 2647 passed + 4 个本地前向提交（NO PUSH）+ 本报告 + 仓库外脱敏 ZIP。**

**来源隔离 = PASS；严格关联门①②③④⑥ = PASS；隔离回归 = PASS → `M3 ISOLATED PROOF = PASS`。** 门⑤ 实例/租户绑定 = 唯一剩余设计阻塞（§2 STOP，Amendment §12）；真实本地联调 = LAB BLOCKED；生产部署认证 = UNKNOWN —— 依授权如实保持未完成，**单独列示，不自动升级为通过，不伪造全部通过**。

**本轮到此停止，等待用户 Final Review。不自动进入门⑤ schema 实现、真实 Lab 接线、Shuffle、Wazuh Reader、下一版本发布或 GitHub push。**
