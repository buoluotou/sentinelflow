# Phase 3.4.5-M4 — 前向派发绑定 & 证明通道收口 — 最终交付报告

> **状态：M4 IMPLEMENTATION = COMPLETE ｜ ISOLATED + FULL REGRESSION = PASS ｜ DELIVERED ｜ AWAITING FINAL REVIEW**
> 本文件是 M4 授权任务（`SentinelFlow M4 — Forward Dispatch Binding & Proof Channel Closure`）的**唯一最终交付**：
> 实施 HEAD/提交链、Amendment 前置裁决与真实实现、六道门当前状态、不可变绑定事实、证据矩阵、意图/设计/安全边界、
> 各类读取失败、版本/凭据检查、隔离/反伪造/时间/实例/租户、完整后端与跨层回归、Git 状态、剩余阻塞。
>
> **诚实明确结论（先讲清楚，再讲证据）：**
> - **M4-A 前向派发绑定 = 已实现**：外部请求发生**前**，绑定即持久化进 `dispatched` 行 `detail`，终态行只**引用**同一 `attempt_id`，绝不重写。绑定在 success / timeout / connection failure / HTTP error / response loss **全部存活**（M4-E 真实 service+DB 回归锁定）。**无 schema 迁移、无旧记录回填。**
> - **M4-D 门④/门⑥ = 已修订**：门④区分**真实派发开始**（`dispatch_started_at`，来自绑定）与**终态记录时间**（`terminal_recorded_at`，终态行 `created_at`），300 秒容差是 defense-in-depth **非权威创建窗口**，权威是 gate 4c 的 `createdAt` epoch-millis **精确匹配**；门⑥核对 `approval_id` + 被批准 recommendation/action/target + **派发时审批快照**（`approval_status_at_dispatch`）+ 执行快照，**不只看当前 `approval.status`**。
> - **M4-C 证明通道 = 已收口**：`VerifiedCreationEffect` 经模块私有 `_VERIFIER_SEAL` 铸造封印；持久化收敛为模块私有 `_persist_verified_creation_outcome`，运行时封印门拒绝任何未封印效果（`UnsealedCreationEffect`，零 fact）；AST 证明构造点唯一 + 调用点唯一 + 私有化。**普通内部对象再也无法直接写 `confirmed_success`。**
> - **M4-B 读取侧身份/版本证据 seam = 已实现（fail-closed，未接线）**：TheHive 4.1.24-1 源码取证确立 `GET /api/status`（公开）→ `versions.TheHive` 运行时版本活性证据、`GET /api/user/current`（需认证）→ 读取者 `organisation`+`roles`；`GET /api/system` **源码中不存在**（不假定）；`OutputCase` **无 organisation**。**诚实结论：门⑤ 仍 fail-closed** —— 读取者组织 ≠ 案件所属组织，`/api/case/{id}` 200 只证明可见性非所有权，无稳定实例 id。seam 存在但**零生产调用者**（AST 证明），绝不单独解锁 `confirmed_success`。
> - **门⑤ 实例/租户 = 唯一剩余门（保持 fail-closed）**：TheHive 4.1.24-1 **无可信派发时实例/租户来源**，真实历史 `ExecutionLog` 也无绑定。M4-A 使绑定**前向就绪**（未来认证来源可填充），**不制造不存在的绑定**。真实历史保持 `instance_binding_unknown` fail-closed。
> - **真实 Lab 联调 = LAB BLOCKED**：无授权的资源充足实验主机（当前 Windows 主机内存不足、无容器运行时）。5 个 `external` 测试默认 deselect。**不以 Mock 冒充真实联调。**
> - **生产版本活性 = UNKNOWN**：registry 密封、router 未接线；`EXPECTED_VERSION` 是 `config-declaration`，**不是运行时活性证明**（约束 #3）。
>
> **`M4 = COMPLETE` 仅指：A/B/C/D/E 五项授权范围内的代码+测试+文档已落地、隔离与完整回归全绿；门⑤真实历史解锁、真实 Lab、生产接线仍按设计保持阻塞/fail-closed，绝不自动放宽。**

## 0. 文档控制（Document Control）

| 字段 | 值 |
| --- | --- |
| 文档状态 | **M4 = COMPLETE ｜ DELIVERED ｜ AWAITING FINAL REVIEW**（一旦 FROZEN，不随证据变化而重写）|
| 授权 | M4（A–E）**ONE AGENT ｜ 里程碑级预授权 ｜ LOCAL FORWARD COMMITS ｜ NO PUSH**；无需为普通代码/测试/文档逐步申请 |
| 授权基线提交 | `fed946f`（M3 Final Report）—— **不重写其历史**；`main` ahead 48（本报告提交前），提交均本地前向 |
| 采集日期 | 2026-09-09 |
| 采集方式 | **权威源码只读取证 + git 元数据核校 + 离线回归**（stub transport，无网络）+ 内存 SQLite（`sqlite://` + StaticPool）+ `AI_PROVIDER=mock`。**无真实读取、无真实外部写入、无生产凭据、无管理员安装、无破坏性操作** |
| 唯一交付物（本文档）| `docs/design/phase3.4.5-m4-forward-dispatch-binding-proof-closure-final-report.md`（本仓库 doc-only 提交）+ 仓库外脱敏审查 ZIP |
| 关联文档（前置）| `phase3.4.5-m2-r-thehive-source-isolation-amendment.md`（§11 M3 前置 Decision Record + §12 门⑤实例/租户前向绑定 Amendment）；`phase3.4.5-m3-thehive-trusted-reader-proof-final-report.md`（M3 六道门 + 证明通道基线）|
| 运行环境 | Windows 10.0.26100（24H2）；`backend\.venv` Python **3.12.2** / pytest **9.1.1**；`sqlite://` 内存库 + StaticPool；`external` marker 默认 deselect |
| 冻结契约 | 不改动通用契约（`normalize_external_state` 2 参数 / `map_external_state` 单委托 / `AdapterReadRequest`·`AdapterReadResult` 公开 DTO）；不改 DB 模型；不改历史 Outcome；不动 Wazuh G1-C 空词表；不进 Shuffle/Wazuh Reader；不接生产 router；不 amend/rebase/reset/force-push/移动 tag；**不 push** |

---

## 1. M4 里程碑摘要（授权项 → 实现 → 验收）

| # | 授权项 | 落点 | 状态 |
| --- | --- | --- | --- |
| **A** | 派发前不可变绑定（A1 修订版）| `executions/binding.py`（NEW）+ `executions/service.py`（派发前写 `dispatched` 行 detail，终态引用 `attempt_id`）+ `executions/thehive.py`（contributor）| ✅ 已实现（`f3bc6e4`）|
| **D** | 修订门④（真实派发开始）与门⑥（派发时审批快照）| `read_adapters/verified.py`（`ReadCorrelationContext` 增 `dispatch_started_at`/`terminal_recorded_at`/`approval_status_at_dispatch`，门④非对称窗口 + 4c 精确匹配权威，门⑥快照交叉核对）+ `outcomes/verified_proof.py`（从绑定派生）| ✅ 已实现（`12923e5`）|
| **C** | 证明通道收口 | `read_adapters/verified.py`（`_VERIFIER_SEAL` 铸造封印）+ `outcomes/verified_proof.py`（`_persist_verified_creation_outcome` 私有化 + 运行时封印门 `UnsealedCreationEffect`）+ AST 收口证明 | ✅ 已实现（`3db671d`）|
| **B** | 读取侧身份/版本证据 seam | `read_adapters/verified.py`（`IdentityEvidence`/`IdentityAssessment`/`assess_identity_evidence` 纯评估器）+ `read_adapters/thehive.py`（`read_identity` + 3 助手，共享 no-redirect 传输/sanitizer，fail-closed，绝不返回原始体）| ✅ 已实现，**未接线**（`f8afd74`）|
| **E** | 完整隔离回归 + 全后端/跨层回归 | `tests/test_dispatch_binding.py`（NEW，102）+ `test_execution_cross_layer_regression.py`（`TestBindingSurvivesEveryOutcome`，12）+ 既有 M3/M4 套件保持绿 | ✅ **2810 passed / 5 deselected / 0 failed**（`ce3f395`）|

---

## 2. Git 提交链（Commit Chain — 全部本地前向，NO PUSH）

| 顺序 | 提交 | 类型 | 说明 | 对应项 |
| --- | --- | --- | --- | --- |
| 基线 | `fed946f` | docs | M3 Final Report（**不重写其历史**）| 前置 |
| 1 | `f3bc6e4` | **code** | M4-A 前向派发绑定：`binding.py`(278 NEW) + `service.py`(+58) + `executions/thehive.py`(+40) + cross-layer(+25) | A |
| 2 | `12923e5` | **code** | M4-D 门④（真实派发开始）+ 门⑥（派发时审批快照）：`verified.py`(+154) + `verified_proof.py`(+99) + `test_verified_creation_proof.py`(+167) | D |
| 3 | `3db671d` | **code** | M4-C 证明通道收口：`verified.py`(+35) + `verified_proof.py`(+51) + 两测试(+98) | C |
| 4 | `f8afd74` | **code** | M4-B 读取侧身份/版本证据 seam：`read_adapters/thehive.py`(+107) + `verified.py`(+155) + `test_read_identity_evidence.py`(510 NEW) + isolation(+46) | B |
| 5 | `ce3f395` | **test** | M4-E 绑定隔离回归 + 全后端/跨层绿：`test_dispatch_binding.py`(490 NEW) + cross-layer(+111) | E |
| 6 | *(本文档)* | docs | M4 最终交付报告（本仓库 doc-only 提交）| 交付 |

- **M4 全范围 diff（`fed946f..ce3f395`）**：**11 文件，+2292 / −132**。
- **当前 HEAD（本报告提交前）**：`ce3f395`，分支 `main`，`origin/main..HEAD = 48 ahead / 0 behind`，`git status --short` 空（工作树干净）。
- **纪律**：单 Agent 连续执行；无 amend/rebase/reset/force-push/移动 tag/push；无 Docker/WSL/VM 安装；无破坏性操作。

---

## 3. M4-A — 前向派发绑定（Amendment §12.2 A1 修订版）

### 3.1 意图与问题
M4 之前，一次派发的不可变目标事实**只**活在终态 `succeeded` 行（`raw_response` 内的外部 `createdAt`）+ 链的 `action`/`target` 列。Amendment §12.2 的 A1 选项设想把 `dispatch_binding` 写进终态 `succeeded` 行。**M4-A 修订 A1**：绑定在外部请求**之前**持久化——写进 `dispatched` 行（Execution Service 在 `executor.execute()` 运行**前** append + flush），终态行随后**引用同一绑定**（`dispatch_attempt_id`），绝不重写。

**为何派发前**：只写在 `succeeded` 终态的绑定，恰恰在最需要时丢失——timeout / connection failure / HTTP error / response loss **不产生 `succeeded` 行**，尝试的目标事实随之消失。`dispatched` 行**总在适配器运行前落地**，故绑定**在每种结果后存活**（任务硬要求）。

### 3.2 实现（`executions/binding.py`，278 行 NEW）
- 常量：`BINDING_DETAIL_KEY="dispatch_binding"`、`TERMINAL_REFERENCE_KEY="dispatch_attempt_id"`、`BINDING_SCHEMA="sentinelflow.dispatch_binding.v1"`、`VERSION_ASSERTION_CONFIG="config-declaration"`。
- `DispatchBinding`（`@dataclass(frozen=True, slots=True)`，14 字段）：`schema`/`execution_id`/`approval_id`/`adapter`/`action`/`target`/`attempt_id`/`dispatch_started_at`/`approval_status_at_dispatch`/`endpoint`/`version_evidence_ref`/`version_assertion_kind`/`target_instance`/`target_tenant`。`to_detail()` 投影为**纯 JSON 标量**；`started_at()` 畸形 ISO → `None`（fail-closed，绝不以服务器时间替代历史派发开始）。
- `DispatchBindingContributor`（`@runtime_checkable` Protocol）：**独立于冻结的 `ResponseExecutor` ABC**——`dispatched` 是平台日志状态，绝非适配器产物（D8），故 ABC 不变。`isinstance` 只检查方法**存在**（与 `TrustedCreationReader` 同一已记录 caveat），信任来自受控调用链而非类型名。
- `build_dispatch_binding(*, ...)`：`attempt_id` 在此**铸造新 uuid4**；contributor 事实经**显式白名单**合并（只读 5 个身份键 `endpoint`/`version_evidence_ref`/`version_assertion_kind`/`target_instance`/`target_tenant`），contributor **绝不能覆盖平台事实**（execution_id/attempt_id/dispatch_started_at/…）**绝不能走私任意键**。
- `parse_dispatch_binding(detail)`：**fail-closed**——非 dict / 无 binding 键（旧历史）/ 未知 schema / 缺任一平台身份事实 → `None`，**绝不 raise、绝不伪造字段**。

### 3.3 服务接线（`executions/service.py`，+58）
guards+policy 通过 → 构建 `ExecutionDispatch` DTO → `dispatch_started_at = datetime.now(timezone.utc)`（**服务器时钟 detail 事实**，与既有 policy-evaluation 时间同一先例，**非 `created_at` 审计列**，后者仍由 `_append` 经 high-water mark 独占盖章，冻结盖章条款不变）→ contributor 事实（仅当 `isinstance(executor, DispatchBindingContributor)`，离线 mock 不是）→ `build_dispatch_binding(...)` → `_append(decision="dispatched", detail={"executor":…, BINDING_DETAIL_KEY: binding.to_detail()})` + **flush（在 execute() 之前）** → `executor.execute()`（try/except `ExecutorOutcomeViolation`）→ 终态 detail **总是** `detail[TERMINAL_REFERENCE_KEY] = binding.attempt_id`（succeeded/failed/protocol_violation 皆然）→ `_append` 终态行。

### 3.4 无 schema 迁移 / 诚实 fail-closed 身份
`ExecutionLog.detail` 是 JSON 列，绑定**骑**在 `dispatched` 行 detail 内，终态引用骑在终态行 detail 内。**无新列、无 Alembic 迁移、无旧记录回填**。旧历史无绑定 → `parse_dispatch_binding` 返回 `None` → 证明派生照旧 fail-closed。TheHive 4.1.24-1 **无权威派发时实例/租户来源**（写配置只有 base URL 非认证实例身份；`OutputCase` 无 organisation），故 TheHive contributor 记录 `target_instance`/`target_tenant` 为 `None`（UNKNOWN），endpoint/version 为 **CONFIG 声明**（`version_assertion_kind="config-declaration"`）。**base URL / config 字符串绝不冒充已验证身份。门⑤ 因此对每次真实执行仍 fail-closed**——M4-A 使绑定**前向就绪**，不制造不存在的绑定。

### 3.5 验收
- 单元测试 `test_dispatch_binding.py`（102）：build 平台事实/新 attempt_id/ISO 派发开始/非字符串审批→None；contributor 白名单（恶意 contributor 不能覆盖平台事实、不能走私 `api_key`/`authorization`/`password`/`verified`/`source`/`raw_response`，`to_detail` 闭合 14 键纯 JSON 标量，走私 secret 绝不出现）；parse fail-closed 全矩阵（absent/非 dict/无 binding 键/未知 schema/七身份事实任一缺失·空·非字符串→None，绝不 raise）；`started_at` aware/naive/畸形；`DispatchBindingContributor` runtime_checkable（真实 `MockExecutor` **非** contributor）。
- 跨层回归 `TestBindingSurvivesEveryOutcome`（12）：真实 service+DB 驱动，success / adapter_unavailable / timeout / adapter_error / 6 种 rogue protocol_violation 后 `dispatched` 行绑定**仍存活**且终态只**引用** `attempt_id`（不重写）；guard 拒绝（未派发）**无任何绑定**；执行 token 绝不泄入任何行 detail。

---

## 4. M4-D — 门④（真实派发开始）与门⑥（派发时审批快照）修订

### 4.1 门④ TIME-ORDER
`ReadCorrelationContext` 新增三个**语义区分**的时间事实：
- `dispatch_started_at` —— **真实派发开始**（M4-D）：平台**开始**外部请求的时刻，来自 M4-A 绑定（`binding.started_at()`）。
- `terminal_recorded_at` —— 终态行不可变服务器 `created_at`：平台**记录终态**的时刻。
- （外部 `createdAt` —— 外部系统**创建资源**的时刻，来自 gate 4c 精确匹配源。）

门④窗口为**非对称** `[dispatch_started_at − 300s, terminal_recorded_at + 300s]`，**绝不**把终态 `created_at` 冒充请求开始。300 秒历史容差是 **defense-in-depth，非权威创建窗口**；**权威是 gate 4c 的 `createdAt` epoch-millis 精确匹配**。`dispatch_started_at`/`terminal_recorded_at` 未知 → `REASON_DISPATCH_STARTED_AT_UNKNOWN`/`REASON_TERMINAL_RECORDED_AT_UNKNOWN` fail-closed。

### 4.2 门⑥ APPROVED ACTION
审批核对**不只看当前 `approval.status`**，而是交叉核对：`approval_id` + 被批准的 recommendation/action/target + **派发时审批事实快照**（`approval_status_at_dispatch`，来自绑定，**不可变**，绝非 reconcile 时重读的 live status）+ 执行快照。任何不一致 → 门⑥ `CreationRefusal`。

### 4.3 验收
`test_verified_creation_proof.py`（+215）覆盖：错误时间（门③/④）、审批不一致（`binding_approval_status` 覆盖派发时快照）、旧历史拒绝（`with_binding=False`，无绑定 → 门④/⑥ 无来源 → fail-closed）。

---

## 5. M4-C — 证明通道收口

### 5.1 边界问题
M4-C 之前，`persist_verified_creation_outcome` 可**直接接受普通内部对象**写 `confirmed_success`——一个未经六门校验的对象即可冒充可信证明（约束 #9 风险）。

### 5.2 三层防御
1. **铸造封印**：`verify_creation_effect` 是 `VerifiedCreationEffect` 的**唯一构造点**，将模块私有哨兵 `_VERIFIER_SEAL = object()` 盖入 `seal` 字段；`is_sealed()` 校验。Python 属性永远不是密码学边界，但配合下方 AST 收口，使"未经校验器铸造的效果"在**受控调用链内不可达**。
2. **持久化私有化 + 运行时封印门**：`persist_verified_creation_outcome` → 模块私有 `_persist_verified_creation_outcome`（**不公开导出**）；运行时检查 `is_sealed()`，未封印 → 抛 `UnsealedCreationEffect(RuntimeError)`，**写零 fact**。
3. **AST 收口证明**（`test_verified_proof_isolation.py`）：`VerifiedCreationEffect` 构造点**唯一**（`verify_creation_effect`）；`_persist_verified_creation_outcome` 调用点**唯一**；persist 模块私有非公开导出。

### 5.3 未来 HTTP 接线约束
未来接线**必须**复用 operator 认证、RBAC、Manual Reconcile 权限。**当前不接生产 router**（约束 #11）；registry 密封默认空。

### 5.4 验收
`test_verified_proof_isolation.py`（+96 累计）：`TestProofChannelClosure`（构造点唯一/调用点唯一/私有化）+ `TestVerifierReachability`（`verify_creation_effect` 恰好一个调用者，webhook 模块绝不调用校验器）+ `TestWebhookImportIsolation`（webhook service/router 无 proof 导入边）。

---

## 6. M4-B — 读取侧身份/版本证据 seam（fail-closed，未接线）

### 6.1 源码取证（TheHive 4.1.24-1，git `b6649bb` / ScalliGraph `2c2a7a4`）
`TheHiveRouter.scala:23-25`：`/api/v1/`→routerV1，`/api/v0/`→routerV0，**`/api/`（无版本）→routerV0（default version）**（与冻结 `read` 的 `/api/case/{id}` 一致）。ScalliGraph `Entrypoint.scala` 认证语义：直接 `apply(block)`/`async(block)` → **公开无认证**；`.auth*`/`.authRoTransaction` → **需认证**。

| 端点 | 认证 | 权威产出 | 取证 |
| --- | --- | --- | --- |
| `GET /api/status` | **公开** | `versions.TheHive`（`getImplementationVersion`，**真实运行时版本活性证据**，区别于 config 声明）| v0 `StatusCtrl.scala`：`entrypoint("status"){_=>...}` 直接 apply |
| `GET /api/user/current` | **需认证** | v0 `OutputUser.organisation: String`（读取者组织=租户上下文）+ `roles: Set[String]`（RBAC）+ 头 `X-Organisation` | v0 `UserCtrl.current`：`.authRoTransaction`，401 若只读钥无效 |
| `GET /api/system` | —— | **源码中不存在（0 匹配）** | **不假定存在**（任务 B 明确要求）|
| `GET /api/case/{id}` | 需认证 | v0/v1 `OutputCase` **无 organisation 字段** | dto `Case.scala` |

**敏感卫生**：`/api/status` 同体含 `config.protectDownloadsWith`（附件 ZIP 密码）。探针**只提取版本字段，绝不返回/记录/持久化原始体**。

### 6.2 实现
- `read_adapters/verified.py`（纯 kernel，**无新 import**，保持 `TestProofKernelPurity` allowed_stdlib 绿）：`IdentityEvidence`（observed_version/observed_reader_organisation/observed_reader_roles/version_probe/organisation_probe）+ `IdentityAssessment`（version_matches_certified/reader_organisation_known/gate5_instance_binding/gate5_tenant_binding/reason）+ `assess_identity_evidence(evidence, *, certified_version)` 纯评估器。
- `read_adapters/thehive.py`：`read_identity()`（两次只读 GET 探针）+ `_identity_get`（单次只读 GET，任何失败→`None` fail-closed，不 raise，不伪造身份，共享 no-redirect 传输，绝不返回原始体）+ `_probe_status_version` + `_probe_reader_organisation`。`read_identity` 是 **READ 动词**，不在 write-verb 封印禁止集内。

### 6.3 诚实结论（门⑤ 仍 fail-closed）
读取者组织 ≠ 案件所属组织；`/api/case/{id}` 200 只证明**可见性**（owned OR shared）非所有权；`/api/status` 无稳定实例 id；`OutputCase` 无 organisation。故 Amendment §12.2-B B2 前置条件**不满足**，`assess_identity_evidence` 对 4.1.24-1 **恒返回** `gate5_instance_binding = gate5_tenant_binding = None`。seam 将版本断言从 config-declaration **升级为运行时观测**，但**绝不单独解锁 `confirmed_success`**。base URL/config 字符串绝不冒充真实身份。

### 6.4 未接线证明（约束 #11）
`test_verified_proof_isolation.py::TestIdentitySeamIsolation`（4）：无 api router 接线身份探针；webhook 路径绝不可达身份探针；`assess_identity_evidence` **零生产调用者**（`app/` 下 callers == 空集）；`derive_context` 绝不调用身份探针（门⑤绑定只来自 M4-A 绑定）。

### 6.5 验收
`test_read_identity_evidence.py`（510 行，34）：`TestAssessIdentityEvidence`（12，full evidence 版本匹配但 gate5 恒 None、版本不符/未观测/空串/非字符串、org 未观测/空串、base_url 非认证版本、config 串非观测、gate5 矩阵恒 None、纯函数不改输入、roles 默认空）+ `TestReadIdentityVerb`（17，观测版本+组织、**只提取版本绝不返回原始体**、**只探 status+user/current 绝不探 /api/system**、每端点单次无重试、status 失败/user 401/字段缺失/非 JSON/非对象/timeout/连接失败→unavailable、roles 排序过滤、端到端全观测仍不解锁门⑤）+ `TestReadIdentityIsolation`（5，read 动词无 write 动词、名称 read 前缀、错误体 secret 不泄露、api_key 不泄露、base_url 非观测身份）。

---

## 7. 六道合取门当前状态矩阵

| 门 | 名称 | 状态 | 依据 |
| --- | --- | --- | --- |
| ① | IDENTITY（资源 ID 精确匹配）| ✅ 实现 | `verify_creation_effect`：字符串 `_id`/`id` 与 reference 精确匹配，跨实例/历史同案号 → `REASON_RESOURCE_ID_MISMATCH` |
| ② | CORRELATION（execution 关联标签）| ✅ 实现 | 声明的 InputCase.tags 含 `sentinelflow_execution_tag(execution_id)`；缺失/旧案件补标签 → refusal |
| ③ | CREATION-TIME（createdAt 存在）| ✅ 实现 | 缺失/非数/bool/越界 → `None` fail-closed |
| ④ | TIME-ORDER（时间顺序）| ✅ **M4-D 修订** | 真实 `dispatch_started_at` vs `terminal_recorded_at` 非对称窗口；**权威 = gate 4c `createdAt` epoch-millis 精确匹配**；300s 容差非权威窗口 |
| ⑤ | INSTANCE/TENANT（实例/租户）| ⛔ **保持 fail-closed** | TheHive 4.1.24-1 无权威派发时来源；M4-A 绑定 `target_instance`/`target_tenant` 诚实 `None`；M4-B seam 未接线且读取者组织 ≠ 案件所属组织 → `instance_binding_unknown` |
| ⑥ | APPROVED ACTION（审批动作）| ✅ **M4-D 修订** | `approval_id` + 被批准 recommendation/action/target + **派发时审批快照** + 执行快照交叉核对，不只看当前 `approval.status` |

**合取语义**：六门全过才铸造 `VerifiedCreationEffect`；首失败即 `CreationRefusal`。门⑤ fail-closed ⇒ **真实历史绝无 `confirmed_success`**（正确且安全）。

---

## 8. M4-E — 隔离回归 + 完整后端/跨层回归

### 8.1 覆盖映射（任务 E 枚举 → 落点）

| E 枚举项 | 落点 | 状态 |
| --- | --- | --- |
| 绑定持久化 | `TestSuccessChain` + `test_dispatch_binding.py` | ✅ |
| 异常后保留 | `TestBindingSurvivesEveryOutcome`（NEW，12）| ✅ |
| 旧历史拒绝 | `test_verified_creation_proof.py`（`with_binding=False`）| ✅ |
| 跨实例/租户 | 门①（`REASON_RESOURCE_ID_MISMATCH`）+ 门⑤（`instance_binding_unknown`）| ✅ |
| 旧案件补标签 | 门②（correlation tag）| ✅ |
| 错误时间 | 门③/④（M4-D）| ✅ |
| 审批不一致 | 门⑥（`binding_approval_status` 快照，M4-D）| ✅ |
| Webhook 伪造 | 来源隔离（PULL-only，webhook 物理不可达）+ `TestWebhookImportIsolation` | ✅ |
| 无权限 | RBAC / operator 认证套件 | ✅ |
| append-only | Outcome append-only 套件 | ✅ |
| 零额外副作用 | `TestPhase2Invariance`（Phase 2 字节不变 + 只触 execution_log）| ✅ |
| 各类读取失败 | M4-B `read_identity`（34）+ M3 `read_creation` | ✅ |

### 8.2 回归结果

| 范围 | 结果 |
| --- | --- |
| **完整后端 + 跨层回归** | **2810 passed / 5 deselected / 0 failed（63.73s）**，0 skipped |
| M4-E 证据集（binding + cross-layer + verified proof + isolation + read identity）| **281 passed / 1 deselected** |
| `test_dispatch_binding.py`（绑定原语单元）| 102 passed |
| `test_execution_cross_layer_regression.py`（含 `TestBindingSurvivesEveryOutcome`）| 51 passed |
| `test_read_identity_evidence.py`（M4-B seam）| 34 passed |

### 8.3 external 默认 deselect（5 个，零出站）
1. `test_execution_shuffle_adapter.py::TestRealShuffle::test_real_workflow_trigger`
2. `test_execution_thehive_adapter.py::TestRealTheHive::test_real_thehive_case_creation`
3. `test_execution_wazuh_adapter.py::TestRealWazuh::test_real_active_response`
4. `test_read_adapter_thehive.py::TestRealLabRead::test_real_get_case_verifies_creation`
5. `test_verified_creation_proof.py::TestRealLabTrustedRead::test_real_read_creation_observes_typed_creation_with_none_bindings`

总收集 2815 = 2810 默认 + 5 external（`conftest.py::pytest_collection_modifyitems` 自动 deselect，非 skip，套件保持 0 skipped）。

---

## 9. 安全边界与冻结契约合规

| 约束 | 合规 |
| --- | --- |
| ① Dispatch Fact 与 External Outcome Fact 独立 | ✅ 绑定是 dispatch 侧事实；证明派生独立读 outcome，互不冒充 |
| ② Outcome append-only | ✅ `_persist_verified_creation_outcome` 只 append，不改历史 |
| ③ 五态固定 | ✅ 未新增/修改状态词 |
| ④ Webhook 只接收外部事实 / Manual Reconcile 只读 | ✅ 来源隔离 AST 证明 webhook 不可达 proof/identity seam |
| ⑤ 不自动轮询/重试/补偿/触发新外部执行 | ✅ `read_identity` 每端点单次无重试；seam 未接线 |
| ⑥ 高风险动作经人工审批 + 权限策略 | ✅ 门⑥ M4-D 强化派发时审批快照核对 |
| ⑦ 四类凭据严格隔离 | ✅ 只读钥独立；绑定/探针绝不记录 secret（token 卫生测试）|
| ⑧ 共享外部状态词表全空 fail-closed | ✅ 未恢复任何词表 |
| ⑨ 不恢复 `case_created`，不以客户端可控 verified/source/provenance 冒充证明 | ✅ M4-C 封印门拒绝未封印效果；contributor 白名单丢弃 `verified`/`source` 走私键 |
| ⑩ 冻结 `normalize_external_state` 2 参数 / `map_external_state` 单委托 / 公开 DTO | ✅ 未改动 |
| ⑪ sealed 默认 Reader registry 空 / 生产 router 未接线 | ✅ `assess_identity_evidence` 零生产调用者（AST 证明）|
| ⑫ 不改历史 Outcome / 不重写 Git / 不移动 tag / 不 push | ✅ 全部本地前向提交，ahead 48，未 push |

---

## 10. 证据矩阵（Evidence Matrix）

| 声明 | 证据类型 | 落点 |
| --- | --- | --- |
| 绑定派发前持久化 | 真实 service+DB 回归 | `TestBindingSurvivesEveryOutcome`（cross-layer）|
| 绑定异常后存活 | 真实 service+DB 回归（adapter 失败/protocol_violation）| 同上 |
| 绑定原语 fail-closed | 纯组件单元 | `test_dispatch_binding.py`（102）|
| contributor 白名单防走私 | 纯组件单元（恶意 contributor）| `TestContributorWhitelist` |
| 门④真实派发开始 | 组件 + 服务 | `test_verified_creation_proof.py`（M4-D）|
| 门⑥派发时审批快照 | 组件 + 服务 | 同上（`binding_approval_status`）|
| 证明通道收口 | AST + 运行时封印门 | `test_verified_proof_isolation.py::TestProofChannelClosure` |
| 身份 seam fail-closed | 源码取证 + stub 回归 | `test_read_identity_evidence.py`（34）|
| seam 未接线 | AST 零生产调用者 | `TestIdentitySeamIsolation`（4）|
| 门⑤真实历史 fail-closed | 服务回归（`instance_binding_unknown`）| `test_verified_creation_proof.py` Service 段 |
| 完整回归绿 | 全后端 + 跨层 | 2810 passed / 5 deselected / 0 failed |

---

## 11. 剩余阻塞（Remaining Blockers — 按设计保持，绝不自动放宽）

1. **门⑤ 实例/租户真实历史解锁 = BLOCKED（设计内 fail-closed）**：TheHive 4.1.24-1 无可信派发时实例/租户来源（`OutputCase` 无 organisation；`/api/status` 无稳定实例 id；读取者组织 ≠ 案件所属组织），真实历史 `ExecutionLog` 无绑定。**不得用当前 config 倒填旧记录**。未来解锁需：上游提供权威认证实例/租户来源 + 前向绑定填充 `target_instance`/`target_tenant` + 门⑤消费该绑定。M4-A/M4-B 已使之前向就绪。
2. **真实 Lab 联调 = LAB BLOCKED**：无授权的资源充足实验主机（当前 Windows 主机内存不足、无容器运行时、无 WSL 分发）。5 个 `external` 测试默认 deselect。**不以 Mock 冒充真实联调**；不强行部署完整 TheHive 栈。
3. **生产版本活性 = UNKNOWN**：registry 密封、router 未接线；`EXPECTED_VERSION` 是 `config-declaration` 非运行时活性证明。M4-B `/api/status` 版本探针提供**运行时观测**能力，但 seam 未接线，故生产活性仍未证明。
4. **生产 HTTP 接线 = 未授权**：M4-C 已收口证明通道并预留 operator 认证/RBAC/Manual Reconcile 权限复用约束，但**当前不接生产 router**（约束 #11）。

---

## 12. 交付物清单

| 交付物 | 位置 |
| --- | --- |
| M4 Final Report（本文档）| `docs/design/phase3.4.5-m4-forward-dispatch-binding-proof-closure-final-report.md`（仓库内 doc-only 提交）|
| 仓库外脱敏审查 ZIP | `phase3.4.5-m4-review-bundle.zip`（完整 patch + 关键源码 + 证据矩阵 + 测试日志 + Git 状态 + 剩余阻塞）|
| M4 代码/测试提交 | `f3bc6e4`→`12923e5`→`3db671d`→`f8afd74`→`ce3f395`（本地前向，ahead 48，未 push）|

> **最终立场**：M4 A–E 五项授权范围内的代码、测试、文档已全部落地，隔离与完整回归全绿（2810 passed / 5 deselected / 0 failed）。门⑤真实历史解锁、真实 Lab 联调、生产版本活性、生产 HTTP 接线**按设计保持阻塞/fail-closed**，绝不以配置声明、客户端可控标志或 Mock 冒充可信证明。等待 Final Review。
