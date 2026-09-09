# Phase 3.4.5-M2-R — TheHive 安全整改 · 最终交付报告（分能力验收）

> **状态：DELIVERED — AWAITING FINAL REVIEW（分能力验收，未合并为「全部通过」）**
> 本文件是 M2-R 安全整改轮的**唯一最终交付**：实际 HEAD/提交链、三项 P1 + 两项修正的逐项处置、
> 全量 diff 清单、来源门验证、版本/凭据检查、修复前后测试、Git 状态、剩余阻塞。
> **本轮明确结论：**
> - **P1-1 来源门（§2）= 已 fail-closed 修复 + 三入口伪造防御测试 PASS**（合成成功信号任何路径不可伪造、不被接受）
> - **P1-2 创建证据门（§3）= gate3 强制已落地 + 负向测试 PASS；严格 time/instance/tenant 关联 = DESIGN ONLY（Amendment，冻结 DTO 边界）**
> - **P1-3 测试验收（§5）= 四级测试分层 + 真实 HTTP 路由链测试 PASS（2568 passed）**
> - **Fix A 版本/凭据/HTTP（§4）= 精确版本门 + 独立只读钥 + 无重定向 opener 已落地；registry 仍空 / router 未接线**
> - **Fix B Lab 部署证据（§6）= 官方 `thehive4` + digest + EOL 事实 + 主机资源重估（含 VM 工具探测）已更正**
> - **真实本地联调（§6）= LAB BLOCKED（本机物理不可行；2026-09-09 重探确认）**
> - **生产部署认证 = UNKNOWN（本里程碑不触碰生产；始终单列）**
>
> **`M2 LOCAL LAB E2E` 仍未达 PASS 条件**（真实本地 TheHive 资源效果闭环因 LAB BLOCKED 未能真实执行）。**不伪造全部通过；不自动宣称 M2 LOCAL LAB E2E PASS。**

## 0. 文档控制区（Document Control）

| 字段 | 值 |
| --- | --- |
| 文档状态 | **DELIVERED — AWAITING FINAL REVIEW**（非 FROZEN；不认证任何生产运行时）|
| 授权 | M2-R §1–§7（ONE AGENT · SECURITY REMEDIATION + ISOLATED REGRESSION + LOCAL COMMITS · **NO PUSH**）|
| 授权基线提交 | `3b23520`（M2 Final Report，**保留、不重写历史**）|
| 采集日期 | 2026-09-09 |
| 采集方式 | **权威源码只读取证 + git 元数据核验 + 本机资源只读重探（含 VM 工具）+ 隔离测试**；测试用 stub transport + 内存 SQLite；**无镜像拉取、无服务启动、无真实外部写入、无生产凭据、无管理员安装、零外部网络** |
| 唯一交付物（本文档）| `docs/design/phase3.4.5-m2-r-thehive-security-remediation-final-report.md`（新增，doc-only 提交）|
| 关联文档（本轮）| `phase3.4.5-m2-r-thehive-source-isolation-amendment.md`（新增，DESIGN ONLY）、`phase3.4.5-m2-thehive-lab-evidence-and-deployment-plan.md`（§2.3/§5.4/§6.2/§6.3 更正）|
| 运行环境 | Windows 10.0.26100（24H2）；16 逻辑核；15.73 GB RAM（**2026-09-09 重探：仅 2.36 GB 空闲**）；`backend\.venv` Python **3.12.2** / pytest **9.1.1**；`sqlite://` 内存库 + StaticPool |
| 保护约束 | 不改冻结通用契约/DTO/DB 模型/历史 Outcome；不改 Wazuh G1-C 空词表（`0c372aa` 保持不变）；不进 Shuffle；不建 WazuhReader；不改 `shuffle.py`/`wazuh.py`/`executions/thehive.py`（写适配器，G3 认证保留）；不改 sealed `default_read_adapter_registry()`；不接线 router；不 amend/rebase/reset/force-push/移动 tag；**不 push** |

---

## 1. 整改摘要（M2 Final Review 裁决 → 逐项处置）

M2 Final Review 裁决「部分通过、完整里程碑未通过」，G5 Reader = **NEEDS FIX**，列出三项 P1（阻塞接线）+ 两项修正。本轮逐项处置：

| # | 审查发现 | 处置 | 状态 |
| --- | --- | --- | --- |
| **P1-1** | 合成成功状态 `case_created` 进入共享入站词表，纯映射 2 参数无法区分可信 Reader vs Webhook | §2 前向修复：thehive 四集**清空 fail-closed**（G1-C 先例）；三入口伪造防御测试；来源隔离通道 → **Amendment（DESIGN ONLY）** | ✅ **已 fail-closed 修复 + 测试 PASS** |
| **P1-2** | 创建效果第三重证据门被放宽（缺 `createdAt` 仍确认成功；不核对创建时间 vs 派发时间）| §3 前向修复：`_verify` gate3 **强制** `createdAt`（缺失/非法/absurd → `case_unverified`）+ 负向测试；严格 time-order/instance/tenant 关联 → **Amendment（冻结 DTO 不携带派发记录）** | 🟡 **gate3 已落地；严格关联 DESIGN ONLY** |
| **P1-3** | 真实测试断言不足（允许 `case_unverified` 冒充成功；seed-chain 命名 E2E）| §5 前向修复：`TestRealLabRead` 严格断言 `CASE_CREATED`（LAB BLOCKED 时 skip）；`TestPlatformChainClosure` → 诚实改名 `TestSeededChainIsolation`；新增 `TestHttpRouteChain`（真实 HTTP 审批/执行/对账路由链）；四级测试分层 | ✅ **已修复 + 测试 PASS** |
| **Fix A** | 版本/凭据门：仅凭 URL+key 自动授权；复用写密钥；重定向凭据外泄风险 | §4 前向修复：`THEHIVE_EXPECTED_VERSION` 精确版本门 + `THEHIVE_READ_API_KEY` 独立只读钥（绝不回退写钥）+ `_NoRedirectHandler`（拒绝 3xx，Authorization 不跨主机）+ 只读钥纳入脱敏集；**不关 TLS、不放松 URL 校验** | ✅ **已落地**（registry 仍空 / router 未接线）|
| **Fix B** | 部署镜像引用有误（`thehiveproject/thehive:4.1.24-1`）；TheHive 4 已 EOL | §6 前向修复：更正为官方 `thehiveproject/thehive4:4.1.24-1` + digest `sha256:c8b6c7…` + EOL/归档事实 + 主机资源重估（含 VM 工具探测）| ✅ **已更正**（Lab 仍 LAB BLOCKED）|

**未在本轮完成（依授权如实保持）**：真实本地联调（**LAB BLOCKED**）；Reader 真实 GET 验证 + 生产接线（**EVIDENCE-GAPPED**）；来源隔离通道 + 严格创建关联的**实现**（**Amendment IMPLEMENTATION 待用户授权**）；生产部署认证（**UNKNOWN**）。

---

## 2. Git 提交链（Commit Chain — 全部本地前向，NO PUSH）

| 顺序 | 提交 | 类型 | 说明 | 对应发现 |
| --- | --- | --- | --- | --- |
| 基线 | `3b23520` | docs | M2 Final Report（**保留，不重写历史**）| 审查对象 |
| 1 | *(本轮)* | **code+test** | §2 来源门 fail-closed：thehive 词表清空 + 三入口伪造拒绝测试 | P1-1 |
| 2 | *(本轮)* | **code+test** | §3+§4 Reader 创建门 `createdAt` 强制 + 版本/独立只读钥/无重定向授权 | P1-2 + Fix A |
| 3 | *(本轮)* | **test** | §5 真实 HTTP 审批/执行/对账路由链测试 + seed-chain 诚实改名 | P1-3 |
| 4 | *(本轮)* | docs | §6 Lab 证据更正（`thehive4`+digest+EOL+主机重估）+ 来源隔离 Amendment（DESIGN ONLY）| Fix B + P1-1/P1-2 设计 |
| 5 | *(本文档)* | docs | M2-R 最终交付报告（分能力验收）| §7 |

- **基线 HEAD**：`3b23520`（已核验：`git rev-parse HEAD` 一致；`main`；`origin/main...HEAD = 0 behind / 33 ahead`，提交本轮前）。
- **纪律**：全程**未 push**、**未** amend/rebase/reset/force-push、**未**移动任何历史 tag；`117ab6b`（M2 §5）/`3b23520`（M2 报告）/`0c372aa`（G1-C）均为**只读历史**；文档与代码分离提交。

---

## 3. P1-1 来源门整改（§2 — 合成成功状态不可伪造）

### 3.1 缺陷与修复

`reconciliation.py` 的 `ADAPTER_STATE_VOCABULARIES["thehive"]` 是 **path-agnostic 单一语义映射**，经 `mapping.py → normalize_external_state(adapter, external_state)`（**冻结 2 参数**）被 **webhook PUSH** 与 **manual_reconcile PULL** 两路共享。M2 §5 曾把 `case_created` 加入 `terminal_success_states`；审查者独立验证：启用有效 `THEHIVE_CALLBACK_TOKEN` 后，裸串 `case_created` 可经 webhook 请求体直接映射为 `confirmed_success`（**G1-A 缺陷类**）。

**修复（G1-C 先例，前向提交，`117ab6b` 未 amend）**：thehive 四集**全部清空** → `case_created` 在**任何路径**都 → `UnrecognizedExternalState` → **422 / 零 Outcome Fact**。全平台**无任何** adapter 拥有 evidenced 外部状态词表（wazuh/shuffle/thehive/mock 四集皆空）。

### 3.2 为何不改冻结契约表达来源隔离（→ Amendment）

在共享词表内区分来源的四种途径**全部违反封板**：(A) 给 `normalize_external_state` 加 source 参数 → 违反冻结 2 参数签名；(B) 在 `map_external_state` 加 `if` → 违反 `test_mapping.py` 单委托封板；(C) 加 `verified=true` 标志 → **审查者明确否决**；(D) 建第二张映射表 → 违反 G1-C「NO second mapping table」。故依授权 §2「先 fail-closed，再提交最小 Amendment」→ 来源隔离通道设计见 `phase3.4.5-m2-r-thehive-source-isolation-amendment.md`（**DESIGN ONLY**）。

### 3.3 三入口伪造防御验证（来源门验证 — 全部零 fact）

| 入口 | 测试 | 伪造尝试 | 结果 |
| --- | --- | --- | --- |
| **webhook PUSH** | `test_webhook_persistence.py::test_thehive_forged_case_created_callback_is_refused_zero_facts` | 有效 callback token + schema/correlation-valid body 携带裸串 `case_created` | **422 / 零 fact** |
| **reconcile PULL（真实 HTTP）** | `test_thehive_write_read_closure.py::TestHttpRouteChain` | 真实 HTTP 执行→对账路由（空生产 registry）| **404 `UnsupportedAdapterRead` / 零 fact**（生产读路径未接线）|
| **service 级（注入 reader）** | `test_thehive_write_read_closure.py::TestSeededChainIsolation` | 注入 reader 产出 verified `case_created` | **fail-closed 空词表拒绝 / 零 fact** |

> **结论**：合成成功信号 `case_created` 现在**既不可被任何入口伪造，也不被任何入口接受**（映射层对来自任何来源的该词一律 REFUSE），直到可信 Reader 来源隔离通道获批。这直接阻止了「与 G1-A/G1-C 同类的问题重新出现」。

---

## 4. P1-2 创建证据门整改（§3 — 三重合取 + 严格关联设计）

### 4.1 已落地：gate3 `createdAt` 强制

`read_adapters/thehive.py:_verify` 三重合取门（统一到冻结设计 §5.2）：

| 门 | 校验 | 不满足时 |
| --- | --- | --- |
| 1. IDENTITY | `resource_id = _id ‖ id`（非空 str）`== external_reference` | `case_unverified`（no_string_resource_id / resource_id_mismatch）|
| 2. CORRELATION | `tags` 含 `sentinelflow:execution:<id>`（精确）| `case_unverified`（missing_execution_correlation_tag）|
| **3. CREATION（M2-R 强制）** | `createdAt`（epoch millis）→ `observed_at`；**缺失/非法/absurd → None → 不再确认** | `case_unverified`（**missing_created_at**）|

**修复了审查者探针**：缺 `createdAt` 现在 → `case_unverified`（原 M2 仍返回 `case_created`）。`observed_at`（外部创建时间）与 server 观察时间**严格区分**；**绝不用「now」伪造历史创建时间**，**绝不让缺失/过早时间取得排序优势**。

### 4.2 DESIGN ONLY：严格 time-order / instance / tenant 关联（→ Amendment §6）

审查者另一探针——**十年前创建、事后补加匹配标签的案件仍返回 `case_created`**——的根治需要门 4（`createdAt >= dispatch_time` + 有界窗口）与门 5（目标实例/租户匹配）。**根因**：冻结的 `AdapterReadRequest` DTO 只携带 `execution_id`/`adapter`/`external_reference`，**结构上不携带不可变派发记录**（派发时间/实例/租户）。依授权 §3「若严格来源关联需要修改冻结 DTO…停止该部分并提交最小 Amendment」→ **停在设计**，方案见 Amendment §6（倾向落在 PULL-only 的 READ-side mapper，从既有 `ExecutionLog` 链行派生派发事实，**不改冻结 DTO 结构**）。

### 4.3 负向测试覆盖（已落地）

`test_read_adapter_thehive.py` 覆盖：缺失/非法/空 `createdAt`、不匹配 reference、跨 execution 标签、非字符串 id、404/401/403/timeout/连接失败各自区分（**绝不** `confirmed_failure`）。门 4/5 的负向（十年前补标签 / 跨实例 / 跨租户 / 未来时间）随 Amendment IMPLEMENTATION 落地。

---

## 5. P1-3 测试验收整改（§5 — 四级分层 + 真实 HTTP 路由链）

### 5.1 四级测试分层（诚实标注，不以 seed 冒充 E2E）

| 级别 | 测试 | 范围 | 状态 |
| --- | --- | --- | --- |
| **L1 COMPONENT** | `TestWriteReadCorrelationHandshake` | reader 级 handshake，无 DB | PASS |
| **L2 SERVICE** | `TestSeededChainIsolation`（原 `TestPlatformChainClosure`，**诚实改名**）| seeded chain + 直接调 `reconcile_execution` + 注入 reader | PASS（fail-closed 零 fact）|
| **L3 HTTP** | `TestHttpRouteChain`（**本轮新增**）| 真实 FastAPI 路由：POST `/api/v1/executions`（经 `get_response_executor` seam 注入真 `TheHiveExecutor`+stub）→ 201 succeeded 真服务写链；POST `/api/v1/executions/{id}/reconcile` → 空生产 registry → 404 零 fact | PASS |
| **真实外部 E2E** | `test_read_adapter_thehive.py::TestRealLabRead` | `@pytest.mark.external`，真实 GET | **DESELECTED（LAB BLOCKED）** |

### 5.2 真实测试严格化

`TestRealLabRead::test_real_get_case_verifies_creation` 现**严格断言 `CASE_CREATED`**（不再接受 `case_unverified` 冒充成功）；`THEHIVE_LAB_*` 未设 → `pytest.skip("LAB BLOCKED")`，**不假装通过**。

### 5.3 L3 HTTP 路由链证明的生产事实

`TestHttpRouteChain` 证明**诚实的生产行为**：真实 HTTP 执行写入链（`requested→dispatched→succeeded`）+ `detail["case_id"]==REFERENCE` + 关联标记；真实 HTTP reconcile 路由关联成功但命中**空生产 registry** → `UnsupportedAdapterRead` **404 静态 detail**（不泄露 execution_id/adapter/reference/token）+ **零 fact** + **只读不写新行**。这证明生产读路径**未接线**（Fix A/§4），HTTP 层**无法伪造** `confirmed_success`。

---

## 6. Fix A 版本 / 凭据 / HTTP 安全（§4）

| 项 | 落地 | 证据 |
| --- | --- | --- |
| **精确版本门** | `CERTIFIED_THEHIVE_VERSION="4.1.24-1"`；工厂仅在 `THEHIVE_EXPECTED_VERSION` **精确等于**时授权 Reader；未设/不匹配 → fail-closed | `read_adapters/thehive.py` L165；`registry.py:_thehive_readers` gate 3 |
| **独立只读钥** | `THEHIVE_READ_API_KEY`（**绝不回退** create-capable 的 `THEHIVE_API_KEY`，最小权限）；纳入 `current_secret_values()` 脱敏集 | `config.py`；`secrets.py` L200+；`registry.py` gate 2 |
| **无重定向 opener** | `_NoRedirectHandler.redirect_request → None`：拒绝任何 3xx，`Authorization` **绝不跨主机转发**（CWE-522）；3xx → `ReadTransportError` → `reconciliation_failed` | `read_adapters/thehive.py` L217-244 |
| **不关 TLS / 不放松 URL** | `build_opener` 仍装默认**验证型** `HTTPSHandler`；`validate_base_url` 未改（拒 query/fragment/userinfo/非 http(s)）| `thehive.py` L230-233；`secrets.py` L66-98 |
| **registry 空 / router 未接线** | `default_read_adapter_registry()` 保持 **sealed 空**；`reconcile.py` 仍 `reconcile_execution(db, id, operator)` 无 registry → 404 零 fact | `registry.py` docstring；`TestHttpRouteChain` |

> **上线前阻塞（非已发生事故）**：当前路由未接线，故 Fix A 是**上线前**门。真实 Lab + 完整安全验收通过前**不开放**真实 Reader、**不接线** router（授权 §4）。实例/租户绑定 + 活性版本证明见 Amendment §7。

---

## 7. Fix B Lab 部署证据更正（§6）

### 7.1 镜像引用更正（官方注册表核验）

| 项 | M2 报告旧值（错误）| M2-R 更正值（官方）|
| --- | --- | --- |
| 镜像仓库 | `thehiveproject/thehive:4.1.24-1` | **`thehiveproject/thehive4:4.1.24-1`** |
| manifest digest | NOT OBTAINED | **`sha256:c8b6c7eaa0cd21853cbf88eae836c57de2aec29e6edb8a9d49b491dbc09c6811`**（审查者从官方 registry 独立核验）|
| 部署校验 | — | 拉取后**必须**校验 digest 一致 + 平台架构匹配；**禁止** `latest` |

### 7.2 TheHive 4 EOL 事实（已记录）

TheHive 4 公开版本**已停止维护**，官方仓库**已归档（archived）**。`thehiveproject/thehive4` 仅适合**隔离兼容性实验**（源码契约取证 + 隔离 Lab），**不应作为新的生产部署推荐**；本 Lab 即便通过也**不得**升级为生产级认证。

### 7.3 主机资源重估（2026-09-09 只读重探，含 VM 工具）

| 探测项 | 结果 | 影响 |
| --- | --- | --- |
| docker / podman / nerdctl | **全部 ABSENT** | 无容器运行时 |
| **VBoxManage / vmware / qemu**（本轮新探）| **全部 ABSENT** | 无本地 VM 管理工具 |
| WSL 已安装分发版 | **零** | 无法承载 Linux 工作负载 |
| 空闲内存 | **2.36 GB**（总 15.73 GB；较 M2 探测的 3.35 GB **更低**）| 不足以跑 TheHive(JVM)+JanusGraph+ES 栈 |
| HypervisorPresent | True（固件级 Hyper-V 可用）| 但无可用运行时/分发版/VM 工具 |

> **判定：`LAB BLOCKED`（范围仅限本 Windows 主机）。** 本轮**已额外探测 VM 工具**（非仅 Docker），均缺失。但依授权 §6「不因未发现 Docker 命令就推断所有可用 VM/远程实验环境均不存在」：本轮**未**穷尽枚举远程/云实验环境，故**不**据此推断「任何可用实验环境均不存在」。若存在资源充足（≥8 GB 空闲 + 容器运行时 + 管理员授权）的 **VM / 远程主机**，§6.3 部署方案（已更正镜像/digest）可在其上复现真实 Lab——**需用户确认实验主机并另行授权**（本轮不自动进入、不管理员安装、不重启、不拉镜像、不伪造 Lab）。

---

## 8. 完整回归证据（§7 — 修复前后）

环境：`backend\.venv`（Python **3.12.2** / pytest **9.1.1**）；`conftest.py` 强制 `AI_PROVIDER=mock`、`db_session`=`sqlite://` 内存库 + StaticPool、`external` marker 默认 deselect。**无生产凭据、零外部网络。**

| # | 命令（于 `backend/`）| M2（修复前）| **M2-R（修复后）** |
| --- | --- | --- | --- |
| 1 | `pytest -q`（**完整后端套件**）| 2556 passed / 4 deselected | **2568 passed / 4 deselected / 0 failed**（61.55s）|
| 2 | `pytest -m external --co -q`（真实系统枚举）| 4/2560 | **4/2572 collected（2568 deselected）** |
| 3 | M2-R 触达 7 文件（reader/closure/写适配器/mapping/reconciliation/webhook/manual_reconcile_api）| — | **593 passed / 2 deselected / 0 failed** |
| 4 | `git diff --check` | EXIT=0 | **EXIT=0（无空白错误）** |

**+12 测试净增（2556→2568）来源**：`TestHttpRouteChain`（+2）、`test_mapping.py` 强化 `case_created`/`case_unverified` 参数（+7）、webhook 伪造拒绝（+1）、reader gate3 负向（+2）。

**4 个 deselected external 精确核算（证明零出站、非隐藏失败）**：`test_execution_shuffle_adapter.py::TestRealShuffle`、`test_execution_thehive_adapter.py::TestRealTheHive`、`test_execution_wazuh_adapter.py::TestRealWazuh`、`test_read_adapter_thehive.py::TestRealLabRead`——正是需真实外部系统的 4 个用例（默认 `pytest` **绝不**自动连接真实系统）。

---

## 9. 分能力验收（逐项报告，任一缺证据保持未完成，绝不合并为「全部通过」）

| # | 能力项 | 状态 | 证据 | 缺什么（若未完成）|
| --- | --- | --- | --- | --- |
| 1 | **P1-1 来源门** | ✅ **已 fail-closed 修复 + 三入口伪造防御 PASS** | §3：thehive 四集 ∅；三入口（webhook 422 / reconcile-HTTP 404 / service 注入）均零 fact | 来源隔离通道**实现**（Amendment IMPLEMENTATION 待授权）|
| 2 | **P1-2 创建证据门** | 🟡 **gate3 强制已落地；严格 time/instance/tenant = DESIGN ONLY** | §4：`_verify` gate3 缺 `createdAt`→`case_unverified`；负向测试 PASS | 门 4/5（派发时间/实例/租户）需冻结 DTO 边界裁决 → Amendment §6 |
| 3 | **P1-3 测试验收** | ✅ **已修复 + PASS** | §5：四级分层；`TestRealLabRead` 严格 `CASE_CREATED`；`TestHttpRouteChain` 真实 HTTP 路由链；seed-chain 诚实改名 | 真实外部 E2E 观测（LAB BLOCKED）|
| 4 | **Fix A 版本/凭据/HTTP** | ✅ **已落地**（registry 空 / router 未接线）| §6：精确版本门 + 独立只读钥 + 无重定向 + 不关 TLS | 实例/租户绑定 + 活性版本证明（Amendment §7，需真实 Lab）|
| 5 | **Fix B Lab 证据** | ✅ **已更正** | §7：`thehive4`+digest+EOL+主机重探（含 VM 工具）| 部署主机实际拉取校验 digest + 平台架构 |
| 6 | **完整后端回归** | ✅ **PASS** | §8：**2568 passed / 4 deselected / 0 failed**；`git diff --check` 净 | —（隔离范围内完成；**不代表**真实联调通过）|
| 7 | **真实本地联调** | ⛔ **LAB BLOCKED** | §7.3：无容器运行时 + 无 VM 工具 + 零 WSL 分发版 + 2.36 GB 空闲 | 资源充足 VM/远程主机（**需用户确认 + 另行授权**）+ 镜像 digest 实拉校验 |
| 8 | **生产部署认证** | ⛔ **UNKNOWN** | 本里程碑不触碰生产 | 真实目标实例契约 / 权威 registry digest + 生产版本取证；**Source CERTIFIED ≠ 生产认证** |

> **合并结论被明确禁止**：能力 1/3/4/5/6 在其范围内 **PASS**；能力 2 **部分完成**（gate3 落地，严格关联 DESIGN ONLY）；能力 7 **LAB BLOCKED**；能力 8 **UNKNOWN**。**不得**表述为「全部通过」。**`M2 LOCAL LAB E2E = PASS` 条件未满足，不标记 PASS。**

---

## 10. 保护约束合规声明（Protection Constraints Compliance）

本轮**未**做任何被禁止的操作，逐项确认：

- ✅ **未改冻结通用契约**：`normalize_external_state`（2 参数）、`map_external_state`（单委托封板）、`AdapterReadRequest`/`AdapterReadResult`（冻结 DTO）、DB 模型、审批规则**均未动**（`git status` 确认 `read/base.py`/`mapping.py` 无修改）。
- ✅ **未改 Wazuh G1-C 空词表**（`0c372aa` 保持不变）；**未改** `shuffle.py`/`wazuh.py`/`executions/thehive.py`（写适配器，G3 认证保留）；**未建** WazuhReader；**未进** Shuffle。
- ✅ **未建第二张映射表**；**未加**调用者可控 `verified` 标志；**未改** sealed `default_read_adapter_registry()`（保持空）；**未接线** router。
- ✅ **未修改任何历史 Outcome / 历史提交**；`117ab6b`/`3b23520`/`0c372aa`/`8b89fe7` 均**只读**；整改经**新前向提交**。
- ✅ **未恢复**任何未经认证的外部状态；**未**用数字案号替代字符串资源 ID；**未**增自动重试/轮询/补偿；**未**绕过人工审批。
- ✅ **未** amend / rebase / reset / force-push；**未**移动历史 tag；**未 push**（全程本地）。
- ✅ **未**管理员安装、**未**重启宿主机、**未**拉取/执行未校验镜像、**未**连接生产、**未**发起真实业务写入。
- ✅ 测试用隔离 stub + 内存 SQLite，**未用生产凭据**、**零外部网络**；占位凭据（`LAB_THEHIVE_KEY_DO_NOT_USE`、`exec-secret-thehive-http-chain`）均**非真实**；`.env` 已 gitignore；本文档/Amendment/diff/审查 ZIP **不含任何真实密钥或敏感数据**。

---

## 11. 剩余阻塞 · 下一阶段建议 · 停止声明

### 11.1 剩余阻塞（均需另行单独授权，本轮不自动进入）

1. **Amendment IMPLEMENTATION（P1-1 来源隔离通道 + P1-2 严格关联）**：本轮 DESIGN ONLY；需用户 Review `phase3.4.5-m2-r-thehive-source-isolation-amendment.md` 并授权独立 Implementation Gate（裁决 §5.3/§6.2 的 DTO 途径）。
2. **真实本地联调（LAB BLOCKED）**：需资源充足（≥8 GB 空闲 + 容器运行时 + 管理员授权）的 VM/远程主机（**用户确认实验主机**）+ 镜像 `thehive4:4.1.24-1` digest `sha256:c8b6c7…` 实拉校验 → 执行 `TestRealLabRead`（`-m external`）→ 观测真实 200/401/403/404 + `~<id>` reference + `createdAt`。
3. **Reader 生产接线（EVIDENCE-GAPPED）**：真实 Lab 证据到位后，将 `create_read_adapter_registry` 接入 router（一行）+ 复核三重合取门 + 门 4/5。
4. **生产部署认证（UNKNOWN）**：真实目标实例契约 / 权威 registry digest + 生产版本取证；**Source CERTIFIED 不升级为生产认证**；TheHive 4 EOL，不作新生产推荐。

### 11.2 停止声明

M2-R 授权范围内的可交付项已完成并取证：**§2 来源门 fail-closed（P1-1）+ §3 创建门 gate3（P1-2）+ §4 版本/凭据/HTTP（Fix A）+ §5 四级测试分层 + HTTP 路由链（P1-3）+ §6 Lab 证据更正（Fix B）+ §7 完整回归 2568 passed + 来源隔离 Amendment（DESIGN ONLY）+ 本地前向提交**。

**真实本地联调 = LAB BLOCKED；Reader 真实读取 + 生产接线 = EVIDENCE-GAPPED；来源隔离通道实现 = 待授权；生产部署认证 = UNKNOWN** —— 依授权如实保持未完成，缺口、风险与前置已入档。**`M2 LOCAL LAB E2E` 未达 PASS 条件，不标记 PASS，不伪造全部通过，不自动宣称 M2 LOCAL LAB E2E PASS。**

**只有安全来源门、创建证据门和隔离回归通过（本轮已达成 fail-closed + gate3 + 2568 passed），才可申请下一阶段真实 Lab 接线。** 审查 ZIP 已在**仓库外**生成（脱敏）。**本轮到此停止，等待用户 Review 并授权下一阶段（Amendment IMPLEMENTATION / 真实 Lab）。不自动进入 Shuffle、Wazuh Reader、下一版本发布或 GitHub push。**
