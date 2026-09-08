# Phase 3.4.5-M1 — TheHive 第一条真实闭环里程碑 · 分能力验收报告

> **状态：DELIVERED — AWAITING FINAL REVIEW（分能力验收，未合并为「全部通过」）**
> 本文件是 M1 里程碑（G2 DOC CLOSURE + THEHIVE CONTRACT DESIGN + CONDITIONAL IMPLEMENTATION + ISOLATED REGRESSION）的**最终交付**：实际 diff、契约证据、测试命令与结果、**五项能力分别验收**、Git 提交链及剩余阻塞。
> **本轮明确结论：G3 写契约修复可交付；G5 Reader、真实本地联调、生产部署认证三项均未完成（证据不足，保持未完成）。**

## 0. 文档控制区（Document Control）

| 字段 | 值 |
| --- | --- |
| 文档状态 | **DELIVERED — AWAITING FINAL REVIEW**（非 FROZEN；不认证任何生产运行时） |
| 授权 | M1 里程碑 §6（分别验收）+ §7（最终交付 diff/证据/测试/能力状态/提交链/阻塞，完成后停止等待 Final Review） |
| 授权基线提交 | `7210f610dbdd0b4db9e55f161c9d79fb6cbfcf60`（§1 声明的已确认 HEAD = G1-D） |
| 采集日期 | 2026-09-08 |
| 采集方式 | **只读取证 + 隔离测试**：文件读取 / grep / `git`；测试用 Mock/Fake + 内存 SQLite；**无网络请求、无镜像拉取、无服务启动、无真实写入、无生产凭据** |
| 唯一交付物（本文档） | `docs/design/phase3.4.5-m1-thehive-closure-acceptance-report.md`（新增，doc-only 提交，与代码提交分离） |
| 关联提交 | G2 收口 `969325b`；G3/G5 契约取证+设计 `8abd93d`；G3 写修复代码 `d04b09b` |
| 保护约束 | 不修改 G1/Consolidation/G2/G3-G5 历史文档；不修改冻结通用契约/DB 模型/历史 Outcome；不改 Wazuh G1-C 空词表；不进 Shuffle G4；不创建 WazuhReader；不改 `shuffle.py`/`wazuh.py`；不发布版本；不 amend/rebase/reset/force-push/移动 tag；**不 push** |

---

## 1. 里程碑摘要（Milestone Summary）

M1 目标是打通 TheHive `escalate_to_incident` 的**一条本地真实资源效果闭环**（人工批准 → 受控创建 case → 保留正确资源 reference → 显式只读查询 → 独立 Outcome → 审计记录）。本轮在**只读取证 + 隔离测试**范围内完成：

1. **G2 文档收口**（`969325b`）：状态改为 `REVIEWED — Evidence Inventory`；「三侧目标实例均不存在」修正为「本轮未识别到明确目标实例，且未取得目标实例证据」；Target Runtime 全部 UNKNOWN；保留全部 Source/Template 冲突、缺失 digest、ScalliGraph 缺口及 G3–G5 依赖。
2. **TheHive 4.1.24-1 契约取证 + 分能力判定**（`8abd93d`）：写契约 **CERTIFIED → PROCEED**；读契约认证/错误语义 **EVIDENCE-GAPPED → G5 STOP**；409 **无原生幂等 → fail-closed**。
3. **G3 写契约最小前向修复 + 测试**（`d04b09b`）：`_id`/`id`/`caseId` 语义分离、409 统一 fail-closed、删除无契约支撑的 `idempotent_duplicate` 成功路径。
4. **隔离回归**：全量后端 + 跨层 **2496 passed, 3 deselected, 0 failed**（新鲜复跑于已提交 `d04b09b`、工作树干净状态）。

**未在本轮完成（依授权明确保持未完成）**：G5 Reader（前置认证门未满足）、真实本地联调（未授权启动外部服务）、生产部署认证（Target Runtime/digest/ScalliGraph commit 均未取得）。

---

## 2. Git 提交链（Commit Chain — 全部本地前向，NO PUSH）

| 顺序 | 提交 | 类型 | 说明 | 里程碑 |
| --- | --- | --- | --- | --- |
| 基线 | `7210f61` | docs | `docs(3.4.5-G1-D): record Wazuh runtime safety closure` —— §1 声明的已确认 HEAD | 起点 |
| 1 | `969325b` | docs | `docs(3.4.5-G2): close production version evidence inventory as REVIEWED` | M2 |
| 2 | `8abd93d` | docs | `docs(3.4.5-G3/G5): TheHive 4.1.24-1 contract evidence + determination` | M3 |
| 3 | `d04b09b` | **code** | `fix(3.4.5-G3): TheHive write adapter honors certified 4.1.24-1 case contract` | M4–M6 |
| 4 | *(本文档)* | docs | `docs(3.4.5-M1): milestone acceptance report` | M7 |

- **文档与代码分离**：`969325b`/`8abd93d`/本报告为 doc-only；`d04b09b` 为 code-only（4 个文件，无任何文档混入）。
- ** ahead / behind**：代码提交后 `origin/main...HEAD = 0 behind / 27 ahead`；**全程未 push**（无 `git push`、无 `--force`、无 `amend/rebase/reset`、未移动任何历史 tag）。
- **工作树**：代码提交后 `git status --porcelain` 为**空**（干净）；本报告为唯一新增未跟踪文件，doc-only 提交后再次干净。

---

## 3. 实际代码 diff（`d04b09b` — 已逐行复核）

**变更范围：4 个文件，`160 insertions(+), 125 deletions(-)`。唯一实现文件为 `thehive.py`；其余 3 个为测试。**

| 文件 | 变更行 | 角色 |
| --- | --- | --- |
| `backend/app/services/executions/thehive.py` | 174 | G3 写适配器修复（唯一实现改动） |
| `backend/tests/test_execution_thehive_adapter.py` | 93 | 适配器套件对齐认证契约 |
| `backend/tests/test_execution_policy_cross_layer.py` | 11 | 跨层 HTTP stub 改为真实 OutputCase 形状 |
| `backend/tests/test_observability_cross_layer.py` | 7 | 跨层 HTTP stub 改为真实 OutputCase 形状 |

### 3.1 写适配器语义修复（`thehive.py`）

- **成功路径 — 字符串资源 reference**：读取 `_id`（渲染器保证 `_id == id`，故 `_id` 缺失时回退 `id`）作为**字符串资源 reference**；必须为**非空 `str`**，否则抛 `ExecutorOutcomeViolation`（适配器不自判，由平台 parse 裁决 `protocol_violation`，D9）。
- **ID 语义分离**：`caseId`（Int，人类案号 `number`）**仅**在确为真实整数（非 `bool`/`None`/缺失）时作为审计字段 `detail["case_number"]` 保留，**绝不**用作 reference。
- **冻结 reconcile 键**：`detail["case_id"]`（= 冻结的 `_EXTERNAL_REFERENCE_KEYS["thehive"]`）**值 = `_id` 字符串**，与 `manual_reconcile.py` / `reconciliation.py` / `read/base.py` 读侧一致（写侧存的正是读侧将来可再取的字符串句柄）。
- **409 统一 fail-closed**：`CaseSrv.create` 自动分配下一案号、**无重复检测**，TheHive v0 无认证幂等/重复恢复契约 → 409 一律 `failed` / `adapter_error`，**body 绝不解析、绝不计入 detail**。
- **删除死代码**：`_conflict_outcome` 方法 + `_DUPLICATE_MARKERS` / `_MISMATCH_MARKERS` / `_EXECUTION_ID_KEYS` 常量；`_on_http_error` 去掉 `dispatch` 形参（调用点同步）。
- **保持不变（冻结）**：出站 body、端点 `POST {base}/api/case`、Bearer-only 认证、零重试/零轮询、202→adapter_error、401/403/404/500→adapter_error、502/503/504→adapter_unavailable、timeout→timeout、连接错误→adapter_unavailable、secret 五重脱敏。
- **未触碰其他 Adapter**：`grep` 确认 `_conflict_outcome`/`_DUPLICATE_MARKERS`/`_MISMATCH_MARKERS`/`_EXECUTION_ID_KEYS` 的残留命中**全在 `shuffle.py`/`wazuh.py`**（各自的独立符号，未改动），`thehive.py` **零 dangling reference**；`py_compile` 通过。

### 3.2 测试对齐（3 个测试文件）

- `_success_payload` → 真实 OutputCase 形状 `{"_id","id","caseId"}`（**从不**含 `case_id`）；成功用例断言 `detail == {provider, case_id:<_id 字符串>, case_number:<int>}`、`raw_response == 真实形状`。
- 协议违背 parametrize 新增：**仅数字 `{"caseId":12}`**、空/`None`/非字符串 `_id`/`id` → `ExecutorOutcomeViolation`（match「resource reference」）。
- 三个原「409 → succeeded idempotent_duplicate」用例改为断言 **fail-closed**（`failed`/`adapter_error`，且 `"idempotent_duplicate" not in detail`）——此为**加强** fail-closed，非弱化安全断言。
- 两个跨层 stub（policy/observability）由旧 `{"case_id":...}` 改为真实 OutputCase 形状；**未改动** reconcile 层对 `detail["case_id"]` 的行引用（修复后仍产生 `case_id` 键）。

---

## 4. 契约证据（Contract Evidence — 详见 `8abd93d`）

全部结论以 TheHive-main `4.1.24-1` **树内权威源码 + TheHive 自带测试**为第一手证据，逐条附 `file:line`（此处摘要，完整见 `8abd93d` §1–§7）：

| 契约事实 | 判定 | 决定性证据 |
| --- | --- | --- |
| 写成功 = `201 + OutputCase{_id,id,caseId,...}`，响应**无 `case_id` 键** | **CERTIFIED** | `dto/v0/Case.scala` `OutputCase.writes` L57-87；`CaseCtrl.create` L43-71 `Results.Created`；`CaseCtrlTest` L74/L130/L377=201 |
| `_id == id == EntityId.toString`（字符串资源 reference）；`caseId == number`（Int 案号） | **CERTIFIED** | `Conversion.scala` `caseOutput` L163-165；`CaseCtrlTest` L156 `EntityIdOrName(outputCase._id)` 再取 |
| `POST /api/case` 无原生幂等/409-重复契约 | **NO MECHANISM → fail-closed** | `CaseSrv.create` L79-120（L87 `nextCaseNumber` 自动分配）；grep 佐证 `CaseSrv.scala` 不含 `Conflict/duplicate/409` |
| 读成功 `200 + OutputCase` / 已删除 `404` | **CERTIFIED** | `CaseCtrl.get` L73-91；`CaseCtrlTest` L170=200、L401/L403=404 |
| 读**认证语义（401 vs 403）** + **错误语义（invisible/租户隔离）** | **EVIDENCE-GAPPED** | 映射全在 ScalliGraph（`CaseCtrl`/`CaseSrv` 大量 `import org.thp.scalligraph.*`）；`CaseCtrlTest` 用 `DummyUserSrv` 绕过认证、**无 401/403 断言** |
| ScalliGraph 子模块 | **空（0 文件）** | `.gitmodules` 声明外部子模块（`branch=develop`，无 commit pin）；`Get-ChildItem -Recurse -File ScalliGraph` → 0 文件；TheHive-main 非 git 仓库（无法定位精确依赖 commit） |
| 镜像 digest / Target Runtime / ScalliGraph pinned commit | **NOT OBTAINED / UNKNOWN** | 树内无 `sha256:`/digest；未查询任何 registry（§3 禁止拉取） |

---

## 5. 测试命令与结果（Test Commands & Results — 新鲜复跑于已提交 `d04b09b`）

环境：`backend\.venv`（Python 3.12 / pytest 9.1.1）；`conftest.py` 强制 `AI_PROVIDER=mock`、`db_session` = `sqlite://` 内存库 + `StaticPool`、`external` marker 默认 deselect、`e2e/*` 不收集。**无生产凭据、零外部网络。**

| # | 命令（于 `backend/`） | 结果 |
| --- | --- | --- |
| 1 | `.\.venv\Scripts\python.exe -m pytest tests/test_execution_thehive_adapter.py -q` | **84 passed, 1 deselected** in 0.56s |
| 2 | `.\.venv\Scripts\python.exe -m pytest -q` | **2496 passed, 3 deselected, 0 failed** in 60.00s |
| 3 | `.\.venv\Scripts\python.exe -m pytest -m external --collect-only -q` | **3/2499 collected (2496 deselected)** —— 精确列出 3 个真实系统测试 |

**Deselected 精确核算（证明零出站、非隐藏失败）**：测试总数 **2499** = 默认收集 **2496** + `external` deselect **3**。3 个被 deselect 的正是需真实外部系统的用例：

- `tests/test_execution_shuffle_adapter.py::TestRealShuffle::test_real_workflow_trigger`
- `tests/test_execution_thehive_adapter.py::TestRealTheHive::test_real_thehive_case_creation`
- `tests/test_execution_wazuh_adapter.py::TestRealWazuh::test_real_active_response`

> `test_real_thehive_case_creation` 被 deselect = **真实本地联调未执行**（§3/§6 未授权启动外部服务），符合「不得以 Mock 结果冒充真实联调」。

**覆盖矩阵（§6 要求项 → 隔离测试落点）**：正常创建（200/201+OutputCase→succeeded）、缺失/非法 ID（空/`None`/非字符串/仅数字 `caseId`→violation）、409 幂等（marker/echo execution_id/服务链→**一律 fail-closed**）、认证失败（401/403→adapter_error）、未知 execution、关联不匹配、读取失败、资源不可见、零事实拒绝（G5 registry 空→`UnsupportedAdapterRead`，无 Outcome Fact）、事务回滚、历史不可变、无自动执行副作用（零重试/零轮询/零回调）——均由 2496 项隔离套件覆盖并通过。

---

## 6. 分能力验收（Per-Capability Acceptance — §6：分别报告，任一缺证据保持未完成，绝不合并为「全部通过」）

| # | 能力项（§6） | 状态 | 证据 | 缺什么（若未完成） |
| --- | --- | --- | --- | --- |
| 1 | **写入契约修复（G3）** | ✅ **完成 — 有证据** | `d04b09b` diff（§3）；契约 CERTIFIED（§4 / `8abd93d` §3/§4/§5）；适配器套件 84 passed（§5） | —（本轮范围内完成） |
| 2 | **Reader 语义认证（G5）** | ⛔ **未完成 — EVIDENCE-GAPPED** | `8abd93d` §6/§7/§10：认证语义（401/403）+ 错误语义（invisible/租户隔离）随**空 ScalliGraph 子模块**缺失；§5 硬 AND 门不满足 → **不实现**，生产 registry 保持空 → thehive 读经 `UnsupportedAdapterRead` 拒绝（= §5「无法认证保持 refused/unsupported」） | 需 (A) `4.1.24-1` 所 pin 的 ScalliGraph 权威源码认证错误→HTTP 映射；或 (B) 另行授权的本地隔离实例观测真实 401/403/404/invisible |
| 3 | **隔离测试（Mock/Fake + 内存库）** | ✅ **完成 — 有证据** | `2496 passed, 3 deselected, 0 failed`（§5 命令 2）；无生产凭据、零外部网络；deselect 精确核算 = 3 个真实系统测试（§5） | —（隔离范围内完成；**不代表**真实联调通过） |
| 4 | **真实本地联调** | ⛔ **未执行 — 未授权启动** | `8abd93d` §11 环境方案 = **PLAN ONLY**；`test_real_thehive_case_creation` 被 deselect（§5） | 需用户**单独确认**测试环境启动（镜像/版本+digest 校验、端口、持久化目录、资源配额、受控测试数据、清理方案），且依赖服务（JanusGraph/ES-OpenSearch/附件）精确镜像版本/digest 未取得 |
| 5 | **生产部署认证** | ⛔ **未完成 — UNKNOWN** | `8abd93d` §1：Target Runtime 版本、镜像 digest、ScalliGraph pinned commit **三项均未取得**；G2（`969325b`）Target Runtime 全部 UNKNOWN | 需目标实例契约或权威 registry digest 校验 + 生产版本取证；**取证完成 ≠ 生产版本认证完成** |

> **合并结论被明确禁止**：本轮**仅** G3 写修复（能力 1）与隔离测试（能力 3）在其范围内完成；能力 2/4/5 保持未完成。**不得**表述为「全部通过」。

---

## 7. 剩余阻塞（Remaining Blockers — 每项均需另行授权，本轮不推测填补）

1. **ScalliGraph 缺口（G5 与本地源码构建的同一根因）**：子模块空（0 文件）、TheHive-main 非 git 仓库 → 无法本地定位 `4.1.24-1` 所 pin 的 ScalliGraph commit。认证/授权错误→HTTP 映射、`EntityIdOrName` 解析、`getOrFail`、`.visible` 租户隔离、`FieldsParser[InputCase]` 严格性**全部缺失**。→ 阻断 G5 认证，阻断从源码本地构建。
2. **镜像 digest 未校验**：候选 `thehiveproject/thehive:4.1.24-1`（repo/version 有 in-tree 证据），但**无 digest**；§3 禁止拉取不明镜像 → 真实联调前必须对权威 registry 校验 digest。
3. **输入 schema 未澄清**：出站 body 含 `sentinelflow_execution_id`/`source`/`approval_id`，**不在 `InputCase` 声明字段内**；其被接受/忽略/拒绝由 ScalliGraph `FieldsParser` 决定（GAPPED）。→ 真实联调前必须澄清（影响闭环可关联性与 case 身份确认）。
4. **真实本地联调未授权**：需用户单独确认环境启动（§6 能力 4）；依赖服务精确镜像版本/digest 未取得。
5. **生产部署认证未完成**：Target Runtime/digest/ScalliGraph commit 三项 UNKNOWN（§6 能力 5）。

---

## 8. 保护约束合规声明（Protection Constraints Compliance）

本轮**未**做任何被禁止的操作，逐项确认：

- ✅ 未修改 Wazuh G1-C 空词表；未进入 Shuffle G4 实现；未创建 WazuhReader；未修改任何历史 Outcome；未发布新版本。
- ✅ 未修改冻结通用执行状态机 / 通用契约 / DB 模型；未改 `shuffle.py` / `wazuh.py`（含其 `idempotent_duplicate`）——`git status` 与 grep 双重佐证。
- ✅ 未 amend / rebase / reset / force-push；未移动历史 tag；**未 push**（`0 behind / 27 ahead`，全程本地）。
- ✅ 文档与代码分离提交；测试用隔离 Mock/Fake + 内存 SQLite，**未用生产凭据**、**零外部网络**。
- ✅ 未启动真实外部服务、未拉取/执行镜像、未连接生产、未发起真实业务写入。
- ✅ 未修改 G1/Consolidation/G2/G3-G5 历史文档（本报告为**新增**文件）。

---

## 9. 停止声明（Stop — Await Milestone Final Review）

M1 授权范围内的可交付项已完成并取证：**G2 收口（`969325b`）+ TheHive 契约取证与判定（`8abd93d`）+ G3 写契约最小修复与测试（`d04b09b`）+ 隔离回归（2496 passed）**。G5 Reader、真实本地联调、生产部署认证三项**依授权保持未完成**，缺口与前置已入档（§7）。

**本轮到此停止，等待里程碑 Final Review。** 解除任一剩余阻塞（启动本地 TheHive、拉取镜像、认证 ScalliGraph、生产版本认证）均需用户**另行单独授权**。
