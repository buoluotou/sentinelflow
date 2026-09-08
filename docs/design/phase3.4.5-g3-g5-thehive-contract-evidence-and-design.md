# Phase 3.4.5-G3/G5 — TheHive 4.1.24-1 契约取证 · 判定 · 设计

> **状态：REVIEWED — Contract Evidence & Determination**
> 本文件记录 TheHive 候选版本 `4.1.24-1` 的**只读契约取证**结果，并据此对两个能力分别作出判定：
> **G3（写契约修复）= CERTIFIED → PROCEED**；**G5（最小只读 Reader）= EVIDENCE-GAPPED → STOP（不实现）**。
> **本文档非 FROZEN。** 取证完成 ≠ 生产版本认证完成；Target Runtime 仍为 UNKNOWN。

## 0. 文档控制区（Document Control）

| 字段 | 值 |
| --- | --- |
| 文档状态 | **REVIEWED — Contract Evidence & Determination**（非 FROZEN；不认证任何生产运行时） |
| 授权 | M1 里程碑 §3（版本取证）+ §4（G3 写契约）+ §5（G5 Reader）+ §7（契约不足则提交设计与证据缺口报告并停止实现） |
| 授权基线提交 | `7210f610dbdd0b4db9e55f161c9d79fb6cbfcf60`（G1-D）；G2 收口提交 `969325b` |
| 采集日期 | 2026-09-08 |
| 采集方式 | **只读**：文件读取 + grep + 目录列举；**无网络请求、无镜像拉取、无服务启动、无真实写入、无凭据索取** |
| 候选版本 | TheHive `4.1.24-1`（`build.sbt` L5）——**候选，非已认证目标版本** |
| 覆盖能力 | G3 = TheHive 写适配器响应契约修复；G5 = TheHive 最小只读资源效果 Reader |
| 唯一交付物（本文档） | `docs/design/phase3.4.5-g3-g5-thehive-contract-evidence-and-design.md`（新增） |
| 保护约束 | 不修改 G1/Consolidation/G2 历史文档；不修改冻结通用契约/DB 模型/历史 Outcome；不改 Wazuh G1-C 空词表；不进 Shuffle G4；不创建 WazuhReader；不改 `shuffle.py`/`wazuh.py`；不发布版本；不 push |

**本轮目标（What this IS）**：从权威源码确定 `4.1.24-1` 的 case creation / read 真实契约与 `_id`/`id`/`caseId` 语义，查清 ScalliGraph 缺失对认证/错误映射/响应 schema 的影响，据此判定 G3 能否实现、G5 能否实现。

**本轮非目标（What this IS NOT）**：不启动真实 TheHive、不拉取/执行镜像、不连接生产、不发起真实业务写入；不用其他大版本字段/错误行为替代；不以推测填补缺口。

---

## 1. 版本与来源确认（Version & Provenance）

| 核验项 | 只读证据 | 结果 |
| --- | --- | --- |
| 源码版本 | `TheHive-main/build.sbt` L5 `val thehiveVersion = "4.1.24-1"` | **4.1.24-1**（与 §3 候选一致） |
| 官方发布条目 | `TheHive-main/CHANGELOG.md` `## [4.1.24](.../milestone/95) (2022-09-12)` | 4.1.24 稳定版，2022-09-12；`-1` 为打包修订后缀 |
| 镜像仓库 | `TheHive-main/docker.sbt` L14 `dockerRepository := Some("thehiveproject")` + L4-12（stable→version） | 候选镜像引用 `thehiveproject/thehive:4.1.24-1` |
| 暴露端口 | `docker.sbt` L16 `dockerExposedPorts := Seq(9000)`；L51 `EXPOSE 9000` | **9000** |
| 基础镜像 | `docker.sbt` L27 `Cmd("FROM", "openjdk:8")` | `openjdk:8`（JVM 运行时） |
| **镜像 digest** | 树内无 `sha256:`/digest 引用；未查询任何 registry（§3 禁止拉取） | **NOT OBTAINED / UNKNOWN**（不得捏造） |
| **仓库 git 元数据** | `git rev-parse` → `fatal: not a git repository` | TheHive-main 为**解压源码树，非 git 仓库** |
| **ScalliGraph pinned commit** | 无 `.git`，`git ls-tree`/`submodule status` 不可用 | **NOT OBTAINED**（无法本地定位精确依赖 commit） |

> 结论：源码树确为 `4.1.24-1`（权威 in-tree 版本文件）。但 **Target Runtime 版本、镜像 digest、ScalliGraph 精确依赖 commit 三项均未取得** —— 与 G2 证据盘点记录的「缺失 digest / ScalliGraph 缺口」一致。

---

## 2. 证据优先级与方法（Evidence Priority & Method）

严格沿用 G2 §2.1 优先级：**目标实例契约 > 精确版本权威源码 > 官方文档 > 部署模板 > 本地源码推断 > 历史假设**。

本轮**无目标实例证据**，故最高可用层级为「精确版本权威源码」= TheHive-main `4.1.24-1` 树内 `.scala`。所有判定均以源码 + TheHive 自带测试（`CaseCtrlTest.scala`）为第一手证据，逐条附 `file:line`。**凡源码不可达（ScalliGraph 子模块）之语义，一律标记 EVIDENCE-GAPPED，绝不以推断或其他版本替代。**

---

## 3. 写契约：POST /api/case（CERTIFIED）

### 3.1 成功响应 schema

`dto/src/main/scala/org/thp/thehive/dto/v0/Case.scala`：

- `OutputCase`（L29-55）字段含 `_id: String`、`id: String`、`caseId: Int // number`、`createdAt: Date`、`updatedAt: Option[Date]`、`status: String` 等。
- `OutputCase.writes`（L57-87）发出的 JSON 键为：`_id`、`id`、`createdBy`、`updatedBy`、`createdAt`、`updatedAt`、`_type`、`caseId`、`title`、`description`、`severity`、`startDate`、`endDate`、`impactStatus`、`resolutionStatus`、`tags`、`flag`、`tlp`、`pap`、`status`、`summary`、`owner`、`customFields`、`stats`、`permissions`。

> **决定性事实：响应中不存在 `case_id` 键。** 现有适配器 `thehive.py` L241 `payload.get("case_id")` 读取的是 TheHive v0 **从不发出**的键 —— 对任何真实 201 响应都会返回 `None` 并触发 `ExecutorOutcomeViolation`，即**当前写适配器无法完成任何一次真实闭环**。

### 3.2 状态码与创建路径

`thehive/app/org/thp/thehive/controllers/v0/CaseCtrl.scala`：

- `create`（L43-71）：`entrypoint("create case").extract("case", FieldsParser[InputCase]) ... .authTransaction(db)` → 权限校验 `organisations(Permissions.manageCase) ... orFail(AuthorizationError("Operation not permitted"))` → `caseSrv.create(...)` → **`Results.Created(richCase.toJson)` = HTTP 201**，body = `OutputCase`。
- 创建路径**无重复检测、无 409 分支**。

`thehive/test/org/thp/thehive/controllers/v0/CaseCtrlTest.scala`（TheHive 自带测试，第一手）：

- L74 / L130 / L377：create → `status equalTo(201)` + `contentAsJson(result).as[OutputCase]`。
- **L156：`app[CaseSrv].get(EntityIdOrName(outputCase._id))`** —— 用响应里的 `_id`（字符串）作为句柄重新取回该 case。**这是「`_id` 是可再取资源 reference」的决定性证据。**

> 写成功契约 = **201 + OutputCase{_id, id, caseId, ...}**，且 `_id` 可作 `EntityIdOrName` 再取。**CERTIFIED。**

### 3.3 输入 schema（参考，不阻断写修复）

`dto/.../v0/Case.scala` `InputCase`（L8-23）字段：`title`、`description`、`severity`、`startDate`、`endDate`、`tags`、`flag`、`tlp`、`pap`、`status`、`summary`、`user`、`customFields`。

> SentinelFlow 出站 body 现含 `sentinelflow_execution_id`、`source`、`approval_id`（`thehive.py` L154-165），**不在 `InputCase` 声明字段内**。其被 TheHive 接受/忽略/拒绝的行为由 ScalliGraph `FieldsParser[InputCase]` 决定 —— 该解析严格性 **EVIDENCE-GAPPED**（见 §7）。这不阻断「响应 ID 修复」（出站 body 由我方控制），但**是真实联调前必须澄清的一项**（见 §10.4）。

---

## 4. `_id` / `id` / `caseId` 语义（CERTIFIED — 决定性）

`thehive/app/org/thp/thehive/controllers/v0/Conversion.scala` `caseOutput` 渲染器（L155-176）：

```scala
.withFieldComputed(_.id,  _._id.toString)   // L163: id  = EntityId.toString
.withFieldComputed(_._id, _._id.toString)   // L164: _id = EntityId.toString
.withFieldRenamed(_.number, _.caseId)       // L165: caseId = number (Int)
```

`thehive/app/org/thp/thehive/models/Case.scala`：`number: Int`（人类案号，唯一索引）；`RichCase._id: EntityId`。

> **语义判定（CERTIFIED）：**
> - **`_id` == `id` == `EntityId.toString`** —— **字符串资源 ID**，是 `GET /api/case/{id}`（`EntityIdOrName`）可再取的**资源 reference**。
> - **`caseId` == `number`（Int）** —— **人类可读案号**，用于审计展示，**不是**字符串资源 ID。
>
> 直接落实 §4「必须区分 `_id`、`id`、`caseId` 的实际语义，不得简单把数字案号当作字符串资源 ID」：**可对账 reference 取 `_id`（字符串），绝不取 `caseId`（数字）。**

---

## 5. 409 / 幂等（NO NATIVE MECHANISM → fail-closed）

`thehive/app/org/thp/thehive/services/CaseSrv.scala` `create`（L79-120）：

- **L87：`val caseNumber = if (\`case\`.number == 0) nextCaseNumber else \`case\`.number`** —— 案号由 `caseNumberActor` 序列**自动分配**。两次相同创建 → 两个不同案号的 case。
- 全体（L89-119）：建实体 → 共享 → 建任务/标签/自定义字段 → 审计（`auditSrv.case.create`）。**无 duplicate/conflict/409 检测。**
- grep 佐证：`thehive/app/.../services/*.scala` 中含 `Conflict|already exists|duplicate|409` 的文件为 AlertSrv / AttachmentSrv / CaseTemplateSrv / CustomFieldSrv / ImpactStatusSrv / ObservableSrv / ObservableTypeSrv / ResolutionStatusSrv / UserSrv —— **`CaseSrv.scala` 不在其中**。

> **判定：TheHive 4.1.24-1 v0 `POST /api/case` 无原生幂等 / 409-重复契约。** 现有 `thehive.py` `_conflict_outcome`（L297-354）在 409+marker 时返回 `succeeded` 且 `detail={"idempotent_duplicate":True}`（L341-345）**不含任何 case reference** —— 既无权威契约支撑，又产生一个 reconcile 层（`_EXTERNAL_REFERENCE_KEYS["thehive"]="case_id"`）无法对账的「成功」。
>
> 依 §4「409 不得自动视为成功。只有权威契约允许且能够可靠恢复、关联并验证既有资源 reference 时，才能按已认证的幂等规则处理；**否则保持明确的拒绝或错误语义**」：**无认证恢复机制 → 409 一律 fail-closed（`failed` / `adapter_error`）。**

---

## 6. 读契约：GET /api/case/{id}（成功/404 CERTIFIED；认证/错误语义 GAPPED）

`CaseCtrl.scala` `get`（L73-91）：`.authRoTransaction(db)` → `caseSrv.get(EntityIdOrName(caseIdOrNumber)).visible(organisationSrv)` → `.getOrFail("Case")` → **`Results.Ok(richCase.toJson)` = HTTP 200**，body = `OutputCase`。

`CaseCtrlTest.scala`：L170/L224/L235/L241/L254/L341/L370 get → **200**；L351 `EntityIdOrName("1")`（数字亦可）；**L401/L403 已删除 case → 404**；L421 错误体含 `(contentAsJson(result) \ "type") == "BadRequest"`（400）。

| 读契约要素（§5 AND 门） | 状态 | 证据 |
| --- | --- | --- |
| 权威读取契约（200 + OutputCase + EntityIdOrName） | **CERTIFIED** | CaseCtrl.get L73-91；CaseCtrlTest L170/L156 |
| 严格关联标识（`_id` 字符串再取） | **CERTIFIED** | CaseCtrlTest L156 `EntityIdOrName(outputCase._id)` |
| 时间戳（`createdAt`/`updatedAt`） | **PRESENT** | OutputCase DTO L34-35 |
| **认证语义（401 vs 403）** | **EVIDENCE-GAPPED** | 见下 |
| **错误语义（invisible/租户隔离 vs not-found）** | **EVIDENCE-GAPPED** | 见下 |

**认证 / 错误语义为何 GAPPED：**

1. `CaseCtrl` / `CaseSrv` 大量依赖 `org.thp.scalligraph.*`：`Entrypoint`、`authTransaction`/`authRoTransaction`、`AuthorizationError`、`EntityIdOrName`、`getOrFail`、`.visible`、`FieldsParser`（CaseCtrl.scala L4-10；CaseSrv.scala L10-18）。**错误 → HTTP 状态映射（401/403/404/400）与认证判定全在 ScalliGraph。**
2. `CaseCtrlTest` 用 `DummyUserSrv`（L6 import；L350 `DummyUserSrv(organisation="cert").authContext`）**绕过真实认证**；全文件**无 `equalTo(401)` / `equalTo(403)` 断言**。
3. `.visible(organisationSrv)`（L79）实现租户隔离，但「case 存在却属其他 org」时的确切 HTTP 语义（404 还是 403 还是空）由 ScalliGraph 的 `visible`+`getOrFail` 交互决定 —— **无 HTTP 层断言**。

> 读**成功/404** CERTIFIED，但 §5 是**硬 AND 门**：「仅当…**认证与错误语义均已认证**时，允许实现」。认证 + 错误语义两项 GAPPED → **前置门不满足**。

---

## 7. ScalliGraph 缺口定性（根因）

| 核验项 | 只读证据 | 结果 |
| --- | --- | --- |
| 子模块声明 | `TheHive-main/.gitmodules`：`[submodule "ScalliGraph"] path = ScalliGraph url = ../scalligraph.git branch = develop` | 依赖外部 git 子模块（develop 分支，无 commit pin 可得） |
| 构建接线 | `build.sbt` L77 `lazy val scalligraph = (project in file("ScalliGraph"))`；L148/L149 `dependsOn(scalligraph)` / `% "test -> test"` | ScalliGraph 是**源码子工程**，非已发布 jar |
| 子模块内容 | `Get-ChildItem -Recurse -File ScalliGraph` → **0 文件** | **子模块为空（未 checkout）** |
| `lib/` | 仅 `play-propfind.jar` | 无 scalligraph jar |
| Conversion.scala 引用 | `org.thp.scalligraph` 命中 4 处 | 渲染层直接依赖缺失子模块 |

> **定性：整条认证 / 授权错误 → HTTP 映射 / 输入解析严格性 / `EntityIdOrName` 解析 / `getOrFail` / `.visible` 租户隔离逻辑，均随空的 ScalliGraph 子模块缺失。** 且因 TheHive-main 非 git 仓库，**连精确依赖 commit 都无法本地定位**。这是 G5 无法认证、且本地无法从源码构建的**同一根因**。

---

## 8. 分能力判定（Per-Capability Determination）

| 能力 | 判定 | 依据 | 处置 |
| --- | --- | --- | --- |
| **G3 写响应 ID / 资源 reference** | **CERTIFIED → PROCEED** | §3（201+OutputCase）、§4（`_id`==`id` 字符串 reference；`caseId` 数字）、CaseCtrlTest L74/L156 | 实现最小前向修复（§9） |
| **G3 409 幂等** | **NO CERTIFIED MECHANISM → fail-closed** | §5（CaseSrv.create 无重复检测，自动分配案号） | 409 一律 `failed`/`adapter_error`（§9.3） |
| **G3 认证失败 / 网络错误分类** | **沿用冻结分类（不改）** | 现 401/403/404/500→adapter_error、502/503/504→adapter_unavailable、timeout→timeout、连接→adapter_unavailable 为 3.2.5 冻结表；§4「分别处理」= 各自显式判失败 | 不新增分类词（避免触碰冻结 `FAILURE_CLASSIFICATIONS`） |
| **G5 最小只读 Reader** | **EVIDENCE-GAPPED → STOP（不实现）** | §6（认证 + 错误语义 GAPPED）、§7（ScalliGraph 空）；§5 硬 AND 门不满足 | 保持生产 registry 为空 → thehive 读经 `UnsupportedAdapterRead` 拒绝（= §5「无法认证的状态保持 refused/unsupported」）；提交缺口报告（§10） |

---

## 9. G3 写契约最小修复设计（PROCEED）

**唯一改动文件：`backend/app/services/executions/thehive.py`（+ 其测试）。** 不触碰通用执行状态机、冻结通用契约、DB 模型、其他 Adapter，不产生新外部副作用。

### 9.1 成功路径：解析真实响应 ID（核心缺陷修复）

- 读取 `_id`（字符串）为**资源 reference**；因渲染器保证 `_id == id`，`_id` 缺失时回退读 `id`。二者必须为**非空 `str`**。
- `caseId`（Int）**仅**在确为真实整数（非 `bool`/`None`/缺失）时，作为**审计字段** `case_number` 保留；**绝不**用作 reference。
- `detail` 键名保持 `case_id`（= 冻结的 `_EXTERNAL_REFERENCE_KEYS["thehive"]`），**值 = `_id` 字符串**：
  ```
  detail = {"provider": "thehive", "case_id": <_id 字符串>[, "case_number": <int>]}
  ```
  与 `manual_reconcile.py` L154-158 / L223-242、`reconciliation.py` L544-546（「`case_id` 是 REFERENCE，不是状态」）、`read/base.py` L52-54（TheHive `external_reference` = `case_id`）**保持一致** —— 写侧存的正是读侧将来可再取的字符串句柄。

### 9.2 缺失 / 非法 ID → fail-closed（D9）

- `_id`/`id` 均缺失、为空、或非字符串（如仅有数字 `caseId`）→ 抛 `ExecutorOutcomeViolation`（`classification="protocol_violation"`，由平台 parse 裁决，适配器不自判）。
- **明确：数字 `caseId` 单独存在不构成合法 reference**（§4「不得把数字案号当作字符串资源 ID」）—— 此为新增关键测试用例。

### 9.3 409 → 统一 fail-closed

- `_on_http_error` 的 409 分支返回 `failed` / `adapter_error`，附明确错误语义：「case 创建无认证幂等恢复契约，冲突绝不声称为成功」。
- 删除 `_conflict_outcome` 及其 marker 常量 `_DUPLICATE_MARKERS` / `_MISMATCH_MARKERS` / `_EXECUTION_ID_KEYS`（在「所有 409 均 fail-closed」下成为死代码；保留会误导）。
- **不改** `shuffle.py` / `wazuh.py` 的 `idempotent_duplicate`（§4「不扩展其他 Adapter」）。

### 9.4 保持不变（冻结）

- 出站 body（title/description/sentinelflow_execution_id/source/severity/approval_id）、端点 `POST {base}/api/case`、Bearer-only 认证面、单次调用零重试、202→adapter_error、非 200/201→adapter_error、502/503/504→adapter_unavailable、timeout→timeout、连接错误→adapter_unavailable、secret 五重脱敏 —— **全部不变**。
- 模块 docstring 更新为已认证契约（201 + `_id`/`id`/`caseId`；409 fail-closed）。

### 9.5 测试更新（`tests/test_execution_thehive_adapter.py`）

| 现断言 | 新断言（认证契约） |
| --- | --- |
| `_success_payload` → `{"case_id": ...}`（L161-162） | → `{"_id": s, "id": s, "caseId": n}`（真实 OutputCase 形状） |
| `test_created_case_is_succeeded` detail/raw（L349-350） | detail = `{"provider","case_id":<_id>,"case_number":<int>}`；raw = 真实形状 |
| `test_success_without_case_id...`（L404-416） | 缺失/空/非字符串 `_id`/`id`、**仅数字 `caseId`** → violation（match 资源 reference） |
| `test_same_execution_duplicate_is_succeeded_idempotent`（L475-482） | 409+marker → **`failed`/`adapter_error`**，无 `idempotent_duplicate` |
| `test_duplicate_with_same_execution_id_echo...`（L484-495） | 409+echo execution_id → **仍 `failed`**（echo 非认证 case reference） |
| `test_duplicate_chain_writes_succeeded_idempotent`（L712-718） | 服务链 409 → **`failed`/`adapter_error`** |
| 已断言 `failed` 的 409 用例（L497-529, L720-726） | 行为不变，仍 `failed`（统一 fail-closed 下自然通过） |
| docstring（L26-34） | 更新为认证契约措辞 |

> 遵循「以 docstring 修正测试契约，绝不弱化安全断言」：409 由 success→fail 是**加强** fail-closed，非弱化。

---

## 10. G5 Reader 证据缺口报告（EVIDENCE-GAPPED → STOP）

依 §7「若权威契约不足，提交设计与证据缺口报告，停止对应实现；不得通过推测填补」，**本轮不实现 TheHive Reader。**

### 10.1 当前（正确的）fail-closed 状态

- 生产 `ReadAdapterRegistry` 构造为空（`read/registry.py` L82 `return ReadAdapterRegistry()`），**无 thehive reader 文件**。
- thehive 读经 registry 门 → `UnsupportedAdapterRead`（`manual_reconcile.py` L279-312）—— 拒绝、**无 Outcome Fact、无 `reconciliation_failed`**。
- `read/base.py` L24-27 明载「Concrete readers (Shuffle / Wazuh / TheHive) are **Evidence-Gapped**（design §16）… NO concrete production ReadAdapter exists in A1 — the registry rejects every adapter」。

> 这正是 §5「无法认证的状态保持 refused/unsupported」要求的现状。**本轮不改动 registry**（保持空 = 保持拒绝）。

### 10.2 缺口清单（认证 G5 所必需，当前均未取得）

1. **认证语义**：`AuthorizationError` / 无效或缺失 Bearer → **401 还是 403** 的权威映射（在 ScalliGraph）。
2. **错误语义**：`.visible(organisationSrv)` 租户隔离下「case 存在但本 org 不可见」→ **404 / 403 / 空** 的确切 HTTP 语义（在 ScalliGraph `visible`+`getOrFail`）。
3. **错误体 schema**：除 `type:"BadRequest"`（400，CaseCtrlTest L421）外的完整错误分类（`type` 取值域）在 ScalliGraph。
4. **输入解析严格性**：`FieldsParser[InputCase]` 对未声明字段（`sentinelflow_execution_id`/`source`/`approval_id`）接受/忽略/拒绝的行为 —— 影响写侧真实联调，也影响读侧对 case 身份的确认。

### 10.3 为何「HTTP 200 / 资源存在」不足以判 confirmed_success（§5）

即便读到 200 + OutputCase，§5 要求「结合**已认证的资源身份、目标效果与关联契约**」。当前无法认证：
- 该 `_id` 是否**本次批准动作**创建的 case（而非同名/历史/跨租户 case）—— 需要认证的关联标识 + 时间戳绑定；
- 「case 存在」只证明**案件存在**，**不证明**「本次 escalate 的受控创建效果」达成（§1：case 创建成功是目标效果；Resolved/任务 Completed/Cortex job/人工结论**不得**自动解释为封禁/隔离等响应效果）。

> 故 G5 保持 EVIDENCE-GAPPED。**不猜测 confirmed_failure**（401/403/404/timeout/不可见/删除/证据不足均不映射为失败），**不猜测 confirmed_success**。

### 10.4 解除缺口的前置（二选一，均需另行授权）

- **(A) 权威 ScalliGraph 源码**：取得 `4.1.24-1` 所 pin 的 ScalliGraph commit（`branch = develop`），只读认证 `AuthorizationError`/`getOrFail`/`visible`/`FieldsParser` → HTTP 映射；或
- **(B) 运行实例观测**：在**另行授权**的本地隔离实例（§11）上，用受控测试数据观测真实 401/403/404/invisible 响应 + 校验镜像 digest。

在 (A) 或 (B) 完成前，G5 不实现、registry 保持空。

---

## 11. 本地隔离测试环境方案（PLAN ONLY — 未授权启动）

> §3 允许「准备本地隔离测试环境的配置和部署方案」，**不授权启动真实外部服务 / 下载执行不明镜像 / 连接生产 / 真实业务写入**。以下为**方案**，实际启动需用户**单独确认**。

| 项 | 方案 | 证据 / 状态 |
| --- | --- | --- |
| 镜像 / 版本 | 候选 `thehiveproject/thehive:4.1.24-1` | repo=docker.sbt L14；version=build.sbt L5。**digest NOT OBTAINED —— 拉取前必须对权威 registry 校验** |
| 依赖服务 | JanusGraph（BerkeleyJE 本地，或 Cassandra）+ 索引后端（Elasticsearch/OpenSearch）+ 附件存储 | `application.sample.conf` L10 `db.janusgraph`、L34-36 `storage.backend: berkeleyje` + `/opt/thp/thehive/database`、L27-28 ES backend、L40-41 附件存储。**各依赖精确镜像版本/digest NOT OBTAINED** |
| 网络端口 | TheHive `9000`（docker.sbt L16/L51）；依赖服务端口待定 | 仅本地回环，隔离网络 |
| 持久化目录 | JanusGraph `/opt/thp/thehive/database`、`/data`、附件目录 | 本地临时卷，测试后清理 |
| 资源需求 | JVM（openjdk:8 基）+ JanusGraph + ES/OpenSearch —— 内存/CPU 非平凡 | **具体配额 TO BE SIZED（启动授权时）** |
| 测试数据 | 单一 org + 单一 user + 一条带 `sentinelflow_execution_id` marker 的 escalate case；**无任何生产数据** | 受控、可识别、可清理 |
| 清理方案 | 停止并移除容器 + 删除本地卷/目录；无残留 | 测试后执行 |
| **源码构建可行性** | **不可行**：需空 ScalliGraph 子模块 + sbt + JDK8 + 全量依赖解析 | 仅预构建镜像可行 → 需拉取授权 + digest 校验 |

> **本方案状态：PLAN ONLY。本轮不拉取镜像、不启动服务、不联网、不真实写入。** 真实本地联调（§6）仅在用户**另行确认测试环境启动**后执行，且不得以 Mock 结果冒充真实联调。

---

## 12. 保护约束重申（Protection Constraints）

- 不修改 Wazuh G1-C 空词表；不进入 Shuffle G4 实现；不创建 WazuhReader；不修改历史 Outcome；不发布新版本。
- 不修改冻结通用执行状态机 / 通用契约 / DB 模型；不改 `shuffle.py` / `wazuh.py`（含其 `idempotent_duplicate`）。
- 不 amend / rebase / reset / force-push；不移动历史 tag；**不 push**。
- 文档与代码分离提交；测试用隔离 Mock/Fake + 内存库，**不用生产凭据**。

---

## 13. 验收映射（分能力，不得合并为「全部通过」）

| 能力项（§6） | 本轮状态 | 证据 |
| --- | --- | --- |
| 写入契约修复（G3） | **PROCEED → 见代码提交** | 本文档 §3/§4/§5/§9 + `thehive.py` diff + 测试 |
| Reader 语义认证（G5） | **EVIDENCE-GAPPED / 未完成** | 本文档 §6/§7/§10（认证 + 错误语义缺 ScalliGraph） |
| 隔离测试（Mock/Fake + 内存库） | **见 M6 回归** | `pytest` 结果（无生产凭据、0 外部网络） |
| 真实本地联调 | **未执行 / 未授权启动** | §11 PLAN ONLY，等待用户单独确认 |
| 生产部署认证 | **未完成 / UNKNOWN** | §1（Target Runtime、digest、ScalliGraph commit 均未取得） |

> 任一缺证据项保持「未完成」。本轮明确：**G3 写修复可交付；G5 Reader、真实联调、生产认证均未完成。**
