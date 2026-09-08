# Phase 3.4.5-M2 — TheHive 精确版本 · ScalliGraph 认证 · 本地 Lab 证据与部署/清理方案

> **状态：CERTIFIED (Source) · LAB BLOCKED (Runtime) · UNKNOWN (Production)**
> 本文件记录 M2 里程碑对 TheHive `4.1.24-1` 的**权威源码取证**结果（解除 M1 G5 §10.4(A) 缺口）、
> **本机 Lab 可行性只读检查**结果（如实标记 **LAB BLOCKED**），以及在获得授权、资源充足的主机上
> **可复现的隔离 Lab 部署方案 + 清理方案**。
> **本文档非 FROZEN，不认证任何生产运行时。** 三域版本严格分离，绝不混用。

## 0. 文档控制区（Document Control）

| 字段 | 值 |
| --- | --- |
| 文档状态 | **CERTIFIED (Source Version) · LAB BLOCKED (Lab Runtime) · UNKNOWN (Production Runtime)** |
| 授权 | M2 §2（精确版本 + ScalliGraph 证据解阻）+ §3（本地实验环境搭建；资源不足如实标记 LAB BLOCKED）|
| 授权基线提交 | `720d142`（M1 分能力验收报告）；本文件为该基线之上的 M2 前向工作 |
| 采集日期 | 2026-09-08 |
| 采集方式 | **只读**：git 元数据核验 + 源码文件读取 + grep + 本机资源只读探测（`Get-CimInstance`/`Get-Command`/`wsl -l -v`）；**无镜像拉取、无服务启动、无真实写入、无生产凭据、无管理员安装** |
| 权威源码位置 | `d:\edge\github\_m2_thehive_src\`（**仓库外**，不纳入 git 跟踪）：`TheHive\`（checkout @ `b6649bb`）、`ScalliGraph\`（checkout @ `2c2a7a4`）|
| 覆盖能力 | §2 版本/依赖认证、§4 输入 Schema 认证、§5 读契约认证、§3 Lab 可行性 + 部署/清理方案 |
| 唯一交付物（本文档） | `docs/design/phase3.4.5-m2-thehive-lab-evidence-and-deployment-plan.md`（新增）|
| 保护约束 | 不改冻结通用契约/DB 模型/历史 Outcome；不改 Wazuh G1-C 空词表；不改 `shuffle.py`/`wazuh.py`；不进 Shuffle G4；不创建 WazuhReader；不管理员安装；不 push；不 amend/rebase/reset/force-push |

**本轮目标（What this IS）**：从**权威 git 源码**确定 `4.1.24-1` 的 case creation / read 真实契约、认证/授权/错误映射、`FieldsParser` 严格性、`EntityIdOrName` 解析、`_id`/`id`/`caseId` 语义；据此**解除 M1 G5 §10.4(A)「权威 ScalliGraph 源码」缺口**；只读检查本机是否可安全启动真实 Lab，并给出部署/清理方案。

**本轮非目标（What this IS NOT）**：不启动真实 TheHive、不拉取/执行镜像、不连接生产、不发起真实业务写入、不做管理员安装；不用其他大版本字段/错误行为替代；不以推测填补缺口。

---

## 1. 三域版本分离（Three-Domain Version Separation — §2 强制）

§2 要求「记录 Source Version、Lab Runtime Version、Production Runtime Version 三域，绝不混用」。

| 域 | 定义 | 本轮值 | 证据 / 状态 |
| --- | --- | --- | --- |
| **Source Version**（源码版本） | 契约取证所依据的**权威源码 commit** | TheHive `4.1.24-1` = commit **`b6649bb58938a414de9f0505cc0a1dad15f0d0ef`**；ScalliGraph 子模块 pin = commit **`2c2a7a461dcfc6aa3e6fcdd23f7fd079c1d5d4c7`** | **CERTIFIED**（§2，git 元数据直接核验）|
| **Lab Runtime Version**（实验运行时版本） | 本地隔离实例**实际运行**的镜像 tag + digest | **未取得** — 本机无法启动真实 Lab | **LAB BLOCKED**（§3；无容器运行时 + 无可安装权限 + 内存不足）|
| **Production Runtime Version**（生产运行时版本） | 未来真实目标实例运行的版本 + digest | **未知** | **UNKNOWN**（本里程碑不触碰生产；§11 始终单列）|

> **关键纪律：Source Version CERTIFIED ≠ Lab/Production Runtime 已认证。** 本轮所有契约判定仅基于 Source Version；任何「运行时行为」结论都标注为 LAB BLOCKED / UNKNOWN，绝不以源码推断冒充运行时观测。

---

## 2. 版本与来源确认（Version & Provenance — CERTIFIED）

### 2.1 TheHive 精确 tag / commit（git 元数据直接核验）

在仓库外权威 checkout `d:\edge\github\_m2_thehive_src\TheHive\` 上执行只读 git 核验：

| 核验项 | 命令 | 结果 |
| --- | --- | --- |
| HEAD commit | `git rev-parse HEAD` | **`b6649bb58938a414de9f0505cc0a1dad15f0d0ef`**（短 `b6649bb`）|
| 最近 tag | `git describe --tags` | **`4.1.24`** |
| 打包版本 | `build.sbt` L5 `val thehiveVersion = "4.1.24-1"` | **`4.1.24-1`**（`-1` = 打包修订后缀，git tag 为 `4.1.24`）|

> **判定：TheHive `4.1.24-1` = git tag `4.1.24` = commit `b6649bb`。** 这是官方精确 tag 对应的可验证 commit，**不是** develop HEAD、不是浮动镜像 tag、不是旧 ZIP 快照。

### 2.2 ScalliGraph 精确依赖 commit（子模块 gitlink pin — 决定性）

M1 G3/G5 文档 §7 记录的核心缺口：「TheHive-main 非 git 仓库 → 连精确依赖 commit 都无法本地定位；ScalliGraph 子模块为空」。**本轮通过权威 git checkout 彻底解除该缺口：**

| 核验项 | 命令 | 结果 |
| --- | --- | --- |
| **TheHive HEAD 内的 ScalliGraph 子模块 pin** | `git ls-tree HEAD ScalliGraph`（在 TheHive checkout 内）| **`160000 commit 2c2a7a461dcfc6aa3e6fcdd23f7fd079c1d5d4c7  ScalliGraph`** |
| ScalliGraph 实际 checkout HEAD | `git rev-parse HEAD`（在 ScalliGraph checkout 内）| **`2c2a7a461dcfc6aa3e6fcdd23f7fd079c1d5d4c7`** |
| 二者一致性 | — | **完全匹配** |

> **决定性事实：**
> - 文件模式 **`160000`** = git **gitlink（子模块引用）**，即 TheHive `b6649bb` 在其树中**明确 pin** 的 ScalliGraph commit 为 `2c2a7a4`。
> - 本地 ScalliGraph 工作树**恰好 checkout 在该 pin commit**（`2c2a7a4`），**不是** `.gitmodules` 声明的 `branch = develop` 的浮动 HEAD。
> - 因此本轮认证所依据的 ScalliGraph 源码 = **TheHive 4.1.24-1 实际引用的历史依赖**，满足 §2「不使用当前 develop HEAD 冒充历史依赖」。

### 2.3 官方镜像与依赖服务（引用记录；digest 待运行时校验）

| 项 | 只读证据 | 状态 |
| --- | --- | --- |
| 镜像仓库 | `TheHive\docker.sbt` L14 `dockerRepository := Some("thehiveproject")` | 候选镜像引用 `thehiveproject/thehive:4.1.24-1` |
| 暴露端口 | `docker.sbt` L16 `dockerExposedPorts := Seq(9000)`；L51 `EXPOSE 9000` | **9000** |
| 基础镜像 | `docker.sbt` L27 `Cmd("FROM", "openjdk:8")` | `openjdk:8`（JVM 运行时）|
| **镜像 digest** | 未查询任何 registry（§3 本轮禁止拉取；LAB BLOCKED）| **NOT OBTAINED** — 部署时**必须**对权威 registry 校验 `sha256:` digest（§6.2）|
| 依赖服务 | `conf\application.sample.conf`：`db.janusgraph`、`storage.backend: berkeleyje`、Elasticsearch/OpenSearch 索引后端、附件存储 | 各依赖精确镜像 tag + digest **NOT OBTAINED**（部署时校验）|

> **纪律：禁止使用未固定的 `latest` 作为最终运行证据。** 部署方案（§6）要求逐镜像固定 tag + 校验 digest 后方可作为 Lab Runtime 证据。

---

## 3. ScalliGraph 认证 / 授权 / 错误映射（CERTIFIED — 解除 M1 §10.4(A) 缺口）

M1 G5 判定为 EVIDENCE-GAPPED 的四项（认证语义、错误语义、错误体 schema、输入解析严格性），本轮**全部**从 ScalliGraph `2c2a7a4` 权威源码取得第一手证据。

### 3.1 错误 → HTTP 状态映射（决定性，`ErrorHandler.scala`）

`ScalliGraph\core\src\main\scala\org\thp\scalligraph\ErrorHandler.scala` `toErrorResult`（L27-50）：

| ScalliGraph 异常 | HTTP 状态 | 行号 | 错误体 `type`（`Errors.scala`）|
| --- | --- | --- | --- |
| `AuthenticationError` | **401 UNAUTHORIZED** | L29 | `"AuthenticationError"`（Errors.scala L17）|
| `AuthorizationError` | **403 FORBIDDEN** | L30 | `"AuthorizationError"`（L18）|
| `MultiFactorCodeRequired` | 402 PAYMENT_REQUIRED | L31 | `"MultiFactorCodeRequired"`（L19）|
| `CreateError` | 400 BAD_REQUEST | L32 | `"CreateError"`（L20）|
| `GetError` | 500 INTERNAL_SERVER_ERROR | L33 | `"GetError"`（L21）|
| `SearchError` | 400 BAD_REQUEST | L34 | `"SearchError"`（L22）|
| `UpdateError` | 500 INTERNAL_SERVER_ERROR | L35 | `"UpdateError"`（L23）|
| `NotFoundError` | **404 NOT_FOUND** | L36 | `"NotFoundError"`（L27）|
| `BadRequestError` | 400 BAD_REQUEST | L37 | `"BadRequest"`（L28）|
| `MultiError` | 207 MULTI_STATUS | L38 | `"MultiError"`（L29）|
| `AttributeCheckingError` | **400 BAD_REQUEST** | L39 | `"AttributeCheckingError"`（L36）|
| `InternalError` | 500 INTERNAL_SERVER_ERROR | L40 | `"InternalError"`（L33）|
| `BadConfigurationError` | 400 BAD_REQUEST | L41 | `"BadConfigurationError"`（L34）|
| `NumberFormatException` | 400 | L42-43 | `"NumberFormatException"` |
| `IllegalArgumentException` | 400 | L44 | `"IllegalArgument"` |
| （`ex.getCause` 递归）| 递归到已知错误 | L45 | — |
| （兜底）| 500 INTERNAL_SERVER_ERROR | L46-49 | 异常类名 |

错误体形状（`GenericError.toJson`，Errors.scala L8-12）：`{"type": <字符串>, "message": <字符串>[, "cause": ...]}`；`onClientError`（ErrorHandler.scala L17-25）对裸状态码给出 `type ∈ {BadRequest, Forbidden, NotFound, Unknown}`。

> **§5 硬 AND 门「认证与错误语义均已认证」→ 满足。** 401（认证失败）/ 403（授权失败）/ 404（不存在或不可见）/ 400（属性校验失败）为**权威、可区分**的映射，TheHiveReadAdapter 的错误分类据此实现（§5.3）。

### 3.2 `getOrFail` → `NotFoundError`（404）：absent / deleted / 不可见统一 404

`ScalliGraph\core\src\main\scala\org\thp\scalligraph\services\VertexSrv.scala` `getOrFail`（L51-54）：

```scala
def getOrFail(idOrName: EntityIdOrName)(implicit graph: Graph): Try[V with Entity] =
  get(idOrName)
    .headOption
    .fold[Try[V with Entity]](Failure(NotFoundError(s"${model.label} $idOrName not found")))(Success.apply)
```

> `headOption` 为空（顶点不存在、已删除、或经 `.visible(organisationSrv)` 过滤后对本 org 不可见）→ `NotFoundError` → **404**。TheHive `CaseCtrl.get`（M1 §6：`.visible(organisationSrv)` → `.getOrFail("Case")`）据此：**「case 存在但跨租户不可见」与「case 不存在」故意合并为同一 404**（不泄漏他租户资源存在性）。TheHiveReadAdapter 将 404 归为 `not_found` → 经既有 read-failure 契约 → `reconciliation_failed`（**绝不**自动等于 `confirmed_failure`）。

### 3.3 `EntityIdOrName` `~` 前缀解析（决定性，`EntityId.scala`）

`ScalliGraph\core\src\main\scala\org\thp\scalligraph\EntityId.scala`：

```scala
object EntityIdOrName {
  val prefixChar: Char = '~'                                                   // L10
  def isId(value: String): Boolean = value.nonEmpty && value.charAt(0) == prefixChar  // L11
  def fold[A](value: String)(ifIsId: String => A, ifIsName: String => A): A =  // L12
    if (isId(value)) ifIsId(value.substring(1)) else ifIsName(value)
  def apply(value: String): EntityIdOrName = fold(value)(new EntityId(_), new EntityName(_))  // L13
}
case class EntityId(override val value: String) extends EntityIdOrName(value) {
  override def toString: String = s"${EntityIdOrName.prefixChar}$value"        // L19  → "~<rawId>"
}
```

> **判定：**
> - `OutputCase._id`（= `EntityId.toString`，见 §4.2）渲染为 **`~<rawVertexId>`**（带 `~` 前缀）。
> - `GET /api/case/{~<rawId>}` → `EntityIdOrName("~<rawId>")` → `isId=true` → `EntityId(<rawId>)` → 命中同一顶点。
> - `~` 属 `urllib.parse.quote` 的 always-safe 集（letters / digits / `_.-~`），故 `quote("~42", safe="") == "~42"`，reference 原样进入 URL path，无需转义、不失真。
> - 这证明 TheHiveReadAdapter 用**字符串 `_id`（带 `~`）**作为 reference 再取，与用**数字案号 `caseId`** 再取是**两条不同路径**（后者走 `EntityName`/number 分支，语义不同）——§4「不得用数字案号替代字符串资源 ID」的源码依据。

### 3.4 `FieldsParser` 对未声明字段：**静默忽略**（决定性，§4 根因）

`ScalliGraph\core\src\main\scala\org\thp\scalligraph\controllers\FieldsParser.scala` L120：case class 的 `FieldsParser[T]` 由宏 `FieldsParserMacro.getOrBuildFieldsParser[T]` 派生。

`ScalliGraph\core\src\main\scala\org\thp\scalligraph\macro\FieldsParserMacro.scala` `buildParser`（L66-107）：

```scala
case CaseClassType(paramSymbols @ _*) =>                       // L68：取 case class 声明的构造参数
  val entityBuilder = paramSymbols.foldLeft(...) {             // L76：仅遍历【声明】参数
    case (maybeBuilder, s) =>
      val symbolName = s.name.toString                         // L79
      ... q""" $parser.apply(path :/ $symbolName, field.get($symbolName)) ... """  // L90：只按声明名 field.get
  }
```

> **决定性事实：宏只对 case class 的【声明字段】调用 `field.get(symbolName)`，从不遍历输入的额外字段，也不注入 `unknownAttribute` 检查。** 因此 `FieldsParser[InputCase]` 遇到**未声明的顶层键**（如 `sentinelflow_execution_id`、`source`、`approval_id`）时：
> - **不拒绝**（不抛 `AttributeCheckingError`/400）；
> - **但也不读取、不持久化** —— 这些键**被静默丢弃**，永远不进入 `InputCase`，也永不出现在 `OutputCase`。
>
> （`FieldsParser.scala` L185-192 确有 `unknownAttribute` 拒绝器，但 case-class 乘积派生**不使用**它；仅显式接线处才生效。）
>
> **这正是 §4 的根因与修复依据：** M1 出站 body 把执行关联信息放在**未声明顶层键**，真实 TheHive 会**静默丢弃**它们 → 关联信息**根本不会被持久化、也就无法在读取时校验** → 闭环断裂。§4 修复将关联信息移入 **`tags`（InputCase 声明的 `Set[String]`，L14）**，使其成为**经认证、被持久化、可回读**的通道（§4.2）。

---

## 4. 输入 / 输出 Schema 认证（CERTIFIED — §4 写入契约）

`TheHive\dto\src\main\scala\org\thp\thehive\dto\v0\Case.scala`（git checkout @ `b6649bb`，比 M1 的解压快照更权威）：

### 4.1 `InputCase`（L8-23）— 真实 case 创建 DTO

```scala
case class InputCase(
    title: String,                       // L9   必填
    description: String,                 // L10  必填
    severity: Option[Int] = None,        // L11  ★ Option[Int] —— 整数标度，字符串 "high" 是 400
    startDate: Option[Date] = None,      // L12
    endDate: Option[Date] = None,        // L13
    tags: Set[String] = Set.empty,       // L14  ★ 声明的 Set[String] —— 关联信息的合法通道
    flag: Option[Boolean] = None,        // L15
    tlp: Option[Int] = None,             // L16
    pap: Option[Int] = None,             // L17
    status: Option[String] = None,       // L18
    summary: Option[String] = None,      // L19
    user: Option[String] = None,         // L20
    customFields: Seq[InputCustomFieldValue] = Nil  // L21-22（@WithParser）
)
```

> **§4 澄清结论：**
> 1. **FieldsParser 对额外字段 = 静默忽略**（§3.4）—— 不是接受持久化，也不是拒绝。
> 2. **真实 case 创建 DTO 字段** = 上述 13 个声明字段；`sentinelflow_execution_id`/`source`/`approval_id` **均不在其中**。
> 3. **关联信息的合法保存机制** = **`tags`（声明的 `Set[String]`）**，由 `CaseSrv.create` 持久化、`OutputCase.tags` 回显（§4.2）。这是**唯一**经认证、被持久化、可回读的通道。
> 4. **`severity` = `Option[Int]`**（L11）—— 整数标度（TheHive：Low=1 / Medium=2 / High=3 / Critical=4）；字符串 `"high"` 会触发 `AttributeCheckingError` → **400**。§4 修复将出站 `severity` 由字符串改为 `THEHIVE_SEVERITY_HIGH = 3`（Int）。

### 4.2 `OutputCase`（L29-55）+ `writes`（L59-87）— 响应资源 ID 与 reference 稳定性

```scala
case class OutputCase(
    _id: String,             // L30  ★ 字符串资源 ID
    id: String,              // L31  ★ 字符串资源 ID（渲染器保证 == _id）
    createdBy: String,       // L32
    updatedBy: Option[String],// L33
    createdAt: Date,         // L34  ★ 权威创建时间戳（epoch millis 序列化）
    updatedAt: Option[Date], // L35
    _type: String,           // L36
    caseId: Int, // number   // L37  ★ Int 人类案号 —— 注释明写 "number"，绝非字符串 reference
    title / description / severity: Int / startDate / ...,
    tags: Set[String],       // L45  ★ 回显 InputCase.tags（writes L76 "tags" -> c.tags）
    ...
)
```

`Conversion.scala` `caseOutput` 渲染器（M1 §4 已认证，本轮 git checkout 复核）：`id = _id.toString`、`_id = _id.toString`、`caseId = number`。

> **§4 澄清结论（reference 稳定性）：**
> - **`_id` == `id` == `EntityId.toString` == `~<rawId>`（字符串）** —— 是 `GET /api/case/{_id}`（`EntityIdOrName`）可稳定再取的**资源 reference**（§3.3）。
> - **`caseId` == `number`（Int）** —— 人类可读案号，**仅审计**，**绝不**作 reference（§3.3）。
> - **`writes`（L59-87）发出的键中不含 `case_id`** —— `case_id` 是 SentinelFlow 内部 reconcile key（`_EXTERNAL_REFERENCE_KEYS["thehive"]`），其**值由适配器从 `_id` 派生**，TheHive 从不发出该键。
> - **`createdAt`（L34）** = 目标创建效果的**权威时间戳**，读侧用作 `observed_at`（`observed_at_kind="external"`）。
> - **`tags`（L45，writes L76）** = 关联信息回显通道，读侧据此校验 `sentinelflow:execution:<id>` 标记（§5.2 correlation）。

### 4.3 409 / 幂等：无原生契约 → fail-closed（M1 §5 复核，仍成立）

`CaseSrv.create`（M1 §5）：案号由 `caseNumberActor` 序列**自动分配**（`if (number == 0) nextCaseNumber`），全体**无 duplicate/conflict/409 检测**；grep 佐证含 `Conflict|duplicate|409` 的服务文件不含 `CaseSrv.scala`。

> **§4 结论：TheHive 4.1.24-1 v0 `POST /api/case` 无可信原生幂等 / 409-重复恢复契约。** 409 一律 **fail-closed**（`failed` / `adapter_error`），**绝不**声称为成功、**绝不**恢复未经认证的 409 幂等成功路径（M1 已删除 `_conflict_outcome`，本轮不改）。

---

## 5. 读契约认证与 TheHiveReadAdapter 对应（CERTIFIED — §5）

### 5.1 `GET /api/case/{id}` 成功契约

`CaseCtrl.get`（M1 §6）：`.authRoTransaction(db)` → `caseSrv.get(EntityIdOrName(caseIdOrNumber)).visible(organisationSrv)` → `.getOrFail("Case")` → **200 OK** + `OutputCase`。`CaseCtrlTest.scala` L156 `EntityIdOrName(outputCase._id)` 决定性证明「`_id` 字符串可再取」。

### 5.2 三重合取门（HTTP 200 / 资源存在 **不**无条件映射 confirmed_success）

§5 要求「只有完整身份、关联和目标效果证据同时满足时才允许确认」。TheHiveReadAdapter `_verify` 实现三重 AND 门，**全部**有 §3/§4 源码依据：

| 门 | 校验 | 不满足时 | 源码依据 |
| --- | --- | --- | --- |
| **1. IDENTITY** | `resource_id = _id ‖ id`（非空 `str`）且 `== request.external_reference` | `case_unverified`（reason=`no_string_resource_id` / `resource_id_mismatch`）| §4.2（`_id`/`id` 字符串；`caseId` 数字不可替代）|
| **2. CORRELATION** | `tags` 含 `sentinelflow:execution:<execution_id>`（精确匹配）| `case_unverified`（reason=`missing_execution_correlation_tag`）| §3.4 + §4.1（tags 是唯一持久化+回显通道）；tag 词由写侧 `sentinelflow_execution_tag` 单一真源产生 |
| **3. CREATION** | `createdAt` → `observed_at`（epoch millis，`datetime.fromtimestamp(v/1000, tz=utc)`）| `case_unverified`（reason=`missing_created_at`）| §4.2（`createdAt` 权威创建时间戳）|
| **通过** | 三门全过 → `external_state = "case_created"`，`observed_at` = 创建时间，`raw_evidence` 含 `resource_id`/`status`/`correlation`/`created_at_present` | — | — |

> **只有三门全过才产出 `case_created`。** `case_created` 是 **SentinelFlow 合成信号**（非 TheHive 原生生命周期状态）——TheHive webhook **不原生发出**该词，唯一合法产者是 reader 的三重合取。case `Resolved`/`Closed`、任务 `Completed`、Cortex job 完成、人工结论**均不**被解释为本次创建效果（保持 REFUSED）。

### 5.3 错误分类 → 契约处置（401/403/404/timeout/连接失败各自区分）

| reader 观测 | 分类（`ReadTransportError.category` / `case_unverified` reason）| 下游契约处置 | 源码依据 |
| --- | --- | --- | --- |
| **401** | `authentication_failure` | `reconciliation_failed`（既有 read-failure 契约，**非** confirmed_failure）| §3.1 L29 |
| **403** | `authorization_failure` | `reconciliation_failed`（**非** confirmed_failure）| §3.1 L30 |
| **404** | `not_found`（absent / deleted / 跨租户不可见**故意合并**）| `reconciliation_failed`（不确定性如实记录，**非** confirmed_failure）| §3.1 L36 + §3.2 |
| **502 / 503 / 504** | `adapter_unavailable` | `reconciliation_failed` | 网关/不可用（冻结分类）|
| **timeout** | `timeout` | `reconciliation_failed` | 传输层 |
| **连接失败**（URLError/OSError）| `connection_failure` | `reconciliation_failed` | 传输层 |
| **200 但三重合取未过** | `case_unverified` | **REFUSED** → `UnrecognizedExternalState` → router **422 零 fact** | §5.2 |
| **200 且三门全过** | `case_created` | `confirmed_success` **一个** 独立 Outcome Fact | §5.2 |

> **纪律（§5）：** 401/403/404/timeout **不自动等于** `confirmed_failure`；HTTP 200 / 资源存在**不无条件**映射 `confirmed_success`；无法建立可信关联时保持 REFUSED（零 fact），**不猜测**。错误 message 经 `redact_text` 脱敏，**never** 含响应 body。

### 5.4 版本限定 mapping 词表（单一路径无关 mapping，仅 TheHive case-creation 范围）

`reconciliation.py` 的 thehive `AdapterStateVocabulary` 本轮**仅新增一个**权威证据词：

- `terminal_success_states = frozenset({"case_created"})`（其余 failure/pending/ambiguous 全空，`case_insensitive=False`，`state_key=None`）
- evidence 明载：case-CREATION effect ONLY；`case_created` 是 reader 三重合取合成信号；源码认证 `b6649bb`/`2c2a7a4`；**非**原生生命周期状态（resolved/closed 保持 REFUSED）；Lab runtime 证据 GAPPED（LAB BLOCKED）。

> **不开放其他 Adapter 词表**：wazuh（G1-C 空词表，保持不变）、shuffle、mock 词表**均未改**。全平台**恰好新增一个** evidenced 词（thehive `case_created`），由 `test_reconciliation.py::test_only_thehive_evidences_a_vocabulary_and_only_case_created` pin 死。

---

## 6. 本地 Lab 可行性只读检查 + 部署 / 清理方案（§3）

### 6.1 本机资源只读探测结果（真实证据，采集于 2026-09-08）

| 探测项 | 命令（只读）| 结果 | 对 Lab 的影响 |
| --- | --- | --- | --- |
| Docker | `Get-Command docker` | **ABSENT** | 无容器运行时 |
| Podman | `Get-Command podman` | **ABSENT** | 无备选运行时 |
| nerdctl | `Get-Command nerdctl` | **ABSENT** | 无备选运行时 |
| WSL2 运行时 | `wsl --version` | **已装：WSL 2.7.12.0，内核 6.18.33.2-2** | 运行时存在，但… |
| **WSL 已安装分发版** | `wsl -l -v` | **「没有已安装的分发版」**（zero distro）| **无法运行任何 Linux 工作负载** |
| 内存（可见 / 空闲）| `Win32_OperatingSystem` | **15.73 GB 总 / 仅 3.35 GB 空闲** | **不足以跑 TheHive+JanusGraph+ES 栈** |
| CPU 逻辑核 | `Win32_ComputerSystem` | 16 | 充足 |
| 虚拟化固件 | `HypervisorPresent` | **True**（Hyper-V 固件级可用）| 但无可用的已装运行时/分发版 |
| D: 空闲磁盘 | `Get-PSDrive D` | 145.24 GB | 充足 |
| OS | `wsl --version` | Windows 10.0.26100.8737 | — |

### 6.2 LAB BLOCKED 判定（诚实标记 — §3 / §9）

**判定：真实本地 TheHive Lab = `LAB BLOCKED`。** 依据（全部为真实探测证据，非推测）：

1. **无容器运行时**：docker / podman / nerdctl 三者**均未安装**。
2. **WSL2 运行时装了但零分发版**：`wsl -l -v` 明报「没有已安装的分发版」→ 即便 Docker Desktop 依赖 WSL2 后端，也**无可用 Linux 分发版**承载。
3. **安装任一运行时/分发版均需管理员权限 + 网络下载 + 宿主机重启/注销**：
   - Docker Desktop = 管理员系统级安装 + WSL2 后端 + 需先装一个 Linux 分发版 + 重启/注销；
   - `wsl --install <Distro>` = 网络下载 + 首个分发版通常需管理员 + 重启。
   - **二者均被 §1 / §3 明确禁止**：「如需管理员权限、系统范围安装、重启宿主机…必须停止该操作并报告」「不得擅自安装需要管理员权限的系统组件或修改宿主机安全配置」。
4. **空闲内存仅 3.35 GB**：TheHive 4.1.24 栈 = JVM（openjdk:8）+ JanusGraph + Elasticsearch/OpenSearch，各组件典型需 ~1 GB+ 堆，整栈现实需 6–8 GB 空闲。3.35 GB 空闲**不足以安全启动**，强行启动有宿主机不稳定风险。
5. **无更轻量替代**：TheHive 4.x 架构上强依赖 JVM + JanusGraph + 索引后端，不存在「跳过容器运行时 + 跳过管理员安装 + 在 3.35 GB 空闲内运行」的轻量精确版本；本机亦无现成可用 VM。

> **§3 纪律遵守：** 「若真实环境确实无法启动，必须如实标记 LAB BLOCKED」「不得把 Mock 服务冒充真实 TheHive」。本轮**不**做管理员安装、**不**重启宿主机、**不**拉取镜像、**不**伪造 Lab 结果。§6 的真实本地联调因此 **LAB BLOCKED**，改以**注入式隔离平台链测试**（真实写适配器 + 真实读适配器 + stub transport + 真实 reconcile 管线 + 内存 DB）作为**已授权的隔离替代**，并**分开报告**（见 `tests/test_thehive_write_read_closure.py` 与 M2 Final Report §6）。

### 6.3 部署方案（PLAN ONLY — 供未来获授权、资源充足的主机复现）

> 以下为**方案**，本轮**不执行**。在满足「管理员授权 + 容器运行时 + ≥8 GB 空闲内存 + 可校验镜像 digest」的主机上按此复现真实 Lab。

| 项 | 方案 | 强制校验 |
| --- | --- | --- |
| **镜像固定** | `thehiveproject/thehive:4.1.24-1`（对应 commit `b6649bb`）| **拉取后必须校验 `sha256:` digest 与权威 registry 一致**；**禁止** `latest`；记录 digest 作为 Lab Runtime 证据 |
| **依赖服务** | JanusGraph（BerkeleyJE 本地后端）+ Elasticsearch/OpenSearch（索引）+ 附件存储 | 各镜像**逐一固定 tag + 校验 digest**；版本与 `application.sample.conf` 一致 |
| **网络** | 仅本机 / 隔离虚拟网络；TheHive `9000` **绑定 loopback（127.0.0.1）**；依赖服务端口仅隔离网内 | **不暴露公网**；不改宿主机现有虚拟化网络 |
| **持久化** | 独立项目卷：JanusGraph `/opt/thp/thehive/database`、ES 数据、附件目录 | **不复用**其他业务数据；卷名带 `sentinelflow-m2-lab-` 前缀以便识别/清理 |
| **账户 / 凭据** | 独立**非生产**账户 + **随机临时** API key（`THEHIVE_API_KEY`）；单一测试 org + 单一测试 user | 凭据存 **Git 忽略**的本地文件 / 环境变量；报告/日志/diff/审查包**脱敏** |
| **资源限制** | 每容器 `mem_limit` / `cpus`；JVM `-Xmx` 显式设定 | 总和 ≤ 主机可用内存的 70%，留宿主机余量 |
| **健康检查 / 超时** | TheHive `GET /api/config` 或 `/` 就绪探测；有界启动超时（如 180s）+ **有界重试**（如 5 次）| 超时未就绪 → 判 Lab 启动失败，**不**伪造成功 |
| **测试数据** | 一条带 `sentinelflow:execution:<uuid>` tag 的 escalate case；受控、可识别、可清理 | **无任何生产数据**；不创建真实客户案件 |
| **受控写入** | 仅执行**经平台人工审批**的 `escalate_to_incident` → case creation | **不绕过审批**直接调外部接口冒充闭环 |

### 6.4 清理方案（测试后执行；不触碰既有用户数据）

| 步骤 | 操作 | 安全边界 |
| --- | --- | --- |
| 1 | 停止并移除**本 Lab 专属**容器（按 `sentinelflow-m2-lab-` 名称/标签精确匹配）| **不使用** `docker system prune -a` / `docker volume prune` 等**全局破坏性**命令 |
| 2 | 删除**本 Lab 专属**命名卷与独立持久化目录（前缀匹配）| **不删除**任何既有用户数据 / 其他业务卷 |
| 3 | 撤销临时账户 / 使临时 API key 失效 | 凭据不留存于仓库；本地 Git 忽略文件测试后清除 |
| 4 | 保留**脱敏**后的请求/响应/关联 ID/时间戳证据于审查包 | 证据脱敏（`redact_text`）后方可归档 |

> **纪律（§3 / §1）：不自动清理已有用户数据，不使用全局破坏性 Docker 清理命令，不执行未授权的破坏性清理。**

---

## 7. 凭据隔离与脱敏（四域凭据隔离 — 冻结契约）

- TheHive 凭据（`THEHIVE_BASE_URL` / `THEHIVE_API_KEY`）经 `credentials_from_settings("thehive", source)` 加载，与 Shuffle / Wazuh / 执行 token **四域隔离**，各自独立校验（`validate_base_url` 拒 query/fragment/userinfo/非法 scheme；`validate_api_key` 仅要求非空）。
- `AdapterCredentials` repr 已掩码；`auth_headers()` 仅将 key 置于 `Authorization` header（Bearer），**绝不**入 URL/body。
- reader 的错误 message 经 `redact_text(text, current_secret_values())` 脱敏（替换 `len ≥ 4` 的敏感值为 `***`），**never** 含响应 body。
- 本 Lab 若启动，临时凭据存 **Git 忽略**文件 / 环境变量；报告、日志、diff、审查 ZIP **全部脱敏**（§10）。

---

## 8. 保护约束重申（Protection Constraints）

- **不修改** Wazuh G1-C 空词表（`0c372aa` 安全修复保持不变）；**不进入** Shuffle G4 实现；**不创建** WazuhReader；**不修改**历史 Outcome / 历史提交。
- **不修改**冻结通用执行状态机 / 通用契约 / DB 模型；**不改** `shuffle.py` / `wazuh.py`。
- **不改** `default_read_adapter_registry()`（sealed empty）；**不改** router 接线（LAB BLOCKED → 无 real external evidence → reader 生产接线保持 EVIDENCE-GAPPED，工厂 `create_read_adapter_registry` 交付并测试但**未接线**）。
- **不 amend / rebase / reset / force-push**；**不移动**历史 tag；**不 push**。
- **不做**管理员安装、不重启宿主机、不改虚拟化网络、不拉取/执行未校验镜像、不连接生产、不发起真实业务写入。
- 文档与代码分离提交；测试用隔离 stub + 内存库，**不用生产凭据**、**0 外部网络**。

---

## 9. 验收映射（分能力，不得合并为「全部通过」）

| 能力项 | 本轮状态 | 证据 |
| --- | --- | --- |
| **§2 精确版本 + ScalliGraph 认证** | **CERTIFIED** | 本文档 §1/§2/§3（git 元数据 `b6649bb` + gitlink pin `2c2a7a4` 匹配；ErrorHandler/VertexSrv/EntityId/FieldsParserMacro 逐条 file:line）|
| **§4 输入 Schema 认证 + 写入修复** | **CERTIFIED（源码）+ 隔离测试 PASS** | 本文档 §3.4/§4（FieldsParser 忽略未声明、severity Option[Int]、tags 声明+持久化+回显、409 fail-closed）+ `executions/thehive.py` diff + `test_execution_thehive_adapter.py` |
| **§5 读契约认证** | **CERTIFIED（源码）** | 本文档 §3.1/§3.2/§3.3/§5（401/403/404/400、getOrFail→404、EntityIdOrName `~`、三重合取门）|
| **§3 Lab Runtime（真实本地联调）** | **LAB BLOCKED** | 本文档 §6.1/§6.2（无容器运行时 + 零 WSL 分发版 + 需管理员安装/重启 + 3.35 GB 空闲内存不足）|
| **生产部署认证** | **UNKNOWN** | 本文档 §1（Production Runtime Version 未知；本里程碑不触碰生产；§11 始终单列）|

> **本轮明确：§2/§4/§5 源码契约 CERTIFIED；Lab Runtime = LAB BLOCKED；生产认证 = UNKNOWN。** 任一缺证据项保持其真实状态，绝不以源码推断冒充运行时观测，绝不以 Mock 冒充真实 TheHive。
