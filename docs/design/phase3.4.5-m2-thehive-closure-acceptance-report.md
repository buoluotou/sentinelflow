# Phase 3.4.5-M2 — TheHive 本地真实闭环一体化冲刺 · 最终交付报告（分能力验收）

> **状态：DELIVERED — AWAITING FINAL REVIEW（分能力验收，未合并为「全部通过」）**
> 本文件是 M2 里程碑的**唯一最终交付**：实际 HEAD/提交链、精确版本与 ScalliGraph 认证、全部 diff 清单、
> 契约↔实现对应、隔离测试与真实本地联调命令与结果、完整平台闭环证据（脱敏）、**五项能力分别验收**、
> 未解决风险与回滚/清理方案。
> **本轮明确结论：**
> - **写入契约（§4）= CERTIFIED（源码）+ 隔离测试 PASS**
> - **Reader（§5）= 源码契约 CERTIFIED + 实现 + 隔离测试 PASS；真实 GET 读取验证 + 生产接线 = EVIDENCE-GAPPED（LAB BLOCKED）**
> - **隔离回归（§7）= PASS（2556 passed / 0 failed）**
> - **真实本地联调（§6）= LAB BLOCKED（本机物理不可行；已交付注入式隔离替代并分开报告）**
> - **生产部署认证 = UNKNOWN（本里程碑不触碰生产；始终单列）**
>
> **`M2 LOCAL LAB E2E` 未达 PASS 条件**（真实本地 TheHive 资源效果闭环因 LAB BLOCKED 未能真实执行）。依 §11，如实标记对应能力为 **LAB BLOCKED / EVIDENCE-GAPPED**，交付已完成的全部合法成果，**不伪造全部通过**。

## 0. 文档控制区（Document Control）

| 字段 | 值 |
| --- | --- |
| 文档状态 | **DELIVERED — AWAITING FINAL REVIEW**（非 FROZEN；不认证任何生产运行时）|
| 授权 | M2 里程碑 §10（最终一次性交付）+ §11（完成条件与最终停止）|
| 授权基线提交 | `720d142`（M1 分能力验收报告）|
| 采集日期 | 2026-09-08 |
| 采集方式 | **权威源码只读取证 + git 元数据核验 + 本机资源只读探测 + 隔离测试**；测试用 stub transport + 内存 SQLite；**无镜像拉取、无服务启动、无真实外部写入、无生产凭据、无管理员安装、零外部网络** |
| 唯一交付物（本文档）| `docs/design/phase3.4.5-m2-thehive-closure-acceptance-report.md`（新增，doc-only 提交，与代码提交分离）|
| 关联提交（本里程碑）| `a5c90df`（§2/§3 证据+部署方案）、`093eb1c`（§4 写 Schema）、`117ab6b`（§5 Reader+mapping）、`beca5ab`（§6 闭环测试）、*(本文档)*（§10 报告）|
| 运行环境 | Windows 10.0.26100（24H2）；16 逻辑核；15.73 GB RAM（探测时 3.35 GB 空闲）；`backend\.venv` Python **3.12.2** / pytest **9.1.1**；`sqlite://` 内存库 + StaticPool |
| 保护约束 | 不改冻结通用契约/DB 模型/历史 Outcome；不改 Wazuh G1-C 空词表（`0c372aa` 保持不变）；不进 Shuffle G4；不创建 WazuhReader；不改 `shuffle.py`/`wazuh.py`；不改 sealed `default_read_adapter_registry()`；不改 router 接线；不发布版本；不 amend/rebase/reset/force-push/移动 tag；**不 push** |

---

## 1. 里程碑摘要（Milestone Summary）

M2 目标是在 §0–§11 授权内打通一条**真实、可验证、可审计**的 TheHive case creation 资源效果闭环。本轮实际完成：

1. **§2 精确版本 + ScalliGraph 证据解阻 → CERTIFIED**：从**权威 git checkout**（仓库外 `_m2_thehive_src\`）核验 TheHive `4.1.24-1` = tag `4.1.24` = commit **`b6649bb`**；ScalliGraph 子模块 **gitlink pin = `2c2a7a4`**（mode `160000`），且本地 checkout HEAD **恰好匹配该 pin**（非 develop 浮动 HEAD）。**彻底解除 M1 G5 §10.4(A) 缺口**（M1 剩余阻塞 #1）。
2. **§4 输入 Schema 澄清 + 最小版本限定修复 → CERTIFIED + 隔离测试 PASS**：认证 `FieldsParser` 宏对**未声明字段静默忽略**（不拒绝、不持久化）；关联信息移入**声明的 `InputCase.tags`**（经认证、被持久化、可回读的唯一通道）；`severity` 字符串 `"high"`（400）改为 **Int `3`**（`Option[Int]`）。解除 M1 剩余阻塞 #3。
3. **§5 最小只读 TheHiveReadAdapter → 源码契约 CERTIFIED + 实现 + 隔离测试 PASS**：三重合取门（identity + correlation + creation）；全平台**恰好新增一个** evidenced 词 `case_created`；401/403/404/timeout/5xx 各自区分且**绝不**自动映射 `confirmed_failure`；reader **交付并隔离测试，但未接线** router（LAB BLOCKED → 无 real external evidence → sealed 空 registry 保持）。
4. **§6 完整平台闭环 → LAB BLOCKED，改以注入式隔离平台链测试替代（分开报告）**：真实写适配器 + 真实读适配器 + stub transport + 真实 reconcile 管线 + 内存 DB，证明写→读 correlation 单一真源闭环、字符串 reference 流、跨执行隔离、append-only。
5. **§7 回归与质量 → PASS**：完整后端 **2556 passed / 4 deselected / 0 failed**；专项/映射/审批/Outcome/跨层分组回归零失败；`git diff --check` 净、`py_compile` OK、凭据泄漏扫描净、冻结文件未动。
6. **§8 单 Agent 本地前向提交 → 4 单元已提交**（+ 本报告为第 5 单元）；工作树干净；`0 behind / 32 ahead`；全程无 amend/rebase/reset/force-push/push。

**未在本轮完成（依授权如实保持）**：真实本地联调（**LAB BLOCKED** — 本机无容器运行时 + 零 WSL 分发版 + 安装需管理员/重启（禁止）+ 3.35 GB 空闲内存不足）；Reader 真实 GET 验证 + 生产接线（**EVIDENCE-GAPPED** — 依赖真实 Lab）；生产部署认证（**UNKNOWN**）。

---

## 2. Git 提交链（Commit Chain — 全部本地前向，NO PUSH）

| 顺序 | 提交 | 类型 | 说明 | § |
| --- | --- | --- | --- | --- |
| 基线 | `720d142` | docs | `docs(3.4.5-M1): TheHive closure milestone per-capability acceptance report` | 起点 |
| 1 | `a5c90df` | docs | TheHive 4.1.24-1 源码 + ScalliGraph `2c2a7a4` 认证；LAB BLOCKED 证据 + 部署/清理方案 | §2/§3 |
| 2 | `093eb1c` | **code** | 关联信息移入声明的 `InputCase.tags`；`severity` 字符串→Int 3 | §4 |
| 3 | `117ab6b` | **code** | TheHiveReadAdapter 已验证 case-creation 效果 + 版本限定 `case_created` mapping | §5 |
| 4 | `beca5ab` | **test** | TheHive 写→读闭环平台链测试（LAB BLOCKED 隔离替代）| §6 |
| 5 | *(本文档)* | docs | M2 最终交付报告（分能力验收）| §10 |

- **实际 HEAD**：`beca5ab`（本报告 doc-only 提交后将前移一位）。
- **branch**：`main`。**ahead/behind**：`origin/main...HEAD = 0 behind / 32 ahead`（提交本报告前）。
- **工作树**：4 个代码/文档提交后 `git status --short` **为空**（干净）；本报告为唯一新增未跟踪文件。
- **纪律**：全程**未 push**（无 `git push`、无 `--force`、无 `amend/rebase/reset`、未移动任何历史 tag）；文档与代码分离提交；G1-C `0c372aa` 安全修复保持不变。

---

## 3. 精确版本 · ScalliGraph · 输入 Schema 认证（§2 + §4 — CERTIFIED）

### 3.1 三域版本分离（绝不混用）

| 域 | 值 | 状态 |
| --- | --- | --- |
| **Source Version** | TheHive `4.1.24-1` = commit `b6649bb58938a414de9f0505cc0a1dad15f0d0ef`；ScalliGraph pin = `2c2a7a461dcfc6aa3e6fcdd23f7fd079c1d5d4c7` | **CERTIFIED**（git 元数据直接核验）|
| **Lab Runtime Version** | 未取得 — 本机无法启动真实 Lab（镜像 tag/digest 未拉取校验）| **LAB BLOCKED** |
| **Production Runtime Version** | 未知 | **UNKNOWN** |

### 3.2 ScalliGraph 认证结果（解除 M1 §10.4(A) 缺口）

`git ls-tree HEAD ScalliGraph`（TheHive `b6649bb` 内）→ **`160000 commit 2c2a7a4…  ScalliGraph`**（gitlink pin）；ScalliGraph checkout HEAD = **`2c2a7a4…`**（完全匹配）。据此认证（逐条 `file:line`，完整见 `a5c90df` 文档 §3）：

| 契约事实 | 判定 | 决定性证据（ScalliGraph `2c2a7a4`）|
| --- | --- | --- |
| 401 = `AuthenticationError` | **CERTIFIED** | `ErrorHandler.scala` L29 `Status.UNAUTHORIZED` |
| 403 = `AuthorizationError` | **CERTIFIED** | `ErrorHandler.scala` L30 `Status.FORBIDDEN` |
| 404 = `NotFoundError`（absent/deleted/跨租户不可见**故意合并**）| **CERTIFIED** | `ErrorHandler.scala` L36；`VertexSrv.getOrFail` L51-54（`headOption` 空→`NotFoundError`）|
| 400 = `AttributeCheckingError`/`BadRequestError`/`CreateError` | **CERTIFIED** | `ErrorHandler.scala` L39/L37/L32 |
| `EntityIdOrName` `~` 前缀解析 | **CERTIFIED** | `EntityId.scala` L10 `prefixChar='~'`、L11 `isId`、L12 `fold`（strip `~`）、L19 `EntityId.toString="~"+value` |
| **`FieldsParser` 对未声明字段 = 静默忽略** | **CERTIFIED** | `FieldsParserMacro.buildParser` L66-107：仅遍历**声明**参数 `field.get(symbolName)`（L90），不遍历额外输入、不注入 `unknownAttribute` 检查 |
| `InputCase`：`title`/`description` 必填、`severity:Option[Int]`、`tags:Set[String]`；**无** `sentinelflow_execution_id`/`source`/`approval_id` | **CERTIFIED** | `dto/v0/Case.scala` L8-23（L11 `Option[Int]`、L14 `Set[String]`）|
| `OutputCase`：`_id`/`id`(String)、`createdAt`(Date)、`caseId:Int //number`、`tags`(回显)；`writes` **从不**发 `case_id` | **CERTIFIED** | `dto/v0/Case.scala` L29-55（L37 `caseId:Int //number`）、L59-87（L76 `"tags"`，无 `case_id`）|
| `POST /api/case` 无原生幂等/409-重复契约 | **CERTIFIED（M1 复核仍成立）** | `CaseSrv.create` 自动分配案号、无 duplicate 检测 |

### 3.3 §4 澄清结论（逐项回答授权问题）

1. **FieldsParser 对额外字段**：**静默忽略**（不拒绝、不持久化）—— M1 body 的 `sentinelflow_execution_id`/`source`/`approval_id` **从未到达 case**，闭环断裂（根因）。
2. **真实 case 创建 DTO 字段**：`InputCase` 的 13 个声明字段；三关联字段均不在其中。
3. **关联信息的合法保存机制**：**`tags`（声明的 `Set[String]`）** —— 经认证、被 `CaseSrv.create` 持久化、`OutputCase.tags` 回显的**唯一**可回读通道。
4. **响应资源 ID 与读取 reference 稳定性**：`_id == id == EntityId.toString == ~<rawId>`（字符串），`GET /api/case/{_id}` 经 `EntityIdOrName` 稳定再取；`caseId`（Int 案号）**绝不**作 reference。
5. **409 幂等**：**无可信原生契约** → 一律 fail-closed（`failed`/`adapter_error`），**绝不**恢复未认证幂等成功路径。

> **未触发 Amendment**：§4 修复严格限于 TheHive 专属字段适配（body 字段位置 + severity 类型），**未**改通用执行状态机、DB 模型、审批规则。

---

## 4. 代码 / 配置 / 测试文件修改清单 + 关键 diff（§10）

**M2 全量变更（`720d142..beca5ab`）：11 个文件，`2255 insertions(+), 75 deletions(-)`。**

| 文件 | 变更 | 角色 | § | 提交 |
| --- | --- | --- | --- | --- |
| `docs/design/phase3.4.5-m2-thehive-lab-evidence-and-deployment-plan.md` | +380（新增）| §2/§3 版本+ScalliGraph 认证、Lab 可行性、部署/清理方案 | §2/§3 | `a5c90df` |
| `backend/app/services/executions/thehive.py` | 73 | §4 写适配器：关联→tags、severity→Int 3、tag helper 单一真源 | §4 | `093eb1c` |
| `backend/tests/test_execution_thehive_adapter.py` | 67 | §4 写适配器测试对齐 | §4 | `093eb1c` |
| `backend/app/services/read_adapters/thehive.py` | +378（新增）| §5 TheHiveReadAdapter（三重合取门 + 错误分类 + 脱敏）| §5 | `117ab6b` |
| `backend/app/services/read_adapters/registry.py` | +114（新增）| §5 容错工厂 `create_read_adapter_registry`（**未接线**）| §5 | `117ab6b` |
| `backend/app/services/read_adapters/__init__.py` | +37（新增）| §5 包导出 | §5 | `117ab6b` |
| `backend/app/services/outcomes/reconciliation.py` | 51 | §5 thehive 词表 += `case_created`；anti-fabrication docstring | §5 | `117ab6b` |
| `backend/tests/test_read_adapter_thehive.py` | +769（新增）| §5 reader 专项 50 测试（含 1 external deselect）| §5 | `117ab6b` |
| `backend/tests/test_reconciliation.py` | 93 | §5 重写 2 个 anti-fabrication pin + 4 新测试 | §5 | `117ab6b` |
| `backend/tests/test_webhook_persistence.py` | 7 | §5 fail-closed 注释精确化（**断言不变**）| §5 | `117ab6b` |
| `backend/tests/test_thehive_write_read_closure.py` | +361（新增）| §6 写→读闭环平台链测试（LAB BLOCKED 隔离替代）| §6 | `beca5ab` |

### 4.1 §4 写适配器关键 diff（`thehive.py`）

```python
# 出站 body（execute）——移除未声明顶层键，改走声明的 tags 通道：
body = {
    "title": f"SentinelFlow escalation: {dispatch.target}",
    "description": "...approved SentinelFlow escalation...",
    "severity": THEHIVE_SEVERITY_HIGH,                 # Int 3（原为字符串 "high" → 400）
    "tags": [                                          # 声明的 Set[String]，被持久化+回显
        SENTINELFLOW_TAG,                               # "sentinelflow"
        sentinelflow_execution_tag(dispatch.execution_id),  # "sentinelflow:execution:<uuid>"
        sentinelflow_approval_tag(dispatch.approval_id),    # "sentinelflow:approval:<uuid>"
    ],
}
# 移除：sentinelflow_execution_id / source / approval_id（未声明 → FieldsParser 静默丢弃）
```

`sentinelflow_execution_tag()` 为**写读共享的单一真源**（G5 reader 导入同一 helper），确保创建时写入的关联串 = 读取时重新校验的串，**永不漂移**。

### 4.2 §5 词表关键 diff（`reconciliation.py`）

```python
"thehive": AdapterStateVocabulary(
    adapter="thehive",
    terminal_success_states=frozenset({"case_created"}),  # ← 全平台唯一新增 evidenced 词
    terminal_failure_states=frozenset(),                  # 空：失败 READ 走 reconciliation_failed
    pending_states=frozenset(), ambiguous_states=frozenset(),
    case_insensitive=False, state_key=None,               # 严格默认（无 TheHive 证据支持放宽）
    evidence="M2 §5: case-CREATION effect ONLY ... source-certified b6649bb/2c2a7a4 ...",
),
# wazuh / shuffle / mock 词表【数据未改】；G1-C 空 Wazuh 集保持不变
```

---

## 5. 权威契约 ↔ 实现对应（§5 — 写入关联 / Reader / mapping）

| 权威契约事实（§3 认证）| 实现落点 | 对应关系 |
| --- | --- | --- |
| `tags:Set[String]` 声明+持久化+回显（`dto/v0/Case.scala` L14/L45/L76）| `thehive.py` execute body `tags`；`read_adapters/thehive.py` `_tags_carry_execution` | 写侧 POST 的 `sentinelflow:execution:<id>` = 读侧在 `OutputCase.tags` 重新校验的串（单一真源）|
| `_id == id == ~<rawId>`（字符串 reference）；`caseId` 数字不可替代 | `thehive.py` `detail["case_id"]=_id`；reader `_verify` identity 门 `resource_id==external_reference` | 写侧存的字符串 reference = 读侧再取并校验身份的 reference；数字 `caseId` 仅 `case_number` 审计 |
| `EntityIdOrName` `~` 前缀（`EntityId.scala` L10-12）| reader `url=f"{base}/api/case/{quote(reference,safe='')}"`；`quote("~42","")=="~42"` | `~` 属 URL always-safe 集，reference 原样入 path，GET 命中同一顶点 |
| `createdAt`(Date/epoch millis) 权威创建时间戳 | reader `_created_at_to_datetime`→`observed_at`（`datetime.fromtimestamp(v/1000,tz=utc)`）| 目标创建效果的权威时间；`observed_at_kind="external"` |
| 401/403/404 = Authentication/Authorization/NotFound（`ErrorHandler` L29/30/36）| reader `_on_http_error`：401→`authentication_failure`、403→`authorization_failure`、404→`not_found`、502-504→`adapter_unavailable` | 各自 `ReadTransportError(category)` → `reconciliation_failed`（**绝不** `confirmed_failure`）|
| `getOrFail`→404（absent/deleted/不可见合并，`VertexSrv` L51-54）| reader 404→`not_found`→`reconciliation_failed` | 资源删除/跨租户不可见的**不确定性如实记录**，不猜测失败 |
| HTTP 200 / 资源存在**不**无条件 = confirmed_success | reader 三重合取门：identity ∧ correlation ∧ creation 全过才 `case_created`；否则 `case_unverified`（REFUSED，零 fact）| 无法建立可信关联 → 保持 REFUSED，**不猜测** |
| 单一 path-agnostic mapping（`normalize_external_state` 无 source 参数）| thehive 词表仅 `case_created`→`confirmed_success`；`case_unverified` 不在词表→`UnrecognizedExternalState`→router 422 零 fact | 复用既有 Manual Reconcile / Outcome 持久化 / 凭据隔离；不新增其他 Adapter 词 |

> **webhook 路径安全性**：`case_created` 是 reader 合成词，真实 TheHive webhook **不原生发出**；且 `THEHIVE_CALLBACK_TOKEN` 默认空 → webhook 认证 uniform 401 fail-closed。故 path-agnostic 加此词**不**开放任何伪造入口（`test_webhook_persistence.py::test_thehive_fail_closed_writes_no_fact` 断言 resolved/closed/success/completed/ok 全部零 fact）。

---

## 6. 测试命令与结果（§7 — 隔离测试；真实本地联调 LAB BLOCKED）

环境：`backend\.venv`（Python **3.12.2** / pytest **9.1.1**）；`conftest.py` 强制 `AI_PROVIDER=mock`、`db_session`=`sqlite://` 内存库 + StaticPool、`external` marker 默认 deselect。**无生产凭据、零外部网络。**

| # | 命令（于 `backend/`）| 结果 | 用时 |
| --- | --- | --- | --- |
| 1 | `.\.venv\Scripts\python.exe -m pytest -q`（**完整后端套件**）| **2556 passed, 4 deselected, 0 failed** | 57.52s |
| 2 | `... pytest tests/test_execution_thehive_adapter.py tests/test_read_adapter_thehive.py tests/test_thehive_write_read_closure.py -q`（**TheHive 写+读专项**）| **141 passed, 2 deselected, 0 failed** | 0.91s |
| 3 | `... pytest tests/test_read_adapter_thehive.py -q`（**Reader 专项**）| **50 passed, 1 deselected, 0 failed** | <1s |
| 4 | `... pytest tests/test_thehive_write_read_closure.py -q`（**§6 写→读闭环**）| **6 passed, 0 failed** | 0.20s |
| 5 | `... pytest`（**映射/Manual Reconcile/Webhook** 12 文件）| **957 passed, 0 failed** | 14.17s |
| 6 | `... pytest`（**执行策略/审批/Outcome/跨层/sealed A1** 12 文件）| **391 passed, 0 failed** | 6.71s |
| 7 | `... pytest -q -m external --co`（**真实系统测试枚举**）| **4/2560 collected（2556 deselected）** | 1.15s |
| 8 | `git diff --check` | **EXIT=0（无空白错误）** | — |
| 9 | `python -m py_compile`（10 个新/改文件）| **PY_COMPILE_OK** | — |

**Deselected 精确核算（证明零出站、非隐藏失败）**：完整套件收集 **2560** = 默认运行 **2556** + `external` deselect **4**。4 个被 deselect 的正是需真实外部系统的用例：

- `test_execution_shuffle_adapter.py::TestRealShuffle::test_real_workflow_trigger`（Shuffle，既有）
- `test_execution_thehive_adapter.py::TestRealTheHive::test_real_thehive_case_creation`（TheHive 写，既有）
- `test_execution_wazuh_adapter.py::TestRealWazuh::test_real_active_response`（Wazuh，既有）
- **`test_read_adapter_thehive.py::TestRealLabRead::test_real_get_case_verifies_creation`（TheHive 读，M2 §5 新增）**

> 新增 reader 的真实 Lab 读取测试**正确标记 `external` 并默认 deselect**（`THEHIVE_LAB_*` 环境变量未设 → `pytest.skip("LAB BLOCKED")`）。默认 `pytest` **绝不**自动连接真实系统（§7 隔离要求满足）。

**PostgreSQL 集成**：本仓库无 live-PG 集成 harness（测试用 SQLite + StaticPool，PG 并发语义在应用层模拟，sealed A1 纯度审计禁用 `asyncpg`/`psycopg2`）。§7「必要的 PostgreSQL 集成测试」由现有架构满足，无需新增真实 PG 连接。

**真实本地外部测试（§7 独立显式启用）**：`-m external` 下的 `test_real_get_case_verifies_creation` / `test_real_thehive_case_creation` 需真实 TheHive Lab → **LAB BLOCKED，未执行**（见 §7）。

---

## 7. 完整平台闭环证据（§6 — 脱敏）

### 7.1 真实本地联调 = LAB BLOCKED（诚实标记）

§6 要求的真实链路「受控 case creation → 保存真实 reference → 显式 Manual Reconcile → **真实 GET case** → 独立 Outcome」中的**真实 GET** 需运行真实 TheHive Lab。本机只读探测（真实证据）：

| 探测项 | 结果 | 影响 |
| --- | --- | --- |
| docker / podman / nerdctl | **全部 ABSENT** | 无容器运行时 |
| WSL2 运行时 | 已装（WSL 2.7.12.0，内核 6.18.33.2-2）| 但… |
| **WSL 已安装分发版** | **零（「没有已安装的分发版」）** | 无法承载 Linux 工作负载 |
| 空闲内存 | **仅 3.35 GB**（总 15.73 GB）| 不足以跑 TheHive(JVM)+JanusGraph+ES 栈（现实需 6–8 GB 空闲）|
| 安装运行时/分发版 | 需**管理员权限 + 网络下载 + 宿主机重启/注销** | **被 §1/§3 明确禁止** |

> **判定：`LAB BLOCKED`。** 依 §3「若真实环境确实无法启动，必须如实标记 LAB BLOCKED」「不得把 Mock 服务冒充真实 TheHive」；依 §1「如需管理员权限、系统范围安装、重启宿主机…必须停止该操作并报告」。本轮**不**管理员安装、**不**重启、**不**拉取镜像、**不**伪造 Lab。部署方案 + 非破坏性清理方案已入档（`a5c90df` 文档 §6.3/§6.4），供未来获授权、资源充足的主机复现。

### 7.2 注入式隔离平台链测试（LAB BLOCKED 的**已授权隔离替代** — 与真实联调分开报告）

`tests/test_thehive_write_read_closure.py`（`beca5ab`，**6 passed**）用**真实 `TheHiveExecutor`（写）+ 真实 `TheHiveReadAdapter`（读）+ 注入 stub transport + 真实 `reconcile_execution` 管线 + 内存 DB**证明闭环。**无任何网络；无 Mock 冒充真实 TheHive。** 脱敏证据：

| 闭环要素 | 隔离证据（脱敏）| 断言 |
| --- | --- | --- |
| 受控 case creation | 真实 executor POST `/api/case`，body `tags` 含 `sentinelflow:execution:<uuid>` | `outcome.status=="succeeded"` |
| **真实字符串资源 reference** | `detail["case_id"] == "~42"`（stub `OutputCase._id`）；`"case_id" not in created`（TheHive 发 `_id`/`id`，SentinelFlow 派生 `case_id`）| **字符串 reference，非数字案号**（`case_number==42` 仅审计）|
| 显式 Manual Reconcile → 真实 GET | `reconcile_execution(db, eid, OPERATOR, ReadAdapterRegistry([reader]))`；reader GET `/api/case/~42` | `read.last.full_url.endswith("/api/case/~42")`；`"/api/case/42" not in url`；`call_count==1`（**零重试/轮询**）|
| **独立 Outcome** | 一个 `confirmed_success` Fact，`source==MANUAL_RECONCILE_SOURCE`，`observed_at_kind=="external"`，`operator=="recon-op"` | `_only_fact` 恰一个 |
| 写读 correlation 单一真源 | 写侧 POST 的 tag == 读侧重新校验的 tag（同一 `sentinelflow_execution_tag` helper）| `posted_tags == created["tags"]` |
| **跨执行隔离**（不误关联）| 另一 execution 读同一 case → identity 过但 correlation 失败 | `case_unverified` → `UnrecognizedExternalState` → **零 fact** |
| **append-only** | 重复 Manual Reconcile 两次 | 两个 Fact，`len({r.id})==2`（永不覆盖）|

> **§6 覆盖矩阵落点**：正常创建+字符串 ID（§7.2 + `test_execution_thehive_adapter.py`）；创建后读取验证（§7.2 + `test_read_adapter_thehive.py::TestVerifiedCreationEffect`）；输入 Schema 合法/非法（§4 测试）；缺失/空/非字符串/不匹配 reference（`TestUnverifiedRefusals`/`TestUrlAndReferenceSafety`）；409/401/403/404/timeout/连接失败（`TestErrorDiscrimination` + 写侧 409 fail-closed）；无权限/跨租户（403→authorization_failure + 跨执行隔离）；资源删除不确定性（404→not_found→reconciliation_failed）；显式读取失败+合法 reconciliation_failed（`TestServiceLevelClosure`）；不可信状态拒绝零 fact（`case_unverified`→422）；历史 Outcome 不可变+append-only（§7.2）；无自动重试/轮询/补偿（`call_count==1` + 冻结策略）；真实执行与真实 Outcome 不混淆（Dispatch Fact ≠ Outcome Fact，§7.2 分离持久化）。**14 类场景全覆盖。**

---

## 8. 分能力验收（§10 — 五项分别报告，任一缺证据保持未完成，绝不合并为「全部通过」）

| # | 能力项 | 状态 | 证据 | 缺什么（若未完成）|
| --- | --- | --- | --- | --- |
| 1 | **写入契约（§4）** | ✅ **CERTIFIED（源码）+ 隔离测试 PASS** | §3.2/§3.3 认证（FieldsParser 忽略未声明、`InputCase`/`OutputCase` DTO、409 fail-closed）；`093eb1c` diff（关联→tags、severity→Int 3）；专项 141 passed（§6 命令 2）| —（源码+隔离范围内完成；真实写入 200/201 观测依赖 Lab，见 #4）|
| 2 | **Reader（§5）** | 🟡 **实现 + 隔离测试 PASS；真实 GET 验证 + 生产接线 = EVIDENCE-GAPPED** | 源码读契约 CERTIFIED（§3.2：401/403/404、`getOrFail`→404、`EntityIdOrName ~`）；`117ab6b`（reader+factory+mapping）；专项 50 passed + 闭环 6 passed（三重合取门、跨执行隔离、append-only）| 真实 `GET /api/case/{_id}` 对活体 TheHive 的观测（LAB BLOCKED）；router 生产接线（无 real external evidence → sealed 空 registry 保持，reader **未接线**）|
| 3 | **隔离回归（§7）** | ✅ **PASS** | 完整后端 **2556 passed / 4 deselected / 0 failed**（§6 命令 1）；分组 A141/B957/C391 零失败；`git diff --check` 净、`py_compile` OK、凭据扫描净、冻结文件未动 | —（隔离范围内完成；**不代表**真实联调通过）|
| 4 | **真实本地联调（§6）** | ⛔ **LAB BLOCKED** | §7.1 真实机器证据（无容器运行时 + 零 WSL 分发版 + 需管理员/重启（禁止）+ 3.35 GB 空闲内存不足）；已交付注入式隔离替代（§7.2）并**分开报告**；部署+清理方案入档（`a5c90df` §6.3/§6.4）| 需**另行授权**、资源充足（≥8 GB 空闲 + 容器运行时 + 管理员安装 + 重启）的主机；镜像 tag+digest 权威校验；依赖服务（JanusGraph/ES-OpenSearch/附件）精确版本 |
| 5 | **生产部署认证** | ⛔ **UNKNOWN** | §3.1 Production Runtime Version 未知；本里程碑不触碰生产 | 需真实目标实例契约或权威 registry digest 校验 + 生产版本取证；**Source CERTIFIED ≠ 生产认证**；本地 Lab 即便通过也**不得**升级为生产级认证（§11）|

> **合并结论被明确禁止**：本轮能力 1（源码+隔离）、能力 3（隔离回归）在其范围内 **PASS**；能力 2 **部分完成**（实现+隔离 PASS，真实读+接线 EVIDENCE-GAPPED）；能力 4 **LAB BLOCKED**；能力 5 **UNKNOWN**。**不得**表述为「全部通过」。
>
> **`M2 LOCAL LAB E2E = PASS` 条件未满足**（§11：需真实本地 TheHive 资源效果闭环通过）——真实闭环因 LAB BLOCKED 未能执行，故**不标记 PASS**。

---

## 9. 未解决风险 · 回滚/清理方案 · 下一阶段建议（§10）

### 9.1 未解决风险

1. **真实运行时行为未观测（LAB BLOCKED）**：所有契约结论基于 Source Version 权威源码；真实镜像的运行时行为（含依赖服务版本交互）未观测。**缓解**：源码证据充分且逐条 `file:line`；隔离测试用真实适配器 + 真实管线；reader 未接线 → 生产无副作用。
2. **reader 生产接线缺口（EVIDENCE-GAPPED）**：`create_read_adapter_registry` 工厂已交付+测试但**未接线** router（`reconcile.py` line 179 未改），sealed `default_read_adapter_registry()` 保持空 → 生产 thehive 读仍经 `UnsupportedAdapterRead` 拒绝（安全默认）。**缓解**：接线仅需一行（工厂已备），但**必须**在真实 Lab 证据到位后才做，避免无证据接线。
3. **镜像 digest 未校验**：候选 `thehiveproject/thehive:4.1.24-1` 有 in-tree repo/version 证据，但**无 digest**（未拉取）。**缓解**：部署方案强制拉取后校验 `sha256:` 与权威 registry 一致，禁 `latest`。
4. **path-agnostic 词表双向开放**：`case_created` 同时可经 webhook 与 reconcile 两路映射。**缓解**：webhook `THEHIVE_CALLBACK_TOKEN` 默认空→fail-closed；`case_created` 是 reader 合成词、TheHive 不原生发出；`test_webhook_persistence.py` 断言全部原生生命周期词零 fact。

### 9.2 回滚 / 清理方案

- **代码回滚**：4 个前向提交均为**独立自然单元**，可逐个 `git revert`（**非** reset/amend）安全回退；§4（`093eb1c`）与 §5（`117ab6b`）解耦，reader 未接线故回退 §5 不影响生产 reconcile 行为（仍走 sealed 空 registry）。
- **G1-C 保持**：`0c372aa` Wazuh 安全修复全程未动；无回滚会重新暴露已确认不安全路径。
- **仓库外取证源清理**：`d:\edge\github\_m2_thehive_src\`（TheHive+ScalliGraph 权威 checkout）在**仓库外**，不被 git 跟踪；审查 ZIP **不含**该大型源码树（仅含从中提取的 `file:line` 证据引用）。
- **Lab 清理（若未来启动）**：见 `a5c90df` 文档 §6.4 —— 按 `sentinelflow-m2-lab-` 前缀精确移除容器/卷，**不使用**全局破坏性 `docker system prune -a`/`volume prune`，**不删除**既有用户数据，测试后使临时凭据失效。

### 9.3 下一阶段建议（均需**另行单独授权**，本轮不自动进入）

1. **在资源充足主机启动真实 Lab**（解除能力 4）：管理员授权 + 容器运行时 + ≥8 GB 空闲内存 + 镜像 digest 校验 → 执行 `test_real_get_case_verifies_creation` / `test_real_thehive_case_creation`（`-m external`）→ 观测真实 200/201/401/403/404 + 真实 `~<id>` reference + `createdAt`。
2. **真实证据到位后接线 reader**（解除能力 2 缺口）：将 `create_read_adapter_registry` 接入 router（一行），并以真实 Lab 观测复核三重合取门。
3. **生产版本认证**（解除能力 5）：取得真实目标实例契约或权威 registry digest + 生产版本取证；**Source CERTIFIED 不升级为生产认证**。
4. **不得自动进入** Shuffle / Wazuh Reader / 下一版本发布 / GitHub push（§11 明确禁止）。

---

## 10. 保护约束合规声明（Protection Constraints Compliance）

本轮**未**做任何被禁止的操作，逐项确认：

- ✅ 未修改 Wazuh G1-C 空词表（`0c372aa` 保持不变）；未进入 Shuffle G4；未创建 WazuhReader；未修改任何历史 Outcome / 历史提交；未发布新版本。
- ✅ 未修改冻结通用执行状态机 / 通用契约 / DB 模型 / 审批规则；未改 `shuffle.py` / `wazuh.py`——`git status` + `git diff --stat`（frozen 文件列表为空）双重佐证。
- ✅ 未改 sealed `default_read_adapter_registry()`（保持空）；未改 router 接线；reader 交付但**未接线**；60 处 `_inject_registry` 跨层缝 + sealed A1 纯度审计全部通过。
- ✅ 未恢复任何未经认证的 409 幂等成功路径；未用数字案号替代字符串资源 ID；未简单删除关联信息声称闭环（改为移入声明的 tags 通道）。
- ✅ 未 amend / rebase / reset / force-push；未移动历史 tag；**未 push**（`0 behind / 32 ahead`，全程本地）。
- ✅ 未做管理员安装、未重启宿主机、未改虚拟化网络、未拉取/执行未校验镜像、未连接生产、未发起真实业务写入、未运行 Wazuh Active Response、未创建真实客户案件、未发送真实通知。
- ✅ 文档与代码分离提交；测试用隔离 stub + 内存 SQLite，**未用生产凭据**、**零外部网络**；临时/占位凭据（`LAB_THEHIVE_KEY_DO_NOT_USE`）与 AWS 文档公开示例值（`AKIAIOSFODNN7EXAMPLE`，仅作脱敏测试诱饵）均非真实凭据；`.env` 已 gitignore；仓库外源码树不被跟踪。

---

## 11. 停止声明（Stop — Await Milestone Final Review）

M2 授权范围内的可交付项已完成并取证：**§2 版本+ScalliGraph 认证 CERTIFIED（`a5c90df`）+ §4 写 Schema 修复（`093eb1c`）+ §5 Reader+mapping+测试（`117ab6b`）+ §6 隔离闭环测试（`beca5ab`）+ §7 隔离回归 2556 passed + §8 四个本地前向提交**。

**真实本地联调 = LAB BLOCKED；Reader 真实读取+生产接线 = EVIDENCE-GAPPED；生产部署认证 = UNKNOWN** —— 三项依授权如实保持未完成，缺口、风险与前置已入档（§9）。**`M2 LOCAL LAB E2E` 未达 PASS 条件，不标记 PASS，不伪造全部通过。**

审查 ZIP 已在**仓库外**生成（脱敏；见交付说明），由用户上传供 Final Review。

**本轮到此停止，等待用户上传审查包并进行 Final Review。不自动进入 Shuffle、Wazuh Reader、下一版本发布或 GitHub push。** 解除任一剩余阻塞（启动本地 TheHive Lab、拉取镜像、接线 reader、生产版本认证）均需用户**另行单独授权**。
