# Phase 3.4.5-M4-F — Durable Dispatch 真实 Lab 最小可执行方案 & 门⑤状态

> **状态：门⑤ UNKNOWN（fail-closed，保持）· Lab Runtime LAB BLOCKED（本机，无授权主机）· Production UNKNOWN**
> 本文件是 **M4-F §5** 的唯一交付物：（1）明确门⑤（实例/租户绑定）保持 **UNKNOWN fail-closed**，本轮**不改写**；
> （2）整理一个**真实 Lab 的最小可执行方案**（精确镜像 digest、资源需求、网络隔离、临时凭据、目标版本与身份认证、
> 创建和读取测试、清理范围），供**未来获用户明确授权、资源充足的专用隔离主机**复现真实闭环。
> **本轮无用户明确授权的实验主机 → 严格遵守「不安装、不启动、不连接真实外部系统」，仅文档化方案。**
> 本文档**非 FROZEN**，**不认证任何生产运行时**；三域版本严格分离，绝不混用。

## 0. 文档控制区（Document Control）

| 字段 | 值 |
| --- | --- |
| 文档状态 | **门⑤ UNKNOWN（fail-closed，保持）· Lab Runtime LAB BLOCKED（本机）· Production UNKNOWN** |
| 授权 | M4-F §5（保留门⑤ UNKNOWN fail-closed + 整理真实 Lab 最小可执行方案；无授权主机则不安装/不启动/不连接） |
| 授权基线提交 | `33e5d34`（M4 前向绑定 & 证明通道收口最终报告，审查者复核基线）；本文件为该基线之上的 **M4-F 前向工作**（HEAD `c1c74c3`，ahead 54，工作树干净） |
| 采集日期 | 2026-09-09 |
| 采集方式 | **只读**：git 元数据核验 + 本机资源只读探测（`Get-Command`/`Get-CimInstance`/`wsl -l -v`）+ 隔离测试运行；**无镜像拉取、无服务启动、无真实写入、无生产凭据、无管理员安装** |
| 前置权威文档 | `phase3.4.5-m2-thehive-lab-evidence-and-deployment-plan.md`（TheHive `4.1.24-1` 镜像/版本/digest/依赖/部署/清理方案的**权威取证来源**，本文档复用其已核验事实，不重复取证） |
| 唯一交付物（本文档） | `docs/design/phase3.4.5-m4-f-durable-dispatch-lab-execution-plan.md`（新增） |
| 保护约束 | 不改门⑤（GATE_INSTANCE_TENANT）；不改冻结通用契约/DB 模型/历史 Outcome；不改 Wazuh G1-C 空词表；不进 Shuffle/Wazuh Reader；不接生产 router；不安装/不启动/不连接真实外部系统；不 push；不 amend/rebase/reset/force-push/移动 tag |

**本轮目标（What this IS）**：把「真实 Lab 能证明、而隔离测试无法证明」的 M4-F 能力（派发前 durable 提交在**真实外部 HTTP 发出后**经崩溃/回滚仍存活、真实请求目标与绑定 endpoint 一致、真实创建+读取闭环）整理为**最小可执行方案**；并如实固定门⑤的 UNKNOWN fail-closed 状态。

**本轮非目标（What this IS NOT）**：不启动真实 TheHive、不拉取/执行镜像、不连接生产、不发起真实业务写入、不做管理员安装；**不改写门⑤以强行解锁**；不把读取者 organisation 当作案件所属 organisation；不以源码/配置推断冒充运行时观测。

---

## 1. 门⑤状态：UNKNOWN fail-closed（保持，不改写）

审查者 M4-F §5：**「保留现有实例/租户 UNKNOWN 的 fail-closed 状态。不要为了完成本轮改写门⑤，也不要把读取者 organisation 直接当作案件所属 organisation。」** 本轮**未对门⑤做任何代码改动**，仅核验其完好。

### 1.1 门⑤拒绝路径（源码，`read_adapters/verified.py`，本轮只读核验未改）

| 常量 | 值 | 行号 |
| --- | --- | --- |
| `GATE_INSTANCE_TENANT` | `"instance_tenant"` | L109 |
| `REASON_INSTANCE_BINDING_UNKNOWN` | `"instance_binding_unknown"` | L128 |
| `REASON_INSTANCE_MISMATCH` | `"instance_mismatch"` | L129 |
| `REASON_TENANT_BINDING_UNKNOWN` | `"tenant_binding_unknown"` | L130 |
| `REASON_TENANT_MISMATCH` | `"tenant_mismatch"` | L131 |

`verify_creation_effect`（L554/L556/L558）：`instance_binding is None` → `CreationRefusal(GATE_INSTANCE_TENANT, REASON_INSTANCE_BINDING_UNKNOWN)`；不匹配 → `REASON_INSTANCE_MISMATCH`；`tenant_binding is None` → `REASON_TENANT_BINDING_UNKNOWN`。

### 1.2 为什么真实历史恒为 UNKNOWN（Amendment §12）

TheHive `4.1.24-1` 的 `OutputCase`（M2 Lab 方案 §4.2）**既不携带实例身份、也不携带租户/organisation 归属**；`dispatch_binding_facts()` 的 `target_instance`/`target_tenant` 恒为 `None`（binding 只记录 config-declaration 的 base URL + 版本，**绝不**把 base URL 当作实例身份）。因此对**任何真实派发历史**，门⑤的 `instance_binding`/`tenant_binding` 均为 `None` → **fail-closed 拒绝**（零 fact）。

> **读取者 organisation ≠ 案件所属 organisation**：`/api/user/current` 的 organisation 只是**读取者自身**的组织归属证据候选，**绝不**能推断为**被创建案件**的所属 organisation。门⑤保持 UNKNOWN 是目前**应保留的安全状态**（审查者已确认「Agent 的处理是正确的」）。

### 1.3 门⑤完好性证据（本轮只读运行，隔离范围）

```
tests/test_verified_creation_proof.py -k "Gate5 or instance or tenant or binding"
→ 11 passed, 67 deselected, 1 warning in 0.30s
```

覆盖：`test_instance_binding_unknown_fails_closed`、`test_tenant_binding_unknown_fails_closed`、`test_instance_mismatch`、`test_tenant_mismatch`、`test_instance_and_tenant_are_always_none`（真实 read 恒 None）、`test_old_history_without_binding_fails_closed`（无 binding 恒 None，**不倒填**）。**结论：门⑤ UNKNOWN fail-closed 完好，本轮无需也未做任何改动。**

> **纪律：Lab 即便未来通过，也不得据此解锁门⑤** —— 除非取得**权威派发时实例/租户来源**（TheHive 4.1.24-1 无此来源）。Lab 通过只证明「运行时行为与源码契约一致」，**不**制造门⑤所缺的不可变事实。

---

## 2. 隔离测试已覆盖 vs 真实 Lab 必须补充（诚实边界）

### 2.1 隔离测试**已**证明（内存/file-backed SQLite + stub transport，全部本地绿）

| 能力 | 隔离证据（M4-F §1/§2/§3 已提交） |
| --- | --- |
| 派发前 durable 提交**独立连接可见** | `DurableDispatchAttemptStore` 用**独立 Session** commit；file-backed SQLite + 独立连接读回（`03e8e6e`/`32e5df0`） |
| 外部发出后 **caller rollback / 崩溃** attempt 存活 | `TestDurableAttemptSurvivesFailures` 6 分类 + PG 专项交错（`d15b7fd`） |
| **无重定向**（Authorization 不跨主机转发） | `TestWriteNoRedirectCredentialLeak`（`1abe5e6`） |
| **目标绑定一致**（请求 target == 绑定 endpoint） | `TestWriteTargetBindingConsistency`（`1abe5e6`） |
| 响应读取中断 fail-closed（绝不推断成功） | `TestResponseReadInterruption`（`1abe5e6`） |

### 2.2 隔离测试**无法**证明（需真实 Lab 或明确保持未验证）

| 缺口 | 为什么隔离测试不够 | Lab 补充 |
| --- | --- | --- |
| **真实 TheHive 4.1.24-1 的重定向行为** | stub transport 只模拟 3xx，无法证明真实端点是否/如何重定向 | §5 T4 |
| **真实网络超时/连接中断语义** | stub 抛 `TimeoutError`/`IncompleteRead` 是模拟，非真实 TCP/TLS 中断 | §5 T6 |
| **真实创建 + 读取闭环**（三重合取门） | stub body 是构造的 `OutputCase`，非真实 TheHive 序列化 | §5 T5 |
| **PostgreSQL 生产锁 / 崩溃语义** | **SQLite 无法可靠模拟**行锁、并发争用、进程崩溃后的 WAL 恢复 | §4.7 + §5 T1/T2（PG 专项） |

> **审查者 M4-F §2 纪律遵守：「不能以 SQLite 全绿宣称 PostgreSQL 事务与并发已认证。」** 本轮 PostgreSQL 专项集成测试（`test_dispatch_durable_postgres.py`）默认 **deselect**（`@pytest.mark.external` + env guard），**保持「PG 真实锁/崩溃语义未验证」的诚实状态**，直到在获授权主机上以真实 PostgreSQL 运行。

---

## 3. 本机 Lab 可行性只读再探测（M4-F session，真实证据，采集于 2026-09-09）

| 探测项 | 命令（只读） | 结果 | 对 Lab 的影响 |
| --- | --- | --- | --- |
| Docker | `Get-Command docker` | **ABSENT** | 无容器运行时 |
| Podman | `Get-Command podman` | **ABSENT** | 无备选运行时 |
| nerdctl | `Get-Command nerdctl` | **ABSENT** | 无备选运行时 |
| WSL 已安装分发版 | `wsl -l -v` | **零分发版**（「没有已安装的分发版」） | 无法承载任何 Linux 工作负载 |
| 空闲内存 | `Win32_OperatingSystem.FreePhysicalMemory` | **仅 2.0 GB 空闲**（总 15.73 GB） | **比 M2 探测（3.35 GB）更低**，远不足以跑 TheHive+JanusGraph+ES 栈（需 6–8 GB） |

**判定：真实本地 TheHive Lab = `LAB BLOCKED`（本机范围，沿用 M2 §6.2）。** 依据：无容器运行时 + 零 WSL 分发版 + 空闲内存仅 2 GB + 安装任一运行时/分发版均需管理员权限/网络下载/宿主机重启（被 §1/§3 明确禁止）。

> **LAB BLOCKED 范围仅限本 Windows 主机**：本轮只读探测**未**穷尽枚举所有可能的 VM/远程/云实验环境，故**不**据此推断「任何可用实验环境均不存在」。若用户确认并明确授权一台资源充足（≥8 GB 空闲 + 容器运行时 + PostgreSQL + 管理员授权）的**专用隔离主机**，§4 方案可在其上复现真实 Lab——**本轮不自动进入**。

---

## 4. 真实 Lab 最小可执行方案（PLAN ONLY — 供未来获授权、资源充足的主机复现）

> 以下为**方案**，本轮**不执行**。镜像/版本/digest/依赖事实**复用 M2 Lab 方案 §2.3/§6.3 已核验值**，不重复取证。
> **TheHive 4 已停止维护、官方仓库已归档**（M2 §2.3 EOL 事实）：本 Lab **仅用于隔离兼容性实验**，**不作为新的生产部署推荐**；Lab 通过**不得**升级为生产认证。

### 4.1 目标版本与镜像 digest（复用 M2 已核验）

| 项 | 值 | 强制校验 |
| --- | --- | --- |
| TheHive 镜像 | **`thehiveproject/thehive4:4.1.24-1`**（官方发布名，对应 commit `b6649bb`） | 拉取后**必须**校验 `sha256:` digest == **`c8b6c7eaa0cd21853cbf88eae836c57de2aec29e6edb8a9d49b491dbc09c6811`**（官方注册表值）+ 平台架构匹配；**禁止** `latest`；记录拉取到的 digest 作为 Lab Runtime 证据 |
| Source Version | TheHive `4.1.24-1` = git `b6649bb`；ScalliGraph pin `2c2a7a4` | 已 CERTIFIED（M2 §2）；Lab Runtime 须与之一致 |
| 暴露端口 | `9000` | 绑定 loopback（§4.3） |
| 基础镜像 | `openjdk:8`（JVM） | — |

> **digest 现状诚实标注**：`c8b6c7…6811` 是审查者从官方 registry 独立核验的 **registry 元数据**；**本机 LAB BLOCKED 未拉取**，故部署主机**仍必须**在拉取后本地校验 digest 一致方可作为 Lab Runtime 证据。

### 4.2 资源需求

| 资源 | 最小要求 | 说明 |
| --- | --- | --- |
| 空闲内存 | **≥ 8 GB** | TheHive(JVM `-Xmx` 显式) + JanusGraph + ES/OpenSearch 各 ~1 GB+ 堆；总和 ≤ 主机可用内存 70% |
| CPU | ≥ 4 逻辑核 | 整栈启动 + 索引 |
| 磁盘 | ≥ 20 GB 空闲 | 镜像 + JanusGraph BerkeleyJE + ES 索引 + 附件卷 |
| 容器运行时 | docker / podman / nerdctl 任一 | 本机均 ABSENT（§3） |
| **PostgreSQL** | **≥ 12**（独立实例，非 SQLite） | **M4-F §2 专项**：真实行锁/并发争用/崩溃恢复语义（§4.7） |

### 4.3 网络隔离

- TheHive `9000` **绑定 loopback（127.0.0.1）**，依赖服务端口仅隔离网内；**不暴露公网**；不改宿主机现有虚拟化网络。
- SentinelFlow 后端 → TheHive 仅经 **loopback / 隔离虚拟网**；写适配器 `THEHIVE_BASE_URL` 指向该隔离端点。
- **无重定向验证**（M4-F §3）：Lab 须验证真实 TheHive 对 `POST /api/case` **不发 3xx**；若发，`_NoRedirectHandler` 须 fail-closed（HTTPError → adapter_error），**Authorization 绝不跨主机转发**（§5 T4）。

### 4.4 临时凭据与身份认证

- 独立**非生产**账户 + **随机临时** API key（`THEHIVE_API_KEY`）；单一测试 org + 单一测试 user。
- 凭据存 **Git 忽略**的本地文件/环境变量；报告/日志/diff/审查包**全部脱敏**（`redact_text`，替换 `len ≥ 4` 敏感值为 `***`）。
- 四域凭据隔离（TheHive / Shuffle / Wazuh / 执行 token）各自独立校验（`validate_base_url` 拒 query/fragment/userinfo/非法 scheme）。
- **身份认证证据边界**：`/api/status`（版本）+ `/api/user/current`（读取者组织）**只作证据候选**；**绝不**把读取者 organisation 当作案件所属 organisation（门⑤保持 UNKNOWN，§1.2）。

### 4.5 依赖服务

| 服务 | 方案 | 校验 |
| --- | --- | --- |
| JanusGraph | BerkeleyJE 本地后端 | 镜像逐一固定 tag + 校验 digest；与 `application.sample.conf` 一致 |
| Elasticsearch / OpenSearch | 索引后端 | 同上 |
| 附件存储 | 独立卷 | 卷名带 `sentinelflow-m4f-lab-` 前缀 |

### 4.6 健康检查 / 超时

- TheHive `GET /api/config` 或 `/` 就绪探测；有界启动超时（如 180s）+ **有界重试**（如 5 次）；超时未就绪 → 判 Lab 启动失败，**不**伪造成功。

### 4.7 PostgreSQL 专项（M4-F §2：生产锁 / 崩溃语义）

> SQLite 无法可靠模拟生产锁/崩溃语义（审查者 §2 明确）。Lab 必须以**真实 PostgreSQL** 运行 M4-F 事务/并发验收：

- 独立 PostgreSQL 实例（非 SQLite）；`dispatch_attempt` 表经 **Alembic head `0011`** 迁移创建。
- 运行 `test_dispatch_durable_postgres.py`（本轮默认 deselect），以 `-m external` + 真实 PG DSN env 解锁。
- 验证：派发前 durable 提交经**独立 PG 连接**可见；外部发出后 caller rollback / 进程崩溃（`SIGKILL` 等效）→ attempt 存活；并发争用（多 worker 同 `execution_id`）→ 唯一约束/行锁保证**恰好一次**外部调用；重启后恢复未决尝试**无自动第二次外部调用**。

---

## 5. M4-F 专项 Lab 测试矩阵（创建 + 读取 + durable 存活）

> 每个测试均以**独立 Session/连接**验证提交可见性，**绝不**以同一 Session 的 flush 可见性冒充 durable（审查者关键发现①）。

| # | 场景 | 注入 | 断言（Lab 必须观测到） |
| --- | --- | --- | --- |
| **T1** | 派发前 durable → 真实 HTTP 发出 → **进程崩溃** | 真实 `POST /api/case` 发出后 `SIGKILL` 后端 | 重启后**独立 PG 连接**读回 attempt **存活**；终态缺失 → 标记「已发出无可靠终态」**不确定**，**人工核查**路径，**零自动重试/补偿/重新派发** |
| **T2** | 派发前 durable → 真实 HTTP 发出 → **caller rollback** | 外部调用返回后回滚整个 caller 事务 | attempt（独立事务提交）**存活**；终态只追加引用同一 `attempt_id`，**不覆盖**绑定 |
| **T3** | **目标绑定一致** | 真实创建 | 绑定记录 `endpoint` == 执行器实际请求 target origin（`{endpoint}/api/case`）；版本仍只记 `config-declaration`，**绝不**把 base URL 当实例身份 |
| **T4** | **3xx 无重定向** | 真实/代理注入 3xx | `_NoRedirectHandler` → HTTPError → fail-closed `adapter_error`；**Authorization 绝不跨主机转发**；恰好一次调用 |
| **T5** | **真实创建 + 读取闭环** | 真实 `POST` + `GET /api/case/{_id}` | 三重合取门（IDENTITY/CORRELATION/CREATION，M2 §5.2）；`sentinelflow:execution:<uuid>` tag 经真实 TheHive 持久化+回显；**门⑤仍 UNKNOWN fail-closed**（真实 OutputCase 无 instance/tenant） |
| **T6** | **响应读取中断**（真实网络） | 真实 TCP/TLS 中断 body | fail-closed `adapter_unavailable`（读超时→`timeout`）；**绝不推断成功**；已提交 attempt 存活；**零重试** |
| **T7** | 重复 `execution_id`/`approval_id` + 并发争用 | 多 worker 同 ID | 唯一约束/行锁 → **恰好一次**外部调用；无重复创建 |

> **T1/T2/T7 必须以真实 PostgreSQL 运行（§4.7）**；T3/T4/T5/T6 针对真实 TheHive 4.1.24-1 端点。**任何实际版本/实例/租户证据必须来自该 Lab 环境，不得由配置声明替代**（审查者 §5）。

---

## 6. 清理范围（测试后执行；不触碰既有用户数据）

| 步骤 | 操作 | 安全边界 |
| --- | --- | --- |
| 1 | 停止并移除**本 Lab 专属**容器（按 `sentinelflow-m4f-lab-` 名称/标签精确匹配） | **不使用** `docker system prune -a` / `docker volume prune` 等**全局破坏性**命令 |
| 2 | 删除**本 Lab 专属**命名卷与独立持久化目录（前缀匹配） | **不删除**任何既有用户数据/其他业务卷 |
| 3 | **drop 本 Lab 专属临时 PostgreSQL 库**（`sentinelflow_m4f_lab`） | **不触碰**任何既有 PG 实例/库 |
| 4 | 撤销临时账户 / 使临时 API key 失效 | 凭据不留存于仓库；本地 Git 忽略文件测试后清除 |
| 5 | 保留**脱敏**后的请求/响应/关联 ID/时间戳/digest 证据于审查包 | 证据脱敏（`redact_text`）后方可归档 |

> **纪律（§3/§1）：不自动清理已有用户数据，不使用全局破坏性清理命令，不执行未授权的破坏性清理。**

---

## 7. 保护约束重申（Protection Constraints）

- **无用户明确授权的实验主机 → 不安装、不启动、不连接真实外部系统**（审查者 §5）；本轮**仅文档化方案**。
- **门⑤保持 UNKNOWN fail-closed**，本轮**不改写**门⑤；**不把读取者 organisation 当作案件所属 organisation**。
- **不接生产 router**；**不恢复**共享 `case_created` 词表；**不修改** Wazuh G1-C 空词表；**不进** Shuffle/Wazuh Reader。
- **不修改**冻结通用执行状态机/通用契约/DB 模型/历史 Outcome/历史提交。
- **不 amend / rebase / reset / force-push**；**不移动**历史 tag；**不 push**。
- **不做**管理员安装、不重启宿主机、不改虚拟化网络、不拉取/执行未校验镜像、不连接生产、不发起真实业务写入。
- 文档与代码分离提交；隔离测试用 stub + 内存/file-backed 库 + 默认 deselect 的 PG 专项，**不用生产凭据**、**0 外部网络**。

---

## 8. 验收映射（分能力，不得合并为「全部通过」）

| 能力项 | 本轮状态 | 证据 |
| --- | --- | --- |
| **门⑤ UNKNOWN fail-closed（保持）** | **PASS（保持，未改写）** | 本文档 §1（verified.py L109/L128-131/L554-558 只读核验；11 passed 隔离证据） |
| **真实 Lab 最小可执行方案（文档化）** | **COMPLETE（PLAN ONLY）** | 本文档 §4/§5/§6（镜像 digest/资源/网络隔离/临时凭据/身份认证/创建+读取测试/清理范围/PG 专项/测试矩阵） |
| **真实 Lab Runtime（本机联调）** | **LAB BLOCKED** | 本文档 §3（无容器运行时 + 零 WSL 分发版 + 仅 2 GB 空闲内存 + 需管理员安装/重启） |
| **PostgreSQL 生产锁/崩溃语义** | **UNVERIFIED（默认 deselect）** | 本文档 §2.2/§4.7（`test_dispatch_durable_postgres.py` 保持 deselect；不以 SQLite 全绿冒充 PG 认证） |
| **生产部署认证与接线** | **UNKNOWN / 未授权** | 本文档 §1.2/§4（Production Runtime 未知；门⑤ UNKNOWN；本里程碑不触碰生产） |

> **本轮明确：门⑤ UNKNOWN fail-closed 保持；真实 Lab 方案文档化 COMPLETE；本机 Lab Runtime = LAB BLOCKED；PG 生产语义 = UNVERIFIED；生产认证 = UNKNOWN。** 任一缺证据项保持其真实状态，绝不以源码/配置推断冒充运行时观测，绝不以 Mock/SQLite 冒充真实 TheHive/PostgreSQL。
