# Phase 3 设计：响应执行架构（Response Execution Architecture）

> 状态：**设计冻结（四段全部经评审确认）**
> 范围：Phase 3.1 —— 执行核心（Execution Core）+ Mock/DryRun 适配器；**不接任何真实外部系统**
> 基线：v1.1.0（commit `0f6e3fc`，tag 冻结，本设计不修改 v1.1.0 任何已发布内容）
> 日期：2026-08-28

---

## 1. 定位与安全哲学

Phase 2 完成了"建议系统"：AI 只解释 / 总结 / 建议，人工审批只记录决定（Approve ≠ Execute）。
Phase 3 是从"建议系统"迈向"安全响应系统"的分水岭 —— 批准的建议**可以**变成受控执行，但：

- **执行是独立的人工决定**（两段式显式执行）：approved ≠ executed；Execute Intent 必须单独发起。
- **React 只表达 Intent，Server Guard 才是唯一安全边界**：浏览器二次确认只是 UX 控件；即使 `curl POST /executions` 绕过前端，也必须经过同一套 Token + Guard + Approval + Policy 链。
- **执行必须可审计到字节级**：追加式日志，从日志单表可重建任一执行的完整生命周期。
- **客户端永远只提供 Intent，不提供执行事实**：action / target / approval 归属全部由服务端从已批准建议装配。

## 2. 总体管道（冻结）

```
Approved Recommendation
        ↓
Execute Intent（客户端：仅 execution_id + operator + 备注）
        ↓
Auth（EXECUTION_TOKEN Bearer） / Schema（extra=forbid）→ 401/422 不落行
        ↓
execution_log: requested（合法 Execute Intent 已形成执行事实）
        ↓
Guard / Policy（审批绑定 / 生命周期 / 幂等 / 适配器能力）
        ├── reject → execution_log: guard_rejected（终态，同事务）
        └── pass   ↓
ResponseExecutor（服务端装配 ExecutionDispatch）
        ↓
execution_log: dispatched（同事务）
        ├── succeeded（终态）
        └── failed（终态，已受理的失败是执行事实，必须落行）

补偿：
Original Execution（succeeded / failed）
        ↓
人工决定补偿（新 execution_id）
        ↓
服务端继承原 approval_id → 重新经过 Token + Compensation Guard
        ↓
compensation_requested
        ├── compensation_succeeded（终态）
        └── compensation_failed（终态）
```

## 3. 冻结决策清单

| # | 决策 |
|---|---|
| D1 | 两段式显式执行：Execute 是独立人工决定，Policy/Guard 全链预检 |
| D2 | Phase 3.1 只交付执行核心 + Mock 适配器；Shuffle / Wazuh / TheHive 只定义接口，不实现、不出站 |
| D3 | 仅 `block_source_ip` / `isolate_host` / `disable_account` 机器可执行；`escalate_to_incident` / `hunt_related_activity` / `monitor_only` 由 Guard 拒绝 |
| D4 | 执行写端点要求 `.env` 共享 `EXECUTION_TOKEN`（Bearer）+ operator 记录；不引入用户体系 |
| D5 | 补偿即执行：补偿是新的 Execution（新 execution_id），走完整执行链，双向链接原执行 |
| D6 | 前端：Execute 按钮（Token + 二次确认）+ 执行历史徽标 + 独立 Execution Audit 页 |
| D7 | 架构为纯追加执行日志（方案 B）：`execution_log` 单表，状态完全派生 |
| D8 | `ExecutionOutcome.status ∈ {succeeded, failed}`；`dispatched` 是平台日志态，不是适配器产物 |
| D9 | `protocol_violation` 由 SentinelFlow 解析适配器返回时判定，适配器无权自声明 |
| D10 | 同步派发（请求内完成全链），`EXECUTION_TIMEOUT_SECONDS` 默认 30；不引入队列/后台基建 |
| D11 | 补偿的 `approval_id` 由服务端从原执行继承，客户端不传；补偿重新经过 Token + Guard |
| D12 | `requested` = “合法执行意图已被服务端接收并形成执行事实”（Auth + Schema 通过即落行），**不是**“所有 Guard 已通过”；Guard 在 `requested` 之后执行，拒绝追加 `guard_rejected`（业务拒绝必留审计事实） |
| D13 | `requested` + Guard 结果（`guard_rejected` 或 `dispatched`）在同一数据库事务内原子提交；`dispatched` + Executor 终态行同事务；不产生永久停留 `requested` 的孤儿执行（v1 同步模型） |
| D14 | 幂等与唯一性的并发防线双保险：Service 预检 + DB 部分唯一索引缺一不可（并发事务可能同时看到“未占用”）；`IntegrityError` → 409（Step 13 `UNIQUE(recommendation_id)` 同款） |

## 4. 数据模型：`execution_log`（迁移 0009，追加式）

| 列 | 语义 |
|---|---|
| `id` | UUID 主键 |
| `execution_id` | 调用方提供的**唯一幂等键 + 执行身份**（见 §5） |
| `approval_id` | FK → `ai_response_approvals`；execute 方向来自请求并验证；compensate 方向**由服务端从原执行继承** |
| `decision` | 冻结词表（与 direction 的合法组合由 CHECK 约束，见 §6） |
| `action` / `target` | **服务端从已批准 Recommendation 快照装配**，客户端请求体不接受这两个字段 |
| `direction` | `execute` / `compensate` |
| `compensates_execution_id` | 补偿行链接原执行（双向可追溯） |
| `operator` | 执行操作者身份（与审批 `reviewer` 分轨） |
| `detail` | JSONB：Guard 拒绝原因 / dispatched 请求回显 / 适配器原始应答 / 失败分类。**永远不含 Token** |
| `created_at` | **服务端生成**（延续 `reviewed_at` 先例），客户端时间永不入库 |

### 约束（冻结 9 条）

1. `UNIQUE(execution_id) WHERE decision='requested'` —— 幂等键唯一；**并发竞态的最后一道防线（D14）**
2. `UNIQUE(approval_id) WHERE direction='execute'` —— 一条审批的正向执行**整个生命周期唯一**（requested / guard_rejected / dispatched / succeeded / failed 任一都占位）
3. `UNIQUE(compensates_execution_id) WHERE decision='compensation_requested'` —— 一条原执行至多一次补偿
4. 只 INSERT
5. 不 UPDATE
6. 不 DELETE
7. `action` / `target` 仅由服务端从批准建议快照写入
8. 状态派生顺序 `ORDER BY created_at DESC, id DESC`（确定性：同时间戳按 id 定序）
9. decision × direction 合法组合由 DB CHECK 兜底（Service 状态机是主裁决者）

### 执行身份绑定（execution_id 语义冻结）

`execution_id` 不只是去重字符串，而是**执行身份**：首次请求将其与 `approval_id` / `direction` / 服务端装配的 `action` / `target` 快照绑定；其后任何携带不同参数的重放一律 **409**，数据库保持首次执行的完整事实，绝不被二次请求污染。
**并发兜底（D14）**：不能依赖 `if not exists: insert()` 单独解决 —— 并发事务可能同时看到 `execution_id` 未被占用。Service 预检与 DB 部分唯一索引必须同时存在，`IntegrityError` 捕获后转稳定 409。

## 5. 派生状态

`当前状态 = 该 execution_id 下按 created_at DESC, id DESC 的第一行 decision`。
读路径纯查询（PG 用窗口/子查询，SQLite 用子查询，与 dashboard 双库写法一致）；写路径永远只 `add` 新行。补偿链经 `compensates_execution_id` 关联，逐 `execution_id` 独立派生。

## 6. 冻结状态机（Service 掌裁决，CHECK 做最后防线）

最终状态机图（冻结版）：

```
                         ┌───────────────┐
                         │ HTTP Auth     │
                         │ + Schema      │
                         └───────┬───────┘
                                 │
                         401 / 422 │
                                 ▼
                              no log

                                 │
                                 ▼
                         ┌───────────────┐
                         │   requested   │
                         └───────┬───────┘
                                 │
                            Guard / Policy
                          ┌──────┴──────┐
                          │             │
                       reject         pass
                          │             │
                          ▼             ▼
                 guard_rejected     dispatched
                                          │
                                   ┌──────┴──────┐
                                   │             │
                              succeeded       failed

补偿：

succeeded / failed
        ↓
Human Compensation Intent
        ↓
compensation_requested
        ↓
 ┌──────┴──────┐
 ▼             ▼
compensation_  compensation_
succeeded      failed
```

迁移矩阵：

```
execute 方向（同一 execution_id 内）：
  (空)        → requested          Auth + Schema 通过、合法 Execute Intent 形成即落行（D12）；
                                   语义 = “执行意图已被接收并形成执行事实”，不是“Guard 已通过”
  requested   → guard_rejected     终态：策略拒绝原因写 detail（业务拒绝必须留审计）
  requested   → dispatched         Guard 全过，适配器受理，请求回显写 detail
  dispatched  → succeeded          终态：适配器原始应答写 detail
  dispatched  → failed             终态：失败分类写 detail

compensate 方向（新 execution_id）：
  (空)                    → compensation_requested
  compensation_requested  → compensation_succeeded   终态
  compensation_requested  → compensation_failed      终态
```

- 非法迁移（对终态追加、跨 direction 的 decision 等）→ 类型化异常 → **409，绝不落行**（写前校验，追加式完整性不受破坏）。
- DB CHECK 只防“非法 decision × direction 组合”；**时序合法性由 Service 状态机裁决**（业务规则在 Service、数据库是最后完整性防线 —— 项目既有原则）。
- **事务边界（D13）**：`requested` + Guard 结果（`guard_rejected` 或 `dispatched`）必须在**同一数据库事务**内原子提交（`BEGIN → INSERT requested → Guard 评估 → INSERT 结果行 → COMMIT`），避免进程在 Guard 前崩溃留下永久停留 `requested` 的孤儿执行；`dispatched` + Executor 终态行（`succeeded` / `failed`）同事务。进程在事务中途的异常崩溃属现实边界，恢复机制留待后续版本；v1 同步模型下以上两个事务边界即为冻结约束。
- 补偿入口预检（写 `compensation_requested` 前，失败不落行）：原执行存在且派生态 ∈ {succeeded, failed}（`requested` / `guard_rejected` / `dispatched` 不可补偿）；适配器声明支持该动作的补偿；约束 3 兜底防重复补偿。

## 7. Guard / Policy 链（与适配器运行时错误严格分轨）

| # | Guard | 检查 | 失败表现 |
|---|---|---|---|
| G0 | Auth（HTTP 层） | `EXECUTION_TOKEN` Bearer 匹配 | **401，不落行**（凭据问题不是执行事实） |
| G1 | Schema 边界 | 请求体字段白名单，`extra="forbid"`；偷渡 `action`/`target` 直接拒绝 | **422，不落行** |
| G2 | 审批绑定 | approval 存在且 `status=approved`；action ∈ 三动作词表（服务端从建议快照读取） | 同事务追加 `guard_rejected`（`requested` 已先落行，D12；**业务拒绝 = 发生过的执行请求，必须留完整审计**） |
| G3 | 生命周期 / 幂等 | 该 approval 无正向执行行；`execution_id` 未被绑定 | 409；**Service 预检 + 部分唯一索引双保险（D14）**，`IntegrityError` → 409 |
| G4 | 适配器能力 | 已注册适配器 `supports(action)`（补偿则 `supports_compensation`） | 同事务追加 `guard_rejected` |

**分轨铁律**：
- Guard failure（确定性策略判断）→ `guard_rejected`
- Adapter failure（运行时：宕机 / 超时 / 拒绝）→ `dispatched → failed`
- 两个统计口径绝不混合（"策略拒绝了多少次" ≠ "外部系统挂了多少次"）。

## 8. Executor 契约（复刻 `AIProvider` 血统）

```
ResponseExecutor（抽象）
├── name: str                              永不伪装（mock 恒为 mock）
├── supports(action) -> bool               Guard G4 的唯一能力依据
├── supports_compensation(action) -> bool  补偿预检依据
├── execute(dispatch) -> ExecutionOutcome
└── compensate(dispatch) -> ExecutionOutcome
```

- **`ExecutionDispatch`**（服务端冻结 DTO）：`execution_id / action / target / 审批引用`，全部由服务端装配，零客户端输入直达适配器。
- **`ExecutionOutcome`**：`{status ∈ {succeeded, failed}, detail, raw_response?}`，`extra=forbid`；结构违规由**平台解析时**判定为 `protocol_violation`（D9），绝不伪装成功。
- **注册表**：`create_executor(settings)` 按 `.env` `EXECUTION_ADAPTER` 选择；默认 `mock`；`shuffle` / `wazuh` / `thehive` 为保留值，当前注册即 `ConfigError` —— 换适配器不改 Guard / 状态机。
- **失败分类词表（冻结，写入 `detail`）**：`adapter_unavailable` · `timeout` · `adapter_error` · `protocol_violation`。

### Mock 适配器（v1 唯一实现，兼 DryRun）

- 零出站、确定性输出（同输入同输出）、`name` 恒为 `mock`。
- `detail` 完整回显"将要执行的动作 + 目标 + 参数"（DryRun 审计：日志可回答"真执行会发生什么"）。
- `fail_with` 故障注入（测试专用）：不可达 / 超时 / 动作拒绝，分别驱动三条 `failed` 分类。
- `compensate` 确定性模拟逆操作回显。

### 失败落行语义（与 Phase 2 的根本差异）

| 场景 | 落行 |
|---|---|
| 401 / 422 | 不落行（未形成执行事实） |
| Guard 策略拒绝 | `requested → guard_rejected`（事实） |
| **`dispatched` 后适配器失败** | **`dispatched → failed` 必须落行** —— 已受理的失败是执行事实，不套用 Phase 2"失败不落库" |
| 协议违规 | `failed` + `protocol_violation`，绝不记成功 |

## 9. API 契约

| 端点 | 语义 |
|---|---|
| `POST /api/v1/executions` | 表达 Execute Intent。请求体冻结 `{execution_id, approval_id, operator, comment?}`，`extra="forbid"`（**不接受 action/target**）。Bearer Token（缺失/不符 401 不落行）。同步全链，**恒 201**：响应体含派生终态 + 完整日志行（`succeeded` / `failed`+分类 / `guard_rejected`+原因）。**规范语义（钉死）**：HTTP 201 表示 Execute Intent 已被接受并形成执行事实，**不表示目标动作已经成功**；因此 `201 + succeeded` / `201 + failed` / `201 + guard_rejected` 均成立；`401` / `422` / `404` / `409` 表示该请求未形成对应的成功执行事实。此边界在设计文档、API 文档与测试中必须完全一致 |
| `POST /api/v1/executions/compensate` | 发起补偿。请求体冻结 `{execution_id, compensates_execution_id, operator, comment?}`（**不含 approval_id** —— 服务端从原执行继承并重验审批状态）。预检失败 404/409 不落行；通过后恒 201 模式同上 |
| `GET /api/v1/executions` | 审计列表：逐 `execution_id` 派生最新态；`?status=&direction=&approval_id=&page=&size=`；最近活动倒序。**读 ≠ 执行，不要求 Token**（与 Phase 2 只读 API 一致） |
| `GET /api/v1/executions/{execution_id}` | 完整时间线：全部日志行（`created_at ASC`）+ 派生态 + 补偿双向链接。纯只读 |

错误契约：`401` 凭据 · `422` schema 违规 · `404` 审批/执行不存在 · `409` 未批准 / 已有正向执行 / 幂等键占用或异参重放 / 非法补偿前置 / 重复补偿。稳定文案，前端逐字透传。

## 10. Token 与安全纪律（冻结）

- `EXECUTION_TOKEN` 存于 `.env`（`.env.example` 提供占位模板），仅执行写端点校验。
- **前端**：执行弹窗输入，**仅驻留内存** —— 不落 localStorage / sessionStorage / 任何持久层。
- **服务端**：① 日志中绝不记录 Token；② 401 比较使用安全密钥比较（`hmac.compare_digest` 等恒定时间比较）；③ Token 永远不进入 `execution_log.detail`；④ Token 永远不进入 API 响应。审计日志不得成为秘密泄露源。
- 浏览器二次确认只是 UX；安全边界恒为 Token + Server Guard + Approval + Policy + Executor。

## 11. React 执行控制台

- **Approval Queue 页**：`Pending / Approved / Rejected` 三态页签；Approved 项出现 **Execute** 按钮 → 弹窗（operator + Token + 备注）→ `execution_id` 由 `crypto.randomUUID()` 生成 → `POST /executions` → 恒从 201 响应体渲染终态（`succeeded` 绿 / `failed` 红+分类 / `guard_rejected` 黄+原因），不追加 GET（Phase 2 同款）。
- **案件 AI 面板**：recommendation 条目挂执行态徽标（只读派生态，零操作按钮延续）。
- **Execution Audit 页**（独立导航项）：执行列表 + 筛选；点击展开完整日志时间线（decision / operator / detail 折叠）。审计入口零操作按钮。
- 页面加载恒零执行流量：执行仅来自显式点击（网络白名单测试延续 14.6 模式）。

## 12. 测试策略（四层 + 攻击面）

1. **后端单元**（+90 左右）：状态机全矩阵合法/非法迁移；`requested` 先于 Guard 落行语义（D12：拒绝路径也必须先有 `requested`）；事务原子性（`requested` + 结果行同事务，D13）；派生态确定性（同 `created_at` 双行 → `id DESC` 定序）；幂等重放（同键同参 → 409 且仅一行 `requested`）；**并发重放防护（直接驱动 `IntegrityError` 路径 → 409，不依赖 Service 预检，D14）**；审批生命周期唯一（正向终态后再试 → 409）；Guard 五关逐关；CHECK 兜底（直接 ORM 塞非法 decision×direction 必炸）；Mock 确定性 + `fail_with` 四分类；401 零落行。
2. **攻击面专项**：
   - **同 execution_id 异事实攻击**：第一次 `execution_id=A / approval=X`；第二次 `execution_id=A / approval=Y` → **409，数据库保持第一次执行的完整事实**；
   - **事实偷渡攻击**：请求体夹带 `action` / `target` → **422**（`extra="forbid"`）；
   - **未批准执行攻击**：对 `rejected` / 无审批的建议发起执行 → 拒绝；
   - **补偿前置攻击**：对 `requested` / `dispatched` 中间态发起补偿 → 409。
3. **跨层回归**（14.4 模式）：真实 API 全链 —— approve → execute → succeeded → GET 时间线；失败链；补偿链（双向链接）；重放防护；`EventRisk` / `Incident` 全程零变动。
4. **前端组件**（vitest）：按钮状态机、弹窗、三终态渲染、页面加载零自动执行。
5. **Browser E2E**（14.6 模式，8–10 旅程）：真实浏览器 + 真实后端 + 临时 SQLite：完整执行链 / 拒绝链 / 失败注入链 / 补偿链 / 审计时间线 / 网络白名单。
6. **迁移**：0009 独立做 `upgrade → downgrade → upgrade` 往返 + 约束验证。

## 13. 非目标（Phase 3.1 明确不做）

- 不接 Shuffle / Wazuh / TheHive 真实出站（接口与注册值预留）。
- 不引入用户体系 / 角色 / 认证系统（Token 是共享秘密，定位"受信任网络评估"不变）。
- 不引入 Celery / Redis / 消息队列 / 后台 Worker（同步派发 + 30s 超时；日志模型天然兼容未来异步化）。
- 不做正向执行重试（失败后恢复路径是补偿）。
- 不修改 v1.1.0 已发布的任何代码与文档语义。

## 14. 后续里程碑（占位，另行设计）

- Phase 3.2：首个真实适配器（候选顺序：Shuffle → Wazuh Active Response → TheHive）+ 故障注入契约测试。
- Phase 3.x：执行策略自动化（按动作类型 auto/manual）、用户体系、异步执行。
