# Phase 3.2 设计：外部响应适配器（External Response Adapters）

> 状态：**设计冻结**（五项开放点 E1–E5 已全部裁决，2026-08-28；冻结后不得再改设计，只允许按 §11 拆步实施）
> 范围：Phase 3.2 —— 把受控执行核心接上真实外部安全系统（Shuffle / Wazuh / TheHive）；**第一次产生真实外部副作用**
> 基线：`657cb87`（Phase 3.1 原子提交，已推送 origin/main；本文档不修改该提交，不修改 v1.1.0 / `0f6e3fc`）
> 前置：`docs/design/phase3-response-execution.md`（Phase 3.1 设计，已冻结；其 D1–D14 全部继续有效，本文只增不改）
> 日期：2026-08-28

---

## 1. 定位与安全哲学

Phase 3.1 交付了受控执行核心：`Approved Recommendation → Execute Intent → Auth/Schema → Guard → Mock Executor → Append-only Audit`。MockExecutor 是**安全隔离层**：零出站、确定性、可注入失败。

Phase 3.2 是 SentinelFlow 第一次产生**真实外部副作用**的阶段。因此安全哲学升级三条：

1. **副作用不可逆假设**：任何到达外部系统的请求都可能已经生效。失败分类、重试、补偿的全部设计都以此为最坏前提。
2. **Fail-closed（关闭即拒绝）**：凭证缺失、配置不完整、适配器无法确认外部结果 —— 一律落 `failed` 行或启动期 ConfigError，**绝不猜测成功**。
3. **平台不信任适配器，适配器不信任外部系统**：双向验证链。适配器必须把外部终态证据翻译为 `ExecutionOutcome`；平台解析层（3.1 的 `protocol.py`）再对适配器产物做结构审判。

项目定位升级（用户裁决 2026-08-28）：

```
AI-assisted Security Operations
+ Human Governance
+ Controlled Real-world Response
+ External Security Orchestration
```

## 2. 三系统职责三分（冻结）

| 系统 | 职责定位 | 一句话 |
|---|---|---|
| **Shuffle** | Workflow Orchestration | 跨系统工作流编排器；SentinelFlow 只触发工作流，**编排逻辑住在 Shuffle 侧** |
| **Wazuh** | Endpoint / Security Response | 真实安全设备动作：封禁源 IP、隔离主机、账号处置响应（active response） |
| **TheHive** | Case / Investigation | 案件与调查管理：把已批准建议/执行事实升级为可调查案件（observability，非设备动作） |

关键推论：**Shuffle 本身就是多系统编排器**。SentinelFlow 不需要自己实现"一个动作同时调用多个系统"——需要跨系统联动时，触发一个 Shuffle 工作流，由 Shuffle 内部去调 Wazuh/TheHive。这直接决定了 §3 的架构选择。

## 3. 架构决策：Parallel Adapters vs Primary/Secondary（冻结）

**冻结结论：Single-Active-Adapter（单一活动适配器），拒绝两种危险替代方案。**

| 候选方案 | 裁决 | 理由 |
|---|---|---|
| ❌ Parallel Adapter（一个动作扇出多个系统） | **拒绝** | 一个动作多个副作用源 → 部分成功时审计语义崩溃（"本地 succeeded、外部半失败"的地狱入口）；补偿无法对齐 |
| ❌ Primary Executor → Secondary 隐式联动 | **拒绝** | 隐式扇出 = 审计盲区；执行链之外发生的副作用违反"字节级可审计"铁律 |
| ✅ **Single-Active-Adapter** | **采纳** | 每个部署一个 `EXECUTION_ADAPTER`，一个动作恰好一个出站目标；跨系统联动显式上移到 Shuffle 工作流（人设计、人可见、可审计） |

与 3.1 基建的契合（**零新架构**）：

- 注册表契约不变：`EXECUTION_ADAPTER ∈ {mock, shuffle, wazuh, thehive}`，每部署一个值；`create_executor(settings)` 继续返回唯一 `ResponseExecutor`。
- Guard G4（`executor_unsupported`）语义不变：未被活动适配器 `supports()` 的动作照旧被拒——**部署了 Wazuh 就不能执行 TheHive 的动作**，这是特性不是缺陷（强制职责三分落地）。
- 多系统协作的合规路径：AI 建议**多条独立推荐**（各自独立审批、各自独立执行链、各自独立审计行），跨系统联动显式上移到 Shuffle 工作流（编排逻辑住在 Shuffle 侧）。**平台内部永远没有扇出**。

## 4. Action → Adapter 映射（冻结）

动作词表保持 Phase 2 冻结的六词不动（E2 裁决：不新增词汇）；3.2 只做两件事：**扩展可执行集**（E1）与**划分适配器能力**。

**E1（已裁决 ✅ 采纳）**：`escalate_to_incident` 从“纯建议”升级为**受控机器可执行**（经由 TheHive 创建/升级案件）。这是把 AI 六词表中唯一语义适配 TheHive 的动作接入，不新增词表词汇。`hunt_related_activity` / `monitor_only` 保持纯建议，永远被 Guard 拒绝。

**E1 边界（钉死）**：
- “建案”不豁免任何安全闸：`escalate_to_incident` 必须走完整链 **Approval → Explicit Execute → Token/Guard → TheHive Executor**，与其他可执行动作完全同链，不得旁路；
- 这是 Phase 3.2 对 **action capability policy 的显式扩展**，不是对 Phase 2 历史 Recommendation 数据的重写：可执行集从 3（`block_source_ip` / `isolate_host` / `disable_account`）变为 4（+ `escalate_to_incident`），非机器执行从 3 变为 2；
- **历史数据零迁移**：已有的 `escalate_to_incident` 建议行不做任何修改；仅从 3.2 起，经正确 Approval + Guard 后，TheHive Adapter 部署下允许执行它们。

| action | Wazuh | Shuffle | TheHive | 说明 |
|---|---|---|---|---|
| `block_source_ip` | ✅ | ✅ | ❌ | Wazuh active response 直接封禁；Shuffle 走封禁工作流 |
| `isolate_host` | ✅ | ✅ | ❌ | 同上 |
| `disable_account` | ✅ | ✅ | ❌ | Wazuh 账号处置响应；Shuffle 走身份处置工作流；两适配器均默认不可补偿（不可逆假设） |
| `escalate_to_incident`（E1 后可执行） | ❌ | ✅ | ✅ | TheHive：创建/升级案件；Shuffle：升级工作流 |
| `hunt_related_activity` | ❌ | ❌ | ❌ | 纯建议，Guard 恒拒（不变） |
| `monitor_only` | ❌ | ❌ | ❌ | 纯建议，Guard 恒拒（不变） |

> **E2（已裁决 ❌ 本阶段不采纳）**：`trigger_workflow` 不进 3.2 词表。理由：它会把 `SentinelFlow → Shuffle → 多个系统` 的真实扇出伪装成普通 response action，直接破坏 Single-Active-Adapter / No internal fan-out 冻结；且现有四可执行动作 + TheHive 入口已足够覆盖 3.2 第一阶段。若未来确需“SentinelFlow → Shuffle → Wazuh → TheHive”级联动，将单独设计更高层的 orchestration capability，绝不把它伪装成普通动作。

**补偿能力表**（`supports_compensation`，Guard 预检用）：

| action | Wazuh 补偿 | Shuffle 补偿 | TheHive 补偿 |
|---|---|---|---|
| `block_source_ip` | ✅（解封 = 触发反向 active response） | 工作流依赖（看编排定义，默认 ✅ 有反向工作流时） | — |
| `isolate_host` | ✅（解除隔离） | 工作流依赖 | — |
| `disable_account` | ⚠️ 默认 ❌（账号处置不可逆假设） | ⚠️ 默认 ❌（除非工作流定义了恢复） | — |
| `escalate_to_incident` | — | — | ⚠️ 默认 ❌（案件创建不回滚；如需"关闭案件"另议，不进 3.2） |

补偿语义继承 3.1：补偿只读审计链接 + 人工触发 + 完整执行链，**永不自动补偿**。

## 5. 外部请求幂等策略（冻结）

三层幂等防线，层层独立：

1. **平台内（已存在，3.1）**：部分唯一索引 + Service 预检 → 同一 `execution_id` / 同一 approval 正向执行 / 同一原执行补偿，全部 409，不可能二次出站。
2. **出站携带幂等键（新）**：`execution_id` 作为外部幂等键透传——
   - Shuffle：工作流触发请求体携带 `sentinelflow_execution_id` 字段；
   - Wazuh：API 请求注释字段 / `command` 参数内嵌；
   - TheHive：案件 description 结构化字段 + 创建前查询去重（同一 `execution_id` 已存在案件 → 返回已有案件，判 `succeeded`）。
3. **外部重复信号翻译（新）**：外部系统返回"已存在/重复"类错误（HTTP 409 / duplicate key）时，适配器**必须翻译为 `succeeded`（幂等命中）而不是 `failed`** —— 重复请求不是失败，前提是该重复确实对应本平台自己的 `execution_id`。

## 6. Timeout / Retry / Unreachable（冻结）

- **超时**：继承 `EXECUTION_TIMEOUT_SECONDS`（默认 30，同步派发铁律不变，D10）。每个适配器允许配置更低的内部 HTTP 超时，但不得高于全局值。
- **零自动重试（E5 已裁决 ✅ 钉死）**：真实副作用场景下，自动重试 = 副作用放大器（封禁请求超时 ≠ 没封禁）。失败链唯一形态：`failed → 人工决定 → 新 execution_id → 再次执行`，或补偿。平台不提供、也不允许适配器内部实现任何形式的自动重试；**尤其适用于 `block_source_ip` / `isolate_host` / `disable_account` 这类真实副作用动作**。
- **失败分类映射**（沿用 3.1 冻结词表，适配器可自报前三词）：
  | 外部症状 | classification |
  |---|---|
  | 连接失败 / DNS / 拒绝连接 / 503 | `adapter_unavailable` |
  | 超时（全局或适配器级） | `timeout` |
  | 4xx/5xx（非幂等命中）、业务拒绝、响应结构异常 | `adapter_error` |
  | 适配器产物结构非法 | `protocol_violation`（**仅平台解析层可判**，D9 不变） |

## 7. 外部返回 → ExecutionOutcome（冻结）

**核心铁律：只有同步终态才被接受。适配器内部禁止轮询、禁止后台任务、禁止 webhook 回调。**（延续 D10 同步模型；异步编排住在 Shuffle 侧，对平台表现为"工作流已触发"的同步终态。）

| 外部返回 | ExecutionOutcome |
|---|---|
| 2xx + 外部业务确认成功 | `status="succeeded"` |
| Shuffle：工作流触发被接受（200/201 + execution id） | `succeeded`，detail 语义钉死为 **"workflow triggered"**（触发确认 ≠ 工作流内每步成功；该语义写入审计 detail，审计页原样展示） |
| TheHive：案件创建成功（或幂等命中已有案件） | `succeeded`，detail 携带案件 id |
| Wazuh：active response 命令被端点确认 | `succeeded` |
| 外部返回 202/已受理但**无终态确认** | ❌ 不得判 `succeeded` —— 适配器必须要么同步等到确认，要么落 `failed` + `adapter_error`（fail-closed） |
| 4xx/5xx / 业务拒绝 | `failed` + 对应分类 |

`ExecutionOutcome.detail` 投影规则（新）：
- 允许：分类词、外部引用 id（Shuffle execution id / Wazuh command id / TheHive case id）、外部消息的一句话投影；
- 禁止：凭证、会话头、完整外部响应体（`raw_response` 字段在 3.2 起**仅存在于内存与测试断言**，落 `execution_log.detail` 前必须经平台投影函数过滤——详见 §8 脱敏闸）。

## 8. 凭证边界（冻结 —— 3.2 安全核心）

**E3 配置模型（已裁决 ✅ 平铺环境变量，每适配器独立一对）**，沿用 3.1 AI provider 的 settings 血统，无新基建；**不引入 secrets manager / Vault / KMS**（那会把 3.2 扩大成凭证管理项目）：

```
SHUFFLE_BASE_URL / SHUFFLE_API_KEY
WAZUH_BASE_URL / WAZUH_API_KEY
THEHIVE_BASE_URL / THEHIVE_API_KEY
```

链路保持 `.env → Settings → Adapter`；延续 3.1 已冻结的 fail-closed / redact / no secret in logs 纪律。

五道防线：

1. **存储**：凭证仅存在于 `.env`（gitignore）→ `Settings`；**不入库、不进日志、不进响应、不进异常字符串**（延续 3.1 Token 纪律，逐字适用）。`.env.example` 只放空占位。
2. **Fail-closed 启动校验（新）**：`EXECUTION_ADAPTER` 选中真实适配器时，其必需凭证/URL 任一为空 → **启动期 `ExecutorConfigError`**，拒绝带半套凭证运行（与 mock 的"随时可用"形成显式对比）。
3. **传输**：凭证只出现在出站请求的 Authorization 头；不出现在 URL、请求体、日志行。
4. **脱敏闸（新，平台级）**：`execution_log.detail` 写入前经过统一 `redact()` 投影——任何命中凭证值、`Authorization`、`token`、`key`、`password` 语义的键值对被剥离。这是最后一道防线，即使某个适配器犯错，凭证也进不了审计库。
5. **测试断言（新）**：3.2 每个适配器的回归套件包含"凭证泄露五查"镜像（3.1.11 E2E 同款）：detail / 异常消息 / API 响应 / 日志捕获 / stub 服务器收到的请求体（除 Authorization 头）——五处全部不得出现凭证值。

## 9. 补偿边界与两大事故防护

**补偿边界（外部世界版）**：
- 补偿仍是新执行链（D5 不变）；外部补偿 = 反向动作的真实出站（如 Wazuh 解封）。
- 外部补偿是 **best-effort**：补偿失败落 `compensation_failed`，**不回滚、不修改原执行的任何行**（追加式铁律）。
- 不可逆动作（`disable_account`、TheHive 建案）默认 `supports_compensation() = False` → 补偿端点照旧 409 族拒绝。

**防"本地 succeeded、外部实际失败"**：
1. 只接受同步终态（§7），202 无确认 ≠ 成功；
2. `dispatched` 永远不是适配器产物（D8）；
3. 平台解析审判（D9）：适配器返回结构非法 → `failed + protocol_violation`，绝不伪成功；
4. Shuffle 语义显式钉死：`succeeded` = "工作流触发确认"，审计语义无歧义，不存在"以为跑完了"的误读。

**防重复执行**：3.1 的部分唯一索引（平台内）+ §5 外部幂等键（平台外）双保险；任何路径上"同一意图两次出站"都需要先突破 DB 约束。

## 10. 测试策略（无外部依赖的发布门）

延续 11.5 / 3.1.11 的分层经验：

| 层 | 方式 |
|---|---|
| 契约层 | 本地 stub 服务器（uvicorn/HTTP server fixture）模拟三系统 API；凭证泄露五查、失败分类映射、幂等命中翻译全部离线可测 |
| 回归层 | 默认套件保持零外网（`collect_ignore_glob` 不变）；外部适配器测试进默认套件（走 stub），不需要真实系统 |
| 真实层 | 可选 `external` marker（同 `ollama` / `browser` 血统）：环境变量指向真实测试实例才运行；无实例自动跳过，**不进 CI 门槛** |
| Browser E2E | 3.1.11 范式复用：stub 外部系统 + 真实后端/前端/Chromium，验证"执行 → 外部调用 → 审计展示"链 |

## 11. 实施拆分（用户钉死，10 步门槛制）

```
3.2.1 External Adapter Architecture（适配器基类扩展/配置/注册表解锁/启动校验）
3.2.2 Credential / Secret Boundary（fail-closed + 脱敏闸 + 泄露五查基建）
3.2.3 Shuffle Adapter（工作流触发 + "workflow triggered" 语义）
3.2.4 Wazuh Adapter（active response 封禁/隔离 + 反向补偿）
3.2.5 TheHive Adapter（建案 + 幂等命中）
3.2.6 External Failure / Idempotency（失败分类映射 + 外部幂等键回归）
3.2.7 Cross-system Regression（stub 三系统全链回归）
3.2.8 Browser E2E（stub 外部 + 真实浏览器）
3.2.9 Final Regression（3.1.12 矩阵全量复刻）
3.2.10 Release（原子提交 + 版本决策点）
```

节奏铁律继承：一步完成 → 测试 → 回报 → 用户验收 → 才进下一步；每步一个原子提交；**不修改 `657cb87`、不动 v1.1.0**。

## 12. 版本边界（用户裁决 2026-08-28）

```
v1.1.0 ── 0f6e3fc ── Phase 2（冻结，不动）
657cb87 ──────────── Phase 3.1 受控执行核心（已推送，不重写）
3.2.x   ──────────── 每步新原子提交，叠加在 657cb87 之上
```

- **现在不给 657cb87 打 v1.2.0**；
- Phase 3.2 真实接入三系统并通过跨系统测试（3.2.9/3.2.10）后，统一决定 v1.2.0 是否代表整个 Phase 3（3.1 + 3.2）。

## 13. 裁决记录（2026-08-28 冻结，无剩余开放点）

| # | 开放点 | 最终裁决 | 理由 |
|---|---|---|---|
| E1 | `escalate_to_incident` 升级为机器可执行（TheHive 建案） | ✅ **采纳** | 不新增 action 词汇，直接利用六词表中唯一与 TheHive 职责对应的动作；必须走完整 Approval → Execute → Guard → Executor 链（§4 边界钉死）；是 capability policy 显式扩展，非历史数据重写，零迁移 |
| E2 | 新增 `trigger_workflow` 词表词汇 | ❌ **本阶段不采纳** | 会把真实扇出伪装成普通 response action，破坏 Single-Active-Adapter / No internal fan-out；未来如需级联动，单独设计更高层 orchestration capability |
| E3 | 凭证配置形态 | ✅ **采纳平铺环境变量** | 每适配器一对 `*_BASE_URL` / `*_API_KEY`；延续 Provider 配置习惯，简单、可审计、易部署；不引入 secrets 管理基建 |
| E4 | Shuffle `succeeded` 语义 | ✅ **采纳并钉死** | `succeeded` = “SentinelFlow 已确认工作流触发成功”，**不是**工作流内部全部完成；工作流内部结果留给 Shuffle 自身执行历史；D10 同步模型下不发明轮询机制（§7） |
| E5 | 零自动重试 | ✅ **采纳并钉死** | 避免外部副作用因网络重试被放大；失败后唯一路径：人工 → 新 `execution_id` → 再次执行（§6） |
