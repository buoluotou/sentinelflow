# SentinelFlow

**面向 SOC 团队的开源安全告警编排与事件响应平台。**

SentinelFlow 将原始安全告警转化为去重、带风险评分的事件与可管理的案件，并提供为快速分诊而生的 Web 控制台。Phase 1 交付一条完整的“检测→案件”流水线；Phase 2（v1.1.0）在其上叠加 AI 辅助分析 —— 告警解释、风险摘要与处置建议 —— 全部置于人工审批队列之后，并在每个案件上提供只读的 AI 调查视图。Phase 3（v1.2.0）在同一审批链之后增加受控响应执行与外部适配器支持（Shuffle / Wazuh / TheHive）。Phase 3.3（v1.3.0）闭合治理三角：操作者身份与 RBAC、执行策略引擎、只读执行度量 / 观测适配器健康。AI 输出仅为建议：**Approve ≠ Execute**（见[路线图](#路线图)）。

```
Simulator / SIEM 适配器
        ↓
   归一化（Normalization）   适配器模式 + 统一事件模型
        ↓
   去重聚合（Deduplication） 指纹 + 时间窗口聚合
        ↓
   风险引擎（Risk Engine）   可解释的规则评分
        ↓
   案件管理（Incident）      自动建案策略 + 生命周期状态机
        ↓
   AI 分析                 解释 / 风险摘要 / 处置建议 —— 仅为建议
        ↓
   人工审批队列（Approval） 记录人类决定；执行不在范围内
        ↓
   响应执行器（Executor）   Guard / Policy → 适配器 → Shuffle / Wazuh / TheHive
        ↓
   执行审计（Audit）        追加式审计轨迹
        ↓
   治理与可观测（Governance & Observability） Operator/RBAC → Policy → Metrics / Observed Health
        ↓
   React Web 控制台          Dashboard / Events / Incidents / Approvals / Execute Console / Audit / Observability
```

## 特性（v1.3.0）

### Phase 1 — 检测到案件

- **告警接入** — HTTP/JSON API；每条告警全量保留为证据
- **归一化** — 适配器模式统一事件模型（Simulator 适配器已实现，Wazuh 适配器已预留）
- **去重与聚合** — SHA-256 指纹 + 5 分钟窗口；150 条重复告警收敛为 1 个事件 + 150 条证据
- **可解释风险引擎** — 严重度 / 频率 / 公网来源三因子，0–100 评分，四级风险；因子明细逐事件落库
- **案件管理** — 风险 ≥ 70 自动建案（幂等），严格生命周期状态机（`open → in_progress → resolved → closed`）
- **Dashboard API** — 控制台首页单一聚合端点
- **React Web 控制台** — 深色 SOC 主题；Dashboard、Events（筛选/分页/风险因子/证据）、Incident Queue（状态流转）
- **场景模拟器** — 5 个攻击场景，一条命令重放，用于演示与测试

### Phase 2 — 人工审批之后的 AI 辅助分析

- **AI Provider 架构** — 统一 `AIProvider` 契约：Mock（默认，离线安全）、Ollama 与 OpenAI 兼容云端；冻结的结构化输出协议与类型化错误契约（404 / 503 / 502），经 `.env` 切换不改业务代码
- **AI 告警解释** — 显式触发的攻击类型分析，含风险成因与置信度；事件详情页追加式历史（append-only）
- **AI 风险摘要** — 关键发现、冻结的风险因子词表与分析师优先级；AI 绝不输出风险分（`EventRisk.score` 是唯一正式分）
- **AI 处置建议** — 最多 5 条建议，取自冻结的六动作词表；空列表是一等答案（“无需处置”）
- **审批队列（Approval Queue）** — 针对建议的一次性人工批准/驳回决定；“待审”是派生状态绝不落库；批准只记录决定，绝不执行任何动作
- **案件 AI 调查视图** — 案件详情页只读面板，单一 GET 聚合事件全部 AI 历史 + 审批审计；零按钮、零变更流量

### Phase 3 — 受控响应执行与外部适配器

- **执行核心（Phase 3.1）** — 追加式 `execution_log`（migration 0009）；八词词表；Guard 五种拒绝码覆盖 `EXECUTABLE_ACTIONS`；确定性零出站 `MockExecutor`（默认）；同步 Execute / Compensation 服务；API `POST /api/v1/executions` + `.../compensate` + 只读端点；Bearer `EXECUTION_TOKEN` 仅保护写入端点；React Execute Console 与 Execution Audit UI
- **外部适配器架构（Phase 3.2）** — Shuffle / Wazuh / TheHive 从预留槽毕业为已实现适配器，共用统一 `ResponseExecutor` 契约；fail-closed 启动验证；Single-Active-Adapter 不变式；密钥隔离（凭据永不落审计记录）；URL 形状闸；日志脱敏过滤器
- **Shuffle 工作流适配器** — 工作流编排：每个可执行动作恰好触发一个预配置工作流；可选反向工作流闸补偿能力；`succeeded = 触发确认`；零自动重试
- **Wazuh 端点响应适配器** — 端点 / 安全响应：`isolate_host` / `disable_account` / `block_source_ip` 经 active-response API；Basic 认证（`WAZUH_API_USER` / `WAZUH_API_PASSWORD`）；端点允许时对称补偿
- **TheHive 案件适配器** — 仅建案：`escalate_to_incident` 向 `POST /api/case` 提交冻结六字段报文；409 重复解析为 `succeeded + idempotent_duplicate`；零补偿 —— 案件生命周期属于调查
- **安全边界** —— 无自动审批、无自动重试、无适配器内部扇出、无隐藏执行。适配器实现已存在，但默认配置保持离线（`EXECUTION_ADAPTER=mock`）；真实 Shuffle / Wazuh / TheHive 连接需要显式 `.env` 配置与凭据

### Phase 3.3 — 执行之上的治理与可观测性

- **操作者身份与 RBAC（Phase 3.3.1）** — 静态操作者注册表（名称 + token + 角色：viewer / reviewer / executor / admin）；Bearer token 是唯一服务端身份源（客户端 `operator` 字段被忽略 —— 无法伪造身份）；仅 executor / admin 可派发；空配置保持 fail-closed（401）
- **执行策略（Phase 3.3.2）** — Guard 与 Executor 之间的只读决策引擎（`EXECUTION_POLICY_*` 配置，默认关闭）：UTC 时间窗 + 逐动作最低风险阈值（消费服务端 `EventRisk.score`）；策略拒绝落 `guard_rejected` 且 `detail.source="policy"`；配置损坏 = 静态 503 + 回滚 —— 绝不静默放行
- **执行度量（Phase 3.3.3）** — 只读 `GET /api/v1/executions/metrics`，从 `execution_log` 派生（免凭据、零写入）：总量 / 成功 / 失败 / 治理拒绝 / 在飞链数，`success_rate` 分母永不含治理拒绝，拒绝来源与延迟；空分母呈现 N/A，绝不 0%
- **观测适配器健康（Phase 3.3.3）** — 只读 `GET /api/v1/executions/health`：逐适配器状态取自冻结词表 `unknown / healthy / degraded / failing`，窗口 = 最近 20 条终局链。**观测 ≠ 探测**：状态仅从已记录的执行事实派生 —— 无实时健康探测、无出站请求
- **执行可观测性 UI** — 只读 `/observability` 控制台页：度量卡片 + 逐适配器健康卡片；零按钮、零写入流量，字段级镜像两个 GET 响应，无自动刷新

## 快速开始

### 前置条件

- Python 3.12+
- Node.js 20+
- Docker（用于 PostgreSQL）；或直接使用 SQLite 零依赖体验

### 1. 后端

```bash
cd backend
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# Linux/macOS:        source .venv/bin/activate
pip install -r requirements/base.txt

# 方案 A — PostgreSQL（贴近生产）
cp ../.env.example ../.env          # 然后修改凭据
docker compose up -d postgres       # 在仓库根目录执行
python -m alembic upgrade head

# 方案 B — SQLite（无需 Docker，适合首次体验）
# Windows PowerShell: $env:DATABASE_URL="sqlite:///sentinelflow.db"
# Linux/macOS:        export DATABASE_URL="sqlite:///sentinelflow.db"
python -m alembic upgrade head

python -m uvicorn app.main:app --port 8000
```

### 2. 前端

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173（/api 代理到 :8000）
```

### 3. 演示：制造一场真实的告警风暴

```bash
python simulator/runner/run.py --repeat 30
```

重放 5 个攻击场景 × 30 轮（150 条告警），产生 5 个聚合事件、风险评分与 3 个自动案件。打开控制台即可看到 Dashboard 数据点亮 —— 随后按 [docs/demo.md](docs/demo.md) 走完 AI 分析链、审批队列与案件 AI 视图。

## 文档

- [架构](docs/architecture.md) — 数据模型、流水线、风险规则、状态机
- [API 参考](docs/api.md) — 全部 REST 端点
- [演示指南](docs/demo.md) — 端到端演示步骤与预期输出
- [部署](docs/deployment.md) — Docker、迁移、安全加固清单
- 交互式文档：启动后端后访问 `http://localhost:8000/docs`（OpenAPI/Swagger）

## 测试

```bash
cd backend
python -m pytest -q        # 1353 个测试（默认套件；真实模型 E2E 与外部适配器测试不在默认收集内）
```

## 路线图

| 版本 | 里程碑 |
|---|---|
| v1.0.0-phase1 | 核心 SOC 平台：接入 → 归一化 → 去重 → 风险 → 案件 → 控制台 |
| v1.1.0 | AI 安全分析：告警解释、风险摘要、处置建议，全部置于人工审批队列之后，外加案件 AI 调查视图 |
| v1.2.0 | 受控响应执行：Guard → 外部适配器（Shuffle / Wazuh / TheHive）→ 追加式审计 |
| **v1.3.0** | 治理与可观测性：操作者身份 / RBAC、执行策略引擎、执行度量 + 观测适配器健康、只读 Observability 控制台 —— 本版本 |
| v2.0 | 执行成熟度：外部结果对账、webhook / 回调、长时执行跟踪 |

**Shuffle**、**Wazuh**、**TheHive** 已作为外部响应适配器实现（Phase 3.2）—— 适配器代码在本仓库内，但其源码永远不会被引入。默认配置保持离线（`EXECUTION_ADAPTER=mock`）；真实连接需要显式 `.env` 配置。

## 项目结构

```
sentinelflow/
├── backend/          # FastAPI 后端（services/、models/、api/、Alembic 迁移）
├── frontend/         # React 19 + TypeScript + Vite 控制台
├── simulator/        # 攻击场景 + 标准库 Runner CLI
├── integrations/     # 外部平台适配器接口（Shuffle / Wazuh / TheHive）
├── infrastructure/   # 预留：部署资产
├── docs/             # 文档
└── tests/            # 预留：集成与 E2E 测试
```

## 安全说明

平台**不含认证机制**，仅建议在受信任网络中评估使用。漏洞报告政策见 [SECURITY.md](SECURITY.md)；任何对外暴露部署前请先完成[部署安全加固清单](docs/deployment.md#security-hardening-checklist)。

## 许可证

MIT License，见 [LICENSE](LICENSE)。
