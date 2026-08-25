# SentinelFlow

**面向 SOC 团队的开源安全告警编排与事件响应平台。**

SentinelFlow 将原始安全告警转化为去重、带风险评分的事件与可管理的案件，并提供为快速分诊而生的 Web 控制台。Phase 1 交付一条完整可演示的"检测→案件"流水线；AI 辅助分析是下一个里程碑（见[路线图](#路线图)）。

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
   React Web 控制台          Dashboard / Events / Incident Queue
```

## 特性（Phase 1 — v1.0.0-phase1）

- **告警接入** — HTTP/JSON API；每条告警全量保留为证据
- **归一化** — 适配器模式统一事件模型（Simulator 适配器已实现，Wazuh 适配器已预留）
- **去重与聚合** — SHA-256 指纹 + 5 分钟窗口；150 条重复告警收敛为 1 个事件 + 150 条证据
- **可解释风险引擎** — 严重度 / 频率 / 公网来源三因子，0–100 评分，四级风险；因子明细逐事件落库
- **案件管理** — 风险 ≥ 70 自动建案（幂等），严格生命周期状态机（`open → in_progress → resolved → closed`）
- **Dashboard API** — 控制台首页单一聚合端点
- **React Web 控制台** — 深色 SOC 主题；Dashboard、Events（筛选/分页/风险因子/证据）、Incident Queue（状态流转）
- **场景模拟器** — 5 个攻击场景，一条命令重放，用于演示与测试

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

重放 5 个攻击场景 × 30 轮（150 条告警），产生 5 个聚合事件、风险评分与 3 个自动案件。打开控制台即可看到 Dashboard 数据点亮。详见 [docs/demo.md](docs/demo.md)。

## 文档

- [架构](docs/architecture.md) — 数据模型、流水线、风险规则、状态机
- [API 参考](docs/api.md) — 全部 REST 端点
- [演示指南](docs/demo.md) — 端到端演示步骤与预期输出
- [部署](docs/deployment.md) — Docker、迁移、安全加固清单
- 交互式文档：启动后端后访问 `http://localhost:8000/docs`（OpenAPI/Swagger）

## 测试

```bash
cd backend
python -m pytest -q        # 202 个测试
```

## 路线图

| 版本 | 里程碑 |
|---|---|
| **v1.0.0-phase1** | 核心 SOC 平台：接入 → 归一化 → 去重 → 风险 → 案件 → 控制台（本版本） |
| v1.1.x | AI 安全分析：告警解释、风险摘要、处置建议，全部置于人工审批队列之后（统一接口对接 Ollama / 云端模型） |
| v2.0 | 自动化响应 / SOAR 集成 |

**Wazuh**、**Shuffle**、**TheHive** 等上游项目仅作为干净的适配器接口目标规划集成 —— 其源码永远不会被引入本仓库。

## 项目结构

```
sentinelflow/
├── backend/          # FastAPI 后端（services/、models/、api/、Alembic 迁移）
├── frontend/         # React 19 + TypeScript + Vite 控制台
├── simulator/        # 攻击场景 + 标准库 Runner CLI
├── integrations/     # 预留：外部平台适配器
├── infrastructure/   # 预留：部署资产
├── docs/             # 文档
└── tests/            # 预留：集成与 E2E 测试
```

## 安全说明

Phase 1 **不含认证机制**，仅建议在受信任网络中评估使用。漏洞报告政策见 [SECURITY.md](SECURITY.md)；任何对外暴露部署前请先完成[部署安全加固清单](docs/deployment.md#security-hardening-checklist)。

## 许可证

MIT License，见 [LICENSE](LICENSE)。
