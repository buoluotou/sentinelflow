# SentinelFlow

**SentinelFlow 是一个面向安全运营场景的智能告警编排、风险分析与事件响应平台。**

[English](README.md) | 简体中文

## 项目简介

SentinelFlow 帮助 SOC（安全运营中心）分析人员高效地接收、处理与响应安全告警。平台提供告警接入（Ingestion）、标准化（Normalization）、去重聚合（Deduplication / Aggregation）与事件关联（Incident Correlation）能力，并规划引入 AI 辅助分析与自动化响应。

## 架构概览

```
Scenario Simulator  →  SentinelFlow Backend (FastAPI)  →  PostgreSQL  →  React Web Console
```

数据链路：

```
Raw Event → Normalized Alert → Deduplicated Alert → Incident
```

上游平台（Wazuh / Shuffle / TheHive / Ollama）通过预留的 Adapter 接口接入，Phase 1 不做直接耦合。

## Phase 1 核心能力

- Alert Ingestion：HTTP/JSON 统一告警接入，保留原始事件（Raw Event）
- Normalization：不同来源事件统一为 SentinelFlow 格式
- Deduplication / Aggregation：同 IP + 主机 + 事件类型 + 时间窗口聚合为一个 Alert
- Alert → Incident：基础事件数据模型
- React Web Console：Dashboard / Alerts / Incidents

## 开发路线

| Step | 内容 | 状态 |
| ---- | ---- | ---- |
| Step 1 | 工程骨架 | ✅ |
| Step 2 | 数据模型 + Alert Ingestion | ✅ |
| Step 3 | Alert Normalization | ✅ |
| Step 4 | Deduplication / Aggregation | ⬜ |
| Step 5 | Scenario Simulator Runner | ⬜ |
| Step 6 | Incident Management | ⬜ |
| Step 7 | React Web Console | ⬜ |

## 快速开始

### 环境要求

- Python 3.11+
- Node.js 20+
- Docker Desktop（用于 PostgreSQL 16）

### 启动步骤

```powershell
# 1. 准备环境变量
Copy-Item .env.example .env   # 修改其中的数据库密码

# 2. 启动 PostgreSQL
docker compose up -d postgres

# 3. 后端
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements/dev.txt
alembic upgrade head
uvicorn app.main:app --reload

# 4. 前端（新开一个终端）
cd frontend
npm install
npm run dev
```

验证：

- 后端健康检查：`http://127.0.0.1:8000/health`
- 交互式 API 文档：`http://127.0.0.1:8000/docs`
- 前端控制台：`http://127.0.0.1:5173`

## 项目结构

```
sentinelflow/
├── backend/          # FastAPI 后端（API / Schema / Service / ORM / Alembic）
├── frontend/         # React + TypeScript + Vite 控制台
├── simulator/        # 安全场景模拟器（5 个示例场景）
├── integrations/     # 外部平台 Adapter 预留（Wazuh / Shuffle / TheHive / AI）
├── infrastructure/   # Docker、脚本
├── docs/             # 文档
└── tests/            # 集成与端到端测试
```

## 许可证

MIT License，详见 [LICENSE](LICENSE)。
