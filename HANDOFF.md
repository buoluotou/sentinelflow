# SentinelFlow 工作交接文档（AI Agent 接手用）

> 最后更新：2026-08-25 · Phase 1 Step 6 完成后（Scenario Simulator Runner 6.1）
> 给新会话的 Agent：请先完整读完本文档，再读 `Phase 1 最终闭环.md`（位于 `D:\edge\github\`，是项目的总规划），然后跑一遍"快速自检"确认基线，再开始新任务。

## 一、项目是什么

SentinelFlow 是一个面向 SOC 的安全告警编排平台，规划数据链路：

```
Raw Event → Normalization → Deduplication/Aggregation → Incident
Simulator/Wazuh → FastAPI Backend → PostgreSQL → React Console
```

上游项目（同工作区 `D:\edge\github\` 下）：Wazuh、Shuffle、TheHive、Ollama —— **只做接口预留，不提前耦合**，这是硬原则。

## 二、当前进度

| Step | 内容 | 状态 | 提交 |
|---|---|---|---|
| 1 | 工程骨架（monorepo） | ✅ | `2e94813` |
| 2 | 数据模型 + Alert Ingestion | ✅ | `2e94813` |
| 3 | Alert Normalization | ✅ | `868c02b` |
| 4 | Deduplication / Aggregation + Events API | ✅ | `533616f` `8bd8b91` `2fb947d` `9537096` `4c7235e` |
| 5 | Risk Engine（可解释风险评分）+ Risk API | ✅ 5.1–5.4 | `81b36f7` `3c1f539` `959fc4a` `ff4aa70` |
| 6 | Scenario Simulator Runner | ✅ 6.1 CLI | 待提交 |
| 7 | Incident Management | ⬜ |
| 8 | React Web Console | ⬜ |

## 三、关键代码地图（都在 `sentinelflow/`）

```
backend/app/
├── main.py                     # FastAPI 入口，/health 含数据库连通性检查
├── api/v1/
│   ├── alerts.py               # POST/GET /api/v1/alerts（Step 2；Step 4.4 起走统一去重链路）
│   ├── normalize.py            # POST /api/v1/normalize（Step 3；响应含 group_id/group_alert_count/created_group）
│   └── events.py               # GET /api/v1/events 列表 + /{id} 详情（Step 4.4）；Step 5.4 起列表项带 risk_score/risk_level，详情带 risk 因子明细，支持 ?level= 筛选（Literal 校验，非法值 422）
├── core/
│   ├── config.py               # pydantic-settings，.env 从 monorepo 根读取；DEDUP_WINDOW_SECONDS=300
│   └── database.py             # engine / SessionLocal / Base / get_db
├── models/
│   ├── alert.py                # alerts 表：含 alert_group_id（nullable FK → alert_groups）+ alert_group 关系
│   ├── alert_event.py          # alert_events 表：raw_data 为 JSONB（with_variant 兼容 SQLite）
│   ├── alert_group.py          # alert_groups 表：fingerprint 只建索引【不建 unique】（窗口过期后同指纹要能建新组）；含 1:1 risk 关系
│   └── event_risk.py           # event_risk 表（Step 5.1）：alert_group_id 唯一约束（每事件一份当前风险快照），score/level/factors(JSONB)/updated_at
├── schemas/
│   ├── alert.py                # AlertCreate/AlertRead/AlertDetail，AlertRead 含 alert_group_id
│   └── event.py                # EventListItem/EventListResponse/EventInfo/EventAlertItem/EventDetailResponse；Step 5.4 新增 RiskFactorItem/EventRiskDetail，EventListItem 加 risk_score/risk_level（无风险记录时为 None）
└── services/
    ├── ingestion/service.py    # ingest_alert(db, payload) —— 唯一落库入口；Step 4.4 起内部走 Normalized→Dedup
    ├── normalization/          # Step 3 核心
    │   ├── models.py           # NormalizedAlert 统一事件模型（AssetInfo/ActorInfo/Category/Observable）
    │   ├── base.py             # BaseAdapter 契约 + 异常体系
    │   ├── normalizer.py       # NormalizationEngine（注册表 + to_alert_create）
    │   └── adapters/
    │       ├── simulator.py    # 已实现：5 场景映射（EVENT_TYPE_MAP 是共享分类表）+ observables 提取
    │       └── wazuh.py        # 空接口，抛 NotImplementedError → API 返回 501
    ├── deduplication/          # Step 4 核心
    │   ├── fingerprint.py      # FingerprintGenerator：SHA256(source+category+title+asset+actor)，sort_keys 保序
    │   ├── rules.py            # AggregationRule + DEFAULT_WINDOW_SECONDS（来自 DEDUP_WINDOW_SECONDS）
    │   ├── engine.py           # DeduplicationEngine.process(db, normalized, alert_create)：查窗口内组→合并/新建→存证据→【commit 前调 risk_service.recalculate】→commit
    │   └── models.py           # DeduplicationResult(group, alert, created_group)
    ├── risk/                   # Step 5 核心（5.1–5.3）
    │   ├── rules.py            # 冻结规则 v1.0：severity 基础分 10/30/50/70；频率分段 +0/10/20/30/40；公网 +20（每事件一次）；封顶 100；等级 0-30 low / 31-70 medium / 71-90 high / 91-100 critical
    │   ├── factors.py          # severity/frequency/public_source 三因子；is_public_ip 用显式排除清单（不用 is_global，Python 3.12.2 多播/TEST-NET/CGNAT 有盲区）
    │   ├── engine.py           # RiskEngine.calculate(group, alerts) -> RiskResult，纯计算不落库；factors = [{name, score, reason}]
    │   └── service.py          # RiskService.recalculate(db, group)：有则原地更新、无则创建 EventRisk
    └── events/service.py       # list_events(db, page, size, level=None) / get_event(db, group_id)；Step 5.4 起 selectinload risk（列表 1 次子查询），?level= 时 JOIN event_risk（无风险记录的事件被排除）
```

关键语义（Step 4 定形）：**fingerprint ≠ group**。fingerprint 标识"事件种类"（跨时间稳定，不含时间戳/原文），AlertGroup 是 fingerprint + 5 分钟窗口切出的"一次事件"；同一指纹可对应多个组。两个入口（/alerts 与 /normalize）统一走 Normalization → Deduplication → DB；每条 Alert 全量保留为证据，`alert_events` 存原始报文。

其他：`frontend/`（React 19 + TS + Vite，页面目录占位在 `src/pages/`）、`simulator/scenarios/*/events.json`（5 个场景，信封 `{scenario, description, events}`，事件已是 AlertCreate 统一格式）、`simulator/runner/run.py`（Step 6.1：纯标准库 CLI，扫描→本地校验→直发 POST /alerts→实时打印→GET /events 摘要→失败非零退出；不走 /normalize 避免 source 指纹分裂；默认 `--timestamps now` 改写当前 UTC，`file` 为确定性重放）、`docker-compose.yml`（仅 PostgreSQL 16）。

Step 5 定形语义：**风险只在事件变化时重算**（去重引擎 `db.add(alert)` 后、`commit()` 前，与告警落库同一事务），GET /events 是纯读路径，不做任何评分计算；`event_risk` 每事件唯一一行（唯一约束），重算原地更新 `score/level/factors/updated_at`。

## 四、环境事实（重要，影响所有验证方式）

- Windows + PowerShell；Git 2.54 / Python 3.12 / Node 24 可用
- **本机没有 Docker** → PostgreSQL 起不来。所有测试与冒烟验证都用 **SQLite** 替代：
  - 单元测试：`tests/conftest.py` 用 `sqlite://` 内存库 + `dependency_overrides`
  - 冒烟/迁移验证：`$env:DATABASE_URL="sqlite:///xxx.db"` 后跑 `alembic upgrade head` + uvicorn，用完删除
- 后端虚拟环境：`backend\.venv`，依赖已装全（含 pytest/httpx）

## 五、常用命令（均在 `sentinelflow\backend`）

```powershell
.\.venv\Scripts\python.exe -m pytest -q                    # 单元测试（当前 127 passed）
$env:DATABASE_URL="sqlite:///tmp.db"
.\.venv\Scripts\python.exe -m alembic upgrade head         # 迁移
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8765   # 起服务
Remove-Item Env:DATABASE_URL                                # 用完清环境变量
cd ..\.. ; python simulator/runner/run.py --repeat 30      # 一键演示全链路（需后端在 8000 端口）
# 前端（sentinelflow\frontend）：npm run build / npm run dev
```

## 六、必须遵守的约定与踩过的坑

1. **分层不可破坏**：API 只管 HTTP，业务在 `services/`，ORM 在 `models/`。新服务建独立子目录。
2. **数据库变更必须走 Alembic** 迁移（`backend/migrations/versions/`），禁止 `create_all` 乱建表。迁移里时间默认值用 `sa.text("CURRENT_TIMESTAMP")`，**不要用 `func.now()`**（SQLite 不识别，Step 2 踩过）。
3. JSON 字段用 `JSON().with_variant(JSONB(), "postgresql")`，保证 SQLite 测试与 PG 生产双兼容。
4. 密码/密钥只进 `.env`（已 git-ignore），`.env.example` 是模板。
5. Commit 规范：Conventional Commits，如 `feat(backend): ...`；**用户明确要求时才提交**。
6. 新增数据源：实现 `BaseAdapter` 并注册进 `NormalizationEngine`，不改动引擎本身。
7. **ORM relationship 赋值必须赋对象**（如 `alert_group=group`），不能赋 flush 前尚为 None 的 `group.id`——此坑已犯过两次，测试 helper 尤其注意。
8. 冒烟用临时 SQLite 库时：**先停服务进程再删库**，否则文件锁定导致删除静默失败、出现"库被重建"假象；用完 `Remove-Item Env:DATABASE_URL`（shell 复用会残留，pydantic-settings 会优先读它）。
9. Python 3.12.2 的 `ipaddress`：多播地址 `is_global=True`、TEST-NET `is_private=True`、CGNAT `is_private=False`——判定公网 IP 必须用显式排除清单（见 `risk/factors.py`），不要只信 `is_global`/`is_private`。
10. 本机存在拦截 localhost 流量的代理（urllib 直连会被 502）——Runner 用 `ProxyHandler({})` 绕过；写任何直连本地服务的脚本同理。
11. 场景数据的 `203.0.113.50` / `198.51.100.77` 是文档保留段，按排除清单判非公网，不会触发 +20 公网加成——冒烟期望值按此设定（如 --repeat 30：ssh 50/medium、malicious_ioc 90/high、file_integrity/suspicious_process 70/medium 边界）。

## 七、下一步任务：Step 6 已完成，候选方向（以用户指令为准）

Step 6.1 落地：`simulator/runner/run.py`（纯标准库，无第三方依赖）。
链路：扫描场景 → 本地校验（快速失败）→ 直发 `POST /api/v1/alerts` →
实时打印 → `GET /api/v1/events` 摘要（alert_count / risk_score / risk_level）→
失败非零退出。冻结验收已通过：`--repeat 30 --timestamps now` →
5 组 × 30 alerts，风险分全部命中（见六-11）。测试 127 passed。
提交建议：`feat(simulator): add scenario runner cli (Step 6)`（待用户确认后提交）。

候选方向：Step 7 Incident Management 或 Step 8 React Web Console（以用户指令为准）。

## 八、快速自检清单（新会话开工前执行）

```powershell
cd d:\edge\github\sentinelflow
git status            # 应为 clean（HANDOFF.md 未跟踪属正常）
git log --oneline     # 应见最新 5.4（ff4aa70）与 959fc4a / 3c1f539 / 81b36f7 / 4c7235e / 9537096 / 2fb947d / 8bd8b91 / 533616f / 868c02b / 2e94813
cd backend
.\.venv\Scripts\python.exe -m pytest -q   # 应为 127 passed
```

任一项不符，先向用户报告差异，再动手。
