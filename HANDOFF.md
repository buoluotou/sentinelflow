# SentinelFlow 工作交接文档（AI Agent 接手用）

> 最后更新：2026-08-26 · Phase 1 已冻结并**已发布到 GitHub**（buoluotou/sentinelflow，tag v1.0.0-phase1 + Release）；Step 9（`f7edcc1`）与 Step 10（`c946ae7 feat(ai): add alert explanation`）均已提交并推送；**Step 11 AI Risk Summary 全部完成（11.1–11.8：协议+Provider+ORM+迁移+Builder+Service+API+Mock/协议回归+真实 Ollama E2E+前端面板+Browser E2E 双链+最终回归）**，一次性提交 `feat(ai): add risk summary`（hash 见 `git log -1`，未推送）；不打新 tag，v1.1.0 等 Step 12–14 全部完成后统一发布
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
| 6 | Scenario Simulator Runner | ✅ 6.1 CLI | `abdb469` |
| 7 | Incident Management | ✅ 7.1–7.5（模型/Service/API/自动创建/Dashboard） | `1e98fab` `57bd981` `0f1b31d` `3c58681` `09049d1` |
| 8 | React Web Console | ✅ 8.1–8.5（API Client/Dashboard/Events/Incidents/E2E） | `4a7f5d5` |
| — | Release Hardening（README×2/architecture/api/demo/deployment/CHANGELOG/安全与 Secrets 检查/tag） | ✅ | 随 tag `v1.0.0-phase1` |
| 9 | AI Provider Architecture（统一接口/配置/错误/结构化协议/Mock） | ✅ | `f7edcc1`（已推送 GitHub） |
| 10 | AI Alert Explanation | ✅ 10.1–10.8 全部完成（后端全链路 + 前端面板 + 真实/Mock 双 E2E） | `c946ae7`（已推送） |
| 11 | AI Risk Summary | ✅ 11.1–11.8 全部完成（后端全链路+前端面板+Browser E2E 双链+最终回归），一次性原子提交 | `feat(ai): add risk summary`（见 `git log -1`） |

## 三、关键代码地图（都在 `sentinelflow/`）

```
backend/app/
├── main.py                     # FastAPI 入口，/health 含数据库连通性检查
├── api/v1/
│   ├── alerts.py               # POST/GET /api/v1/alerts（Step 2；Step 4.4 起走统一去重链路）
│   ├── normalize.py            # POST /api/v1/normalize（Step 3；响应含 group_id/group_alert_count/created_group）
│   ├── events.py               # GET /api/v1/events 列表 + /{id} 详情（Step 4.4）；Step 5.4 起列表项带 risk_score/risk_level，详情带 risk 因子明细，支持 ?level= 筛选（Literal 校验，非法值 422）
│   ├── incidents.py            # Step 7.3：POST /incidents（201，案件记录自动填充）/ GET 列表（分页 + ?status=，非法值 422）/ GET /{id} / PATCH /{id}/status（显式动作路由，非法转换 409，文案固定）；业务异常→404/409 映射，状态机零复制
│   └── dashboard.py            # Step 7.5：GET /dashboard/summary —— 纯读实时聚合快照，前端绑定单端点不自行拼 API
├── core/
│   ├── config.py               # pydantic-settings，.env 从 monorepo 根读取；DEDUP_WINDOW_SECONDS=300
│   └── database.py             # engine / SessionLocal / Base / get_db
├── models/
│   ├── alert.py                # alerts 表：含 alert_group_id（nullable FK → alert_groups）+ alert_group 关系
│   ├── alert_event.py          # alert_events 表：raw_data 为 JSONB（with_variant 兼容 SQLite）
│   ├── alert_group.py          # alert_groups 表：fingerprint 只建索引【不建 unique】（窗口过期后同指纹要能建新组）；含 1:1 risk 关系
│   ├── event_risk.py           # event_risk 表（Step 5.1）：alert_group_id 唯一约束（每事件一份当前风险快照），score/level/factors(JSONB)/updated_at
│   └── incident.py             # incidents 表（Step 7.1）：alert_group_id 唯一（每事件一个当前案件），title/description/severity/risk_score（创建时从 EventRisk 快照）/status/disposition/resolved_at/closed_at；状态机在 Step 7.2 的 Service 层
├── schemas/
│   ├── alert.py                # AlertCreate/AlertRead/AlertDetail，AlertRead 含 alert_group_id
│   ├── event.py                # EventListItem/EventListResponse/EventInfo/EventAlertItem/EventDetailResponse；Step 5.4 新增 RiskFactorItem/EventRiskDetail，EventListItem 加 risk_score/risk_level（无风险记录时为 None）
│   ├── incident.py             # IncidentCreate（仅 alert_group_id）/IncidentStatusUpdate（status 为 str，由服务层状态机判合法性）/IncidentRead（含全部生命周期字段）/IncidentListResponse
│   └── dashboard.py            # RiskDistribution（critical/high/medium/low）+ DashboardSummary（7 项指标 + 分布）
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
    │   ├── engine.py           # DeduplicationEngine.process(db, normalized, alert_create)：查窗口内组→合并/新建→存证据→【commit 前调 risk_service.recalculate，再调 auto_create_from_risk（Step 7.4，同事务）】→commit
    │   └── models.py           # DeduplicationResult(group, alert, created_group)
    ├── risk/                   # Step 5 核心（5.1–5.3）
    │   ├── rules.py            # 冻结规则 v1.0：severity 基础分 10/30/50/70；频率分段 +0/10/20/30/40；公网 +20（每事件一次）；封顶 100；等级 0-30 low / 31-70 medium / 71-90 high / 91-100 critical
    │   ├── factors.py          # severity/frequency/public_source 三因子；is_public_ip 用显式排除清单（不用 is_global，Python 3.12.2 多播/TEST-NET/CGNAT 有盲区）
    │   ├── engine.py           # RiskEngine.calculate(group, alerts) -> RiskResult，纯计算不落库；factors = [{name, score, reason}]
    │   └── service.py          # RiskService.recalculate(db, group)：有则原地更新、无则创建 EventRisk
    ├── incidents/              # Step 7 核心（7.2–7.4）
    │   ├── models.py           # IncidentStatus/IncidentDisposition 枚举 + ALLOWED_TRANSITIONS 冻结矩阵 + 4 个业务异常（全部报错不静默）；InvalidIncidentTransition 携带 current/target 供 API 渲染稳定文案
    │   ├── policy.py           # Step 7.4 创建策略 v1.0：AUTO_CREATE_THRESHOLD=70，should_create_incident(score)。按 score 不按 severity（Risk Engine 是唯一权重源）；只在写路径评估，不回填存量事件
    │   └── service.py          # create_incident(db, alert_group_id)：自动填 title/severity/description，risk_score 快照复制；无组/已有案件/无风险均拒绝。auto_create_from_risk(db, group)：管道钩子，已有案件跳过（幂等），风险未达阈值不动作。transition_status(db, incident_id, target)：严格状态机；→resolved 写 resolved_at+disposition=resolved；→false_positive 写 disposition；→closed 写 closed_at 保留原 disposition。另含只读 list_incidents(db, page, size, status)（created_at DESC）/get_incident。写操作只 flush 不 commit，事务边界在 API/管道
    ├── dashboard/service.py    # Step 7.5：get_summary(db) 纯实时聚合不建表不缓存。冻结指标语义：open_incidents = 活跃案件（status in open+in_progress）；severity 三项仅统计活跃案件；today_alerts/today_events 从今天 00:00 UTC 起（aware 比较，SQLite/PG 双兼容）；risk_distribution = 全量事件的 EventRisk.level（无风险记录的事件不计入）
    ├── ai/                     # Phase 2 Step 9：AI Provider 层（本步不碰真实模型，不碰 ollama-main）
    │   ├── base.py             # AIProvider 抽象契约：generate(AIRequest) -> AIAnalysis | RiskSummary（按 request.task 分派）；explain() 为 Step 10 兼容别名（仅接受 alert_explanation）；SYSTEM_PROMPTS 按任务注册（alert_explanation/risk_summary），build_user_prompt 用 exclude_none 保证 Step 10 提示词字节级冻结
    │   ├── models.py           # AIRequest（task/event/severity/risk/factors/evidence/prior_explanation 可选）+ 双协议：AIAnalysis {summary, attack_type, why_risky[], confidence}（Step 10）、RiskSummary {summary, key_findings[1..5], risk_drivers[词表], analyst_priority(low/medium/high/critical), confidence 0..1}（Step 11），均 extra=forbid；RISK_DRIVERS 冻结 10 词表；AI 绝不输出新 risk_score
    │   ├── protocol.py         # parse_analysis / parse_risk_summary / parse_task_output：容忍 ```json 围栏/前后文案，schema 校验严格，risk_drivers 显式词表校验；坏输出→AIResponseParseError，绝不伪造兼容结果
    │   ├── exceptions.py       # AIProviderError 基类 + Config/Unavailable/Parse 三子类，调用方只捕基类，失败全部显式上抛
    │   ├── transport.py        # 默认 HTTP 层（stdlib urllib，零新依赖），可注入替换；网络类故障统一映射 AIProviderUnavailable
    │   ├── mock.py             # MockProvider：确定性输出（同输入同输出），默认提供者，支持 fail_with 注入故障；永不伪装真模型（name 恒为 mock）
    │   ├── ollama.py           # OllamaProvider：/api/chat + format=json + stream=false；接口就绪，Step 10 才接真实例；需 AI_MODEL（空则 ConfigError）
    │   ├── openai_compatible.py# /chat/completions + response_format=json_object + Bearer 头；"cloud" 不是独立代码路径，只是部署配置（AI_PROVIDER=cloud）；model/api_key/base_url 缺一即 ConfigError
    │   └── registry.py         # create_provider(settings)：mock/ollama/openai_compatible/cloud → 具体实现，未知名→ConfigError；业务代码只见 AIProvider 契约，换模型不改 Incident/Risk 代码
    └── events/service.py       # list_events(db, page, size, level=None) / get_event(db, group_id)；Step 5.4 起 selectinload risk（列表 1 次子查询），?level= 时 JOIN event_risk（无风险记录的事件被排除）
```

关键语义（Step 4 定形）：**fingerprint ≠ group**。fingerprint 标识"事件种类"（跨时间稳定，不含时间戳/原文），AlertGroup 是 fingerprint + 5 分钟窗口切出的"一次事件"；同一指纹可对应多个组。两个入口（/alerts 与 /normalize）统一走 Normalization → Deduplication → DB；每条 Alert 全量保留为证据，`alert_events` 存原始报文。

其他：`simulator/scenarios/*/events.json`（5 个场景，信封 `{scenario, description, events}`，事件已是 AlertCreate 统一格式）、`simulator/runner/run.py`（Step 6.1：纯标准库 CLI，扫描→本地校验→直发 POST /alerts→实时打印→GET /events 摘要→失败非零退出；不走 /normalize 避免 source 指纹分裂；默认 `--timestamps now` 改写当前 UTC，`file` 为确定性重放）、`docker-compose.yml`（仅 PostgreSQL 16）、`docs/`（architecture/api/demo/deployment 四篇 + README 双语 + CHANGELOG，v1.0.0-phase1 发布物）。

**frontend/**（Step 8 落地，React 19 + TS + Vite + react-router-dom，无 UI 库，纯手写深色 SOC 主题）：

```
frontend/
├── vite.config.ts              # dev 代理 /api + /health → localhost:8000（后端须先起）
└── src/
    ├── api/                    # 唯一数据入口：client.ts（fetch 包装，ApiError 透传 FastAPI detail）+ dashboard/events/incidents 三模块，含分页/筛选参数拼接与 PATCH 状态流转
    ├── types/                  # 与后端 schema 字段级一一对应的 TS 镜像（dashboard/event/incident）；UUID/datetime 一律 string；前端零业务规则计算，只渲染后端返回值（案件状态按钮只镜像冻结矩阵做展示，合法性仍由后端状态机裁决）
    ├── layouts/ConsoleLayout.tsx  # 侧边栏导航壳（Dashboard/Events/Incidents）+ Outlet
    ├── components/common.tsx   # LevelBadge/StatusBadge/formatTime/Panel/Loading/ErrorBanner 展示原子
    ├── pages/                  # DashboardPage（仅绑 /dashboard/summary，15s 自动刷新，风险分布条形图）/ EventsPage（?level= 筛选+分页）/ EventDetailPage（fingerprint+风险因子表+证据告警）/ IncidentsPage（?status= 筛选+分页）/ IncidentDetailPage（生命周期动作按钮：open→3 选、in_progress→3 选、resolved/false_positive→closed）
    └── App.tsx                 # BrowserRouter 路由；index.css 为深色主题设计令牌（严重度四色+生命周期五色）
```

Step 5 定形语义：**风险只在事件变化时重算**（去重引擎 `db.add(alert)` 后、`commit()` 前，与告警落库同一事务），GET /events 是纯读路径，不做任何评分计算；`event_risk` 每事件唯一一行（唯一约束），重算原地更新 `score/level/factors/updated_at`。

## 四、环境事实（重要，影响所有验证方式）

- Windows + PowerShell；Git 2.54 / Python 3.12 / Node 24 可用
- **本机没有 Docker** → PostgreSQL 起不来。所有测试与冒烟验证都用 **SQLite** 替代：
  - 单元测试：`tests/conftest.py` 用 `sqlite://` 内存库 + `dependency_overrides`
  - 冒烟/迁移验证：`$env:DATABASE_URL="sqlite:///xxx.db"` 后跑 `alembic upgrade head` + uvicorn，用完删除
- 后端虚拟环境：`backend\.venv`，依赖已装全（含 pytest/httpx）

## 五、常用命令（均在 `sentinelflow\backend`）

```powershell
.\.venv\Scripts\python.exe -m pytest -q                    # 单元测试（当前 253 passed）
$env:DATABASE_URL="sqlite:///tmp.db"
.\.venv\Scripts\python.exe -m alembic upgrade head         # 迁移
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8765   # 起服务
Remove-Item Env:DATABASE_URL                                # 用完清环境变量
cd ..\.. ; python simulator/runner/run.py --repeat 30      # 一键演示全链路（需后端在 8000 端口）
# 前端（sentinelflow\frontend）：npm install → npm run dev（http://localhost:5173，后端须先在 8000 端口）；npm run build = tsc 类型检查 + vite 构建
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
11. 场景数据的 `203.0.113.50` / `198.51.100.77` 是文档保留段，按排除清单判非公网，不会触发 +20 公网加成——冒烟期望值按此设定（如 --repeat 30：ssh/web 50/medium、malicious_ioc 90/high、file_integrity/suspicious_process 70/medium 边界；Step 7.4 起恰好 3 个自动案件，快照均为首次越阈时的 70 分）。

## 七、当前任务：Step 10 AI Alert Explanation（✅ 已提交 `c946ae7` 并推送，工作树干净）

Step 9 已提交 `f7edcc1` 并随 main 推送至 GitHub（仓库：buoluotou/sentinelflow，Release 基于
tag v1.0.0-phase1，正文取自 CHANGELOG）。Step 9 冻结语义不变：契约 `AIProvider.explain(AIRequest)
-> AIAnalysis`；协议 {summary, attack_type, why_risky[], confidence∈[0,1]} extra=forbid；
错误三子类 Config/Unavailable/Parse；cloud 是 openai_compatible 的部署别名；默认 mock 离线可跑。

Step 10 已落地（用户冻结范围 10.1–10.3，**未接真实 Ollama**，AI 只分析不执行）：
- 10.1 `models/ai_analysis.py` + 迁移 0005：`ai_analyses` **历史表**（alert_group_id 只建索引，
  无唯一约束——重复分析追加记录，模型会换）；与 EventRisk/Incident 职责隔离，互不覆盖；
  `JSONVariant` 已迁至 `models/types.py` 打破循环导入（alert.py 保留兼容再导出）；
- 10.2 `services/ai/request_builder.py`：AlertGroup+EventRisk+Alerts → 冻结 AIRequest；
  证据硬上限 `MAX_EVIDENCE=20`（最早的 20 条，JSON 投影、丢弃 None 字段、不含内部 id）；
  无 EventRisk 时降级为 score 0/level "unassessed"，不报错；
- 10.3 `services/ai/service.py`：`AIAnalysisService.explain_event(db, event_id)`，
  flush 不 commit（事务边界在 API 层）；未知事件抛 `AIEventNotFound`；provider 错误原样上抛，
  绝不伪造成功；另有 `latest_analysis` 读最近一次。默认 provider 由 settings 构造（.env 未设 AI_PROVIDER → mock）。
- 测试 15 个（builder 5 + service 10，全 MockProvider，零网络）。迁移 0005 已在临时 SQLite 完成 upgrade→downgrade→upgrade 往返验证。
- 10.5 `api/v1/ai_analysis.py` + `schemas/ai_analysis.py`：显式触发，两个端点：
  `POST /api/v1/events/{id}/ai-analysis` → 201 + 完整分析体（id/alert_group_id/provider/model/
  summary/attack_type/why_risky/confidence/created_at）；`GET 同路径` → 最近一次（历史列表接口延后）。
  错误契约：AIEventNotFound→404（含非法 UUID）、Config/Unavailable→503、Parse→502；
  失败绝不落库（service 在 add 前抛出）。服务经 `get_ai_analysis_service` 依赖注入，测试可换坏 provider。
- 10.6 测试 10 个（创建字段校验/最新读取/无分析 404/未知与非法 id 404/503×2/502/失败不落库且恢复后可再分析）。
- 10.4 真实 Ollama 联调**已通过**（2026-08-25，本机 qwen3:4b）：
  `.env` 现为 `AI_PROVIDER=ollama / AI_MODEL=qwen3:4b / AI_BASE_URL=http://localhost:11434 /
  AI_TIMEOUT_SECONDS=180`（`.env.example` 补了 AI_TIMEOUT_SECONDS，默认 60）。
  真实链路验证：Simulator 造事件（risk=50）→ POST /ai-analysis → 201，约 45s，
  返回 provider=ollama / model=qwen3:4b / summary / attack_type / why_risky[3] /
  confidence=0.95，ai_analyses 恰 1 行。异常注入：伪 Ollama 服务返回违协议文本 → 502 且 0 行；
  AI_BASE_URL 指死端口 → 503 且 0 行。**模型适配 Parser，Schema 未放宽**（OllamaProvider 加
  `format:"json"` 原生 JSON 模式 + transport 超时可配 `AI_TIMEOUT_SECONDS`）。
  测试隔离：`tests/conftest.py` 顶部强制 `os.environ["AI_PROVIDER"]="mock"`，
  pytest 永不碰真模型。全量 253 passed。docs/api.md 端点表待 10.8 一并补。
  Ollama 进程为系统托盘服务（`%LOCALAPPDATA%\Programs\Ollama`），CLI 不在 PATH，验证走 HTTP API。
- 10.7 前端 AI 面板（无 Chat）：
  `frontend/src/types/aiAnalysis.ts`（与 AIAnalysisRead 字段级一致）；
  `frontend/src/api/aiAnalysis.ts`（getLatestAnalysis："No AI analysis" 的 404 → null，
  其余错误上抛；createAnalysis：POST 201）；
  `frontend/src/components/AiAnalysisPanel.tsx`（idle/loading/success/error 四态；
  Analyzing… 禁用防连点 + “可能需 60 秒”提示；错误横幅直透后端 detail 不另加前缀
  【503/502 后端文案已含人类可读前缀】；历史语义注释：重新分析追加记录，面板只展最新）；
  集成在 `EventDetailPage.tsx` Risk 面板之后、Evidence 之前。
- 10.8 真实浏览器 E2E（五 Case 全过）：
  Case1 无分析→点击→Analyzing→成功（qwen3:4b 约 20–30s）；
  Case2 刷新→直接展示最近分析，无自动模型调用（仅 GET）；
  Case3 再次分析→DB count 2 且页面展示最新（新 created_at）；
  Case4 AI_BASE_URL 指死端口（等价模拟 Ollama 停服，Ollama 未注册为 Windows 服务无法 Stop-Service）
  → 503 横幅“AI provider unavailable: ...”单一前缀，旧分析保留无假成功，DB 不增长；
  Case5 AI_PROVIDER=mock → 即时成功 provider=mock/model=mock-deterministic（CI/offline 路径）。
  验收终态：253 passed + npm run build ✅ + 真实 qwen3:4b ✅ + Mock ✅ + E2E ✅。

Step 11.1（已完成，未提交）：AI Risk Summary 协议与 Provider 任务化。
  审计结论（先审计后最小改动）：Step 9/10 三 provider 共用单一 SYSTEM_PROMPT、
  explain 硬编码 parse_analysis、AIRequest.task 从未被消费 → 决策：generate()
  升为唯一抽象方法按 task 选提示词/解析器，explain() 降为基类兼容别名，
  Step 10 全部调用方与既有测试（274 行，全走 explain）零改动。
  协议冻结：RiskSummary = {summary, key_findings[1..5], risk_drivers[RISK_DRIVERS
  10 词表], analyst_priority 枚举, confidence 0..1}，extra=forbid；未知 driver/
  未知字段（如 risk_score）一律 ParseError。AI 绝不输出新 risk_score：
  EventRisk.score 是唯一正式分，analyst_priority 仅运营优先级。
  落库：ai_risk_summaries 独立历史表（迁移 0006，alert_group_id 索引非唯一，
  往返验证 upgrade/downgrade/upgrade 通过）；AIRequest.prior_explanation 可选
  携带 Step 10 结果（exclude_none 保证不泄漏进 Step 10 提示词）。
  验收：281 passed（253 旧 + 28 新，test_ai_provider.py 全绿证明向后兼容）。

Step 11.2（已完成，未提交）：Risk Summary Request Builder。
  request_builder.py 新增 build_risk_summary_request(group, risk, alerts,
  latest_analysis=None)：task 在 builder 内固定为 risk_summary（签名无 task 参数，
  调用方无法改写）；无 Step 10 分析时 prior_explanation=None 照常构造，绝不拒绝。
  证据复用：抽出 _build_evidence() 两个任务共享同一投影（MAX_EVIDENCE=20、最早在前、
  None 字段丢弃），改上限只需改一处。prior_explanation 为结构化投影 {summary,
  attack_type, why_risky, confidence}（AIRequest.prior_explanation 类型放宽为
dict|str|None）——不含 id/provider/时间戳；exclude_none 保证 Step 10 提示词仍不含它。
  风险因子完整透传（_factors 共用）；risk 缺失时同样降级 0/unassessed。
  risk_summary 系统提示词补一句 prior_explanation 使用引导（11.1 未提交，顺手修正）。
  验收：290 passed（281 + 9 新，tests/test_ai_risk_summary_request_builder.py 覆盖
  8 Case：无分析/注入最新/只取一条/50→20 条/None 清理/因子完整/task 固定/Step 10 不漂移）。

Step 11.3（已完成，未提交）：Risk Summary Service。
  risk_summary_service.py：AIRiskSummaryService(provider 可注入，默认 create_provider)。
  generate_risk_summary(db, event_id) 严格按序：查 AlertGroup(selectinload risk/alerts，
  不存在抛 AIEventNotFound）→ alerts 按 first_seen_at 最早在前 → latest_analysis_for
  取最近 Step 10 分析（从 AIAnalysisService 抽出的模块级函数，避免第二套语义）→
  build_risk_summary_request → provider.generate → isinstance(RiskSummary) 任务守卫
  （错协议抛 AIResponseParseError 绝不落库）→ AIRiskSummary 落库 → flush 不 commit。
  另含 latest_summary（created_at desc, id desc）。错误边界与 Step 10 完全一致：
  404/503/502，失败一律不落库。安全边界：不碰 EventRisk/Incident，不产生执行动作。
  验收：301 passed（290 + 11 新，tests/test_ai_risk_summary_service.py 覆盖 9 Case：
  全字段落库/无分析成功/注入最新分析/历史追加/无 Risk 降级/503 不落库/502 不落库/
  flush+rollback 归零，另加错协议守卫与 404）；Step 10 三文件（41 用例）单独全绿。
  补录：11.4 回归发现 11.2 测试 flaky（两次 _alert(0) 各自取 datetime.now() 跨时钟 tick
  时 first_seen_at 漂移）→ 改为共享同一 alert 实例，已修。

Step 11.4（已完成，未提交）：Risk Summary API。
  api/v1/ai_risk_summary.py：POST /api/v1/events/{id}/ai-risk-summary → 201（service
  flush 后 API commit+refresh）；GET → 最新一条（created_at desc, id desc），无记录 404。
  错误映射与 Step 10 逐字一致：404（不存在/非法 UUID）/503（Config/Unavailable）/
  502（ParseError，含错协议守卫），任何失败不落脏数据。依赖注入 get_ai_risk_summary_service
  供测试覆写。schemas/ai_risk_summary.py：AIRiskSummaryRead 11 字段（含 updated_at，
  from_attributes，ORM→Schema→JSON 不直返 ORM）；响应体无 risk_score 字段（测试断言）。
  验收：313 passed（301 + 12 新，tests/test_ai_risk_summary_api.py 覆盖 8 Case：
  201 五核心字段/GET 取最新/无记录 404/双 404/503×2 不落库/502 不落库/错协议 502/历史 2 行）。
  四个必过文件（provider/request_builder/analysis_service/risk_summary_service）全绿。

Step 11.5（已完成，未提交）：Mock/协议回归 + 真实 Ollama 联调。
  tests/test_ai_risk_summary_provider_regression.py（34 用例）：合法协议/ risk_score
  注入被 extra=forbid 拒绝 / 非法 driver 无自动转换 / confidence [0,1] 边界 /
  key_findings 1..5 / analyst_priority 枚举 / Config+Unavailable+Parse 三类失败
  一律 count==0。全量默认套件 347 passed（313+34），e2e 不被默认收集。
  tests/conftest.py 新增 ollama marker + collect_ignore_glob=["e2e/*"]；
  tests/e2e/test_ai_risk_summary_ollama.py（2 用例，模块级 skip 保护）：
  真实 qwen3:4b 全链路（30 条高危 SSH 告警→201→协议断言只查结构不查文案→
  落库+1→GET id 一致）与死地址故障注入（503 + count==0），78s 全绿。
  人工 HTTP 闭环（uvicorn+临时 SQLite）：POST 201（64.3s，180s 超时生效）/
  GET 200 / ai_risk_summaries 恰好 1 行 / 响应无 risk_score；验证后清理。
  环境坑：Ollama 旧 llama-server 子进程 CUDA 初始化失败后残留 → 所有推理返回
  500/502 空 body；Stop-Process llama-server 后重新加载即恢复。另：shell 代理环境
  变量会让 urllib 把 localhost 请求走代理 → 跑真实测试前必须清 HTTP_PROXY 并设
  NO_PROXY=localhost,127.0.0.1。

Step 11.6（已完成，未提交）：Event Detail Risk Summary UI。严格克隆 Step 10.7
  AiAnalysisPanel 模式，未重构前端：
  types/aiRiskSummary.ts（镜像 AIRiskSummaryRead，故意无 risk_score 字段）；
  api/aiRiskSummary.ts：getRiskSummary（404 "No AI risk summary" → null，其余透传）
  + generateRiskSummary（POST）；components/RiskSummaryPanel.tsx：加载只 GET
  绝不自动 POST，404 = 正常空态（"No risk summary generated yet." 非红色报错），
  POST 201 直接用响应体 setSummary 不追加 GET，生成中按钮 disabled + 防连点，
  503/502 detail 原样透传；展示 Analyst Priority（LevelBadge）/Confidence/Summary/
  Key Findings/Risk Drivers/Provider/Model/Generated At。EventDetailPage 在
  AI Alert Explanation 面板后集成。前端测试基建首次引入：vitest + jsdom +
  @testing-library/react + jest-dom（vite.config.ts test 段，npm test），
  RiskSummaryPanel.test.tsx 8 用例：200 渲染且仅一次 GET 无自动 POST / 404 空态 /
  点击触发 POST / 201 直接渲染无额外 GET / 503 detail / 502 detail /
  飞行中 disabled 且双击只产生一次 POST / payload 偷渡 risk_score=93 也不渲染。
  8 passed + tsc 零错误 + vite build 成功；后端 347 基线未动仍全绿。
  坑：未开 vitest globals 时 RTL 自动 cleanup 不会注册 → 跨用例 DOM 残留报
  "Found multiple elements"，需显式 afterEach cleanup()。

Step 11.7（已完成，未提交）：Browser E2E 双链（真实浏览器，无新增脚本，
  uvicorn + vite dev + Browser Agent 驱动，临时库/脚本验证后全部清理）。
  链路 A（Mock）：空态→点击生成→面板全字段渲染→刷新仅 GET 不自动 POST→
  再次生成。后端访问日志铁证：总共恰好 2 次 POST（均 201），刷新/首次加载只
  GET；DB：2 条独立 id 记录（第一条未覆盖，仅追加）、EventRisk 仍 60/medium、
  incidents=0；页面无 risk_score 字样。注意 mock priority=medium 是冻结行为
  （priority=risk_level，该事件 60/medium）。
  链路 B（真实 qwen3:4b）：空态→点击→捕捉到 disabled+"Generating risk
  summary…"→约 33s 后 201→面板渲染：Provider=ollama/Model=qwen3:4b、5 个
  drivers 全属冻结词表、priority=high、confidence 95%、findings 4 条、无
  risk_score；DB 1 行，EventRisk/Incident 未变。timeout=180 生效（33s 推理
  未超时）。坑再现：shell 复用残留 $env:AI_PROVIDER='mock' 覆盖了 .env 的
  ollama 导致链路 B 首跑返回 mock 结果（Browser Agent 发现）→ 重启时显式设
  全部 AI_* 变量修复。另：空态下生成提示显示 "the configured model" 而非
  模型名，因无已有 summary 可取（与 Step 10 同款 fallback，非 bug）。

Step 11.8（已完成）：最终验收 + 工作区审计 + 一次提交，零功能改动。
  后端全量 347 passed（0 failed/0 skipped）；前端 8 passed + tsc 零错误 +
  vite build 成功。Browser E2E 双链重执行全绿：Mock 链（空态→生成→五字段渲染→
  刷新仅 GET→二次生成；日志恰好 2 次 POST 201；DB 2 行追加、EventRisk 60/medium
  未变、incidents=0）；真实 qwen3:4b 链（空态→约 40s 推理→201；priority=high、
  confidence=85%、4 drivers 全属冻结词表、findings 4 条、无 risk_score；DB 1 行、
  EventRisk/Incident 未变）。`tests/e2e/` 显式 `-m ollama` 实跑最终 2 passed
  （故障注入恒过；全链路因 qwen3:4b thinking 模式偶发输出越界被协议 502 正确拒绝，
  重试后全绿——生成式模型非 fixture，协议拒绝即冻结契约生效）。
  迁移审计：0006_add_ai_risk_summaries.py 存在且 `alembic upgrade head` 到 0006，
  生产路径（app/）无任何 create_all。默认收集策略复核：默认 `pytest backend/tests`
  收集恰 347（`collect_ignore_glob = ["e2e/*"]` 排除真实模型测试，不依赖本地
  Ollama）；Ollama 不可达时显式跑整模块 skip 不失败。git 审计：`git diff --check`
  干净（无 trailing whitespace/冲突标记），35 项变更全部归属 11.1–11.8，无敏感文件。
  坑：会话切换后 venv 缺 aiosqlite（临时装，未进 requirements；应用为同步引擎，
  运行时用 `sqlite:///` 同步 URL，`sqlite+aiosqlite` 仅用于旧记录且本应用不兼容）；
  ollama.exe 不在新终端 PATH（完整路径启动 `ollama serve`）；Invoke-WebRequest/
  urllib 探活前必须清代理变量并加 `-Proxy ''`。

下一步：Step 12 Response Recommendation（AI≠执行器，只出建议）→
  Step 13 Approval Queue（Phase 2 最关键安全边界）→ Step 14 Incident AI Integration；
  全部完成后统一打 v1.1.0 tag。安全边界不变：AI 只解释/总结/辅助判断，绝不执行响应；
  Step 11 不改 EventRisk.score/level、Incident.status/disposition。docs/api.md
  端点表可随后续 Step 一并补齐。

更后续：Step 11 风险摘要 → Step 12 处置建议（AI≠执行器）→ Step 13 Approval Queue
（Phase 2 最关键安全边界）→ Step 14 AI 与 Incident 全链路。

## 八、快速自检清单（新会话开工前执行）

```powershell
cd d:\edge\github\sentinelflow
git status            # 应为 clean（Step 10 已提交 c946ae7）
git log --oneline     # 应见 c946ae7(step 10) / f7edcc1(step 9) / 3794cc0(release hardening) / ...
git remote -v         # 应见 origin -> github.com/buoluotou/sentinelflow.git
git tag               # 应见 v1.0.0-phase1
cd backend
.\.venv\Scripts\python.exe -m pytest -q   # 应为 253 passed
```

任一项不符，先向用户报告差异，再动手。
