# SentinelFlow 工作交接文档（AI Agent 接手用）

> 最后更新：2026-08-25 · Phase 1 已冻结并**已发布到 GitHub**（buoluotou/sentinelflow，tag v1.0.0-phase1 + Release）；Step 9（`f7edcc1`）与 Step 10（`c946ae7 feat(ai): add alert explanation`）均已提交并推送；**下一步 Step 11 AI Risk Summary**（不打新 tag，v1.1.0 等 Step 11–14 全部完成后统一发布）
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
    │   ├── base.py             # AIProvider 抽象契约：explain(AIRequest) -> AIAnalysis；SYSTEM_PROMPT/build_user_prompt 全部 Provider 共用（冻结提示词合同）
    │   ├── models.py           # AIRequest（task/event/severity/risk/factors/evidence）+ AIAnalysis 冻结结构化协议 {summary, attack_type, why_risky[], confidence 0..1}，extra=forbid 防漂移
    │   ├── protocol.py         # parse_analysis：容忍 ```json 围栏/前后文案，schema 校验严格；坏输出→AIResponseParseError，绝不伪造兼容结果
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

下一步：Step 11 AI Risk Summary（用户冻结：不是再让 AI 生成一段闲话，而是把
Event + Risk Factors + 多条 Evidence 压缩成 SOC 分析师真正可用的风险摘要），
随后 Step 12 Response Recommendation → Step 13 Approval Queue（Phase 2 最关键安全边界）
→ Step 14 Incident AI Integration；全部完成后统一打 v1.1.0 tag。安全边界不变：
AI 只解释/总结/辅助判断，绝不执行响应。docs/api.md 端点表可随 Step 11 一并补齐。

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
