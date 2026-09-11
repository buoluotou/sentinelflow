# SentinelFlow

SentinelFlow 是一个开源的安全告警编排与事件响应平台。它通过 HTTP/JSON API 接收告警，
将其归一化、去重为带评分的事件，从高风险事件中建立案件，并把每一个响应动作置于人工审批
和另一条独立执行路径之后，全过程写入追加式审计轨迹。

它开箱即可离线运行。Demo Mode 使用 mock AI provider 和零出站的 mock executor，因此整条
流水线 —— 告警 → 事件 → 案件 → AI → 审批 → 执行 → 审计 —— 无需安装 Wazuh、Shuffle、
TheHive 或 Ollama 即可跑通。

SentinelFlow 不是生产级 SOAR。它是一个可以阅读、运行和扩展的演示与参考实现：它不带边缘
认证，真实集成仅限实验环境，外部结果通道在缺乏依据时一律拒绝而不是猜测
（见[已知限制](#已知限制)）。

## 为什么

告警队列缺的不是告警，而是决策。分析师需要知道哪条告警重要、它为什么得到这样的评分、
以及一旦处置会发生什么 —— 而且这份记录必须能经受事件复盘。

设计由此展开：

- 检测是确定性的。去重（时间窗口内的 SHA-256 指纹）与风险评分都基于规则，每个事件都会
  保存其 0–100 评分背后的因子明细。
- AI 只提供建议。模型按照固定的动作词表撰写解释、风险摘要与处置建议。它从不输出风险
  评分，任何 AI 输出都不会自行抵达外部系统。
- 审批不等于执行。决定被记录为独立的事实；执行是另一条需要认证的路径，拥有自己的
  Guard、策略闸和耐久派发记录。
- 尝试不等于结果。向外部系统派发请求，与从外部系统读回一个已确认的结果，是两件不同的
  事实，分开存储。

## 快速开始

### Docker（推荐）

只需要 Docker，宿主机上不需要 Python 或 Node。

```powershell
# Windows（PowerShell）
git clone https://github.com/buoluotou/sentinelflow.git
cd sentinelflow
./scripts/quickstart.ps1
```
```bash
# Linux / macOS
git clone https://github.com/buoluotou/sentinelflow.git
cd sentinelflow
./scripts/quickstart.sh
```

脚本会检查 Docker，写入带有随机本地密钥的 `.env`，按 PostgreSQL → migrate → backend →
frontend 的顺序启动，等待健康检查，运行一次端到端冒烟测试，并打印访问地址：

| 项目 | URL |
|---|---|
| 前端（从这里开始） | http://localhost:5173 |
| 后端 API | http://localhost:8000/api/v1 |
| 交互式 API 文档 | http://localhost:8000/docs |

首次运行的时间主要花在基础镜像下载和两次镜像构建上，因此取决于你的网络：镜像已缓存时只需
几秒，全新机器或慢速链路上需要几分钟。之后的启动很快。

如果 PyPI 下载在受限网络下卡住，可以把构建指向你信任的镜像源（默认仍为官方 PyPI）：在
`.env` 中设置 `PIP_INDEX_URL=https://<trusted-mirror>/simple/`，然后用
`./scripts/quickstart.sh --rebuild` 重新构建，或直接用
`docker compose build --build-arg PIP_INDEX_URL=https://<trusted-mirror>/simple/` 构建。
参见 [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)。

### 本地运行（不使用容器）

本地安装会检查前置条件、创建后端 venv、安装依赖、初始化 `.env` 并执行迁移：

```powershell
./scripts/setup-dev.ps1                     # Windows
./scripts/setup-dev.ps1 -Database sqlite    # 本地核心链路数据库，不使用 PostgreSQL
```
```bash
./scripts/setup-dev.sh                      # Linux / macOS
DATABASE=sqlite ./scripts/setup-dev.sh
```

然后启动两个开发服务器：

```bash
# 终端 1 —— 后端
cd backend && uvicorn app.main:app --reload --port 8000

# 终端 2 —— 前端
cd frontend && npm run dev
```

环境要求：Python ≥ 3.10（3.12 已验证）、Node ≥ 20.19（推荐 22 LTS）、PostgreSQL 16 ——
或使用 SQLite 跑通到审批为止的核心链路。完整说明：
[docs/QUICKSTART.md](docs/QUICKSTART.md#3-native-quickstart-developers)。

### 配置

所有设置都来自仓库根目录下的同一个 `.env`（pydantic-settings）。请复制模板而不是手写 ——
`scripts/quickstart` 和 `scripts/setup-dev` 会替你完成，并填入一个随机本地密钥：

```bash
cp .env.example .env      # Windows：Copy-Item .env.example .env
```

`.env.example` 分为八个有文档的区块：**CORE · DATABASE · AI · EXECUTION · THEHIVE ·
WAZUH · SHUFFLE · OBSERVABILITY**。密钥没有可用的默认值（`*_API_KEY`、`*_TOKEN`、
`*_PASSWORD`、`DATABASE_URL` 都是占位符），`.env` 已被 git 忽略，后端启动时会打印一份
摘要，说明启用了哪些 provider 与适配器 —— 只给出“是否已设置 token”的布尔值，从不出具体
值。前端只读取一个变量 `VITE_API_BASE_URL`，默认走同源配置。关键变量与加固清单见
[docs/deployment.md](docs/deployment.md)。

### 验证与测试

```bash
# 环境与配置诊断（PASS / WARN / FAIL；后端未启动时加 -SkipHttp）
./scripts/doctor.ps1     # Windows
./scripts/doctor.sh      # Linux / macOS

# 通过真实 HTTP 端到端验证，从不导入 app 内部服务
./scripts/smoke.ps1      # Windows → "SentinelFlow demo smoke test: PASS"
./scripts/smoke.sh       # Linux / macOS

# 后端：2997 个测试；外部集成套件默认不收集
# 覆盖率受闸门约束：阈值见 scripts/ci/check_coverage.py
cd backend && python -m pytest -q

# 前端
cd frontend && npm run typecheck && npm run test && npm run build
```

在 PostgreSQL 上，冒烟测试会跑完整条链路，包括耐久派发执行。在 SQLite 上，它验证到审批
为止的链路，并断言执行步骤 fail closed（`... core smoke test (SQLite): PASS`）。失败时以
非零码退出。

## 演示与走查

制造一场告警风暴（一条命令即可；需要宿主机上有 Python 3.10+，或者你也可以直接在 `/docs`
界面里 POST 告警）：

```bash
python simulator/runner/run.py --repeat 30 --base-url http://localhost:8000
```

它会把五个攻击场景各重放三十次：150 条告警收敛为 5 个聚合事件，这些事件获得风险评分，
其中 3 个自动建立案件。打开 http://localhost:5173 并跟随
**[演示指南](docs/demo.md)** —— 一份 15 分钟的走查，每一步都给出预期输出：Dashboard
计数器、事件列表及其风险因子、案件生命周期、事件上的三个 AI 面板、审批队列、执行审计、
可观测性页面，以及只读的案件 AI 调查视图。

控制台有六个页面 —— Dashboard、Events、Incidents、Approval Queue、Execution Audit、
Execution Observability。执行是从案件上的 **AI Investigation** 面板派发的；不存在单独的
Execute Console 页面。

## 架构

```
        Simulator / SIEM adapters
                 │
   Alert ────────▼
   Normalization            adapter-based unified event model
                 │
   Deduplication ─▼          fingerprint + time-window aggregation
   Risk Engine              explainable, rule-based scoring (0–100)
                 │
   Incident ─────▼           auto-creation policy + lifecycle state machine
                 │
   AI Analysis ──▼           explanation / risk summary / recommendation (advisory)
                 │
   Approval ─────▼           human approve / reject — records a decision only
                 │
   Execution ────▼           Guard → policy → durable dispatch → adapter
                 │
   External Outcome ◀──────── inbound webhook  (separate trust domain)
                 │            manual reconcile (separate trust domain)
   Dashboard ────▼           read-only aggregation for the console
```

告警作为证据被完整保留；归一化把适配器的载荷映射到同一个事件模型；去重在
`DEDUP_WINDOW_SECONDS`（默认 300）内按指纹聚合；风险引擎把评分上限设为 100，并保存其
因子。风险 ≥ 70 时，每个事件建立一次案件，案件沿着
`open → in_progress → resolved → closed` 流转（`false_positive` 是出口状态）。审批决定、
执行审计行与外部结果分别存放在独立的追加式表中；结果取值为 `unknown`、`pending`、
`confirmed_success`、`confirmed_failure` 或 `reconciliation_failed` 之一。

**技术栈：** FastAPI + SQLAlchemy + Alembic（后端）；React 19 + TypeScript + Vite
（前端）；PostgreSQL 16，核心链路开发也支持 SQLite。控制台以同源方式访问 API —— 开发时
由 Vite 代理 `/api`，Docker 镜像中由 nginx 代理 —— 因此没有需要调整的 CORS 配置。对外的
适配器调用使用标准库（`urllib`，并禁用重定向）。

```
sentinelflow/
├── backend/          # FastAPI：services/、models/、api/、Alembic 迁移
├── frontend/         # React 19 + TypeScript + Vite 控制台
├── simulator/        # 攻击场景 + 标准库 Runner CLI
├── integrations/     # 外部适配器接口（Shuffle / Wazuh / TheHive）
├── scripts/          # quickstart · setup-dev · doctor · smoke (.ps1 + .sh)
├── infrastructure/   # 部署资产
└── docs/             # 文档
```

### 运行模式

**Demo Mode（默认）。** 前端 + 后端 + PostgreSQL。`AI_PROVIDER=mock`、
`EXECUTION_ADAPTER=mock`，所有外部系统关闭 —— Docker 快速开始得到的就是这个组合。

**AI Local Mode。** 在 Demo Mode 之上加一个本地模型：
`docker compose --profile ollama up -d`，然后设置 `AI_PROVIDER=ollama`、`AI_MODEL` 与
`AI_BASE_URL`。Ollama 是可选项，从不阻塞安装；若它不可达，只有 AI 相关端点降级，平台
照常运行。若改用 OpenAI 兼容端点，设置 `AI_PROVIDER=openai_compatible`（或其别名
`cloud`），并配置 `AI_BASE_URL` 与 `AI_API_KEY`。

**Integration Lab Mode。** 在你自行运维的实验环境中连接真实的 Wazuh / Shuffle / TheHive
实例。它由配置开关控制，不会被自动部署：设置 `EXECUTION_ADAPTER` 并完整配置 `.env` 中
对应的区块 —— 配置不完整的适配器会拒绝启动。这些连接仅限实验环境，未通过生产认证。
各模式的说明见 [docs/QUICKSTART.md](docs/QUICKSTART.md#run-modes)。

## 安全边界

- AI 输出仅供参考。它被存储和展示；它从不写入风险评分，也从不触发动作。
- 决定与执行分开记录。批准或驳回会针对每条建议写入一个决定，不执行任何动作。
- 执行是一条独立的受保护路径。它需要带有 `executor` 或 `admin` 角色的 bearer token，
  经过 Guard 与可选的执行策略（UTC 时间窗加上逐动作最低风险），并在任何外部调用之前先
  提交耐久派发记录。没有自动重试，也没有绕过审批的通道。
- 审计轨迹是追加式的。执行日志与外部结果只写入一次，永不重写。
- 身份来自 bearer token。执行操作者就是通过认证的主体；客户端提交的 `operator` 字段会
  被忽略。在生产模式下，审批记录中的 reviewer 同样是该 token 的主体。
- 缺失的配置会 fail closed。操作者注册表为空（`OPERATORS_JSON` 与 `EXECUTION_TOKEN`
  都为空）时，所有写入路径都返回 401；配置不完整的适配器会拒绝启动。
  `DEPLOYMENT_MODE=production` 还额外要求：PostgreSQL、一个至少包含一个可审批角色和一个
  可执行角色的操作者注册表、一个真实的执行适配器、不启用补偿工作流，以及回环地址绑定。

## 已知限制

**平台不带边缘认证。** 没有登录、会话或 SSO 层；发布的端口绑定在回环地址
（`BIND_HOST=127.0.0.1`）上，以此作为暴露面控制。若要把它暴露到受信任网络之外，需要你
自己的 SSO / 反向代理。参见 [SECURITY.md](SECURITY.md) 与
[加固清单](docs/deployment.md#security-hardening-checklist)。

**控制台在决策方面是 Demo Mode 工具。** 当 `DEPLOYMENT_MODE=production` 时，
`POST .../approve` 与 `POST .../reject` 需要 bearer token，而随仓库发布的前端不会为这
两个调用发送 `Authorization` 头：它没有会话层，也不保存任何凭据，因此这些调用会返回
401。执行对话框确实接受手工输入的 token，所以只有在操作者每次动作都粘贴一个 token 时，
执行才可用。在出现边缘认证或会话层之前，请把浏览器控制台当作 Demo Mode 界面使用。

**真实的 Wazuh / Shuffle / TheHive 连接仅限实验环境。** 它们由配置开关控制，需要你为
自己运行的实验环境提供凭据，且未通过生产认证。

**外部结果通道一律拒绝。** 入站 webhook 回调与人工对账已经实现、经过测试，并且会持久化
结果，但每个适配器的外部状态词表都是空的，生产读取适配器注册表也是空的。因此，任何上报
的状态都会被以静态 `404` 或 `422` 拒绝，而不是被映射，不会凭空产生任何结果。今天配置
一个真实适配器也不会让你得到 `confirmed_success`；那需要有证据支撑的词表和一个已注册的
读取适配器。

## 路线图

| 状态 | 能力 |
|---|---|
| **可用** | 检测 → 案件流水线；建议性 AI（mock / Ollama / OpenAI 兼容）；人工审批；使用 mock executor 的受控执行；治理（操作者 RBAC、执行策略、度量、观测到的适配器健康）；耐久派发 |
| **已实现 — fail-closed** | 外部结果通道（入站 webhook + 人工对账，分属独立信任域）。外部状态词表与生产读取适配器注册表为空，因此结果被以静态 `404` / `422` 拒绝。配置一个适配器目前不会改变这一点 |
| **已实现 — 认证受阻** | 真实的 Shuffle / Wazuh / TheHive 适配器：由配置开关控制、仅限实验环境、未通过生产认证 |
| **下一步** | 认证一套有证据支撑的外部状态词表及其背后的读取注册表；控制台的边缘认证 / 会话层；真实适配器的生产认证；审计日志规模下进一步的读取路径工作（执行审计列表在 SQL 中按链分页） |

## 文档

- **[快速开始](docs/QUICKSTART.md)** —— Docker 与本地安装、首次运行走查、运行模式
- **[演示指南](docs/demo.md)** —— 带预期输出的端到端走查
- **[架构](docs/architecture.md)** · **[API 参考](docs/api.md)** · **[部署](docs/deployment.md)**
- **[故障排查](docs/TROUBLESHOOTING.md)** · **[SECURITY.md](SECURITY.md)**
- 交互式 API 文档：启动后端后打开 `http://localhost:8000/docs`
- 内部设计历史保存在 `docs/design/` 下 —— 属于工程记录，不是使用 SentinelFlow 的必读材料。

## 许可证

MIT License，见 [LICENSE](LICENSE)。
