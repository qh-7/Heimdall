# Heimdall

面向企业信息保护与数据安全的自托管监测平台，单进程内提供两个独立功能：

| 功能 | 入口 | 做什么 |
|------|------|--------|
| **仿冒网站发现** | `/` | 输入品牌词/官方域名，从多个测绘与情报源发现疑似仿冒钓鱼站点，经过滤、AI 降噪、行为分析与评分后供人工复核 |
| **敏感信息监测** | `/sensitive/` | 输入目标关键字，从网页/代码托管/暗网情报等来源发现数据泄露线索，AI 逐条研判后按敏感等级排序供人工复核 |

两个功能共用一套部署与配置，数据与流程互相隔离。

---

## 安装部署

### 前置要求

- **Python 3.11 或更高**。`python3 --version` 确认；没有的话：
  - Windows：到 [python.org/downloads](https://www.python.org/downloads/) 下载安装包，安装时**勾选 "Add Python to PATH"**
  - macOS：`brew install python3`
  - Linux：`apt install python3 python3-venv python3-pip`（Debian/Ubuntu）
- 能访问外网（调用 FOFA / Exa / GitHub / 大模型等 API）。
- 磁盘预留足够空间（依赖 + Chromium 浏览器 + 截图数据）。

### 第一步：安装依赖

```bash
cd Heimdall

# 创建并激活虚拟环境
python3 -m venv .venv
source .venv/bin/activate        # Windows 是 .venv\Scripts\activate

# 安装 Python 依赖（国内网络慢可加 -i https://pypi.tuna.tsinghua.edu.cn/simple）
pip install -r requirements.txt
```

### 第二步：安装 Playwright 浏览器（多数人没装过，别跳过）

`pip install` 只装了 Playwright 的 Python 包，**无头浏览器本体需要单独下载**：

```bash
playwright install chromium

# 如果提示 playwright: command not found（没激活虚拟环境时常见），用完整路径：
.venv/bin/playwright install chromium          # Windows: .venv\Scripts\playwright install chromium
```

这一步会下载约 150MB 的 Chromium，国内网络慢属正常，可设置单次环境变量走代理。
Linux 服务器上首次运行如报缺系统库，再执行一次：

```bash
.venv/bin/playwright install-deps chromium    # 需要 root/sudo
```

> **没装会怎样？** 仿冒站发现的「行为分析」阶段会失败——没有截图、登录表单/支付特征识别，
> 评分相应偏低，但流水线不会中断，其余阶段照常出结果。**敏感信息监测完全不依赖 Playwright**。
> 所以也可以先跳过这步把服务跑起来，之后再补装。

### 第三步：填配置

项目根目录的 `config.yaml` 是唯一配置文件，至少填这几项才有可用结果：

```yaml
fofa:
  key: "你的 FOFA key"        # 仿冒站发现主力源
exa:
  key: "你的 Exa key"         # 仿冒站发现 + 监测网页搜索共用
llm:
  base_url: "https://api.deepseek.com"   # 任意 OpenAI 兼容服务
  model: "deepseek-chat"
  key: "你的大模型 key"        # AI 降噪/研判，两个功能共用
sensitive:
  code:
    github_token: "你的 GitHub token"     # 监测代码搜索（GitHub 设置页生成，只读权限即可）
  intel:
    key: "你的零零信安 key"               # 监测暗网情报
```

没有的 key 留空即可，对应来源会自动跳过。完整配置项与环境变量写法见下文「配置」。

### 第四步：启动与验证

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

- 浏览器打开 **http://localhost:8000** 看到「Heimdall」页面即部署成功
- 建一个小任务（如品牌词填一个词），在任务列表看实时日志：
  各来源逐个返回条数 = 对应 key 有效；某来源报错不影响其它来源
- 监测功能入口在主页右上角，或直接访问 **http://localhost:8000/sensitive/**

### Windows 手动安装

```cmd
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\playwright install chromium
.venv\Scripts\uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 服务器长期运行（可选）

```bash
# 简单方式：nohup 后台运行
nohup .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 >> run.log 2>&1 &
```

或写 systemd 服务（开机自启、崩溃自动拉起）：

```ini
# /etc/systemd/system/heimdall.service
[Unit]
Description=Heimdall
After=network.target

[Service]
WorkingDirectory=/opt/Heimdall
ExecStart=/opt/Heimdall/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now heimdall
```

> ⚠️ **平台没有登录认证**，`--host 0.0.0.0` 会监听所有网卡。部署在服务器上时务必用防火墙
> 限制来源 IP，或改 `--host 127.0.0.1` 后通过带认证的 Nginx 反代访问，避免结果数据外泄。

### 常见问题

| 现象 | 原因与处理 |
|------|-----------|
| 行为分析阶段全部失败 / 无截图 | 没执行 `playwright install chromium`，补装后重启 |
| `playwright: command not found` | 虚拟环境没激活，用完整路径 `.venv/bin/playwright install chromium` |
| Linux 上 Chromium 启动报缺 `libnss3` 等 | 执行 `.venv/bin/playwright install-deps chromium` |
| 改了 `config.yaml` 不生效 | 配置启动时加载一次，**必须重启服务** |
| 某来源日志显示 0 条且带错误 | 对应 key 无效/配额耗尽，只影响该来源 |
| `database is locked` | 极少见，已开 WAL；确认没有多个进程共用同一 db 文件 |

---

## 配置（`config.yaml`）

所有配置集中在项目根目录 `config.yaml`。该文件含密钥，**已在 `.gitignore` 中，不要提交、不要外泄**。
配置在进程启动时加载一次（`get_config()` 带缓存），**改完必须重启服务才生效**。

### 密钥总览

| 配置段 | 用途 | 是否需要 key |
|--------|------|:---:|
| `fofa` | 仿冒站发现：FOFA 关键词 + icon_hash 检索 | 需要 |
| `hunter` | 仿冒站发现：奇安信 Hunter 检索 | 需要 |
| `crtsh` | 仿冒站发现：crt.sh 证书透明日志 | 免费 |
| `exa` | 仿冒站发现 + 监测网页搜索（key 共用） | 需要 |
| `permutation` | 仿冒站发现：域名变体生成 + DNS 验证 | 免费 |
| `urlscan` | 仿冒站发现：URLScan.io（限速 ~10/min） | 免费 |
| `llm` | 两个功能共用的 OpenAI 兼容大模型 | 需要 |
| `sensitive.code` | 监测：GitHub 代码搜索（限速 ~10 次/分） | 需要 token |
| `sensitive.intel` | 监测：零零信安 0.zone 暗网/泄露情报 | 需要 |
| `sensitive.netdisk` | 监测：网盘文库搜索 | 只有企业版才具备API KEY |

每个源都有 `enabled: true/false`，未配 key 或关闭时自动跳过，不影响其它源。

### key 也可用环境变量覆盖（不改文件）

`FOFA_KEY`、`HUNTER_KEY`、`EXA_KEY`、`LLM_KEY`、`LLM_BASE_URL`、`LLM_MODEL`、`GITHUB_TOKEN`、`ZONE_KEY`
（映射关系见 `app/config.py` 的 `_ENV_MAP`）。

---

## 功能一：仿冒网站发现

```
发现(多源并发) → 过滤+归并 → 入库 → AI 降噪 → 行为分析(截图) → 评分 → 人工复核
```

- **多源发现**：FOFA、Hunter、crt.sh、Exa、URLScan.io、域名排列、favicon 同源，插件式可扩展。
- **三层名单过滤**：IP 黑名单 / 域名白名单 / 标题黑名单，先粗筛去噪再归并。
- **多源归并**：按注册域名合并，被多个源命中 = 强信号。
- **AI 降噪**：OpenAI 兼容大模型（DeepSeek / 通义 / 智谱等）判定是否仿冒并给置信度。
- **行为分析**：Playwright 无头浏览器访问，截图、识别登录表单 / 支付特征 / 跳转。
- **加权评分**：favicon 精确匹配、品牌词、登录表单、可疑证书等多维度打分。

每一步完成即写库，前端实时可见；支持中途停止。编排见 `app/pipeline/orchestrator.py`。

### 黑白名单维护（`filter:` 段）

改完重启服务生效，无需改代码：

```yaml
filter:
  domain_whitelist:        # 这些域名(及子域)永不视为仿冒，官方域名自动并入
    - "gov.cn"
    - "yourbrand.com"
  ip_blacklist:            # 命中则丢弃(官方/CDN 出口 IP，精确匹配)
    - "203.0.113.10"
  title_blacklist:         # 标题含这些词则丢弃(子串匹配、大小写不敏感)
    - "404"
    - "域名出售"
```

### 评分（`scoring:` 段）

`scoring.threshold` 为标记「疑似仿冒」的总分阈值；`scoring.weights` 控制各特征权重
（favicon 精确匹配 40、品牌词 20、登录表单 15、支付 10、可疑证书 10、跳转 5、多源 10、LLM 上限 30），全部可在 config 调整。

### API

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/tasks` | 新建并启动任务 |
| GET | `/api/tasks` | 任务列表 |
| GET | `/api/tasks/{id}` | 任务详情 |
| GET | `/api/tasks/{id}/candidates` | 候选列表（分页/按评分排序） |
| GET | `/api/tasks/{id}/logs` | 实时日志 |
| POST | `/api/tasks/{id}/stop` | 停止任务 |
| DELETE | `/api/tasks/{id}` | 删除任务及候选 |
| PATCH | `/api/candidates/{id}` | 人工复核标注 |
| GET | `/api/tasks/{id}/export` | 导出 CSV |
| GET | `/api/screenshots/{name}` | 截图访问 |

---
<img width="1066" height="629" alt="1" src="https://github.com/user-attachments/assets/0eb4bc19-441e-454a-afec-a8dd08bc471e" />

<img width="1365" height="739" alt="2" src="https://github.com/user-attachments/assets/ecde91f5-b55f-4a3e-8a9d-6765b86bf865" />


<img width="1442" height="951" alt="3" src="https://github.com/user-attachments/assets/89588d17-8635-4b94-9ec6-fd918a569cbd" />



## 功能二：敏感信息监测

```
发现(多源并发) → 按定位去重 → 入库 → AI 研判(结论/等级/类型) → 人工复核
```

输入四类**目标关键字**（至少一类）：单位名/品牌词、域名/子域名、邮箱后缀、内部特征串（系统名/项目代号/特征路径）。AI 以这些关键字为锚，研判每条线索是否与目标单位相关、是否本应非公开。

### 来源类型（`sensitive:` 段）

| 来源 | 说明 | key |
|------|------|-----|
| `web` | 通用网页搜索，走 Exa（复用顶层 `exa` 的 key） | 复用 Exa |
| `code` | GitHub 代码搜索，发现误传的密钥/配置/源码 | `github_token` 或 `GITHUB_TOKEN` |
| `intel` | 零零信安 0.zone 暗网/泄露情报，`query_type` 可调 | `key` 或 `ZONE_KEY` |
| `netdisk` | 网盘文库搜索 | 占位未实装 |

### AI 研判输出

复用顶层 `llm` 配置段，逐条线索输出：

- **研判结论**：确认泄露 / 疑似 / 无关（误报）
- **敏感等级**：高 / 中 / 低（列表默认按此排序）
- **泄露类型**：账号口令 / 源代码 / 内部文档 / 数据库 / 密钥 / 其他
- 置信度与中文理由

线索按「定位」去重（网页=URL、代码=仓库+路径、情报=记录 ID），不跨源归并、逐条独立研判。

### API（挂载于 `/sensitive` 前缀）

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/sensitive/api/monitor/tasks` | 新建并启动监测任务 |
| GET | `/sensitive/api/monitor/tasks` | 监测任务列表 |
| GET | `/sensitive/api/monitor/tasks/{id}` | 任务详情 |
| GET | `/sensitive/api/monitor/tasks/{id}/leaks` | 泄露线索列表（按等级排序，可按等级/结论/标记筛选） |
| GET | `/sensitive/api/monitor/tasks/{id}/logs` | 实时日志 |
| POST | `/sensitive/api/monitor/tasks/{id}/stop` | 停止 |
| DELETE | `/sensitive/api/monitor/tasks/{id}` | 删除任务及线索 |
| PATCH | `/sensitive/api/monitor/leaks/{id}` | 人工复核标注 |
| GET | `/sensitive/api/monitor/tasks/{id}/export` | 导出 CSV |

---

<img width="1429" height="792" alt="4" src="https://github.com/user-attachments/assets/4f694b8c-779b-4e94-b532-e4191d180672" />


## 目录结构

```
app/
  main.py                  FastAPI 入口与仿冒站路由(并挂载 /sensitive 子应用)
  config.py                配置加载(yaml + 环境变量覆盖)
  models.py / db.py        SQLModel 模型与 SQLite(WAL)
  common/
    taskrunner.py          后台任务执行器(线程 + 取消标志，两个领域共用)
    tasklog.py             任务日志写入
  pipeline/                ── 仿冒网站发现 ──
    orchestrator.py        流水线编排
    filtering.py           ★ 三层名单过滤 + 多源归并
    denoise.py             LLM 降噪
    behavior.py            Playwright 行为分析 + 截图
    scoring.py             加权评分
    discovery/             各发现源(fofa/hunter/crtsh/exa/urlscan/permutation/favicon)
  sensitive/               ── 敏感信息监测(独立领域) ──
    main.py                子应用路由 + 前端
    models.py              MonitorTask / Leak / MonitorLog
    orchestrator.py        监测编排(发现→去重→AI 研判)
    denoise.py             AI 研判
    sources/               各来源(web/code/intel/netdisk)
config.yaml                ★ 全部配置与密钥(不入 git)
```

## 技术栈

Python 3.11+ / FastAPI + Uvicorn / httpx(async) / Playwright(chromium) /
SQLModel + SQLite(WAL) / mmh3 + Pillow。前端为原生 JS + 手写 CSS，无构建步骤；
后台任务用进程内线程 + asyncio，无 Celery / Redis。

## 注意事项

- `config.yaml` 含真实密钥，务必保持在 `.gitignore` 中，勿外泄。
- 新增发现源/监测来源是插件式的：在 `app/pipeline/discovery/` 或 `app/sensitive/sources/` 照现有源新建模块 + `@register` + 配置段，三步接入，不改其它代码。
- 本工具用于企业信息保护与本单位数据泄露监测，请在合法授权范围内使用。
