# p2s — php2shell 检测与暴露面评估工具

> 针对 **CVE-2026-109618**（OOM 内存破坏）与 **CVE-2026-109619**（陈旧全局状态 UAF），
> 代号 `php2shell`。两个漏洞 CVSS 9.2 / Critical，未认证 RCE，已被 CISA 列入 KEV（2026-10-26）。

**修复基线：PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**

---

## 1. 这个工具是什么形态

一个工具，三种形态，按场景选用：

| 形态 | 入口 | 适合谁 | 能做什么 |
|---|---|---|---|
| **Web 控制台**（主形态） | `p2s serve` → 浏览器 | 客户的安全/IT 团队 | 资产台账、扫描编排、报告中心、规则与 IOC 管理 |
| **CLI / 无头模式** | `p2s assets/probe/logs/host` | CI/CD、批量任务、自动化 | 与控制台共用同一套引擎，可独立运行 |
| **Agent** | `p2s-agent` | 客户的目标主机 | 在主机本地执行 L3 深度检测（生效配置、可疑文件、进程、连接）并上报 |

**架构上是三层：**

```
   ┌──────────────────────────────────────────────┐
   │  Web 控制台 (FastAPI)                        │   浏览器 / 客户侧
   │  资产台账 · 扫描编排 · 报告中心 · 规则库        │
   └──────────────────┬───────────────────────────┘
                      │ API
   ┌──────────────────┴───────────────────────────┐
   │  扫描引擎 (Python)                            │   客户侧 / 中枢
   │  L1 被动日志  ·  L2 主动探针  ·  IOC 匹配      │
   └──────────────────┬───────────────────────────┘
                      │ POST /api/agent/report
   ┌──────────────────┴───────────────────────────┐
   │  Agent                                         │   客户的目标主机
   │  L3 主机侧：配置 / 文件 / 进程 / 连接 / 持久化   │
   └──────────────────────────────────────────────┘
```

> **为什么需要 Agent？** L3 检测必须在目标主机本地执行 —— 生效的 `php.ini` 值、临时目录里的落地文件、
> PHP worker 派生的 shell、出站 C2 连接，远程探测拿不到这些信息。

---

## 1.4 检测原理（五层收敛）

工具的目标不是"扫端口"，而是**回答：我的资产里有哪些跑 PHP 且版本不安全的设备**。

| 层 | 做什么 | 关键手段 |
|---|---|---|
| **L0 存活与端口发现** | 哪些端口开着 | 并发 TCP connect 探测，100+ 端口，含安全设备管理端口(2000/10000/2082/4243…) |
| **L1 服务协议识别** | 跑什么服务 | HTTP/HTTPS 指纹 · **TLS 证书取证** · SSH/FTP/SMTP banner · favicon 哈希；UA 与路径双回退阶梯 |
| **L2 存活判定** ⭐ | 是不是真在线 | **必须拿到有意义的协议响应**才算在线 |
| **L3 设备类型分类** | 这是什么设备 | 页面标题 · Server 头 · TLS 证书 · 登录路径 · Cookie（主）+ 端口画像（兜底）+ MAC OUI（厂商） |
| **L4 PHP 暴露面** | 要不要处置 | 有无 PHP → SAPI → 版本 → 基线 8.2.35/8.3.36/8.4.27/8.5.12 |

### L2 为什么要单独一层

实测本机所在网段 `192.168.1.0/24`：

```
254 个 IP 全部"可连接" 25/110/143，但 1.5 秒内收不到任何字节
```

出口防火墙做**全锥 NAT** 或对邮件端口做 **tarpit** 的典型表现。
只看 TCP 握手的话，**254 台不存在的主机会被全部判为存活** —— 台账里就是几百条"未识别设备"。

正确判据：HTTP 任意状态码 / 非空协议 banner / TLS 握手成功 = 有效响应；
**TCP 连上但零数据 = 噪声，不算存活**。离线主机不写入台账、不显示、不计入统计。

### L3 为什么用标签而不是端口

| 主机 | 只看端口 | 用标签 |
|---|---|---|
| 192.168.1.253 | 网络设备 / 未识别 | **华为 Quidway 交换机**（证书 `CN=Quidway`） |
| 192.168.1.252 | 网络设备 / 未识别 | **华为 iBMC 带外管理**（标题 `iBMC Login`） |
| 192.168.1.254 | 网络设备 / 未识别 | **华为交换机**（`Server: sw3`） |
| 192.168.1.15 | Windows 主机 | **FileZilla Server**（banner 特征） |
| 192.168.1.230 | Web 服务器 | **PHP 应用站点**（`Set-Cookie: PHPSESSID`） |
| 192.168.1.227 | 网络设备 | **准入控制系统 NAC**（标题 `准入控制系统`） |

签名库 128 条（`core/signatures.py`），每条声明 **字段 + 子串 → 类型/厂商/产品**。
通用词（`server`/`company`/`localhost`）绝不作判据 —— 实测大量设备证书就是 `CN=server,O=company`。

完整说明见 [docs/DETECTION.md](docs/DETECTION.md)。
---

## 1.6 控制台界面

**设计取向：企业级工具，不是营销页。**

- 零 emoji —— 全部使用单色线性 SVG 图标（35 个 symbol）
- 单一强调色 + 语义状态色，其余一律中性灰
- 扁平化：1px 描边分层，无渐变、无装饰性阴影、无径向背景
- 紧凑行距与信息密度，数字用等宽字形

**十个页面，全部对接真实后端 API，无任何模拟数据：**

| 页面 | 真实功能 |
|---|---|
| 态势总览 | KPI + 暴露面环形图 + 设备类型分布 + 最近扫描 |
| **设备发现** | 提交后台任务，实时进度条，任务结果自动刷新 |
| **任务中心** | 运行中任务（进度 + 取消）+ 历史任务（持久化，可删除） |
| 资产台账 | 筛选/搜索、**分组与负责人行内编辑**、CSV 导出、复扫、删除 |
| PHP 暴露面 | 版本 vs 修复基线矩阵、处置建议、CSV 导出 |
| 日志分析 | 服务器路径分析 + **文件拖拽上传**、覆盖缺口提示 |
| 主机侧检测 | 本机安装点/生效配置/痕迹/进程/连接、台账 CSV 导出 |
| 规则中心 | 规则明细、一键导出 Sigma / ModSecurity / Suricata |
| IOC 中心 | 攻击者基础设施、dropper URL、样本哈希 |
| 报告中心 | 历史报告查看、下载 MD/HTML、**删除** |

### 后台任务队列

长耗时操作（网段扫描、日志分析、主机侧检测）全部走 `core/jobs.py`：

- 单工作线程串行执行，避免并发扫描打满网络
- 状态持久化到 `p2s-data/jobs.json` —— **控制台重启后历史任务仍在**
- 实时进度（`done/total` + 百分比 + 当前目标）
- 可取消；运行中的任务在重启后标记为"已中断"
- 时间戳毫秒精度，保证同秒内多任务的排序稳定

早期版本把扫描直接放在 HTTP 请求里同步跑，导致三个问题：浏览器超时（看起来"没反应"）、零进度反馈、切页即任务丢失。现在全部解决。
---

## 2. 快速开始（本地开发）

### 2.1 初始化（已有 .venv 可跳过）

```powershell
# 1) 进入项目目录（仓库根目录下的 app/）
Set-Location app

# 2) 建虚拟环境
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3) 安装（editable 开发模式）
python -m pip install --upgrade pip
python -m pip install -e ".[all]"

# 4) 验证：113 个用例 + 静态检查
python -m pytest
python -m ruff check src tests scripts
python -m p2s.cli rules
```

> macOS / Linux：把 `.\.venv\Scripts\Activate.ps1` 换成 `source .venv/bin/activate`。

### 2.2 三条命令跑通全流程

```powershell
# 被动日志检测（零风险）
python -m p2s.cli logs --file examples\access.log.sample --report reports\

# 主机侧检测
python -m p2s.cli host --report reports\

# Web 控制台（首次访问需要口令）
$env:P2S_CONSOLE_PASSWORD = "换成你的口令"
python -m p2s.cli serve --port 18080
# 浏览器打开 http://127.0.0.1:18080 → 跳转登录页 → 输入口令
```

> 未设置 `P2S_CONSOLE_PASSWORD` 时，控制台会随机生成一个口令并打印在启动日志里，
> 每次重启都会变；正式部署请显式设置该环境变量。
> Agent 上报用的令牌是 `P2S_AGENT_TOKEN`（缺省复用控制台口令）。

**后台常驻启动（Windows）**

```powershell
.\scripts\start-console.ps1                 # 默认 18080，自带健康检查与「已运行」识别
.\scripts\start-console.ps1 -Port 19000     # 指定端口
.\scripts\stop-console.ps1                  # 停止
```

> `serve` 命令在端口被占用时会**自动顺延**到下一个可用端口；`--no-fallback` 可关闭该行为。
### 2.3 设备发现（推荐先跑这个）

```powershell
# 单台
python -m p2s.cli discover --host 192.168.1.229 --report reports\

# 网段批量（最多 1024 台）
python -m p2s.cli discover --cidr 192.168.1.0/24 --report reports\
```

输出示例：

```
发现完成 [disc-b6ad8f1cc9]  目标=2
  设备类型分布: 堡垒机 / 运维审计×1  Web 服务器（无 PHP）×1
  [ ] 192.168.1.229           堡垒机 / 运维审计             PHP=无 暴露=not_php 置信=0.87
        端口: [25, 110, 143, 443, 2000, 10000]
        · TLS 证书: CN=server,OU=yanfa,O=jump
        · Server 头: Jump_server
        · 页面标题: 开发测试防火墙系统
  [ ] 192.168.1.188           Web 服务器（无 PHP）          PHP=无 暴露=not_php 置信=0.77
        端口: [22, 25, 80, 110, 143, 3389, 8080, 8088]
        · SSH banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20
```

### 2.4 Web 控制台的九个页面

| 页面 | 作用 |
|---|---|
| **态势总览** | KPI 卡 + PHP 暴露面环形图 + 设备类型分布条形图 + 最近扫描 |
| **设备发现** | 网段/批量主机发现，设备卡片网格，点开看完整画像 |
| **资产台账** | 设备画像持久化，按暴露面筛选、搜索、CSV 导出、复扫 |
| **PHP 暴露面** | 只列真正跑 PHP 的资产，版本 vs 修复基线矩阵 + 处置建议 |
| **日志分析** | 被动检测，命中明细 + **规则覆盖缺口**提示 |
| **主机侧检测** | 本机 PHP 安装点、生效配置、可疑痕迹 |
| **规则中心** | 13 条规则，一键导出 Sigma / ModSecurity / Suricata |
| **IOC 中心** | 攻击者基础设施、dropper URL、样本哈希 |
| **报告中心** | 历史扫描，JSON / Markdown / HTML 三份报告下载 |

界面支持**浅色 / 深色切换**（右上角 ◐ 按钮，选择记在 localStorage）。
### 2.5 后台任务（长耗时操作）

```powershell
# 设备发现 —— 提交后台任务，立即返回 job id
python -m p2s.cli discover --host 192.168.1.229 --report reports\
```

`/24` 网段建议用快速模式（仅探测 20 个常见端口与 SSH banner），实测约 1.6 秒/台：

| 模式 | 每台耗时 | /24 预计 | 内容 |
|---|---|---|---|
| 快速 | ~1.6s | ~7 分钟 | 20 个常见端口 + SSH/banner |
| 深度 | ~2.5s | ~11 分钟 | 110+ 端口 + HTTP 指纹 + TLS 证书 + 路径/UA 回退 |

控制台的「设备发现」页会显示预计耗时，并在后台执行、可随时切页或取消。
---

## 3. 多平台支持

### 3.1 工具自身可运行在

| 平台 | 支持 | 说明 |
|---|---|---|
| Linux (x86_64 / arm64) | ✅ | Ubuntu / Debian / CentOS / RHEL / Alpine / openEuler / 麒麟 |
| Windows Server 2016–2025 | ✅ | 含注册表枚举、计划任务调度 |
| Windows 10/11 | ✅ | |
| macOS (Intel / Apple Silicon) | ✅ | Homebrew / MacPorts 安装路径识别 |
| Docker / Podman / Kubernetes | ✅ | 镜像内运行，扫描容器与镜像层中的 PHP |
| WSL | ✅ | 走 Linux 分支 |

### 3.2 可检测的目标系统类型

| 目标类型 | 识别方式 | L1 | L2 | L3 |
|---|---|---|---|---|
| Apache + **mod_php** | `Server: Apache/x` + `X-Powered-By: PHP/x` | ✅ | ✅ | ✅ |
| Nginx + PHP-FPM | `Server: nginx` | ✅ | ✅ | ✅ |
| Apache + mod_proxy_fcgi | `Server: Apache` + FPM 错误页 | ✅ | ✅ | ✅ |
| Microsoft IIS + php-cgi | `Server: Microsoft-IIS` | ✅ | ✅ | ✅ |
| LiteSpeed / OpenLiteSpeed | `Server: LiteSpeed` | ✅ | ✅ | ✅ |
| FrankenPHP | `Server: FrankenPHP` / Caddy | ✅ | ✅ | ✅ |
| OpenResty | `Server: openresty` | ✅ | ✅ | ✅ |
| Docker / K8s 容器 | 主机侧枚举镜像与进程 | ✅ | ✅ | ✅ |
| 嵌入式设备（路由器/防火墙/存储/摄像头/工控） | HTTP 指纹 | ✅ | ✅ | ⚠️ 依赖厂商补丁 |
| WordPress / Drupal / Joomla / Magento | 指纹 + 路径特征 | ✅ | ✅ | ✅ |
| 面板（cPanel / Plesk / 宝塔 / DirectAdmin / Webmin） | 主机侧进程与配置 | ✅ | ✅ | ✅ |

**SAPI 感知是核心差异化**：同一个 PHP 版本，在 mod_php 与 PHP-FPM 上的实际风险、
可用的探测手段、以及缓解优先级都不同。`p2s` 会在指纹阶段判定 SAPI 并据此给出结论。

详见 [docs/PLATFORMS.md](docs/PLATFORMS.md)。

---

## 4. 目录结构

```
php2shell-sentinel/
├── src/p2s/
│   ├── cli.py                 # CLI 入口（6 个子命令）
│   ├── core/
│   │   ├── versions.py        # 版本 → 修复状态判定
│   │   ├── fingerprint.py     # HTTP 指纹 + SAPI 识别
│   │   ├── rules.py           # 13 条检测规则（数据驱动）
│   │   ├── logscan.py         # 日志解析 + 规则匹配 + 行为关联
│   │   ├── probe.py           # 安全主动探针（无害）
│   │   ├── ioc.py             # IOC 库 + webshell 特征
│   │   ├── hostcheck.py       # 跨平台主机侧检测
│   │   └── report.py          # JSON / Markdown / HTML 报告
│   ├── console/app.py         # FastAPI Web 控制台
│   └── agent/agent.py         # 主机侧 Agent
├── tests/                     # 40 个测试
├── scripts/
│   └── check_payload_literals.py   # 载荷字面量守护检查
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PLATFORMS.md
│   └── DEPLOY-CUSTOMER.md
├── deploy/                    # 客户交付物料
├── examples/                  # 示例日志与主机列表
├── Dockerfile / docker-compose.yml
└── .github/workflows/ci.yml    # 三平台 CI
```

---

## 5. 命令参考

```powershell
p2s assets --file hosts.txt --report reports/    # 资产测绘：版本 + SAPI + 修复判定
p2s probe  --file hosts.txt --report reports/    # 资产测绘 + 主动安全探测
p2s logs   --file access.log  --report reports/  # 被动日志检测（L1）
p2s host   --report reports/                     # 主机侧检测（L3）
p2s ioc    --scan-file sample.txt                # IOC 匹配
p2s rules  --format json                         # 导出规则库
p2s serve  --port 18080                           # 启动 Web 控制台
```

---

## 6. 安全红线（写在代码里，也写在测试里）

1. **探针绝不携带利用载荷。** 只发送最小无害请求以触发可观测差异；
   `tests/test_probe.py` 中有专门的断言确保探针不含 PHP 代码 / 危险函数。
2. **源码不含完整载荷字面量。** 工具源码会被客户的杀毒/EDR 扫描，
   含完整 webshell 字符串会导致工具自身被拦截。`scripts/check_payload_literals.py`
   是强制守护，CI 里会跑。
3. **所有主机侧操作只读。** 不修改配置、不删除文件、不 kill 进程。
4. **主动探测需要授权。** 文档与 UI 均提示只可对自有或已获授权的资产使用。

---

## 7. 开发

```powershell
python -m pytest                       # 测试
python -m ruff check src tests scripts # 静态检查
python scripts/check_payload_literals.py .   # 载荷守护检查
```

新增一条规则：在 `src/p2s/core/rules.py` 增加 `Rule`，在 `core/logscan.py` 的 `_match()`
里实现 `matcher` 判定分支，并补一个测试。规则是数据驱动的，加规则不需要动引擎。

---

## 8. 参考

- PHP 官方公告：https://www.php.net/archive/2026.php#2026-10-21-5
- CISA 警报：https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- NCSC-NL 运营情报：https://github.com/NCSC-NL/php2shell
- TU Delft 在野观测：https://php2shell.delftintellab.com/
- 社区规则参考：https://github.com/ikow/php2shell-poc
