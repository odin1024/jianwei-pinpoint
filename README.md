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

## 2. 快速开始（本地开发）

### 2.1 建目录 + 初始化

```powershell
# 1) 建项目目录
$root = "C:\Users\<用户名>\Documents\Codex\2026-10-29\zui\php2shell-sentinel"
New-Item -ItemType Directory -Force -Path $root | Out-Null
Set-Location $root

# 2) 建虚拟环境
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3) 安装（editable 开发模式）
python -m pip install --upgrade pip
python -m pip install -e ".[all]"

# 4) 验证
python -m pytest
python -m p2s.cli rules
```

> macOS / Linux：把 `.\.venv\Scripts\Activate.ps1` 换成 `source .venv/bin/activate`。

### 2.2 三条命令跑通全流程

```powershell
# 被动日志检测（零风险）
python -m p2s.cli logs --file examples\access.log.sample --report reports\

# 主机侧检测
python -m p2s.cli host --report reports\

# Web 控制台
python -m p2s.cli serve --port 18080
# 浏览器打开 http://127.0.0.1:18080
```

**后台常驻启动（Windows）**

```powershell
.\scripts\start-console.ps1                 # 默认 18080，自动检测端口占用
.\scripts\start-console.ps1 -Port 19000     # 指定端口
.\scripts\stop-console.ps1                  # 停止
```

> `serve` 命令在端口被占用时会**自动顺延**到下一个可用端口；`--no-fallback` 可关闭该行为。

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
