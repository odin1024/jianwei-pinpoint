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

## 1.5 检测原理（四层收敛）

工具不是"只查 PHP 横幅"，而是分四层逐级收敛：

| 层 | 做什么 | 关键手段 |
|---|---|---|
| **L0 存活与端口发现** | 哪些端口开着 | 并发 TCP 探测，100+ 端口，含安全设备管理端口(2000/10000/2082...) |
| **L1 服务协议识别** | 跑什么服务 | HTTP 指纹 · **TLS 证书取证** · SSH/SMTP banner；UA 与路径回退阶梯 |
| **L2 设备类型分类** | 这是什么设备 | 证书 CN/O/OU + Server 头 + 页面标题 + SSH banner + 端口画像 加权打分 |
| **L3 PHP 暴露面判定** | 是否受本漏洞影响 | 有无 PHP → SAPI → 版本 → 对比基线 8.2.35/8.3.36/8.4.27/8.5.12 |

**为什么要分四层**：php2shell 只影响跑 PHP 的服务。客户的资产里有防火墙、堡垒机、
Linux 主机、邮件网关、摄像头 —— 它们根本不跑 PHP。工具必须先说清"这是什么设备"，
再说"要不要处置"，而不是对所有设备一律输出空白。

实测示例：

```
192.168.1.229   堡垒机 / 运维审计  ·  JumpServer  ·  置信 87%
                 端口 [25,110,143,443,2000,10000]  证书 CN=server,O=jump
                 结论：无 PHP 痕迹 → 与 php2shell 无关，无需处置

192.168.1.188   Web 服务器（无 PHP）  ·  Ubuntu  ·  置信 77%
                 端口 [22,25,80,110,143,3389,8080,8088]  nginx/1.24.0 (Ubuntu)
                 结论：无 PHP 痕迹 → 与 php2shell 无关，无需处置
```

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
