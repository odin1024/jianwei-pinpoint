# 见微 Pinpoint · 产品设计与开发文档

**产品名称**：见微 Pinpoint　**原代号**：p2s（php2shell Sentinel）
**版本**：v0.5.0
**文档日期**：2026-10-29（v0.5.0 品牌重塑与评审修订）
**适用对象**：产品负责人、安全工程师、后端开发、交付实施、运维

---

## 文档说明

本文件是 p2s 的**单一权威设计文档**，覆盖产品定位、需求、设计、开发规范与交付要求。

配套文档：
| 文档 | 内容 |
|---|---|
| `docs/DETECTION.md` | 检测原理详解（五层模型、计分规则、实测数据） |
| `docs/ARCHITECTURE.md` | 架构分层与扩展点 |
| `docs/PLATFORMS.md` | 多平台支持矩阵 |
| `docs/DEPLOY-CUSTOMER.md` | 客户交付指引与验收清单 |
| `README.md` | 快速开始与命令参考 |

代码规模：核心代码 **6190 行**，测试 **646 行 / 7 个文件**，API **30 个**，检测签名 **133 条**，日志规则 **13 条**。

---

## 一、产品概述

### 1.1 背景

2026-10-21，PHP 项目发布两个 CVSS 9.2 的未认证远程代码执行漏洞：

| 编号 | 名称 | 根因 |
|---|---|---|
| CVE-2026-109618 | RCE via OOM corruption | `longjmp()` 处理 OOM 时跳过清理，请求内存处于半初始化状态仍被使用 |
| CVE-2026-109619 | RCE via stale global state | 请求级全局状态未重置，请求内存释放后仍被后续请求引用（UAF） |

代号 `php2shell`。CISA 于 10-26 列入 KEV「已知被利用漏洞」目录，强制修复截止 **2026-10-29**。
修复基线：**PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**。

### 1.2 问题陈述

组织需要回答一个问题：**「我的资产里，哪些设备跑着不安全的 PHP？」**

朴素做法是"扫一遍看有没有 PHP 横幅"，但这在真实企业网络里会同时产生两类错误：

| 错误类型 | 表现 | 原因 |
|---|---|---|
| **假阴性** | 真有漏洞的设备没被发现 | 很多站点不暴露 `X-Powered-By`，只通过 `Set-Cookie: PHPSESSID` 暴露自己是 PHP 应用 |
| **假阳性** | 台账里几百条「未识别设备」 | 出口防火墙全锥 NAT / tarpit 让**任意 IP** 的某些端口「可连但零响应」，只看 TCP 握手会把不存在的主机全部判为存活 |

实测数据（`192.168.1.0/24`）：254 个 IP 全部在 25/110/143 可连接但零字节响应。旧实现据此写入 254 条「未识别设备」。

### 1.3 产品定位

> **一句话**：见微 Pinpoint 是面向企业内网资产的 **PHP 暴露面发现与合规评估工具**，它先把资产「看清楚」，再回答「哪些要修」。

见微 Pinpoint 不做漏洞扫描器（不探测 CVE、不发利用载荷），而是做三件事：
1. **资产测绘** —— 这台机器是什么设备、什么厂商、什么系统
2. **PHP 暴露面判定** —— 它跑不跑 PHP、什么版本、SAPI 是哪个、是否低于修复基线
3. **证据与报告** —— 每条结论都带可复核的证据链，报告可直接交付客户

### 1.4 价值主张

| 客户痛点 | 见微 Pinpoint 的应对 |
|---|---|
| 资产清单是 Excel，不知道有多少台跑 PHP | 自动发现 + 自动分类，台账可导出 CSV |
| 安全设备（防火墙/堡垒机/交换机）识别不出来 | 133 条标签签名（页面标题/证书/Server 头/登录路径） |
| 离线主机污染台账 | L2 存活判定，必须有有效协议响应才入库 |
| 想验证 WAF 规则有没有用 | 13 条规则可导出 Sigma / ModSecurity / Suricata |
| 客户问「到底哪些机器要升级」 | PHP 暴露面页按版本 vs 基线排序，带处置建议 |
| 报告发出去被杀毒拦 / 载荷二次传播 | 报告输出前统一脱敏 |

### 1.5 目标用户与场景

| 角色 | 场景 | 用到的功能 |
|---|---|---|
| **甲方安全工程师** | 季度自查：找出所有跑 PHP 的资产，导出整改清单 | 设备发现 → PHP 暴露面 → CSV 导出 → 报告中心 |
| **乙方交付工程师** | 项目实施：帮客户摸清内网有什么、哪些有风险 | 设备发现（网段）→ 资产台账 → 报告交付 |
| **甲方运维** | 收到整改通知，需要判断自家机器有没有中招 | 主机侧检测（本机痕迹/配置/进程/连接） |
| **SOC / 运营中心** | 持续监控是否有人在打 php2shell | 日志分析（被动、零风险）+ IOC 中心 |
| **合规 / 审计** | 需要一份可追溯的评估报告 | 报告中心（JSON/MD/HTML，含证据链） |

### 1.6 能力边界

**做**：
资产发现与设备分类 · PHP 版本与 SAPI 判定 · 修复基线比对 · Web 日志被动检测 · 主机侧只读取证 · IOC 匹配 · 报告生成 · 规则导出

**不做**（明确排除，避免期待错位）：
- ❌ 不做漏洞利用、不发送利用载荷、不做 DoS
- ❌ 不做漏洞扫描（CVE 探测、PoC 验证）
- ❌ 不做渗透测试、不提权、不做横向移动
- ❌ 不修改任何被检系统（全部只读）
- ❌ 不做资产纳管/监控告警（不是 CMDB，不做持续监控）

---

## 二、需求分析

### 2.1 功能需求

| 编号 | 需求 | 优先级 | 实现状态 | 验收 |
|---|---|---|---|---|
| FR-01 | 支持单个 IP、主机列表、CIDR 三种目标输入 | P0 | ✅ | `p2s discover --host/--file/--cidr` |
| FR-02 | 识别设备类型、厂商、具体产品 | P0 | ✅ | 133 条签名，实测 17/17 台精准 |
| FR-03 | 区分在线与离线，离线不入库不显示 | P0 | ✅ | L2 存活判定 |
| FR-04 | 判定是否跑 PHP、版本、SAPI | P0 | ✅ | 支持 4 种 PHP 线索 |
| FR-05 | 版本 vs 修复基线，输出处置建议 | P0 | ✅ | 6 种状态分级 |
| FR-06 | 长耗时操作后台执行，有进度、可取消 | P0 | ✅ | 任务中心 |
| FR-07 | 任务历史持久化，重启不丢 | P0 | ✅ | `p2s-data/jobs.json` |
| FR-08 | 资产台账：筛选、搜索、分组、责任人 | P0 | ✅ | 行内编辑 |
| FR-09 | Web 控制台覆盖全部能力 | P0 | ✅ | 10 个页面 |
| FR-10 | 被动日志检测，零风险 | P1 | ✅ | 13 条规则 + 行为关联 |
| FR-11 | 日志支持服务器路径与文件上传两种来源 | P1 | ✅ | `/api/scan/logs/upload` |
| FR-12 | 主机侧只读取证 | P1 | ✅ | 安装点/配置/痕迹/进程/连接 |
| FR-13 | 规则导出到 Sigma / ModSecurity / Suricata | P1 | ✅ | 3 种格式 |
| FR-14 | IOC 库与匹配 | P1 | ✅ | 9 IP / 3 域 / 14 URL / 4 哈希 |
| FR-15 | 报告三格式 + 可下载 + 可删除 | P1 | ✅ | JSON / MD / HTML |
| FR-16 | 资产批量导入（主机列表 / 网段） | P1 | ✅ | `/api/assets/import` |
| FR-17 | 浅色 / 深色主题 | P2 | ✅ | localStorage 持久化 |
| FR-18 | Agent 在目标主机本地做 L3 检测 | P2 | ✅ | systemd timer / 计划任务 |
| FR-19 | 控制台登录认证 | P0 | ⛔ **待做** | — |
| FR-20 | 定时扫描调度 | P2 | ⛔ 待做 | — |

### 2.2 非功能需求

| 编号 | 指标 | 目标 | 实测 |
|---|---|---|---|
| NFR-01 | 单台设备发现耗时 | ≤ 3s | 1.4s（快速）/ 2.5s（深度） |
| NFR-02 | `/24` 网段完成时间 | ≤ 15 min | 6 min（254 台） |
| NFR-03 | 设备分类准确率 | ≥ 90% | 17/17 台有具体产品标签 |
| NFR-04 | 假阳性率（离线主机入库） | 0 | 0（237 台全部排除） |
| NFR-05 | 单次请求最长阻塞时间 | ≤ 5s | 全部长耗时操作走任务队列 |
| NFR-06 | 前端外部依赖 | 0 | 单文件内联 SVG，无 CDN |
| NFR-07 | 核心第三方依赖 | ≤ 4 | httpx / cryptography / fastapi / uvicorn |
| NFR-08 | 目标平台 | Linux / Windows / macOS | 三平台 CI 全绿 |
| NFR-09 | Python 版本 | ≥ 3.9 | 3.9 / 3.11 / 3.12 CI |
| NFR-10 | 源码不含完整利用载荷 | 强制 | `scripts/check_payload_literals.py` CI 门禁 |

### 2.3 关键约束

| 约束 | 原因 | 影响 |
|---|---|---|
| 不发利用载荷 | 法律与伦理；避免打挂客户生产 | 主动探测能力受限，靠版本判定而非利用验证 |
| 只读被检系统 | 不能在客户环境改配置 | 主机侧仅读取 |
| 不依赖外网 | 客户内网环境 | IOC/签名/OUI 全部内置 |
| 不用原始套接字 | Windows / 容器 / 非 root 环境 | 用 TCP connect 而非 SYN 扫描，慢一些但通用 |
| 不信任证书 | 内网设备几乎全自签名 | TLS 握手不校验 |

---
## 三、系统设计

### 3.1 总体架构

```
┌──────────────────────────────────────────────────────────────┐
│  表现层                                                      │
│  ┌────────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │ Web 控制台      │  │ CLI          │  │ Agent            │ │
│  │ FastAPI + 单文件│  │ 6 个子命令   │  │ 主机侧采集上报    │ │
│  │ 前端（10 页）   │  │ 无头/CI 友好  │  │ systemd/计划任务  │ │
│  └───────┬────────┘  └──────┬───────┘  └────────┬─────────┘ │
│          └──────────────────┴───────────────────┘           │
│                             │ HTTP API                       │
├─────────────────────────────┼────────────────────────────────┤
│  编排层    JobManager（单线程串行 · 进度 · 取消 · 持久化）    │
├─────────────────────────────┼────────────────────────────────┤
│  引擎层    core/                                             │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────┐ │
│  │ discovery  │ │ logscan    │ │ hostcheck  │ │ probe    │ │
│  │ 端口/服务   │ │ 日志+规则  │ │ 主机取证   │ │ URL 探测 │ │
│  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └────┬─────┘ │
│        │              │              │             │       │
│  ┌─────┴──────────────┴──────────────┴─────────────┴─────┐ │
│  │ identification  signatures  versions  rules  ioc  oui  │ │
│  │ redact  report  fingerprint                          │ │
│  └───────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────┤
│  存储层    p2s-data/                                         │
│  assets.json  jobs.json  scans/{id}.{json,md,html}  uploads/│
└──────────────────────────────────────────────────────────────┘
```

**分层原则**：表现层不碰业务逻辑；引擎层不知道 HTTP；编排层管理长耗时与并发；存储层只有 JSON 文件（可换 SQLite，不影响引擎）。

### 3.2 检测引擎：五层模型

这是产品的核心。完整算法见 `docs/DETECTION.md`，此处给出结构。

```
L0 存活与端口发现   TCP connect（96 线程并发）
   端口集 = TOP_PORTS(通用) ∪ DEVICE_PORTS(安全设备 2000/10000/2082/4243…)
   快速模式用 FAST_PORT_SET(27 个常见端口)

L1 服务协议识别     按端口性质分流探测，各端口并行（12 线程）
   ├─ 22        → SSH banner
   ├─ 443/8443… → HTTPS + TLS 证书解析（CN/O/OU/SAN/有效期）
   ├─ 80/8080…  → HTTP
   ├─ 2000/2082 → 先 HTTPS，失败回落 HTTP（安全设备协议不固定）
   ├─ 21/25/110→ 直接抓 banner（先试 HTTP 会在 tarpit 上白等）
   └─ 未知端口   → 先试 HTTP，再回落 banner

L2 存活判定  ⭐     必须拿到「有意义的协议响应」
   HTTP 任意状态码 / 非空 banner / TLS 交换成功 = 有效
   TCP 连上但零数据 = 噪声 → 不算存活
   跨主机统计 detect_noise_ports() 识别网络级噪声端口

L3 设备类型分类     133 条签名加权计分
   主证据：页面标题(×1.8) · Server 头 · TLS 证书 · 登录路径 · Cookie · WWW-Authenticate
   辅证据：协议 banner · favicon 哈希
   补充：MAC OUI 厂商（读本机 ARP 表）
   兜底：端口画像（仅当无任何标签证据）

L4 PHP 暴露面       有无 PHP → SAPI → 版本 → 基线比对 → 六态结论
```

### 3.3 计分模型

```
得分(产品) = Σ 该产品下各签名的【最高权重】× 字段系数
             ＋ 0.8 × (命中该产品的不同字段数 − 1)      ← 互证加分

字段系数：页面标题 ×1.8（最"人写"的标签）  其余 ×1.0

置信度 = 0.35 + 优势度×0.35 + 强度×0.30
   优势度 = 最高分 / 总分        强度 = 最高分 / 8（封顶 1.0）

候选类型：得分 ≥ 最高分 × 40% 的其它产品，并列展示
```

**两条硬性纪律**（有测试守护）：

1. **通用词绝不作厂商判据**。`server` / `company` / `localhost` / `root` / `cn` 一律禁止作为签名 needle。实测中大量设备证书就是 `CN=server,O=company`。
2. **品牌名与产品名分离**。「捷普」是品牌，旗下有 WAF / 防火墙 / 审计 / 准入多条产品线，因此品牌名只做低权重厂商提示，具体产品由更细的标题关键词决定。

### 3.4 设备类型体系

28 类，覆盖网络设备、安全设备、服务器、应用平台：

| 类别 | 类型 | 主要判据 |
|---|---|---|
| 安全 | `firewall` `waf` `nac` `vpn` | 标题含「防火墙/应用防火墙/准入控制/VPN」，证书含 firewall/utm |
| 运维 | `bastion` `ibmc` | 标题含「堡垒机/iBMC/idrac/xclarity」，证书含 jump/yanfa |
| 网络 | `switch` `router` `net_mgmt` `load_balancer` | 证书 `CN=Quidway`，`Server: sw1`，标题含「交换机/路由器」 |
| 终端 | `linux_host` `windows_host` `iot_device` `camera` | SSH banner 发行版名，445/3389，标题含「海康/大华」 |
| 服务 | `mail` `ftp` `db` `storage` `file_service` | 端口画像 + banner + 标题 |
| 应用 | `php_app` `java_app` `dotnet_app` `cms` `web_server` | `PHPSESSID`/`JSESSIONID`/IIS 头/`X-Powered-By` |
| 平台 | `monitoring` `devops` `cloud` `container` | 标题含 Zabbix/Grafana/Jenkins/K8s/vCenter/Portainer |

### 3.5 PHP 暴露面六态

| 状态 | 含义 | 处置 |
|---|---|---|
| `exposed` | 跑 PHP 且版本 < 修复基线 | **立即升级** + 重启 worker |
| `patched` | 跑 PHP 且版本 ≥ 基线 | 保持领先；保持 `session.upload_progress.enabled=0` |
| `not_php` | 无 PHP 痕迹 | 与本漏洞无关，无需处置 |
| `unknown` | 有 PHP 迹象但版本未知 | 人工确认版本 |
| `not_applicable` | 主机离线 | 不处置 |
| `dev_branch` / `eol_*` | 开发分支 / 已 EOL | 升级或走厂商回补 |

**PHP 判定线索（4 种，实测都需要）**：
`X-Powered-By: PHP/x.y.z` · `Set-Cookie: PHPSESSID` · 正文 `Powered by PHP` · `Server` 头含 `PHP/x`

### 3.6 数据模型

**资产记录（assets.json 元素）**

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | str | 12 位 hex 主键 |
| `host` | str | IP 或主机名 |
| `group` / `owner` / `note` | str | 可编辑的分组、责任人、备注 |
| `alive` | bool | **L2 存活判定结果**，false 不入库 |
| `device_type` / `device_label` | str | 设备类型码 / 中文标签 |
| `product` / `vendor` / `os_hint` | str? | 具体产品 / 厂商 / 操作系统 |
| `tech_stack` | list[str] | PHP / Java / .NET |
| `mac` / `mac_vendor` | str? | MAC 与 OUI 厂商 |
| `open_ports` | list[int] | 全部可连端口 |
| `meaningful_ports` | list[int] | **有效响应的端口**（判定依据） |
| `noise_ports` | list[int] | 可连但无响应（NAT/tarpit） |
| `services` | list[dict] | 每个服务的完整画像（标题/证书/banner/cookie…） |
| `php_present` / `php_version` / `sapi` | | PHP 判定三要素 |
| `exposure` / `risk` | str | 暴露面与风险等级 |
| `confidence` | float | 0~1 置信度 |
| `evidence` | list[str] | **可复核的判定证据链** |
| `candidates` | list[dict] | 次优候选类型 |
| `remediation` | list[str] | 处置建议 |
| `last_checked` | str | ISO 时间戳 |

**任务记录（jobs.json 元素）**：`id` `kind` `title` `params` `state` `progress` `message` `total` `done` `result` `error` `created_at` `started_at` `finished_at` `cancel_requested`

### 3.7 API 规格（30 个）

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/api/health` | 健康检查 |
| GET | `/api/overview` | 总览聚合（资产数/暴露面分布/类型分布/最近扫描） |
| POST | `/api/jobs` | **创建后台任务**（discover / logs / host / url） |
| GET | `/api/jobs` | 任务列表 |
| GET | `/api/jobs/{id}` | 任务状态与进度 |
| POST | `/api/jobs/{id}/cancel` | 取消任务 |
| DELETE | `/api/jobs/{id}` | 删除已完成任务 |
| GET | `/api/assets` | 资产列表 |
| POST | `/api/assets` | 添加资产（自动触发发现） |
| PATCH | `/api/assets` | 修改分组/责任人/备注 |
| DELETE | `/api/assets?host=` | 移除资产 |
| POST | `/api/assets/import` | 批量导入主机 |
| POST | `/api/assets/rescan` | 重新检测单台 |
| GET | `/api/assets/export` | 资产 CSV 导出 |
| GET | `/api/php-exposure` | PHP 暴露面明细 |
| GET | `/api/php-exposure/export` | PHP 暴露面 CSV 导出 |
| POST | `/api/scan/logs` | 日志分析（服务器路径） |
| POST | `/api/scan/logs/upload` | 日志分析（文件上传，multipart） |
| POST | `/api/scan/host` | 主机侧检测 |
| POST | `/api/scan/url` | 单 URL 探测 |
| GET | `/api/host/export` | 主机台账 CSV 导出 |
| GET | `/api/host/report` | 最近一次主机侧报告 |
| GET | `/api/rules` | 规则库 |
| GET | `/api/rules/export/{fmt}` | 导出 sigma / modsecurity / suricata |
| GET | `/api/ioc` | IOC 库 |
| GET | `/api/scans` | 历史扫描 |
| GET | `/api/scans/{id}/report?fmt=` | 报告内容（md/html） |
| DELETE | `/api/scans/{id}` | 删除报告 |
| POST | `/api/agent/report` | Agent 上报接收 |

**错误约定**：统一 `{"detail": "中文错误说明"}`，HTTP 400/404/422。

### 3.8 任务队列

`core/jobs.py`，设计要点：

| 决策 | 理由 |
|---|---|
| 单工作线程（max_workers=1） | 并发扫描会打满客户网络，也可能触发 IDS 告警 |
| 状态持久化到 `jobs.json` | 控制台重启后历史仍在；运行中任务标记为「已中断」 |
| 毫秒精度时间戳 | 秒级精度会让同秒创建的多个任务排序不稳定 |
| 取消 = 协作式 | 设置 `cancel_requested`，任务在下一个检查点优雅退出 |
| 失败捕获异常与 traceback | 任务失败不影响控制台其它功能 |

**任务类型**：`discover`（设备发现）/ `logs`（日志分析）/ `host`（主机侧）/ `url`（URL 探测）

### 3.9 存储

当前是 JSON 文件（零运维成本）。规模上来后可换 SQLite/PostgreSQL，只需替换 `console/app.py` 的存储层，引擎不受影响。

```
p2s-data/
├── assets.json         资产台账
├── jobs.json           任务历史
├── scans/              每次扫描的 json/md/html 三份报告
└── uploads/            上传的日志文件
```

---
## 四、界面设计

### 4.1 设计原则

| 原则 | 具体做法 |
|---|---|
| **企业级工具，不是营销页** | 零 emoji；单色线性 SVG 图标（35 个 symbol）；单一强调色；1px 描边分层；无渐变、无装饰性阴影 |
| **信息密度高但不拥挤** | 表格紧凑行距 + 粘性表头；KPI 用等宽数字；标签用小圆角方形而非圆润胶囊 |
| **结论必须可解释** | 每条结论带证据链；分类给置信度 + 候选类型；详情抽屉列出全部判定依据 |
| **诚实报告不确定性** | 低置信度照实标 0.45%；识别不到就说「未匹配到任何产品级特征」，不编造 |
| **零外部依赖** | 单文件内联 CSS/JS/SVG，无 CDN，内网离线可用 |

**反面清单**（明确不做）：emoji 图标 · 渐变装饰条 · 径向渐变背景 · 16px 大圆角 · 满屏彩色胶囊 · 模糊阴影堆叠 · 装饰性动画

### 4.2 设计令牌

```css
:root{
  --bg:#f2f3f5;          --surface:#fff;        --surface-2:#f7f8fa;  --surface-3:#edeff2;
  --border:#dfe3e8;      --border-2:#c9cfd6;    --border-3:#aeb6c0;
  --text:#14181f;        --text-2:#545c68;      --text-3:#8a929e;
  --accent:#1f5fd0;      --accent-soft:#eef3fc; --accent-border:#c3d5f3;
  --danger:#b42318;      --warn:#b54708;        --ok:#067647;
  --neutral:#5a6472;
  --r:4px;  --r-lg:6px;  --sidebar:208px;  --topbar:56px;
  --mono: ui-monospace,"SF Mono",Menlo,Consolas,monospace;
}
[data-theme="dark"]{ /* 同名令牌换深色值，深浅切换只改这一层 */ }
```

深浅主题通过 `data-theme` 属性切换，选择存 localStorage。

### 4.3 组件清单

| 组件 | 用途 | 关键样式 |
|---|---|---|
| `card` | 内容容器 | 1px 描边 + 4px 圆角 + 极轻投影 |
| `kpi` | 指标卡 | 24px 等宽数字，语义色可选 |
| `tag` | 状态标签 | 2.5px 圆角，方形，5 种语义变体 |
| `table` | 数据表 | 粘性表头、hover 高亮、等宽字体排 IP |
| `dev` | 设备卡片 | 网格布局，hover 上浮 3px |
| `job` | 任务条 | 4px 进度条 + 状态图标 + 取消按钮 |
| `drawer` | 详情抽屉 | 右侧滑入 540px，遮罩模糊 |
| `editable` | 行内编辑 | hover 显示底色，focus 蓝边 |
| `dz` | 拖拽上传区 | 虚线框，拖入变蓝 |
| `seg` | 分段控件 | 容器灰底，选中项白底 |

### 4.4 页面清单（10 个）

| 页面 | 主要内容 | 关键交互 |
|---|---|---|
| **态势总览** | 6 个 KPI、暴露面环形图（SVG）、设备类型条形图、最近扫描表 | 跳转设备发现/报告中心 |
| **设备发现** | 目标输入（CIDR/主机列表/分组）、快速↔深度切换、预计耗时、任务进度条、结果卡片网格 | 提交任务、取消、点开详情 |
| **任务中心** | 运行中任务（进度+取消）、历史任务（可删） | 取消、删除、查看结果 |
| **资产台账** | 表格（主机/类型/产品/厂商/技术栈/PHP/暴露面/置信度/分组/负责人） | 筛选、搜索、行内编辑、复扫、删除、CSV 导出、批量导入 |
| **PHP 暴露面** | 4 个 KPI + 受影响资产明细 + 修复基线 | CSV 导出 |
| **日志分析** | 路径输入 + 拖拽上传、命中明细、**规则覆盖缺口** | 上传、查看报告 |
| **主机侧检测** | 风险 KPI、安装点、生效配置、可疑痕迹 | 执行检测、台账 CSV 导出 |
| **规则中心** | 13 条规则明细 | 导出 Sigma / ModSecurity / Suricata |
| **IOC 中心** | 基础设施、dropper URL、样本哈希 | 复制 |
| **报告中心** | 历史扫描表 | 查看、下载 MD/HTML、删除 |

### 4.5 响应式与无障碍

- 断点 1180px：双栏图表区折为单栏；1100px 以下 dev 网格自适应
- 语义化标签（`aside`/`header`/`main`/`nav`）、`aria` 标签、`contenteditable` 行内编辑
- 键盘可达：Tab 焦点环（`--accent-soft` 3px 外发光）
- 颜色不是唯一信息载体：所有状态同时有文字

---

## 五、部署与交付

### 5.1 三种形态

| 形态 | 组成 | 适用 | 交付物 |
|---|---|---|---|
| **A 私有化部署** | Docker Compose：console 容器 + `p2s_data` 卷 | 客户有运维能力、要留数据在自己内网 | `docker-compose.yml` |
| **B 单机部署** | Python venv + `p2s serve` | 客户不允许 Docker | `pip install -e ".[console]"` |
| **C 无头/CLI** | 仅 `p2s` 命令 | CI/CD、批处理、集成进客户平台 | `p2s assets/probe/logs/host/discover` |

### 5.2 环境要求

| 项 | 要求 |
|---|---|
| 操作系统 | Linux (x86_64/arm64)、Windows Server 2016–2025 / Win10-11、macOS (Intel/ARM) |
| Python | ≥ 3.9 |
| 内存 | ≥ 1 GB（扫描并发受端口数限制，单机 100MB 足够） |
| 网络 | 需能直连被扫目标（同一网段或可达路由） |
| 特权 | **不需要** root / 原始套接字 |
| 容器 | Docker 20.10+ / Compose v2（形态 A） |

### 5.3 目录与配置

| 路径 | 环境变量 | 说明 |
|---|---|---|
| 数据目录 | `P2S_DATA_DIR` | 默认 `./p2s-data` |
| 监听地址 | `--host` | 默认 `127.0.0.1` |
| 端口 | `--port` | 默认 `18080`，被占用自动顺延 |

### 5.4 升级与回滚

```
升级：拉新镜像/新代码 → 备份 p2s-data → 停服 → 起新 → 验证 /api/health 与首页
回滚：还原上一版本 + 还原 p2s-data 备份
```

**数据向后兼容**：新增字段一律可选；旧 assets.json 可直接被新版本读取。

### 5.5 Agent 部署（形态 A/B 的补充）

L3 主机侧检测必须在目标主机本地执行。

```bash
# Linux systemd timer
ExecStart=/usr/local/bin/p2s-agent --console http://console.internal:18080 --interval 3600

# Windows 计划任务
p2s-agent.exe --console http://console.internal:18080 --interval 3600
```

---

## 六、安全设计

### 6.1 红线（写进代码，也有测试守护）

| # | 红线 | 落实方式 |
|---|---|---|
| 1 | **探针绝不含利用载荷** | `tests/test_probe.py` 断言探针不含 `<?php`/`system(`/`eval(`/`base64` |
| 2 | **源码不含完整 PHP 载荷字面量** | `scripts/check_payload_literals.py`，CI 门禁（否则工具会被客户杀毒拦） |
| 3 | **报告输出前脱敏** | `core/redact.py` 把 PHP 代码块/序列化对象/命令调用替换为结构占位符，避免报告被拦与载荷二次传播 |
| 4 | **主机侧操作只读** | 只读文件/进程/连接，不改配置、不删文件、不 kill 进程 |
| 5 | **主动探测需授权** | 文档与界面明示；探针尺寸保守（gentle 档 50KB 级） |
| 6 | **通用词不作厂商判据** | `tests/test_identification.py` 守护 |
| 7 | **不请求授权绕过** | 只做识别，不爆破、不尝试默认口令 |

### 6.2 威胁建模

| 威胁 | 缓解 |
|---|---|
| 工具被用于未授权扫描 | 部署文档要求书面授权；`p2s` 无自动爬取能力，目标必须显式提供 |
| 控制台未鉴权被他人使用 | ⚠️ **当前待修复**（FR-19）。当前只监听 127.0.0.1；对外暴露前必须加认证 |
| 扫描流量触发客户 IDS 告警 | 提供 `--quick` 模式与端口范围收敛；建议先小范围试跑；告知客户会产生连接日志 |
| 扫描导致生产服务过载 | 单工作线程串行；探针尺寸保守；`pm.max_requests` 建议 |
| 报告泄露攻击样本 | `core/redact.py` 脱敏 |
| 工具自身被当成恶意软件 | 载荷字面量守护检查 |

### 6.3 授权与合规

交付前必须与客户书面确认：
1. 授权扫描的资产范围（IP 段 / 网段清单）
2. 扫描时段（避免业务高峰）
3. 日志留存与数据出境策略
4. 主机侧检测是否需要（涉及进程/连接可见性）
5. WAF/IDS 是否需要提前加白名单

---

## 七、性能与容量

### 7.1 实测基线（`192.168.1.0/24`，254 台）

| 指标 | 快速模式 | 深度模式 |
|---|---|---|
| 单台耗时 | 1.4s | 2.5s |
| /24 总耗时 | 361s（6 min） | ~11 min |
| 端口探测并发 | 96 线程 | 96 线程 |
| 单台服务探测并发 | 12 线程 | 12 线程 |
| 内存占用 | < 120 MB | < 150 MB |

### 7.2 性能设计要点

| 优化 | 效果 |
|---|---|
| 各端口**并行**探测 | 一台开 8 端口的设备几乎不增加耗时（串行是 8 倍） |
| 邮件/文件端口**不先试 HTTP** | tarpit 端口上白等一个 HTTP 超时 → 每台省 ~3s |
| 快速模式 banner 超时 0.5s | 真实服务 <100ms 就响应，0.5s 足够 |
| 路径阶梯带截止时间 | 单端口最多 10s，不会无限重试 |
| 任务队列单线程 | 避免并发打满客户网络 |

### 7.3 容量预估

| 数据量 | 存储 | 备注 |
|---|---|---|
| 1 万台资产 | assets.json ≈ 30 MB | 建议换 SQLite |
| 10 万次扫描报告 | ≈ 3 GB | 建议加保留策略（如 90 天） |
| 1000 并发任务 | 队列内存 ≈ 200 MB | 单线程串行下不现实，需拆多实例 |

---

## 八、测试策略

### 8.1 分层

| 层 | 位置 | 数量 | 内容 |
|---|---|---|---|
| 单元测试 | `tests/` | 81 | 版本判定、规则匹配、签名库自检、分类引擎、存活判定、任务队列、脱敏、探针红线 |
| 集成/回归 | 手工脚本 + CI | 26 项 | 30 个端点、离线不入库、任务全流程、上传、行内编辑、报告删除 |
| 实网验证 | 客户网段 | 12 台 | 真实设备识别准确率 |
| CI | `.github/workflows/ci.yml` | 3 平台 × 3 Python | pytest + ruff + 载荷守护 + 镜像构建 |

### 8.2 质量门（CI 必过）

```
pytest 81 passed
ruff check src tests scripts        # 零告警
python scripts/check_payload_literals.py .   # 源码无完整载荷字面量
docker build                         # 镜像可构建
```

### 8.3 测试数据策略

**全部测试基于实测数据**，不臆造：

| 测试 | 数据来源 |
|---|---|
| `test_jumpserver_by_server_header` | 实测 `Server: Jump_server` + `CN=server,OU=yanfa,O=jump` |
| `test_nac_title_beats_generic_server_header` | 实测 .227：Server 泛匹配 vs 标题特异 |
| `test_huawei_ibmc_by_title` | 实测 .252：`iBMC Login` |
| `test_huawei_switch_by_cert_cn` | 实测 .253：`CN=Quidway,O=FutureMatrix` |
| `test_filezilla_by_banner` | 实测 .15：`220-FileZilla Server 0.9.60 beta` |
| `test_php_detected_by_cookie` | 实测 .230：无 X-Powered-By，仅 `PHPSESSID` |
| `test_tarpit_ports_are_not_alive` | 实测：254 台全在 25/110/143 可连但零响应 |

---

## 九、开发规范

### 9.1 代码约定

| 项 | 约定 |
|---|---|
| 目录 | `core/` 纯引擎（无 HTTP 依赖）· `console/` API 与界面 · `agent/` 主机侧 · `cli.py` 入口 |
| 类型标注 | 全量标注，`Optional[X]` 而非 `X \| None`（兼容 3.9） |
| 异常 | 引擎层捕获所有网络异常并记录，不向上抛；`except Exception` 必须带 `# noqa: BLE001` |
| 日志 | 用 `logging`，不用 `print`（CLI 除外） |
| 注释 | 解释**为什么**，不复述代码 |
| 编码 | `.py`/`.toml` UTF-8 **无 BOM**；`.ps1` UTF-8 **有 BOM**（Windows PowerShell 5.1 按 ANSI 解码无 BOM 的 UTF-8 会语法报错） |

### 9.2 新增检测规则的流程

1. 在 `core/signatures.py` 增加 `Sig`（字段 + needle → 类型/厂商/产品 + 权重）
2. 若需新字段，在 `core/identification.py` 的 `observations` 采集处加一行
3. 在 `tests/test_identification.py` 加一条**基于实测数据**的用例
4. 跑 `pytest` + `ruff`

**新增日志规则的流程**：`core/rules.py` 加 `Rule` → `core/logscan.py::_match` 加分支 → 补测试。

### 9.3 版本号规范

`MAJOR.MINOR.PATCH`
- MAJOR：数据模型或 API 不兼容变更
- MINOR：新功能
- PATCH：修复

### 9.4 提交规范

```
feat: 新功能
fix: 缺陷修复
refactor: 重构（行为不变）
perf: 性能
docs: 文档
test: 测试
```

---

## 十、路线图

| 优先级 | 事项 | 说明 |
|---|---|---|
| **P0** | **控制台认证** | 登录 + 会话 + 简单用户管理。当前无鉴权，对外暴露即风险 |
| **P0** | 资产存储换 SQLite | JSON 文件在数千条资产后难用 |
| P1 | 定时扫描调度 | 按 cron/间隔自动扫网段并入库 |
| P1 | 规则导出增强 | 输出可直接对接 Elastic/ Splunk 的字段映射 |
| P1 | OUI 库完整化 | 内置表扩充；可支持从内网镜像源更新 |
| P2 | SNMP sysDescr | 需 161 端口可达，当前环境被拦 |
| P2 | favicon mmh3 哈希库 | 比 sha256 更通用（可与 Shodan 对齐） |
| P2 | 容器镜像层扫描 | 离线解包镜像查 PHP 版本 |
| P2 | 报告模板化 | 客户品牌 Logo、章节定制 |
| P3 | 资产变更检测 | 只对新增/状态变化的资产告警 |

---

## 十一、已知限制

| 限制 | 原因 | 影响 | 规避 |
|---|---|---|---|
| 无法确定部分 PHP 版本 | 目标不暴露 `X-Powered-By` 且无其它线索 | 结论为 `unknown`，需人工确认 | 在目标上执行 `php -v` |
| SNMP 型号不可得 | 161 端口被防火墙拦截 | 缺少最精确的型号信息 | 走 HTTP/证书标签 |
| 无反向 DNS | 网段无 PTR 记录 | 无法用主机名辅助判断 | 依赖标签与 MAC |
| OUI 覆盖不全 | IEEE 在线接口返回 418（反爬） | 部分 MAC 显示「厂商未收录」 | 内置表已覆盖主流厂商，可扩充 |
| tarpit 端口消耗扫描时间 | 无法预知哪些是噪声端口 | 每台多花 ~1s | 已优化至 1.4s/台 |
| 无认证 | 未实现 FR-19 | 对外暴露有风险 | 仅监听 127.0.0.1 |

---

## 附录 A 术语表

| 术语 | 含义 |
|---|---|
| **php2shell** | CVE-2026-109618 + CVE-2026-109619 的通称 |
| **SAPI** | PHP 的服务器接入层（mod_php / FPM / php-cgi / LiteSpeed），决定漏洞利用路径 |
| **修复基线** | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| **KEV** | CISA「已知被利用漏洞」目录 |
| **tarpit** | 接受 TCP 连接但永不回应数据的服务/策略 |
| **全锥 NAT** | 允许任意外部主机发起连接的 NAT 模式，会导致端口探测假阳性 |
| **OUI** | MAC 地址前 3 字节，标识网卡厂商 |
| **PHPSESSID** | PHP 会话 Cookie，是判定 PHP 应用的可靠线索 |
| **上传进度（upload_progress）** | PHP 的会话上传进度功能，php2shell 攻击链的关键生产者 |
| **暴露面（exposure）** | 一台设备与本次漏洞的暴露关系：exposed / patched / not_php / unknown / not_applicable |

## 附录 B 关键参考资料

| 类别 | 链接 |
|---|---|
| PHP 官方安全公告 | https://www.php.net/archive/2026.php#2026-10-21-5 |
| PHP 信息性公告（CVE-2026-115560） | https://www.php.net/archive/2026.php#2026-10-23-1 |
| GitHub Advisory | https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w |
| CISA 警报 | https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| NCSC-NL 运营情报 | https://github.com/NCSC-NL/php2shell |
| TU Delft 在野观测 | https://php2shell.delftintellab.com/ |
| CERT-EU 2026-018 | https://cert.europa.eu/publications/security-advisories/2026-018/ |
| 社区规则参考 | https://github.com/ikow/php2shell-poc |
| NSA 公告 | https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4630238/ |