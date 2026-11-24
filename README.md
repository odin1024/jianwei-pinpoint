# PHP2Shell 检测工具 · 见微 Pinpoint

> 针对 **CVE-2026-109618**（OOM 内存破坏）/ **CVE-2026-109619**（陈旧全局状态 UAF）的
> PHP 暴露面评估与失陷排查工具。两个漏洞 CVSS v4 **9.2**，修复基线
> **PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**，2026-10-21 官方发布，已被 CISA KEV 收录（2026-10-26）。

本目录由原 `workbuddy/`（立项文档 + M1 原型）与 `zui/`（成品 + 交付物）合并整理而来。
代码只有一份，文档按用途分三层，历史产物归档保留。

---

## 一、目录结构

```
PHP2Shell漏洞检测工具/        ← Git 仓库根（含文档、工具与代码）
├── app/                       ★ 唯一代码工程（可直接运行）
│   ├── src/p2s/               引擎（core/）+ 命令行（cli.py）+ 控制台（console/）+ Agent
│   ├── tests/                 121 个用例
│   ├── docs/                  技术文档（架构/检测原理/平台/交付）+ 截图
│   ├── scripts/               启停脚本 · 载荷守护 · 控制台验收脚本
│   ├── examples/              示例日志与主机清单
│   ├── p2s-data/              运行时数据（资产台账 assets.json + 历史报告 scans/）
│   └── .venv/                 已装好依赖的虚拟环境（Python 3.12）
├── docs/
│   ├── 01-立项/               5 份立项文档（事件分析/PRD/架构/引擎方案/实施计划）+ 原型手册
│   ├── 02-产品/               设计文档、评审报告、交付包索引、**v0.5.1 修复清单**
│   │   └── schema与规则包/    schema.sql、php2shell-vuln-db.yaml（设计契约，非运行依赖）
│   ├── 03-情报/               情报报告 + 2 份 GHSA 原文 + 附录 A/B
│   │   └── 证据/              NVD 抓取、GHSA 列表、PHP NEWS、CVE 原文（事实核查用）
│   └── assets/                Logo（SVG）与多尺寸预览
├── samples/                   示例报告、样例日志、暴露面自查脚本
├── dist/                      打包产物（v0.5.1 完整交付包 + 仅源码包）
├── tools/package_release.py   重新打包脚本
└── archive/                   M1 原型代码、媒体稿草稿（保留但不维护）
```

---

## 二、三分钟跑起来

```powershell
cd app
# 1.0.5 起没有内置默认口令：必须显式设置，否则每次重启随机生成并打印到启动日志
$env:P2S_ADMIN_PASSWORD = "换成你的强口令"
.\.venv\Scripts\python.exe -m p2s.cli serve --port 18080   # 浏览器开 http://127.0.0.1:18080
```

已装好依赖，无需重新 `pip install`。常用命令：

```powershell
.\.venv\Scripts\python.exe -m p2s.cli discover --cidr 192.168.1.0/24 --report reports\  # 设备发现
.\.venv\Scripts\python.exe -m p2s.cli logs --file examples\access.log.sample --report reports\  # 日志分析
.\.venv\Scripts\python.exe -m p2s.cli host --report reports\   # 本机 PHP 检查
.\.venv\Scripts\python.exe -m p2s.cli rules                     # 查看 13 条规则
```

> 端口被占用时 `serve` 会自动顺延，也可用 `--port` 指定。

---

## 三、能力边界（重要）

| 做 | 不做 |
|---|---|
| 端口/协议/存活/设备类型/PHP 暴露面五层收敛 | 不做通用漏扫 |
| **跨主机噪声端口识别**（NAT/tarpit 环境不产生假设备） | 不发送利用载荷、不做打穿验证 |
| **资产变更检测**（新增 / 变更 / 消失，保留变更历史） | 不修改被检系统 |
| 13 条数据驱动日志规则 + 行为关联 | 无定时调度（变更检测已具备，自动排期未做） |
| 主机侧只读检测（安装点/生效配置/痕迹/进程/连接） | 控制台已加登录口令，默认只监听回环地址 |
| 报告导出 JSON / Markdown / HTML / CSV | |

**授权**：对非自有资产执行主动探测必须事先取得书面授权。控制台默认仅监听 `127.0.0.1`。

---


## 项目结构

```
PHP2Shell漏洞检测工具/        ← Git 仓库根（含文档、工具与代码）
├── app/                    代码与发行包（CI 在 app/.github/）
│   ├── src/p2s/
│   │   ├── core/           引擎：探测/识别/取证/日志/规则/报告
│   │   │   ├── discovery.py     端口→协议→存活→指纹→PHP 暴露面
│   │   │   ├── identification.py 证据分级 T1/T2/T3 与签名匹配
│   │   │   ├── signatures.py     设备/应用签名库（163 条）
│   │   │   ├── binforensics.py   M5 二进制取证（PE 时间戳 / ELF build-id）
│   │   │   ├── containers.py     Docker / K8s 容器内 PHP 清点
│   │   │   ├── hostcheck.py      主机侧只读取证
│   │   │   └── report.py         报告渲染（MD / HTML / JSON）
│   │   ├── console/        控制台：app / deps / 4 个路由模块 / ui + ui_pages
│   │   └── agent/          采集端
│   ├── scripts/            验收、载荷守护、依赖审计、报告重渲染
│   ├── tests/              201 项测试（含契约/版本/取证）
│   └── docs/               截图与交付说明
├── docs/                   立项 / 产品 / 情报 / 部署 文档
├── samples/                样例日志与报告
├── archive/                历史原型（不参与构建）
├── tools/                  打包脚本
├── CHANGELOG.md            版本记录（发布前必须更新）
└── CONTRIBUTING.md         开发规范（每条都对应一次真实事故）
```

## 四、当前状态（2026-11-25 实测）

| 项 | 值 |
|---|---|
| 版本 | **1.1.3**（单一来源：`app/src/p2s/__init__.py`）|
| 单元测试 | **537 passed**（44 个用例文件）|
| 加固规则库 | **112 条**（11 类：会话/信息暴露/高危特性/资源/日志/FPM/Web 服务器/系统服务/K8s/Windows-IIS/Windows 权限）|
| 覆盖 CVE | CVE-2026-109618、CVE-2026-109619 |
| 修复基线 | 8.5→8.5.12 · 8.4→8.4.27 · 8.3→8.3.36 · 8.2→8.2.35 |
| 加固层次 | PHP ini / PHP-FPM / Web 服务器 / systemd / Kubernetes |

**门禁**（改完必跑，见 [`CONTRIBUTING.md`](./CONTRIBUTING.md)）：

```powershell
cd app
$env:P2S_ADMIN_PASSWORD = "你的口令"      # 1.0.5 起无内置默认口令
.\.venv\Scripts\python.exe -m pytest -q          # 537 passed
.\.venv\Scripts\python.exe -m ruff check src tests scripts
.\.venv\Scripts\python.exe scripts\verify_console.py      # 29 项
.\.venv\Scripts\python.exe scripts\check_page_js.py       # 内联 JS 语法
.\.venv\Scripts\python.exe scripts\check_page_html.py     # 标签配平
.\.venv\Scripts\python.exe scripts\check_api_consistency.py  # 前后端接口一致
```

**历史实测记录**（2026-10-30）：`192.168.1.0/24` 全子网 254 台探测 → 17 台在线，
设备识别捷普 10 / 华为 3 / FileZilla 2 / 小米 1 / 未识别 2，无跨厂商误判。
该网段现已不可达，相关资产已于 1.1.3 清理，仅保留真实主机。

**文档地图**：本项目文档分两处，分工与权威性见 **[`docs/README.md`](./docs/README.md)**。
- `docs/` — 立项 / 产品 / 情报 / 部署（决策与背景）
- `app/docs/` — 架构 / 检测原理 / 平台适配 / 客户部署（**技术描述以此为准**，随代码走）
- [`CHANGELOG.md`](./CHANGELOG.md) — **变更记录的唯一权威来源**

---

## 五、许可与使用授权

### 开源协议

本项目采用 **Apache License 2.0**（见 [`LICENSE`](./LICENSE)），附带 [`NOTICE`](./NOTICE) 说明
第三方依赖与情报素材的来源与版权。

- ✅ 可商用、可修改、可闭源分发
- ✅ 含**专利授权**（第 3 条），企业客户合规审查更容易通过
- ⚠️ 修改后的文件需保留变更说明；须随分发附上本许可
- ⚠️ 许可**不授予**使用本项目商标与商品名的权利（第 6 条）

### 使用授权（请务必阅读）

这是一个**主动探测**工具。对非自有资产执行扫描，
在很多司法辖区属于违法行为，并可能触发对方的安全响应。

**使用前请确认：**

1. 目标资产属于你本人，或你已取得**书面授权**（含探测范围与时窗）；
2. 已告知目标系统的运维方，避免被误判为攻击而中断业务；
3. 扫描频率与并发控制在业务可承受范围内（本项目默认保守，勿随意调高）。

**平台的设计约束（按此实现，不是口头承诺）：**

| 约束 | 实现方式 |
|---|---|
| 不主动外联 | 只连接你填写的目标，无遥测、无回连 |
| 控制台默认仅监听回环 | `serve` 默认 `127.0.0.1`，对外暴露需显式 `--host 0.0.0.0` |
| 加固不直连主机 | 生成"包"由你在目标机执行，平台不远程改配置 |
| 加固不等于修复 | 只降低攻击面；唯一完整修复是升级 PHP 到修复版本 |

### 免责声明

本软件按"现状"提供，不附带任何明示或暗示的担保。
因使用本软件造成的任何直接或间接损失（含业务中断、数据损坏、
法律纠纷），作者与贡献者不承担责任。**使用即表示你已理解并接受上述约束。**
