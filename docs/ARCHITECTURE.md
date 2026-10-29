# 架构说明

## 设计目标

1. **同一套引擎，三种形态。** CLI、控制台、Agent 共用 `p2s.core` 下的检测逻辑，
   避免出现"控制台能查、CLI 查不了"的行为分叉。
2. **按风险分层，越往下越危险。** L1 被动（零风险）→ L2 主动探针（需授权）→ L3 主机侧（需权限）。
   每一层可独立使用，也可组合。
3. **结论必须可解释。** 每条结论都带证据（evidence）和置信度，不给黑盒二元判断。
4. **默认离线可用。** IOC 库与规则库内置，无网也能跑。

---

## 检测分层

| 层 | 模块 | 输入 | 输出 | 风险 |
|---|---|---|---|---|
| **L1 被动** | `core/logscan.py` + `core/rules.py` | Web 日志 / WAF 日志 / IDS 告警流 | Finding 列表 + 规则覆盖度 | 零 |
| **L2 主动** | `core/probe.py` + `core/fingerprint.py` | HTTP 响应 | 版本、SAPI、探测结论 + 置信度 | 低（需授权） |
| **L3 主机** | `core/hostcheck.py` | 本机文件系统 / 进程 / 连接 | 安装点、配置、痕迹 | 无外发（需权限） |

三层产出统一进 `core/report.py`，生成 JSON / Markdown / HTML 三种报告。

---

## 模块依赖

```
cli.py ─┬─> core.fingerprint ─┐
        ├─> core.probe ───────┤
        ├─> core.logscan ─────┼─> core.report
        ├─> core.hostcheck ───┤
        └─> core.ioc ─────────┘
console/app.py  ──> 同上（走 HTTP API）
agent/agent.py  ──> core.hostcheck + core.report
```

`core.versions` 被 `fingerprint` / `probe` / `hostcheck` / `logscan` 共同依赖，是最底层的纯函数模块。

---

## 规则引擎

规则是**数据驱动**的，定义在 `core/rules.py`：

```python
Rule(
    id="P2S-REQ-001",
    name="multipart 请求体含 PHP_SESSION_UPLOAD_PROGRESS",
    dimension="request",     # request | response | host | behavior | recon
    severity="critical",
    cves=CVES,
    requires="body",         # 命中所需的日志字段
    description="...",
    matcher="upload_progress",  # 对应 logscan._match() 的分支
)
```

加一条规则 = 加一个 `Rule` + 在 `_match()` 里加一个分支 + 补一个测试。引擎本身不需要改。

### 规则覆盖度是显式的一等公民

标准访问日志**不记录请求体**。因此标注 `requires="body"` 的规则在普通访问日志里
**永远命中不了**。工具在扫描结束时会输出 `coverage.uncovered`，
提示客户"要覆盖这几条规则，需要开启请求体/响应体落盘"。

这是一个刻意设计：宁可告诉你覆盖不了，也不让你误以为已经安全。

---

## 判定逻辑（为什么不是黑盒）

### 版本判定（`core/versions.py`）

| 状态 | 含义 |
|---|---|
| `patched` | 版本 ≥ 该分支修复基线 |
| `vulnerable` | 版本 < 修复基线 |
| `eol_backport_available` | 8.1/8.0/7.4 —— 已 EOL，但 PHP 团队提供最小源码回补 |
| `eol_unpatchable` | 5.x/7.0-7.3 —— 已 EOL，无补丁 |
| `dev_branch` | 8.6 RC —— 含修复但不可上生产 |
| `unknown` | 版本解析不出来 |

### 主动探测结论（`core/probe.py`）

先发一个 42 字节级别的**控制请求**建立基线，再发探针，比较两者差异：

| 观察到的差异 | 解释 |
|---|---|
| 响应体含 PHP 内存耗尽错误 | mod_php 强信号 |
| 差分空 500（控制 200 → 探测 500 且响应体为空） | FPM worker 崩溃 |
| 响应耗时接近超时 | 疑似 worker 重启/卡死 |

结论是**置信度**而非布尔值：

- 探测有差异 + 版本未修复 → `vulnerable`，置信度 0.7~0.9
- 探测有差异 + 版本已修复 → `suspect`，并提示可能是已知误报场景
  （Assetnote 已在已修补的 8.4.27 + `memory_limit` 2M~32M、8.3.36 + `max_multipart_body_parts ≥ 2785` 上复现过误报）

### 行为关联（`core/logscan.py`）

单条规则命中是"证据"，多条按攻击链组合才是"判定"。已实现的关联：

- 同源 IP 在时间窗内多次 upload_progress 探测 → 自动化扫描
- 探测 + 5xx + LFI 参数 → 完整攻击链
- 扫描器 UA 聚集 → 已知工具活动

---

## 探针安全设计

`core/probe.py` 只实现两条**无害**探针：

| 探针 | 原理 | 尺寸档位 |
|---|---|---|
| `header_amplification` | 单个 multipart 分段内塞入大量自定义 header。PHP 内部表示内存约为线上体积的 3~5 倍 | gentle: 400×120B；standard: 1200×200B |
| `nested_arrays` | 空文件控件 + 嵌套字段名。空文件控件不计入 `max_file_uploads`，却仍生成完整元数据数组 | gentle: 5×8；standard: 8×16 |

**不发**的东西：PHP 代码、伪造 zval、序列化 gadget 链、超大 body。
`tests/test_probe.py` 里有断言强制这一点。

---

## 数据存储

当前用 JSON 文件（`P2S_DATA_DIR`，默认 `./p2s-data`）：

```
p2s-data/
├── assets.json      # 资产台账
└── scans/           # 每次扫描的 json/md/html 三份报告
```

规模上来后换成 SQLite 或 PostgreSQL，只需替换 `console/app.py` 里的存储层，
引擎不受影响。

---

## 扩展点

| 想加什么 | 改哪里 |
|---|---|
| 新检测规则 | `core/rules.py` + `core/logscan.py::_match` |
| 新 IOC | `core/ioc.py` |
| 新 SAPI 识别特征 | `core/fingerprint.py::SAPI_SIGNATURES` |
| 新探针 | `core/probe.py`（记得同步加"不含载荷"断言） |
| 接 SIEM | 导出 Sigma —— 参考 `ikow/php2shell-poc` 的格式 |
| 接 WAF | 导出 ModSecurity / Suricata 规则 |