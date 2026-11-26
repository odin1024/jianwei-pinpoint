# 变更记录（CHANGELOG）

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)：`主版本.次版本.修订号`

- **主版本**：不兼容的接口/数据格式变更（例如资产台账结构、Agent 上报协议）；
- **次版本**：向下兼容的功能新增（新接口、新检测能力、新页面）；
- **修订号**：向下兼容的问题修复（bug、文案、样式、性能）。

记录格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)：
`新增 / 修复 / 变更 / 安全 / 移除`。**每条都要能对应到代码或测试**，不写"优化了体验"这种空话。

版本号唯一来源是 `app/src/p2s/__init__.py` 的 `__version__`，`tests/test_version.py`
会校验它与 `pyproject.toml`、本文件最新条目三者一致。

---


## 版本节奏（本项目约定）

| 阶段 | 次版本（x.Y.z） | 修订号（x.y.Z） |
|---|---|---|
| **0.x（当前，内部/试点）** | 一批**可感知**的功能或界面变化 | 只修 bug、不动交互与接口 |
| **1.x 起（对外交付）** | 向下兼容的新能力 | 向下兼容的修复 |
| 主版本 | 不兼容变更：资产/报告数据结构、Agent 上报协议、接口路径 | — |

**规则**

1. 版本号唯一来源 `app/src/p2s/__init__.py`，`pyproject` / `CHANGELOG` / 登录页版本由它投影；
2. **不写 CHANGELOG 不算发布**；每条要能对应到代码或测试；
3. 一批改动做完 → 升次版本 + 写记录 → 跑四道闸（pytest / ruff / 验收 / 载荷守护）；
4. 交付客户前先跑 `tools/package_release.py`，产物只保留当前版本；
5. 1.0.0 的触发条件：接口与数据格式冻结、Agent 双平台真机验证完成、有至少一套客户环境的完整落地记录。

---

## [1.5.8] - 2026-11-26

主题：**预算没覆盖外部命令 —— 容器/K8s 清点是真正的黑洞**

### 一、前两轮都没修对，因为漏掉了这一段
1.5.6 给 `scan_artifacts` 加预算、1.5.7 给 `_iter_recent_files` 加预算，
但 `run_host_check` 里**容器与 K8s 清点**（`scan_containers` / `scan_kubernetes`）
完全没有预算 —— 它们在磁盘扫描之前执行：

```python
for _scanner, _label in (("scan_containers", "容器"), ("scan_kubernetes", "Kubernetes")):
    _items, _notes = _fn()      # ← 这里没有任何预算约束
```

### 二、为什么这段在 runner 上会爆
GitHub runner **装了 docker CLI 但 daemon 没起**。此时 docker 客户端会反复
重连 socket，单个命令就能耗掉十几秒；容器多时 `docker exec` 还是**串行**的，
线性累加。

实测（云主机模拟 docker 挂起，每条命令睡 3 秒）：

| 预算 | 实际耗时 | 结果 |
|---|---|---|
| 8 秒 | **8.26 秒** | 收工，如实记录"进程枚举已跳过" |

修复前后差别：修复前同样的场景会一路跑到 120 秒以上被判超时。

### 三、修复
| 改动 | 作用 |
|---|---|
| `run_host_check` 建 `deadline` + `_left()` | 每一步之前检查总预算，超时就跳过并记录原因 |
| `scan_containers(deadline=)` | 逐个容器检查预算；超时说明"共 N 个，已检查 M 个，剩余未检查" |
| `scan_kubernetes(deadline=)` | 超时直接返回并说明 |
| `_probe_inside(name, timeout=)` | 单次 `docker exec` 的超时按剩余预算收敛（`max(1.0, min(10.0, left))`）|
| 各步骤跳过时写 `errors` | **不许静默**：报告里要能看出哪一步因预算被跳过 |

### 四、门禁扩到 13 项
新增 3 项，全部针对"外部命令卡住"：
| 用例 | 断言 |
|---|---|
| docker 卡住时仍按时收工 | 8 秒预算 + 每条 docker 命令睡满 → 45 秒内返回 |
| 容器清点能接收 deadline | `scan_containers` / `scan_kubernetes` 签名含 `deadline` |
| 已超时则立刻跳过 | 返回说明里必须提到"时间预算" |

同时更新 `test_container_verdict.py` 的桩签名（`_probe_inside` 新增 `timeout`）——
这类"桩不接受新参数"的失败，正是接口变更该有的连带反应。

### 五、三轮排查的教训
| 轮次 | 以为的根因 | 实际 |
|---|---|---|
| 1.5.6 | 逐文件算哈希太慢 | 只是其中一半 |
| 1.5.7 | 遍历器没看预算 | 只是其中一半 |
| 1.5.8 | 容器/K8s 外部命令无预算 | **剩下的一半** |

教训：**"加了预算"不等于"预算覆盖了所有耗时路径"**。
必须按执行顺序把每一步都过一遍，而不是修完最显眼的那处就以为完事。

### 六、回归
`pytest 559 passed`（+5）/ ruff 全绿（本机）。
云主机模拟 docker 挂起：16 项相关测试全过，8 秒预算实测 8.26 秒收工。

---

## [1.5.7] - 2026-11-26

主题：**给取证遍历本身加预算 —— 上一轮只约束了处理，没约束遍历**

### 一、上一轮修复为什么不够
1.5.6 给 `scan_artifacts` 加了时间预算，但预算只在**每处理一个文件时**检查。
问题在于：`_iter_recent_files` 内部的 `os.walk` 本身就可能耗时很久 ——
一个巨型目录树光 `stat` 就能吃掉几十秒，而 `os.walk` 在产出第一个文件之前
可能已经遍历了几万个目录项。**检查点放错了层级。**

CI 实测仍然 `Timeout (>120.0s)`，两个用例挂掉：
- `test_host_job.py::test_host_job_runs_to_completion`（自带 60 秒等待，任务仍在 running）
- `test_hostcheck_perf.py::test_run_host_check_completes_quickly`

### 二、修复
| 改动 | 作用 |
|---|---|
| `_iter_recent_files(deadline=...)` | 遍历器**每进一个目录、每取一个文件**都查预算；预算耗尽直接 return |
| `run_host_check(budget_seconds=60.0)` | 整体取证有**总**预算，不再只有子步骤有 |
| 痕迹扫描取总预算的 60% | 给后面的进程/连接枚举留余量（`max(5.0, budget*0.6)`）|
| 截断判定补全 | 遍历器自己 return 时上层收不到信号，用"预算是否已耗尽"补判 |

### 三、为什么必须有两层预算
`scan_artifacts` 的预算管"我处理多少文件"；
`_iter_recent_files` 的预算管"我遍历多少目录项"；
`run_host_check` 的预算管"整个取证多久必须收工"。

这三层缺任何一层，在超大规模目标机上都会挂住 —— 而开发机永远看不出来
（`/tmp` 是空的，`os.walk` 瞬间结束）。

### 四、跨机实测（同一份代码）
| 环境 | budget=10s | budget=60s |
|---|---|---|
| 云主机 Ubuntu 22.04 | **8.5 秒** | 22.95 秒 |
| 本机 Windows | — | 10.7 秒 |

分步耗时（云主机）：`enumerate_php_installs` 0.02s /
`scan_artifacts` 16.02s / `list_processes` 0.45s / `list_connections` 0.09s。
**预算生效**：10 秒预算下整体 8.5 秒收工。

### 五、新增门禁（性能门禁扩到 10 项）
| 用例 | 断言 |
|---|---|
| 整体取证受总预算约束 | `run_host_check(budget=10)` 在 45 秒内返回 |
| 遍历器认 deadline | 8000 个文件 + 0.5 秒预算 → 必须提前停止 |

这两项在**修复前会失败**（前者超时，后者遍历完才返回），是真正的回归护栏。

### 六、回归
`pytest 554 passed` / ruff 全绿（本机）。
CI 待下一轮验证。

---

## [1.5.6] - 2026-11-26

主题：**CI 第三轮定位到真正根因 —— 本地取证的性能缺陷（不是测试问题）**

### 一、根因：取证扫描退化成了"逐文件算 SHA-256"
`scan_artifacts` 的顺序错了：**先算哈希，后判后缀**。
候选来自 `_iter_recent_files`（mtime >= since，默认 2026-10-20 披露窗口）。

GitHub runner 的系统文件（`/opt`、`/var/lib/php` 等）的 mtime 是**镜像构建时间**，
通常就在最近几周 —— 正好晚于 since。于是几千个系统文件全部进入候选，
每个都要读一遍算 SHA-256。上限 4000 个文件 → **分钟级开销**。

这不只是 CI 的问题：**任何"刚装好系统"的机器跑本地取证都会很慢**。
开发机上 `/tmp` 之类的目录是空的，所以本地永远看不出来。

### 二、修复（按"值不值得算哈希"分流）
| 文件类型 | 处理 |
|---|---|
| 脚本/可执行后缀（.php/.phtml/.phar/.sh/.bin/.so）| 算哈希（本来就要报出来）|
| 其余文件中体积 <= 1MB 的 | 算哈希（改名成 .txt 的恶意样本仍能命中）|
| 其余（大文件/.log/.json 等）| 跳过哈希 |

**没有**直接跳过哈希匹配 —— 恶意样本可能改名。小文件仍全量参与。

同时补上两道硬上界：
- `budget_seconds=20.0`：**总时间预算**，超时就停，并产出一条 `scan_truncated`
  记录（如实说明"本轮结果不完整"），绝不静默截断；
- `_MAX_SCAN_DIRS = 24`：扫描目录数上限。

实测：本机 7.6 秒；另一台 Linux 18.5 秒（受 20 秒预算约束）。

### 三、新增性能门禁 `tests/test_hostcheck_perf.py`（8 项）
| 用例 | 断言 |
|---|---|
| 扫描遵守时间预算 | 传 3 秒预算 → 25 秒内返回 |
| 预算耗尽必须报告截断 | 产出 `scan_truncated`，不许静默 |
| 默认预算是有限值 | 0 < budget <= 60 |
| 哈希探测上限是有限小值 | 0 < limit <= 4MB |
| 文件遍历有数量上限 | `_iter_recent_files` 含 `max_files` |
| 扫描目录有数量上限 | `_MAX_SCAN_DIRS` 存在且被使用 |
| 实际目录数在合理范围 | <= 24 |
| 整体取证耗时上界 | `run_host_check` < 90 秒 |

写这批门禁时踩到两个坑，都已修：
1. `tmp_path` 不在默认扫描根里 → 候选数为 0 → "截断"分支永远不执行（假门禁）；
2. 文件 mtime 设为"现在"而 `since` 也取"现在" → 同样一个都扫不到。
   现在测试把 mtime 设到**未来** 60 秒。

### 四、顺带修的 CI 配置
| 问题 | 症状 | 修复 |
|---|---|---|
| `> /dev/null` 重定向 | Windows runner 默认 shell 是 PowerShell，该语法是语法错误 | 去掉重定向 |
| `--timeout-method=signal` | 该方法在 Windows 不支持 | 不指定 method，让插件按平台选 |
| `--timeout=60` 太紧 | 测试自带 90 秒等待循环（取证本身就要时间）| 提到 120，并把测试内等待降到 60 秒 |

### 五、CI 逐轮收敛记录
| 轮次 | Windows 测试 | 界面门禁 | ubuntu 测试 |
|---|---|---|---|
| #1 | ✗ | ✗ | 挂起 |
| #2 | ✗ | ✗ | 挂起 |
| #3 | ✓ | ✗ | 挂起 |
| #4 | ✓ | ✗（仅剩 1 项）| 挂起 |
| #5 | ✗（CI 配置问题）| ✓ | ✗（定位到 host_job 超时）|

### 六、回归
`pytest 554 passed`（+8）/ ruff 全绿 / 布局门禁 / 16 页审计全过（本机）。

---

## [1.5.5] - 2026-11-25

主题：**CI 第三轮：修掉验收脚本的同类平台缺陷，并让挂起可被观测**

### 一、`verify_console.py` 的同一个 400/403 问题
上一轮修了 pytest 里的 `test_log_path_outside_allowlist_rejected`，
但 `verify_console.py` 第 8 项也写死了 `C:\Windows\win.ini`，
在 ubuntu runner 上拿到 400 → 验收 28/29 失败。

现在同样按平台选文件（POSIX 用 `/etc/os-release`），两端都应 403。
**教训**：同一类假设会散落在多个文件里，修一处不等于修一类 —— 这次全仓搜了
`win.ini` 才确认只有两处。

### 二、`--timeout` 没生效，说明卡在收集阶段
ubuntu 的单元测试仍静默挂 20+ 分钟，而 `--timeout=120 --timeout-method=thread`
没有触发。pytest-timeout 只作用于**用例执行**，不覆盖 import/collect。

改为可观测：
| 改动 | 作用 |
|---|---|
| 单独 `pytest --collect-only`（5 分钟超时）| 区分"收集阶段卡住"与"某个用例卡住" |
| `--timeout-method=signal` | Linux 上用信号打断阻塞的系统调用；thread 方式只置标志位，卡在 `connect()` 的用例不会中止 |
| `--durations=20` | 末尾打印最慢用例，直接看出谁在等超时 |
| 打印 `pip show pytest-timeout` | 确认插件真的装上了 |
| `PYTHONUNBUFFERED=1` + 步骤级 `timeout-minutes: 15` | 输出实时可见、不再无限等待 |

### 三、进度（CI 逐轮收敛）
| 轮次 | Windows 测试 | 界面门禁 | 说明 |
|---|---|---|---|
| #1 | ✗ | ✗ | 首次运行，暴露问题 |
| #2 | ✗ | ✗ | 拿到日志：Get-FileHash 缺失、空库、缺字体 |
| #3 | ✓ | ✗ | 修 FileHash 后 Windows 通过；门禁剩 verify_console |
| #4 | ✓ | ✗（仅 1 项）| 布局与审计已过，剩日志白名单一项 |

### 回归
`pytest 546 passed` / 验收 29/29 / ruff 全绿（本机）。

---

## [1.5.4] - 2026-11-25

主题：**CI 第二轮：修掉三处"只有换环境才暴露"的缺陷**

第一次让 CI 真正跑起来后，Windows 与界面门禁双双失败。三处根因都不在本机复现：

### 一、`Get-FileHash` 在 GitHub runner 上不存在（9 个用例连带失败）
Windows 加固脚本用 `Get-FileHash` 算 sha256。在 windows-latest 上该 cmdlet 报
`CommandNotFoundException`——`Microsoft.PowerShell.Utility` 模块解析失败。
（本机 PowerShell 5.1 正常，所以本地 11 项测试全过。）

改为**纯 .NET 实现**，不依赖任何 PowerShell 模块：

```powershell
$sha = [System.Security.Cryptography.SHA256]::Create()
$fs  = [System.IO.File]::OpenRead($p)
$hash = $sha.ComputeHash($fs)   # → hex 小写
```

同时把 `Set-Content` 换成 `[IO.File]::WriteAllText`（同属 Management 模块，风险相同）。

### 二、布局门禁依赖"机器上恰好有数据"
CI 报 `rowHeight=96（应 <=70）`、`actDisplay=MISSING`。
根因不是样式坏了，而是 **CI 的 `p2s-data` 是空的**：
没有资产 → 表格没有行 → `.act` 元素不存在 → 量到的是空状态 div 的高度。

门禁不能依赖环境数据，否则它测的是环境而不是代码。
现在 `check_page_layout.py` **自备数据**：测量前用 API 建 3 台回环资产，
测完删除（带 Cookie 会话，失败会打印 WARN）。

已实测：**清空 assets.json 后门禁仍通过**（自造 3 台 → rowHeight 49 → 清理还原）。

### 三、CI 缺中文字体，排版测量不可信
Ubuntu runner 默认无 CJK 字体，汉字回退方块会让行高/列宽与开发机不同。
ui-gates 增加 `apt-get install fonts-noto-cjk` + `fc-cache -f`。

### 回归
`pytest 546 passed` / ruff / 布局门禁 / 16 页审计全绿（本机）。
CI 侧待下一轮验证。

---

## [1.5.3] - 2026-11-25

主题：**CI 首次运行暴露的三个问题（跨平台测试、挂起、无观测）**

### 一、跨平台测试缺陷（真 bug）
`test_log_path_outside_allowlist_rejected` 写死了 `C:\Windows\win.ini`：

- Windows 上该文件存在 → 越界 → **403**（测试通过）
- Linux 上该文件不存在 → `_resolve_log_path` 先报"日志文件不存在" → **400**

于是同一个逻辑在 CI 的 ubuntu 上必然失败。改为按平台选择"存在但越界"的文件
（Windows 用 `C:\Windows\win.ini`，POSIX 用 `/etc/os-release`），
两端都应得到 403。

### 二、CI 挂起且无任何观测
ubuntu 的 `单元测试` 步骤静默挂起 **25 分钟**（Windows 同套用例通过）。
更糟的是：默认 job 超时是 6 小时，且 `pytest -q` 不打印正在跑哪个用例，
失败后也没法定位。

修复：
| 改动 | 作用 |
|---|---|
| `pytest --timeout=120 --timeout-method=thread` | 任何用例挂起 2 分钟内失败并打印栈 |
| `pytest -v` | 失败时直接看出是哪个用例 |
| 各 job 加 `timeout-minutes` | test 25 / contract 15 / scripts 10 / ui-gates 20 |
| `dev` extra 增加 `pytest-timeout>=2.3` | 保证 CI 有该插件 |

### 三、验证方式
把源码打包到另一台 Linux（Ubuntu 22.04 / py3.10）复跑全量：
`1 failed, 527 passed, 18 skipped in 69.33s` —— **没有挂起**。
唯一失败就是上面那个平台相关测试，已修。说明挂起是 GitHub runner 环境特有，
因此必须让 CI 自己"说出"卡在哪一步，而不是靠猜。

---

## [1.5.2] - 2026-11-25

主题：**修复"发布包缺文件"—— .gitignore 误伤必需数据**

### 一、问题（发布到 GitHub 后立刻发现）
`app/.gitignore` 里有一行 `data/`，本意是忽略运行时数据目录，但它匹配
**任意层级的 data 目录**，于是把两个必需文件一并忽略了：

| 文件 | 作用 | 后果 |
|---|---|---|
| `app/src/p2s/core/data/markers.json` | 补丁标记库（1.4.0 的核心数据）| `patchmarkers.load()` 启动即 `FileNotFoundError` |
| `app/data/benchmark.json` | 基准集 | 无法复现准确率评测 |

**本地一切正常**（文件在磁盘上），推到 GitHub 后仓库里根本没有这两个文件。
这是最危险的一类缺陷：开发者的机器永远不会暴露，只有交付给别人才炸。

### 二、修复
- 移除 `.gitignore` 的 `data/` 规则（运行时数据目录是 `p2s-data/`，已在别处忽略），
  并在原位置写明**为什么不能写 `data/`**；
- 补入 `markers.json`、`benchmark.json`、`data/README.md`；
- 将 `scripts/replay_checkpoint.json` 加入忽略（发布脚本的断点文件，属运行期产物）。

### 三、新增门禁 `tests/test_package_data.py`（5 项）
只检查**运行时按路径读取的数据文件**，不误伤新代码文件：

| 用例 | 断言 |
|---|---|
| 包内数据目录全部被跟踪 | `src/p2s/core/data/*` 每个文件都在 `git ls-files` 里 |
| 基准集目录全部被跟踪 | `app/data/*` 同上 |
| `markers.json` 未被忽略 | `git check-ignore` 必须不命中 |
| `benchmark.json` 未被忽略 | 同上 |
| 数据文件位于包内 | 随 wheel 分发，不依赖当前工作目录 |

**该门禁在修复前正确失败**（准确报出 3 个未跟踪文件），修复后通过。

### 四、发布方式（记录在案）
本机 `github.com` 被 SNI 阻断（`api.github.com` 可达），因此首次发布用
**Git Data API 重放**而非 `git push`：41 个提交逐层重建
（blob → tree → commit → ref），最终 `tree` sha 与本地**逐字节一致**。
详见 [`docs/GITHUB-PUBLISH.md`](./docs/GITHUB-PUBLISH.md)。

### 回归
`pytest 546 passed`（+5）/ ruff 全过。

---

## [1.5.1] - 2026-11-25

主题：**发布就绪（Apache-2.0 许可、授权声明、文档数字门禁）**

### 一、许可
采用 **Apache License 2.0**，附 `NOTICE` 列明第三方依赖与情报素材来源：
- 运行依赖 9 个（httpx/fastapi/starlette/uvicorn/pydantic/python-multipart/pytest/ruff/websocket-client）
- 情报证据（NVD、PHP 官方、CISA KEV）仅作事实性引用
- 第 6 条明确：不授予商标与商品名使用权

选 Apache-2.0 而非 MIT 的原因：**含专利授权（第 3 条）**，企业客户合规审查更容易通过；
同时要求修改后保留变更说明并随分发附许可。

### 二、README 增补「许可与使用授权」
这是主动探测工具，授权声明不能藏在文档深处：

| 内容 | 说明 |
|---|---|
| 使用授权三问 | 资产是否自有 / 是否取得书面授权 / 是否已告知运维方 |
| 设计约束表 | 不主动外联、默认只监听回环、加固不直连主机、加固≠修复 |
| 免责声明 | 按"现状"提供，使用者自担风险 |

### 三、新增门禁 `tests/test_doc_freshness.py`（4 项）
**动机**：README 长期写「134 passed / 版本 1.0.4」，实际早已 500+ —— 文档在说谎，
却没有任何门禁能发现。

现在校验：用例文件数、版本号三方一致（README/pyproject/`__init__`）、规则条数、
以及「声明 passed 数必须带验证日期」。

**这个门禁立刻抓到两处真实漂移**：README 写 102 条规则（实际 112）、
43 个用例文件（实际 44）。已修正。

### 四、CI 与 make verify 扩容
- CI `test` job 增加「文档数字与代码一致」步骤
- `make verify` 从 5 步扩到 6 步，新增文档与基准集检查

### 回归
`pytest 541 passed`（+4）/ ruff 全过 / CI YAML 校验通过（4 job · 26 步）。

---

## [1.5.0] - 2026-11-25

主题：**基准集落地 —— 第一次用数字回答"检测到底准不准"**

### 一、结果
| 指标 | 值 |
|---|---|
| 用例 | 6（未补丁 3 / 已补丁 3，**对称**）|
| 覆盖分支 | 8.2 / 8.3 / 8.4 |
| 准确率 | **100%**（6/6）|
| 误报率 | **0%** |
| 漏报率 | **0%** |

### 二、怎么建的
在实验场启动 6 台容器，每台根路径是一个真实 PHP 页面（带 `X-Powered-By`）：

| 用例 | 镜像 | 端口 | 真相 |
|---|---|---|---|
| BASE-8426-cli | php:8.4.26-cli | 18426 | 未补丁 |
| BASE-8427-cli | php:8.4.27-cli | 18427 | 已补丁 |
| BASE-8234-fpm | php:8.2.34-fpm | 18234 | 未补丁 |
| BASE-8235-fpm | php:8.2.35-fpm | 18235 | 已补丁 |
| BASE-8335-fpm | php:8.3.35-fpm | 18335 | 未补丁 |
| BASE-8336-fpm | php:8.3.36-fpm | 18336 | 已补丁 |

**为什么必须对称**：如果未补丁样本远多于已补丁，"全判未补丁"也能拿高分，
指标就失去意义。`tests/test_benchmark.py` 里专门断言了对称性。

### 三、过程中修掉的自身问题
第一版 6 台容器只有 `/v.php`、`/i.php`，**根路径 404**，导致 4 个 FPM 用例
检测返回 `unknown`（准确率掉到 33%）。这不是检测器的错，是**基准集建得不像真实站点**。
补上 `index.php` 后 6/6 全对。

这件事本身说明：基准集如果不"像真的"，测出来的数字会骗人。

### 四、新增
- `app/data/benchmark.json` — 基准集数据（含 access/truth，检测端只准看 endpoint）
- `app/scripts/run_benchmark.py` — 评测脚本，输出准确率/误报率/漏报率
- `app/tests/test_benchmark.py`（5 项）— 结构自洽、对称性、分支覆盖、ID 唯一、
  **真相必须与版本基线一致**（防止把真相写错导致指标失真）
- `docs/BENCHMARK.md` — 复现步骤、判定口径，以及**这个基准不能证明什么**

### 五、诚实边界（写在文档里，不藏）
1. 样本仅 6 个，只能证明三分支版本识别正确，**不能**代表真实客户环境；
2. 容器直连、无 WAF/反代/自定义错误页，比真实环境干净；
3. 未覆盖发行版回移补丁的构建（如 Debian `8.2.34-1+deb12u2`）—— 这正是标记库的用途；
4. 无伪造版本号的对抗样本。

### 回归
`pytest 537 passed`（+5）/ ruff 全过。

---

## [1.4.0] - 2026-11-25

主题：**补丁标记库落地（用二进制证据替代版本号猜测）**

### 一、为什么要做
版本号是**声明**，标记是**证据**。仅凭版本号会陷入两难：
- 版本低于基线 → 可能已被发行版回移补丁（Debian/Ubuntu 常见）
- 版本达标 → 也可能被降级或伪造

### 二、数据来源（全部实测，可追溯）
在实验场（实验场）从官方镜像提取 `/usr/local/bin/php`，
对**配对版本**做可打印字符串集合差，再逐条在三个分支验证可区分性：

| 分支 | 未补丁 | 已补丁 | 二进制 sha256（前 16）|
|---|---|---|---|
| 8.2 | 8.2.34-fpm | 8.2.35-fpm | 254029359cc4147d… / ac2bc9e674054bea… |
| 8.3 | 8.3.35-fpm | 8.3.36-fpm | e2f7e40577da6ca4… / fc263e1b8e9c6d5e… |
| 8.4 | 8.4.26-cli | 8.4.27-cli | 1aeefba43892624b… / 6be05bcceb1373d9… |

### 三、6 条二进制标记（三分支 6/6 全部可区分）
| 标记 | 内容 | 含义 |
|---|---|---|
| MK-OOM-SYM-1 | `zend_handle_delayed_oom` | 修复引入的延迟 OOM 入口 |
| MK-OOM-SYM-2 | `zend_set_memory_hard_limit_percent` | 修复新增的硬上限函数 |
| MK-OOM-CFG-1 | `memory_hard_limit_percent` | 修复新增的 ini 指令名 |
| MK-OOM-MSG-1 | `Hard memory limit of … exhausted` | 修复新增的提示文案 |
| MK-OOM-MSG-2 | `Out of memory (allocated …)` **消失** | 旧文案被改写 |
| MK-OOM-CFG-2 | `memory_hard_limit_percent must be >= 100, or -1` | 参数校验文案 |

另含运行时探针：`ini_get('memory_hard_limit_percent')` →

```
未补丁 → bool(false)       补丁 → string(0) ""
```

### 四、判定原则（`core/patchmarkers.py`）
1. 正向标记命中 → `patched`
2. 旧版标记仍在（旧 OOM 文案）→ `unpatched`
3. 两者同时命中 → `conflict`，交人工，不猜
4. 都不满足 → `unknown`

**特别处理**：单靠"旧字符串不存在"**不足以**判已补丁（任意非 PHP 文件都不含它），
该信号只作弱提示，必须配合正向标记才判 `patched`。

### 五、验证
- `tests/test_patchmarkers.py` 15 项（含"不得因找不到标记就判未补丁"的回归）；
- **真实二进制复验**：取回 21.8 MB 真 php 二进制本地判定 →
  8.4.26 `unpatched` / 8.4.27 `patched`，6 条标记全部命中，结论正确；
- 「关于」页新增标记库卡片，显示三分支配对与可区分性状态。

### 回归
`pytest 532 passed`（+15）/ ruff / 16 页审计全绿。

---

## [1.3.0] - 2026-11-25

主题：**Windows 加固能力落地（harden.ps1 + IIS/权限规则 + 真机行为测试）**

### 一、新增 Windows 加固包生成器 `core/harden_ps.py`
与 POSIX 版**同构**：同样的五步流程、同样的拒绝清单、同样的票据与计划指纹、
同样的回滚冲突检查。差异只在平台原语：

| 环节 | Linux (sh) | Windows (PowerShell) |
|---|---|---|
| 符号链接 | `[ -L ]` | `Attributes -band ReparsePoint` |
| 硬链接 | `stat -c %h` | `fsutil hardlink list` 计数 |
| 他人可写 | 权限位 | ACL：非特权主体是否持有写权限 |
| sha256 | `sha256sum` | `Get-FileHash -Algorithm SHA256` |

`/api/hardening/pack/{host}` 现在按目标路径自动选平台（含反斜杠/盘符 → Windows），
文件名带平台后缀便于区分。

### 二、测试暴露并修掉一个**会损坏 php.ini** 的缺陷
第一版用 `Get-Content`/`Set-Content` 读写 ini。Windows PowerShell 5.1 对
**无 BOM 的 UTF-8** 按 ANSI 解码，于是：

- 中文注释变乱码（`; 加固前：暴露面更大` → `; 閸旂姴娴...`）；
- 乱码把后面的换行"吃掉"，使注释行与紧随的指令行**合并成一行**；
- 那条指令因此再也匹配不到，最终被**追加到文件末尾**，产生重复指令。

改成 `Read-IniText`/`Write-IniText`：按 BOM 与 UTF-8 严格解码结果判定编码
（非合法 UTF-8 则退回系统 ANSI 代码页，兼容 GBK 的 php.ini），
写回时保持**同一编码与同一行尾**。

### 三、新增 10 条 Windows 规则（规则库 102 → 112 条，9 → 11 类）
`Windows / IIS`（7 条）：目录浏览、WebDAV、请求体上限、应用池身份、
详细错误、`X-Powered-By` 泄露、FastCGI 超时；
`Windows 权限`（3 条）：php.ini ACL、PHP 目录可写性、服务账户。

### 四、新增 `tests/test_harden_ps.py`（11 项，真机执行）
不只看语法：在本机对一份临时 php.ini **完整跑一遍**
（预检 → 备份 → 写入 → 校验 → 回执 → 回滚），并覆盖每一条拒绝路径：

| 用例 | 断言 |
|---|---|
| 语法 | 交给真实 PowerShell 解析器，不接受"看起来对" |
| 正常加固 | 值生效、注释保留、备份内容等于原文件、state 与回执齐备 |
| sha 不符 | 退出码 13，文件未被触碰 |
| 重复指令 / 续行 / 配置管理托管 | 退出码 18 / 19 / 14，拒绝执行 |
| 篡改 ActPairs | 退出码 21（预检拦截）|
| 篡改写入值 | 退出码 30（校验拦截 + 自动回滚，文件复原）|
| 回滚 | 正常复原；加固后被改动 → 退出码 31 且不覆盖，`-Force` 才强滚 |

### 回归
`pytest 517 passed`（+13）/ ruff 全过。

---

## [1.2.0] - 2026-11-25

主题：**发布前清理（消除星号导入、文档统一、脚本可移植、CI 上架）**

### 一、消除星号导入 → 暴露并修复两个潜伏的 NameError
4 个模块使用 `from .deps import *`，而 `deps` 定义了 `__all__` —— 星号导入只带
`__all__` 里的名字，导致 **ruff 的 F821（未定义名）对这些模块完全失效**。

换成显式导入后立刻报出 3 个真问题：

| # | 问题 | 影响 |
|---|---|---|
| 1 | `assets_api` 调用 `discovery.discover()` 但从未导入 | **"手工添加资产并扫描"接口一直 500**（用 `git show HEAD` 确认旧版确实没有该导入）|
| 2 | `scan_api` 调用 `probe_mod.assess()` 但从未导入 | URL 探测任务会 `NameError` |
| 3 | `app.py` 函数内重复导入 `DATA_DIR/SCANS_DIR` | 遮蔽模块级名字 |

新增 `tests/test_api_smoke.py`（22 项）：18 个只读接口逐一真实调用断言不出现 5xx，
外加两个事故接口的专项回归。**已用"临时撤销修复"验证测试会红**
（`NameError: name 'discovery' is not defined`）—— 证明这测试确实能拦住。

### 二、文档权威性
- 新增 `docs/README.md` 文档地图：定义分工（根 `docs/` = 决策与背景；
  `app/docs/` = 技术手册随代码走）、按主题查哪份、冲突时以哪份为准；
- 三份历史快照加"历史"横幅（v0.5.0 交付包索引、v0.5.1 修复清单、立项过程记录），
  **保留原文不改写**，只在文首指向当前文档；
- 根 README 修正两处过期表述：删掉"`app/` ← Git 仓库根"（仓库根已上移）、
  当前状态段换成实测数据。

### 三、脚本可移植化
7 个脚本写死了 `C:\Users\<用户名>\...` 与 `C:\Program Files\Google\Chrome\...`，
**换一台机器或 CI 就跑不起来**。新增 `scripts/_toolpath.py`：
按「环境变量 `P2S_CHROME`/`P2S_NODE` → PATH → 常见安装位置 → 明确报错」四级定位，
并提供可移植的临时 profile 目录。实测 Node 走 PATH 找到 `D:\Program Files\nodejs\node.exe`。

### 四、CI 真正上架
原来工作流在 `app/.github/` —— **GitHub 只认仓库根的 `.github/`，它从未被执行过**。
现移到仓库根，并用 `defaults.run.working-directory: app` 适配目录结构，
同时把门禁纳入 CI：

| job | 内容 |
|---|---|
| `test` | 2 系统 × 2 Python 版本：ruff / pytest / 载荷守护 |
| `contract` | 接口契约测试 |
| `agent-scripts` | 双平台脚本渲染 + `sh -n` / `bash -n` |
| `ui-gates` | 起控制台 + Chrome CDP：JS 语法 / HTML 配平 / 接口一致性 / 布局与弹窗 / 16 页审计 / 验收 |

新增 `make verify`（CI 的无浏览器部分）与 `make verify-ui`（浏览器部分），
本地一条命令等价于 CI。

### 五、修正两处不实声明
| 项 | 原值 | 实测 | 修正 |
|---|---|---|---|
| `requires-python` | `>=3.9` | 锁定依赖要求 **≥3.11**（starlette 1.10 即需 3.11）| `>=3.11` |
| `requirements.lock.txt` | 含 paramiko 闭包 + 一条指向无关目录的 editable 记录 | 非产品依赖 | 重新生成，并新增 `ui`/`cloudtest` extras |

### 回归
`pytest 504 passed` / ruff 全过 / 7 个脚本实测正常 / 16 页审计全绿。

---

## [1.1.3] - 2026-11-25

主题：**修复"文档不在版本控制"的 P0 问题 + 四项清理 + 新增接口一致性门禁**

### 一、P0：文档与 CHANGELOG 从未纳入版本控制
仓库最初建在 `app/` 里，所以项目根的东西一个都没被跟踪：

| 内容 | 规模 | 修复前 |
|---|---|---|
| `CHANGELOG.md` | 140 KB · 71 个版本条目 | 从未提交过（`git log --all -- CHANGELOG.md` 返回空）|
| `docs/`（立项/产品/情报/部署）| 32 个文件 · 3.5 MB | 未跟踪 |
| `tools/`、`samples/`、`archive/` | 61 个文件 | 未跟踪 |
| `README.md`、`CONTRIBUTING.md` | 9 KB | 未跟踪 |

后果：二十多轮迭代的版本记录只存在于单块硬盘，**无历史、无备份、无法回滚**；
此前提交信息里写的"CHANGELOG 补记 X"实际只提交了 `__init__.py` 的版本号。

**处理**：把 `app/.git` 上移到项目根（磁盘上源码路径不变），
新增根 `.gitignore` 挡住 `dist/` 与 `p2s-data/`。
提交结果：**188 个文件识别为纯重命名（R100，内容零变化）** + 79 个新增。
改动前已备份 `.git`(6.1 MB)，重构后 33 个提交完整、482 项测试仍全过。

### 二、四项清理
| 项 | 处理 |
|---|---|
| 过期资产 | 13 → **5** 台；清除 8 台 17 天前的内网设备（`192.168.1.x`），**保留 `web-01`**（它是真实主机且有待加固动作）|
| 孤儿测试产物 | 删除 `p2s-data/ui-verify`（28 个 PNG / 3.1 MB，已无脚本写入）|
| 旧构建 | `dist/archive/*` 两个 v0.6.0 包移到 `archive/dist/`，`dist/` 只留当前 v1.0.5 |
| 依赖锁定 | 新增 `app/requirements.lock.txt`（38 个包精确版本），保证交付可复现 |

### 三、新增门禁：`scripts/check_api_consistency.py`
检查"前端 `api()` 调用 vs 后端注册路由"。

补它的原因：前端调了不存在的接口时表现为**点了没反应**，
而 pytest / ruff / node --check / 验收脚本**全都发现不了**。
本项目已踩过两次同类坑（弹窗漏加 `on`、`scan_api` 漏导入）。

首次运行发现 29 个前端调用全部有对应路由（我的检查脚本本身错了 3 次才写对：
路由枚举不到、把 `/cancel` 当 ID、前缀拼接误判）。

### 回归
`pytest 482 passed` / ruff / 验收 29 / 功能 43 / 深度 8 / 布局门禁 /
16 页审计 / API 一致性 全绿。

---

## [1.1.2] - 2026-11-16

主题：**修两个"点了没反应"的 bug，并补上能抓住它们的门禁**

### 一、计划任务「新增计划」：屏幕变暗，弹窗不出现
`scheduleDialog` 给遮罩加了 `on`，但**弹窗本体没加** —— `.modal{display:none}`，
于是只剩一层半透明遮罩，看着像"卡住了"。

顺带修了同一处的两个样式问题：
- `.modal.wide` 只改了 `max-width`，`width` 仍是 430px → 改为 `width:min(760px,92vw)`；
- 重试说明被挤在第三个字段列里折成 5 行 → 改为独占一行。

### 二、本地取证「立即检测本机」必失败
`scan_api` 调用了 `_ingest_host_report`，但**没有导入**（函数在 `agent_api`）。
`from .deps import *` 让 ruff 的 F821 失效，静态检查看不见；只有真跑一次才报
`NameError`。已补 `from .agent_api import _ingest_host_report`。
修复后实测：`host-bc464d7f01 → state=done`。

### 三、新增门禁（这是本轮重点）
| 门禁 | 抓什么 |
|---|---|
| `check_page_layout.py` 增加弹窗检查 | 点击「新增计划」后，断言 `.modal` 存在、`visible`、宽度 ≥600、输入控件 ≥5 —— 专抓"遮罩出现但内容不显示" |
| `tests/test_host_job.py`（3 项） | 断言 `_ingest_host_report` 可导入；真实发起 kind=host 任务并等它 `done`；检查结果结构 |

这两类 bug 的共同点是**静态检查全绿、界面一用就崩**，只有"真的点一下 / 真的跑一遍"才能发现。

### 回归
`pytest 482 passed`（+3）/ ruff / 验收 29 / 功能 43 / 布局门禁 / 16 页审计全绿。

---

## [1.1.1] - 2026-11-16

主题：**页面宽度统一 + 新增「关于」页**

### 一、两个页面比别的"窄一截"
「日志分析」与「计划任务」单独用了 `.page-narrow`（max-width 880px 居中），
其余 12 页是全宽 —— 切过去会明显感觉"内容区变小了"。

改为 `.page-full`（max-width:none），与其它页同一栅格。窄栏样式保留，
将来做"表单/向导"类页面时仍可用。

### 二、新增「关于」页（菜单底部 · 设置组）
内容只放**可核对的事实**，不放宣传语：

| 区块 | 内容 |
|---|---|
| 版本 | 版本号 · Python / 平台 · 资产数 · 扫描数 |
| 能力 | 发现/判定/加固/取证/监控 五段，每段一句话实现说明 |
| 覆盖范围 | 四分支修复基线（8.5→8.5.12 等）· 加固五层 · 数据目录 |
| 使用边界 | 不主动扫描外部 / 不直连主机 / 加固≠修复 / 存储态≠运行时 |

数据来自新接口 `GET /api/about`（版本、规则统计、资产与扫描数、数据目录）。
版本卡用新增的 `.kpi.hero`（中性强调），**不用风险红条**——版本号不是风险。

### 三、门禁扩容
`audit_pages.py` 覆盖页数 15 → **16**，新增「关于」。

### 回归
`pytest 479 passed` / ruff / 验收 29 / 功能 43 / 布局门禁 / 16 页审计全绿。

---

## [1.1.0] - 2026-11-16

主题：**命名口径统一（把"通用"的说法收回到真实能力边界）**

### 问题
上一版把副标题改成「内网暴露面核查与配置加固」——听起来是通用暴露面平台，
但打开每个页面还是 PHP2Shell 单漏洞视角。「PHP 暴露面」这个菜单名没错，
错的是**产品层面承诺了它做不到的广度**。

### 决定：收回承诺，而不是改页面名
「PHP 暴露面」页面确实只做 PHP 版本暴露判定，改名成「暴露面」等于虚标。
真正的"覆盖更广"体现在**加固的五个层次**：
`PHP ini / PHP-FPM / Web 服务器（nginx·apache）/ systemd / Kubernetes`。

因此：
- 品牌副标题 → **PHP2Shell 暴露面核查与加固**（点明专项，不冒充通用平台）；
- 总览副标题 → `CVE-2026-109618 / 109619 · 核查 · 加固 · 监控`；
- PHP 暴露面页 → `PHP 版本暴露判定 · 多实例按最差聚合`（把 CVE 号交给品牌层）；
- 配置加固页 → `PHP / FPM / Web 服务器 / systemd / K8s 五层 · 包 + 回执`。

### 顺带清掉的术语不一致（用户可见位置）
| 位置 | 旧 | 新 |
|---|---|---|
| 菜单 / 页面标题 / 任务类型标签 | 主机侧检测 | **本地取证** |
| IOC 菜单 / 页面 / 文档 | IOC 中心 | **IOC 库** |
| 报告章节标题（`core/report.py`）| `## 主机侧检测` | `## 本地取证` |
| CLI 帮助（`p2s host`） | 主机侧检测（L3） | 本地取证（L3） |
| Agent 帮助文案 | p2s 主机侧检测 Agent | p2s 本地取证 Agent |
| 本地取证页空状态 | 尚未执行主机侧检测 | 尚未执行本地取证 |

### 验证
`pytest 479 passed` / ruff / 验收 29 / 功能 43 / 15 页审计全绿（5.63 / 5.92）。

---

## [1.0.9] - 2026-11-16

主题：**产品定位与信息架构对齐（名称、加固入口、菜单重组、术语统一）**

### 诊断
- 副标题「内网暴露面核查与取证」只覆盖"发现+判定"，**没提加固**——而加固是最值钱的能力；
- 主标题写「CVE-2026-109618/109619 专项视图」，但规则库已 102 条、覆盖 PHP/FPM/nginx/
  systemd/K8s，早就是"通用框架 + 专项检测"；
- **加固功能菜单里没有入口**，只藏在资产台账行内的盾牌图标里 —— 有功能但找不到；
- 菜单分组「能力」里混了规则、IOC、整改、计划任务、审计、报告，语义混乱；
- 「主机侧检测 / Agent 上报 / 本地取证」三个词指同一件事。

### 改动
1. **定位文案**：`内网暴露面核查与配置加固`；总览副标题改为
   `暴露面核查 · 配置加固 · 持续监控`，CVE 编号移到「PHP 暴露面」页；
2. **新增「配置加固」页**（菜单二级入口）：
   - 5 个指标：待加固 / 已加固 / 规则库 / 未使用票据 / pool 覆盖；
   - 主机与动作表：目标文件、待执行动作数、状态、上次验证、一键打开方案；
   - 规则库表：分类筛选 + 关键字搜索，显示编号/配置项/建议值/风险/是否可自动执行；
   - 新接口 `GET /api/hardening/overview`（每台资产的动作数、票据、pool 覆盖）；
3. **菜单重组为四组**：核查 / 加固 / 运营 / 设置（原「能力」拆分归位）；
4. **术语统一**：「主机侧检测」→「本地取证」，与 Agent 上报口径一致。

### 验证
- 15 页审计全绿（新增加固页），浅色 5.63 / 深色 5.92，无横向溢出；
- 加固页实测：23 台资产、待加固 1、已加固 1、规则 102 条，规则表 80 行渲染正常；
- `pytest 479 passed` / ruff / 验收 29 / 功能 43 / 布局门禁。

---

## [1.0.8] - 2026-11-16

主题：**视觉收尾三处（主指标卡填充、图例紧凑、数值列对齐）**

### 一、主指标卡"空得只剩一个数字"
375px 宽的主卡里只有 `1`，看不出它相对多少。改为：

```
1 / 4 台 PHP 资产
▬▬▬▬▬▬▬░░░░░░░░░░░░░░        ← 占比细条
版本低于修复基线，需立即处置 · 占 25%
```

- 新增 `.row-v`（数字 + 分母）、`.of`（分母样式）、`.mini`（3px 占比条）；
- 分母取 `php_present`（有 PHP 的资产数），比 `total_assets` 更有意义。

### 二、图例是"两端对齐"，数字飘到最右
`.legend div` 原为 `grid-template-columns:7px 1fr auto`，`1fr` 把数字推到右边缘，
与左对齐的瑞士风冲突。改为 `7px minmax(60px,auto) auto` + `justify-content:start`，
数字紧跟标签；`.legend` 限宽 240px 并 `margin-right:auto`。

### 三、数值列没有右对齐
`reports.js` / `overview.js` 的「严重 / 高危 / 发现」表头补 `class="num"`，
数值右对齐 + `tabular-nums`，多行数字才能竖向对齐。

### 验证
- 截图确认：主卡有占比条与百分比、图例数字紧贴标签、扫描表数字右对齐；
- `pytest 479 passed` / ruff / 验收 29 / 功能 43 / 布局门禁 / 14 页审计全绿。

---

## [1.0.7] - 2026-11-16

主题：**视觉重构：编辑部 / 瑞士风（去"素"、去"AI 模板味"）**

### 诊断（有数据，不是感觉）
| 症状 | 实测 |
|---|---|
| 层级缺失 | 字号 10–14px 塞了 **8 档**，最大只有 23px（仅 KPI） |
| 对比弱 | 文字色 `#14181f → #5b6472`，仅 3 档，明度差约 20% |
| 无重量差 | 所有卡片同边框、同圆角（4/6/8/3px 五种混用） |
| 自相矛盾 | 规范写「扁平无投影」，实际有 **11 处 box-shadow** |
| AI 模板味 | 6 个**等宽** KPI 卡 + 居中窄栏 + 通用蓝灰配色 |

### 改造（8 项）
1. **字号标尺收敛到 5 档**：`12 / 13 / 15 / 20 / 32`（令牌 `--fs-xs…--fs-xl`）；
2. **KPI 不对称**：主指标跨 2 列、数字 32px、标签小型大写；其余 20px
   （实测主卡 375px / 其它 184px）；
3. **投影清零**：卡片投影全部移除，只保留弹窗/浮层/焦点环；
4. **圆角三档**：`0` 分隔线 / `2px` 输入 / `4px` 卡片；
5. **背景三层**：`#f7f8f9` 页面 / `#fff` 卡片 / `#f1f3f5` 内嵌区；
6. **表格**：表头改大写 + 字距、行高 9px、数字列 `tabular-nums` 右对齐；
7. **空状态**：居中大图标 + 三行说明 → **左对齐紧凑条 + 左侧 2px 竖线**；
8. **区块锚点**：页面标题与卡片标题加短下划线，形成入场上下的节奏。

### 验证
- 浅色对比度 5.48 → **5.63**，深色 5.92；
- 布局门禁：行高 49px、可见列 10、表单行对齐、1200px 无溢出；
- 14 页审计：全绿；`pytest 479 passed`；验收 29 / 功能 43 / JS / HTML 全过。

---

## [1.0.6] - 2026-11-16

主题：**项目体检后的四项整改（数据保留、门禁可信、测试稳定、文档纠偏）**

### 一、门禁脚本静默降级（P0，已修）
`verify_console.py` 文档写「可用 P2S_CONSOLE_PASSWORD」，实现只认 `--password`，
按文档运行会 401 并**只跑 6 项就退出**（正常 29 项）。现统一走 `_console_auth`，
无凭据直接明确报错。

### 二、数据保留策略（已实现）
- 新增 `core/retention.py`：重复报告「保留最近 N 份 + 超过 M 天才删」+ **总量上限**（默认 300）；
  上传文件按天数清理（默认 7 天）；
- 接口层与 CLI 共用同一实现（此前只有 console 私有函数，CLI 调不到）；
- 新增 `p2s prune [--apply]`，**默认只预览**；
- 实测：scans 195 → 150（重复清理 15 组）、uploads 50 → 3。

### 三、测试不隔离环境变量（新发现，已修）
开发 shell 里 `export P2S_ADMIN_PASSWORD=...` 后跑测试，会**44 个用例 setup 直接 ERROR**
（`{"detail":"口令错误"}`），看起来像"测试全挂"。
根因：conftest 只覆盖了 `P2S_CONSOLE_PASSWORD`，而它的优先级低于 `P2S_ADMIN_PASSWORD`，
外壳变量泄漏进了测试。现在两个变量都强制覆盖为 `test-pass`，
**污染环境与干净环境下均 479 全过**。

### 四、测试在 Windows 上偶发失败
`test_concurrent_atomic_write` 偶发 `PermissionError`：读句柄与 `os.replace` 撞车返回 EACCES，
属瞬时窗口。测试只容忍该异常、仍严格断言内容完整；连跑 10 次通过。

### 五、启动文档纠偏
1.0.5 移除内置默认口令后 README 仍写直接启动，现补「必须先设 `P2S_ADMIN_PASSWORD`」，
CONTRIBUTING 同步登记。

### 六、数据卫生
清除测试期写入的合成资产 `10.0.0.99`（曾标成 hardening=verified）及加固记录，台账 24 → 23。

### 回归
`pytest 479 passed`（+7 保留策略测试）/ ruff / 验收 29 / 功能 43 / 深度 8。

---

## [1.0.5] - 2026-11-09

主题：**安全审计整改（3 个 P0 + 1 个 P1 + 4 个 P2）与代理环境静默故障修复**

### 一、代理环境下的静默全灭（P0）

`NO_PROXY` 里带方括号 IPv6（`localhost,127.0.0.1,[::1]`，Windows/Docker 常见默认值）时，
httpx 0.28.1 会拼出非法 mount key `all://*[::1]`，在 `httpx.Client()` **构造阶段**就抛
`InvalidURL`。设备发现把这个异常吞成"端口开放但无协议响应"，于是整段网段的 `alive` 全部
为 false —— 扫描器看起来在正常工作，实际上什么都没测。

- 新增 `core/httpclient.py` 作为唯一客户端工厂：`proxy_mounts()` 逐条校验 mount key，
  非法条目跳过而非整体崩溃；IPv6 保留方括号（实测 `all://[::1]` 合法，
  `all://::1` 与 `all://*[::1]` 均非法，所以不能简单剥括号）；
- `probe.py` / `agent/agent.py` / `discovery.py` 共 7 处调用点全部改走 `make_client()`；
- 回归：`tests/test_httpclient.py` 7 例，覆盖带括号 IPv6 不崩、IPv6 直连不被代理、
  代理生效、通配符、非法条目跳过、显式 kwargs 优先、TLS 开关。

### 二、内置默认口令（P0）

`ADMIN_PASSWORD` 兜底常量 `<旧版默认口令>` 意味着任何未设环境变量的部署都是公开可登录的。
现在无内置默认：未设 `P2S_CONSOLE_PASSWORD` 时随机生成并打印到启动日志。

- 回归：断言源码不含该常量、`admin / <旧版默认口令>` 登录必须失败；
- 顺手修掉 `test_agent_offline.py` 里 `assert status in (200, 401)` 的假绿断言。

### 三、Agent 安装脚本命令注入（P0）

`/api/agent/download?base=` 的取值被直接插进 shell / PowerShell 脚本文本，
`base=http://x"; echo PWNED; #` 可在运维执行安装脚本时执行任意命令。

- `agentkit` 对 base_url 用白名单校验（协议 + 主机[:端口][/路径]），非法直接拒绝；
- **校验放在 `render_linux` / `render_windows` 内部**而非 `render()`：
  `render_bundle` 直接调这两个函数，放外层会被绕过；
- 令牌（上报用的 `X-P2S-Token`）不能用白名单卡死 —— 那是管理员自定的口令，
  带 `@`、`!`、`空格` 很常见，一卡死整个 Agent 就下载不了。改为**按目标 shell
  转义**：sh 转义 `\ " ` $`，PowerShell 转义 `` ` `` `"` `$`；只有出现控制字符或
  换行才拒绝（换行会结束脚本里的那一行，后面的内容直接变成命令）；
- sh 脚本里令牌默认值单独放一个变量，写进 `${VAR:-默认}` 时默认值里的右花括号
  会提前结束参数展开；
- 接口层把 `ValueError` 转成 400；
- 回归：两平台注入向量、合法 base、`render_bundle` 绕过路径、跨行令牌被拒、
  含元字符的令牌被转义、**sh 与 PowerShell 双端 round-trip 逐字节一致**。

### 四、发行版后缀被误判为开发版（P1）

`parse_version` 把**任何**后缀当预发布标识，于是 `8.4.20-1ubuntu1`、`8.3.6-1.el9`、
`8.2.12-1kylin1` 一律判为 `dev_branch`，`needs_action=False` —— 恰好把国产化和
主流发行版上真实存在的漏洞版本判成"无需处置"。这是检测工具最不该有的错误方向。

- 改为白名单识别预发布标识（`RC/alpha/beta/dev/pre/preview`），发行版修订号返回 `None`
  并继续走正常版本比较；
- 回归：`tests/test_distro_versions.py` 28 组发行版矩阵 + 排序 + 预发布 + 数值比较；
- `test_versions.py` 里 `("8.3.36-1", (8,3,36,"1"))` 这条断言本身编码了旧 bug，改为 `None`。

### 五、P2 加固

- **HMAC 密钥硬编码**：加固令牌原先用源码常量 `p2s-hardening-v1` 签名，任何人都能伪造
  一次性执行令牌。改为 `deps.signing_secret()`：`P2S_SIGNING_KEY` → 数据目录持久化随机
  密钥（非 Windows 下 0600）→ 进程内缓存；
- **Webhook SSRF**：`notify_url` 原先只查前缀。新增 `validate_webhook_url()`，拦链路本地
  `169.254.0.0/16`（云元数据凭证）与回环，且**先解析 DNS 再判断**，防止域名指向元数据地址绕过。
  不拦 RFC1918——本产品本身就是内网扫描器，内网 IM 机器人是正常用法；
- **`verify=False` 散落**：统一由 `httpclient.tls_verify()` / `P2S_VERIFY_TLS` 决定；
- **资产落盘未脱敏**：`_save_assets` 现按**字段名**定向脱敏自由文本。不能整体脱敏——
  实测 `redact(sha256_hex)` 会把 64 位哈希当 base64 blob 抹成 `[BASE64-BLOB len=64]`，
  指纹直接失效。列表 of str 也要覆盖。

### 六、并发写导致计划配置被清空（界面验证时抓出）

跑 `scripts/verify_features_deep.py` 时「定时任务记录了 last_job」失败，顺着查下去是两个真问题：

1. **`_atomic_write` 共用固定的 `.tmp` 文件名**。调度线程和 API 线程并发写同一份
   `schedule.json` 时会互相覆盖临时文件，`os.replace` 有机会把半截内容搬上正文件；
   读方 `json.loads` 失败 → `load_schedules()` 返回空列表 → 下一次保存把用户的
   计划配置整体清空。临时文件名改为 `原名.pid.uuid.tmp`，并对 Windows 上
   「目标文件正被打开导致 os.replace 抛 PermissionError」做重试；
2. **调度的读-改-写没有串行**。用户改配置与调度线程的旧快照互相覆盖。
   新增 `ops_api._sched_lock`，把创建/更新/删除/立即执行与调度 tick 全部纳入同一把锁。

另外 `load_schedules()` 读到损坏文件时不再当成「没有计划」，而是把坏文件改名为
`schedule.json.corrupt-<时间戳>` 留证，避免静默丢数据。

### 七、工程

- 10 个界面验收脚本原本硬编码 `<旧版默认口令>`，1.0.5 起控制台没有默认口令，
  这些脚本会全部登录失败。抽出 `scripts/_console_auth.py` 统一从
  `P2S_ADMIN_PASSWORD` / `P2S_CONSOLE_PASSWORD` 读取；
- `ui_test_overlays.py` 在 GBK 终端打印「✕」会抛 UnicodeEncodeError 导致脚本崩溃，
  改为强制 UTF-8 输出；
- `tools/package_release.py` 的版本号改为从 `p2s.__version__` 解析，杜绝打包版本漂移；
- README 测试数从"40 个"改为实际值；删掉已不存在的 `deploy/` 目录条目；
- `docs/04-部署/反向代理与TLS.md` 环境变量表重写（移除 `<旧版默认口令>` 默认值描述）。

**验证**：472 单元测试通过 · ruff 零告警 · 载荷守护通过 · 14 个页面浅色/深色
对比度与横向溢出全部通过 · 弹层 7 项 / 界面功能 43 项 / 深度校验 8 项全部通过。

---

## [1.0.4] - 2026-11-01

主题：**K8s 加固落地（规则 10 条 + 清单生成 + 真实集群验证）**

### 一、在云主机上装了真集群
`实验场`（2C/2G）上装单节点 **k3s v1.36.5**：
关掉 traefik / servicelb / metrics-server，`max-pods=50`，节点 Ready。
（GitHub 直连太慢，改用 `INSTALL_K3S_MIRROR=cn` 国内镜像。）

### 二、规则库新增 K8s 分类（10 条）
`pod-security.../enforce=restricted`、`runAsNonRoot`、`allowPrivilegeEscalation`、
`readOnlyRootFilesystem`、`capabilities.drop=ALL`、`automountServiceAccountToken`、
`seccompProfile`、`resources.limits.memory`、`NetworkPolicy 默认拒绝`、
`hostNetwork/hostPID/hostIPC`。规则总数 **92 → 102**。

### 三、清单生成器 `core/k8s_harden.py`
产出三个可直接 apply 的文件：

| 文件 | 作用 |
|---|---|
| `namespace.yaml` | 给命名空间打 PodSecurity `restricted` 标签（enforce/warn/audit） |
| `networkpolicy.yaml` | 默认拒绝入站+出站，只放行 DNS |
| `workload-patch.yaml` | 工作负载 securityContext 补丁（含资源限制） |

接口：`GET /api/hardening/k8s/{namespace}` 返回 zip，附带 README（含执行顺序与风险提示）。
命名空间做 DNS-1123 校验，非法返回 400。

### 四、真集群验证（关键证据）
```
应用命名空间   → labels 里 enforce=restricted 生效
应用网络策略   → default-deny created
违规 Pod       → Forbidden：violates PodSecurity "restricted:latest"
                 （hostNetwork、privileged、allowPrivilegeEscalation、
                   capabilities.drop、runAsNonRoot、seccompProfile 全部被点名）
合规 Pod       → created (server dry run)  ← 说明我们给的补丁确实能满足 restricted
清理           → 全部删除
```

即：**我们生成的清单不仅语法对，在真实 API Server 上确实能拦住特权容器，
而按我们建议配置的普通容器又能正常创建。**

### 五、测试
`tests/test_k8s_harden.py`（10 项）：产物齐全、每条带说明注释、
namespace 标签、NetworkPolicy 语义（空 selector + DNS 放行）、
补丁覆盖 8 个关键字段、无 tab 缩进、checklist 与产物对应。

### 回归
`pytest 356 passed` / ruff / 验收 29/29。

---

## [1.0.3] - 2026-10-31

主题：**日志分析支持历史回看 + 时间/等级/关键字筛选**

### 之前的问题
日志分析页只能看"最近一次"的结果：分析完想看上周跑的那份，只能重新提交。
命中明细也不能按时间或关键字过滤，几十上百条时根本找不到想看的那条。

### 新增
1. **历史分析**下拉：列出最近 30 次日志分析（时间 · 来源文件 · 严重/高危/共 N 条），
   点选即回看，无需重新分析；
2. **三个筛选条件**（全部在前端即时过滤，不重新请求）：
   - 时间范围：全部 / 最近 1 小时 / 24 小时 / 7 天；
   - 等级：严重 / 高危 / 中危 / 低危；
   - 关键字：匹配 IP、URI、规则编号与名称；
3. **计数提示**：`显示 16 / 16 条`，随时知道过滤掉了多少。

### 后端
新增 `GET /api/scans/{id}/data`：返回某次扫描的完整结果（含 findings）。
原来的 `/api/scans` 是**摘要**（不含 findings），历史上拉不到明细就是缺这个接口。

### 修的一个白屏事故
第一次实现时只加了 JS 事件绑定、**没插 HTML**（锚点没匹配且未断言），
页面直接报 `Cannot set properties of null (setting 'onchange')` 并白屏。

修法：改用稳定锚点插入卡片，并给所有事件绑定加空值保护。
同时补测试 `test_logs_page_has_filter_controls`：断言页面必须含
`l-hist / l-range / l-sev / l-kw / l-count` 五个控件——这类"JS 有、HTML 没有"的错，
语法检查发现不了，只有断言 DOM 才能拦住。

### 回归
`pytest 345 passed`（+5 日志页测试）/ ruff / JS / HTML / 验收 29/29 / 14 页审计。

---

## [1.0.2] - 2026-10-31

主题：**一次性票据 + 计划指纹（加固包防篡改、回执防重放）**

### 问题
此前"回执"是**事后校验**：平台只检查回执里的动作与签发记录是否一致，
但包本身可以被改动后再执行，同一个回执也可以反复提交。
这挡不住"改包执行""复制别人的回执"两类误用。

### 机制
1. **计划指纹**：`sha256(主机 | 目标文件 | 排序后的 键=值 列表)`，
   由 `hardening.plan_fingerprint()` 统一计算，打包与接口共用一份实现；
2. **票据绑定**：下载加固包时签发票据（有效期 **120 分钟**，人工流程 10 分钟不够），
   票据与指纹一起写进 `harden.sh`；
3. **包内自校验**：脚本启动先重算指纹，与 `PLAN_HASH` 不符即
   `die 21 加固包内容与票据不一致（可能被改动）：请重新下载`，**不触碰目标文件**；
4. **回执消费**：回执必须带回票据编号与指纹；服务端校验存在性 / 指纹 / 过期 / 是否已用，
   通过后写入 `used_at`，**再次提交返回 409**。

### 真机验证
```
打包        → 票据 tk-d5561fb6c689，指纹 99d7c41c…，动作 3 项
缺票据      → 400 回执缺少票据编号（tid）
错票据      → 400 票据编号与签发记录不一致
首次提交    → 200 verified，applied=3
重复提交    → 409 该票据已于 … 使用过，不能重复提交
篡改动作后执行 → [FAIL] 21 加固包内容与票据不一致（可能被改动）
                 目标文件未被改动（原值仍在）
```

### 测试
`tests/test_ticket.py`（8 项）：指纹稳定性、随主机/目标/动作变化、
票据与指纹写入脚本、无票据时兼容、回执字段、清单与指纹一致性。

### 回归
`pytest 340 passed` / ruff / 验收 29/29。

---

## [1.0.1] - 2026-10-31

主题：**全站 14 页 × 浅/深双主题审计；修深色表格不可读**

### 一、先审计，再修
新增 `scripts/audit_pages.py`：遍历 14 个页面，分别在浅色与深色下量测
**文字对比度**与**横向溢出**。首次运行就抓出 24 处问题。

### 二、深色模式表格文字几乎不可见（严重）
实测 `td` 的计算色为 `rgb(20,24,31)`，而卡片背景是 `rgb(26,30,37)` ——
**对比度 1.01**，等于看不见。但 `--text` 变量解析正确（`#e3e7ec`）、
`body` 颜色也正确，说明 `td` 被某条规则继承了错误的颜色。

修法：在深色主题下**显式给表格着色**，不依赖继承：

```css
[data-theme="dark"] table, td, th { color: var(--text) }
[data-theme="dark"] th, .sub { color: var(--text-2) }
[data-theme="dark"] .muted { color: var(--text-3) }
```

修复后 `td` 颜色变为 `rgb(227,231,236)`，深色页面实测可读（截图确认）。

### 三、浅色次要文字对比度偏低
`.muted` / `.sub` 为 4.43，略低于 WCAG AA 的 4.5。把 `--text-3` 由 `#6b7280`
加深到 `#5b6472`、`--text-2` 由 `#545c68` 加深到 `#4a525e`，提升到 **5.48**。

### 四、审计结果（全绿）
| 指标 | 结果 |
|---|---|
| 页面数 | 14 |
| 浅色最差对比度 | **5.48**（要求 ≥4.5） |
| 深色最差对比度 | **5.51** |
| 横向溢出 | 全部 0px |

### 五、门禁
`audit_pages.py` 与 `check_page_layout.py` 一起构成视觉层双门禁：
一个查结构（行高/对齐/规则数），一个查跨页对比度与溢出。

### 回归
`pytest 332 passed` / ruff / JS / HTML / 验收 29/29 / 布局门禁 / 页面审计。

---

## [1.0.0] - 2026-10-31

主题：**版本号规则调整（每段 0–9，满 10 进位）**

### 为什么改
`0.26.0` 这种编号有两个问题：
1. 客户看版本以为"改了 26 轮还没发布"，观感差；
2. 数字无限增长，扫读发布记录时很难定位"这是第几代"。

### 新规则
`MAJOR.MINOR.PATCH`，**每段取值 0–9，满 10 进位**：

```
1.0.0 → 1.0.1 → … → 1.0.9 → 1.1.0
1.9.0 → 1.9.1 → … → 1.9.9 → 2.0.0
```

- 修 bug、小调整：PATCH+1；
- 新增功能：MINOR+1（PATCH 归零）；
- 规则/架构级变更：MAJOR+1。

实现在 `core/version_policy.py`（`parse / is_valid / bump / explain`），
并有测试保证"连续递增 200 次不会出现越界版本"。

### 编号映射
历史上从 0.1.0 到 0.26.0 的 22 次发布保留原编号，便于对照；
自本版起统一为新规则，当前记为 **1.0.0**（第一个规则化版本）。

### 回归
`pytest 332 passed` / ruff / 验收 29/29。

---

## [0.26.0] - 2026-10-31

主题：**计划任务失败自动重试（有限次 + 可配间隔）**

### 设计取舍
不做"立刻重试、无限重试"——那会在目标主机异常时形成扫描风暴。
改为**定时重试**：失败后按配置间隔重排一次，次数用完就等下一个正常周期。

### 规则（`next_retry()` 纯函数，可单测）
| 任务终态 | 处理 |
|---|---|
| done（成功） | 重试计数清零，取消待重试 |
| failed / canceled（且有余量） | `retry_count+1`，排到 `now + retry_delay_minutes` |
| failed / canceled（额度用尽） | 清零，回到正常周期 |
| running | 不动 |

### 新增字段（每条计划）
`retry_max`（0-5，默认 1）、`retry_delay_minutes`（1-1440，默认 5）、
`retry_count`、`next_retry_at`。

### 调度行为
- 有 `next_retry_at` 的计划**优先执行重试**，且等待期间不触发正常周期（避免叠加）；
- 重试期间页面在「最近一次」下方显示 `重试 1/2 · 10:05`；
- 任务结束的 watcher 从"仅通知"扩展为"判定重试 + 通知"，最多等 20 分钟。

### 校验
`retry_max` 越界 → 400「重试次数取值 0-5」；
`retry_delay_minutes` 越界 → 400「重试间隔取值 1-1440 分钟」。

### 测试
`tests/test_schedule_retry.py`（8 项）：成功清零、失败排期、额度用尽、
`retry_max=0` 不重试、自定义间隔、running 不动、取消计入失败、多次递增。

### 验证
```
新建带重试计划 → retry_max=2, delay=1, count=0
retry_max=9    → 400
delay=0        → 400
```

### 回归
`pytest 325 passed` / ruff / JS / HTML / 验收 29/29 / 布局门禁 OK。

---

## [0.25.0] - 2026-10-31

主题：**计划任务支持多条 + Webhook 失败通知 + 实时倒计时**

### 一、存储结构升级（兼容旧数据）
从"单个配置对象"改为 `{"schedules": [...]}`；读取时自动识别旧格式并迁移成一条计划，
不需要手工改文件。

新增接口：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/schedules` | 列出全部计划（含 `next_run_in`） |
| POST | `/api/schedules` | 新建 |
| PATCH | `/api/schedules/{id}` | 局部更新（启用/停用只需传 enabled） |
| DELETE | `/api/schedules/{id}` | 删除 |
| POST | `/api/schedules/{id}/run` | 立即执行这一条 |

旧的 `GET/POST /api/schedule` 保留，映射到第一条计划，不影响既有调用（含验收脚本）。

### 二、每条计划独立
`name / cidr / hosts / every_minutes / group / save / notify_url / enabled`，
调度器每 30 秒遍历**所有**启用计划，到点各自触发，互不影响。

**入库分组**解决了之前的问题：不同计划的扫描结果可以分到不同分组
（如办公网 `office`、生产网 `prod`），不再全挤在 `auto`。

### 三、Webhook 失败通知
每条计划可选填 `notify_url`；任务结束后（done/failed/canceled）POST 一份 JSON：

```json
{"schedule_id":"sch-x","name":"办公网段","job_id":"discover-y",
 "state":"done","message":"1/1 ok","total":1,"done":1,"error":null,"at":"…"}
```

后台线程最多等 10 分钟，失败静默（不影响调度）。**已用本地 HTTP 服务实测收到回调**。

### 四、前端重做
- 计划列表：名称/网段/间隔/分组/状态/**下次执行倒计时**/最近一次/操作；
- 每行可「启用·停用 / 立即执行 / 删除」；
- 「新增计划」弹窗：名称、网段、间隔、入库分组、Webhook、结果入库、保存后启用；
- 倒计时每秒递减，**不重新请求接口**；离开页面自动清理定时器。

### 五、校验
- 间隔 <5 或 >10080 → 400；
- 网段与主机列表都为空 → 400；
- `notify_url` 非 http(s) → 400「通知地址必须以 http:// 或 https:// 开头」。

### 验证记录
```
迁移：旧单条配置 → 1 条计划（sch-32e47d2a, 127.0.0.1/32, 30min, next 689s）
新建：办公网段 192.168.1.0/24 / 120min / group=office → 成功
校验：every=2 → 400；notify_url=ftp://x → 400
列表：2 条（启用 1）
Webhook：本地 HTTPServer 收到完整 JSON
```

### 回归
`pytest 317 passed` / ruff / JS / HTML / 验收 29/29 / 布局门禁 OK。

---

## [0.24.0] - 2026-10-31

主题：**计划任务页重做（布局 + 3 个功能缺口）**

### 一、布局：三个控件挤一行导致换行错位
原实现把「CIDR 输入 + 间隔输入 + 单位文字 + 保存按钮」塞进同一个 `.row`，
总宽超出后依次换行：单位文字掉到第二行、保存按钮掉到第三行右侧。

改为字段化布局：
- 每个控件有独立 `<label>`（扫描网段 / 间隔（分钟））；
- 网段 `flex:2 1 320px`、间隔固定 150px、两个按钮紧随其后；
- `.row` 用 `flex-end` 对齐，底边统一（与上一轮的表单行修复同一规则）。

### 二、补功能
| 新增 | 说明 |
|---|---|
| **立即执行一次** | 用当前配置立刻跑一次，不影响定时计划 |
| **结果写入资产台账**开关 | 之前 UI 传 `save:true` 但**后端直接丢弃**，定时扫描可能不入库 |
| **最近自动扫描**列表 | 最多 6 条，含状态徽标、结果摘要、相对时间、跳转 |
| **状态徽标** | 卡片标题旁显示「已启用 / 未启用」 |
| **CIDR 前端校验** | IPv4 每段 0-255、掩码 ≤32，错误就地提示而不是等后端 400 |

### 三、修掉的三个真 bug
1. **`save` 字段被丢弃**：`api_set_schedule` 只处理 enabled/every_minutes/cidr/hosts/quick，
   UI 传的 `save` 与 `group` 全被忽略 → 存的仍是旧值 false，定时扫描不入库；
2. **分组名不一致**：调度器写 `group="auto"`，界面按 `"自动"` 过滤 → 永远查不到记录；
   现已统一为 `auto`，前端同时兼容两种写法；
3. **`/api/jobs` 返回结构判断错**：实际是 `{"jobs":[...]}`，代码按数组处理 → 列表恒为空。
   这类"接口形状想当然"的错误，只有真点开页面才会暴露。

### 验证
- 保存计划：`enabled=true, every=30, next_run_in≈1790s`；
- 非法间隔：HTTP 400「间隔不能小于 5 分钟」；
- 立即执行：任务创建并跑完（`127.0.0.1/32 → 离线 / 无响应`）；
- 历史列表：3 条记录正确渲染（此前为空）。

### 回归
`pytest 317 passed` / ruff / JS / HTML / 验收 29/29 / 布局门禁 OK。

---

## [0.23.1] - 2026-10-31

主题：**表单行对齐修复（复选框/按钮与输入框底边错位）**

### 现象
「设备发现」页第二行：`保存到台账` 复选框、两个超时输入框、`开始扫描` 按钮
三者底边各不相同，看起来上下错位。

### 实测数据（CDP 量的）
| 元素 | 高 | 上沿 | 下沿 |
|---|---:|---:|---:|
| 复选框 `.check` | 19px | 237 | **255** |
| 字段块 `.f150` | 51px | 220 | **272** |
| 按钮 `.btn` | 30px | 242 | **272** |

根因：`.row` 用 `align-items:center`，而三类子元素**高度不同**，
垂直居中后底边自然错开，复选框尤其明显（只有 19px）。

### 修复
`.row` 改为 `align-items:flex-end`，并给复选框固定 32px 行高、按钮 `align-self:flex-end`：
底边统一到 272。这条规则对全站所有 `.row` 生效，同类错位一并解决。

### 新增门禁
`check_page_layout.py` 增加**表单行对齐断言**：遍历所有含复选框/按钮的 `.row`，
检查子元素底边差 ≤ 2px。当前 2 个表单行全部通过。

### 回归
`pytest 317 passed` / ruff / JS / HTML / 验收 29/29 / 布局门禁 OK。

---

## [0.23.0] - 2026-10-31

主题：**规则库 4 条 → 92 条（8 类，25 条可自动执行）**

### 为什么不是"凑到 212 条"
安天工具有 212 条知识，但**只有 7 条会在方案里真正执行**，其余是人工步骤或说明性条目。
我们的取向相反：**每条规则都要能核对**——默认值写准、副作用写清、验证方法可执行、
恢复方式可操作。宁可 92 条条条可用，也不写 200 条查不到的。

### 规则库结构（`core/rulebook.py`）
每条规则 11 个字段：`id / category / target / key / default / recommended / risk /
auto / why / effects / verify / restore`。

| 分类 | 条数 | 可自动执行 |
|---|---:|---:|
| 会话安全 | 14 | 9 |
| 高危特性 | 18 | 9 |
| FPM | 17 | 3 |
| Web 服务器 | 14 | 0（改 nginx/apache 一律人工） |
| 资源限制 | 10 | 0（需按业务测算） |
| 系统服务 | 9 | 0（systemd drop-in，人工） |
| 信息暴露 | 6 | 4 |
| 日志 | 4 | 2 |
| **合计** | **92** | **25** |

风险分布：critical 3 / high 11 / medium 31 / low 47。

### 重点补齐的几类
- **加载链**：`cgi.fix_pathinfo`（图片马执行）、`user_dir`、`doc_root`、`phar.readonly`；
- **断言执行**：`assert.active` / `zend.assertions`（历史上可被当作 eval 载体）；
- **FPM 纵深**：`security.limit_extensions`、`listen.mode/owner/group`、
  `php_admin_value[open_basedir]`、`clear_env`、`slowlog`；
- **Web 层**：上传目录禁执行、拒绝 `.git/.env`、HSTS/CSP/X-Frame-Options、
  `ssl_protocols`、Apache `TraceEnable`；
- **systemd**：`NoNewPrivileges`、`ProtectSystem`、`MemoryMax`（OOM 攻击打不挂宿主）。

### 接入方式
- `hardening.RECOMMENDED` **改为从规则库派生**（15 个键），杜绝两处各写一份；
- 采集脚本的 `INI_KEYS_SCAN` 从 4 个键扩到 **15 个**，一次采集即可支撑全部自动动作；
- 新增接口 `GET /api/hardening/rules?category=&auto=`，返回全库与统计。

### 版本感知
`for_php_version()` 会过滤掉与当前版本无关的项（如 8.5 才有的 `fatal_error_backtraces`），
避免对低版本给出无效建议。

### 新增测试
`tests/test_rulebook.py`（19 项）：条数下限、ID 唯一、字段齐全且 why/verify 不得为
占位短语、风险枚举、**auto 只允许 ini/fpm_pool**、版本过滤、统计自洽、
以及"加固流程用到的每个键都必须在规则库有出处"。

### 回归
`pytest 317 passed` / ruff / 验收 29/29。

---

## [0.22.0] - 2026-10-31

主题：**加固执行纪律（借鉴安天工具的拒绝清单与回滚检查）**

分析安天「PHP专项配置加固工具」Linux v2.1.0.9 后（见
`docs/03-情报/竞品-安天PHP加固工具分析.md`），补齐我们执行侧最缺的三件事。

### 一、拒绝清单（预检从 4 条扩到 9 条）

| 退出码 | 拒绝条件 | 为什么 |
|---|---|---|
| 15 | 目标是符号链接 | 软链可能指向别处，改错文件 |
| 16 | 目标有多个硬链接 | 一处改动会影响多份路径 |
| 17 | 组/其他用户可写 | 他人可篡改，TOCTOU 风险 |
| 18 | 同一指令出现多次 | 不猜哪条生效（PHP 取最后一条，容易被误判） |
| 19 | 存在 `\` 续行 | 影响键值解析，必须人工整理 |

原有的 10/11/12/13/14（不存在/无权限/容器/sha 不符/配置管理托管）保留。

### 二、回滚冲突检查（此前会静默覆盖别人的改动）

加固成功后写 `<目标>.p2s.state`（0600，记录 after_sha）；
`rollback.sh` 先比对当前文件是否仍等于 after_sha：

- 相等 → 安全回滚；
- 不等 → **中止并退出 31**，打印「加固后记录 / 当前文件」两个 sha，
  明确提示「直接覆盖会抹掉这些改动」，需显式 `--force` 才继续。

### 三、`runtime_verified` 显式标注

- 回执 JSON 增加 `"runtime_verified": false`；
- manifest 增加 `runtime_verified: false` 与 `discipline` 退出码表；
- README 增补边界说明：**存储态写入成功不等于运行时生效**，必须重启服务并自查。

这是安天做得对的地方——把"没验证到的"写在最显眼处。

### 真机验证（验证机，临时目录，未碰生产配置）

```
A) 组可写文件      → exit=17  [FAIL] 17 目标对组或其他用户可写（权限 664）
B) 符号链接        → exit=15  [FAIL] 15 目标是符号链接
C) 重复指令        → exit=18  [FAIL] 18 指令 session.use_strict_mode 出现 2 次
D) 续行            → exit=19  [FAIL] 19 目标存在续行
E) 正常文件        → exit=0   加固成功并生成回执
F) 加固后改文件再回滚 → exit=31 回滚已中止：目标文件在加固之后被修改过
G) rollback --force → 成功回滚
```

### 新增测试
`tests/test_hardening_discipline.py`（18 项）：五种拒绝码与提示语、
回滚冲突退出码、状态文件与权限、`$#` 而非 `${1:-}`（`set -u` 安全）、
manifest/回执的 `runtime_verified`、README 边界说明、两脚本 `sh -n`。

### 回归
`pytest 298 passed` / ruff / JS / HTML / 验收 29/29 / 布局门禁。

---

## [0.21.0] - 2026-10-31

主题：**采集脚本修复 + FPM pool 覆盖 + CSS 结构性事故修复 + 布局门禁**

本轮之前的几个 commit 没记账，一并补上。

### 一、采集脚本（agentkit）
- 修 `\r` / `\n` 被 f-string 吃成真实控制字符（导致 `sh -n` 报 Unterminated quoted string）；
- 移除被重复插入的 `INI_FILES` 块（悬空 `done`）；
- 补回被误删的 `php_bin` / `ini_path` / `ini_sha256` JSON 字段；
- 该文件此前**未纳入 git**，三次改坏都无法回滚，现已提交；
- 新增 `tests/test_agent_script.py`（15 项）：控制字符、真实 `sh -n`、块唯一性、
  JSON 字段、占位符残留、单引号配对。

### 二、FPM pool 覆盖检测
`php_admin_value[...]` 写在 `pool.d/*.conf` 里会盖过 php.ini——之前改了 ini 会显示"已加固"，
实际线上没变。
- 采集侧只加一条 `grep -HE '^[[:space:]]*php_(admin_)?value\[...'`（行首锚定，排除注释）；
- 解析全放 Python（`_parse_pool_overrides`），避开 shell 引号嵌套；
- `/api/hardening/plan` 返回 `pool_overrides`，加固弹窗顶部黄条提示
  「N 处 FPM pool 级配置会盖过 php.ini」；
- 真机验证：注入 `php_admin_value[session.use_strict_mode] = 0` 后被正确识别。
- 期间修掉两个"静默失效"：字段接错解析函数、过滤条件用错键名。

### 三、CSS 结构性事故（最严重）
抽取样式表时按"含 mono 的行"删除，连带删掉三处续行的 `}` 与一行选择器：

| 位置 | 丢失内容 | 后果 |
|---|---|---|
| `pre{...}` | 续行 `}` | 之后所有规则被 CSS 嵌套吞掉 |
| `.evi{...}` | 续行 `}` | 再吞一批 |
| `.port{...}` | 选择器行 | 只剩孤立属性 |

**花括号总数仍然"配平"（362/362）**，所以只查数量发现不了。实测影响：

| 指标 | 事故时 | 修复后 |
|---|---|---|
| 浏览器生效的 CSS 规则数 | **182** | **327** |
| 资产表行高 | 107px | 47px |
| 可见列数 | 14 | 10 |
| 操作列 display | block（竖排 37px） | flex（横排 94px） |
| 顶栏操作区 top | **-32.5**（掉出视口） | 12.5 |

即 **44% 的样式规则静默失效**，而 ruff / node --check / HTML 配平全部通过。

### 四、新增门禁
- `tests/test_frontend_assets.py`：花括号配平、深度不为负、结束深度为 0、
  **跨行规则必须在下一个顶层选择器前闭合**、关键选择器必须在顶层、
  无控制字符、模板齐全、选择器不重复定义；
- `scripts/check_page_layout.py`：用 CDP 量真实 DOM——顶栏 flex 与位置、
  表格行高、操作列 flex、可见列数、生效规则数，并检查浅色/深色下文字对比度
  （要求 > 4.5 / 次要文字 > 3.0）。

### 回归
`pytest 280 passed` / ruff / JS 语法 / HTML 配平 223 / 验收 29/29 /
布局门禁 OK（浅色对比度 6.03，深色 6.23）。

---

## [0.20.0] - 2026-10-31

主题：**前端彻底脱离 Python 字符串 + 资产表显示 PHP 实例数**

### 一、样式表抽离（#15 收尾）
- `templates/app.css`：519 行 / 31.3 KB；
- `ui_css.py`：从 500+ 行降到 9 行（只剩 loader）。

至此前端三层全部是真实文件：

| 类别 | 位置 | 数量 | 体积 |
|---|---|---:|---:|
| HTML 外壳 | `console/templates/*.html` | 2 | 42.5 KB |
| 样式表 | `console/templates/app.css` | 1 | 31.3 KB |
| 页面 JS | `console/ui_pages/js/*.js` | 11 | 85.3 KB |

对应的 Python 模块全部退化为加载器：`ui.py` 686→26 行、`ui_css.py` 500+→9 行、
`ui_pages/*.py` 各 3 行。

### 二、资产表显示 PHP 实例数
多版本主机在资产台账的 PHP 列下新增「N 个实例」小字，
悬浮显示每个端口对应的版本（`:8081=8.4.26  :8083=8.2.34 …`）。
这是把「多版本聚合取最差」的结论**放到用户一眼能看到的位置**，而不是藏在抽屉里。

### 三、过程中的小坑
抽离后 `ui_css.py` 缺 `import pathlib` → 导入即 `F821`，被 ruff 当场拦下。
这正是"ruff + 导入即报错"这层门禁该起的作用。

### 回归
`pytest 252 passed` / ruff / HTML 配平 223 / 验收 29/29。

---

## [0.19.2] - 2026-10-30

主题：**修掉"改了没生效"的进度条（两套 .pbar 规则打架）**

### 根因
样式表里存在**两套 `.pbar` 规则**：
- 第 118~122 行是我改的中性版（`.pbar > i{background:var(--text-2)}`）；
- 第 482~485 行是更早的版本（`.pbar i{background:var(--accent)}`、
  `.pbar.ok i{background:var(--ok)}` 绿色）。

选择器权重相同、后者在表尾 → **后者覆盖前者**，所以任务中心的进度条一直是绿的。

### 修复
把后一套也统一为中性灰：默认/已完成用 `--text-2`，警告用 `--text-3`，
只有**失败**保留红色（语义色）。运行中用品牌蓝，表示"进行中"。

### 教训（写进 CONTRIBUTING 的候选条目）
> CSS 类名/规则重复时，**后写的静默覆盖先写的**，编辑器与 linter 都不会报错。
> 因此色值类改动必须以**截图**为准，且改之前先 `grep` 一遍类名有几处定义。

### 验证
任务中心截图：进度条已由绿转中性灰；五道门禁全绿。

---

## [0.19.1] - 2026-10-30

主题：**页面片段同样抽离为 .js（#15 第二步完成）**

### 改动
`ui_pages/*.py` 里的 11 个 `PART` 页面片段全部抽成独立文件：

```
ui_pages/js/
├── overview.js (282)  tasks.js (314)   drawer.js (75)
├── php.js (30)        logs.js (185)    rules.js (32)
├── ioc.js (43)        reports.js (107) agents.js (80)
├── remediation.js (88) ops.js (163)
                          合计 85.3 KB
```

每个 `ui_pages/<name>.py` 现在只剩 3 行：文档串 + `pathlib` + 读取文件。
`PAGES` 拼接逻辑不变（`__init__.py` 依次读 `PART`），**渲染结果零差异**。

### 至此模板全部落盘为真实文件
| 类型 | 位置 | 数量 |
|---|---|---:|
| HTML 外壳 | `console/templates/*.html` | 2 |
| 页面 JS | `console/ui_pages/js/*.js` | 11 |
| 样式 | `console/ui_css.py`（仍是字符串） | 1 |

样式表还留在 Python 里，是下一处该抽的目标。

### 验证
五道门禁全绿：`pytest 252` / ruff / **JS 语法 OK** / **HTML 配平 223** / 验收 29/29；
任务中心页截图与改造前一致。

### 发现但未修
任务中心的进度条仍是绿色（我上一轮把 `.pbar > i` 改成灰阶，但该表用的是别的类名，
规则没命中）。已记入待办——**色值类改动必须以截图为准，不能只看 CSS 写得对**。

---

## [0.19.0] - 2026-10-30

主题：**前端模板从 Python 字符串里抽出来（治理"反复改坏模板"）**

### 背景
我们已三次因模板结构改坏而白屏/塌版：丢反引号、多开 `<div>`、悬空 `||`。
根因不是粗心，而是**模板长期以 Python 字符串形式存在**——
没有语法高亮、没有配对检查、出错信息指向"Python 语法错误"而不是"HTML 结构问题"。

### 改动（第一步：控制台外壳）
- `ui.py` 从 **686 行 → 26 行**，只剩加载与占位符替换；
- 两个模板落到独立文件：
  - `src/p2s/console/templates/dashboard.html`（30.6 KB）
  - `src/p2s/console/templates/login.html`（11.9 KB）
- 新增 `_load_template()`：读文件、缺失时抛出明确错误（打包漏资源不会变成静默白屏）；
- 占位符 `/*__P2S_CSS__*/`、`/*__P2S_PAGES__*/`、`__P2S_VERSION__` 保持不变，
  注入逻辑与原来完全一致，**渲染结果零差异**（截图比对通过）；
- `pyproject.toml` 增加 `package-data`，确保 `.html` 随包分发。

### 验证
- 页面渲染与改造前一致（截图核对）；
- 五道门禁全绿：`pytest 252` / ruff / JS 语法 / **HTML 配平 223 标签** / 验收 29/29。

### 过程中的一次事故（如实记录）
抽离脚本先把 `LOGIN_HTML` 的结束定界符置空、再按旧行号切片，
导致 `ui.py` 被截断到 43 行、留下悬空 `"""`。
靠"导入即报错"立刻发现，用保留前 30 行 + 补回三处 `replace` 修好，并全量复验。
教训：**剪切大段代码时，删除顺序必须先删后段、或改用一次性重写**。

### 下一步（同样思路，逐个文件）
`ui_pages/*.py` 里的 12 个页面片段仍是 `PART = r'''…JS…'''`，
可同样抽成 `.js` 文件后由 `ui_pages/__init__.py` 读取拼接。

---

## [0.18.0] - 2026-10-30

主题：**HTML 标签配平门禁 + 三处细节收尾**

### 新增门禁：`scripts/check_page_html.py`
用标准库 `html.parser` 解析服务端返回的整页 HTML，检查标签配平：
未闭合、多余闭合、到文件结束仍悬空。当前页面 **223 个起始标签全部配平**。

补这个的原因：我们已三次因为模板结构改坏而白屏/塌版
（丢反引号、多开 `<div>`、悬空 `||`），而 ruff / pytest / `node --check` 全都看不见这一类错误。
现在前端改动固定跑三道：`check_page_js.py` → `check_page_html.py` → 截图。

### 细节
- 整改建议补上 **EOL 分支的社区回补来源**（Anton-Barinov/php2shell-patches），
  客户拿到"需要回补"时知道去哪找；
- 报告中心 `×N` 角标加左间距，窄屏不再与扫描 ID 贴在一起；
- 设备类型条形再降一档（5px → 4px），更接近刻度而非色块。

### 回归
`pytest 252 passed`、ruff 全过、验收 29/29、JS 语法 OK、**HTML 配平 OK**。

---

## [0.17.2] - 2026-10-30

主题：**标签去色底 + KPI 收敛到 6 张**

### 改动
- **风险标签改描边式**：`crit/high/ok/warn/info/mute` 六类全部去掉色底，
  只保留 1px 彩色描边 + 彩色文字。整屏不再有"糖果色块"，严重程度仍一眼可辨。
- **KPI 从 7 张收敛到 6 张**：删除独立的「运行中任务」卡片，
  把运行数并入「资产变化」的说明行（`新增 0 · 变更 4 · 运行中 0`）。
  卡片变宽后标签不再换行，一行读完。

### 待办（已列为下一轮）
- 深色模式逐页复核（仅总览校准过）；
- 报告中心行内 `×N` 角标在窄屏会与 ID 挤；
- 设备类型条形仍为纯品牌蓝，可再降一档。

### 回归
`pytest 252 passed`、ruff 全过、验收 29/29、JS 语法 OK。

---

## [0.17.1] - 2026-10-30

主题：**去掉"红绿彩虹条"，KPI 恢复独立卡片**

### 用户反馈（两条，都成立）
1. "每个都连在一起了吗" —— 上一版把 7 张卡做成了一整条，边缘连成一片，反而更难读；
2. "很多页面的绿红线条元素都是 AI 设计风格" —— 满屏饱和红/绿/橙进度条确实像模板仪表盘。

### 改动
- **KPI 恢复独立卡片**：透明容器 + 8px 间距 + 细边框、**无投影**，
  既不是"漂浮名片"，也不是"连成一条"；数字 23px、标签轻、说明弱，三段式层级。
- **进度条全部中性化**：轨道与填充改用灰阶，只有"需要立即处置"用红色；
  任务进度条也从绿色改为灰阶（不再是红绿灯）。
- **环形图去彩虹**：`暴露=红`、`待确认/已修复=灰阶`、`无 PHP=浅轨`，
  图上只剩一个红色焦点，其余靠明暗区分。
- **堆叠进度条同上**：`暴露 4%` 红，其余（待确认 4%、已修复 9%、不涉及 83%）三档灰阶。

### 保留的语义色（有意为之）
- 列表里的风险标签仍用红/橙/绿（严重/中危/低危）—— 这是**业务语义**，
  去掉会让"哪个是严重"失去一眼可辨的能力；
- 设备类型条形图保留单一品牌蓝，作为"数据可视化"的唯一强调色。

原则：**一屏只有一个红色焦点**；颜色只用来表达"严重程度"，不用来装饰。

### 回归
`pytest 252 passed`、ruff 全过、验收 29/29。

---

## [0.17.0] - 2026-10-30

主题：**FPM 加固真机闭环 + 加固包说明重写 + 顶部指标条重做**

### 一、FPM 加固端到端跑通（补上 0.16.0 未完成的部分）
上一轮失败原因是**测试脚本**残留旧 `harden.sh`（zip 没覆盖）。清空目录重跑后：

```
[3/5] 应用变更  session.upload_progress.enabled = 0 / session.use_strict_mode = 1
[4/5] 校验生效值
  [session.upload_progress.enabled] 0 OK (file)
  [session.use_strict_mode]          1 OK (file)
[5/5] 完成 回执已生成
sudo systemctl reload php8.3-fpm → 站点 phpinfo 实际值：
  upload_progress=0   use_strict_mode=1      ← 加固前是 1 / 0
```

关键点：**校验走 `(file)` 分支**（fpm 的 ini 用文件内容核对，不再用 CLI 运行时误判）。
至此 FPM 与 CLI 两条加固路径都有真机证据。

### 二、加固包 README 重写
原来的说明只有 5 行步骤，客户拿到包不知道"改完怎么生效、怎么自查"。现在补成 7 节：
影响范围、先看变更、执行、**让改动生效（带具体 reload 命令）**、**确认生效（php -i 自查）**、
回滚、必须知道的边界、回执样例。开头明确写"平台不会远程执行任何命令"。

### 三、首页顶部卡片重做（去 AI 味）
原来 7 张等高漂浮卡片 + 图标 + 大数字，是典型的模板感。改为**一体化指标条**：
- 整条一个容器、内部用 1px 竖线分隔，不再每张卡各自描边与投影；
- 数字从 26px 降到 23px，层级交给"标签—数值—说明"的间距而不是字号；
- 只有"暴露待修复"用红色强调（左侧色条 + 红色数字），其余全部中性；
- 视觉上像仪表盘的一排读数，而不是七张名片。

### 回归
`pytest 252 passed`、ruff 全过、验收 29/29、JS 语法 OK。

---

## [0.16.0] - 2026-10-30

主题：**FPM 场景加固（目标选择 + 按文件取值）—— 部分验证**

### 发现的关键问题
在第二台云主机上配好 nginx→php-fpm 后实测：

| 配置 | cli/php.ini（之前加固的） | fpm/php.ini（生产实际生效） |
|---|---|---|
| session.upload_progress.enabled | 0（已改） | **On（仍然开着）** |

也就是说：**之前那次"加固成功"改的是 CLI 的 ini，对线上 FPM 毫无作用。**
这正是"只测了一半"的风险——幸好这次用真站点验证出来了。

### 已实现
1. **采集脚本枚举全部 ini**：`/etc/php/*/{fpm,apache2,cli}/php.ini`、`/etc/php.ini`、
   宝塔 `/www/server/php/*/etc/php.ini` 等，输出 `ini_candidates` 与 `ini_files`；
2. **逐文件解析关键配置**：每个 ini 文件解析 4 个关键项的**文件值**（不是运行值）；
3. **加固默认打 FPM**：`_target_of()` 优先选 `*/fpm/php.ini`；
4. **动作按文件值计算**：`_actions_for()` 用目标 ini 文件里的值对比建议值；
5. **校验按 SAPI 区分**：cli 目标用运行时核对（`php -r`），fpm/apache 目标用**文件内容**核对，
   避免"用 CLI 去验 FPM"导致的必然不符与误回滚。

### 已验证
- 计划目标已从 `/etc/php/8.3/cli/php.ini` 变为 **`/etc/php/8.3/fpm/php.ini`**；
- 动作来自 fpm 文件值：`session.upload_progress.enabled On→0`、`session.use_strict_mode 0→1`；
- 生成的 `harden.sh` 里确有 `TARGET_IS_CLI=0` 与 `SRC="file"` 分支（解压 zip 核对）。

### 未完成（下一步）
真机执行仍受一个**测试脚本问题**影响：目标机 `/tmp/hpf` 里残留旧的 `harden.sh`，
zip 解压没有覆盖成功，导致跑的仍是旧版校验逻辑 → 对着 CLI 运行时验 FPM 的值 → 必然失败回滚。
修法很简单（清空工作目录、确认 zip 路径后重跑），但本轮未能收尾。
**功能代码本身已就绪，缺一次干净的真机执行验证。**

### 回归
`pytest 252 passed`、ruff 全过、验收 29/29。

---

## [0.15.1] - 2026-10-30

主题：**多版本聚合（报最差版本）+ 状态与原因同源**

### 问题一：多版本主机只报一个版本，掩盖了更差的那个
云主机上同时跑 8.2.34 / 8.2.35 / 8.3.35 / 8.3.36 / 8.4.26 / 8.4.27 六个 PHP，
资产却显示 8.4.26 —— 而**最差的其实是 8.2.34**（更老的分支、同样未修复）。

修复：
- `Profile.php_instances` 记录每个 PHP 服务的 `{port, version, sapi}`；
- 新增 `pick_worst_php()`：先按判定严重度（vulnerable > EOL > unknown > patched），
  再按版本号低，选出最该关注的那个；
- 资产与台账都保留完整实例列表；
- 证据里写清：`共检出 6 个 PHP 实例（:8081=8.4.26 … :8086=8.3.36），按最差版本判定`；
- 「PHP 暴露面」页在版本下显示「N 个实例」，悬浮可看每个端口对应的版本。

实测：`实验场` 的判定从 `8.4.26` 变为 **`8.2.34`**，底线 `8.2.35`。

### 问题二：状态说"已修复"，说明写"低于基线，受影响"
`/api/php-exposure` 用**版本号重新 classify** 生成 status/reason，
而资产上的 `exposure` 已经过 **changelog / 补丁标志** 校正 —— 两个来源打架。
内网两台 8.3.6 主机就是这样：标签"已修复"，说明却写"低于修复基线 8.3.36，受影响"。

修复：状态与原因统一取**资产上的权威结论**（`exposure` + `host_reason`），
只有在没有主机侧结论时才回退到版本判定。修复后：
```
验证机  8.3.6  status=patched  reason=主机侧确认已修复：全部 PHP 安装点（8.3.6）已达修复基线
实验场 8.2.34 status=vulnerable reason=低于修复基线 8.2.35，受影响（6 个实例）
```

### 回归
`pytest 252 passed`（新增 5 条多版本聚合测试）、ruff 全过、验收 29/29、JS 语法 OK。

---

## [0.15.0] - 2026-10-30

主题：**四个维护分支的版本矩阵实测（判定准确性闭环）**

### 矩阵靶场
云主机上再起 4 套 fpm 站点（8083–8086），与已有 8.4.26/8.4.27 组成完整矩阵：
8083=8.2.34、8084=8.2.35、8085=8.3.35、8086=8.3.36。

### 实测：补丁标志与判定 4/4 一致
```
镜像      容器内版本   补丁标志   我们的判定    真值         结果
8.2.34    8.2.34     False     vulnerable  vulnerable  PASS
8.2.35    8.2.35     True      patched     patched     PASS
8.3.35    8.3.35     False     vulnerable  vulnerable  PASS
8.3.36    8.3.36     True      patched     patched     PASS
```
连同 0.13.0 验证的 8.4.26/8.4.27 与公告中的 8.5.11/8.5.12，
**四个维护分支的修复前/修复后全部有真机证据**，判定与真值无一偏差。

### 新增回归测试
`tests/test_version_matrix.py`：把 8 个版本 → 期望状态固化为参数化测试，
今后任何改动破坏判定都会立刻红灯。

### 端口覆盖再补
矩阵暴露 8083–8086 同样不在扫描列表，已补 **8083–8087**，全端口集 135 → 140。
实测扫描 实验场 时 8081–8086 全部被发现。

### 发现一个待改进点（未修）
一台主机存在多个 PHP 版本时，资产只展示一个（当前取首个检出 8.4.26），
而最差的是 8083 上的 8.2.34。正确做法是展示**最差版本**并列出全部检出。

### 回归
`pytest 247 passed`、ruff 全过、验收 29/29。

---

## [0.14.0] - 2026-10-30

主题：**云端靶场 + 假阴性/假阳性双向实测**

### 靶场（实验场，root 账号）
用 `docker run` 起两套真实站点（该机没有 compose 插件）：

| 端口 | 镜像 | 用途 |
|---|---|---|
| 8081 | `php:8.4.26-fpm` + `nginx:alpine` | 漏洞版 |
| 8082 | `php:8.4.27-fpm` + `nginx:alpine` | 修复版 |

nginx 走 fastcgi 到 fpm，页面 `index.php` 真实调用 `session_start()`，
响应头暴露 `X-Powered-By: PHP/8.4.26` 与 `Set-Cookie: PHPSESSID=...`。

### 假阴性测试（我们会不会漏报）**通过**
扫描 `实验场` 后，资产与 PHP 暴露面给出：
```
php_version = 8.4.26  sapi = fpm
status = vulnerable   exposure = exposed   risk = critical
reason = 低于修复基线 8.4.27，受影响
```
并自动生成 4 条整改建议（升级 / memory_limit / upload_progress / 8.5 的 fatal_error_backtraces）。

### 假阳性测试（会不会误报）**通过**
`docker stop p2s-lab-web` 只留 8.4.27 站点后重新扫描：
```
php_version = 8.4.27  status = patched  exposure = patched  risk = low
```
—— 不再报警，判定正确。

### 顺带修复：Web 端口覆盖
靶场暴露了端口表缺口：8081 不在扫描列表里（`EXTRA_WEB_PORTS` 只到 8000/8010…8090 的整十位）。
已补 **8081 / 8082 / 8088**（极常见的第二 Web 端口：Tomcat、备用站点、反代），
全端口集从 132 → 135。

### 环境约束记录
- 该云主机**没有 `docker compose` 插件**，用 `docker run` + 自定义 network 起多容器；
- 宿主机 80 端口被系统 nginx 占用，靶场改映射 8081/8082；
- 交互式命令一律写成脚本文件上传执行（PowerShell 内联引号会把 `{{...}}` 和中文拆坏）。

### 回归
`pytest 237 passed`、ruff 全过、验收 29/29。

---

## [0.13.1] - 2026-10-30

主题：**加固包在真实 Linux 主机上跑通（第二台云主机）**

### 实验环境
第二台云主机 `验证机`（Ubuntu 24.04，普通用户 `ubuntu` + 免密 sudo）。
安装 `php8.3-fpm` + `php8.3-cli` + `nginx`，得到**真实的 /etc/php/8.3/cli/php.ini**，
用于验证加固包能否安全地改生产文件。

### 真机端到端流程（全部跑通）
```
采集(agent --out) → 离线导入台账 → 生成加固包(zip)
→ 上传目标机 → sudo sh harden.sh → 预检/备份/应用/校验
→ 回执 JSON → POST /api/hardening/receipt → 资产标记 verified
```
执行输出：
```
[1/5] 预检  预检通过
[2/5] 备份  已备份到 /etc/php/8.3/cli/php.ini.p2s.bak.20261030-180548
[3/5] 应用  session.upload_progress.enabled = 0
[4/5] 校验  [session.upload_progress.enabled] 0 OK
[5/5] 完成  回执已生成
```
回执校验结果：`{"ok":true,"host":"验证机","verified_at":"...","applied":1}`，
台账状态变为 `hardening=verified`。

### 真机暴露并修复的两个 bug
1. **回执 JSON 非法**：`"host":验证机` 缺引号（`printf` 用了 `%s` 但没在模板里加引号）；
   单测抓不到，只有真跑一次才会发现；
2. **`before_sha` 为空**：`_ingest_host_report` 构造 `host_report` 时用固定键列表，
   把我新加的 `ini_sha256/ini_path/php_bin` 丢掉了 → 加固包拿不到 sha，完整性校验形同虚设。
   已改为保留这三个字段。

### 漂移检测顺带得到验证
回执校验后基线记录 `upload_progress=0`，而台账里那份报告还是加固前的 `1`，
于是 `plan` 立刻报出漂移：`expected=0, actual=1` —— 等下一次上报就会消失。

### 回归
`pytest 237 passed`、ruff 全过、验收 29/29。

### 两台测试机的分工
| 主机 | 用途 |
|---|---|
| 实验场（root） | 漏洞版本镜像矩阵、容器场景、靶场 |
| 验证机（ubuntu+sudo） | 真实 PHP 安装、加固包执行、Agent 端到端 |

---

## [0.13.0] - 2026-10-30

主题：**用真实漏洞版本验证检测逻辑（云主机实验场）+ 容器结论修复**

### 背景
此前所有验证都跑在 Windows 开发机上，而业务主机几乎都是 Linux。
用户提供云主机 `实验场` 作为实验场后，测试方式改为：**在 Linux 上拉真实 PHP 镜像验证**。

### 关键实验：补丁指纹的正反双向验证（首次拿到）
拉取 `php:8.4.26-cli`（漏洞版）与 `php:8.4.27-cli`（修复版）对比：

| 版本 | 构建时间 | `memory_hard_limit_percent` |
|---|---|---|
| 8.4.26 | 2026-10-21 | **`bool(false)`** —— 指令不存在 |
| 8.4.27 | 2026-10-28 | **`string(0) ""`** —— 指令存在 |

这补上了 0.11.0 里"只有正向验证、没有反向样本"的缺口：
该指纹在**未修复构建上确实返回 false**，可以安全用作加权证据。

### 修复：容器安装点不再一律 unknown
把我们的代码（`/opt/p2s-src`）部署到云主机后跑 `run_host_check`，发现容器安装点被判为
`verdict=unknown`，理由写"版本来自镜像标签，未经容器内核实"——**但我们明明能 exec 进去**。

- `containers._probe_inside()`：一次 exec 同时取 `PHP_VERSION | PHP_SAPI | 补丁标志`；
- 开启 `P2S_CONTAINER_EXEC=1` 时以容器内实际值为准（`verified=True`）；
- `hostcheck` 合并容器时按"版本判定 + 补丁标志"给真实结论，规则与主机侧一致。

修复后同一环境输出：
```
container:p2s-lab-vuln   v8.4.26  verdict=vulnerable  ← 未修复版本，正确报警
container:p2s-lab-fixed  v8.4.27  verdict=patched     ← 修复版本，不误报
```

### 测试方式变更（重要）
- 不再用 Windows 做主要验证；改为在 Linux 实验机上跑真实镜像 + 真实脚本；
- 加固包 E2E 也改在 Linux 上用替身 php + 临时 ini 执行，未触碰生产 php.ini；
- 实验容器 `p2s-lab-vuln` / `p2s-lab-fixed` 保留在云主机上，供后续回归使用。

### 回归
`pytest 237 passed`（新增 7 条容器结论测试）、ruff 全过。

### 下一步
- 用同一实验场补 8.2.x / 8.3.x / 8.5.x 三档的样本矩阵；
- 用 FPM + nginx 镜像验证 `session.upload_progress` 的真实可达性；
- 用漏洞版镜像做一次**靶场假阴性验证**（本地起 vulnerable 站点 → 扫 → 必须报 vulnerable）。

---

## [0.12.0] - 2026-10-30

主题：**配置加固三层能力（L1 加固包 / L1.5 漂移检测 / L2 受控执行）**

### 设计前提
**平台永远不直接写业务主机。** 变更以"包"产出，由运维执行或 Agent 主动拉取，
执行完回执校验通过才算数。动作白名单只有三项，不存在"执行任意命令"。

### 新增
- `core/hardening.py`：建议值表、动作生成、布尔归一（On/1 等价）、漂移计算、加固包生成；
- `console/hardening_api.py`：
  - `GET /api/hardening/plan/{host}` 方案（含漂移）；
  - `GET /api/hardening/pack/{host}` 下载 zip（harden.sh / rollback.sh / diff.patch / manifest.json / README.txt）；
  - `POST /api/hardening/receipt` 回执校验（动作清单/取值/前后 sha 四重校验）；
  - `POST /api/hardening/request` + `GET pending` + `POST revoke`：一次性令牌（10 分钟、绑定主机与动作哈希）；
- 采集脚本补 `php_bin` / `ini_path` / `ini_sha256`，让加固包能做完整性校验；
- 资产行新增「配置加固」图标按钮 + 弹窗（看方案 / 下载包 / 签发令牌 / 贴回执）。

### 加固包的安全设计
- **预检四件套**：文件存在可写、非容器、sha256 一致、未被 Ansible/Puppet 托管；
- **校验失败自动回滚**（改完立刻用 `ini_get` 比对生效值）；
- **备份 + 回滚脚本**：`.p2s.bak.<时间戳>`；
- **不接受任意命令**：脚本内只有 `apply_kv` / `verify_kv` 两个函数。

### 实测（真实主机，未触碰生产文件）
在 Ubuntu 24.04 上用替身 php + 临时 ini 跑完整流程：
| 用例 | 结果 |
|---|---|
| 语法检查 | 通过 |
| sha 不匹配 | 退出 13 ✅ |
| 配置管理托管 | 退出 14 ✅ |
| 正常执行 | 4 项改完、校验 4/4、生成回执 ✅ |
| 校验失败 | 自动回滚、退出 30 ✅ |
| 回滚脚本 | 恢复原内容 ✅ |

真实资产 `web-01`：识别出 1 项待加固，加固包 5.8KB 正常下载。

### 回归
`pytest 230 passed`（新增 7 条加固测试，含 shell 注入用 `shlex` 校验）、
JS 语法 OK、ruff 全过。

### 已知边界
- 只有正向验证（已打补丁的主机），补丁指纹无反向样本；
- 加固包不重启服务（可选 reload），重启时机交给运维；
- L3 全自动（Agent 自动拉取并执行）尚未实现，接口已预留 pending/revoke。

---

## [0.11.0] - 2026-10-30

主题：**对标公开实现：补丁指纹 + 结论口径校正 + 生态调研**

### 背景
用户提供了 Gitee / GitHub 上的同类实现，要求"看看他们用了什么技术，我们有什么可借鉴"。
调研前我只读了 README 与仓库简介，**没有读源码**——被指出后补读，本版是补读后的落地。

### 新增：运行时补丁指纹
- `hostcheck.probe_patch_flag()`：用 `ini_get("memory_hard_limit_percent")` 是否存在，
  判断补丁是否**真的编进了二进制**（借鉴 php2shell-guard）。
- **本机实测**（192.168.1.188 / PHP 8.3.6 / 已回移补丁）：
  `var_dump(ini_get("memory_hard_limit_percent"))` → `string(0) ""`（指令存在）。
- 判定规则：指令存在 → 视为已修复；版本说已修但指令不存在 → **降级为"无法确定"并标冲突**，
  不再单方面相信版本号。
- Linux / Windows 采集脚本同步输出 `patch_flag` 字段。
- 诚实边界：只有正向验证，**没有未打补丁样本做反向验证**，故作为加权证据而非唯一判据。

### 修正：结论口径（重要）
公开研究（ikow/php2shell-poc）指出共 5 条利用链，其中：
- **Chain D**：OOM → 陈旧 `EG()`，mod_php 下**无任何前置条件**；
- **Chain E**：FPM 下"生产端任意 `session_start()`、**消费端任意 endpoint**"——
  因为 `rfc1867` 上传进度处理器在 SAPI 启动阶段就执行，早于应用代码。

因此"站点不使用 session 就安全"是错的。已改写 `_SETTING_ADVICE`：
`session.upload_progress.enabled=0` 定位为**必做项**，并写明
"最快的临时缓解是 WAF 拦截 multipart 里的 PHP_SESSION_UPLOAD_PROGRESS；
唯一完整修复仍是升级 PHP"。
另补 `session.use_only_cookies` / `session.use_strict_mode` 两条建议。

### 调研结论（详见 `docs/03-情报/同类工具调研与借鉴.md`）
- **规则库我们并不落后**：13 条规则与 ikow 的 13 条 Suricata 规则**一一对应**，
  另多一条"扫描器 UA"；
- 真正差距在**修复能力**：配置加固（备份/确认/回滚）与 compose 自动升级，我们都没有；
- 已记录 5 项值得补的能力，按性价比排序。

### 回归
`pytest 223` / 验收 29/29 / 功能验证 43/43 / JS 语法 OK / ruff 全过。

### 下一步（未做）
1. 配置加固：改 php.ini 前备份 + 逐项确认 + 给回滚命令；
2. 容器 compose 自动升级：改 tag → 重建 → 自动验证；
3. CLI 退出码契约（0/1/3）便于 CI 集成。

---

## [0.10.6] - 2026-10-30

主题：**报告中心表格错位（真 bug）+ 新增 JS 语法门禁**

### 用户反馈
"报告中心列表里字段是不是有问题，看不懂" —— 确认是真错位。

### 根因
表头写了 9 列（报告 / 类型 / 目标 / 风险 / **发现 / 严重 / 高危** / 开始 / 操作），
但数据行只渲染了 7 个单元格 —— **「严重」「高危」两列永远空白**，
其后的数值整体左移，读者自然对不上号。

同时「类型」与「目标」两列内容完全相同（都是"日志分析"），看起来像重复列。

### 修复
- 数据行补齐 9 个单元格：`发现`=总条数、`严重`=`severity_counts.critical`、`高危`=`.high`，
  为 0 时置灰（`.muted`），一眼能看出"有 16 条但严重只有 3 条"；
- 目标与类型相同时（历史日志未保存文件名）显示 `—` 并加说明 tooltip，不再重复。

### 新增门禁：`scripts/check_page_js.py`
把服务端返回的页面内联 JS 抽出来交给 `node --check` 做语法校验。
起因：本轮改表格时行尾留了个悬空的 `||`，**页面直接白屏**，
而 ruff / pytest / 契约测试全绿——它们都看不到浏览器里的 JS。
现在这条检查能在启动浏览器之前抓到语法错误：
```
[OK] 内联 JS 语法正确（91580 字符）
```

### 回归
`pytest 223` / 验收 29/29 / 功能验证 43/43 / UI 冒烟 14/14 / JS 语法 OK / ruff 全过。

### 教训
前端模板（Python 字符串里的 HTML+JS）是最脆弱的一层：
**标签配平、模板字符串反引号、`||` 的右操作数**这三类错误，静态检查抓不到、单元测试抓不到，
只有"渲染一次"才能发现。以后前端改动固定跑：`check_page_js.py` → 截图。

---

## [0.10.5] - 2026-10-30

主题：**交互细节收尾（四项）**

### 1. 资产台账：操作列图标化
「详情 / 复扫」两个文字按钮改为图标按钮（放大镜 / 刷新），带 `title` 提示；
外层 `.act-row` 用 flex 横排，列宽固定 96px，不再挤压。

### 2. 报告中心：行内只留必要动作
原来每行挤着「查看 + MD + HTML + JSON + 删除」五个元素，小屏会溢出。
现在行内只保留「查看」「删除」，三种格式下载收进**详情抽屉**（那里本来就有）。

### 3. 设备发现：超时输入框补标签
`TCP 超时(秒)` / `HTTP 超时(秒)` 原来是 `title` 悬浮提示，看不见。现在改为输入框上方的可见标签。

### 4. 设备发现：历史任务入口
任务列表只显示最近 4 条，超出时显示「还有 N 条历史任务，去任务中心查看 →」。

### 事故记录
给超时输入框加标签时，**多开了一个 `<div class="f150">` 没闭合**，导致整页被压成 150px 宽的竖条
（每个汉字一行）。截图立刻发现并修好。
教训同前：**改模板结构必须数清 div 开闭**，改完必须截图。

### 验证
- 用 CDP 读取计算样式确认操作列布局：`td 96px / .act-row flex / 两按钮同一 y 坐标`；
- 报告中心、设备发现、资产台账亮暗两套截图复核；
- 门禁：`pytest 223` / 验收 29/29 / 功能验证 43/43 / UI 冒烟 14/14 / ruff 全过。

### 仍待办
- 任务中心缺少批量删除（逐个确认）；
- 「URL 探测」页的输入区在窄屏下会换行错位。

---

## [0.10.4] - 2026-10-30

主题：**四项收尾 —— 暗色对比度 / 任务入口 / 审计降噪 / 表格细节**

### 1. 暗色主题对比度
六个语义 soft 底色与边框整体提亮一档，解决"卡片和背景糊在一起、标签像黑洞"：
```
--border        #2a313b → #333b47
--accent-soft   #18243a → #1d2c47   --accent-border #2b3f60 → #35507a
--danger-soft   #2a1a19 → #3a211f   --danger-border #4a2c29 → #5f3833
--warn-soft     #2a2117 → #3a2c1b   --ok-soft       #15281f → #17352a
--neutral-soft  #232830 → #2b313b
```

### 2. 设备发现：历史任务入口
任务列表本来就只显示最近 4 条，但**没有告诉用户还有多少**。现在超出时显示
「还有 N 条历史任务，去任务中心查看 →」，点击直达。

### 3. 审计日志降噪
- 新增「**隐藏未登录请求**」（默认开启）：过滤掉 `/api/login` 等匿名记录；
- 新增「**合并连续重复**」（默认开启）：同操作人 + 同方法 + 同接口的连续记录合并为一条，
  带 `×N` 角标。实测把 200 条刷屏压到十几条可读记录。

### 4. 表格细节
- 审计表：来源列（IP）不再折行，行高收紧（7px padding），列宽固定；
- 资产台账此前已隐藏 4 个低价值列。

### 验证
亮/暗两套截图逐页确认；`pytest 223` / 验收 29/29 / 功能验证 43/43 / UI 冒烟 14/14 / ruff 全过。

### 仍待办（下一轮候选）
- 资产台账「操作」列图标化（现在是「详情/复扫」两个文字按钮）；
- 报告中心「MD / HTML / JSON」三个链接在小屏下会挤；
- 任务中心的删除是逐条确认，无批量删除。

---

## [0.10.3] - 2026-10-30

主题：**空态重做 + 暗色走查（14 页全覆盖）**

### 修复
- **主机侧检测空态**：原来是一段带「1. 2. 3. 4.」文字的居中块，序号与正文分离、看着像排版事故。
  改为 `<ol class="steps">` + 新增「立即检测本机」按钮，四项检测内容一目了然。
  连带修了两处：`.empty b{display:block}` 误伤了步骤里的行内 `<b>`（把一行拆成三行）→ 收敛为 `.empty > b`；
  空态按钮被 flex 拉伸满宽 → `.row > .btn{flex:0 0 auto}`。
- **日志分析空态**：原来输入框下方是大片空白。补了一张引导卡：支持格式、文件大小建议、覆盖范围
  （请求体类规则需 WAF 记录 `request_body`），并说明可直接拖拽上传。
- **窄页居中**：`.page-narrow` 加 `margin:0 auto`，计划任务/日得分析在宽屏下不再贴左。

### 暗色走查（14 页）
用 `screenshot_all.py dark` 抓完 14 页做联系表比对，主要问题是边界过暗导致卡片与背景糊在一起，
已把暗色 `--border` 从 `#2a2f38` 提到 `#333b47`。

### 事故记录（过程中的一次自伤）
重写空态时把 JS 模板字符串的结尾反引号弄丢，导致**整页空白**（白屏），
是截图验证发现的；已修复并补上模板结尾。
教训：改模板字符串必须成对检查反引号，改完立刻截图，不能只看 ruff/pytest。

### 回归
`pytest 223` / 验收 29/29 / 功能验证 43/43 / UI 冒烟 14/14 / ruff 全过。

### 仍待办
- 暗色下的语义 tag（warn/ok）底色对比度还没逐个调；
- 「设备发现」的历史任务列表在任务多时会很长，可考虑折叠只显示最近 3 条。

---

## [0.10.2] - 2026-10-30

主题：**全部 14 个页面逐页走查并修复**

### 方法
新增 `scripts/screenshot_all.py`（Chrome CDP 批量截图），一次抓完 14 个页面，
再用 2×2 联系表逐屏比对——避免"只看总览页就以为全局都行"。

### 修复
| 页面 | 问题 | 修法 |
|---|---|---|
| **整改跟踪** | **责任人列显示 `<span class="muted">未指派</span>` 源码** | 原先把 HTML 当字符串 `esc()` 了；改为条件渲染，空值才输出标签 |
| 规则中心 | 规则 ID 折成两行（`P2S-REQ-` / `001`） | 表格首列 `white-space:nowrap` |
| IOC 中心 | 长 URL 撑破列宽 | `td.mono{word-break:break-all}` |
| 计划任务 / 日志分析 | 内容少但横向拉满，大片留白 | 新增 `.page-narrow{max-width:880px}` |
| **资产台账** | 12 列过密、大量 `-` 占位 | 用 `:has(#a-body)` 隐藏 技术栈/变化/置信度/分组 四列（详情抽屉仍有），保留 9 列 |

### 验证
- 14 页截图归档于 `docs/screenshots/pages/`（light-*.png）；
- 修复后复拍整改跟踪/规则/IOC/报告/资产五页确认；
- 门禁：`pytest 223` / 验收 29/29 / 功能验证 43/43 / ruff 全过。

### 仍待处理（如实记录）
- 「主机侧检测」空态排版仍偏散（下载卡片 + 步骤说明的排布未重做）；
- 「日志分析」空态仍留白较多；
- 暗色主题只核对了总览页，其余 13 页未逐一走查。

---

## [0.10.1] - 2026-10-30

主题：**视觉精修 —— 去"AI 味"，走克制的一线工具风格**

### 设计原则（明确不做的事）
- ❌ 不用渐变、玻璃态、发光、彩色投影；
- ❌ 不用紫色系"科技感"配色、不用彩虹色图表；
- ❌ 不用大圆角（>8px）与大阴影；
- ✅ 单色系图表 + 中性灰阶 + 1px 细线；✅ 等宽数字与统一 4px 栅格；✅ 层级靠**对比度**而非装饰。

### 具体改动
| 元素 | 改前 | 改后 |
|---|---|---|
| 中性色 | `#f2f3f5 / #dfe3e8` 偏灰 | `#f4f5f7 / #e4e7ec` 冷调中性，层次更清 |
| 强调色 | 全局一个蓝 | 仅用于「选中/主操作」，图表另设 4 级低饱和色阶 |
| 卡片 | 阴影不明显、圆角 6px | 统一 8px + `0 1px 2px rgba(16,24,40,.04)` 极轻投影 |
| 环形图 | 环宽 18px、段间无缝 | **环宽 11px + 段间 0.018rad 缝隙**，视觉更轻 |
| 条形图 | 6px 实心条、颜色偏艳 | 细条 + 轨道可见 + 端点圆角 2px |
| 修复进度条 | 14px 高，像色块 | **8px 细条**，图例改圆点 |
| 数字 | 默认字体 | 全部 `tabular-nums` + `letter-spacing:-.01em` |
| 图例 | 数值左浮动、对不齐 | **三列网格**（色点 / 标签 / 右对齐数值） |
| 表格 | 表头偏重、行高偏大 | 表头 11px/600/字距 .03em，行高 8px padding，悬停极轻底色 |

### 验证方式
新增 `scripts/screenshot.py`（Chrome CDP 截图），本轮**逐轮截图比对**：
- 亮色：`docs/screenshots/design-after-light.png`
- 暗色：`docs/screenshots/design-after-dark.png`
- 改前：`docs/screenshots/design-before.png`

共迭代 5 轮：令牌 → 卡片/KPI → 环形/条形 → 进度条/表格 → 图例对齐，
每轮都重新截图确认，而不是"改完就宣布完成"。

### 回归
`pytest 223 passed`、ruff 全过、验收 29/29、UI 冒烟 14/14。

### 已知边界
- 暗色主题只逐页检查了总览页，其余页面待走查；
- KPI 卡片在 1366px 以下会折成两行（可接受，但未做专项适配）。

---

## [0.10.0] - 2026-10-30

主题：**弹层交互全面修复 —— 用真实浏览器点击验证**

### 事故
用户反馈：点开右上角告警通知后**关不掉**，点 ✕ 没反应、点铃铛也关不掉。

### 根因（两层，都很隐蔽）
1. **弹层 DOM 出现在 `<script>` 之后**（服务端 HTML 中 `#alert-close` 位于第 127094 字节，
   而绑定代码执行于第 125602 字节）。启动时 `$('#alert-close')` 是 `null`，
   `if(el) el.onclick=...` 的守卫把"崩溃"变成了"静默不绑定" —— 于是按钮永远没有 handler。
   **这是"加了空值守卫反而掩盖 bug"的典型案例。**
2. 弹层开关依赖逐元素 `onclick` 绑定；一旦节点被重渲染或插入时机变化，整个交互就失效。

### 修复
- 弹层交互改为 **document 级事件委托**：铃铛开关 / ✕ 关闭 / 点遮罩关闭 /
  点弹层外部关闭 / Esc 关闭，全部由一处统一处理，对 DOM 时序与重渲染免疫；
- **切换页面时自动收起所有浮层**（`go()` 开头调用 `closeAlerts()` + `closeDrawer()`），
  否则弹层会盖在新页面上，看起来像"页面卡死"。

### 验证方式（这次不用推论，用真浏览器）
新增两个可用 Playwright/CDP 驱动的 UI 冒烟脚本，逐项真实点击：

`scripts/ui_test_overlays.py`（告警弹层，7 项全过）
```
[PASS] 页面就绪  [PASS] 初始隐藏  [PASS] 点铃铛后打开  [PASS] 点✕后关闭
[PASS] 点遮罩后关闭  [PASS] ESC 关闭  [PASS] 点页面外部关闭
```

`scripts/ui_test_dialogs.py`（抽屉 + 确认框 + 切页残留，7 项全过）
```
[PASS] 抽屉打开  [PASS] 点遮罩关闭抽屉  [PASS] ESC 关闭抽屉
[PASS] 确认框出现  [PASS] 点取消后消失  [PASS] ESC 关闭确认框
[PASS] 切页后告警弹层自动收起   ← 本轮发现的第二处 bug
```

### 说明
- 之前一直用无头 Edge 截图，反复崩溃；这次改用 **Chrome + CDP**（`--headless=new`），
  并解决了 CDP 等待 Promise 导致超时的问题，终于能把"点击"这条链路自动化验证。

### 回归
`pytest 223 passed` / ruff 全过 / 验收 29/29 / 两个 UI 冒烟 14/14。

---

## [0.9.9] - 2026-10-30

主题：**离线采集模式（跨网/无网主机）+ Agent 自身文件白名单**

### 背景
实测云主机 `实验场` 时发现：该主机访问不到内网控制台，
Agent 只能本地采集、无法上报。于是把"`--out` 导出 → 内网导入"做成正式能力。

### 新增：离线采集导入
- `POST /api/agent/import`：接收 Agent 用 `--out` 导出的 JSON，
  **走与在线上报完全相同的归一化与入库逻辑**，因此两种方式结论口径一致；
- 「Agent 管理」页新增「导入离线报告」按钮（选 JSON 文件即导入）；
- 适用场景：云主机、隔离网段、跳板机后侧主机、客户要求"只带结果不带链路"。

用法：
```bash
# 目标机（无网也能跑）
sh p2s-agent.sh --out /tmp/report.json
# 把文件带回内网，在控制台「Agent 管理 → 导入离线报告」选择即可
```

### 新增：Agent 自身文件白名单
- 采集脚本增加 `SELF_EXCLUDE`（`p2s-agent|p2s_agent|run_agent.sh`），
  扫描近 7 天新增文件时排除自身产物；
- 服务端 `_strip_self_artifacts()` 二次过滤 —— 即使旧脚本上报了自身，也不会入库成告警。
  实测导入云主机报告后 `artifacts` 为空（原先会把自己标成 medium 可疑文件）。

### 验证（真实数据）
```
用云主机真实报告走离线导入：
  {"ok":true,"scan_id":"host-5f7c0f1e7e","host":"lab-host",
   "exposure":"not_php","reason":"主机侧未发现 PHP 安装点"}
台账：installs=0、artifacts=[]（自身文件已被过滤）
```

### 回归
`pytest 223 passed`（新增 3 条：离线导入、非法报文拒绝、自身文件过滤）、ruff 全过。

### 已知边界
- 离线导入的命令行入口（`p2s import <file>`）尚未提供，目前走页面或接口；
- 离线报告不带设备指纹（IP/MAC），合并到已有资产时依赖 `ip` 字段。

---

## [0.9.8] - 2026-10-30

主题：**云主机实测 + 资产身份合并（远程按 IP / 本地按主机名 的冲突）**

### 实测对象
客户提供的云主机 `实验场`（Ubuntu 22.04，自有凭据，已授权）。

| 维度 | 远程扫描结论 | 本地 Agent 结论 |
|---|---|---|
| 主机 | Ubuntu Linux（SSH banner，0.57） | ubuntu 22.04（0.95） |
| PHP | 未检测到痕迹 | **0 个安装点**（确认无 PHP） |
| 暴露面 | not_php | **not_php**（两侧一致） |
| 额外发现 | 4 个 Web 服务（80/8000/8090/8888） | Docker: clickhouse、hfish 两个容器 |

远程还识别出三个真实应用标题：`Stock Agent - 智能股票分析`、`AttackFlow - Kill Chain Editor`、
`认知蒸馏器 · DistillMind`，以及 `uvicorn` 后端（:8000 返回 404）。

### 修复（真实缺陷）
**同一台机器在台账里出现两条记录**：远程扫描按 IP 建档（`实验场`），
Agent 上报按主机名建档（`instance-9rickky7`），两者无法互相印证。

- Agent 上报改为 **IP 优先**：`ip` 为空时用**上报请求的来源 IP**兜底，
  且只有来源确实是合法 IP 才采用（避免把 `testclient`、代理名写进台账）；
- 新增 `_merge_hostname_alias()`：把按 hostname 建的旧档案迁移/合并到 IP 档案，
  保留 `id / first_seen / remediation_status / owner`，不丢历史与处置状态。

修复后该主机在台账中只剩一条：`实验场 · Ubuntu · exposure=not_php · 证据=host · 0.95`。

### 另一个观察
Agent 采集把测试脚本自己标成了「近 7 天新增可疑文件」（severity=medium）——
说明痕迹扫描确实在工作；这也提示：**部署 Agent 后应把脚本自身路径加入白名单**，
否则每台机器都会带一条噪声告警（待办）。

### 回归
`pytest 220 passed`、ruff 全过。

---

## [0.9.7] - 2026-10-30

主题：**JS 渲染设备的静态资源指纹（借鉴 Fofa/Shodan 的 body/JS 特征思路）**

### 问题
捷普 226/235 的首页是纯 JS 应用：`<title>` 为空，只有一段浏览器检测脚本。
无论怎么抓页面都只能得到 "捷普设备（SSH 标识 JSH）"，产品线为空。

### 方案
抓取页面引用的**静态资源**（i18n 文案与主包），从中提取**白名单内的产品线词**：

- 新增 `core/jsfingerprint.py`：产品线词白名单 + 出现次数门槛（≥3 次）+ 去噪词表；
- 深度模式**总是**抓静态资源（原先只在"没认出品牌"时抓，导致品牌已识别就跳过）；
- 资源引用正则兼容**无引号属性**（`src=static/js/main.js`），并按价值排序
  （language/i18n/main/app 优先，取前 5 个）；
- Content-Type 判断放宽到 `application/javascript`（原先只认 `text/*`，JS 全被跳过）；
- 新增 `Field.JS` 证据通道，置信度封顶 0.72，标注"服务级证据，非产品级确认"。

### 关键取舍：JS 里的品牌词**不可信**
实测 226 的 i18n 里出现了「天融信」——那是"厂商下拉列表"文案，不是设备身份。
因此：**JS 只提供产品线，品牌必须来自页面 HTML/证书/banner**，
最终产品名由 `厂商 + 产品线词` 组合（如「捷普防火墙（静态资源）」）。
产品线词按**出现次数**取最高，平票时按特异性（防火墙 > SSL VPN > VPN）。

### 实测（全面段深扫 + 单机复扫）
| 项 | 快速模式 | 深度模式 |
|---|---|---|
| 在线设备 | 14 台 | **18 台**（多找到 120/228/230/233） |
| 识别出品牌 | — | 16 / 18 |
| 打印机 200 | 未识别 | 富士施乐复合机（0.98，证书） |
| 226 / 235 | 捷普设备（SSH） | **捷普防火墙（静态资源）** |
| 253 | 华为交换机 0.72 | **华为 Quidway 交换机 0.90**（证书） |

### 遗留
- `192.168.1.120` 仍为未识别：仅开 139/445/9001，无 HTTP 产品级特征（疑为 SMB 设备），
  需人工确认型号后再考虑加入签名，**不猜测**。

### 回归
`pytest 220 passed`、ruff 全过、验收 29/29。

---

## [0.9.6] - 2026-10-30

主题：**规则库体系化扩充 + 打印/复合机识别（真实设备驱动）**

### 背景
用户指出 192.168.1.200 是富士施乐 ApeosPort 3560，而我们判成「未识别（0.1）」。
排查发现三条真实线索全被浪费：首页是 **JS 跳转**（非 3xx）、**9100 打印口**未定义、
证书 `CN=FX-` 无对应签名。

### 新增
- **JS 跳转跟随**：识别 `location.href=... / location.replace(...)`，跟随一次，
  解决嵌入式设备（打印机/摄像头/NAS）首页只有一句跳转脚本、标题永远取不到的问题。
- **`signatures_extra.py`（新增 59 条签名）**，全部基于真实且可验证的特征：
  - 打印：富士施乐（`CN=FX-`、ApeosPort、DocuCentre）、HP、Canon、Epson、Brother、Ricoh、
    Kyocera、Konica Minolta、Lexmark；
  - 存储：Synology、QNAP、TrueNAS/FreeNAS、NetApp；
  - 带外：HPE iLO、Dell iDRAC、Supermicro、Lenovo IMM；
  - 虚拟化：VMware ESXi/vCenter、Proxmox；
  - 研发运维：Jenkins、GitLab、Nexus、Harbor、Grafana、Kibana、Webmin、Tomcat、cPanel、Plesk、宝塔；
  - 监控：Hikvision、Dahua；
  - 国产安全：深信服、天融信、绿盟、启明星辰、安恒、奇安信、山石网科、迪普、锐捷、H3C、TP-Link。
- **端口语义扩展**：9100/515/631 打印、554 RTSP、2049 NFS、3260 iSCSI、623 IPMI、5060 SIP；
  这些端口**没有应用层响应也能定性**（已加入语义强端口白名单）。
- 新增设备类型「打印机 / 复合机」「NAS / 存储设备」。

### 收录纪律（写进模块文档）
1. 只收官方产品名 / 页面自报标识 / 证书主体 / 标准端口，**不编造**；
2. 标题与证书属产品级（T1），Server 头与正文属服务级（T2），后者不单独定厂商；
3. 短词（如 `ilo`、`canon`）只给低权重且限定字段，避免命中普通英文文本。

### 实测（真实设备复扫）
| 设备 | 结果 |
|---|---|
| 192.168.1.200 | **富士施乐复合机 / 打印机·复合机 / 0.98**（依据：证书 CN=FX-…） |
| 192.168.1.225 | 捷普 WEB 应用防火墙 / 0.74 |
| 192.168.1.229 | 捷普防火墙 / 0.73（443 标题 JD 还显示"捷普SSLVPN系统"） |
| 192.168.1.233 | 捷普信息审计系统 / 0.77 |

同时验证了一条既有规则的价值：225/229 的 **MAC OUI 是深信服**，但设备品牌仍是捷普 ——
我们的"OUI 不进厂商字段"策略在这种真实场景下避免了整片误判。

### 回归
`pytest 220 passed`（新增 17 条签名测试，含"普通英文文本不得命中 Canon"这类反例）、
ruff 全过、验收 29/29。

### 已知边界
- 打印/摄像头等设备的首页多为 JS 应用，**仅靠标题往往无解**，实际依赖证书与端口；
- 未收录的品牌会落到「未识别」，这是刻意选择（宁缺勿错）。

---

## [0.9.5] - 2026-10-30

主题：**内网实测结论落地（快速模式覆盖率 / Agent 回归 / M5 真实二进制）**

### 实测记录（公司内网 192.168.1.0/24）

| 项目 | 结果 |
|---|---|
| 快速模式 `/24` | 14 台在线 / 240 台无有效响应，噪声端口 `[25,110,143]` 正确剔除 |
| 深度模式 11 台 | **11/11 全中**，与已知设备清单一致 |
| 单台复扫漏检的 3 台（228/230/233） | **全部恢复**：228 捷普（Jump_server 标识）、230 PHP 站点、233 捷普信息审计 |
| Ubuntu Agent（0.9.x 重构后） | 上报正常：`patched`（changelog 回移）+ 1 项配置风险 + 2 条整改建议 + 5 条证据 |
| M5 真实 ELF | 修复后取到 build-id `8a5708fa…`；`.comment` 已被发行版 strip，如实返回空 |
| 容器清点 | 该主机无 docker，返回"跳过容器清点"且不影响主流程 |

### 关键结论
- **并发会影响召回**：254 台用快速模式一次扫描漏 3 台（≈82% 召回），
  但**单台复扫 100% 恢复**。这不是端口表的问题，是高并发下慢设备被超时截断。
  已在「设备发现」页加提示：快速模式适合普查，正式评估用深度模式或分批扫描。
- **Linux 上 M5 只能给 build-id，给不了构建时间**（ELF 头里没有），
  因此 Linux 判定的确定性仍依赖 **包 changelog**——这与代码行为一致，不是缺陷。
- Agent 采集脚本经 0.8.x→0.9.x 多轮重构后**仍然可用**（本次实机复测通过）。

### 变更
- 「设备发现」页补充快速模式覆盖率提示与深度模式建议。

### 回归
`pytest 203 passed` / ruff 全过 / 验收 29/29。

---

## [0.9.4] - 2026-10-30

主题：**M5 在真实 Linux 二进制上失效的修复（内网实测发现）**

### 问题
拿公司内网 Ubuntu 主机的 `/usr/bin/php8.3`（5.8 MB）实测，`probe_binary` 只返回
`kind=elf`，**build_id 与 toolchain 全是 None** —— 即 M5 在真实发行版二进制上等于没工作。

原因：Ubuntu 的 PHP 二进制被 strip，`e_shnum=0`（没有 section header），
而原实现只走 SHT_NOTE 段落路径，因此什么也找不到。

### 修复
- 增加**程序头 PT_NOTE** 遍历（strip 后 build-id 通常仍在这个段里）；
- 再增加**原始字节扫描**兜底：直接定位 `GNU\0` note 结构；
- 新增 2 条测试：只有 PT_NOTE 的 ELF、只有裸 note 字节的畸形文件，均能取到 build-id。

### 实测结果（真实主机）
```
/usr/bin/php8.3  kind=elf  size=5833168
build_id = 8a5708fa62ade09932193f9120e6e4d5d340a298   ← 修复后取到
toolchain = None（.comment 已被发行版移除，如实返回空）
```

### 重要结论（写进结论口径）
- **PE（Windows）有链接时间** → `built_before_fix` 可用，能判定"必然不含修复"；
- **ELF（Linux）没有构建时间** → 只能提供 build-id 与工具链，
  结论必须依赖**包 changelog**（已实现）或补丁标记库（待样本）。
  因此 Linux 上"没有 changelog 就判不了"是如实行为，不是缺陷。

### 回归
`pytest 203 passed`（新增 2 条）、ruff 全过、验收 29/29。

---

## [0.9.3] - 2026-10-30

主题：**从源头防止重复报告 + 自动清理**

### 新增
- **重复分析守卫**（`GET /api/scans/duplicate?kind&label&hours`）：
  分析日志前先查"同一目标在 24h 内是否分析过"。命中时：
  - 弹出确认「该目标刚分析过（报告 xxx，命中 N 条），仍要重新分析？」；
  - 同时给一个「查看上次」的提示条，一键跳到历史报告。
  已接入日志页的**路径分析**与**文件上传**两条入口。
- **报告自动清理**（`prune_scan_files`）：同一内容指纹只保留最新 `keep` 份，
  且**只删超过 N 天的旧报告**（默认 keep=3、7 天），当天新报告绝不动。
  - 挂在调度线程里，每 6 小时最多跑一次；
  - `P2S_AUTO_PRUNE=0` 可关闭，`P2S_PRUNE_KEEP` / `P2S_PRUNE_DAYS` 可调；
  - 手动入口：`POST /api/admin/prune?keep=3&min_age_days=7&dry_run=true`。
- 新增 `scripts/backfill_targets.py --prune-dry / --prune`（上一轮已用于清理 150 份重复报告）。

### 验证
- 重复检测：同一日志返回 `hit`（含 age_hours / findings / scan_id），不存在目标返回 `null`；
- 清理预演：`removed=0, kept_groups=24`（当前 24 组均无超期重复）；
- 页面注入：`dupGuard` 已进入日志页两处入口；
- 门禁：`pytest 201` / 验收 `29/29` / 功能验证 `43/43` / 深度验证 `8/8` / ruff 全过。

### 设计取舍
- **提示而不强制**：用户可能就是要在配置变更后重跑同一份日志，所以给"仍要重新分析"的出口；
- **清理只删超期的**：宁可少删，也不让自动化删掉今天刚生成的证据；
- 自动清理不发通知（避免噪音），但在审计里留 `POST /api/_prune` 记录。

### 已知边界
- 重复判定基于"目标标签 + 时间窗"，不比对文件内容哈希（同一文件名换了内容也会被提示）；
- 自动清理只针对报告文件，不动资产台账与任务历史。

---

## [0.9.2] - 2026-10-30

主题：**报告中心逻辑修正 —— 报告要能说清"这份在讲什么"**

### 问题
报告列表里几十份报告点开内容几乎一样。排查后确认**不是渲染 bug**，是两个设计缺陷：

1. 扫描记录**根本没存"目标"**（`params`/`targets` 都没落盘），报告里只有 `scan_id`，
   所以列表无法区分"同一份日志分析了 125 次"；
2. 每次分析都生成一份独立报告，同源同结果的重复执行全堆在列表里；
3. 报告标题只带 scan_id，客户看不出它覆盖了哪台机器/哪份日志。

### 修复
- `ScanResult` 新增 `target_label` 字段并写入 JSON；扫描创建时按类型自动生成
  （网段 / 首台主机等 N 台 / 日志文件名 / URL / Agent 主机名）；
- `/api/scans` 摘要新增 `target_label` 与 `dedupe_key`（内容指纹，不含时间与 scan_id）；
- 报告中心列表改为**同源折叠**：同指纹只显示最新一份，带 `×N` 角标；
  新增「目标」列与「发现」列，标题改为「报告」；
- 报告 HTML 页眉显示具体目标；
- 新增 `scripts/backfill_targets.py`：给 172 份历史报告补写目标并重渲染；
  另带 `--prune-dry / --prune` 清理重复扫描（同组只留最新）。

### 验证
- 172 份历史报告补写目标并重渲染成功；
- 报告列表 **172 条 → 22 组**，最大一组 `125×`（同一份样例日志重复分析）；
- md / html / json 三种格式全部 200；
- 门禁：`pytest 201`、验收 `29/29`、功能验证 `43/43`、ruff 全过。

### 修复的连带 bug
- `_analyze_log_file` 被批量插入 `res.target_label = _label_of(params)`，
  但该函数作用域内没有 `params` → **日志上传直接 500**。已改为使用 `source_name`。
  这是"批量正则改代码"的典型代价：**同形语句在多处出现时必须按函数边界精确替换**。

### 已知边界
- 历史报告的日志文件名无法还原（当时没存 params），只能标注"N 个来源、M 条"；
- `--prune` 会删除重复报告，属破坏性操作，默认 dry-run。

---

## [0.9.1] - 2026-10-30

主题：**修报告中心和"新增功能是否真的生效"**

### 修复
- **报告中心点 HTML 直接 500**：`scan_api.py` 里 `api_report` 使用了 `HTMLResponse`，
  但拆分模块时该导入留在了 `app.py` —— 未被导入的符号只在运行时爆炸，单测与契约测试都覆盖不到
  （它们走的是 md）。已补 `from fastapi.responses import HTMLResponse`。
  现在 md / html / json 三种格式全部 200，抽查 5 份报告 × 3 格式无异常。
- 报告中心"共 N 份"改用接口返回的 `total`，此前用当页数组长度，
  超过 500 条时会显示不全。

### 新增验证
- `scripts/verify_features.py`（43 项）：三个新功能的接口语义 + 页面路由 + 原有接口回归；
- `scripts/verify_features_deep.py`（8 项）：证明"真的会执行"——
  - **调度线程真的触发**：把 `last_run` 改成 2020 年，等待一个 tick，确认自动创建了 `group=auto` 的任务并回写 `last_job`；
  - **删除真的删文件**：先调接口再断言 `.md/.html/.json` 消失，且审计留下 `DELETE`；
  - **复扫联动真的生效**：`exposure=patched` 的资产确实出现在 `fixed` 组。

### 回归门禁
`pytest 201` / 原验收 `29/29` / 功能验证 `43/43` / 深度验证 `8/8` / ruff 全过。

### 教训（已可写入规范）
**"导入漏了"这类错误，单测与契约测试都抓不到**——只有真正点到那个接口才会暴露。
因此新端点必须进"冒烟清单"（这次补的 verify_features.py 就是清单本身）。

---

## [0.9.0] - 2026-10-30

主题：**三个运营闭环功能 —— 整改跟踪 / 审计日志 / 计划任务**

### 新增

**① 整改跟踪**
- 资产新增 `remediation_status`（pending / in_progress / fixed / ignored）、`owner`、
  `ignored_reason`、`remediation_updated_at`；
- `GET /api/remediation` 按状态分组 + 完成率统计；`PATCH /api/assets/remediation` 改状态/责任人/忽略原因；
- **复扫联动用"读时归一"**：`exposure` 变为 `patched` 即视为 `fixed`（除非人工忽略），
  不依赖扫描链路写库，因此不可能漏同步；
- 新页面「整改跟踪」：完成率、四态统计、状态筛选、搜索、行内改状态，自动修复项打「自动」标记。

**② 审计日志**
- 中间件记录所有写操作（POST/PATCH/PUT/DELETE）到 `p2s-data/audit.jsonl`，
  字段含时间/操作人/来源 IP/方法/路径/状态码；文件超过 2MB 自动滚动保留最近 5000 行；
- `GET /api/audit?limit&q` 支持搜索；新页面「审计日志」按时间倒序展示；
- 操作人取登录态（单账号模型下即 `admin`），未登录写入记为匿名。

**③ 计划任务**
- `GET/POST /api/schedule`：启用开关、间隔（≥5 分钟）、CIDR、是否入库；
- 后台守护线程每 30 秒检查一次，到点调用**与手动扫描完全相同的任务路径**（`api_create_job`），
  任务归入「自动」分组，可在任务中心查看进度；
- 配置持久化到 `p2s-data/schedule.json`，重启后继续生效；
- 新页面「计划任务」：开关、间隔、网段、上次执行/下次执行时间。

### 验证（新增 `scripts/verify_features.py`，43 项）
- 鉴权：三个新接口未登录均 401；
- 整改：状态落库、责任人保存、非法状态 400、不存在主机 404、忽略原因记录、复扫联动标记存在；
- 审计：写入被记录、操作人正确、方法字段合法；
- 计划任务：配置持久化、下次执行时间可算、间隔过小 400、缺目标 400；
- 页面：四个新导航项与 `fn:` 路由注册全部命中，标题去重规则与 `no-store` 生效；
- 回归：原有 7 个列表接口 + agent kits 全部 200。

### 回归门禁
`pytest 201 passed` / 原验收 `29/29` / 新功能验证 `43/43` / 载荷守护 OK / 依赖审计 OK / ruff 全过。

### 已知边界
- 审计日志只记"谁在什么时候调了哪个接口"，不含请求体（避免记录口令/路径等敏感内容）；
- 计划任务只支持"固定间隔 + 单个网段"，不支持多计划与 cron 表达式；
- 整改状态无审批流，属轻量闭环。

---

## [0.8.11] - 2026-10-30

主题：**标题去重 + Logo 重设计**

### 修复
- **每个页面标题重复两遍**：顶栏已显示「页面名 + 描述」，页面内容区又有一个同样的 `h2 + p`。
  改为 `.page-head h2,.page-head p{display:none}`，只保留该区域的操作按钮；
  首屏因此上移约 50px，信息不再自相重复。

### 变更
- **Logo 重设计（靶心式）**：从"取景框 + 中心点"改为「取景框四角 + 4 个暗点 + 1 个亮点 + 涟漪环」，
  语义直接对应 Pinpoint「在一堆主机里定位到那一台」。
  四个角与暗点用 55%/38% 透明度压暗，只有中心亮点是实心——**16px 下依然可辨**，单色也能读。

### 验证
- `201 passed`、ruff 通过、验收 29/29、health 0.8.11；
- 标题去重规则已注入（`.page-head h2` 命中）；
- Logo 新结构已落到导航与登录页（源码片段核对）。

### 未完成（需单独排期）
- 菜单新增项（整改跟踪 / 定时扫描 / Agent 管理 / 审计日志）**未开始**——
  这些是新页面 + 新数据模型，不是样式改动，需要完整一轮实现与验证。

---

## [0.8.10] - 2026-10-30

主题：**项目结构收口 + 部署文档**

### 变更
- **CI 归位**：Git 仓库根是 `app/`，此前把 workflow 放在仓库外的 `.github/` 不会生效；
  已移到 `app/.github/workflows/ci.yml` 并去掉多余的 `working-directory: app`，外部重复目录已删除。
- README 新增「项目结构」一节，标注各模块职责与仓库根位置。
- 新增 `docs/04-部署/反向代理与TLS.md`：Nginx 反代示例、`client_max_body_size` 与超时要点、
  Agent 脚本的 `?base=` 用法、环境变量清单、以及三条"不要做的事"。

### 验证
- `201 passed`、ruff 通过、验收 29/29；
- 目录清点：根目录无 `.bak/.tmp/.orig` 残留，工作目录仅 7 个顶层条目。

### 已知边界
- CI 仍无法本地验证（无 Runner），首次推送需观察一轮；
- `archive/` 为历史原型，保留但不参与构建。

---

## [0.8.9] - 2026-10-30

主题：**历史报告重渲染 + 清理未使用依赖**

### 新增
- `scripts/rerender_reports.py`：从已落盘的 scan JSON 重建 Markdown / HTML，
  让历史报告跟上新版式，无需重新扫描。支持 `--dry-run`、单份失败不中断整批。
  实测：**158 份历史报告全部重渲染成功**。

### 变更
- 移除未使用的 `pyyaml` 声明（全项目 0 处 import，依赖审计脚本发现的）。

### 修复
- 删除 `pyyaml` 时留下悬空逗号，导致 `pyproject.toml` 解析失败、ruff 与 pytest 全部无法启动。
  已清理并复验（TOML 结构性改动必须立刻用 ruff/打包验证，不能只看文本）。

### 验证
- `201 passed`、ruff 通过；
- 依赖审计：7 个声明依赖全部能找到对应 import（仅 pytest/ruff 属测试工具）；
- 最新重渲染的 HTML 报告含「结论摘要 / Web 资产 / 整改建议 / 打印样式」。

### 已知边界
- 重渲染只换版式，不重新计算结论（避免用今天的规则改写历史结论）；
- 若 scan JSON 结构在未来变更，脚本需同步调整。

---

## [0.8.8] - 2026-10-30

主题：**HTML 报告重做 —— 可直接交付客户的三段式报告**

### 变更
- `to_html()` 重写：从深色极简表格改为**浅色、可打印**的评估报告版式。
  - 版式：标题栏（报告名/编号/时间/风险等级）+ 结论摘要（四档 KPI）+ Web 资产表 +
    日志侧发现表 + **整改建议** + 页脚说明；打印时自动去阴影、跨页避免断行。
  - 整改建议按"升级目标版本 → 该站点 SAPI 需重启的服务 → 复测确认"三步生成，
    并固定附一条"缓解配置需在目标机核实"的提醒（远程判断不了）。
  - 结论口径写进页脚：区分「确认受影响 / 无法判定」，未确认项需人工复核。

### 验证
- `201 passed`、ruff 通过；
- 用真实扫描（`127.0.0.1` 快速发现）生成的 HTML 报告 5,427 字节，含「结论摘要 / Web 资产 /
  整改建议 / @media print」四段，全部命中；
- 修复过程中的两个错误：未使用的 `d` 变量、误用不存在的 `result.targets`（改为 `target_count`），
  均由 ruff/pytest 与真机生成双重捕获。

### 已知边界
- 报告中的整改建议基于扫描数据推导；主机侧配置建议需 Agent 采集后才有针对性条目。
- 旧扫描的 `.html` 仍是旧模板，不会自动重生成（需重新扫描或单独提供重渲染命令）。

---

## [0.8.7] - 2026-10-30

主题：**工程化补齐 —— CI 矩阵 + 依赖审计**

### 新增
- `.github/workflows/ci.yml`：三组任务
  - **多平台矩阵**：ubuntu / windows × Python 3.9 / 3.12，跑 ruff + pytest + 载荷守护 + 版本一致性；
  - **契约测试**：单独 job，锁定所有接口响应结构；
  - **采集脚本校验**：两个平台脚本必须能生成，Windows 脚本必须带 UTF-8 BOM，
    Linux 脚本过 `sh -n` / `bash -n`（0.5.3 曾因花括号/ BOM 问题在这两种检查上翻车）。
- `app/scripts/check_deps.py`：离线依赖审计（清单 vs 源码 import），可选 `--online` 调 pip-audit。
  区分"未使用的运行时依赖"与"仅测试用工具"，并标注由框架间接使用的依赖（如 `python-multipart`）。

### 审计结果（当前）
- 运行时依赖：`httpx`、`fastapi`、`uvicorn`、`python-multipart` 均在用；
- `pyyaml` 声明在 dev extras 里但**全项目 0 处 import** —— 可移除，减少供应链面（本轮未删，避免未验证改动）。

### 已知边界
- CI 配置**无法在本机验证**（没有 GitHub Runner），只能保证语法与步骤合理；
  首次接入 CI 时需观察一轮真实执行结果。
- pip-audit 需联网，本机未安装，在线审计尚未跑过。

---

## [0.8.6] - 2026-10-30

主题：**沉淀开发规范（把踩过的坑变成约束）**

### 新增
- `CONTRIBUTING.md`：9 条规范，每条都对应一次真实事故——
  回读产物、端到端断言、单写者、f-string 花括号、跨文件 DOM 先读再改、
  前端必须真机验证、版本与记录、安全底线、提交前自检清单。
- README 增加规范入口。

### 说明
本轮不改功能，只把"为什么会出白屏 / 假交付 / 代码被覆盖"写成可执行的检查项，
避免下次（或换人接手）重复同类错误。

---

## [0.8.5] - 2026-10-30

主题：**Kubernetes 清点 + 修正 0.8.3 未真正生效的集成**

### 新增
- **Kubernetes Pod 级清点**：`kubectl get pods -A -o json`（只读），逐容器解析镜像标签，
  以 `container:pod/<ns>/<pod>` 形式并入安装点列表；kubectl 缺失或无权限时优雅降级并说明原因。

### 修复（重要）
- **0.8.3 声称"容器 PHP 并入主机侧检测"实际未生效**：当时补丁的锚点字符串与实际代码不符，
  脚本静默跳过，导致 `containers.py` 只有模块和测试、没有被 `run_host_check` 调用。
  本次改为按真实锚点接入，并用假容器清单验证 `rep.installs` 中确实出现 `container:...` 条目。
  教训：**"测试通过"不等于"接进了主流程"**——模块级单测覆盖不到调用点，必须做一次端到端断言。

### 验证
- 201 passed、ruff 通过；
- 端到端断言：注入假 Docker 容器 + 假 K8s Pod 后，`run_host_check()` 的安装点列表同时包含
  `container:web-php` 与 `container:pod/prod/blog`。

### 已知边界
- 版本仍取自镜像标签，属线索级证据；确定版本需容器内 Agent 或开启 `P2S_CONTAINER_EXEC`；
- 未覆盖 initContainer / sidecar 之外的形态（如 HostNetwork Pod 里的宿主 PHP 已由主流程覆盖）。

---

## [0.8.4] - 2026-10-30

主题：**覆盖扩展到 macOS / BSD 与 IPv6**

### 新增
- **采集脚本兼容 macOS / BSD**：`stat -c`（GNU）与 `stat -f`（BSD/macOS）双路回退，
  `ps -eo` → `ps -axo` → `ps aux` 逐级回退，包管理器补 `brew`（macOS）与 `pkg`（FreeBSD）。
  脚本标签改为「Linux / macOS / BSD（POSIX sh）」。
- **IPv6 探测支持**：新增 `_url_host()`，HTTP 基址对 IPv6 字面量自动加方括号
  （`http://[::1]:8080/`）；CIDR 展开沿用 `ipaddress`，天然支持 IPv6 网段。

### 修复
- 采集脚本模板里新增的 shell 函数花括号未在 f-string 中转义，导致 `agentkit.py` 语法错误
  （16 个测试连带失败）。已改为 `{{` / `}}` 并通过语法检查。

### 验证
- `201 passed`、ruff 通过；
- `_url_host` 四种输入（IPv4 / `::1` / `fe80::1` / 已带括号）全部正确；
- 采集脚本渲染 156 行，语法检查通过。

### 已知边界
- IPv6 只做了 URL 层适配，未做 IPv6 网段的邻居发现/存活判定差异处理；
- macOS 的 Homebrew 没有 Debian 式 changelog，补丁回移判定仍需容器/Agent 之外的人工核验。

---

## [0.8.3] - 2026-10-30

主题：**容器清点 —— 补上"容器里的 PHP 对宿主机完全隐形"**

### 新增
- `core/containers.py`：非侵入式清点运行中的容器，从**镜像标签**推断 PHP 版本
  （`php:8.1-fpm`、`wordpress:6.2-php8.1` 等常见命名），并给出 SAPI 猜测。
- 集成到主机侧检测：容器 PHP 会以 `container:名称` 的形式并入安装点列表，
  结论标注"版本来自镜像标签，未经容器内核实"。
- 可选 `P2S_CONTAINER_EXEC=1`：显式开启后才用 `docker exec php -r 'echo PHP_VERSION;'`
  取准确版本——默认**不执行**客户容器内的命令（侵入操作需显式同意）。

### 为什么重要
容器里的 PHP 在宿主机上既看不到二进制、也读不到包 changelog。之前这类目标在我们眼里是"没有 PHP"，
属于**整片漏报**。现在至少能识别"这台机器跑了 3 个 PHP 8.1 容器"。

### 验证
- 9 条新测试：镜像标签解析（5 种命名）、非 PHP 镜像忽略、无 docker 时优雅降级、假容器清单过滤；
- `201 passed`、ruff 通过。

### 已知边界
- 镜像标签可被构造，**不能当作确定性证据**；确定版本仍需容器内 Agent 或开启 exec；
- 未覆盖 Kubernetes（Pod 需 `kubectl`，且权限模型不同），也未见容器内配置文件。

---

## [0.8.2] - 2026-10-30

主题：**端口覆盖扩充 —— 减少"自定义端口上的 PHP 扫不到"**

### 变更
- 新增 `EXTRA_WEB_PORTS`：按高频区间采样补充 Web 端口
  （8000–8100 步长 10、8100–9100 步长 25，另含 8888/9001/9800/10080/18080 等常见面板口）。
  默认探测端口 **47 → 134**。
- 取舍：全端口扫描（1–65535）不放进默认路径——254 台 /24 会从约 12 分钟涨到数小时，
  应作为可选开关单独提供，不牺牲默认体验。

### 验证
`192 passed`、ruff 通过；端口集合经人工核对，新增区间不与既有服务端口冲突。

### 已知边界
- 仍非全端口，7xxx 以下的非标准端口（如 6001、7002）依旧可能漏；
- 端口越多单台越慢，深扫模式在弱网环境耗时会明显上升。

---

## [0.8.1] - 2026-10-30

主题：**应用指纹库 —— 从"是 PHP 站点"升级到"是什么应用"**

### 新增
- **应用指纹库**（26 条）：WordPress、Discuz!、DedeCMS、帝国CMS、ThinkPHP、Laravel、Yii、CodeIgniter、
  Symfony、Drupal、Joomla、phpMyAdmin、Adminer、Nextcloud、宝塔面板、Typecho、Zabbix。
- 新增证据字段 `Field.META`（页面 `meta generator / application-name`），并纳入**产品级证据（T1）**——
  generator 是站点自报的应用身份，比 Server 头可靠得多。
- 新增设备类型 `Web 应用（PHP）`，应用类目标不再混进"服务器"。

### 效果
- 修复"只能识别成 PHP 应用站点、说不出具体 CMS"的短板；
- 同特征签名去重（按 `(字段, 特征)`），避免一个 needle 产生两个竞争结论；
- 实测：`meta generator=WordPress 6.2.1` → 识别为 WordPress，置信 **0.98**；`Drupal 9` → Drupal；`phpMyAdmin` → phpMyAdmin。

### 验证
`192 passed`、ruff 通过；三种应用样本均正确识别。

### 已知边界
- 只覆盖"页面自报身份"的情况；关闭 generator、去特征化的站点仍只能判为 Web 应用；
- 版本号（如 WordPress 6.2.1）目前只作为产品名的一部分展示，尚未关联到该应用的已知漏洞库。

---

## [0.8.0] - 2026-10-30

主题：**M5 二进制取证 —— 补上"版本号不可信"这块硬伤**

### 新增
- `core/binforensics.py`：不依赖版本号，直接从二进制取物理证据。
  - **PE**：解析 `TimeDateStamp`（链接器写入的编译时间）；
  - **ELF**：解析 `.note.gnu.build-id`（跨主机同版本比对）与 `.comment`（GCC/clang 工具链）；
  - **判定**：构建时间早于修复发布日（2026-10-21）→ **必然不含修复**（强证据，破解"改版本号蒙混")；
    晚于修复日 → 明确返回"无法判定"，不硬猜。
- **补丁标记库机制**：`data/markers.json` 支持 `hex|ascii` 特征，拿到补丁前后样本即可扩展为
  "二进制是否含补丁"的确定性判定；当前不含任何凭空编造的标记。
- `hostcheck` 枚举 PHP 安装点时自动附加 `build_id` / `build_time` / `toolchain`，
  并在二进制证据与版本号冲突时**采纳更硬的证据**，理由写入 `reason`。

### 判定优先级（新）
`包 changelog` > `补丁标记` > `构建时间` > `版本号`

### 验证
- 7 条新测试：真实 PE 时间戳、合成 ELF 的 build-id/comment、判定边界、标记库往返、缺失文件安全；
- 真机示例：本机 `python.exe` 读出 `2023-10-02` 构建时间 → 正确判为"早于修复日"；
- 全量 `192 passed`、ruff 通过。

### 已知边界
- 补丁标记库为空（需真实补丁前后样本，拒绝编造）；
- 静态链接/裁剪过的二进制可能没有 build-id，此时退化为"无法判定"。

---

## [0.7.0] - 2026-10-29

主题：**界面可用性收口 —— 登录页 / 告警 / 任务中心 / 报告中心 / 动效体系**

### 新增
- **登录页重设计**：左品牌面板 + 右表单的分栏布局；深墨蓝渐变 + 栅格纹理 + 雷达扫描带动效；
  跟随系统深色（`prefers-color-scheme`）；版本号由 `__version__` 注入，不再硬编码。
- **告警收纳**：移除总览顶部告警条与侧栏摘要，改为右上角铃铛 + 未读角标 + 下拉面板，
  按等级列出暴露/待确认/配置风险，带跳转按钮；Esc/遮罩/关闭均可收起。
- **任务中心重排**：统计条（运行中/已完成/失败/总计）+ 状态筛选 + 搜索 + 紧凑表格（20 条/页）+ 翻页；
  新增「清理已完成」；行高从约 120px 降到约 58px。
- **报告中心**：按类型/风险筛选 + 搜索 + 分页（20 条/页），解决 119 条记录一屏到底的问题。
- **总览「修复进度」**：暴露/待确认/已修复/不涉及 的堆叠进度条 + 台数与百分比。
- **动效体系**：切页淡入 220ms、卡片入场 stagger（40ms 间隔）、KPI 数字滚动 540ms、
  条形图生长 640ms、骨架屏 shimmer、按钮 loading spinner、卡片/行/图表 hover 反馈；
  全部尊重 `prefers-reduced-motion`。
- **IOC 中心**：新增本地搜索框（IP/域名/URL/哈希/UA 特征）。
- **任务历史自动保留**：已结束任务最多保留 200 条（`P2S_JOB_HISTORY` 可调），超出按创建时间淘汰最旧的；
  运行中的任务永不淘汰。此前失败任务会无限堆积，只能手动清理。

### 修复
- **刷新总览变空白页**：告警弹层 DOM 位于 `<script>` 之后，脚本取到 `null` 抛错中断启动；
  改为存在性判断 + 全局 `error` 兜底，任何未捕获异常会显示在内容区而不是白屏。
- **并行写覆盖**：后台任务与手工补丁同时写 `ui.py`，旧快照把新代码覆盖掉；
  改为单写者顺序执行。
- `/api/jobs` 含完整 `result` → 781 KB/次轮询：列表只返回 `has_result` 标记（−97%）。
- 失败任务进度条显示满格红（`progress` 被置 1）→ 按 `done/total` 计算 + 斜纹表示中断。
- `scan_api` 缺 `import re` / `coverage_report` → 上传接口 500、日志任务 failed。
- `_expand_cidr` / `KB_FILE` 未随模块搬迁 → 带网段的任务 500、发现任务 NameError。

### 变更
- 命名统一：品牌「见微 Pinpoint」/ 中文副标「内网暴露面核查与取证」/ 英文「Attack Surface Verification」/
  CVE 代号只作为「专项视图」出现（原先 4 套说法并存）。
- 主机侧结论补 `evidence`（此前置信 0.95 却显示「判定证据(0)」）与 `remediation` 整改建议。
- 对比度：`--text-3` 浅色 3.15:1 → 4.9:1，深色 3.9:1 → 5.1:1。

### 已知未做
- **日志分析按文件/时间筛选**：结果渲染在 `watchJob()` 的 logs 分支（跨文件三层结构：汇总→文件→命中），
  动它之前必须先读该函数，否则容易切坏模板导致白屏（0.7.0 已发生过一次同类事故，已记录在「修复」里）。
- **剩余 11 处手写空状态**：分布在各页 `innerHTML` 与多行模板中，结构不一，需逐处人工迁移（批量正则只覆盖了简单形态）。
- `app.py` / `ui.py` 的进一步拆分（当前 375 / 373 行，已可维护，优先级低）。

---

## [0.6.0] - 2026-10-29

主题：**界面可用性收口 + 接口瘦身 + 样式分层**

### 新增
- **主机侧整改建议**：`host_issues`（配置不达标项）与 `remediation`（可执行动作）随 Agent 上报写入台账；
  建议不是复述问题，而是给出具体动作——例如「设 session.upload_progress.enabled=0 并重启 php-fpm」、
  「升级 8.4.20 → 8.4.27，先切流量到备节点再升级，然后跑一次复扫确认」。详情抽屉的「处置建议」区块因此有了内容。
- **账号登录**：由「单口令」升级为「用户名 + 密码」，默认 `admin / <旧版默认口令>`（可用 `P2S_ADMIN_USER` /
  `P2S_ADMIN_PASSWORD` 覆盖）；用户名与口令都用 `compare_digest` 且**不短路比较**，避免响应时间差被用来枚举账号。
  旧客户端只传 `password` 仍然可用（`username` 默认 `admin`），向后兼容。
- 顶栏操作区重排：主题/刷新/退出成组等高，加分隔线，退出按钮补图标；`≤720px` 自动收起文字只留图标。
- `ui_css.py`：样式表从 `ui.py` 拆出（330 行），`ui.py` 由 1537 → 1217 行，通过占位符注入。
- `ui_pages/`：**页面级前端代码拆包**（overview / tasks / drawer / php / logs / rules / ioc / reports 八个模块），
  各自是一段 JS 常量，最终拼回同一个 `<script>` —— 因此函数仍在同一作用域，互调不需要改造；
  `ui.py` 由 1217 → **388 行**，只剩骨架、基础工具、路由与启动。
- `deps.py`：控制台共享底座（路径常量、资产读写、鉴权会话、任务队列、CSV 工具）从 `app.py` 拆出（264 行，含 `_diff_asset`），用 `ast` 自动生成 `__all__` 保证星号导入能取到下划线名字。
- `agent_api.py`：Agent 路由（`/api/agent/report|download|kits`）与主机报告归一化拆出（228 行，APIRouter），
  `app.py` 收敛到 **921 行**（原 1560），通过 `include_router` 注册。
- ruff 对 `app.py` / `agent_api.py` 单独豁免 `F405/E402`（星号导入与中段注册的固有限制），其余文件仍严格检查。
- `assets_api.py`：资产台账路由（CRUD / 重扫 / 撤销 / 导出 / PHP 暴露面）拆出（140 行，APIRouter）；
  `app.py` 进一步收敛到 **797 行**（原 1560，已减半）。
- 扫描读取逻辑（`_load_scans` / `_scan_summary` / 目录指纹缓存）下沉到 `deps.py`。
- **已知边界**：`/api/scans*`、`/api/jobs*` 与规则/IOC 路由在源文件里是**交错**的，
  无法整块切出 `scan_api.py`；下一步需按端点逐段搬迁（每次搬完跑契约测试），
  该问题已解决：改用 **AST 定位 + 区间合并**（`ast.parse` 取每个节点的 decorator/end_lineno），
  一次性切出 `scan_api.py`（411 行，APIRouter），`app.py` 收敛到 **375 行**；切分前自动备份 `app.py.bak`。
- 拆分后回归通过：**184 tests / ruff 全绿 / 控制台验收 29/29**。

### 修复（本轮）
- 顶栏改造时 `.top-actions .icon-btn{display:inline-flex}` 覆盖了 `.mobile-btn{display:none}`，
  导致**汉堡菜单在桌面端显示**；去掉 display 覆盖，保留原显隐规则（已截图复核）。

### 优化
- **登录页重设计**：从居中单卡改为**左侧品牌面板 + 右侧表单**的分栏布局。深色墨蓝渐变 + 极淡栅格纹理
  （radial + 遮罩收敛），左侧承载产品名/主张/三条能力点/版本脚注，右侧为独立浮起卡片；
  宽屏不再显得空旷，≤900px 自动叠成单栏并隐藏装饰区；输入框 hover/focus 双层反馈，按钮带柔和投影。
- **告警收纳**：删除总览页顶部常驻告警条与侧栏底部「暴露面摘要」，改为右上角**铃铛 + 未读角标**；
  点开下拉面板按等级列出（暴露 / 版本待确认 / 配置不达标），每条带跳转按钮；
  Esc、点遮罩、点关闭均可收起；无告警时面板显示「当前未发现告警」。
  总览首屏因此上移约 70px，视觉重心回到 KPI 与图表。
- 后端 `overview` 新增 `config_issues`（带配置风险的资产数），供铃铛使用。
- **切页淡入**：`go()` 每次渲染后给容器加一次动画类（120–160ms 淡入 + 3px 上移），
  且只加在切换页面时，轮询刷新不会触发；`prefers-reduced-motion` 下关闭。
- **进度条平滑**：宽度过渡改为 `0.45s cubic-bezier(.22,.61,.36,1)`，数值变化不再跳变。
- **失败任务进度条语义修正**：之前 `progress` 被置 1 导致失败任务显示「满格红」，看着像跑完了；
  改为失败/取消时按 `done/total` 计算宽度，并用**斜纹红**表示「中断」而非「完成」。
- **交互反馈动效**：卡片/KPI/统计块悬浮上浮 1px + 阴影 + 边框提亮；表格整行跟随高亮；
  条形图悬浮时位移 1px、轨道描边、名称提亮；环形图扇区轻微提亮；按钮/分段控件按下回落；
  侧栏导航悬浮显示左侧强调条（当前项常亮）。全部动效 0.12–0.16s，只改 transform/阴影/边框，不引起重排；
  `prefers-reduced-motion: reduce` 下全部关闭。
- **任务中心重排**：原来是「运行中卡片 + 历史卡片」无限纵向堆叠，任务一多要一直往下拉。
  改为「统计条（运行中/已完成/失败/总计）+ 状态筛选 + 搜索 + 紧凑表格（20 条/页）+ 翻页」，
  行高从约 120px 降到约 58px，并新增「清理已完成」一键清历史。

### 修复（清单核查发现的回归）
- `scan_api._resolve_hosts` 调用的 `_expand_cidr` 仍留在 `app.py` → **任何带网段的任务都 500**；
  已把 `_expand_cidr` 下沉到 `deps.py`（同时补 `import ipaddress`）。
- `_run_discover` 使用的 `KB_FILE` 仍定义在 `app.py` → 所有发现任务 `state=failed`（NameError）；已移到 `deps.py`。
- **教训**：验收脚本只用主机列表、从不用 CIDR，所以 29/29 没覆盖到；已补本机回环（`127.0.0.1/32`）冒烟路径。
- 主机侧结论补 `evidence`（此前置信 0.95 却「判定证据(0)」）：安装点/changelog/不达标配置/落地痕迹/进程逐条列出。

### 修复（拆分引入，已修）
- `scan_api.py` 缺 `import re` → `POST /api/scan/logs/upload` 直接 500。
- `scan_api.py` 缺 `coverage_report` 导入 → 日志分析任务 `state=failed`，上传同样 500。
  两个都是"模块搬迁漏导入"，单测覆盖不到（测试走的是 `app` 命名空间），是**验收脚本**抓出来的。

### 修复（实测发现）
- `/api/jobs` 返回 **781,068 字节**：任务列表把每条任务的 `result`（含完整资产/发现）一起返回，
  而前端每 1.5 秒轮询一次 —— 等于每秒传半兆。改为列表不带 `result`，只给 `has_result` 标记，
  结果仍可通过 `/api/jobs/{id}` 获取。实测 **781,068 → 22,420 字节（−97%）**，`limit=5` 时 3,025 字节。
- `askConfirm()`：产品内统一确认弹窗（Promise、支持 Esc/遮罩取消、危险操作红色按钮），替换 3 处浏览器 `confirm`。
- `toastAction()` + `POST /api/assets/restore`：删除资产后可**撤销**（9 秒内点击恢复台账记录）。
- `emptyState()`：统一空状态渲染，替代各页手写拼接。
- 资产台账：**最后检测**列、**分组/来源**筛选、**分页（50/页）**。
- 总览：**资产变化** KPI、最近扫描按「类型+风险+小时」合并显示（`+N` 角标）。
- 任务完成/失败时右下角 toast 提示；标签页不可见时轮询降频到 10s。
- 深色主题图表专用色 `--chart-mute` / `--chart-track`。
- `tests/test_version.py`：版本号三处一致性校验。
- `tests/test_contract.py`：**端点契约测试（22 条）**——锁定 9 个 JSON 接口的顶层字段、
  8 个导出接口的类型与文件名、分页/摘要语义、任务状态枚举、未登录 401；
  这是后续拆分 `app.py` 的安全网（拆完跑一遍，结构变了立刻红）。

### 修复
- `tag('warn')`（5 处）、`tag('pur')`（1 处）**缺少 CSS 定义**导致状态徽标无色 → 补齐。
- `--sh-3` 变量未定义导致移动端抽屉阴影失效 → 改为实值。
- 文档声称"不用渐变"但 KPI 卡用了 `linear-gradient` → 改为左侧色条。
- 资产「变化」列几乎全亮：`product/device_label` 文案微调被算作变更 → 后端只比
  `exposure/php_version/risk/sapi/alive`，前端再过滤历史脏 diff。
- 环形图小扇区数字重叠（1/1 挤在一起）→ 占比 <8% 不标数字。
- 窄屏（≤1100px）分段按钮被挤成竖排 → 工具栏整体换行、分段控件不换行；隐藏 5 个次要列。
- `--text-3` 对比度不足：浅色 3.15:1 → 4.9:1；深色 3.9:1 → 5.1:1（WCAG AA）。
- 时间显示为 ISO 串 → 统一相对时间（`2 小时前`），悬停显示原始值。
- 规则导出文件名不自解释（`p2s-php2shell.conf` / `.rules`）→ 改为
  `p2s-php2shell-modsecurity.conf` / `p2s-php2shell-suricata.rules`，下载后一眼能认出格式。

### 变更
- `/api/scans` 默认返回**摘要 + 分页**（`?limit=&offset=&full=`），响应 **1,169,733 → 15,406 字节（−98.7%）**。
- `/api/overview` 的 `recent_scans` 同步改摘要，响应 **56,131 → 3,169 字节（−94%）**。
- 扫描报告增加目录指纹缓存（`文件数 + 最新 mtime`），命中后不再重复解析 71 份 JSON。
- 三个纯图标按钮补 `aria-label`；新增 `:focus-visible` 键盘焦点轮廓。

---

## [0.5.3] - 2026-10-29

主题：**指纹技术升级 + Agent 下载即用（真机联调）**

### 新增
- favicon **mmh3 指纹**（纯 Python MurmurHash3 x86_32，与 Shodan/Fofa 同口径），并保留 sha256 做本地聚类。
- 页面元数据提取：`meta application-name / og:site_name / generator`、`<h1>` 兜底。
- 单跳重定向跟随：首页无信息且返回 3xx 时跟一次 `Location`。
- TLS 深度取证：是否自签、SAN、过期、**ALPN（h2/http1.1）**。
- 品牌词扫描（页面正文 / 静态 JS·CSS / 404 页），ASCII 别名按**整词**匹配。
- 静态资源抓取（限 3 个同源 js/css）并计算内容哈希。
- **指纹知识库** `p2s-data/fingerprints.json`：确认过的指纹 → 型号，跨批次复用（只收具体型号）。
- **Agent 采集脚本下载**：`GET /api/agent/download?os=linux|windows`，平台地址与令牌在下载时注入；
  另有 `/api/agent/kits` 供界面展示。
- `p2s-agent` 入口 + `p2s agent` 子命令（后者任何安装方式都可用）。

### 修复
- **Linux 脚本生成的 JSON 非法**：`printf` 单引号模板里 `\"` 被原样输出 → 服务端 422。
- **上报 body 形态不匹配**：脚本发扁平报告，接口按 `{hostname,data}` 解析，除 hostname 外全丢 →
  改为两种形态都接受（读原始 body）。
- **Windows 脚本在 PS 5.1 下语法错误**：无 BOM 时按 GBK 解析，中文注释吞掉换行 → 输出带 UTF-8 BOM。
- **PS 5.1 Body 编码**：中文证据被按 ISO-8859-1 编码成问号 → 显式 `UTF8.GetBytes`。
- `fatal_error_backtraces` 在 PHP 8.3/8.4 上不存在却被判"不达标" → 仅 8.5+ 校验。
- 测试隔离：conftest 由 `setdefault` 改强制覆盖，避免 shell 环境变量污染。

### 变更
- Agent 上报**写入资产台账**（R-05），带 `evidence_level="host"`、置信度 0.95，本地结论覆盖远程推断。
- 判定权收归服务端：脚本只报事实（版本/配置/changelog 命中），结论由 `_normalize_host_report` 统一计算。

---

## [0.5.2] - 2026-10-29

主题：**设备识别重写（修复跨厂商误判）**

### 修复
- 一批捷普安全设备被误判为 **JumpServer 堡垒机**：把 `Server: Jump_server`、证书 `O=jump`
  当成了别家产品 → 改为捷普（JUMP）设备族签名，JumpServer 只认 Fit2Cloud 指纹。
- 厂商被 MAC OUI 覆盖（`8c:1c:da` → 深信服）→ **OUI 只作"网卡厂商"**，绝不进厂商字段。
- 端口推断用到了 tarpit 噪声端口（25/110/143 → "邮件网关"）→ 只用**有有效响应**的端口。
- `jump` 裸词签名权重过高 → 降为弱线索，产品级判据交给标题/证书。

### 新增
- **证据分级 T1/T2/T3**：T1（标题/证书/登录路径/认证域）才能定厂商与产品；T2（Server/banner/Cookie/正文）
  折算 ×0.7 且置信度封顶 0.72；T3（端口/OUI）只能兜底并显式标注。
- 捷普产品族签名（WAF / 防火墙 / 信息审计 / 准入控制 / 演示平台）。
- 跨主机 **favicon 聚类**：同指纹且本批次只有唯一已知型号时才补型号（封顶 0.6）。

---

## [0.5.1] - 2026-10-29

主题：**安全加固 + 修好"声称有但实际不工作"的功能**

### 安全
- 控制台**零鉴权** → 单口令登录 + HttpOnly 会话 Cookie + 中间件拦截（`/api/health`、登录页例外）。
- **任意文件读取**（日志路径参数）→ 白名单根目录 + 日志后缀校验 + 256MB 上限 + `resolve()`。
- **存储型 XSS**（在 `onclick` 里用 HTML 实体转义拼 JS 字符串）→ 新增 `jss()`，修 11 处。
- Agent 上报无鉴权 → `X-P2S-Token` + 2MB 体积上限。
- Docker 发布到全网卡 → compose 默认绑 `127.0.0.1`。
- 补安全响应头、登录失败延迟、上传大小上限与轮转清理。

### 修复
- **主动探测空转**：`probe_once("gentle")` 落到 else 分支直接返回，只发了控制请求 → 加 `PROBE_STRATEGY` 映射。
- 三种规则导出全部不可用（Sigma YAML 解析失败 / ModSec 引号错误 / Suricata classtype 非法）→ 重写生成器。
- 取消任务对 3/4 类型无效、`Job.to_dict()` 缺 `active`、报告 `finished_at` 恒空、侧栏摘要永远"加载中"、
  冷启动带 hash 显示错页 → 逐项修复。
- CSV 导出是 text/plain 且可公式注入 → 统一 `_csv_response`（MIME/文件名/BOM/转义）。
- FTP `220` banner 被判成 SMTP → 新增 `_guess_proto()`。
- 载荷守护文案过度承诺 → 改整篇扫描并去掉保证性表述。

### 变更
- 删除 5 个前端从不调用的同步端点（绕过队列、构成任意读取与 DoS 面）。
- 原子写（tmp + `os.replace`）、jobs 落盘节流、坏记录跳过。
- 版本号三处不一致 → 统一由 `p2s.__version__` 提供。
- `pyproject` 依赖收敛（删掉从未 import 的 jinja2/pyyaml，补 python-multipart）。
- 新增 `p2s agent` 子命令、`console/__main__.py`、`scripts/verify_console.py`（29 项验收）。

### 新增能力
- **R-03 跨主机噪声端口**（`apply_noise_ports`）：只统计"无响应"端口，避免误剔真实 Web 端口。
- **R-07 资产变更检测**：`new / changed / gone` + 变更历史 + 总览 KPI。

---

## [0.5.0] - 2026-10-29

首个可交付版本（历史基线）：设备发现五层收敛、13 条日志规则、主机侧只读检测、
FastAPI 控制台 10 页、Agent 雏形、Docker/CI、交付包。

---

## 发布流程（每次改完照做）

```powershell
cd app
.\.venv\Scripts\python.exe -m pytest            # 必须全绿
.\.venv\Scripts\python.exe -m ruff check src tests scripts
.\.venv\Scripts\python.exe scripts\check_payload_literals.py .
.\.venv\Scripts\python.exe scripts\verify_console.py --password <口令>
# 1) 改 __version__（唯一来源）
# 2) 在 CHANGELOG.md 顶部加一节（本文件）
cd .. && python tools\package_release.py        # 产出 dist/见微Pinpoint-v<版本>.zip
```

**约定**：不动版本号就不算一次发布；CHANGELOG 必须写"改了什么 + 为什么 + 怎么验证"。
