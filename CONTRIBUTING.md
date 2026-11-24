# 开发规范（CONTRIBUTING）

这份规范不是通用建议，**每一条都是本项目真实踩过的坑**。违反其中任何一条，我们都实际付出过代价
（白屏、假交付、测试全绿但功能没接上）。改动前请先读一遍。

---

## 一、改完必须"回读产物"

**症状**：脚本打印"已应用"，但文件其实没变。

**本项目实例**
- 版本号脚本跑完显示成功，`__init__.py` 仍是旧值（并行任务把文件写回了旧快照）；
- 补丁输出"入场动效已修正"，实际 `slice(0,10)` 仍在文件里。

**规则**
```python
# 改完之后，立刻回读并断言
text = path.read_text(encoding="utf-8")
assert "新内容" in text, "补丁未落盘"
```
版本号类改动，必须 `python -c "import p2s; print(p2s.__version__)"` 与实际服务
`/api/health` 双向确认，**两边一致才算改完**。

---

## 二、"单测通过"不等于"接进了主流程"

**症状**：模块有单测、测试全绿，但主流程根本没调用它。

**本项目实例**：`containers.py` 写好了、9 条测试全过，但接入 `hostcheck` 的补丁因锚点
拼错（`errs` vs `errors`）静默跳过 —— 连续两个版本对外宣称"已支持容器"，
实际上容器里的 PHP 完全没被清点。

**规则**
- 新增能力必须有**端到端断言**（不是只测函数本身）：
```python
c.docker_available = lambda: True          # 注入假数据
rep = hostcheck.run_host_check(deep=False)
assert any(i.path.startswith("container:") for i in rep.installs)
```
- 打补丁用**精确锚点 + `assert old in s`**，禁止 `if old in s:` 这种"匹配不上就跳过"的写法。

---

## 三、同一文件只允许一个写者

**症状**：改完的东西过一会儿"自己变回去了"。

**本项目实例**：一边让后台任务跑"修复空白页"，一边手工打"加强动画"补丁，
后台任务结束时把它启动时读到的旧内容整份写回，动画代码被抹掉。

**规则**
- 后台任务未结束前，不要改它涉及的同一个文件；
- 需要批量改动时，先 `Stop-Process` 掉会写该文件的进程；
- 长任务改为"只读 + 最后一次性写回"，缩短写窗口。

---

## 四、往 f-string 模板里塞 shell / JS，必须转义花括号

**症状**：`SyntaxError: f-string: expecting '}'`，一次性打挂十几个测试。

**本项目实例**：采集脚本模板（Python f-string）里新增了两个 shell 函数，
`{` / `}` 没写成 `{{` / `}}`，`agentkit.py` 直接语法错误。

**规则**：改完立刻做一次渲染 + 语法检查，不要只看 pytest：
```python
t = agentkit.render("linux", "http://x:1", "t")
assert t.count("\n") > 100
```

---

## 五、跨文件的 DOM 结构，先读再改

**症状**：整页白屏，控制台一个报错都不给。

**本项目实例**：切割 `overview.py` 的告警块时按字符串索引切片，切坏了模板；
另一处是弹层 DOM 放在 `<script>` 之后，`$('#alert-bg')` 取到 `null` 抛错，
中断整段启动逻辑（`go()` 没执行 → 内容区空白）。

**规则**
- 改模板前先 `read` 出真实片段，不要凭记忆拼锚点；
- 取 DOM 一律做存在性判断：`const el=$('#x'); if(el) el.onclick=...`；
- 全局兜底：`window.addEventListener('error', ...)` 把异常显示在页面上，**禁止静默白屏**。

---

## 六、前端改动必须真机验证

**规则**：改完执行 `scripts/verify_console.py`（29 项，走真实 HTTP）+ 截图核对。
无头浏览器不稳定时，至少要做 DOM 级断言（元素存在、计算样式生效），
把"没验证"如实写进回复，不要用"应该没问题"代替验证。

---

## 七、版本与记录

1. 版本号唯一来源 `app/src/p2s/__init__.py`，其余（pyproject / Dockerfile / compose /
   打包脚本 / README / 登录页）都是投影，**必须同步**；
2. 不写 `CHANGELOG.md` 不算发布；每条要写"改了什么 / 为什么 / 怎么验证"；
3. 语义化版本在 0.x 阶段的约定见 CHANGELOG 顶部"版本节奏"；
4. 发布前四道闸：
```powershell
pytest                      # 必须全绿
ruff check src tests scripts
python scripts/check_payload_literals.py .
python scripts/verify_console.py --password <口令>
```

---

## 八、安全底线（做安全工具的人，自己不能先破防）

- 采集脚本**默认只读**，任何 `exec` 类侵入操作必须显式开关（如 `P2S_CONTAINER_EXEC=1`）；
- 用户可控的路径/主机参数，必须经白名单与 `resolve()` 校验；
- 结论必须区分「确认 / 无法判定」，**不知道就写不知道**，禁止用推断冒充事实；
- 不编造检测数据（例如补丁标记库没有样本就留空，不写猜测特征）。

---

## 九、提交前自检清单

```
□ 回读过改动后的文件内容（不是只看脚本输出）
□ 新增能力有端到端断言，且主流程真的调用了
□ 没有并行写同一文件
□ f-string 模板里的花括号已转义、渲染通过
□ 前端改动跑过 check_page_js.py（JS 语法）+ check_page_html.py（标签配平）
   + check_page_layout.py（真实 DOM 布局与对比度）
   + audit_pages.py（16 页 × 浅/深 对比度与溢出全站审计）
   + check_api_consistency.py（前端 api() 调用 vs 后端路由）
   → 验收脚本 → 截图/DOM 断言
□ 版本号与 CHANGELOG 同步，四道闸全绿
□ 回复里如实说明"没验证的部分"
```

## 版本号规则

`MAJOR.MINOR.PATCH`，**每段 0–9，满 10 进位**（见 `core/version_policy.py`）：

- bug 修复 → PATCH+1，到 9 再加进位到 MINOR；
- 新功能 → MINOR+1，PATCH 归零，MINOR 到 9 进位到 MAJOR；
- 规则/架构变更 → MAJOR+1。

发版时同步更新：`app/src/p2s/__init__.py`、`pyproject.toml`、`Dockerfile`、
`docker-compose.yml`、`tools/package_release.py`、`README.md`、`CHANGELOG.md`。

## 运行验收门禁的前提

1.0.5 起控制台不再有内置默认口令。跑任何需要登录的门禁前，必须先设凭据：

```powershell
$env:P2S_ADMIN_PASSWORD="你的口令"
$env:P2S_CONSOLE_PASSWORD="你的口令"   # 兼容旧脚本
```

缺凭据时脚本会直接报错退出（而不是静默 401 少跑一半用例）。
