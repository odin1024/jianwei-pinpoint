# P2S-Guard 快速上手

零第三方依赖，只用 Python 标准库。Python 3.10+ 即可运行（开发环境为 3.13）。

---

## 一、30 秒看到效果

```bash
cd "F:/自媒体/AI编程/PHP2Shell漏洞检测工具"
python run_demo.py
```

它会自动完成：

1. 启动 6 个模拟 PHP 靶场（127.0.0.1:8801–8806）
2. 扫描全部目标并输出彩色结果
3. 跑一遍失陷排查（`lab/sample_logs`）
4. 写出 `reports/php2shell-report.md` 与 `reports/php2shell-result.json`
5. 打印「与期望结果对照」

预期输出结尾：

```
符合期望 6/6
```

---

## 二、六个靶场分别演练什么

| 端口 | 场景 | 期望结论 | 演练的能力 |
|---|---|---|---|
| 8801 | PHP 8.4.24 + mod_php，phpinfo 暴露 | 确认受影响 / P0 | 基础判定 + 配置可利用性 |
| 8802 | PHP 8.4.27 + mod_php | 已修复 / P3 | 版本达标路径 |
| 8803 | PHP 8.3.35 + FPM，`expose_php=Off` 隐藏头 | 确认受影响 / P0 | 头隐藏时靠 phpinfo 与 SAPI 判定 |
| 8804 | 头部谎报 8.4.27，实际 8.4.26，构建日期早于补丁日 | 确认受影响 / P0 | **版本造假识别 + 证据冲突消解** |
| 8805 | WAF 全站 403，无任何 PHP 信息 | 无法判定 / P1 | **UNKNOWN 是一等公民**，不判"安全" |
| 8806 | PHP 8.1.31（EOL 分支） | 确认受影响 / P0 | **EOL 分支无修复，给"迁移"而非"升级"** |

> 8804 是整套逻辑的关键验证点：所有"只看版本号"的工具在这一台上都会判错（判为已修复），我们靠 phpinfo 与构建日期双重反证揪出来。

---

## 三、常用命令

```bash
# 单目标
python -m p2s scan http://127.0.0.1:8801

# 多目标 + 出报告
python -m p2s scan http://127.0.0.1:8801 http://127.0.0.1:8804 \
    --md reports/out.md --json reports/out.json

# 指定资产暴露面（影响风险分）
python -m p2s scan http://10.0.0.5 --exposure internal

# 深度画像 + SSH 主机核查（开启 D3/D4 补丁级核验）
python -m p2s scan https://example.com --profile deep \
    --ticket SEC-2026-1028 --i-have-authorization \
    --host 10.0.0.5 --ssh-user deploy --ssh-key ~/.ssh/id_rsa

# 失陷排查（支持目录、.gz 轮转日志）
python -m p2s hunt --log ./logs --md reports/hunt.md

# 看规则库
python -m p2s rules

# 测试
python -m unittest discover -s tests -v
```

退出码（方便接 CI）：

| 码 | 含义 |
|---|---|
| 0 | 全部已修复 / 不适用 |
| 1 | 存在确认受影响 |
| 3 | 存在无法判定（需要补采证据） |
| 4 | 存在疑似受影响 |

---

## 四、授权闸：为什么扫不了 example.com

非本机目标必须同时给出：

```bash
--i-have-authorization --ticket <工单号/合同号>
```

否则直接拒绝执行。这是产品设计里的硬约束，不是刁难 —— 任何未授权扫描都是违法行为，工具必须把这条写进代码而不是写进说明书。

回环地址（127.0.0.1 / localhost）豁免，所以靶场可以直接扫。

---

## 五、D5（OOM 探针）为什么默认关闭

D5 会让目标 PHP worker 达到 `memory_limit`，本质是一次 DoS 强度动作。要执行必须同时给两个开关：

```bash
--allow-intrusive --probe-oom
```

代码里还有前置/后置健康检查、单次执行、连接重置熔断。**绝大多数场景不需要 D5** —— D1–D4 已经能给结论，D5 只在"必须区分补丁前后行为"且能接受风险时才有意义。

---

## 六、目录结构

```
p2s/
  models.py        证据/结论/报告数据模型
  phpversion.py    版本解析与受影响判定（32 个单测覆盖）
  rules.py         规则库（内置 + 可加载外部 JSON）
  netclient.py     纯标准库 HTTP 客户端
  safety.py        限速 / 预算 / 熔断 / 授权闸
  verdict.py       证据聚合、冲突消解、评分、处置生成
  engine.py        检测编排
  report.py        终端 / Markdown / JSON 渲染
  cli.py           命令行
  detectors/
    d1_passive.py  被动指纹（头、phpinfo、Cookie、框架、WAF）
    d2_active.py   主动探测（非破坏性）
    d3_host.py     主机核查（local / SSH）
    d4_patch.py    补丁级核验（changelog / 构建日期 / 版本一致性）
    d5_behavior.py 受控 OOM 探针（双开关）
    d6_hunt.py     失陷排查（12 条规则 + 时间线关联）
lab/
  mock_php.py      6 个 persona 的模拟靶场
  sample_logs/     模拟攻击日志
tests/             单元测试
reports/           输出目录
```

---

## 七、接真实环境前必须知道的四件事

1. **`--profile deep` + `--host` 才能做补丁级核验。** 只给 URL 时，工具只能给"版本达标"，会在结论里明确写「未经安装物料核验」。这不是缺陷，是诚实。
2. **发行版回移补丁**：RHEL/Ubuntu/麒麟把补丁打进包里但不改版本号。这种机器只有读 changelog 才能判对，所以深度模式很重要。
3. **时间线要回溯到 2026-10-17**，不是 10-21。AWS 观测到的最早在野利用在披露前 4 天。`hunt` 会在日志起点晚于该日期时给出警告。
4. **扫描会在目标日志里留下痕迹**（D2 会产生少量 warning）。报告里会写明本次探测消耗了多少请求，便于客户事后核对。

---

## 八、当前实现的边界（不要高估）

| 已实现 | 未实现（设计文档中规划） |
|---|---|
| D1 被动指纹、D2 主动探测 | 二进制特征字节扫描（`signature_bytes`，需指纹库与样本） |
| D3 本机/SSH 只读采集 | WinRM（Windows/IIS）采集 |
| D4 changelog + 构建日期 + 版本一致性 | 镜像/固件离线解析（D7） |
| D5 受控探针（双开关） | Web 控制台、批量任务队列、RBAC |
| D6 12 条规则 + 时间线关联 | PDF/Word 报告、等保映射 |
| CLI + Markdown/JSON 报告 | OpenAPI 服务端 |

这些是 M1 的范围，M2–M4 的规划见 `05-开发实施计划与测试方案.md`。
