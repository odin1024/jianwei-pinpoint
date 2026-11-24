# 交付给客户的三种部署方式

按客户的技术能力与合规要求选。

---

## 方式 A：Docker Compose 私有化部署（推荐给大多数客户）

**适合**：有运维能力、希望快速上线、希望把日志与报告留在自己内网的客户。

```bash
git clone <repo> && cd p2s
export P2S_CONSOLE_PASSWORD='<给客户设置一个口令>'
docker compose up -d
# 浏览器打开 http://127.0.0.1:18080 → 输入口令
```

只暴露一个 HTTP 端口，且默认只发布到回环地址；数据落在 `p2s_data` 卷里。

> **口令是必须的**：未设置 `P2S_CONSOLE_PASSWORD` 时控制台会随机生成一个，
> 并打印在容器日志里（`docker compose logs console`）。不要把一个没有口令的
> 扫描控制台暴露到网络上——任何能访问它的人都能驱动主动探测。

**给客户的说明模板：**

> 本工具仅做资产识别与漏洞暴露面评估，**不修改任何被检系统**。
> 主动探测会向目标发送最小化的无害请求，请确认目标均在授权范围内。
> 客户侧日志目录通过 `./logs:/app/logs:ro` **只读**挂载；控制台也有日志路径白名单，
> 只能读取这几类目录内的文件。

**要求**：Docker 20.10+ / Docker Compose v2。

---

## 方式 B：单机 Python + 本地 Web 控制台

**适合**：客户环境不允许 Docker，但可以装 Python。

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[console]"
p2s serve --host 0.0.0.0 --port 18080
```

Windows：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[console]"
p2s serve --port 18080
```

**要求**：Python 3.9+。

---

## 方式 C：纯 CLI / 无头（CI/CD、批量任务）

**适合**：客户已有资产管理系统，只需把扫描接进流水线。

```bash
p2s assets --file hosts.txt --report reports/
p2s probe  --file hosts.txt --report reports/ --no-probe   # 只判版本，不发探针
p2s logs   --file /var/log/nginx/access.log --report reports/
```

**退出码约定**（便于流水线判断）：

| 命令 | 0 | 非 0 |
|---|---|---|
| `assets` / `probe` / `logs` / `host` | 执行完成 | — |
| `ioc` | 未命中任何 IOC | 命中（=1） |

> 建议在 CI 中自行解析报告 JSON 的 `risk` 字段决定是否阻断发布。

---

## Agent 部署（需要 L3 主机侧检测时）

L3（生效配置、落地文件、进程、连接）必须在目标主机本地执行。

### Linux（systemd timer）

```bash
pip install p2s            # 或从源码安装
cat >/etc/systemd/system/p2s-agent.service <<'EOF'
[Service]
Environment=P2S_AGENT_TOKEN=<与控制台一致的令牌>
ExecStart=/usr/local/bin/p2s agent --console http://console.internal:18080 --interval 3600
User=root
EOF

cat >/etc/systemd/system/p2s-agent.timer <<'EOF'
[Timer]
OnBootSec=10min
OnUnitActiveSec=1h
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now p2s-agent.timer
```

### Windows（计划任务）

```powershell
$env:P2S_AGENT_TOKEN = "<与控制台一致的令牌>"
p2s agent --console http://console.internal:18080 --interval 3600
# 注册为计划任务：程序 p2s.exe，参数 "agent --console ... --interval 3600"，触发器为系统启动时 + 每 1 小时重复
```

> Agent 上报接口要求 `X-P2S-Token` 头（值 = 控制台的 `P2S_AGENT_TOKEN`），
> 否则返回 401 —— 一个无鉴权的上报接口等于让任何人往台账里投毒。
>
> 命令形式：`p2s agent ...` 与 `p2s-agent ...` 等价。前者在任何安装方式下都可用；
> 后者需要 `pip install p2s` 之后才会生成（旧的可编辑安装要重装一次）。

---

## 交付前检查清单

- [ ] `python scripts/check_payload_literals.py .` 通过
        —— 源码含完整 webshell 字符串会被客户杀毒/EDR 拦截，工具装不上
- [ ] `python -m pytest` 全绿
- [ ] `python -m ruff check src tests scripts` 无告警
- [ ] 确认客户环境的 Python 版本 ≥ 3.9（或提供 Docker 镜像）
- [ ] 与客户书面确认**授权扫描的资产范围**
- [ ] 确认日志挂载路径与数据留存策略（客户可能有数据出境/留存合规要求）
- [ ] 在客户环境做一次 PoC 演练：故意把一台测试机降到 8.4.26，验证工具能报出 `vulnerable`

---

## 客户常见问题

**Q：会不会把我的网站打挂？**
A：L1 被动检测零风险。L2 主动探针刻意使用保守尺寸（gentle 档约 50KB 级），
不做 OOM 洪泛、不发利用载荷。生产环境建议先用 `--no-probe` 只做版本判定。

**Q：扫描会不会被业务日志里的告警淹没？**
A：P2S-REQ-001（请求体含 `PHP_SESSION_UPLOAD_PROGRESS`）误报率近乎为零 ——
现代应用几乎不使用这个字段。其余规则误报率较高，建议只部署 001 / 003 / 004 / 006 / REC-003 五条。

**Q：能不能顺便帮我修？**
A：工具只读，不做任何修改。修复动作由客户的变更流程执行，
工具提供 `remediation` 字段给出该目标的具体处置建议。

**Q：8.1 及更早版本怎么办？**
A：官方已 EOL。工具会标为 `eol_backport_available` / `eol_unpatchable`，
建议走发行版/LTS 厂商回补，或升级到 8.3+。

**Q：WAF 能不能当缓解措施？**
A：只能作为补丁前的临时屏障。Cloudflare 自己也强调攻击者在持续变换载荷绕过 WAF 规则，
最终必须升级 PHP。