# 检测原理：四层收敛

> 这是本工具最核心的设计。**php2shell 只影响跑 PHP 的服务**，
> 而客户资产清单里大量是防火墙、堡垒机、路由器、Linux 主机、邮件网关、摄像头 ——
> 它们根本不跑 PHP。工具必须先说清"这是什么设备"，再说"有没有 PHP"。

```
   L0  存活与端口发现      TCP 连接探测  →  哪些端口开着
        │                   并发扫描，超时可控，覆盖 100+ 端口
        ▼
   L1  服务协议识别        HTTP/HTTPS 指纹 · TLS 证书取证 · SSH/SMTP/FTP banner
        │                   自签名证书自动降级 · UA 与路径回退阶梯
        ▼
   L2  设备类型分类        多信号加权打分
        │                   端口画像 + 证书 CN/O/OU + Server 头 + 页面标题 + SSH banner
        ▼
   L3  PHP 暴露面判定      是否跑 PHP → SAPI → 版本 → 是否低于修复基线 → 结论
```

---

## L0 · 存活与端口发现

并发 TCP 连接探测（默认 96 线程、1.2 秒超时），覆盖三类端口：

| 类别 | 端口示例 |
|---|---|
| 通用服务 | 21 22 23 25 53 80 110 143 161 389 443 445 3389 3306 5432 6379 8080 8443 9090 9200 27017 … |
| **安全设备管理端口** | **2000** 2082 2083 2086 2087 4243 7070 7443 8181 8880 10000 10001 10443 |
| 容器编排 | 2375 4243 6443 10250 10255 |

> 端口 2000/10000/2082 这类非标准端口是**安全设备管理界面**的典型落点，
> 早期版本只扫常见端口，所以客户的防火墙设备完全扫不出来。

---

## L1 · 服务协议识别

### HTTP / HTTPS 指纹
采集 `Server`、`X-Powered-By`、`Set-Cookie`、`Location`、页面 `<title>`。

### TLS 证书取证 ⭐
这是识别厂商和设备类型**最强的信号**：

```
CN=server,OU=yanfa,O=jump,ST=shan'xi,C=CN   →  JumpServer 堡垒机
CN=cacert,OU=jump,O=firewall,L=xian          →  JumpServer 堡垒机（443）
```

同时提取签发者、SAN、有效期与是否过期。

### 三条回退阶梯（应对内网设备的反扫描策略）

| 阶梯 | 做法 | 应对 |
|---|---|---|
| 协议 | 443/2000 等按 **TLS** 优先，明文回落 | 之前明文打到 TLS 端口，设备直接回 400 |
| User-Agent | 真实 Chrome UA → 通用 UA → curl | 部分设备屏蔽含 scanner/bot 的 UA |
| 路径 | `/` → `/index.html` → `/login` → `/cgi-bin/` → `/webui/` | 根路径 404 但真实入口在子路径 |

### SSH / SMTP / FTP banner
`SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20` 直接告诉你操作系统。

---

## L2 · 设备类型分类

多信号**加权打分**，不是单一匹配：

| 信号 | 权重 | 说明 |
|---|---|---|
| TLS 证书 CN/O/OU | 3.5 | 厂商与设备类型的首选判据 |
| SSH banner | 3.0 | 操作系统判据 |
| 页面标题 | 2.5 | 「开发测试防火墙系统」「堡垒机」「Zabbix」… |
| HTTP Server 头 | 2.0 | `Jump_server` / `nginx` / `Microsoft-IIS` / `fortinet`… |
| 存在 PHP | 4.0 | 直接判定为 PHP 应用站点 |
| 端口画像 | 1.0~2.0 | 25+110+143 → 邮件；3389 → Windows；容器端口 → 容器 |

### 支持的设备类型

| type | 中文标签 | 典型判据 |
|---|---|---|
| `firewall` | 防火墙 / 安全网关 | 证书含 firewall/utm、标题含「防火墙」 |
| `bastion` | 堡垒机 / 运维审计 | 证书/标题/Server 含 jump、堡垒机 |
| `network_device` | 网络设备（路由/交换） | 证书含 h3c/cisco/huawei、23/161 端口 |
| `mail_gateway` | 邮件网关 / 邮件服务器 | 25+110+143 同时开放 |
| `linux_host` | Linux 主机 | SSH banner 含 Ubuntu/Debian/RHEL |
| `windows_host` | Windows 主机 | 3389 开放、IIS Server 头 |
| `php_app` | PHP 应用站点 | 存在 PHP 迹象 |
| `web_server` | Web 服务器（无 PHP） | HTTP 服务但无 PHP 痕迹 |
| `app_server` | Java / 应用服务器 | Tomcat / Jetty / WebLogic |
| `cms` | CMS 网站 | WordPress / Drupal / Joomla / Magento |
| `db_tool` | 数据库管理工具 | phpMyAdmin |
| `monitoring` | 监控 / 运维平台 | Zabbix / Grafana / Prometheus |
| `devops` | DevOps 平台 | Jenkins / GitLab / Confluence |
| `file_service` | 文件共享服务 | Nextcloud / ownCloud |
| `cloud` / `container` | 云 / 容器平台 | OpenStack / Kubernetes / Docker / Portainer |
| `iot_device` | IoT / 嵌入式设备 | Raspbian / BusyBox / Dropbear |
| `appliance` | 网络设备 / 嵌入式 appliance | 有 Web 管理界面但无法细分 |

判定同时给出**置信度**与**候选类型**（次优类型分数接近时并列展示），不做黑盒断言。

---

## L3 · PHP 暴露面判定

```
是否跑 PHP？
  ├─ 否 → exposure = not_php
  │        结论："未检测到 PHP 痕迹，该设备与 php2shell 无关"
  │        处置：不需要任何动作，保留在台账里作为基线
  └─ 是 → 取版本 → 取 SAPI → 对比修复基线
          ├─ 版本 < 基线 → exposure = exposed     （严重）
          ├─ 版本 ≥ 基线 → exposure = patched     （低危）
          └─ 版本未知   → exposure = unknown     （待人工确认）
```

**版本基线**：8.2.35 / 8.3.36 / 8.4.27 / 8.5.12；8.1 及更早标为 `eol_backport_available`。

**SAPI 判定**（决定风险与可用手段）：

| SAPI | 风险 | 说明 |
|---|---|---|
| `apache` (mod_php) | 🔴 最高 | 请求启动期即可触发，**在应用代码运行前**就能被利用 |
| `fpm` | 🟠 高 | 启动失败会退出子进程，阻断部分链路 |
| `iis` (php-cgi) | 🟠 高 | |
| `litespeed` | 🟡 中 | 建模类似 FPM |

---

## 为什么不是"只查 PHP 横幅"

早期版本只做一件事：发一个 HTTP 请求，找 `X-Powered-By` 里的 PHP 版本号。
遇到不含 PHP 的设备就输出空白。用户无法区分两种完全不同的情况：

| 情况 | 正确结论 | 早期版本输出 |
|---|---|---|
| 这台是真 PHP 站点，但版本未知 | 需要进一步探测 | 空白 ❌ |
| **这台根本不跑 PHP** | **与本漏洞无关，无需处置** | 空白 ❌ |

新版本对这两种情况分别给出 `unknown` 和 `not_php`，并附带证据链。