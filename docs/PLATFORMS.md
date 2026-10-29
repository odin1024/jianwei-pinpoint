# 多平台支持矩阵

## 一、工具运行平台（p2s 自己跑在哪）

| 平台 | 架构 | 状态 | 备注 |
|---|---|---|---|
| Linux | x86_64 / arm64 | ✅ | Ubuntu / Debian / RHEL / CentOS / Alpine / openEuler / 麒麟 / UOS |
| Windows Server | x86_64 | ✅ | 2016 / 2019 / 2022 / 2025 |
| Windows 桌面 | x86_64 / arm64 | ✅ | 10 / 11 |
| macOS | Intel / Apple Silicon | ✅ | Homebrew / MacPorts |
| Docker / Podman | 多架构 | ✅ | 容器内扫描宿主机挂载目录 |
| Kubernetes | 多架构 | ✅ | 以 Job/DaemonSet 方式运行 |

CI 矩阵（`.github/workflows/ci.yml`）覆盖 ubuntu / windows / macos × Python 3.9 / 3.11 / 3.12。

---

## 二、目标系统类型（被扫描的是什么）

### Web 服务器 / SAPI

| SAPI | 风险等级 | 指纹特征 | L1 | L2 | L3 | 特殊说明 |
|---|---|---|---|---|---|---|
| **Apache + mod_php** | 🔴 最高 | `Server: Apache/x` + `X-Powered-By: PHP/x` | ✅ | ✅ | ✅ | 请求启动期即可触发，**在应用代码运行前**就能被利用 |
| Nginx + PHP-FPM | 🟠 高 | `Server: nginx` + PHP 头 | ✅ | ✅ | ✅ | 启动失败会退出子进程，阻断部分链路 |
| Apache + mod_proxy_fcgi | 🟠 高 | Apache 头 + FPM 错误页 | ✅ | ✅ | ✅ | |
| Microsoft IIS + php-cgi | 🟠 高 | `Server: Microsoft-IIS` | ✅ | ✅ | ✅ | |
| LiteSpeed / OpenLiteSpeed | 🟡 中 | `Server: LiteSpeed` | ✅ | ✅ | ✅ | 建模类似 FPM |
| FrankenPHP | 🟠 高 | `Server: FrankenPHP` / Caddy | ✅ | ✅ | ✅ | 与 mod_php 行为同构 |
| OpenResty | 🟠 高 | `Server: openresty` | ✅ | ✅ | ✅ | |

### 应用与 CMS

| 类型 | 指纹 | 特殊关注点 |
|---|---|---|
| WordPress | `/wp-content/`、首页特征 | 插件漏洞密度最高；phpMyAdmin 路径特殊处理 |
| Drupal / Joomla | 特征路径 | Wiz 已确认这两者上存在预认证 RCE 变体 |
| Magento / Adobe Commerce | 特征头 | |
| phpMyAdmin | `/show_config_errors.php` | 扫描器会自动尝试该路径 |
| Laravel / Symfony | 响应头与错误页 | 框架自身漏洞另计（见生态报告） |
| Nextcloud / WikiMediaWiki / TYPO3 | 特征路径 | |

### 嵌入式与设备

路由器、防火墙、存储设备、摄像头、工控 HMI 的 Web 管理界面常内置 PHP。
这类目标**通常无法直接打补丁**，只能等厂商公告。

NCSC-NL 追踪的 757 个产品中，218 个确认易受影响、144 个已修复、354 个调查中 ——
Cisco ISE、Cisco Unified Industrial Wireless 目前标记为 Vulnerable。

### 容器与虚拟化

| 形态 | 检测方式 |
|---|---|
| Docker | `docker ps` → 容器内 PHP 版本；镜像层扫描 |
| Podman | `podman ps` |
| Kubernetes | API 列举 Pod/Deployment → 逐 Pod 检查 |
| VMware ESXi appliance | 嵌入的 PHP 只能通过 HTTP 指纹 + 厂商公告 |
| 云镜像（ECS/CVM/OpenStack） | 镜像清单 + 启动后指纹 |

---

## 三、主机侧配置来源（L3 必须合并全部来源）

同一台机器上，`session.upload_progress.enabled` 可能被 6 个地方设置，
**实际生效的是优先级最高的那一个**。`core/hostcheck.py` 通过 `php -r "echo ini_get(...)"`
直接读取**运行时真实生效值**，而不是去猜配置文件。

排查时需要覆盖的来源：

| 来源 | 作用域 | 优先级 |
|---|---|---|
| `php.ini`（系统级） | 全局 | 最低（被覆盖） |
| FPM pool `php.ini` | FPM 全局 | 低 |
| `.user.ini` | 目录级 | 中（请求后期生效，**不适用于 upload_progress 缓解**） |
| `.htaccess` `php_value` | 目录级 | 中 |
| `php_admin_value`（FPM pool / Apache） | 目录级 | 高 |
| `PHP_VALUE` / `PHP_ADMIN_VALUE`（FastCGI 参数） | 请求级 | 最高 |
| `ini_set()` 运行期调用 | 代码级 | 最高 |

> **重要**：`session.upload_progress.enabled=0` 必须写在 `php.ini` 或 FPM pool（请求解析前生效）。
> 用 `ini_set()` 或 `.user.ini` **无效** —— 官方公告明确点名了这一点。

---

## 四、跨平台实现要点

| 能力 | Windows | Linux | macOS |
|---|---|---|---|
| 找 PHP | PATH + 注册表 `SOFTWARE\PHP\PHP` + 常见目录 | PATH + alternatives + `/usr/bin` 等 | PATH + Homebrew + MacPorts |
| 读生效配置 | `php -r "echo ini_get()"` | 同 | 同 |
| 列进程 | `tasklist`（可选 psutil） | `ps -eo` | 同 Linux |
| 列连接 | `netstat -ano` | `ss -tunp` | `netstat -tunp` |
| 文件痕迹扫描 | `%TEMP%` / `C:\inetpub\wwwroot` / `C:\xampp\htdocs` | `/tmp` `/var/tmp` `/var/lib/php/sessions` | `/private/tmp` |
| 样本哈希比对 | SHA-256（跨平台一致） | 同 | 同 |
| 伪装进程检测 | `sysmon` / `crong3-agent` | 同 | 同 |

---

## 五、暂未覆盖（规划中）

- Windows 下 `php.ini` 注册表路径深度遍历（当前只枚举一级子键）
- 容器镜像层离线扫描（需 `docker save` + 层解包）
- Kubernetes 多集群纳管
- Windows ETW 事件订阅（当前用轮询 + tasklist）