# PHP 核心严重 RCE「php2shell」全面情报报告

> 报告日期：2026-10-29（Asia/Shanghai）  数据截取时间：2026-10-29 01:00 UTC 前后
> 主题：2026 年 10 月爆发的两个 PHP 核心远程代码执行漏洞（CVE-2026-109618 / CVE-2026-109619），代号 **php2shell**

---

## 〇、一句话结论

10 月 21 日，PHP 项目一次性发布两个 **CVSS 9.2 / Critical** 的未认证远程代码执行漏洞（CVE-2026-109618、CVE-2026-109619），影响**所有对外提供 Web 服务的 PHP 安装**（PHP-FPM、Apache mod_php、php-cgi、FrankenPHP、LiteSpeed）。漏洞公开数小时内即出现多个可用 PoC 与扫描器，**已在野利用**；CISA 于 10 月 26 日将其列入 KEV「已知被利用漏洞」目录，**强制修复截止日为 2026-10-29（今天）**。

**唯一完整有效的修复：升级到 PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35。**

---

## 一、核心事实速览

| 项目 | 内容 |
|---|---|
| 漏洞编号 | CVE-2026-109618（OOM 内存破坏）、CVE-2026-109619（陈旧全局状态 UAF） |
| GHSA | GHSA-w8hw-w9fx-j79w、GHSA-6wmf-4rv5-p3rp |
| CVSS | 9.2 Critical（CVSS 4.0，`AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H`） |
| 攻击前提 | **无需认证**、无需用户交互；可绕过应用层代码直接触发 |
| 影响范围 | 所有对外提供 Web 请求的 PHP 安装；PHP 官方认定 **mod_php 风险最高** |
| 修复版本 | PHP **8.5.12**、**8.4.27**、**8.3.36**、**8.2.35**（2026-10-21 发布） |
| 在野利用 | 已确认（AWS MadPot 蜜罐 10-17 即见首波扫描） |
| CISA KEV | 2026-10-26 收录，**修复截止 2026-10-29** |
| 攻击链关键 | `session.upload_progress`（会话上传进度）预认证 UAF |
| 关联漏洞 | CVE-2026-115560（同一功能，配置罕见，官方不发版，走常规修复周期） |
| 波及面 | 757 个产品被追踪，其中 **218 个确认易受影响**、144 个已修复、354 个调查中（NCSC-NL，10-28） |

### 发布版本一览

| 分支 | 修复版本 | 发布日期 | 说明 |
|---|---|---|---|
| 8.5 | 8.5.12 | 2026-10-22 | 现行最新稳定版 |
| 8.4 | 8.4.27 | 2026-10-22 | 安全维护中 |
| 8.3 | 8.3.36 | 2026-10-21 | 安全维护中 |
| 8.2 | 8.2.35 | 2026-10-21 | 安全维护中（接近 EOL，官方支持至 2026-12-31） |
| 8.1 及更早 | 无官方更新 | — | 已 EOL；官方仅提供 7.4 / 8.0 / 8.1 的**最小源码回补** |
| 8.6 | 8.6.0 RC4 | 2026-10-21 | 含修复，但为 RC，**禁止上生产** |

> Windows 用户注意：8.5.12-1 / 8.4.27-1 / 8.3.36-1 / 8.2.35-1（2026-10-26 发布）额外包含 Brotli 1.2.1，修复了同样被列入 KEV 的 CVE-2026-111497（Google Brotli 解码器越界写，CVSS 9.2）。PHP 的 cURL 扩展在开启自动 HTTP 响应解压时可触达该解码器。

---

## 二、技术原理

### CVE-2026-109618 —— RCE via OOM corruption（内存破坏）

**根因**：PHP 用 `longjmp()` 处理内存超限（OOM）。当 OOM 发生在「请求内存尚未完全初始化」的时刻，`longjmp()` 会直接跳出当前上下文，导致请求内存处于**半初始化状态**；随后的请求清理流程（shutdown）会把这份无效内存当作有效数据来读取或做分支判断。此时内存里可能残留着攻击者早前可控的分配内容。

**官方补丁思路**：**彻底移除 OOM 路径上的 `longjmp()`**。改为在下一个 VM 安全点触发「软 OOM」优雅退出；内存占用达到第二级更高阈值时用 `_exit()` 硬退出。请求清理流程因此不会再看到无效状态，同时 PHP 仍保有正常的内存限制能力。

**触发 OOM 的三条低门槛路径**（均在 `post_max_size` 之内）：

1. **缺少可用 Content-Length 的 multipart 请求** —— 绕过 `post_max_size` 初始检查，继续投递解码后的 body 数据。
2. **multipart 分段内的 header 数量不受限** —— PHP 内部表示这些 header 的内存开销远大于其线上表示，一个「合规」请求即可耗尽 `memory_limit`。
3. **空文件控件不计入 `max_file_uploads`**，却照样生成完整的文件元数据数组；嵌套字段名会成倍放大数组构造开销。

### CVE-2026-109619 —— RCE via stale global state（陈旧全局状态 UAF）

**根因**：PHP 的错误、会话、对象、扩展等**全局状态**由 worker 进程持有，但其中一部分指向的是**属于某个请求的内存**。正常情况下请求结束时会先重置这些全局状态再释放请求内存。但只要出现以下任一情况，重置就会被跳过：

- **致命错误**中断了操作（parse/compile 失败、未捕获异常、`require` 失败、`Maximum execution time exceeded`）；
- **OOM** 在状态已发布之后发生；
- 扩展/服务器清理阶段产生的**非致命诊断**（warning 等）在已清空之后**重新填充**了错误状态。

于是：请求堆被释放 → worker 全局字段仍指向已释放内存 → **同一个 worker 处理下一个请求**时，在正常初始化之前读取/释放/分支于这份陈旧状态 → **堆 UAF**。精心设计的堆布局可实现完整 RCE。

**已确认的两条具体链路**：

| 链路 | 生产者（producer） | 消费者（consumer） | 验证情况 |
|---|---|---|---|
| **fatal_error_backtraces**（PHP 8.5 独有） | 启用 `fatal_error_backtraces` 后，致命错误回溯状态属请求所有，shutdown 阶段**必然漏掉重置** | 下一个请求在初始化前触发的 INI 诊断（warning/notice/deprecation）读到该陈旧回溯 | mod_php 上确认 RCE |
| **session.upload_progress 生命周期** | 上传初始化早于普通模块初始化即发布会话/解码器状态；此后 OOM 或致命错误使配对重置未执行 | 后续请求的 upload progress 操作在普通初始化前使用这些全局 | mod_php 与 **FPM 均验证 RCE** |

**INI 诊断消费路径的触发方式极其普遍** —— 以下配置就会在每个请求前产生一条诊断信息：

- 确定性弃用：`auto_detect_line_endings=1`、非默认 `filter.default`、PHP 8.3+ 遗留 `assert.*`、PHP 8.4+ 遗留 session 设置、PHP 8.5 的 `report_memleaks=0` 或非零 `intl.error_level`
- 显式配置的 `mbstring.http_input/http_output/internal_encoding`、`iconv.*_encoding`
- 非法或冲突的 `zend.assertions`、`memory_limit`、`date.timezone`、DBA / EXIF / mail / OpenSSL / zlib 及已加载扩展的值
- 畸形或溢出的数量值（PHP 8.2+ 的 `memory_limit`、body 大小、输入、超时、栈、扩展值）
- 被 `open_basedir` 拒绝的 log / mail / session / SOAP 缓存路径

> **关闭 `display_errors` / `log_errors`、改 `error_reporting`、加 `@` 抑制符都无效** —— PHP 在决定是否报告/显示/记录**之前**就已经访问了这块陈旧状态。

### 受影响 SAPI 的差异

| SAPI | 风险 |
|---|---|
| **Apache mod_php** | **最高**。无条件调用请求清理流程，且请求启动期（自动 body 解析）就能触发，**在应用代码运行前即可被利用** |
| **PHP-FPM** | 受影响，但启动失败会退出子进程从而阻断部分链路；已验证的 FPM 路径需要应用层配合（上传后致命错误 + upload_progress 消费） |
| **php-cgi** | 受影响 |
| **FrankenPHP** | 源码分析表明与 mod_php 同构，**很可能易受影响**（应用无关攻击） |
| **LiteSpeed (LSAPI)** | 建模类似 FPM，应用层利用可能性大但未经验证 |

### 一条关键的横向约束

**生产者请求与消费者请求必须命中同一个 worker 进程**。多 worker、进程回收会降低单次成功率，但不消除条件。

---

## 三、完整时间线

| 时间（UTC） | 事件 |
|---|---|
| 10-17 | **AWS MadPot 蜜罐观察到首波攻击尝试**（早于任何公开披露 4 天） |
| 10-20 15:20 | Hacker News「泄露讨论帖」流出两个 CVE 编号，且**评分误标为 10.0**，PHP 因此决定**提前发布** |
| 10-20 18:39 | Kevin Beaumont 在 Mastodon 点名两个 CVE 编号（泄露窗口期） |
| 10-20 19:30 | PHP 官方预告：10-21 14:00 发布，**CVSS 9.2** |
| 10-20 19:52 | The PHP Foundation 同步预告 |
| 10-20 20:27 | Calif 误发布 PoC 演示视频（随即删除，副本仍在流传） |
| 10-21 00:30 | X 上有人声称已做出可用 PoC（未验证） |
| 10-21 07:43 | **Cloudflare CTO 公开预警早期攻击流量**，称 WAF 规则只是补丁前的临时缓解 |
| 10-21 08:37 | TU Delft 网络望远镜首次观测到 php2shell 特征请求 |
| 10-21 09:01 | Tenable 发布 FAQ 与 Nessus 插件覆盖 |
| 10-21 09:59 | **Wiz Research 披露四种 bug 变体，指出在 WordPress / Drupal / Joomla 上为预认证 RCE** |
| 10-21 11:03 | Nuclei 上架受影响检测模板 |
| 10-21 12:00 | **UK NCSC** 与 **US CISA** 同日发布国家级别警报 |
| 10-21 13:00 / 13:25 / 13:42 | 蜜罐首见高交互请求 → **首条 OS 命令** → **首次 UAF（伪造 zval 结构）** |
| 10-21 13:34 | php-src 官方 GitHub Security Advisory 上线（两个） |
| 10-21 13:46 | **NSA** 发布警报：可导致攻击者直接读取文件与数据库 |
| 10-21 13:56 | Cloudflare WAF 规则上线（自 03:02 UTC 起生效），攻击者随即变换载荷绕过 |
| 10-21 14:00 | **PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 正式发布**；Calif 发布技术长文；PHP Foundation 公告 |
| 10-21 14:19 | watchTowr 发布 PHP2Shell FAQ |
| 10-21 14:59 | **FBI 网络部门**建议监控 PHP 进程启动 shell 或下载文件的行为 |
| 10-21 15:20 | CERT-EU 发布公告 2026-018 |
| 10-21 16:13 / 18:35 / 18:36 | 首次 OOM（深层嵌套名）、OOM（header 洪泛）、OOM（数百分段） |
| 10-23 | PHP 发布**信息性公告**：建议在下次常规修复版前保持 `session.upload_progress.enabled=0`（对应 **CVE-2026-115560**） |
| 10-23 | CISA 补充 SIGMA 检测规则与伙伴机构资源 |
| 10-26 | **CISA 将两漏洞写入 KEV 目录**，强制修复截止 2026-10-29 |
| 10-26 | PHP 发布 Windows 构建 8.5.12-1 等，含 Brotli 1.2.1（修 CVE-2026-111497） |
| 10-26 之后 | NCSC-NL、ACSC、NCSC-NZ、Cyber Centre(CA) 等多国机构持续发布/更新通告 |

---

## 四、在野利用现状（TU Delft INTELLAB 实时观测，截至 2026-10-29 01:13 UTC）

**核心数字**

- **72,678** 次利用请求，来自 **664** 个源 IP、**309** 个自治系统（AS）、**73** 个国家
- 其中 **176 个源 IP 发送了代码或 dropper**
- 首个请求：2026-10-21 08:37:17 UTC（网络望远镜）；高交互蜜罐首见 13:00:12
- **最忙时段：10-26 14:00 UTC，8,179 次请求**
- 747 个不同的 multipart boundary；命中 2,725 个蜜罐地址
- 修复版发布（10-21）之前仅有 **2 个 IP** 发起 49 次请求 → 说明攻击者是在公开后才规模化

**利用阶段分布**

| 阶段 | 请求数 | 源 IP |
|---|---:|---:|
| 探测（probe） | 52,990 | 553 |
| OS 命令执行 | 10,957 | 63 |
| 代码执行 | 10,510 | 148 |
| dropper（wget/curl 拉取二阶段） | 4,655 | 50 |
| 过载 / OOM | 4,523 | 132 |
| 会话反序列化 gadget | 1,323 | 108 |
| OOM：深层嵌套字段名 | 3,116 | 55 |
| OOM：空文件字段 | 2,646 | 45 |
| OOM：header 洪泛 | 484 | 8 |
| OOM：数百分段 | 1,298 | 78 |
| PHP 代码写入 progress 字段 | 10,423 | 35 |
| PHP 代码写入文件名 | 1,464 | 35 |
| UAF：伪造 zval 结构 | 1,807 | 10 |

**已落地的恶意样本（沙箱内捕获）**

| 样本 | 类型 | 说明 |
|---|---|---|
| `nfs` | Mirai 衍生 DDoS 机器人 | SHA-256 `0c5486f0…d1486`。**加密 C2 通道**，通过域名取 C2，并以 **Ethereum ENS 名称**作为备份。x86_64 |
| `x86_64(2)` | Mirai 变种 "2.0.4_socks5" | SHA-256 `7d9965de…100a9`。沙箱中域名解析失败后回退到备用地址，**该 C2 当时在线**，接受连接并保持会话 |
| `cb` | Nim 植入体 "crong3-agent"（build 3.0.0-929），**伪装成 sysmon** | SHA-256 `a5289abe…3af`。以 **Ethereum ENS 名 + Solana 账户**读取 C2；不使用常规 DNS 解析器 |
| `f0aa…` | 未定性 | SHA-256 `f0aa83bb…987`。通过 DoT 做 DNS 查询并发出单条加密消息 |

> 这些样本表明攻击者已把漏洞武器化为 **DDoS 僵尸网络 + 长期后门**，而非一次性 webshell。

**Dropper / 落地 URL（用于封堵的 IOC，勿访问）**

```
http://45.74.7.227/collect/p2srun.php?w=p2s…
http://45.74.7.227/collect/p2srun.php?w=p2s…&stage=diag&u=$
http://45.74.7.227/collect/p2srun.php?w=p2s…&stage=diag&d=u%3D$
http://176.65.139.153/wget.sh
https://217.60.102.5/sh
https://pastebin.com/raw/wCYGVCBG
http://92.118.112.100/p
http://92.118.112.100/s
http://92.118.112.100/nfs
http://217.15.162.38:27182/$T/srl.sh
http://217.15.162.38:27182/DT14REn1ylaykdkWBqbML5wf/issue
http://87.251.64.204:7716/i
http://185.225.191.232/c
http://191.217.250.227:8081/b.php?w=p2s…
http://45.115.26.26:8000/cCmono
http://45.115.26.26:8000/cClar
http://hana.by/
https://webhook.site/c8370342-2a5c-489c-a0d3-35930cc2bc54/…   (多条)
https://webhook.site/0e7f04d6-7839-40d6-963e-a6d7744a4cd3
```

**典型攻击请求特征**（Arctic Wolf 蜜罐捕获）

```
User-Agent: php2shell-scan/109618
Cookie: PHPSESSID=<REDACTED>
Content-Type: multipart/form-data; boundary=B7kQpoc618
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"   ← 关键字段
Content-Disposition: form-data; name="f"; filename="a" AAAA…
```

部分扫描器混淆了 php2shell 与**旧式会话投毒**技术（把序列化 Monolog gadget 链塞进上传文件名元数据，再用本地文件包含读取会话文件）——这类请求**不构成对 CVE-2026-109618/109619 的实际利用**，但在识别时需区分。

---

## 五、处置方案

### 5.1 唯一完整修复

升级到 **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**。

- Linux 发行版与 LTS 厂商**提前**收到了补丁，请检查各自仓库更新。
- PHP 8.1 及更早已 EOL，官方项目不再更新。PHP 团队为 **7.4 / 8.0 / 8.1** 提供了**最小源码回补**（源码构建或无 LTS 厂商时使用）。
- 升级后**必须重启所有 PHP worker**（reload 不够）。
- 8.2 分支支持至 2026-12-31，请规划升级到 8.3+。

### 5.2 无法立即升级时的临时缓解（均非完整修复）

#### 针对 CVE-2026-109618（OOM）

| 措施 | 说明 |
|---|---|
| `memory_limit=-1` | 用 `php_admin_value`（FPM pool / Apache）设置，**确保应用无法覆盖**；并核查没有 pool / 目录 / 应用层重新设回有限值。**同时重启所有 worker** |
| `post_max_size` 调小 | 无上传需求：`post_max_size = 8M`；有上传需求：`32M`。保持 `upload_max_filesize < post_max_size` |
| 前置层限额 | 在 Web 服务器 / 反向代理层限制**解码后**请求体大小、输入字段数、multipart 分段数、每段 header 数、嵌套深度。**限额必须覆盖没有可用 Content-Length 的请求** |
| 容器 / cgroup 限额 | 作为可用性边界，策略应**只杀受影响的 worker**（避免连带杀掉 master 与全部 worker） |
| **禁用 `RLIMIT_AS` / `RLIMIT_DATA`** | 这会让 `mmap()` 在触达上限时失败，反而**触发受漏洞影响的 `longjmp()` 路径** |

> 官方明确说明：即便 `memory_limit=-1`，底层分配失败（如 `mmap()` 失败）仍可能走到受影响的 `longjmp()` 路径，因此这不是完整缓解。

#### 针对 CVE-2026-109619（陈旧全局状态）

| 措施 | 说明 |
|---|---|
| `session.upload_progress.enabled=0` | 用 `php.ini` / FPM pool / 服务器配置在**请求解析前**生效；**不要依赖 `ini_set()` 或 FPM `.user.ini`**。设置后**重启所有 worker** |
| `fatal_error_backtraces=0`（仅 PHP 8.5） | 移除已确认 RCE 链路的生产者。设置后**重启所有 worker** |
| 清理按请求生效的非法/弃用配置 | 消除初始化前产生的诊断信息 |
| 无效手段 | `error_reporting` / `display_errors` / `log_errors` / `@` **一律无效** —— 状态在决定是否报告之前就已被访问 |
| `pm.max_requests=1` | 若不在乎性能，限制单 worker 处理请求数可打破「生产者/消费者同 worker」前提 |
| 执行超时 | **视同致命错误处理**。防止攻击者可控请求可预测地触发 `Maximum execution time exceeded`；**改时限只是移除了这条中断路径，并不构成缓解** |

#### 关于 CVE-2026-115560（10-23 信息性公告）

需要同时满足罕见条件才会触发：应用将 `session.serialize_handler` 设为 `php_binary` 或 `php_serialize`，再在运行时用 `ini_set()` 切回 `php` 后调用 `session_start()`，且 upload progress 仍启用。PHP 走常规修复周期，官方不发版。**从不出现在运行时切换 serialize handler 的应用可继续启用该功能**；其余情况建议保持 `session.upload_progress.enabled=0` 直到下次常规修复版。

### 5.3 排查与检测

**立即执行**

1. **清点所有运行 PHP 的资产** —— PHP 常作为其他软件的组件存在，暴露面不可直接观测；优先处理互联网暴露系统。
2. **检查访问日志**，关注：`PHP_SESSION_UPLOAD_PROGRESS` 字段出现的 multipart 请求、超大 `Content-Length` / 无 `Content-Length` 的 multipart、大量 multipart header、超多分段、异常的 `PHPSESSID` 复用模式。
3. **检查 PHP worker 进程是否启动 shell 或下载工具**（FBI、CISA 均明确提示）：`sh`/`bash`/`curl`/`wget` 由 www-data/php-fpm 用户派生；检查 `/tmp`、`/var/tmp`、upload_tmp_dir 下的可疑文件。
4. **核对 `session.upload_progress` / `fatal_error_backtraces` / `memory_limit` / `post_max_size` 实际生效值**（注意 `.htaccess`、`php_admin_value`、`PHP_VALUE`、`.user.ini` 多层覆盖）。
5. **利用蜜罐/扫描工具确认暴露面**：Assetnote `php2shell-scanner`、`openai/php2shell-checker`、Nuclei 模板、Nessus 插件（Tenable）、`ikow/php2shell-poc`（含 Docker lab 与 Suricata/Sigma/ModSecurity 规则）。
6. **规则与 IOC**：CISA SIGMA 规则（`cisagov/SIGMA_Rules`）、NCSC-NL `php2shell` 仓库的 `detection_mitigation` 目录、TU Delft 蜜罐 IOC 列表（本文第四节）。

**无法修补时（临时）**

- 将受影响的 PHP 系统**下线**，直到完成修补。
- WAF 可提供部分缓解（Cloudflare 规则 10-21 03:02 UTC 已上线，但攻击者持续变换载荷绕过），**只能作为补丁前的临时屏障**。

### 5.4 处置优先级 Checklist

```
1. 立刻确认 PHP 版本（php -v / phpinfo），对照 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35
2. 识别所有 SAPI：mod_php > PHP-FPM > php-cgi > FrankenPHP > LiteSpeed（mod_php 风险最高）
3. 排查嵌入式 PHP：路由器/防火墙/摄像头/存储/管理后台/工控设备（NCSC-NL 特别强调）
4. 升级补丁 → 重启所有 worker → 复验版本
5. 未能升级：设 memory_limit=-1 + post_max_size 收紧 + 前置层限额；设 session.upload_progress.enabled=0 + fatal_error_backtraces=0（8.5）
6. 清除旧值：确认没有 .user.ini / ini_set / pool 配置把上述值改回去
7. 巡检日志：upload_progress 探测、异常 multipart、worker 派生 shell、/tmp 落地文件
8. 封堵 IOC 与 C2（dropper URL、webhook.site、45.74.7.227、217.60.102.5 等）
9. 排查是否已被植入 Mirai / crong3-agent 后门（样本哈希见第四节）
10. 确认 8.1 及更早的资产 → 走发行版/LTS 厂商补丁或源码回补，制定升级到 8.3+ 的计划
11. 评估 CVE-2026-115560：若运行时会切换 session.serialize_handler，保持 upload_progress 关闭
12. Windows 资产：升级到 -1 构建（Brotli 1.2.1，修 CVE-2026-111497）
```

---

## 六、同期 PHP 生态的其他漏洞（不可忽视的第二战场）

php2shell 抢占注意力时，PHP 生态本身在 2026 年 10 月仍高频爆出漏洞。**这些漏洞往往比核心漏洞更容易被直接利用**（无需内存布局工程）。

### 2026 年 10 月 Composer/Packagist 生态高危公告（节选）

| 日期 | 等级 | 编号 | 摘要 |
|---|---|---|---|
| 10-27 | 高 | CVE-2026-109413 | Symfony：YAML 内联词法器无界递归，单个文档即可打崩进程 |
| 10-27 | 高 | CVE-2026-108082 | Symfony：`HeaderUtils::split()` ReDoS，可经 Cache-Control 请求头触发 |
| 10-27 | 高 | CVE-2026-108358 | PhpSpreadsheet：XmlScanner 被 ISO-2022 转义序列绕过，导致 XXE 与 DoS |
| 10-27 | 高 | CVE-2026-108357 | PhpSpreadsheet：XmlScanner 被二次编码 `unentity()` TOCTOU 绕过，导致 XXE 与 DoS |
| 10-27 | 高 | CVE-2026-108359 | PhpSpreadsheet：ODS 读取器 `number-rows-repeated` 无限制 → CPU/内存耗尽 |
| 10-23 | 严重 | CVE-2026-114509 | **Laravel TokenGuard：非字符串 API 凭据导致认证绕过** |
| 10-23 | 中 | CVE-2026-114508 | Laravel：关系 include 可触发未授权数据销毁 |
| 10-15 | 高 | CVE-2026-85990 | Leantime：任意已认证用户可通过未授权 JSON-RPC 方法自提权为 Admin |
| 10-09 | 严重 | CVE-2026-107845 | Contao：评论组件存储型 XSS |
| 10-07 | 高 | CVE-2026-104890 | Kunstmaan CMS：MediaBundle 扩展名黑名单绕过 → 可上传可执行 PHP → RCE |

### 2026 年 10 月 NVD 中 PHP 相关高危/严重（按产品族）

| 类别 | 代表案例 |
|---|---|
| **WordPress 插件（PHP Object Injection / 任意文件上传）** | Prime Mover <=2.2.1（9.8）、Pie Register Premium <=3.8.4.0（9.8）、Checkout Files Upload for WooCommerce <2.4.0（9.8）、Contact Manager <=9.1.2（9.8）、IvyForms <=1.5.1（8.8）、Rank Math SEO（8.8）、Icegram <=3.1.31（8.8）、Kirki <=6.2.5（8.8） |
| **GetSimple CMS** | 密码重置绕过（9.1）、更新处理器（9.1）、未认证访问（7.1） |
| **Apache Thrift PHP 绑定** | 一次性爆出 5 个：整数溢出、栈溢出、未捕获异常、资源无限制分配（8.7 / 8.2 / 7.2），影响 **Thrift < 0.25.0** |
| **CMS / 框架** | Craft CMS 沙箱 Twig 逃逸（8.7）、baserCMS 权限提升（8.5）、Mautic 反序列化（8.0）、phpMyFAQ 未授权修改（8.7）、Semantic MediaWiki 复杂度 DoS（8.7） |
| **语言/库** | phpseclib X25519 纯 PHP 侧信道（**CVE-2026-84308**）、Predis 流水线聚合命令缺陷（**CVE-2026-84372**）、Composer Perforce `p4` 命令注入（**CVE-2026-84361**，影响 Composer <2.2.30 / <2.10.3） |
| **供应链** | CVE-2026-84361：恶意依赖包可将 `source.type` 设为 perforce、`source.url` 设为 `rsh:`/`jsh:`，Composer 未校验即交给 `p4`，导致**本地命令以 CI/用户权限执行**（Packagist 自身不允许该元数据，风险主要在私有仓库与不可信 lock 文件） |
| **Cypht** | CVE-2026-71981：`back_query` GET 参数 base64 反序列化 → 未认证 PHP 对象注入 → RCE |

> 统计口径：NVD 2026 年 10 月以 `PHP` 为关键词收录 **278** 条 CVE，其中 CVSS >= 7.0 者占绝大多数。

### 2026 年 PHP 核心其他已修复漏洞（年初至今，共 30 条公告）

| 发布批次 | 代表条目 |
|---|---|
| 2026-05-07 | **CVE-2026-6722** SOAP Apache map UAF → RCE（高）；**CVE-2025-14179** pdo_firebird NUL 字节 SQL 注入（高）；CVE-2026-6104 `mb_convert_encoding()` 全局缓冲区越界读；CVE-2026-7258 `urldecode()` 越界读；CVE-2026-7263 `DOMNode::C14N()` DoS |
| 2026-07-02 | CVE-2026-14355 `openssl_encrypt` AES-WRAP-PAD 内存破坏；CVE-2026-12184 TLS 握手失败导致远程 DoS |
| 2026-07-30 | **CVE-2026-17543** ext-pgsql `E'...'` 反斜杠逃逸 SQL 注入；**CVE-2026-17544** `bccomp()` 越界写；CVE-2026-7260 phar 循环符号链接栈溢出 |
| 2026-09-24 | **CVE-2026-91765** SOAP `cleanup_xml_node` 无界递归（高）；**CVE-2026-91768** FastCGI `listen.allowed_clients` IPv6 ACL 绕过（memcmp 只比 12 字节）；**CVE-2026-91769** TLS 主机名校验在 SAN 不匹配时回退到 CN；CVE-2026-91766 HTTP stream wrapper 重定向跨源凭据泄露；CVE-2026-6103 Phar TAR 整数溢出导致归档条目注入；CVE-2026-93682 HTTP stream wrapper 空 Location 重定向越界读 |
| 2026-10-21 | **CVE-2026-109618 / CVE-2026-109619** —— 本次主角 |

---

## 七、给不同角色的行动摘要

**系统管理员 / 运维**
> 今天之内把 PHP 升到 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35，重启全部 worker。升不了的按 5.2 节临时缓解配置，**并把受影响的互联网暴露系统下线**。查 `/tmp`、upload_tmp_dir 有无落地文件，查日志有无 `PHP_SESSION_UPLOAD_PROGRESS` 探测。

**开发 / 产品**
> 升级 PHP 运行时；用 `composer audit` 检查依赖（Symfony、PhpSpreadsheet、Laravel TokenGuard 都有 10 月新公告）；WordPress 站点重点清理插件，升级 Prime Mover / Pie Register / Checkout Files Upload / Contact Manager / IvyForms / Rank Math / Kirki / Icegram；核查是否在运行时切换 `session.serialize_handler`。

**安全 / 运营中心**
> 拉取 CISA SIGMA 规则与 NCSC-NL `php2shell` 仓库的检测物料；部署本文 IOC（dropper URL、C2 域名与 ENS）；对蜜罐/IDS 中的 `php2shell-scan/*` User-Agent 与畸形 multipart 请求建立告警；重点审计 worker 派生 shell 的行为；确认 8.1 及更早资产清单。

**管理者 / 采购**
> 注意「PHP 不只是网站的技术栈」——757 个产品被 NCSC-NL 追踪，218 个确认易受影响，涵盖网络设备、存储设备、管理后台、工控系统等嵌入式场景，这些产品你无法直接给 PHP 打补丁，只能等厂商公告（如 Cisco ISE、Cisco Unified Industrial Wireless 目前均标记为 Vulnerable）。

---

## 八、参考链接

**官方**
- PHP 安全公告（10-21）：https://www.php.net/archive/2026.php#2026-10-21-5
- PHP 信息性公告（10-23，CVE-2026-115560）：https://www.php.net/archive/2026.php#2026-10-23-1
- The PHP Foundation 博客：https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/
- GitHub Advisory：https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w 与 https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- CVE 记录：https://www.cve.org/CVERecord?id=CVE-2026-109618 与 ?id=CVE-2026-109619
- oss-security 邮件列表：http://www.openwall.com/lists/oss-security/2026/10/21/

**政府 / 机构**
- CISA 警报（10-21，10-26 更新）：https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- CISA KEV 目录：https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NSA 公告：https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4630238/
- UK NCSC：https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php
- CERT-EU 2026-018：https://cert.europa.eu/publications/security-advisories/2026-018/
- NCSC-NL 运营情报仓库：https://github.com/NCSC-NL/php2shell
- ASD ACSC：https://www.cyber.gov.au/alert/critical-vulnerabilities-in-php
- NCSC-NZ：https://www.ncsc.govt.nz/news/ncsc-encourages-immediate-patching-against-php-vulnerability/
- 加拿大 CC：https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619

**研究与观测**
- TU Delft INTELLAB 在野观测（实时刷新）：https://php2shell.delftintellab.com/
- Arctic Wolf 分析：https://arcticwolf.com/resources/blog/php2shell-critical-php-vulnerabilities-enable-unauthenticated-remote-code-execution/
- CISA SIGMA 规则库：https://github.com/cisagov/SIGMA_Rules

**工具与 PoC（仅限授权测试）**
- Assetnote 扫描器：https://github.com/assetnote/php2shell-scanner
- OpenAI 核查工具：https://github.com/openai/php2shell-checker
- ikow PoC + 检测规则：https://github.com/ikow/php2shell-poc
- NCSC-NL 检测与缓解物料：https://github.com/NCSC-NL/php2shell/tree/main/detection_mitigation

---

## 附录：数据来源与核查说明

本报告结论均来自以下一手来源的实时抓取（2026-10-29）：
php.net（发行公告、NEWS、News Archive）、api.github.com（php-src 仓库安全公告 30 条 + Packagist 生态公告）、services.nvd.nist.gov（NVD API，含 2026-10 全月 `PHP` 关键词 278 条）、cisa.gov（KEV JSON 全量 1,762 条 + 10-21 警报）、github.com/NCSC-NL/php2shell（运营情报与软件清单）、php2shell.delftintellab.com（在野观测实时数据）、cert.europa.eu、thephp.foundation、arcticwolf.com。

> 本报告为情报整理，不构成合规建议。组织级风险评估与应急响应决策请结合自身资产情况与法律要求。
