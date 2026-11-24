# PHP2Shell 检测报告

> 生成时间：2026-10-28 23:34:21　|　工具：P2S-Guard 1.0　|　规则库：2026.10.28-1　|　画像：standard
> 授权凭据：DEMO-LOCAL-LAB

## 一、结论摘要

| 指标 | 数值 |
|---|---|
| 检测资产数 | 6 |
| 确认受影响 | **4** |
| 疑似受影响 | 0 |
| 已修复 | 1 |
| 不适用 | 0 |
| 无法判定 | 1 |
| P0 紧急 | **4** |

> **处置优先级：立即处理 P0 资产。** 官方明确：升级到 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 是唯一完整缓解手段。

## 二、资产明细

| # | 目标 | 结论 | 置信度 | 分数 | 等级 | PHP | SAPI |
|---|---|---|---|---|---|---|---|
| 1 | `http://127.0.0.1:8801` | 确认受影响 | 高度可能 | 92 | P0 | 8.4.24 | apache2handler |
| 2 | `http://127.0.0.1:8802` | 已修复 | 疑似 | 21 | P3 | 8.4.27 | apache2handler |
| 3 | `http://127.0.0.1:8803` | 确认受影响 | 高度可能 | 86 | P0 | 8.3.35 | fpm-fcgi |
| 4 | `http://127.0.0.1:8804` | 确认受影响 | 高度可能 | 92 | P0 | 8.4.26 | apache2handler |
| 5 | `http://127.0.0.1:8805` | 无法判定 | 未知 | 43 | P1 | - | unknown |
| 6 | `http://127.0.0.1:8806` | 确认受影响 | 高度可能 | 100 | P0 | 8.1.31 | apache2handler |

## 三、逐项详情

### 3.1 `http://127.0.0.1:8801`

- **结论**：确认受影响（置信度：高度可能）
- **风险分**：92 / 100　**等级**：P0
- **PHP 版本**：8.4.24　**SAPI**：apache2handler
- **判定理由**：未修复：8.4.24 < 修复版本 8.4.27（8.4 分支受影响）；且补丁核验未发现修复痕迹
- **评分分解**：版本风险 0.80×0.40 ｜ SAPI 暴露 1.00×0.25 ｜ 配置可利用 1.00×0.20 ｜ 资产暴露 1.00×0.15 ｜ 补丁因子 1.00

**证据链**

| 检测器 | 类型 | 键 | 值 | 置信度 | 采集方法 |
|---|---|---|---|---|---|
| D1 | http_header | `http.server` | `Apache/2.4.58 (Debian)` | 疑似 | 响应头 Server |
| D1 | http_header | `http.x_powered_by` | `PHP/8.4.24` | 疑似 | 响应头 X-Powered-By |
| D1 | version | `php.version` | `8.4.24` | 疑似 | 响应头 X-Powered-By（可被伪造或关闭，仅作线索） |
| D1 | http_header | `http.status` | `200` | 确认 | 主页状态码 |
| D1 | sapi | `php.sapi` | `apache2handler` | 弱线索 | Apache + X-Powered-By: PHP/8.4.24（可能是 mod_php，也可能是 proxy_fcgi） |
| D1 | file | `leak.phpinfo` | `phpinfo.php` | 确认 | 可直接访问 phpinfo.php（信息泄露） |
| D1 | version | `php.version` | `8.4.24` | 高度可能 | phpinfo 输出版本（反映 Web 实际运行时） |
| D1 | sapi | `php.sapi` | `apache2handler` | 确认 | phpinfo Server API = Apache 2.0 Handler |
| D1 | version | `php.build_date` | `Jun 12 2026 09:31:04` | 高度可能 | phpinfo Build Date |
| D1 | version | `php.configure_command` | `'./configure' '--build=x86_64-linux-gnu' '--with-apxs2'` | 高度可能 | phpinfo Configure Command（判断是否自编译） |
| D1 | ini | `ini.memory_limit` | `128M` | 高度可能 | phpinfo memory_limit |
| D1 | ini | `ini.post_max_size` | `8M` | 高度可能 | phpinfo post_max_size |
| D1 | ini | `ini.max_file_uploads` | `20` | 高度可能 | phpinfo max_file_uploads |
| D1 | ini | `ini.max_input_nesting_level` | `64` | 高度可能 | phpinfo max_input_nesting_level |
| D1 | ini | `ini.session.upload_progress.enabled` | `On` | 高度可能 | phpinfo session.upload_progress.enabled |
| D1 | ini | `ini.enable_post_data_reading` | `On` | 高度可能 | phpinfo enable_post_data_reading |
| D1 | ini | `ini.expose_php` | `On` | 高度可能 | phpinfo expose_php |
| D1 | ini | `ini.open_basedir` | `no value` | 高度可能 | phpinfo open_basedir |
| D2 | behavior | `http.multipart_accepted` | `True` | 疑似 | POST multipart 被接受（说明 PHP 会解析 multipart 请求体） |
| D2 | behavior | `ini.session.upload_progress.enabled` | `On(推断)` | 弱线索 | 上传进度探针触发 PHPSESSID 下发，推断 session.upload_progress 开启 |
| D4 | changelog | `php.patch_status` | `{'patched': False, 'verified': True, 'method': 'build_date_…` | 高度可能 | 构建日期 2026-06-12 早于补丁发布日 2026-10-21，且版本低于 8.4.27 |

**处置建议**

- 【完整修复】 升级至 8.4.27 或更高版本
  - 说明：官方明确：升级是唯一完整缓解手段
- 【临时缓解】 任何配置变更后必须重启全部 PHP worker
  - 说明：运行中的 worker 仍沿用旧配置，未重启等于未生效
- 【临时缓解】 session.upload_progress.enabled=0
  - 说明：仅切断已演示的 session 生命周期路径，不覆盖其他 producer
- 【临时缓解】 memory_limit=-1，并在 Web 服务器/代理层独立限制请求体大小
  - 说明：非完整缓解；若底层 mmap 失败仍可能回到脆弱路径
- 【临时缓解】 WAF/反向代理阻断已知攻击模式，限制 multipart part 数、part 内 header 数、请求体大小
  - 说明：可被构造变形绕过，仅作时间窗保护
- 【临时缓解】 临时下线 / 只读模式 / 收敛至运维网段或 VPN
- 【禁止】 禁止使用 RLIMIT_AS / RLIMIT_DATA 做内存限制
  - 说明：达到限制会使 mmap() 失败，重新触发脆弱 longjmp 路径，扩大攻击面

**补充说明**

- ⚠ phpinfo.php 暴露 phpinfo：这本身是严重的信息泄露问题，应尽快下线
- 推断 session.upload_progress.enabled=On（已验证的 109619 producer 之一）
- ✗ 构建日期早于补丁发布日，不可能包含该修复
- 该分支安全支持至 2028-12-31
- 探测预算：已用 8/60 次请求

### 3.2 `http://127.0.0.1:8802`

- **结论**：已修复（置信度：疑似）
- **风险分**：21 / 100　**等级**：P3
- **PHP 版本**：8.4.27　**SAPI**：apache2handler
- **判定理由**：版本 8.4.27 达到修复版本 8.4.27，但未经安装物料核验（版本号可被伪造/回移补丁也可保留旧版本号）
- **评分分解**：版本风险 0.00×0.40 ｜ SAPI 暴露 1.00×0.25 ｜ 配置可利用 1.00×0.20 ｜ 资产暴露 1.00×0.15 ｜ 补丁因子 0.35

**证据链**

| 检测器 | 类型 | 键 | 值 | 置信度 | 采集方法 |
|---|---|---|---|---|---|
| D1 | http_header | `http.server` | `Apache/2.4.58 (Debian)` | 疑似 | 响应头 Server |
| D1 | http_header | `http.x_powered_by` | `PHP/8.4.27` | 疑似 | 响应头 X-Powered-By |
| D1 | version | `php.version` | `8.4.27` | 疑似 | 响应头 X-Powered-By（可被伪造或关闭，仅作线索） |
| D1 | http_header | `http.status` | `200` | 确认 | 主页状态码 |
| D1 | sapi | `php.sapi` | `apache2handler` | 弱线索 | Apache + X-Powered-By: PHP/8.4.27（可能是 mod_php，也可能是 proxy_fcgi） |
| D1 | file | `leak.phpinfo` | `phpinfo.php` | 确认 | 可直接访问 phpinfo.php（信息泄露） |
| D1 | version | `php.version` | `8.4.27` | 高度可能 | phpinfo 输出版本（反映 Web 实际运行时） |
| D1 | sapi | `php.sapi` | `apache2handler` | 确认 | phpinfo Server API = Apache 2.0 Handler |
| D1 | version | `php.build_date` | `Oct 21 2026 10:11:12` | 高度可能 | phpinfo Build Date |
| D1 | version | `php.configure_command` | `'./configure' '--build=x86_64-linux-gnu' '--with-apxs2'` | 高度可能 | phpinfo Configure Command（判断是否自编译） |
| D1 | ini | `ini.memory_limit` | `128M` | 高度可能 | phpinfo memory_limit |
| D1 | ini | `ini.post_max_size` | `8M` | 高度可能 | phpinfo post_max_size |
| D1 | ini | `ini.max_file_uploads` | `20` | 高度可能 | phpinfo max_file_uploads |
| D1 | ini | `ini.max_input_nesting_level` | `64` | 高度可能 | phpinfo max_input_nesting_level |
| D1 | ini | `ini.session.upload_progress.enabled` | `On` | 高度可能 | phpinfo session.upload_progress.enabled |
| D1 | ini | `ini.enable_post_data_reading` | `On` | 高度可能 | phpinfo enable_post_data_reading |
| D1 | ini | `ini.expose_php` | `On` | 高度可能 | phpinfo expose_php |
| D1 | ini | `ini.open_basedir` | `no value` | 高度可能 | phpinfo open_basedir |
| D2 | behavior | `http.multipart_accepted` | `True` | 疑似 | POST multipart 被接受（说明 PHP 会解析 multipart 请求体） |
| D2 | behavior | `ini.session.upload_progress.enabled` | `On(推断)` | 弱线索 | 上传进度探针触发 PHPSESSID 下发，推断 session.upload_progress 开启 |
| D4 | behavior | `php.patch_status` | `{'patched': None, 'verified': False, 'method': 'version_onl…` | 弱线索 | 版本 8.4.27 达到 8.4.27，但无安装物料证据，无法排除版本字符串被改写或自编译未打补丁 |

**处置建议**

- 【完整修复】 保持监测：日志回溯至 2026-10-17，排查是否在修复前已被利用
  - 说明：补丁只能关门，回答不了「谁进来过」
- 【禁止】 禁止使用 RLIMIT_AS / RLIMIT_DATA 做内存限制
  - 说明：达到限制会使 mmap() 失败，重新触发脆弱 longjmp 路径，扩大攻击面

**补充说明**

- ⚠ phpinfo.php 暴露 phpinfo：这本身是严重的信息泄露问题，应尽快下线
- 推断 session.upload_progress.enabled=On（已验证的 109619 producer 之一）
- 补丁状态未经安装物料核验：版本达标 ≠ 已修复。如需确认，请提供主机凭证（--host）以便读取包 changelog 或二进制指纹
- 该分支安全支持至 2028-12-31
- 探测预算：已用 8/60 次请求

### 3.3 `http://127.0.0.1:8803`

- **结论**：确认受影响（置信度：高度可能）
- **风险分**：86 / 100　**等级**：P0
- **PHP 版本**：8.3.35　**SAPI**：fpm-fcgi
- **判定理由**：未修复：8.3.35 < 修复版本 8.3.36（8.3 分支受影响）；且补丁核验未发现修复痕迹
- **评分分解**：版本风险 0.80×0.40 ｜ SAPI 暴露 0.75×0.25 ｜ 配置可利用 1.00×0.20 ｜ 资产暴露 1.00×0.15 ｜ 补丁因子 1.00

**证据链**

| 检测器 | 类型 | 键 | 值 | 置信度 | 采集方法 |
|---|---|---|---|---|---|
| D1 | http_header | `http.server` | `nginx/1.24.0` | 疑似 | 响应头 Server |
| D1 | http_header | `http.status` | `200` | 确认 | 主页状态码 |
| D1 | sapi | `php.sapi` | `fpm-fcgi` | 弱线索 | nginx 无 PHP 头，最常见为 PHP-FPM |
| D1 | file | `leak.phpinfo` | `info.php` | 确认 | 可直接访问 info.php（信息泄露） |
| D1 | version | `php.version` | `8.3.35` | 高度可能 | phpinfo 输出版本（反映 Web 实际运行时） |
| D1 | sapi | `php.sapi` | `fpm-fcgi` | 确认 | phpinfo Server API = FPM/FastCGI |
| D1 | version | `php.build_date` | `Jun 12 2026 09:31:04` | 高度可能 | phpinfo Build Date |
| D1 | version | `php.configure_command` | `'./configure' '--build=x86_64-linux-gnu' '--with-apxs2'` | 高度可能 | phpinfo Configure Command（判断是否自编译） |
| D1 | ini | `ini.memory_limit` | `256M` | 高度可能 | phpinfo memory_limit |
| D1 | ini | `ini.post_max_size` | `64M` | 高度可能 | phpinfo post_max_size |
| D1 | ini | `ini.max_file_uploads` | `20` | 高度可能 | phpinfo max_file_uploads |
| D1 | ini | `ini.max_input_nesting_level` | `64` | 高度可能 | phpinfo max_input_nesting_level |
| D1 | ini | `ini.session.upload_progress.enabled` | `On` | 高度可能 | phpinfo session.upload_progress.enabled |
| D1 | ini | `ini.enable_post_data_reading` | `On` | 高度可能 | phpinfo enable_post_data_reading |
| D1 | ini | `ini.expose_php` | `Off` | 高度可能 | phpinfo expose_php |
| D1 | ini | `ini.open_basedir` | `no value` | 高度可能 | phpinfo open_basedir |
| D1 | file | `app.composer_json` | `composer.json` | 疑似 | composer.json 可读（可能泄露依赖与版本） |
| D2 | behavior | `http.multipart_accepted` | `True` | 疑似 | POST multipart 被接受（说明 PHP 会解析 multipart 请求体） |
| D2 | behavior | `ini.session.upload_progress.enabled` | `On(推断)` | 弱线索 | 上传进度探针触发 PHPSESSID 下发，推断 session.upload_progress 开启 |
| D4 | changelog | `php.patch_status` | `{'patched': False, 'verified': True, 'method': 'build_date_…` | 高度可能 | 构建日期 2026-06-12 早于补丁发布日 2026-10-21，且版本低于 8.3.36 |

**处置建议**

- 【完整修复】 升级至 8.3.36 或更高版本
  - 说明：官方明确：升级是唯一完整缓解手段
- 【临时缓解】 任何配置变更后必须重启全部 PHP worker
  - 说明：运行中的 worker 仍沿用旧配置，未重启等于未生效
- 【临时缓解】 session.upload_progress.enabled=0
  - 说明：仅切断已演示的 session 生命周期路径，不覆盖其他 producer
- 【临时缓解】 memory_limit=-1，并在 Web 服务器/代理层独立限制请求体大小
  - 说明：非完整缓解；若底层 mmap 失败仍可能回到脆弱路径
- 【临时缓解】 pm.max_requests=1
  - 说明：打破跨请求复用条件，代价是每请求一次进程启动开销
- 【临时缓解】 WAF/反向代理阻断已知攻击模式，限制 multipart part 数、part 内 header 数、请求体大小
  - 说明：可被构造变形绕过，仅作时间窗保护
- 【临时缓解】 临时下线 / 只读模式 / 收敛至运维网段或 VPN
- 【禁止】 禁止使用 RLIMIT_AS / RLIMIT_DATA 做内存限制
  - 说明：达到限制会使 mmap() 失败，重新触发脆弱 longjmp 路径，扩大攻击面

**补充说明**

- ⚠ info.php 暴露 phpinfo：这本身是严重的信息泄露问题，应尽快下线
- ⚠ composer.json 可访问，建议限制访问权限
- 推断 session.upload_progress.enabled=On（已验证的 109619 producer 之一）
- ✗ 构建日期早于补丁发布日，不可能包含该修复
- 该分支安全支持至 2027-12-31
- 探测预算：已用 9/60 次请求

### 3.4 `http://127.0.0.1:8804`

- **结论**：确认受影响（置信度：高度可能）
- **风险分**：92 / 100　**等级**：P0
- **PHP 版本**：8.4.26　**SAPI**：apache2handler
- **判定理由**：未修复：8.4.26 < 修复版本 8.4.27（8.4 分支受影响）；且补丁核验未发现修复痕迹
- **评分分解**：版本风险 0.80×0.40 ｜ SAPI 暴露 1.00×0.25 ｜ 配置可利用 1.00×0.20 ｜ 资产暴露 1.00×0.15 ｜ 补丁因子 1.00

**证据链**

| 检测器 | 类型 | 键 | 值 | 置信度 | 采集方法 |
|---|---|---|---|---|---|
| D1 | http_header | `http.server` | `Apache/2.4.58 (Ubuntu)` | 疑似 | 响应头 Server |
| D1 | http_header | `http.x_powered_by` | `PHP/8.4.27` | 疑似 | 响应头 X-Powered-By |
| D1 | version | `php.version` | `8.4.27` | 疑似 | 响应头 X-Powered-By（可被伪造或关闭，仅作线索） |
| D1 | http_header | `http.status` | `200` | 确认 | 主页状态码 |
| D1 | sapi | `php.sapi` | `apache2handler` | 弱线索 | Apache + X-Powered-By: PHP/8.4.27（可能是 mod_php，也可能是 proxy_fcgi） |
| D1 | file | `leak.phpinfo` | `phpinfo.php` | 确认 | 可直接访问 phpinfo.php（信息泄露） |
| D1 | version | `php.version` | `8.4.26` | 高度可能 | phpinfo 输出版本（反映 Web 实际运行时） |
| D1 | sapi | `php.sapi` | `apache2handler` | 确认 | phpinfo Server API = Apache 2.0 Handler |
| D1 | version | `php.build_date` | `Aug 02 2026 14:20:11` | 高度可能 | phpinfo Build Date |
| D1 | version | `php.configure_command` | `'./configure' '--build=x86_64-linux-gnu' '--with-apxs2'` | 高度可能 | phpinfo Configure Command（判断是否自编译） |
| D1 | ini | `ini.memory_limit` | `128M` | 高度可能 | phpinfo memory_limit |
| D1 | ini | `ini.post_max_size` | `8M` | 高度可能 | phpinfo post_max_size |
| D1 | ini | `ini.max_file_uploads` | `20` | 高度可能 | phpinfo max_file_uploads |
| D1 | ini | `ini.max_input_nesting_level` | `64` | 高度可能 | phpinfo max_input_nesting_level |
| D1 | ini | `ini.session.upload_progress.enabled` | `On` | 高度可能 | phpinfo session.upload_progress.enabled |
| D1 | ini | `ini.enable_post_data_reading` | `On` | 高度可能 | phpinfo enable_post_data_reading |
| D1 | ini | `ini.expose_php` | `On` | 高度可能 | phpinfo expose_php |
| D1 | ini | `ini.open_basedir` | `no value` | 高度可能 | phpinfo open_basedir |
| D2 | behavior | `http.multipart_accepted` | `True` | 疑似 | POST multipart 被接受（说明 PHP 会解析 multipart 请求体） |
| D2 | behavior | `ini.session.upload_progress.enabled` | `On(推断)` | 弱线索 | 上传进度探针触发 PHPSESSID 下发，推断 session.upload_progress 开启 |
| D4 | behavior | `consistency.version_conflict` | `{'8.4.27': 'version_remote', '8.4.26': 'version_local'}` | 高度可能 | 不同来源报告的 PHP 版本不一致（可能为头伪造、缓存污染或多版本共存） |
| D4 | changelog | `php.patch_status` | `{'patched': False, 'verified': True, 'method': 'build_date_…` | 高度可能 | 构建日期 2026-08-02 早于补丁发布日 2026-10-21，且版本低于 8.4.27 |

**处置建议**

- 【完整修复】 升级至 8.4.27 或更高版本
  - 说明：官方明确：升级是唯一完整缓解手段
- 【临时缓解】 任何配置变更后必须重启全部 PHP worker
  - 说明：运行中的 worker 仍沿用旧配置，未重启等于未生效
- 【临时缓解】 session.upload_progress.enabled=0
  - 说明：仅切断已演示的 session 生命周期路径，不覆盖其他 producer
- 【临时缓解】 memory_limit=-1，并在 Web 服务器/代理层独立限制请求体大小
  - 说明：非完整缓解；若底层 mmap 失败仍可能回到脆弱路径
- 【临时缓解】 WAF/反向代理阻断已知攻击模式，限制 multipart part 数、part 内 header 数、请求体大小
  - 说明：可被构造变形绕过，仅作时间窗保护
- 【临时缓解】 临时下线 / 只读模式 / 收敛至运维网段或 VPN
- 【禁止】 禁止使用 RLIMIT_AS / RLIMIT_DATA 做内存限制
  - 说明：达到限制会使 mmap() 失败，重新触发脆弱 longjmp 路径，扩大攻击面

**补充说明**

- ⚠ phpinfo.php 暴露 phpinfo：这本身是严重的信息泄露问题，应尽快下线
- 推断 session.upload_progress.enabled=On（已验证的 109619 producer 之一）
- ⚠ 版本来源冲突：8.4.27(version_remote)、8.4.26(version_local) — 以 phpinfo/主机事实为准，HTTP 头可信度下调
- ✗ 构建日期早于补丁发布日，不可能包含该修复
- 该分支安全支持至 2028-12-31
- 探测预算：已用 8/60 次请求

### 3.5 `http://127.0.0.1:8805`

- **结论**：无法判定（置信度：未知）
- **风险分**：43 / 100　**等级**：P1
- **PHP 版本**：未知　**SAPI**：unknown
- **判定理由**：证据不足：既无版本信息，也无法确认 SAPI 与 multipart 可达性
- **评分分解**：版本风险 0.30×0.40 ｜ SAPI 暴露 0.60×0.25 ｜ 配置可利用 0.60×0.20 ｜ 资产暴露 1.00×0.15 ｜ 补丁因子 0.80

**证据链**

| 检测器 | 类型 | 键 | 值 | 置信度 | 采集方法 |
|---|---|---|---|---|---|
| D1 | http_header | `http.server` | `cloudflare` | 疑似 | 响应头 Server |
| D1 | http_header | `http.status` | `403` | 确认 | 主页状态码 |
| D1 | sapi | `php.sapi` | `unknown` | 未知 | 无足够信息判定 SAPI |
| D1 | http_header | `net.waf` | `Cloudflare` | 疑似 | 响应头/拦截页特征 |
| D2 | behavior | `http.multipart_accepted` | `blocked` | 弱线索 | multipart POST 被前置防护拦截（403） |
| D4 | behavior | `php.patch_status` | `{'patched': None, 'verified': False, 'method': 'no_data'}` | 未知 | 无任何版本或补丁线索，无法核验 |

**处置建议**

- 【临时缓解】 补采证据：提供主机 SSH 凭证，或检查 phpinfo / 包 changelog
  - 说明：当前证据不足，无法判定。禁止按「无风险」处理
- 【临时缓解】 WAF/反向代理阻断已知攻击模式，限制 multipart part 数、part 内 header 数、请求体大小
  - 说明：可被构造变形绕过，仅作时间窗保护
- 【禁止】 禁止使用 RLIMIT_AS / RLIMIT_DATA 做内存限制
  - 说明：达到限制会使 mmap() 失败，重新触发脆弱 longjmp 路径，扩大攻击面

**补充说明**

- 检测到前置防护设备：Cloudflare（WAF 只能拦截已知模式，不能替代补丁）
- POST 被 WAF 拦截，主动探测能力受限，结论主要依赖 D3/D4
- 无可用版本线索，补丁状态无法判定（UNKNOWN，不等于安全）
- 等级已上调至 P1：无法判定 ≠ 无风险，必须在 24 小时内补采证据
- SAPI 为远程推断（unknown），建议通过主机核查或 phpinfo 确认
- 探测预算：已用 15/60 次请求

### 3.6 `http://127.0.0.1:8806`

- **结论**：确认受影响（置信度：高度可能）
- **风险分**：100 / 100　**等级**：P0
- **PHP 版本**：8.1.31　**SAPI**：apache2handler
- **判定理由**：未修复：8.1 分支已停止支持（可追溯至 PHP 5.4），官方无修复版本，装到该分支最新版 8.1.31 仍受影响
- **评分分解**：版本风险 1.00×0.40 ｜ SAPI 暴露 1.00×0.25 ｜ 配置可利用 1.00×0.20 ｜ 资产暴露 1.00×0.15 ｜ 补丁因子 1.00

**证据链**

| 检测器 | 类型 | 键 | 值 | 置信度 | 采集方法 |
|---|---|---|---|---|---|
| D1 | http_header | `http.server` | `Apache/2.4.57 (Debian)` | 疑似 | 响应头 Server |
| D1 | http_header | `http.x_powered_by` | `PHP/8.1.31` | 疑似 | 响应头 X-Powered-By |
| D1 | version | `php.version` | `8.1.31` | 疑似 | 响应头 X-Powered-By（可被伪造或关闭，仅作线索） |
| D1 | http_header | `http.status` | `200` | 确认 | 主页状态码 |
| D1 | sapi | `php.sapi` | `apache2handler` | 弱线索 | Apache + X-Powered-By: PHP/8.1.31（可能是 mod_php，也可能是 proxy_fcgi） |
| D1 | file | `leak.phpinfo` | `phpinfo.php` | 确认 | 可直接访问 phpinfo.php（信息泄露） |
| D1 | version | `php.version` | `8.1.31` | 高度可能 | phpinfo 输出版本（反映 Web 实际运行时） |
| D1 | sapi | `php.sapi` | `apache2handler` | 确认 | phpinfo Server API = Apache 2.0 Handler |
| D1 | version | `php.build_date` | `Mar 14 2026 08:02:33` | 高度可能 | phpinfo Build Date |
| D1 | version | `php.configure_command` | `'./configure' '--build=x86_64-linux-gnu' '--with-apxs2'` | 高度可能 | phpinfo Configure Command（判断是否自编译） |
| D1 | ini | `ini.memory_limit` | `128M` | 高度可能 | phpinfo memory_limit |
| D1 | ini | `ini.post_max_size` | `8M` | 高度可能 | phpinfo post_max_size |
| D1 | ini | `ini.max_file_uploads` | `20` | 高度可能 | phpinfo max_file_uploads |
| D1 | ini | `ini.max_input_nesting_level` | `64` | 高度可能 | phpinfo max_input_nesting_level |
| D1 | ini | `ini.session.upload_progress.enabled` | `On` | 高度可能 | phpinfo session.upload_progress.enabled |
| D1 | ini | `ini.enable_post_data_reading` | `On` | 高度可能 | phpinfo enable_post_data_reading |
| D1 | ini | `ini.expose_php` | `On` | 高度可能 | phpinfo expose_php |
| D1 | ini | `ini.open_basedir` | `no value` | 高度可能 | phpinfo open_basedir |
| D2 | behavior | `http.multipart_accepted` | `True` | 疑似 | POST multipart 被接受（说明 PHP 会解析 multipart 请求体） |
| D2 | behavior | `ini.session.upload_progress.enabled` | `On(推断)` | 弱线索 | 上传进度探针触发 PHPSESSID 下发，推断 session.upload_progress 开启 |
| D4 | behavior | `php.patch_status` | `{'patched': False, 'verified': True, 'method': 'version_ran…` | 高度可能 | 版本 8.1.31 低于修复版 None，且无补丁证据 |

**处置建议**

- 【完整修复】 该分支无官方修复，必须迁移至受支持分支（建议 8.4.x / 8.5.x）
- 【临时缓解】 任何配置变更后必须重启全部 PHP worker
  - 说明：运行中的 worker 仍沿用旧配置，未重启等于未生效
- 【临时缓解】 session.upload_progress.enabled=0
  - 说明：仅切断已演示的 session 生命周期路径，不覆盖其他 producer
- 【临时缓解】 memory_limit=-1，并在 Web 服务器/代理层独立限制请求体大小
  - 说明：非完整缓解；若底层 mmap 失败仍可能回到脆弱路径
- 【临时缓解】 WAF/反向代理阻断已知攻击模式，限制 multipart part 数、part 内 header 数、请求体大小
  - 说明：可被构造变形绕过，仅作时间窗保护
- 【临时缓解】 临时下线 / 只读模式 / 收敛至运维网段或 VPN
- 【禁止】 禁止使用 RLIMIT_AS / RLIMIT_DATA 做内存限制
  - 说明：达到限制会使 mmap() 失败，重新触发脆弱 longjmp 路径，扩大攻击面

**补充说明**

- ⚠ phpinfo.php 暴露 phpinfo：这本身是严重的信息泄露问题，应尽快下线
- 推断 session.upload_progress.enabled=On（已验证的 109619 producer 之一）
- ✗ 版本位于受影响区间且无任何补丁证据，判定未修复（构建日期佐证）
- EOL 分支无官方修复，升级路径应为「迁移」而非「打补丁」
- 探测预算：已用 8/60 次请求

## 四、失陷排查

- 解析文件：3 个，日志行 21，成功解析 21
- 时间范围：2026-10-20 03:10 ~ 2026-10-20 03:26
- 综合判定：**suspicious**

| 时间 | 规则 | 说明 | 来源 |
|---|---|---|---|
| 2026-10-20 03:12:01 | HUNT-004 | 请求中出现 PHP_SESSION_UPLOAD_PROGRESS，若非业务正常调用则高度可疑 | access.log:2 |
| 2026-10-20 03:14:22 | HUNT-001 | 3 次启动期 OOM（Allowed memory size ... in Unknown on line 0）集中在 10 分钟内，符合… | php_error.log:1 |
| 2026-10-20 03:14:22 | HUNT-002 | 启动期 OOM 前后 60s 内出现 3500032 字节 POST，请求体大小与 OOM 触发条件吻合 | access.log:4 |
| 2026-10-20 03:14:25 | HUNT-003 | Apache/FPM 子进程以 SIGSEGV 退出，可能是利用失败（地址猜测错误）的痕迹 | error.log:1 |
| 2026-10-20 03:15:02 | HUNT-009 | Web 可写目录下出现 PHP 文件被访问，典型 webshell 落地特征 | access.log:8 |
| 2026-10-20 03:15:09 | HUNT-009 | Web 可写目录下出现 PHP 文件被访问，典型 webshell 落地特征 | access.log:9 |
| 2026-10-20 03:15:09 | HUNT-010 | 错误/审计日志中出现 shell 或下载工具调用痕迹 | error.log:2 |
| 2026-10-20 03:26:40 | HUNT-002 | 启动期 OOM 前后 60s 内出现 3500032 字节 POST，请求体大小与 OOM 触发条件吻合 | access.log:11 |

- ⚠ 日志起点 2026-10-20 晚于在野利用起点 2026-10-17，10-17 至该日期的活动无法覆盖
- 命中 6 类规则（HUNT-001,HUNT-002,HUNT-003,HUNT-004,HUNT-009,HUNT-010），按「疑似失陷」处置

---

本报告由 P2S-Guard 自动生成，所有结论均附带采集证据，可追溯至原始命令输出或日志行。工具不包含漏洞利用代码，「确认受影响」表示满足可利用前置条件，不代表已验证代码执行。
