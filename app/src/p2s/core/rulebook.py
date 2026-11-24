"""配置加固规则库（PHP / FPM / Web 服务器 / systemd）。

设计原则（比数量更重要）：
1. **每条规则都要能核对**：默认值写清楚，副作用写清楚，验证方法可执行；
2. **能自动执行的才标 auto**：只允许"改 ini 键值"这一类，改 nginx/systemd 的一律人工；
3. **不猜**：默认值不确定就写"依发行版模板"，不编造。

字段说明：
    id          规则编号（分类前缀 + 三位序号）
    category    分类
    target      ini | fpm_pool | nginx | apache | systemd
    key         配置项名（ini 用指令名，pool 用 php_admin_value[key] 的内层键）
    default     默认值（字符串；None 表示无默认/不存在）
    recommended 建议值
    risk        critical | high | medium | low
    auto        是否可由加固包自动写入
    why         为什么改（攻击面/合规依据）
    effects     副作用与兼容性影响
    verify      怎么验证
    restore     怎么恢复
"""
from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    target: str
    key: str
    default: str | None
    recommended: str
    risk: str
    auto: bool
    why: str
    effects: str
    verify: str
    restore: str

    def to_dict(self) -> dict:
        return asdict(self)


# ======================================================================
# A. php2shell 直接相关（会话层）
# ======================================================================
SESSION: tuple[Rule, ...] = (
    Rule("SESS-001", "会话安全", "ini", "session.upload_progress.enabled", "1", "0", "critical", True,
         "上传进度特性是 php2shell 攻击链 E 的生产者：只要任意脚本调用 session_start()，"
         "攻击者上传一个带 PHP_SESSION_UPLOAD_PROGRESS 的 multipart 请求，就会在 session 文件中"
         "留下受控内容，被消费端读取后触发利用。关闭后整条链失效。",
         "使用上传进度条的站点会失去进度显示；WordPress/Discuz 等主流程序本身不依赖该特性。",
         "php -i | grep session.upload_progress.enabled  应输出 0（FPM 需重启后生效）",
         "改回 1 并重启 PHP-FPM"),
    Rule("SESS-002", "会话安全", "ini", "session.use_strict_mode", "0", "1", "high", True,
         "默认关闭时，服务端会接受客户端自选的、未初始化的会话 ID，攻击者可以先埋一个已知 ID "
         "再诱导受害者在同一 ID 上登录（会话固定），是链 A 的前置条件之一。",
         "极少数依赖\"预置 session id\"的老代码可能失效（正确做法本就禁止）。",
         "php -i | grep session.use_strict_mode  应为 1；用未初始化 ID 发请求应得到新 ID",
         "改回 0 并重启"),
    Rule("SESS-003", "会话安全", "ini", "session.use_only_cookies", "1", "1", "high", True,
         "禁止通过 URL 查询参数或表单字段传递会话 ID，避免把 PHPSESSID 当普通参数提交后被日志、"
         "Referer 或下游应用记录，从而被用于会话固定。",
         "依赖 URL 传 session id 的老站点（如部分老论坛）会掉登录态，需改用 cookie。",
         "php -i | grep session.use_only_cookies 应为 1；URL 带 ?PHPSESSID= 应被忽略",
         "改回 1 并重启"),
    Rule("SESS-004", "会话安全", "ini", "session.use_trans_sid", "0", "0", "medium", True,
         "开启后 PHP 会自动在 URL 里续写会话 ID，等价于把会话凭据暴露在地址栏、日志与 Referer 中。",
         "无（纯增强项）。",
         "php -i | grep session.use_trans_sid 应为 0",
         "改回 0"),
    Rule("SESS-005", "会话安全", "ini", "session.cookie_httponly", None, "1", "medium", True,
         "会话 Cookie 不可被 JavaScript 读取，降低 XSS 直接窃取会话的风险。",
         "前端若用 JS 读 document.cookie 拿 PHPSESSID（本身就不该这么做）会失效。",
         "响应头 Set-Cookie 应带 HttpOnly",
         "改回默认（空/0）"),
    Rule("SESS-006", "会话安全", "ini", "session.cookie_samesite", None, "Lax", "medium", True,
         "限制跨站请求携带会话 Cookie，降低 CSRF 与会话固定组合利用的成功率。",
         "依赖跨站 POST 回跳的老流程（如第三方支付回调页面）可能受影响，需按业务评估。",
         "响应头 Set-Cookie 应带 SameSite=Lax",
         "改回默认（空）"),
    Rule("SESS-007", "会话安全", "ini", "session.cookie_secure", None, "1", "medium", False,
         "仅在 HTTPS 下发送会话 Cookie，避免明文链路被嗅探。**纯 HTTP 站点不要开**，会导致无法登录。",
         "站点未启用 HTTPS 时开启将导致会话无法建立。",
         "curl -sI https://站点/ | grep -i set-cookie 应带 Secure",
         "改回默认（空）"),
    Rule("SESS-008", "会话安全", "ini", "session.sid_length", "32", "48", "low", True,
         "加长会话 ID，提高暴力枚举成本。",
         "几乎无影响；极老的前端若假设 ID 长度为 32 可能截断显示。",
         "php -i | grep session.sid_length 应为 48",
         "改回 32"),
    Rule("SESS-009", "会话安全", "ini", "session.gc_maxlifetime", "1440", "1440", "low", False,
         "会话存活时间。过长会扩大被窃取会话的可用窗口；过短影响体验。默认值通常即可。",
         "调短会导致用户频繁掉线。",
         "php -i | grep session.gc_maxlifetime",
         "改回原值"),
)

# ======================================================================
# B. 信息暴露
# ======================================================================
EXPOSURE: tuple[Rule, ...] = (
    Rule("INFO-001", "信息暴露", "ini", "expose_php", "1", "0", "medium", True,
         "移除响应头里的 X-Powered-By: PHP/x.y.z。版本号是最省事的指纹，"
         "攻击者据此直接匹配已知漏洞与利用链，不需要探测。",
         "极少数依赖该头做兼容判断的客户端可能受影响；我们自己的检测也会失去一个证据源。",
         "curl -sI http://站点/ | grep -i x-powered-by 应无输出",
         "改回 1 并重启"),
    Rule("INFO-002", "信息暴露", "ini", "display_errors", "1", "0", "high", True,
         "错误信息会带出绝对路径、SQL、配置片段与调用栈，是信息泄露的首要来源。",
         "排障时看不到报错，需改用 error_log 落盘查看。",
         "php -i | grep 'display_errors' 应为 Off",
         "改回 On（仅限临时排障）"),
    Rule("INFO-003", "信息暴露", "ini", "display_startup_errors", "1", "0", "medium", True,
         "启动期错误同样会输出到页面，包含加载的扩展路径等信息。",
         "无（错误仍写入 error_log）。",
         "php -i | grep display_startup_errors 应为 Off",
         "改回 On"),
    Rule("INFO-004", "信息暴露", "ini", "html_errors", "1", "0", "low", True,
         "关闭 HTML 化的错误输出，避免错误页里出现可点击的源码/函数文档链接。",
         "无。",
         "php -i | grep html_errors 应为 Off",
         "改回 On"),
    Rule("INFO-005", "信息暴露", "nginx", "server_tokens", "on", "off", "low", False,
         "隐藏 nginx 版本号，减少按版本匹配已知漏洞的便利。",
         "无功能影响。",
         "curl -sI http://站点/ | grep -i '^server:' 应只剩 nginx 无版本号",
         "改回 on 并 nginx -s reload"),
    Rule("INFO-006", "信息暴露", "apache", "ServerTokens", "Full", "Prod", "low", False,
         "Apache 默认在响应头和服务页暴露完整版本与模块列表。",
         "无功能影响。",
         "curl -sI http://站点/ | grep -i '^server:'",
         "改回 Full 并重启 apache"),
)

# ======================================================================
# C. 高危特性与函数
# ======================================================================
DANGEROUS: tuple[Rule, ...] = (
    Rule("DANG-001", "高危特性", "ini", "allow_url_include", "0", "0", "critical", True,
         "允许 include/require 从 URL 加载代码，是经典 RFI 的直接入口。即便已为 0，"
         "也应确认为显式关闭（部分老模板为 On）。",
         "无（现代代码不使用该特性）。",
         "php -i | grep allow_url_include 应为 Off",
         "改回 On 仅限确实依赖的场景"),
    Rule("DANG-002", "高危特性", "ini", "allow_url_fopen", "1", "0", "medium", False,
         "允许把 URL 当文件打开，常被用于 SSRF 与远程取 payload。关闭影响面较大，需评估。",
         "依赖 file_get_contents('http://...') 的代码、部分 SDK、composer 会失效。",
         "php -i | grep allow_url_fopen",
         "改回 On"),
    Rule("DANG-003", "高危特性", "ini", "enable_dl", "1", "0", "high", True,
         "允许运行时 dl() 加载任意扩展。除 CLI 外几乎无用，却可被用于加载恶意 .so。",
         "无（现代部署不使用 dl）。",
         "php -i | grep enable_dl 应为 Off",
         "改回 On"),
    Rule("DANG-004", "高危特性", "ini", "open_basedir", None, "/var/www:/tmp", "high", False,
         "限制 PHP 只能访问指定目录，可显著削弱 LFI 与横向读取。**必须按站点实际路径配置**，"
         "填错会导致整站 500。",
         "任何落在目录之外的包含、缓存、上传、临时文件都会失败；CLI 与 FPM 需分别配置。",
         "php -i | grep open_basedir；访问站点确认无 500",
         "注释掉该行并重启"),
    Rule("DANG-005", "高危特性", "ini", "disable_functions", None,
         "exec,passthru,shell_exec,system,proc_open,popen,curl_multi_exec,putenv", "medium", False,
         "禁用命令执行类函数，抬高拿到 shell 之后的门槛。注意 disable_functions 只拦函数调用，"
         "**不拦已加载扩展的能力**，也拦不住 LD_PRELOAD 类手法。",
         "依赖这些函数的插件（备份、图像处理、composer 脚本）会直接报错；需按业务逐项放开。",
         "php -r 'var_dump(function_exists(\"exec\"));' 应为 false（或调用时报 disabled）",
         "恢复原值并重启"),
    Rule("DANG-006", "高危特性", "ini", "session.upload_progress.cleanup", "1", "1", "low", True,
         "开启时上传完成即清理进度信息。保持开启可缩短受控内容在 session 文件中的存活时间。",
         "无。",
         "php -i | grep upload_progress.cleanup 应为 On",
         "改回 On"),
    Rule("DANG-007", "高危特性", "ini", "zend.exception_ignore_args", "0", "1", "low", True,
         "异常堆栈不再包含函数实参，避免日志/页面泄露口令、令牌、SQL 片段。",
         "排障时看不到实参，需要时临时关闭。",
         "php -i | grep zend.exception_ignore_args 应为 On",
         "改回 Off"),
    Rule("DANG-008", "高危特性", "ini", "fatal_error_backtraces", "1", "0", "high", False,
         "PHP 8.5 新增：致命错误回溯。已确认与 php2shell 相关的 RCE 链路生产者之一，"
         "**仅 PHP >= 8.5 存在该项**，低版本设置会被忽略。",
         "排障时拿不到致命错误回溯，需靠 error_log。",
         "php -i | grep fatal_error_backtraces（8.5+ 才有输出）",
         "改回 1"),
)

# ======================================================================
# D. 资源与 OOM 面（php2shell 的 OOM 路径）
# ======================================================================
RESOURCE: tuple[Rule, ...] = (
    Rule("RES-001", "资源限制", "ini", "memory_limit", "128M", "128M", "high", False,
         "内存上限。php2shell 的 OOM 路径依赖把 worker 打到内存耗尽，"
         "**设为 -1（无限制）会让 OOM 更快、更彻底**；D 链（stale EG）正依赖这一点。"
         "不要把 -1 当成\"性能优化\"。",
         "调得过低会让图像处理、导入导出类业务直接 OOM；建议不低于 128M。",
         "php -i | grep memory_limit",
         "改回原值"),
    Rule("RES-002", "资源限制", "ini", "post_max_size", "8M", "8M", "medium", False,
         "POST 体上限。与 upload_max_filesize 一起决定单个请求能吃多少内存，收紧可降低 OOM 攻击收益。",
         "小于业务真实上传需求会导致上传失败（返回空 $_POST）。",
         "php -i | grep post_max_size",
         "改回原值"),
    Rule("RES-003", "资源限制", "ini", "upload_max_filesize", "2M", "2M", "low", False,
         "单文件上传上限，需 <= post_max_size。",
         "小于业务需求会导致上传失败。",
         "php -i | grep upload_max_filesize",
         "改回原值"),
    Rule("RES-004", "资源限制", "ini", "max_file_uploads", "20", "20", "medium", False,
         "单请求允许的文件数。php2shell 的上传链常一次塞多个文件，收紧可降低成功率。",
         "批量上传类业务可能失败。",
         "php -i | grep max_file_uploads",
         "改回原值"),
    Rule("RES-005", "资源限制", "ini", "max_execution_time", "30", "30", "medium", False,
         "脚本最长执行时间（秒）。调小可缩短 OOM 攻击窗口，但会砍掉长任务。",
         "导出、报表、同步类脚本可能被中断；CLI 不受此项限制。",
         "php -i | grep max_execution_time",
         "改回原值"),
    Rule("RES-006", "资源限制", "ini", "max_input_vars", "1000", "1000", "low", False,
         "单个请求的输入变量数上限，防止哈希碰撞/参数爆炸拖垮 worker。",
         "超大表单（批量编辑）可能丢字段。",
         "php -i | grep max_input_vars",
         "改回原值"),
    Rule("RES-007", "资源限制", "ini", "max_input_nesting_level", "64", "64", "low", False,
         "输入数组嵌套层数上限，防止深层嵌套导致的解析开销与栈压力。",
         "极少数深层 JSON/form 结构会失败。",
         "php -i | grep max_input_nesting_level",
         "改回原值"),
)

# ======================================================================
# E. 日志与错误处理
# ======================================================================
LOGGING: tuple[Rule, ...] = (
    Rule("LOG-001", "日志", "ini", "log_errors", "0", "1", "medium", True,
         "把错误写入日志而不是页面。关闭 display_errors 后必须打开它，否则等于把错误彻底丢掉。",
         "无（需要可写的 error_log 目标）。",
         "php -i | grep log_errors 应为 On；业务报错时日志有记录",
         "改回 Off"),
    Rule("LOG-002", "日志", "ini", "error_log", None, "/var/log/php/error.log", "low", False,
         "显式指定错误日志路径，避免落到 Web 根目录下被直接下载。",
         "路径必须存在且 PHP 进程可写，否则错误丢失。",
         "php -i | grep error_log；触发一次错误看文件是否增长",
         "注释掉该行"),
    Rule("LOG-003", "日志", "ini", "error_reporting", "E_ALL", "E_ALL & ~E_DEPRECATED", "low", False,
         "生产环境屏蔽废弃告警可减少噪音，但**不建议屏蔽 E_WARNING 及以上**。",
         "会隐藏 PHP 版本升级相关的废弃提示。",
         "php -i | grep error_reporting",
         "改回 E_ALL"),
    Rule("LOG-004", "日志", "ini", "ignore_repeated_errors", "0", "1", "low", False,
         "重复错误只记一次，避免日志被刷爆（也降低日志洪泛攻击的效果）。",
         "排障时可能看不到重复次数。",
         "php -i | grep ignore_repeated_errors",
         "改回 Off"),
)

# ======================================================================
# F. PHP-FPM
# ======================================================================
FPM: tuple[Rule, ...] = (
    Rule("FPM-001", "FPM", "fpm_pool", "security.limit_extensions", ".php .phar", ".php", "high", True,
         "限制 FPM 只执行指定后缀的脚本。若允许任意后缀，攻击者可上传 .jpg 内含 PHP 代码后"
         "直接请求执行，绕过上传校验。",
         "使用 .phar 或自定义后缀的站点需相应放开，否则会 404/403。",
         "在 pool 里查看 security.limit_extensions；请求一个 .jpg 应被拒绝",
         "改回默认并 reload FPM"),
    Rule("FPM-002", "FPM", "fpm_pool", "listen.mode", "0660", "0660", "medium", False,
         "FPM socket 权限。过宽（0666）允许任意本地用户连上 FPM 执行脚本。",
         "需与 Web 服务器用户组匹配，否则 nginx 502。",
         "ls -l /run/php/*.sock 应为 srw-rw---- 且属组正确",
         "改回原值"),
    Rule("FPM-003", "FPM", "fpm_pool", "pm.max_children", "5", "按内存与并发测算", "medium", False,
         "worker 数上限。过大在 OOM 攻击下更快耗尽宿主内存；过小会 502。",
         "需按 (可用内存 / 单进程常驻内存) 估算。",
         "ps -o rss= -C php-fpm8.3 | awk '{s+=$1} END {print s/1024\" MB\"}'",
         "改回原值"),
    Rule("FPM-004", "FPM", "fpm_pool", "request_terminate_timeout", "0", "60s", "medium", False,
         "单个请求的硬超时（FPM 层，独立于 max_execution_time）。设为 0 表示不限制，"
         "长耗时请求会一直占着 worker，放大 OOM 攻击效果。",
         "长任务（导出、同步）会被强杀，需按业务调大或拆分。",
         "查看 pool 配置；发起慢请求观察是否被 502 中断",
         "改回 0"),
    Rule("FPM-005", "FPM", "fpm_pool", "catch_workers_output", "no", "yes", "low", False,
         "把 worker 的 stdout/stderr 收进 FPM 日志，崩溃类问题不再无踪可查。",
         "日志量会上升。",
         "故意触发一个 fatal，检查 FPM 错误日志是否有输出",
         "改回 no"),
    Rule("FPM-006", "FPM", "fpm_pool", "clear_env", "yes", "yes", "low", False,
         "清空环境变量后再启动 worker，避免把宿主的环境变量（含密钥）泄给应用。",
         "依赖系统环境变量的应用需要在 pool 里显式 env[...] 声明。",
         "在页面里 var_dump(getenv()) 应看不到宿主变量",
         "改回 no"),
    Rule("FPM-007", "FPM", "fpm_pool", "php_admin_value[open_basedir]", None, "/var/www", "high", False,
         "在 pool 级别强制 open_basedir，优先级高于 php.ini 且**应用无法用 ini_set 覆盖**，"
         "是防 LFI 最有效的一层。",
         "路径配错整站 500；需按虚拟主机分别配置。",
         "页面 phpinfo 里 open_basedir 显示为 local value，master value 同值",
         "删除该行并 reload"),
    Rule("FPM-008", "FPM", "fpm_pool", "php_admin_value[disable_functions]", None,
         "exec,passthru,shell_exec,system", "medium", False,
         "pool 级别的函数禁用，应用无法用 ini_set 绕过（php.ini 里的 disable_functions 是 PHP_INI_SYSTEM，"
         "但 pool 级更直观且可分组）。",
         "依赖这些函数的插件会报错。",
         "php -r 或用页面调用 exec，应提示函数被禁用",
         "删除该行并 reload"),
)

# ======================================================================
# G. Web 服务器
# ======================================================================
WEBSERVER: tuple[Rule, ...] = (
    Rule("WEB-001", "Web 服务器", "nginx", "client_max_body_size", "1m", "按业务设定", "low", False,
         "请求体上限，nginx 层先于 PHP 拦截超大请求，降低 OOM 攻击收益。",
         "小于业务上传需求会返回 413。",
         "上传一个超过限制的文件应得 413",
         "改回原值"),
    Rule("WEB-002", "Web 服务器", "nginx", "fastcgi_read_timeout", "60s", "60s", "low", False,
         "等待 FPM 响应的超时。过长会在 worker 被打满时拖住连接。",
         "长任务接口可能被超时掐断。",
         "观察长请求是否 504",
         "改回原值"),
    Rule("WEB-003", "Web 服务器", "nginx", "add_header X-Content-Type-Options", None, "nosniff", "low", False,
         "禁止浏览器猜测 MIME 类型，降低上传文件被当 HTML/JS 执行的风险。",
         "无。",
         "curl -sI http://站点/ | grep -i x-content-type-options",
         "删除该 header"),
    Rule("WEB-004", "Web 服务器", "nginx", "上传目录禁止执行", None, "/uploads/ { location ~ \\.php$ { deny all; } }",
         "high", False,
         "对对上传目录直接拒绝 PHP 执行，是防「上传即 getshell」最省事的一层。",
         "若业务确实在上传目录放可执行脚本（不规范）会失败。",
         "在上传目录放一个 .php 并请求，应得 403",
         "删除该 location 块"),
    Rule("WEB-005", "Web 服务器", "nginx", "隐藏备份/配置文件", None,
         "location ~* \\.(bak|sql|conf|ini|swp|git) { deny all; }", "medium", False,
         "阻止直接下载 .bak/.sql/.git 等敏感文件——这类文件常因运维习惯留在 Web 根目录。",
         "无（正常业务不应直接请求这些后缀）。",
         "请求 /index.php.bak 应得 403",
         "删除该 location 块"),
)

# ======================================================================
# H. systemd 单元加固（PHP-FPM 服务）
# ======================================================================
SYSTEMD: tuple[Rule, ...] = (
    Rule("SYS-001", "系统服务", "systemd", "NoNewPrivileges", "no", "yes", "medium", False,
         "禁止进程及其子进程通过 setuid/setgid 提权，压缩拿到代码执行后的逃逸面。",
         "极少数依赖 setuid 二进制的场景会失败。",
         "systemctl show php8.3-fpm -p NoNewPrivileges 应为 yes",
         "删除该 drop-in 并 daemon-reload"),
    Rule("SYS-002", "系统服务", "systemd", "PrivateTmp", "no", "yes", "low", False,
         "给服务独立的 /tmp，避免与其他进程共享临时目录被投毒或窥探。",
         "跨服务通过 /tmp 交换文件的流程会失效。",
         "systemctl show php8.3-fpm -p PrivateTmp 应为 yes",
         "删除 drop-in"),
    Rule("SYS-003", "系统服务", "systemd", "ProtectSystem", "no", "full", "medium", False,
         "把 /usr、/boot、/etc 挂成只读（除显式放开的路径），显著限制落盘型后门。",
         "若 PHP 需要写 /etc 下文件（不规范）会失败；需配合 ReadWritePaths。",
         "systemctl show php8.3-fpm -p ProtectSystem",
         "删除 drop-in"),
    Rule("SYS-004", "系统服务", "systemd", "LimitNOFILE", None, "65535", "low", False,
         "提高文件描述符上限，避免高并发下 worker 因 fd 耗尽而异常。",
         "无（仅提高上限）。",
         "systemctl show php8.3-fpm -p LimitNOFILE",
         "删除该行"),
)



# ======================================================================
# 第二批：更深一层的会话 / 加载链 / 传输层
# ======================================================================
SESSION2: tuple[Rule, ...] = (
    Rule("SESS-010", "会话安全", "ini", "session.save_path", None, "/var/lib/php/sessions", "medium", False,
         "会话文件落盘位置。放在 Web 根目录下会被直接下载；放在共享 /tmp 下则可能被同机其他用户读取。",
         "需保证目录存在、属主为 PHP 运行用户、权限 0700，否则会话无法写入。",
         "php -i | grep session.save_path；ls -ld 该目录应为 0700",
         "改回默认（空，使用系统默认）"),
    Rule("SESS-011", "会话安全", "ini", "session.name", "PHPSESSID", "SESSID", "low", False,
         "默认会话名是最常见的扫描特征之一。改名可降低被自动化工具一键识别的概率（不是安全边界，只是降噪）。",
         "前端或第三方 SDK 若硬编码 cookie 名会失效。",
         "响应头 Set-Cookie 的键名应变为 SESSID",
         "改回 PHPSESSID"),
    Rule("SESS-012", "会话安全", "ini", "session.cookie_lifetime", "0", "0", "low", True,
         "0 表示浏览器关闭即失效，减少长期驻留的会话凭据被复用。",
         "用户每次关浏览器需重新登录。",
         "php -i | grep session.cookie_lifetime 应为 0",
         "改回原值"),
    Rule("SESS-013", "会话安全", "ini", "session.sid_bits_per_character", "5", "6", "low", True,
         "每字符承载的比特数，配合 sid_length 提升会话 ID 熵值。",
         "无（仅影响 ID 字符集）。",
         "php -i | grep session.sid_bits_per_character 应为 6",
         "改回 5"),
    Rule("SESS-014", "会话安全", "ini", "session.lazy_write", "1", "1", "low", True,
         "会话数据未变化时不重写文件，减少磁盘写放大（对 OOM/IO 型攻击是轻微缓解）。",
         "无。",
         "php -i | grep session.lazy_write 应为 On",
         "保持默认即可"),
)

DANGEROUS2: tuple[Rule, ...] = (
    Rule("DANG-009", "高危特性", "ini", "cgi.fix_pathinfo", "1", "0", "critical", True,
         "设为 1 时，PHP 会按 PATH_INFO 修正脚本路径。配合 nginx 的 fastcgi_pass 写法不当，"
         "攻击者可用 /upload/x.jpg/anything.php 让不存在的 .php 被交给 FPM 执行——"
         "这是最经典的「图片马」执行路径。",
         "部分依赖 PATH_INFO 路由的框架（老版 ThinkPHP 等）需调整为 rewrite 写法。",
         "php -i | grep cgi.fix_pathinfo 应为 0；请求 /x.jpg/a.php 应 404",
         "改回 1 并重启 FPM"),
    Rule("DANG-010", "高危特性", "ini", "file_uploads", "1", "1", "low", False,
         "若业务完全不需要上传，关闭可直接消除整类上传链。多数站点需要，故默认建议保持开启。",
         "关闭后所有上传功能失效。",
         "php -i | grep file_uploads",
         "改回 1"),
    Rule("DANG-011", "高危特性", "ini", "upload_tmp_dir", None, "/var/tmp/php-uploads", "medium", False,
         "上传临时目录。放在共享 /tmp 且有可写权限时，其他本地用户可在文件被移动前读取/替换。",
         "目录需存在且 PHP 用户可写；跨分区移动会变慢。",
         "php -i | grep upload_tmp_dir；ls -ld 应为 0700 且属主正确",
         "注释掉该行"),
    Rule("DANG-012", "高危特性", "ini", "phar.readonly", "1", "1", "medium", False,
         "Phar 反序列化是常见 RCE 入口。保持 readonly=1 可阻止运行时创建/修改 phar 包。"
         "**默认已是 1，此项用于确认没被改成 0**。",
         "需要构建 phar 包的构建机必须设为 0（但不应在线上）。",
         "php -i | grep phar.readonly 应为 On",
         "确认后保持"),
    Rule("DANG-013", "高危特性", "ini", "user_dir", None, "（空，不启用）", "low", True,
         "启用后 /~user/ 会映射到用户目录下的 PHP 脚本，等于开了一个不受控的脚本入口。",
         "无（绝大多数站点不使用）。",
         "php -i | grep user_dir 应为空",
         "改回原值"),
    Rule("DANG-014", "高危特性", "ini", "doc_root", None, "（按站点根目录设定）", "low", False,
         "限定 PHP 的文档根。与 open_basedir 配合可进一步收窄可访问范围。",
         "CLI 与 FPM 配置不一致会导致脚本找不到。",
         "php -i | grep doc_root",
         "改回原值"),
    Rule("DANG-015", "高危特性", "ini", "disable_classes", None, "（按业务评估填写）", "low", False,
         "禁用指定的危险类（如某些可执行命令的扩展类）。",
         "按业务实际使用的类评估。",
         "php -i | grep disable_classes",
         "改回原值"),
    Rule("DANG-016", "高危特性", "ini", "assert.active", "1", "0", "medium", True,
         "assert 在历史上被用作代码执行载体（字符串参数会被 eval）。生产环境应关闭。",
         "依赖 assert 做断言的测试代码会失效（生产本不该有）。",
         "php -i | grep assert.active 应为 Off",
         "改回 On"),
    Rule("DANG-017", "高危特性", "ini", "zend.assertions", "1", "0", "medium", True,
         "PHP 7+ 用该指令控制 assert 是否被编译执行；0 表示完全不编译断言代码。",
         "无功能影响，与上一条配套生效。",
         "php -i | grep zend.assertions 应为 -1 或 0",
         "改回 1"),
    Rule("DANG-018", "高危特性", "ini", "opcache.restrict_api", None, "/var/www", "low", False,
         "限制只有指定路径下的脚本能调用 opcache_* 管理函数（其中 opcache_reset 可被用于 DoS）。",
         "运维脚本若不在该路径下将无法重置 opcache。",
         "php -r 'var_dump(opcache_reset());' 应报 not allowed",
         "改回空"),
)

RESOURCE2: tuple[Rule, ...] = (
    Rule("RES-008", "资源限制", "ini", "max_input_time", "-1", "60", "low", False,
         "解析输入（POST/上传）的最长时间。设为 -1 表示不限制，慢速上传（Slowloris 变种）会长期占用 worker。",
         "大文件上传慢速链路可能被中断。",
         "php -i | grep max_input_time",
         "改回 -1"),
    Rule("RES-009", "资源限制", "ini", "output_buffering", "4096", "4096", "low", False,
         "输出缓冲大小。过大在大量并发下会抬高单进程内存占用，间接放大 OOM 攻击效果。",
         "关闭后 header 必须在任何输出前发送。",
         "php -i | grep output_buffering",
         "改回原值"),
    Rule("RES-010", "资源限制", "fpm_pool", "pm.max_requests", "0", "500", "low", False,
         "每个 worker 处理 N 个请求后重启，能回收内存碎片与潜在内存泄漏，降低长期运行下的 OOM 风险。",
         "频繁重启有轻微性能损耗。",
         "查看 pool 配置；观察 worker pid 是否周期性变化",
         "改回 0"),
)

FPM2: tuple[Rule, ...] = (
    Rule("FPM-009", "FPM", "fpm_pool", "listen.owner", None, "www-data", "medium", False,
         "socket 属主。与 listen.group + 0660 配合，确保只有 Web 服务器能连 FPM。",
         "属主与 nginx 用户不一致会导致 502。",
         "ls -l /run/php/*.sock",
         "改回原值"),
    Rule("FPM-010", "FPM", "fpm_pool", "listen.group", None, "www-data", "medium", False,
         "socket 属组。与 listen.owner、listen.mode 共同决定谁能连上 FPM；设得过宽会让本机任意用户直接向 FPM 提交脚本执行。",
         "无功能影响，与上一条配套生效。",
         "ls -l /run/php/*.sock",
         "改回原值"),
    Rule("FPM-011", "FPM", "fpm_pool", "slowlog", None, "/var/log/php/slow.log", "low", False,
         "记录慢请求堆栈，是排查 OOM/卡死类问题的关键证据（php2shell 的 OOM 链会表现为慢请求）。",
         "需要日志轮转，否则会堆积。",
         "触发一次慢请求后检查该文件是否增长",
         "注释掉该行"),
    Rule("FPM-012", "FPM", "fpm_pool", "request_slowlog_timeout", "0", "5s", "low", False,
         "配合 slowlog，超过阈值就抓一次堆栈。",
         "日志量上升。",
         "发起一次慢请求，检查 slow.log 是否抓到堆栈",
         "改回 0"),
    Rule("FPM-013", "FPM", "fpm_pool", "access.log", None, "/var/log/php/access.log", "low", False,
         "FPM 侧访问日志可记录到具体脚本与耗时，Web 日志被篡改时仍能对照。",
         "额外磁盘开销。",
         "查看该文件是否记录请求",
         "注释掉"),
    Rule("FPM-014", "FPM", "fpm_pool", "php_admin_flag[log_errors]", "0", "on", "medium", True,
         "pool 级强制记录错误，覆盖应用里 ini_set('log_errors', 0) 的行为。",
         "无。",
         "页面触发错误，检查 error_log 是否增长",
         "删除该行"),
    Rule("FPM-015", "FPM", "fpm_pool", "php_admin_value[error_log]", None, "/var/log/php/fpm-error.log", "low", False,
         "pool 级错误日志路径，与 php.ini 分开便于按站点排查。",
         "需保证目录可写。",
         "触发一次 PHP 错误后，检查该文件是否新增记录",
         "删除该行"),
    Rule("FPM-016", "FPM", "fpm_pool", "user", None, "www-data", "medium", False,
         "FPM worker 运行用户。**绝不要用 root**——一旦代码执行，直接就是 root 权限。",
         "用户不存在会导致 FPM 启动失败。",
         "ps -o user= -C php-fpm8.3 不应出现 root",
         "改回原值"),
    Rule("FPM-017", "FPM", "fpm_pool", "chdir", None, "/var/www", "low", False,
         "worker 启动时的工作目录。设为 Web 根可避免相对路径包含落到意外位置。",
         "依赖默认工作目录的脚本可能找不到相对路径文件。",
         "页面 getcwd() 应为设定值",
         "改回原值"),
)

WEBSERVER2: tuple[Rule, ...] = (
    Rule("WEB-006", "Web 服务器", "nginx", "autoindex", "off", "off", "low", False,
         "目录浏览。开启后会把上传目录、备份目录的完整文件清单暴露给任何人。",
         "无（正常业务不依赖目录列表）。",
         "请求一个无 index 的目录，应得 403 而非文件列表",
         "改回 on"),
    Rule("WEB-007", "Web 服务器", "nginx", "add_header X-Frame-Options", None, "SAMEORIGIN", "low", False,
         "防点击劫持。管理后台尤其需要。",
         "确实需要被第三方 iframe 嵌入的页面需放开。",
         "curl -sI http://站点/ | grep -i x-frame-options",
         "删除该 header"),
    Rule("WEB-008", "Web 服务器", "nginx", "add_header Referrer-Policy", None, "no-referrer-when-downgrade", "low", False,
         "控制 Referer 外泄，避免 URL 中的敏感参数被第三方站点拿到。",
         "依赖 Referer 的防盗链/统计可能受影响。",
         "curl -sI http://站点/ | grep -i referrer-policy",
         "删除该 header"),
    Rule("WEB-009", "Web 服务器", "nginx", "拒绝 .git/.env", None,
         "location ~ /\\.(git|env|svn) { deny all; }", "high", False,
         ".git 目录与 .env 文件常因部署方式不当残留在 Web 根，泄露源码与密钥。",
         "无。",
         "请求 /.git/config 与 /.env 应得 403",
         "删除该 location"),
    Rule("WEB-010", "Web 服务器", "nginx", "ssl_protocols", None, "TLSv1.2 TLSv1.3", "medium", False,
         "禁用 TLS 1.0/1.1。较新 nginx 默认已不含旧协议，此项用于确认。",
         "极老客户端（XP/IE8）无法连接。",
         "openssl s_client -connect 站点:443 -tls1 应失败",
         "改回原值"),
    Rule("WEB-011", "Web 服务器", "nginx", "add_header Strict-Transport-Security", None,
         "max-age=31536000", "low", False,
         "强制浏览器后续只用 HTTPS 访问，防止降级。**仅在 HTTPS 站点且证书稳定时开启**。",
         "一旦下发，浏览器会在 max-age 内拒绝 HTTP 访问；证书出问题会导致站点不可用。",
         "curl -sI https://站点/ | grep -i strict-transport",
         "删除该 header 并等待缓存过期"),
    Rule("WEB-012", "Web 服务器", "nginx", "add_header Content-Security-Policy", None,
         "default-src 'self'", "medium", False,
         "限制页面可加载的资源来源，显著降低 XSS 成功率。老站点可能需要放宽。",
         "内联脚本、外部 CDN、内联样式会被拦截，需按站点实际调整。",
         "浏览器控制台不应出现 CSP 报错导致功能异常",
         "删除该 header"),
    Rule("WEB-013", "Web 服务器", "apache", "Options -Indexes", None, "Options -Indexes", "low", False,
         "关闭 Apache 目录浏览。",
         "无。",
         "请求无 index 的目录应得 403",
         "改回 Options Indexes"),
    Rule("WEB-014", "Web 服务器", "apache", "TraceEnable", "on", "off", "low", False,
         "关闭 TRACE 方法，避免跨站追踪（XST）类问题。",
         "无。",
         "curl -X TRACE http://站点/ -i 应得 405",
         "改回 on"),
)

SYSTEMD2: tuple[Rule, ...] = (
    Rule("SYS-005", "系统服务", "systemd", "ProtectHome", "no", "yes", "low", False,
         "把 /home、/root、/run/user 对服务隐藏，压缩横向读取面。",
         "若站点代码放在 /home 下会失效，需改用 /var/www。",
         "systemctl show php8.3-fpm -p ProtectHome",
         "删除 drop-in"),
    Rule("SYS-006", "系统服务", "systemd", "PrivateDevices", "no", "yes", "low", False,
         "隐藏物理设备节点，降低从 PHP 进程直接操作设备的可能。",
         "极少数需要访问 /dev 的扩展（如某些 GPU/串口）会失败。",
         "systemctl show php8.3-fpm -p PrivateDevices",
         "删除 drop-in"),
    Rule("SYS-007", "系统服务", "systemd", "RestrictAddressFamilies", None,
         "AF_INET AF_INET6 AF_UNIX", "low", False,
         "限制进程可用的 socket 家族，阻断 AF_PACKET 等原始套接字能力。",
         "需要特殊协议（如 netlink）的场景会失败。",
         "systemctl show php8.3-fpm -p RestrictAddressFamilies",
         "删除该行"),
    Rule("SYS-008", "系统服务", "systemd", "MemoryMax", "infinity", "按机器内存的 70%", "medium", False,
         "给整个服务设内存上限。OOM 攻击最多打挂 FPM，不至于把宿主一起拖死。",
         "设置过低会导致正常业务在高峰期被 OOM killer 杀掉。",
         "systemctl show php8.3-fpm -p MemoryMax",
         "删除该行"),
    Rule("SYS-009", "系统服务", "systemd", "Restart", "no", "on-failure", "low", False,
         "异常退出后自动拉起，缩短 OOM 攻击造成的服务中断时间。",
         "若进程启动即崩会进入重启循环，需配合 StartLimitBurst。",
         "systemctl show php8.3-fpm -p Restart",
         "改回 no"),
)


# ======================================================================
# I. Kubernetes 工作负载加固
# ======================================================================
K8S: tuple[Rule, ...] = (
    Rule("K8S-001", "K8s", "k8s", "pod-security.kubernetes.io/enforce", "privileged",
         "restricted", "critical", False,
         "命名空间级 Pod Security 档位。privileged 档位等于不设防，任何 Pod 都能以特权容器运行；"
         "restricted 会强制非 root、禁提权、丢能力、要求 seccomp。",
         "违规的既有工作负载会被 API Server 拒绝创建/更新，需先按补丁改造工作负载。",
         "kubectl get ns <名称> -o jsonpath='{.metadata.labels}'",
         "把标签改回 privileged（不推荐）"),
    Rule("K8S-002", "K8s", "k8s", "securityContext.runAsNonRoot", "false", "true",
         "critical", False,
         "容器以 root 运行时，应用层 RCE 直接等于节点级 root 起点。设为 true 后镜像若声明 root 会启动失败。",
         "镜像内进程需能写自身目录；部分老镜像以 root 写日志会失败。",
         "kubectl get pod <名称> -o jsonpath='{.spec.securityContext.runAsNonRoot}'",
         "移除该字段并重建 Pod"),
    Rule("K8S-003", "K8s", "k8s", "securityContext.allowPrivilegeEscalation", "true", "false",
         "high", False,
         "允许进程通过 setuid/setgid 提权。关闭后可阻断大量容器逃逸手法。",
         "需要 setuid 的工具（如部分包管理器）会失败。",
         "同上，查 allowPrivilegeEscalation",
         "移除该字段"),
    Rule("K8S-004", "K8s", "k8s", "securityContext.readOnlyRootFilesystem", "false", "true",
         "high", False,
         "根文件系统只读，webshell 无法落盘、攻击者无法替换二进制。需配合 emptyDir 写临时文件。",
         "应用若往镜像内写文件（缓存、上传）会失败，需挂载可写卷。",
         "kubectl exec 进入容器后 touch /tmp/x 应失败（/tmp 若挂了空目录卷则正常）",
         "改回 false"),
    Rule("K8S-005", "K8s", "k8s", "securityContext.capabilities.drop", "[]", "ALL",
         "high", False,
         "默认容器带有 CHOWN/DAC_OVERRIDE/NET_RAW 等能力，是提权与网络嗅探的抓手。丢弃 ALL 后按需单独加回。",
         "需要原始套接字或改文件属主的程序会失败。",
         "kubectl get pod <名称> -o jsonpath='{.spec.containers[0].securityContext.capabilities}'",
         "移除 drop 列表"),
    Rule("K8S-006", "K8s", "k8s", "automountServiceAccountToken", "true", "false",
         "medium", False,
         "默认会把 ServiceAccount token 挂进容器，一旦代码执行即可用它对 API Server 发起请求。",
         "需要访问 API Server 的控制器/Operator 必须显式开启。",
         "kubectl exec 后 ls /var/run/secrets/kubernetes.io/serviceaccount 应不存在",
         "改回 true"),
    Rule("K8S-007", "K8s", "k8s", "seccompProfile.type", "Unconfined", "RuntimeDefault",
         "medium", False,
         "Unconfined 允许全部系统调用。RuntimeDefault 由容器运行时提供默认白名单，能拦住多数内核利用。",
         "极少数依赖特殊 syscall 的程序会失败。",
         "kubectl get pod <名称> -o jsonpath='{.spec.securityContext.seccompProfile}'",
         "改回 Unconfined"),
    Rule("K8S-008", "K8s", "k8s", "resources.limits.memory", None, "512Mi",
         "medium", False,
         "没有内存上限时，OOM 型攻击可以把整个节点拖垮（同节点其他 Pod 一起被驱逐）。",
         "设置过低会让正常业务 OOMKilled，需按实际用量测算。",
         "kubectl get pod <名称> -o jsonpath='{.spec.containers[0].resources.limits.memory}'",
         "移除 limits"),
    Rule("K8S-009", "K8s", "k8s", "NetworkPolicy", None, "default-deny + 放行 DNS",
         "high", False,
         "K8s 默认全通，Pod 之间可任意互访。默认拒绝策略能显著压缩横向移动范围。",
         "未放行的依赖（数据库、缓存、外部 API）会连不通，需逐条补白名单。",
         "kubectl get networkpolicy -n <命名空间>",
         "删除该 NetworkPolicy"),
    Rule("K8S-010", "K8s", "k8s", "hostNetwork / hostPID / hostIPC", "false", "false",
         "high", False,
         "开启任一 host* 都会让 Pod 与节点共享网络/进程/IPC 命名空间，逃逸门槛大幅降低。",
         "需要抓包或监控节点的 DaemonSet 会用到，属于例外。",
         "kubectl get pod <名称> -o jsonpath='{.spec.hostNetwork}{.spec.hostPID}'",
         "改回 true（不推荐）"),
)


# ======================================================================
# J. Windows / IIS 加固
#
# 为什么单独成组：IIS 的配置模型（applicationHost.config + 站点/应用池/web.config
# 三级继承）与 nginx/apache 完全不同，指令名不能照搬；Windows 的"他人可写"是 ACL
# 而非权限位。这些规则的目标类型为 iis / acl / winsvc，由 Windows 侧工具读取。
# ======================================================================
WIN: tuple[Rule, ...] = (
    Rule("WIN-001", "Windows / IIS", "iis", "directoryBrowse.enabled", "true", "false",
         "high", False,
         "开启目录浏览会把站点目录结构完整暴露给未授权访问者，"
         "攻击者可据此定位上传目录、备份文件与配置文件。",
         "依赖目录列表的静态资源站点会 403，需先确认没有页面依赖自动索引。",
         "Get-WebConfigurationProperty -PSPath 'IIS:\\' -Filter 'system.webServer/directoryBrowse' "
         "-Name enabled",
         "Set-WebConfigurationProperty -Filter 'system.webServer/directoryBrowse' -Name enabled "
         "-Value true"),
    Rule("WIN-002", "Windows / IIS", "iis", "webdav.enabled", "true", "false",
         "critical", False,
         "IIS 的 WebDAV 模块允许通过 HTTP 直接 PUT/MOVE 文件。"
         "它既是 webshell 上传通道，历史上也出过多个远程执行漏洞。",
         "确实用 WebDAV 共享文档的站点会失效，需改用 SMB 并关闭公网暴露。",
         "Get-WebConfigurationProperty -PSPath 'IIS:\\' -Filter 'system.webServer/webdav' -Name enabled",
         "Enable-WebDAV（不推荐恢复）"),
    Rule("WIN-003", "Windows / IIS", "iis", "requestFiltering.maxAllowedContentLength",
         "30000000", "8388608", "high", False,
         "默认 30MB 的上传上限远超 webshell 所需体积，"
         "调小可显著降低「大文件上传绕过」与磁盘占满风险。",
         "业务若确实要传大附件（视频/安装包）会 404.13，需按业务目录单独放宽。",
         "Get-WebConfigurationProperty -PSPath 'IIS:\\' "
         "-Filter 'system.webServer/security/requestFiltering/requestLimits' "
         "-Name maxAllowedContentLength",
         "改回 30000000"),
    Rule("WIN-004", "Windows / IIS", "iis", "applicationPool.processModel.identityType",
         "LocalSystem", "ApplicationPoolIdentity", "critical", False,
         "应用池以 LocalSystem 运行时，webshell 一旦落地就直接拿到本机管理员权限；"
         "ApplicationPoolIdentity 是自动生成的低权限虚拟账户，能把影响面限制在站点目录内。",
         "切换到低权限账户后，站点目录与 session 目录需要显式授予该账户读/写权限，"
         "否则会立即 500。",
         "Get-IISAppPool <应用池> | Select-Object -ExpandProperty ProcessModel | "
         "Select-Object IdentityType",
         "改回 LocalSystem（强烈不推荐）"),
    Rule("WIN-005", "Windows / IIS", "iis", "httpErrors.errorMode", "Detailed", "DetailedLocalOnly",
         "medium", False,
         "详细错误会把堆栈、物理路径、PHP 配置暴露给外部访问者，是信息收集的起点。"
         "DetailedLocalOnly 让本机排障照旧，外部只看到通用错误页。",
         "需要从远端看详细错误时必须临时调整，排障后应改回。",
         "Get-WebConfigurationProperty -PSPath 'IIS:\\' -Filter 'system.webServer/httpErrors' "
         "-Name errorMode",
         "改回 Detailed"),
    Rule("WIN-006", "Windows / IIS", "iis", "httpProtocol.customHeaders.X-Powered-By", "PHP/8.x",
         "(删除)", "medium", False,
         "响应头直接写明 PHP 版本，让攻击者无需探测即可匹配已知漏洞，"
         "本项目关注的 php2shell 正属于此类。",
         "无功能影响；仅极少数监控脚本会读该头。",
         "(Invoke-WebRequest -Uri http://<站点>/ -UseBasicParsing).Headers['X-Powered-By']",
         "expose_php=1 且重启 IIS 后会重新出现"),
    Rule("WIN-007", "Windows / IIS", "iis", "fastCgi.activityTimeout", "300", "30",
         "medium", False,
         "FastCGI 活动超时过长时，OOM 崩溃的 php-cgi 进程会长时间挂住，"
         "配合请求堆积可拖垮整个应用池。",
         "长耗时任务（报表导出/大文件处理）可能被中断，需按业务上限调整。",
         "Get-WebConfigurationProperty -PSPath 'IIS:\\' "
         "-Filter 'system.webServer/fastCgi/application' -Name activityTimeout",
         "改回 300"),
    Rule("WIN-008", "Windows 权限", "acl", "php.ini ACL", "Everyone:(R)",
         "仅 Administrators + SYSTEM", "critical", False,
         "php.ini 若对普通用户或 Everyone 可写，任何本地低权限进程都能植入恶意指令；"
         "加固脚本本身也会拒绝执行对非特权主体可写的目标。",
         "收紧后必须确认 IIS 应用池账户仍可读取该文件，否则 PHP 启动即失败。",
         "icacls C:\\php\\php.ini",
         "icacls C:\\php\\php.ini /grant Everyone:(R)"),
    Rule("WIN-009", "Windows 权限", "acl", "PHP 安装目录可写性", "Users:(M)", "仅 Administrators + SYSTEM",
         "critical", False,
         "PHP 安装目录（含 ext/、php.ini 所在目录）若对普通用户可写，"
         "webshell 可以直接落地并被 include —— 这比改配置更难察觉。",
         "部分自更新脚本依赖目录可写，收紧后需改用计划任务以管理员身份运行。",
         "icacls C:\\php /T",
         "icacls C:\\php /grant Users:(M)"),
    Rule("WIN-010", "Windows 权限", "winsvc", "W3SVC / php-cgi 服务账户", "LocalSystem",
         "NT AUTHORITY\\LocalService", "high", False,
         "服务以 LocalSystem 运行时，服务进程被攻陷等于拿下本机；"
         "LocalService 或独立虚拟账户可显著限制横向移动。",
         "换账户后需重新授予日志目录、临时目录与 php.ini 的访问权限，"
         "否则服务无法启动。",
         "Get-CimInstance Win32_Service -Filter \"Name='W3SVC'\" | Select-Object StartName",
         "sc.exe config W3SVC obj= LocalSystem"),
)


ALL: tuple[Rule, ...] = (SESSION + SESSION2 + EXPOSURE + DANGEROUS + DANGEROUS2
                         + RESOURCE + RESOURCE2 + LOGGING
                         + FPM + FPM2 + WEBSERVER + WEBSERVER2 + SYSTEMD + SYSTEMD2
                         + K8S + WIN)

CATEGORIES: tuple[str, ...] = tuple(dict.fromkeys(r.category for r in ALL))


def by_category(category: str) -> list[Rule]:
    return [r for r in ALL if r.category == category]


def auto_rules() -> list[Rule]:
    """可被加固包自动写入的规则（只含 ini / fpm_pool 的键值修改）。"""
    return [r for r in ALL if r.auto]


def for_php_version(version: str | None) -> list[Rule]:
    """过滤掉与当前 PHP 版本无关的规则（目前只有 8.5 的 fatal_error_backtraces）。"""
    if not version:
        return list(ALL)
    major_minor = ".".join(str(version).split(".")[:2])
    out = []
    for r in ALL:
        if r.key == "fatal_error_backtraces" and major_minor < "8.5":
            continue
        out.append(r)
    return out


def stats() -> dict:
    auto = auto_rules()
    return {
        "total": len(ALL),
        "auto": len(auto),
        "manual": len(ALL) - len(auto),
        "categories": len(CATEGORIES),
        "by_category": {c: len(by_category(c)) for c in CATEGORIES},
        "by_risk": {k: sum(1 for r in ALL if r.risk == k)
                    for k in ("critical", "high", "medium", "low")},
    }
