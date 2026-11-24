"""D1 被动指纹

只做「正常客户端也会发的请求」，不构造任何畸形请求。
能拿到什么算什么，拿不到就诚实记录 UNKNOWN。

证据来源优先级（models.SOURCE_PRECEDENCE）：
    phpinfo 暴露  → version_local / ini / sapi（高）
    HTTP 头       → http_header / version_remote（低）
"""

from __future__ import annotations

import html as html_mod
import re
from urllib.parse import urlsplit

from ..models import Confidence, DetectionContext, DetectionResult, Evidence
from ..netclient import HttpClient, HttpResponse
from ..rules import RULESET
from ..safety import ProbeBudget, RateLimiter

# phpinfo 中要提取的键（大小写不敏感）
PHPINFO_KEYS = [k.lower() for k in RULESET["phpinfo_keys"]]

TAG_RE = re.compile(r"(?s)<[^>]+>")
SCRIPT_RE = re.compile(r"(?is)<script.*?</script>")
STYLE_RE = re.compile(r"(?is)<style.*?</style>")
SPACE_RE = re.compile(r"[ \t\u00a0]+")

FRAMEWORK_SIGS = {
    "WordPress": [r"/wp-content/", r"/wp-includes/", r'name="generator" content="WordPress'],
    "Drupal": [r"Drupal\.settings", r"sites/default/files", r'content="Drupal'],
    "Joomla": [r"/media/system/js/", r'content="Joomla'],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN", r"Whoops! There was an error"],
    "ThinkPHP": [r"ThinkPHP", r"think_var", r"/index\.php/"],
    "Symfony": [r"symfony", r"Symfony\\\\Component"],
    "CodeIgniter": [r"ci_session"],
}

WAF_SIGS = {
    "Cloudflare": [r"cloudflare", r"cf-ray"],
    "Sucuri": [r"x-sucuri"],
    "AWS WAF": [r"awselb", r"x-amzn-requestid"],
    "Imperva": [r"x-iinfo", r"incap_ses"],
    "安全狗/云锁": [r"safedog", r"yunsuo"],
    "阿里云WAF": [r"aliyun", r"acw_tc"],
}


def _strip_html(html: str) -> list[str]:
    text = SCRIPT_RE.sub(" ", html)
    text = STYLE_RE.sub(" ", text)
    text = TAG_RE.sub("|", text)
    text = html_mod.unescape(text)
    parts = [SPACE_RE.sub(" ", p).strip() for p in text.split("|")]
    return [p for p in parts if p]


def parse_phpinfo(content: str) -> dict[str, str]:
    """从 phpinfo 页面（HTML 或纯文本）提取配置项。

    同时兼容三种形态：
      - phpinfo() 的 HTML 表格（td 单元被替换成 |）
      - php -i 的纯文本（key => local => master）
      - 简化的 key: value 行
    """
    out: dict[str, str] = {}

    # 形态 1：HTML 表格
    parts = _strip_html(content)
    for i, part in enumerate(parts[:-1]):
        key = part.lower().rstrip(":")
        if key in PHPINFO_KEYS and key not in out:
            nxt = parts[i + 1]
            if nxt.lower() not in PHPINFO_KEYS and nxt:
                out[key] = nxt

    # 形态 2：php -i 纯文本
    if not out:
        for line in content.splitlines():
            if "=>" not in line:
                continue
            segs = [s.strip() for s in line.split("=>")]
            key = segs[0].lower()
            if key in PHPINFO_KEYS and len(segs) >= 2:
                out[key] = segs[1]

    return out


def parse_phpinfo_text(content: str) -> dict[str, str]:
    """专门解析 `php -i` 的纯文本输出（本地模式用）。"""
    out: dict[str, str] = {}
    for line in content.splitlines():
        if "=>" not in line:
            continue
        segs = [s.strip() for s in line.split("=>")]
        key = segs[0].lower().rstrip(":")
        if key in PHPINFO_KEYS and len(segs) >= 2:
            out[key] = segs[1]
    return out


def infer_sapi(headers: HttpResponse) -> tuple[str, Confidence, str]:
    """从响应头推断 SAPI。远程推断天然不可靠，故置信度最高只到 medium。"""
    server = (headers.header("server") or "").lower()
    xpb = headers.header("x-powered-by") or ""
    powered = xpb.lower()

    if "frankenphp" in server or "frankenphp" in powered:
        return "frankenphp", Confidence.MEDIUM, f"Server/头含 frankenphp 特征：{server or xpb}"
    if "litespeed" in server:
        return "litespeed", Confidence.MEDIUM, f"Server: {server}"
    if "php" in powered:
        if "apache" in server:
            return "apache2handler", Confidence.LOW, f"Apache + X-Powered-By: {xpb}（可能是 mod_php，也可能是 proxy_fcgi）"
        if "nginx" in server:
            return "fpm-fcgi", Confidence.LOW, f"nginx + X-Powered-By: {xpb}"
        if "caddy" in server:
            return "frankenphp", Confidence.LOW, "Caddy + PHP 头，可能是 FrankenPHP"
        return "unknown", Confidence.LOW, f"检测到 PHP 头但无法确定 SAPI：{server}"
    if "apache" in server:
        return "unknown", Confidence.LOW, f"Apache 但无 PHP 头（expose_php 可能关闭）：{server}"
    if "nginx" in server:
        return "fpm-fcgi", Confidence.LOW, f"nginx 无 PHP 头，最常见为 PHP-FPM"
    return "unknown", Confidence.UNKNOWN, "无足够信息判定 SAPI"


def detect_phpsessid(resp: HttpResponse) -> list[Evidence]:
    evs: list[Evidence] = []
    for cookie in resp.header_values("set-cookie"):
        m = re.search(r"PHPSESSID=([^;]+)", cookie, re.I)
        if not m:
            continue
        val = m.group(1)
        evs.append(
            Evidence(
                detector="D1", kind="http_header", key="cookie.phpsessid",
                value={"length": len(val), "preview": val[:32]},
                confidence=Confidence.MEDIUM,
                method="响应 Set-Cookie 头",
                source="http_header",
                source_ref=cookie[:200],
            )
        )
        # HUNT-005：异常 PHPSESSID（内存泄露回显的强特征）
        encoded_runs = len(re.findall(r"%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}", val))
        if len(val) > 200 or encoded_runs:
            evs.append(
                Evidence(
                    detector="D1", kind="behavior", key="hunt.abnormal_phpsessid",
                    value={"length": len(val), "encoded_runs": encoded_runs},
                    confidence=Confidence.HIGH,
                    method="PHPSESSID 长度/编码特征检测",
                    source="behavior",
                    source_ref=cookie[:300],
                )
            )
    return evs


def _detect_by_dict(text: str, table: dict[str, list[str]]) -> list[str]:
    """按正则表匹配特征。规则写错不能拖垮整层检测，故逐条容错。"""
    hits = []
    for name, pats in table.items():
        for p in pats:
            try:
                if re.search(p, text, re.I):
                    hits.append(name)
                    break
            except re.error:
                # 正则非法时退化为子串匹配
                if p.lower() in text.lower():
                    hits.append(name)
                    break
    return hits


def run(ctx: DetectionContext, client: HttpClient,
        limiter: RateLimiter, budget: ProbeBudget) -> DetectionResult:
    res = DetectionResult(detector="D1")
    host = urlsplit(ctx.target).hostname or ctx.target
    base = ctx.target.rstrip("/")

    # ---- 1. 主页响应 ----
    limiter.acquire(host)
    budget.consume()
    home = client.request(ctx.target, "GET")
    budget.record(home.error is not None or home.status >= 500)

    if home.error and home.status == 0:
        res.err(f"主页请求失败：{home.error}")
        return res

    server = home.header("server") or ""
    xpb = home.header("x-powered-by") or ""

    if server:
        res.add(Evidence("D1", "http_header", "http.server", server,
                         Confidence.MEDIUM, "响应头 Server", "http_header", server))
    if xpb:
        res.add(Evidence("D1", "http_header", "http.x_powered_by", xpb,
                         Confidence.MEDIUM, "响应头 X-Powered-By", "http_header", xpb))
        ver = re.search(r"PHP/([0-9][0-9A-Za-z.\-+~]*)", xpb)
        if ver:
            res.add(Evidence("D1", "version", "php.version", ver.group(1),
                             Confidence.MEDIUM,
                             "响应头 X-Powered-By（可被伪造或关闭，仅作线索）",
                             "version_remote", xpb))
    if home.status:
        res.add(Evidence("D1", "http_header", "http.status", home.status,
                         Confidence.CONFIRMED, "主页状态码", "http_header", ctx.target))

    # ---- 2. SAPI 推断 ----
    sapi, conf, why = infer_sapi(home)
    res.add(Evidence("D1", "sapi", "php.sapi", sapi, conf, why, "sapi", why))

    # ---- 3. 框架 / WAF ----
    body = home.text[:200000]
    combined = body + "\n" + "\n".join(f"{k}: {v}" for k, v in home.headers)
    for fw in _detect_by_dict(combined, FRAMEWORK_SIGS):
        res.add(Evidence("D1", "http_header", "app.framework", fw,
                         Confidence.MEDIUM, "页面/响应特征匹配", "http_header", fw))
    for waf in _detect_by_dict(combined, WAF_SIGS):
        res.add(Evidence("D1", "http_header", "net.waf", waf,
                         Confidence.MEDIUM, "响应头/拦截页特征", "http_header", waf))
        res.notes.append(f"检测到前置防护设备：{waf}（WAF 只能拦截已知模式，不能替代补丁）")

    # ---- 4. PHPSESSID ----
    for ev in detect_phpsessid(home):
        res.add(ev)
    if any(e.key == "hunt.abnormal_phpsessid" for e in res.evidences):
        res.notes.append(
            "⚠ 检测到异常 PHPSESSID：正常 PHP session id 为定长字母数字，"
            "出现长度异常或连续 URL 编码串通常意味着内存泄露正在发生"
        )

    # ---- 5. phpinfo 暴露探测（只读路径探测，绝不写入文件）----
    for path in RULESET["phpinfo_paths"]:
        if not budget.consume():
            break
        limiter.acquire(host)
        url = f"{base}/{path}"
        r = client.request(url, "GET")
        budget.record(r.error is not None or r.status >= 500)
        if not r.ok or r.error:
            continue
        text = r.text
        if "PHP Version" not in text and "phpinfo()" not in text and "Zend Engine" not in text:
            continue

        info = parse_phpinfo(text)
        if not info:
            continue

        res.add(Evidence("D1", "file", "leak.phpinfo", path, Confidence.CONFIRMED,
                         f"可直接访问 {path}（信息泄露）", "http_header", url))
        res.notes.append(
            f"⚠ {path} 暴露 phpinfo：这本身是严重的信息泄露问题，应尽快下线"
        )

        v = info.get("php version")
        if v:
            res.add(Evidence("D1", "version", "php.version", v, Confidence.HIGH,
                             "phpinfo 输出版本（反映 Web 实际运行时）",
                             "version_local", url))
        api = info.get("server api")
        if api:
            res.add(Evidence("D1", "sapi", "php.sapi", normalize_sapi(api),
                             Confidence.CONFIRMED, f"phpinfo Server API = {api}",
                             "sapi", url))
        if info.get("build date"):
            res.add(Evidence("D1", "version", "php.build_date", info["build date"],
                             Confidence.HIGH, "phpinfo Build Date", "version_local", url))
        if info.get("configure command"):
            res.add(Evidence("D1", "version", "php.configure_command",
                             info["configure command"][:400], Confidence.HIGH,
                             "phpinfo Configure Command（判断是否自编译）",
                             "version_local", url))
        for k in ("memory_limit", "post_max_size", "max_file_uploads",
                  "max_input_nesting_level", "session.upload_progress.enabled",
                  "enable_post_data_reading", "fatal_error_backtraces",
                  "expose_php", "open_basedir"):
            if k in info:
                res.add(Evidence("D1", "ini", f"ini.{k}", info[k], Confidence.HIGH,
                                 f"phpinfo {k}", "ini", url))
        break  # 命中一个就够

    # ---- 6. 低风险信息补充（失败不影响结论）----
    for probe, key, label in (
        ("composer.json", "app.composer_json", "composer.json 可读"),
        ("vendor/composer/installed.json", "app.composer_installed", "vendor 依赖清单可读"),
    ):
        if not budget.consume():
            break
        limiter.acquire(host)
        r = client.request(f"{base}/{probe}", "GET")
        budget.record(False)
        if r.ok and r.body and len(r.body) < 400_000 and b"{" in r.body[:200]:
            res.add(Evidence("D1", "file", key, probe, Confidence.MEDIUM,
                             f"{label}（可能泄露依赖与版本）", "http_header", f"{base}/{probe}"))
            res.notes.append(f"⚠ {probe} 可访问，建议限制访问权限")

    return res


def normalize_sapi(api: str) -> str:
    a = api.lower().replace(" ", "")
    if "apache" in a:
        return "apache2handler"
    if "fpm" in a:
        return "fpm-fcgi"
    if "cgi" in a:
        return "cgi-fcgi"
    if "cli" in a and "server" in a:
        return "cli-server"
    if "cli" in a:
        return "cli"
    if "litespeed" in a:
        return "litespeed"
    return a or "unknown"
