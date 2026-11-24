"""PHP2Shell 模拟靶场

纯 Python 实现，不依赖 Docker / PHP，用于演示与回归测试。

六个 persona 覆盖 04 文档判定矩阵的关键分支：
    8801  PHP 8.4.24 + mod_php，expose_php On，phpinfo 暴露     → 确认受影响 P0
    8802  PHP 8.4.27 + mod_php，同上                            → 已修复
    8803  PHP 8.3.35 + FPM，expose_php Off，仅 phpinfo 暴露     → 确认受影响（需 D1 深挖）
    8804  头部谎报 8.4.27，phpinfo 实为 8.4.26，构建日期早于补丁 → 版本造假，仍受影响
    8805  WAF 全站 403，无任何 PHP 头                            → 无法判定 UNKNOWN
    8806  PHP 8.1.31 + mod_php                                  → EOL 分支，无修复

注意：这是靶场，不是产品代码。故意模拟了脆弱版本的特征响应，
      但**不包含任何可利用的畸形解析逻辑**，只是一个返回固定内容的 HTTP 服务。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GIF_1PX = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
    b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
    b"\x00\x02\x02D\x01\x00;"
)


@dataclass
class Persona:
    key: str
    port: int
    title: str
    php_version: str
    server: str
    x_powered_by: str | None
    sapi: str                      # phpinfo 中的 Server API
    expose_php: bool
    phpinfo_path: str | None = "phpinfo.php"
    build_date: str = "Jun 12 2026 09:31:04"
    configure: str = "'./configure' '--build=x86_64-linux-gnu' '--with-apxs2'"
    waf: bool = False
    ini: dict[str, str] = field(default_factory=lambda: {
        "memory_limit": "128M",
        "post_max_size": "8M",
        "max_file_uploads": "20",
        "max_input_nesting_level": "64",
        "session.upload_progress.enabled": "On",
        "enable_post_data_reading": "On",
        "expose_php": "On",
        "display_errors": "Off",
        "open_basedir": "no value",
    })
    expect: str = ""
    expect_key: str = ""      # vulnerable / patched / unknown / not_applicable


PERSONAS: list[Persona] = [
    Persona(
        key="vuln-modphp", port=8801,
        title="PHP 8.4.24 + Apache mod_php（未修复）",
        php_version="8.4.24", server="Apache/2.4.58 (Debian)",
        x_powered_by="PHP/8.4.24", sapi="Apache 2.0 Handler",
        expose_php=True, expect="确认受影响 / P0", expect_key="vulnerable",
    ),
    Persona(
        key="patched-modphp", port=8802,
        title="PHP 8.4.27 + Apache mod_php（已修复）",
        php_version="8.4.27", server="Apache/2.4.58 (Debian)",
        x_powered_by="PHP/8.4.27", sapi="Apache 2.0 Handler",
        expose_php=True, build_date="Oct 21 2026 10:11:12",
        expect="已修复 / 低风险", expect_key="patched",
    ),
    Persona(
        key="vuln-fpm-hidden", port=8803,
        title="PHP 8.3.35 + FPM（隐藏 PHP 头，仅 phpinfo 泄露）",
        php_version="8.3.35", server="nginx/1.24.0",
        x_powered_by=None, sapi="FPM/FastCGI",
        expose_php=False, phpinfo_path="info.php",
        ini={
            "memory_limit": "256M",
            "post_max_size": "64M",
            "max_file_uploads": "20",
            "max_input_nesting_level": "64",
            "session.upload_progress.enabled": "On",
            "enable_post_data_reading": "On",
            "expose_php": "Off",
            "display_errors": "Off",
            "open_basedir": "no value",
        },
        expect="确认受影响 / P0（FPM 默认配置）", expect_key="vulnerable",
    ),
    Persona(
        key="spoof-version", port=8804,
        title="版本造假：头部报 8.4.27，实际 8.4.26 且构建日期早于补丁",
        php_version="8.4.26", server="Apache/2.4.58 (Ubuntu)",
        x_powered_by="PHP/8.4.27", sapi="Apache 2.0 Handler",
        expose_php=True, build_date="Aug 02 2026 14:20:11",
        expect="确认受影响（识别出版本造假）/ P0", expect_key="vulnerable",
    ),
    Persona(
        key="waf-blind", port=8805,
        title="WAF 全站拦截（无任何 PHP 信息）",
        php_version="", server="cloudflare",
        x_powered_by=None, sapi="", expose_php=False,
        phpinfo_path=None, waf=True,
        expect="无法判定 UNKNOWN", expect_key="unknown",
    ),
    Persona(
        key="eol-81", port=8806,
        title="PHP 8.1.31 + mod_php（EOL 分支，无官方修复）",
        php_version="8.1.31", server="Apache/2.4.57 (Debian)",
        x_powered_by="PHP/8.1.31", sapi="Apache 2.0 Handler",
        expose_php=True, build_date="Mar 14 2026 08:02:33",
        expect="确认受影响（EOL）/ P0", expect_key="vulnerable",
    ),
]


def _phpinfo_html(p: Persona) -> str:
    rows = [
        ("PHP Version", p.php_version),
        ("Build Date", p.build_date),
        ("Configure Command", p.configure),
        ("Server API", p.sapi),
        ("Thread Safety", "disabled"),
    ]
    ini_rows = [(k, v) for k, v in p.ini.items()]
    body_rows = "".join(
        f'<tr><td class="e">{k} </td><td class="v">{v}</td></tr>' for k, v in rows
    )
    ini_html = "".join(
        f'<tr><td class="e">{k}</td><td class="v">{v}</td><td class="v">{v}</td></tr>'
        for k, v in ini_rows
    )
    return f"""<!DOCTYPE html>
<html><head><title>phpinfo()</title></head>
<body>
<div class="center">
<table>
<tr><td class="h">PHP Version {p.php_version}</td></tr>
</table>
<table>
{body_rows}
</table>
<h2>Core</h2>
<table>
{ini_html}
</table>
</div>
<div class="foot">PHP Credits — Zend Engine v4</div>
</body></html>"""


def make_handler(p: Persona):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def version_string(self) -> str:
            return p.server or "Server"

        def log_message(self, fmt, *args):  # 静默
            pass

        def _send(self, code: int, body: bytes, ctype="text/html; charset=UTF-8",
                  extra: dict | None = None):
            self.send_response(code)  # 这里会自动带 Server / Date
            if p.expose_php and p.x_powered_by:
                self.send_header("X-Powered-By", p.x_powered_by)
            if p.waf:
                self.send_header("cf-ray", "8a1b2c3d4e5f6a7b-SJC")
            if extra:
                for k, v in extra.items():
                    self.send_header(k, v)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _waf_block(self):
            body = (b"<html><head><title>Access denied</title></head><body>"
                    b"<h1>Access Denied</h1><p>cloudflare ray id: 8a1b2c3d4e5f6a7b</p>"
                    b"</body></html>")
            self._send(403, body)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            if p.waf:
                return self._waf_block()

            path = self.path.split("?")[0]

            if path in ("/", "/index.php", "/index.html"):
                body = (f"<html><head><title>P2S Lab</title></head><body>"
                        f"<h1>P2S-Guard Lab</h1><p>{p.title}</p></body></html>").encode()
                return self._send(200, body)

            if path == "/health":
                return self._send(200, b"ok", "text/plain")

            # phpinfo 暴露
            if p.phpinfo_path and path.lstrip("/") == p.phpinfo_path:
                return self._send(200, _phpinfo_html(p).encode())

            # easter egg 侧信道
            if self.path.startswith("/?=PHPE9568F36"):
                return self._send(200, GIF_1PX, "image/gif")

            # composer.json 泄露（仅 FPM 那台）
            if path == "/composer.json" and p.key == "vuln-fpm-hidden":
                body = (b'{"require": {"php": ">=8.1", "laravel/framework": "^10.0"},'
                        b'"name": "demo/app"}')
                return self._send(200, body, "application/json")

            body = b"<html><body><h1>404 Not Found</h1></body></html>"
            return self._send(404, body)

        def do_POST(self):
            if p.waf:
                return self._waf_block()
            length = int(self.headers.get("Content-Length") or 0)
            # 只读掉请求体，不做任何解析（靶场不实现脆弱逻辑）
            remaining = min(length, 8 * 1024 * 1024)
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)

            sess = "a1b2c3d4e5f6g7h8i9j0k1l2m3"
            body = b"<html><body>upload ok</body></html>"
            return self._send(200, body, extra={"Set-Cookie": f"PHPSESSID={sess}; path=/"})

    return Handler


class LabServer:
    def __init__(self, personas: list[Persona] | None = None):
        self.personas = personas or PERSONAS
        self._servers: list[tuple[Persona, ThreadingHTTPServer, threading.Thread]] = []

    def start(self, wait: float = 0.2) -> list[Persona]:
        for p in self.personas:
            httpd = ThreadingHTTPServer(("127.0.0.1", p.port), make_handler(p))
            httpd.daemon_threads = True
            t = threading.Thread(target=httpd.serve_forever, daemon=True)
            t.start()
            self._servers.append((p, httpd, t))
        time.sleep(wait)
        return self.personas

    def stop(self) -> None:
        for _p, httpd, _t in self._servers:
            try:
                httpd.shutdown()
                httpd.server_close()
            except Exception:
                pass
        self._servers.clear()

    @property
    def targets(self) -> list[str]:
        return [f"http://127.0.0.1:{p.port}" for p in self.personas]
