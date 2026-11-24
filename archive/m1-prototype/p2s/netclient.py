"""极简 HTTP 客户端（纯标准库）

为什么不用 requests/httpx：
    本项目要求零第三方依赖，客户内网/应急现场可直接运行。
    同时 http.client 能拿到保序的原始响应头，便于做指纹分析。
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

DEFAULT_UA = "P2S-Guard/1.0 (+authorized-scan)"


@dataclass(slots=True)
class HttpResponse:
    url: str
    method: str
    status: int = 0
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    elapsed_ms: int = 0
    error: str | None = None
    truncated: bool = False

    def header(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None

    def header_values(self, name: str) -> list[str]:
        low = name.lower()
        return [v for k, v in self.headers if k.lower() == low]

    @property
    def text(self) -> str:
        enc = "utf-8"
        for k, v in self.headers:
            if k.lower() == "content-type" and "charset=" in v.lower():
                cand = v.lower().split("charset=")[-1].split(";")[0].strip()
                if cand:
                    enc = cand
                break
        try:
            return self.body.decode(enc, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 400

    @property
    def server_error(self) -> bool:
        return self.status >= 500 or (self.error is not None and "reset" in (self.error or "").lower())


class HttpClient:
    def __init__(self, timeout: float = 8.0, max_body: int = 512 * 1024,
                 user_agent: str = DEFAULT_UA, verify_tls: bool = False):
        self.timeout = timeout
        self.max_body = max_body
        self.user_agent = user_agent
        self.verify_tls = verify_tls
        self._ssl_ctx: ssl.SSLContext | None = None

    def _ctx(self) -> ssl.SSLContext:
        if self._ssl_ctx is None:
            ctx = ssl.create_default_context()
            if not self.verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self._ssl_ctx = ctx
        return self._ssl_ctx

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        follow_redirects: bool = False,
        host_header: str | None = None,
    ) -> HttpResponse:
        parts = urlsplit(url)
        scheme = parts.scheme or "http"
        host = parts.hostname or ""
        port = parts.port or (443 if scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        resp = HttpResponse(url=url, method=method)
        if not host:
            resp.error = "invalid url"
            return resp

        hdrs = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        if host_header:
            hdrs["Host"] = host_header
        if headers:
            hdrs.update(headers)

        conn: http.client.HTTPConnection | None = None
        started = time.perf_counter()
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(
                    host, port, timeout=self.timeout, context=self._ctx()
                )
            else:
                conn = http.client.HTTPConnection(host, port, timeout=self.timeout)

            conn.request(method, path, body=body, headers=hdrs)
            raw = conn.getresponse()

            resp.status = raw.status
            resp.headers = raw.getheaders()

            if method != "HEAD":
                chunks: list[bytes] = []
                size = 0
                while True:
                    chunk = raw.read(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= self.max_body:
                        resp.truncated = True
                        break
                resp.body = b"".join(chunks)

            if follow_redirects and resp.status in (301, 302, 303, 307, 308):
                loc = resp.header("location")
                if loc:
                    from urllib.parse import urljoin
                    return self.request(urljoin(url, loc), "GET", headers, None,
                                        follow_redirects=True, host_header=host_header)

        except socket.timeout:
            resp.error = "timeout"
        except ConnectionResetError:
            resp.error = "connection reset"
        except ConnectionRefusedError:
            resp.error = "connection refused"
        except ssl.SSLError as e:
            resp.error = f"tls error: {e}"
        except socket.gaierror as e:
            resp.error = f"dns error: {e}"
        except (BrokenPipeError, http.client.HTTPException, OSError) as e:
            resp.error = f"{type(e).__name__}: {e}"
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            resp.elapsed_ms = int((time.perf_counter() - started) * 1000)

        return resp
