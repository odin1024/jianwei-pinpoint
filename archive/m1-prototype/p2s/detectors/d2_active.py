"""D2 主动安全探测（非破坏性）

红线（04 文档 4.1）：
    只发「合法客户端可能发出的请求」，不构造畸形到足以触发内存缺陷的请求。
    超大字段名 / 超多 header / 深层嵌套 / 空文件控件洪水 → 属于 D5，需授权。
"""

from __future__ import annotations

import uuid
from urllib.parse import urlsplit

from ..models import Confidence, DetectionContext, DetectionResult, Evidence
from ..netclient import HttpClient
from ..safety import ProbeBudget, RateLimiter

# 历史 easter egg 标识（多数现代配置已失效，仅作兼容保留）
EASTER_EGGS = [
    "PHPE9568F36-D428-11d2-A769-00AA001ACF42",  # Zend logo
    "PHPE9568F34-D428-11d2-A769-00AA001ACF42",  # PHP logo
]


def _multipart_probe_body(boundary: str, field: str = "p2s_probe") -> bytes:
    """构造一个最小合法 multipart：一个普通字段 + 一个极小的内存文件。

    注意：这里刻意只放 1 个 part、1 个文件、字段值全为随机 ASCII，
    不含任何结构化/序列化数据 —— 检测与攻击的分界线就在这里。
    """
    parts = [
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"p2s-{uuid.uuid4().hex[:8]}\r\n",
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="p2s.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
        f"p2s-guard-probe\r\n",
        f"--{boundary}--\r\n",
    ]
    return "".join(parts).encode("ascii")


def run(ctx: DetectionContext, client: HttpClient,
        limiter: RateLimiter, budget: ProbeBudget) -> DetectionResult:
    res = DetectionResult(detector="D2")
    host = urlsplit(ctx.target).hostname or ctx.target
    base = ctx.target.rstrip("/")

    # ---- 1. 上传进度 / multipart 可用性探针 ----
    if budget.consume():
        limiter.acquire(host)
        boundary = "----p2s" + uuid.uuid4().hex[:16]
        body = _multipart_probe_body(boundary)
        r = client.request(
            ctx.target, "POST",
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        budget.record(r.error is not None or r.status >= 500)

        if r.status in (200, 201, 204, 302, 303):
            res.add(Evidence("D2", "behavior", "http.multipart_accepted", True,
                             Confidence.MEDIUM,
                             "POST multipart 被接受（说明 PHP 会解析 multipart 请求体）",
                             "behavior", f"{ctx.target} POST multipart"))
            cookies = " ".join(r.header_values("set-cookie"))
            if "PHPSESSID" in cookies.upper():
                res.add(Evidence("D2", "behavior", "ini.session.upload_progress.enabled",
                                 "On(推断)", Confidence.LOW,
                                 "上传进度探针触发 PHPSESSID 下发，推断 session.upload_progress 开启",
                                 "behavior", cookies[:200]))
                res.notes.append(
                    "推断 session.upload_progress.enabled=On（已验证的 109619 producer 之一）"
                )
        elif r.status in (405, 501):
            res.add(Evidence("D2", "behavior", "http.multipart_accepted", False,
                             Confidence.MEDIUM, f"POST 不被接受（HTTP {r.status}）",
                             "behavior", ctx.target))
        elif r.status == 403:
            res.add(Evidence("D2", "behavior", "http.multipart_accepted", "blocked",
                             Confidence.LOW, "multipart POST 被前置防护拦截（403）",
                             "behavior", ctx.target))
            res.notes.append("POST 被 WAF 拦截，主动探测能力受限，结论主要依赖 D3/D4")

    # ---- 2. 历史 easter egg 侧信道 ----
    for egg in EASTER_EGGS[:1]:
        if not budget.consume():
            break
        limiter.acquire(host)
        r = client.request(f"{base}/?={egg}", "GET")
        budget.record(False)
        ctype = (r.header("content-type") or "").lower()
        if r.status == 200 and ctype.startswith("image/"):
            res.add(Evidence("D2", "behavior", "ini.expose_php", "On", Confidence.LOW,
                             "easter egg 返回图片，说明 expose_php=On 且未禁用该侧信道",
                             "behavior", f"{base}/?={egg}"))
            break

    # ---- 3. 错误页 PHP 特征（判断 display_errors 与运行时存在）----
    if budget.consume():
        limiter.acquire(host)
        r = client.request(f"{base}/p2s-not-exist-{uuid.uuid4().hex[:8]}", "GET")
        budget.record(False)
        text = r.text[:8000]
        if "Warning:" in text or "Fatal error:" in text or "Notice:" in text:
            res.add(Evidence("D2", "behavior", "ini.display_errors", "On", Confidence.MEDIUM,
                             "404 页面泄露 PHP 错误信息，说明 display_errors=On",
                             "behavior", r.url))
            res.notes.append("⚠ display_errors=On：错误信息外泄，同时会放大探测噪音")
        # 错误文案里的 "in ... on line N" 是 PHP 运行时确实在处理的证据
        if "on line" in text and (r.status >= 400):
            res.add(Evidence("D2", "behavior", "php.present", True, Confidence.LOW,
                             "错误页含 PHP 运行时特征", "behavior", r.url))

    # ---- 4. HEAD vs GET 差异（辅助判断前置代理/缓存）----
    if budget.consume():
        limiter.acquire(host)
        g = client.request(ctx.target, "GET")
        limiter.acquire(host)
        h = client.request(ctx.target, "HEAD")
        budget.record(False)
        if g.status and h.status and h.status != g.status and h.status not in (0, 405):
            res.notes.append(
                f"HEAD({h.status}) 与 GET({g.status}) 状态码不一致，"
                f"可能存在前置代理/缓存层，远程指纹可信度下调"
            )

    return res
