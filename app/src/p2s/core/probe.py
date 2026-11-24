"""主动安全探测（L2）。

设计红线：
  1. 只发送"无害请求"——仅能触发可观测差异，绝不发送利用载荷
     （不发送 <?php 代码、不发送伪造 zval、不做 OOM 洪泛）
  2. 探针尺寸远小于已知会触发误报的场景（Assetnote 在已修补版本上
     用 1MiB~20MiB 探针 + 低 memory_limit 复现过误报）
  3. 全程只读探测，不写入任何数据

判定采用"控制请求 vs 探测请求"的差分，而不是单次响应判断。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

import httpx

from .fingerprint import Fingerprint, fingerprint
from .httpclient import make_client
from .versions import Verdict, classify

#: 探针尺寸档位（字节）。刻意保持保守。
PROBE_SIZES = {
    "gentle": {"headers": 400, "header_size": 120, "array_depth": 5, "array_width": 8},
    "standard": {"headers": 1200, "header_size": 200, "array_depth": 8, "array_width": 16},
}


@dataclass
class ProbeResult:
    """一次探测的结果。"""

    url: str
    probe: str
    status_code: Optional[int] = None
    control_status: Optional[int] = None
    body_len: Optional[int] = None
    control_body_len: Optional[int] = None
    payload_bytes: int = 0
    elapsed_ms: Optional[int] = None
    oom_signature: bool = False
    empty_500: bool = False
    worker_restart_hint: bool = False
    error: Optional[str] = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Assessment:
    """对单个目标的综合评估。"""

    url: str
    fingerprint: Fingerprint
    version_verdict: Verdict
    probe_verdict: str = "unknown"          # vulnerable | likely_patched | suspect | unknown | skipped
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    probes: list[ProbeResult] = field(default_factory=list)

    @property
    def risk(self) -> str:
        if self.probe_verdict == "vulnerable":
            return "critical"
        if self.version_verdict.status == "vulnerable":
            return "critical"
        if self.probe_verdict == "suspect":
            return "high"
        if self.version_verdict.status in ("eol_unpatchable", "eol_backport_available"):
            return "high"
        if self.probe_verdict == "likely_patched":
            return "low"
        return "unknown"

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "risk": self.risk,
            "fingerprint": self.fingerprint.to_dict(),
            "version_verdict": self.version_verdict.to_dict(),
            "probe_verdict": self.probe_verdict,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "probes": [p.to_dict() for p in self.probes],
        }


def _boundary(tag: str) -> str:
    return f"----p2s{tag}7f3a9c"


def build_control_request(boundary: str) -> bytes:
    """控制请求：42 字节级别的最小 multipart，作为差分基线。"""
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="p2s_ctl"\r\n\r\n'
        f"x\r\n"
        f"--{boundary}--\r\n"
    )
    return body.encode()


def build_header_amplification(boundary: str, headers: int = 400, header_size: int = 120) -> bytes:
    """策略 2（温和版）：单个 multipart 分段内塞入大量自定义 header。

    PHP 内部表示（zend_string + HashTable bucket）的内存开销约为线上体积的 3~5 倍，
    这是官方公告披露的三条 OOM 路径之一。此处刻意使用保守尺寸。
    """
    part = f"--{boundary}\r\n"
    part += 'Content-Disposition: form-data; name="p2s_hdr"; filename="a"\r\n'
    for i in range(headers):
        part += f"X-Pad-{i}: {'A' * header_size}\r\n"
    part += "\r\nZ\r\n"
    part += f"--{boundary}--\r\n"
    return part.encode()


def build_nested_arrays(boundary: str, depth: int = 5, width: int = 8) -> bytes:
    """策略 3（温和版）：空文件控件 + 嵌套字段名，放大 PHP 数组构造开销。

    空文件控件不计入 max_file_uploads，却仍会生成完整的文件元数据数组。
    """
    parts = []
    for i in range(width):
        name = "p2s_f"
        for d in range(depth):
            name += f"[{d}]"
        name += f"[{i}]"
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"; filename=""\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        )
    return ("".join(parts) + f"--{boundary}--\r\n").encode()


_OOM_RE = ("Allowed memory size", "exhausted", "Allowed memory")


def _send(
    client: httpx.Client, url: str, boundary: str, body: bytes, timeout: float
) -> tuple[Optional[int], Optional[int], Optional[str], Optional[int]]:
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "User-Agent": "p2s-probe/0.1 (authorized-assessment)",
        "Connection": "close",
    }
    try:
        resp = client.post(url, content=body, headers=headers, timeout=timeout)
        return resp.status_code, len(resp.content), resp.text[:4000], int(
            resp.elapsed.total_seconds() * 1000
        )
    except Exception as exc:  # noqa: BLE001
        return None, None, f"{type(exc).__name__}: {exc}", None


#: 探针名 → 策略。以前 "gentle"/"standard" 会落到 else 分支直接返回，
#: 导致「主动探测」只发了一个控制请求、什么都没探测到（v0.5.0 的真实 bug）。
PROBE_STRATEGY = {
    "gentle": "header_amplification",
    "standard": "header_amplification",
    "header_amplification": "header_amplification",
    "nested_arrays": "nested_arrays",
}


def probe_once(
    url: str, probe: str = "gentle", *, timeout: float = 20.0, verify_tls: bool = True
) -> ProbeResult:
    """对单个 URL 执行一次差分探测：先发控制请求建基线，再发探针比差异。"""
    cfg = PROBE_SIZES.get(probe, PROBE_SIZES["gentle"])
    result = ProbeResult(url=url, probe=probe)
    strategy = PROBE_STRATEGY.get(probe)
    if strategy is None:
        result.notes.append(f"未知探针类型 {probe!r}，跳过")
        return result

    with make_client(follow_redirects=False, timeout=timeout, verify=verify_tls) as client:
        cb = _boundary("ctl")
        c_status, c_len, c_text, _ = _send(client, url, cb, build_control_request(cb), timeout)
        result.control_status = c_status
        result.control_body_len = c_len

        if strategy == "header_amplification":
            b = _boundary("hdr")
            payload = build_header_amplification(b, cfg["headers"], cfg["header_size"])
        else:
            b = _boundary("arr")
            payload = build_nested_arrays(b, cfg["array_depth"], cfg["array_width"])

        status, blen, text, ms = _send(client, url, b, payload, timeout)
        result.status_code = status
        result.body_len = blen
        result.elapsed_ms = ms
        result.payload_bytes = len(payload)

        if text and any(sig in text for sig in _OOM_RE):
            result.oom_signature = True
        if status == 500 and c_status is not None and c_status != 500:
            if not text or len(text.strip()) == 0:
                result.empty_500 = True
        if ms is not None and ms > timeout * 1000 * 0.8:
            result.worker_restart_hint = True
    return result


def assess(
    url: str, *, timeout: float = 15.0, do_probe: bool = True, verify_tls: bool = True
) -> Assessment:
    """对目标做"指纹 -> 版本判定 -> 主动探测"的完整评估。"""
    fp = fingerprint(url, timeout=timeout, verify_tls=verify_tls)
    vv = classify(fp.php_version)
    asm = Assessment(url=url, fingerprint=fp, version_verdict=vv)

    # 证据 1：版本横幅
    if vv.status == "vulnerable":
        asm.evidence.append(f"版本横幅显示 PHP {vv.version}，低于修复基线 {vv.fixed_release}")
    elif vv.status == "patched":
        asm.evidence.append(f"版本横幅显示 PHP {vv.version}，已达修复基线 {vv.fixed_release}")

    # 证据 2：SAPI
    if fp.sapi:
        asm.evidence.append(f"SAPI 判定为 {fp.sapi_label}（信号: {', '.join(fp.signals)}）")

    if not do_probe:
        asm.probe_verdict = "skipped" if fp.php_version else "unknown"
        asm.confidence = 0.9 if fp.php_version else 0.3
        asm.remediation = _remediation(vv)
        return asm

    if not fp.ok:
        asm.probe_verdict = "unknown"
        asm.confidence = 0.2
        asm.evidence.append(f"目标不可达或指纹失败: {fp.error}")
        return asm

    # 版本已修复 -> 仍做一次温和探测做交叉验证（置信度不足时不轻易下结论）
    for pname in ("gentle",):
        pr = probe_once(url, pname, timeout=timeout, verify_tls=verify_tls)
        asm.probes.append(pr)
        if pr.oom_signature:
            asm.evidence.append("探测响应出现 PHP 内存耗尽错误")
        if pr.empty_500:
            asm.evidence.append(
                f"差分空 500（控制请求 {pr.control_status} -> 探测请求 {pr.status_code}），"
                "疑似 FPM worker 崩溃"
            )
        if pr.worker_restart_hint:
            asm.evidence.append("探测响应耗时接近超时，疑似 worker 重启或卡死")

    signals = sum(1 for p in asm.probes if p.oom_signature or p.empty_500)
    if signals >= 1 and vv.status in ("vulnerable", "unknown", "eol_unpatchable"):
        asm.probe_verdict = "vulnerable"
        asm.confidence = 0.9 if signals >= 2 else 0.7
    elif signals >= 1 and vv.status == "patched":
        asm.probe_verdict = "suspect"
        asm.confidence = 0.5
        asm.evidence.append(
            "版本看似已修复但探测出现差异 —— 可能是低 memory_limit 导致的已知误报场景，"
            "请人工复核实际 memory_limit 与 max_multipart_body_parts"
        )
    elif vv.status == "vulnerable":
        asm.probe_verdict = "vulnerable"
        asm.confidence = 0.8
    elif vv.status == "patched":
        asm.probe_verdict = "likely_patched"
        asm.confidence = 0.75
    else:
        asm.probe_verdict = "unknown"
        asm.confidence = 0.3

    asm.remediation = _remediation(vv)
    return asm


def _remediation(vv: Verdict) -> list[str]:
    if vv.status == "patched":
        return [
            f"PHP {vv.version} 已达修复基线 {vv.fixed_release}，保持版本领先",
            "按 PHP 2026-10-23 公告，建议保持 session.upload_progress.enabled=0 直到下次常规修复版",
        ]
    if vv.status == "vulnerable":
        return [
            f"立即升级到 PHP {vv.fixed_release}（或更高），升级后重启所有 PHP worker",
            "若暂时无法升级：memory_limit=-1（php_admin_value 级别）+ post_max_size 收紧至 8M/32M",
            "设置 session.upload_progress.enabled=0（写在 php.ini / FPM pool），并重启 worker",
            "PHP 8.5 另需设置 fatal_error_backtraces=0 并重启 worker",
            "在 WAF / 反向代理层限制解码后请求体大小、字段数、分段数、header 数、嵌套深度",
        ]
    if vv.status in ("eol_unpatchable", "eol_backport_available"):
        return [
            f"PHP {vv.branch} 已停止官方安全维护，必须升级到 8.3+",
            "如无法立即升级，使用发行版/LTS 厂商回补包；PHP 团队为 7.4/8.0/8.1 提供最小源码回补",
            "在升级完成前，保持 session.upload_progress.enabled=0 与 memory_limit 收紧",
        ]
    return ["无法确定版本，请人工确认目标 PHP 版本与 SAPI"]
