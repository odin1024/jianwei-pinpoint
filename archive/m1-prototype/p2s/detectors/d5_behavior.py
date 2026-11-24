"""D5 受控行为验证（默认关闭，双开关 + 健康检查）

原理：补丁前后 OOM 行为存在可观测差异。
风险：本层会主动让目标 PHP worker 达到 memory_limit，本质是一次 DoS 强度动作。

因此设置三道闸（04 文档 7.2）：
    1. --allow-intrusive
    2. --probe-oom（二次确认）
    3. 前置/后置健康检查，任一失败立即中止并告警

注意：探针只发送随机 ASCII 填充，不含任何结构化数据、指针或序列化内容。
      检测与攻击的分界线就在这里。
"""

from __future__ import annotations

import random
import string
import time
import uuid
from urllib.parse import urlsplit

from ..models import Confidence, DetectionContext, DetectionResult, Evidence
from ..netclient import HttpClient
from ..safety import RateLimiter

MAX_FIELD_NAME = 4 * 1024 * 1024   # 硬上限，绝不放大


def _rand_ascii(n: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choices(alphabet, k=n))


def _health(client: HttpClient, url: str, times: int = 3) -> tuple[bool, list[int]]:
    codes: list[int] = []
    for _ in range(times):
        r = client.request(url, "GET", headers={"Cache-Control": "no-cache"})
        codes.append(r.status)
        time.sleep(0.1)
    ok = all(200 <= c < 400 for c in codes)
    return ok, codes


def run(ctx: DetectionContext, client: HttpClient, limiter: RateLimiter,
        memory_limit_mb: int = 128) -> DetectionResult:
    res = DetectionResult(detector="D5")
    host = urlsplit(ctx.target).hostname or ctx.target

    if not ctx.allow_intrusive or not ctx.options.get("probe_oom"):
        res.notes.append("D5 未启用（需 --allow-intrusive 且 --probe-oom 双重确认）")
        return res

    ok, before = _health(client, ctx.target)
    res.notes.append(f"前置健康检查：{before}")
    if not ok:
        res.err("前置健康检查未通过，拒绝执行 OOM 探针")
        return res

    # 字段名长度按 memory_limit 估算（1.2 倍），并受硬上限约束
    target_len = min(int(memory_limit_mb * 1024 * 1024 * 1.2), MAX_FIELD_NAME)
    boundary = "----p2s" + uuid.uuid4().hex[:16]
    name = _rand_ascii(target_len)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
        f"1\r\n"
        f"--{boundary}--\r\n"
    ).encode("ascii")

    limiter.acquire(host)
    t0 = time.perf_counter()
    r = client.request(
        ctx.target, "POST",
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        },
        body=body,
    )
    elapsed = int((time.perf_counter() - t0) * 1000)

    res.add(Evidence(
        "D5", "behavior", "d5.oom_probe",
        {"status": r.status, "error": r.error, "elapsed_ms": elapsed,
         "field_name_len": target_len},
        Confidence.MEDIUM,
        "单次受控 OOM 探针（仅一次，无重试）",
        "behavior", f"{ctx.target} POST multipart len={len(body)}",
    ))

    # 后置健康检查
    time.sleep(2)
    ok2, after = _health(client, ctx.target)
    res.add(Evidence(
        "D5", "behavior", "d5.post_health", {"ok": ok2, "codes": after},
        Confidence.CONFIRMED if ok2 else Confidence.HIGH,
        "后置健康检查", "behavior", str(after),
    ))
    res.notes.append(f"后置健康检查：{after}")

    if not ok2:
        res.err("⚠ 后置健康检查失败：疑似影响目标可用性，已立即停止后续探测，请人工介入")
        return res

    # 行为解读（仅作辅助证据，不单独定性）
    if r.error and "reset" in r.error.lower():
        res.add(Evidence(
            "D5", "behavior", "d5.signature", "worker_exit",
            Confidence.LOW,
            "探针后连接被重置，可能触发硬 OOM 退出（补丁后特征）或 worker 崩溃",
            "behavior", r.error,
        ))
    elif r.status == 500 and "unknown on line 0" in r.text.lower():
        res.add(Evidence(
            "D5", "behavior", "d5.signature", "startup_oom",
            Confidence.MEDIUM,
            "响应含启动期 OOM 特征（Unknown on line 0），指向未修复路径",
            "behavior", r.text[:200],
        ))
    else:
        res.add(Evidence(
            "D5", "behavior", "d5.signature", "inconclusive",
            Confidence.UNKNOWN, "行为差异不显著，无法据此判定补丁状态",
            "behavior", f"HTTP {r.status}",
        ))

    res.notes.append(
        "D5 结果仅作辅助证据：受 memory_limit、worker 模型、前端代理影响，不能单独定性"
    )
    return res
