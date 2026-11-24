"""安全护栏：限速、预算、熔断、授权记录

03 文档 3.3.3 指出：熔断不是性能优化，是法律风险控制。
在 PHP2Shell 场景下，扫描器把目标 PHP worker 打崩是完全可能的。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


class TokenBucket:
    """按 host 的令牌桶限速。"""

    def __init__(self, rate: float = 5.0, burst: float | None = None):
        self.rate = max(rate, 0.1)
        self.capacity = burst if burst is not None else max(self.rate, 1.0)
        self.tokens = self.capacity
        self.updated = time.monotonic()

    def take(self, n: float = 1.0) -> float:
        """取令牌，返回需要等待的秒数（0 表示可立即执行）。"""
        now = time.monotonic()
        elapsed = now - self.updated
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.updated = now
        if self.tokens >= n:
            self.tokens -= n
            return 0.0
        deficit = n - self.tokens
        self.tokens = 0.0
        return deficit / self.rate


class RateLimiter:
    def __init__(self, qps: float = 5.0):
        self.qps = qps
        self._buckets: dict[str, TokenBucket] = {}

    def acquire(self, host: str) -> None:
        bucket = self._buckets.setdefault(host, TokenBucket(self.qps))
        wait = bucket.take()
        if wait > 0:
            time.sleep(wait)


@dataclass
class ProbeBudget:
    """单个目标的探测预算（04 文档 4.3）。"""

    max_requests: int = 60
    max_error_rate: float = 0.30
    min_samples: int = 6

    used: int = 0
    errors: int = 0
    aborted: bool = False
    abort_reason: str = ""
    _marks: list[int] = field(default_factory=list)

    def consume(self) -> bool:
        if self.aborted:
            return False
        if self.used >= self.max_requests:
            self.abort("探测请求数达到预算上限")
            return False
        self.used += 1
        return True

    def record(self, is_error: bool) -> None:
        self._marks.append(1 if is_error else 0)
        if is_error:
            self.errors += 1
        if len(self._marks) >= self.min_samples:
            recent = self._marks[-self.min_samples:]
            rate = sum(recent) / len(recent)
            if rate > self.max_error_rate:
                self.abort(
                    f"最近 {self.min_samples} 次请求错误率 {rate:.0%} 超过阈值 "
                    f"{self.max_error_rate:.0%}，疑似影响目标可用性"
                )

    def abort(self, reason: str) -> None:
        self.aborted = True
        self.abort_reason = reason

    @property
    def remaining(self) -> int:
        return max(0, self.max_requests - self.used)


@dataclass
class Authorization:
    """授权闸：没有授权凭据不允许执行任何探测。"""

    ticket: str = ""
    acknowledged: bool = False

    def check(self) -> tuple[bool, str]:
        if not self.acknowledged:
            return False, "未确认授权（需 --i-have-authorization）"
        if not self.ticket.strip():
            return False, "缺少授权凭据（需 --ticket <工单号/合同号>）"
        return True, f"授权凭据：{self.ticket}"
