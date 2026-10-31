"""计划任务失败重试的决策逻辑测试。"""
from __future__ import annotations

from datetime import datetime

from p2s.console.ops_api import next_retry


def _cfg(**kw):
    base = {"retry_count": 0, "retry_max": 1, "retry_delay_minutes": 5}
    base.update(kw)
    return base


def test_success_resets():
    got = next_retry(_cfg(retry_count=1), "done")
    assert got == {"retry_count": 0, "next_retry_at": ""}


def test_failure_schedules_retry():
    now = datetime(2026, 10, 31, 10, 0, 0)
    got = next_retry(_cfg(), "failed", now)
    assert got["retry_count"] == 1
    assert got["next_retry_at"] == "2026-10-31T10:05:00"


def test_failure_when_exhausted():
    got = next_retry(_cfg(retry_count=1, retry_max=1), "failed")
    assert got == {"retry_count": 0, "next_retry_at": ""}


def test_retry_max_zero_never_retries():
    got = next_retry(_cfg(retry_max=0), "failed")
    assert got == {"retry_count": 0, "next_retry_at": ""}


def test_custom_delay():
    now = datetime(2026, 10, 31, 10, 0, 0)
    got = next_retry(_cfg(retry_delay_minutes=30), "failed", now)
    assert got["next_retry_at"] == "2026-10-31T10:30:00"


def test_running_is_noop():
    assert next_retry(_cfg(), "running") == {}


def test_canceled_counts_as_failure():
    now = datetime(2026, 10, 31, 10, 0, 0)
    got = next_retry(_cfg(), "canceled", now)
    assert got["retry_count"] == 1


def test_multiple_retries_increment():
    now = datetime(2026, 10, 31, 10, 0, 0)
    got = next_retry(_cfg(retry_count=1, retry_max=3), "failed", now)
    assert got["retry_count"] == 2
