"""P2S-Guard 核心数据模型

设计原则（见 03 文档 1.2）：
  引擎内部流转的是 Evidence，Finding 只是证据的聚合视图。
  Detector 不允许直接产出 Verdict。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    @property
    def score(self) -> float:
        return {
            "confirmed": 1.0,
            "high": 0.85,
            "medium": 0.6,
            "low": 0.35,
            "unknown": 0.0,
        }[self.value]

    @property
    def label(self) -> str:
        return {
            "confirmed": "确认",
            "high": "高度可能",
            "medium": "疑似",
            "low": "弱线索",
            "unknown": "未知",
        }[self.value]


class Verdict(str, Enum):
    VULNERABLE = "vulnerable"
    LIKELY_VULNERABLE = "likely_vulnerable"
    PATCHED = "patched"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"

    @property
    def label(self) -> str:
        return {
            "vulnerable": "确认受影响",
            "likely_vulnerable": "疑似受影响",
            "patched": "已修复",
            "not_applicable": "不适用",
            "unknown": "无法判定",
        }[self.value]

    @property
    def color(self) -> str:
        return {
            "vulnerable": "red",
            "likely_vulnerable": "yellow",
            "patched": "green",
            "not_applicable": "gray",
            "unknown": "magenta",
        }[self.value]


class Grade(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    NONE = "NONE"

    @property
    def color(self) -> str:
        return {
            "P0": "red",
            "P1": "yellow",
            "P2": "cyan",
            "P3": "gray",
            "NONE": "green",
        }[self.value]


# 证据来源优先级（04 文档 3.5.1）
SOURCE_PRECEDENCE: dict[str, int] = {
    "changelog": 100,
    "binary": 95,
    "source": 95,
    "ini": 80,
    "sapi": 80,
    "behavior": 75,
    "version_local": 70,
    "version_remote": 30,
    "http_header": 25,
    "log": 60,
    "process": 65,
}


@dataclass(slots=True)
class Evidence:
    detector: str
    kind: str
    key: str
    value: Any
    confidence: Confidence
    method: str = ""
    source: str = "version_remote"
    source_ref: str = ""
    raw: str | None = None
    weight: float = 1.0
    collected_at: float = field(default_factory=time.time)

    @property
    def precedence(self) -> int:
        return SOURCE_PRECEDENCE.get(self.source, 10)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["confidence"] = self.confidence.value
        return d


@dataclass(slots=True)
class DetectionContext:
    target: str
    profile: str = "standard"
    allow_intrusive: bool = False
    timeout: float = 8.0
    qps: float = 5.0
    user_agent: str = (
        "P2S-Guard/1.0 (+authorized-scan; https://example.local/p2s)"
    )
    options: dict[str, Any] = field(default_factory=dict)
    # 运行期填充
    findings_meta: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DetectionResult:
    detector: str
    evidences: list[Evidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    elapsed_ms: int = 0

    def add(self, ev: Evidence) -> None:
        self.evidences.append(ev)

    def err(self, msg: str) -> None:
        self.errors.append(msg)


@dataclass(slots=True)
class Finding:
    target: str
    verdict: Verdict
    confidence: Confidence
    risk_score: int
    grade: Grade
    reason: str
    sapi: str | None = None
    php_version: str | None = None
    factors: dict[str, float] = field(default_factory=dict)
    evidences: list[Evidence] = field(default_factory=list)
    remediation: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanned_at: float = field(default_factory=time.time)
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "verdict": self.verdict.value,
            "verdict_label": self.verdict.label,
            "confidence": self.confidence.value,
            "risk_score": self.risk_score,
            "grade": self.grade.value,
            "reason": self.reason,
            "php_version": self.php_version,
            "sapi": self.sapi,
            "factors": self.factors,
            "evidence": [e.to_dict() for e in self.evidences],
            "remediation": self.remediation,
            "notes": self.notes,
            "errors": self.errors,
            "scanned_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.scanned_at)
            ),
        }


@dataclass(slots=True)
class ScanReport:
    findings: list[Finding] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    ruleset_version: str = ""
    profile: str = "standard"

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    @property
    def counts(self) -> dict[str, int]:
        c = {v.value: 0 for v in Verdict}
        for f in self.findings:
            c[f.verdict.value] += 1
        return c

    def to_dict(self) -> dict:
        return {
            "tool": "P2S-Guard",
            "version": "1.0.0",
            "ruleset_version": self.ruleset_version,
            "profile": self.profile,
            "started_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.started_at)
            ),
            "finished_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.finished_at or time.time())
            ),
            "duration_s": round((self.finished_at or time.time()) - self.started_at, 2),
            "summary": self.counts,
            "findings": [f.to_dict() for f in self.findings],
        }
