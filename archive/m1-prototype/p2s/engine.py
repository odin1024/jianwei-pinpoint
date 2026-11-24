"""检测编排

流程（03 文档 3.4）：
    D1 被动 → D2 主动 → D3 主机（可选）→ D4 补丁核验 → D5 受控验证（可选）→ 判定
"""

from __future__ import annotations

import time
from urllib.parse import urlsplit

from . import detectors
from .detectors import d1_passive, d2_active, d3_host, d4_patch, d5_behavior
from .models import DetectionContext, DetectionResult, Evidence, Finding, ScanReport
from .netclient import HttpClient
from .rules import load_ruleset
from .safety import ProbeBudget, RateLimiter
from .verdict import judge


def normalize_target(target: str) -> str:
    t = target.strip()
    if not t:
        return t
    if "://" not in t:
        t = "http://" + t
    return t


class Engine:
    def __init__(
        self,
        ruleset: dict | None = None,
        profile: str = "standard",
        timeout: float = 8.0,
        qps: float = 5.0,
        allow_intrusive: bool = False,
        ticket: str = "",
        ssh_conf: dict | None = None,
        exposure: str = "internet",
        probe_oom: bool = False,
        max_requests: int = 60,
        quiet: bool = False,
    ):
        self.ruleset = ruleset or load_ruleset()
        self.profile = profile
        self.timeout = timeout
        self.qps = qps
        self.allow_intrusive = allow_intrusive
        self.ticket = ticket
        self.ssh_conf = ssh_conf or {}
        self.exposure = exposure
        self.probe_oom = probe_oom
        self.max_requests = max_requests
        self.quiet = quiet
        self.client = HttpClient(timeout=timeout)
        self.limiter = RateLimiter(qps)

    def _log(self, msg: str) -> None:
        if not self.quiet:
            print(msg, flush=True)

    def scan(self, target: str) -> Finding:
        target = normalize_target(target)
        ctx = DetectionContext(
            target=target,
            profile=self.profile,
            allow_intrusive=self.allow_intrusive,
            timeout=self.timeout,
            qps=self.qps,
            user_agent=f"P2S-Guard/1.0 (+authorized-scan; ticket={self.ticket or 'none'})",
            options={"exposure": self.exposure, "probe_oom": self.probe_oom},
        )
        budget = ProbeBudget(max_requests=self.max_requests)
        results: list[DetectionResult] = []
        evidences: list[Evidence] = []
        notes: list[str] = []
        errors: list[str] = []

        # ---- D1 ----
        t0 = time.perf_counter()
        try:
            r1 = d1_passive.run(ctx, self.client, self.limiter, budget)
        except Exception as e:  # noqa: BLE001
            r1 = DetectionResult(detector="D1", errors=[f"{type(e).__name__}: {e}"])
        r1.elapsed_ms = int((time.perf_counter() - t0) * 1000)
        results.append(r1)
        self._log(f"  D1 被动指纹     {'OK' if not r1.errors else 'FAIL'}  "
                  f"{len(r1.evidences)} 条证据  {r1.elapsed_ms}ms")

        # ---- D2 ----
        if self.profile in ("standard", "deep", "forensic"):
            t0 = time.perf_counter()
            try:
                r2 = d2_active.run(ctx, self.client, self.limiter, budget)
            except Exception as e:  # noqa: BLE001
                r2 = DetectionResult(detector="D2", errors=[f"{type(e).__name__}: {e}"])
            r2.elapsed_ms = int((time.perf_counter() - t0) * 1000)
            results.append(r2)
            self._log(f"  D2 主动探测     {'OK' if not r2.errors else 'FAIL'}  "
                      f"{len(r2.evidences)} 条证据  {r2.elapsed_ms}ms")

        # ---- D3 主机核查（仅当提供凭证）----
        if self.ssh_conf.get("host"):
            t0 = time.perf_counter()
            r3 = d3_host.run(ctx, mode="ssh", ssh_conf=self.ssh_conf)
            r3.elapsed_ms = int((time.perf_counter() - t0) * 1000)
            results.append(r3)
            self._log(f"  D3 主机核查     {'OK' if not r3.errors else 'PART'}  "
                      f"{len(r3.evidences)} 条证据  {r3.elapsed_ms}ms")

        # 汇总中间证据
        for r in results:
            evidences.extend(r.evidences)
            notes.extend(r.notes)
            errors.extend(r.errors)

        # ---- D4 补丁核验 ----
        t0 = time.perf_counter()
        r4 = d4_patch.run(ctx, evidences)
        r4.elapsed_ms = int((time.perf_counter() - t0) * 1000)
        results.append(r4)
        evidences.extend(r4.evidences)
        notes.extend(r4.notes)
        errors.extend(r4.errors)
        self._log(f"  D4 补丁核验     OK  {len(r4.evidences)} 条证据  {r4.elapsed_ms}ms")

        # ---- D5 受控验证（双开关）----
        if self.allow_intrusive and self.probe_oom:
            mem = 128
            for e in evidences:
                if e.key == "ini.memory_limit":
                    from .verdict import _to_mb
                    v = _to_mb(str(e.value))
                    if v and v > 0:
                        mem = int(v)
            t0 = time.perf_counter()
            r5 = d5_behavior.run(ctx, self.client, self.limiter, memory_limit_mb=mem)
            r5.elapsed_ms = int((time.perf_counter() - t0) * 1000)
            results.append(r5)
            evidences.extend(r5.evidences)
            notes.extend(r5.notes)
            errors.extend(r5.errors)
            self._log(f"  D5 受控验证     OK  {len(r5.evidences)} 条证据  {r5.elapsed_ms}ms")

        if budget.aborted:
            notes.append(f"⚠ 探测已熔断：{budget.abort_reason}")

        # ---- 判定 ----
        finding = judge(ctx, evidences, self.ruleset, notes, errors)
        finding.notes.append(f"探测预算：已用 {budget.used}/{self.max_requests} 次请求")

        # 去重 notes
        seen = set()
        uniq = []
        for n in finding.notes:
            if n in seen:
                continue
            seen.add(n)
            uniq.append(n)
        finding.notes = uniq
        finding.errors = list(dict.fromkeys(finding.errors))
        return finding

    def scan_many(self, targets: list[str], progress=None) -> ScanReport:
        report = ScanReport(
            ruleset_version=self.ruleset.get("version", "unknown"),
            profile=self.profile,
        )
        for i, t in enumerate(targets, 1):
            if progress:
                progress(i, len(targets), t)
            else:
                self._log(f"[{i}/{len(targets)}] {t}")
            f = self.scan(t)
            report.add(f)
            if not progress:
                self._log(f"      → {f.verdict.label} / {f.risk_score} / {f.grade.value}")
        report.finished_at = time.time()
        return report
