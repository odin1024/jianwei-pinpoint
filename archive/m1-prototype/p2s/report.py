"""报告渲染：终端 / Markdown / JSON"""

from __future__ import annotations

import json
import os
import time
import unicodedata
from typing import Iterable

from .models import Finding, ScanReport, Verdict


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"

    MAP = {
        "red": RED, "green": GREEN, "yellow": YELLOW,
        "blue": BLUE, "magenta": MAGENTA, "cyan": CYAN, "gray": GRAY,
    }


def enable_ansi() -> None:
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass


def _paint(text: str, color: str | None, on: bool) -> str:
    if not on or not color:
        return text
    return f"{C.MAP.get(color, '')}{text}{C.RESET}"


def _w(s: str) -> int:
    """近似显示宽度（CJK 记 2）。"""
    n = 0
    for ch in str(s):
        n += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return n


def _pad(s: str, width: int) -> str:
    s = str(s)
    diff = width - _w(s)
    return s + " " * max(0, diff)


def _hr(char: str = "-", width: int = 74) -> str:
    return char * width


def _score_bar(score: int, width: int = 20) -> str:
    filled = int(round(score / 100 * width))
    return "[" + "#" * filled + "." * (width - filled) + f"] {score:>3}/100"


def _short(v, limit: int = 68) -> str:
    s = str(v)
    s = s.replace("\n", " ")
    return s if len(s) <= limit else s[: limit - 1] + "…"


def render_terminal(report: ScanReport, color: bool = True, show_evidence: bool = True) -> str:
    out: list[str] = []
    p = lambda s, c=None: _paint(s, c, color)  # noqa: E731

    out.append("")
    out.append(p(_hr("="), "cyan"))
    out.append(p("  P2S-Guard 1.0   PHP2Shell 检测报告", "bold"))
    out.append(
        f"  规则库 {report.ruleset_version}   画像 {report.profile}   "
        f"目标 {len(report.findings)} 个   耗时 "
        f"{(report.finished_at or time.time()) - report.started_at:.1f}s"
    )
    out.append(p(_hr("="), "cyan"))

    counts = report.counts
    summary = "  ".join(
        f"{k}:{v}" for k, v in counts.items() if v
    ) or "无结果"
    out.append("  结论分布  " + summary)
    out.append("")

    for i, f in enumerate(report.findings, 1):
        v_color = f.verdict.color
        out.append(p(f"[{i}] {f.target}", "bold"))
        out.append(
            "    结论   "
            + p(f"{f.verdict.label}", v_color)
            + f"   (置信度：{f.confidence.label})"
            + "   等级 "
            + p(f.grade.value, f.grade.color)
        )
        out.append("    风险   " + _score_bar(f.risk_score))
        out.append(
            f"    PHP    {f.php_version or '未知':<10} SAPI  {f.sapi or '未知'}"
        )
        out.append(f"    理由   {_short(f.reason, 90)}")

        fa = f.factors
        out.append(
            "    评分   "
            + p(
                f"版本 {fa.get('version_risk', 0):.2f}×0.40  "
                f"SAPI {fa.get('sapi_exposure', 0):.2f}×0.25  "
                f"配置 {fa.get('config_exploitability', 0):.2f}×0.20  "
                f"暴露 {fa.get('exposure', 0):.2f}×0.15  "
                f"补丁因子 {fa.get('patch_factor', 0):.2f}",
                "gray",
            )
        )

        if show_evidence and f.evidences:
            out.append(p("    证据", "cyan"))
            for e in f.evidences[:14]:
                tag = f"[{e.detector}]"
                out.append(
                    f"      {tag:<5} {_pad(e.kind, 12)} {_pad(e.key, 40)} = {_short(e.value, 46)}"
                )
                out.append(p(f"            {e.confidence.label}｜{_short(e.method, 70)}", "gray"))
            if len(f.evidences) > 14:
                out.append(p(f"      … 另有 {len(f.evidences) - 14} 条证据", "gray"))

        if f.remediation:
            out.append(p("    处置", "cyan"))
            for r in f.remediation[:7]:
                pri = r.get("priority", 9)
                mark = "禁" if r.get("forbidden") else ("全" if r.get("complete") else "缓")
                out.append(f"      {pri}. [{mark}] {_short(r.get('action', ''), 76)}")
                if r.get("note"):
                    out.append(p(f"         {_short(r['note'], 78)}", "gray"))

        if f.notes:
            out.append(p("    提示", "cyan"))
            for n in f.notes[:8]:
                out.append(p(f"      - {_short(n, 84)}", "gray"))

        if f.errors:
            out.append(p("    错误", "yellow"))
            for err in f.errors[:5]:
                out.append(p(f"      ! {_short(err, 84)}", "yellow"))

        out.append("")

    out.append(p(_hr("="), "cyan"))
    out.append(
        "  说明：本工具为防御性检测，不包含漏洞利用代码。"
        "「确认受影响」表示满足可利用前置条件，不代表已验证代码执行。"
    )
    out.append(p(_hr("="), "cyan"))
    out.append("")
    return "\n".join(out)


def render_markdown(report: ScanReport, hunt=None, meta: dict | None = None) -> str:
    meta = meta or {}
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    lines: list[str] = []

    lines.append("# PHP2Shell 检测报告")
    lines.append("")
    lines.append(f"> 生成时间：{now}　|　工具：P2S-Guard 1.0　|　规则库：{report.ruleset_version}　|　画像：{report.profile}")
    if meta.get("ticket"):
        lines.append(f"> 授权凭据：{meta['ticket']}")
    lines.append("")

    # 只跑失陷排查、没有扫描结果时，走独立报告模板，避免出现空章节
    if not report.findings and hunt is not None:
        return _render_hunt_markdown(hunt, meta)

    counts = report.counts
    total = len(report.findings)
    p0 = sum(1 for f in report.findings if f.grade.value == "P0")

    lines.append("## 一、结论摘要")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("|---|---|")
    lines.append(f"| 检测资产数 | {total} |")
    lines.append(f"| 确认受影响 | **{counts.get('vulnerable', 0)}** |")
    lines.append(f"| 疑似受影响 | {counts.get('likely_vulnerable', 0)} |")
    lines.append(f"| 已修复 | {counts.get('patched', 0)} |")
    lines.append(f"| 不适用 | {counts.get('not_applicable', 0)} |")
    lines.append(f"| 无法判定 | {counts.get('unknown', 0)} |")
    lines.append(f"| P0 紧急 | **{p0}** |")
    lines.append("")

    if p0:
        lines.append(
            "> **处置优先级：立即处理 P0 资产。** 官方明确：升级到 "
            "8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 是唯一完整缓解手段。"
        )
        lines.append("")

    # 明细表
    lines.append("## 二、资产明细")
    lines.append("")
    lines.append("| # | 目标 | 结论 | 置信度 | 分数 | 等级 | PHP | SAPI |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for i, f in enumerate(report.findings, 1):
        lines.append(
            f"| {i} | `{f.target}` | {f.verdict.label} | {f.confidence.label} | "
            f"{f.risk_score} | {f.grade.value} | {f.php_version or '-'} | {f.sapi or '-'} |"
        )
    lines.append("")

    # 逐个详情
    lines.append("## 三、逐项详情")
    lines.append("")
    for i, f in enumerate(report.findings, 1):
        lines.append(f"### 3.{i} `{f.target}`")
        lines.append("")
        lines.append(f"- **结论**：{f.verdict.label}（置信度：{f.confidence.label}）")
        lines.append(f"- **风险分**：{f.risk_score} / 100　**等级**：{f.grade.value}")
        lines.append(f"- **PHP 版本**：{f.php_version or '未知'}　**SAPI**：{f.sapi or '未知'}")
        lines.append(f"- **判定理由**：{f.reason}")
        fa = f.factors
        lines.append(
            f"- **评分分解**：版本风险 {fa.get('version_risk', 0):.2f}×0.40 ｜ "
            f"SAPI 暴露 {fa.get('sapi_exposure', 0):.2f}×0.25 ｜ "
            f"配置可利用 {fa.get('config_exploitability', 0):.2f}×0.20 ｜ "
            f"资产暴露 {fa.get('exposure', 0):.2f}×0.15 ｜ "
            f"补丁因子 {fa.get('patch_factor', 0):.2f}"
        )
        lines.append("")

        if f.evidences:
            lines.append("**证据链**")
            lines.append("")
            lines.append("| 检测器 | 类型 | 键 | 值 | 置信度 | 采集方法 |")
            lines.append("|---|---|---|---|---|---|")
            for e in f.evidences:
                val = _short(e.value, 60).replace("|", "\\|")
                method = _short(e.method, 70).replace("|", "\\|")
                lines.append(
                    f"| {e.detector} | {e.kind} | `{e.key}` | `{val}` | {e.confidence.label} | {method} |"
                )
            lines.append("")

        if f.remediation:
            lines.append("**处置建议**")
            lines.append("")
            for r in f.remediation:
                mark = "【禁止】" if r.get("forbidden") else ("【完整修复】" if r.get("complete") else "【临时缓解】")
                lines.append(f"- {mark} {r.get('action', '')}")
                if r.get("note"):
                    lines.append(f"  - 说明：{r['note']}")
            lines.append("")

        if f.notes:
            lines.append("**补充说明**")
            lines.append("")
            for n in f.notes:
                lines.append(f"- {n}")
            lines.append("")

        if f.errors:
            lines.append("**采集错误**")
            lines.append("")
            for err in f.errors:
                lines.append(f"- `{err}`")
            lines.append("")

    # 失陷排查
    if hunt is not None:
        lines.append("## 四、失陷排查")
        lines.append("")
        lines.append(f"- 解析文件：{len(hunt.files)} 个，日志行 {hunt.events}，成功解析 {hunt.parsed}")
        if hunt.earliest:
            lines.append(f"- 时间范围：{hunt.earliest:%Y-%m-%d %H:%M} ~ {hunt.latest:%Y-%m-%d %H:%M}")
        lines.append(f"- 综合判定：**{hunt.verdict}**")
        lines.append("")
        if hunt.findings:
            lines.append("| 时间 | 规则 | 说明 | 来源 |")
            lines.append("|---|---|---|---|")
            for h in hunt.findings[:100]:
                ts = h.ts.strftime("%Y-%m-%d %H:%M:%S") if h.ts else "-"
                detail = _short(h.detail, 70).replace("|", "\\|")
                src = f"{os.path.basename(h.log_file)}:{h.line_no}"
                lines.append(f"| {ts} | {h.rule_id} | {detail} | {src} |")
            lines.append("")
        for n in hunt.notes:
            lines.append(f"- {n}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "本报告由 P2S-Guard 自动生成，所有结论均附带采集证据，可追溯至原始命令输出或日志行。"
        "工具不包含漏洞利用代码，「确认受影响」表示满足可利用前置条件，不代表已验证代码执行。"
    )
    lines.append("")
    return "\n".join(lines)


def render_json(report: ScanReport, hunt=None) -> str:
    data = report.to_dict()
    if hunt is not None:
        data["hunt"] = {
            "files": hunt.files,
            "events": hunt.events,
            "parsed": hunt.parsed,
            "verdict": hunt.verdict,
            "earliest": hunt.earliest.isoformat() if hunt.earliest else None,
            "latest": hunt.latest.isoformat() if hunt.latest else None,
            "findings": [
                {
                    "rule_id": h.rule_id,
                    "rule_name": h.rule_name,
                    "confidence": h.confidence,
                    "ts": h.ts.isoformat() if h.ts else None,
                    "detail": h.detail,
                    "ip": h.ip,
                    "method": h.method,
                    "uri": h.uri,
                    "status": h.status,
                    "log_file": h.log_file,
                    "line_no": h.line_no,
                }
                for h in hunt.findings
            ],
            "notes": hunt.notes,
        }
    return json.dumps(data, ensure_ascii=False, indent=2)


def _render_hunt_markdown(hunt, meta: dict | None = None) -> str:
    """失陷排查单独报告的模板（没有扫描结果时使用）。"""
    meta = meta or {}
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    lines: list[str] = []

    verdict_label = {
        "clean": "未发现异常",
        "suspicious": "疑似失陷",
        "inconclusive": "无法判定",
    }.get(hunt.verdict, hunt.verdict)

    lines.append("# PHP2Shell 失陷排查报告")
    lines.append("")
    lines.append(f"> 生成时间：{now}　|　工具：P2S-Guard 1.0　|　排查范围：`{meta.get('log', '-')}`")
    lines.append("")

    lines.append("## 一、排查概况")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("|---|---|")
    lines.append(f"| 解析文件数 | {len(hunt.files)} |")
    lines.append(f"| 日志总行数 | {hunt.events} |")
    lines.append(f"| 成功解析 | {hunt.parsed} |")
    if hunt.earliest and hunt.latest:
        lines.append(f"| 时间范围 | {hunt.earliest:%Y-%m-%d %H:%M} ~ {hunt.latest:%Y-%m-%d %H:%M} |")
    lines.append(f"| 命中规则数 | {len(hunt.findings)} |")
    lines.append(f"| 综合判定 | **{verdict_label}** |")
    lines.append("")

    lines.append("## 二、命中明细")
    lines.append("")
    if hunt.findings:
        lines.append("| 时间 | 规则 | 置信度 | 说明 | 来源 |")
        lines.append("|---|---|---|---|---|")
        for h in hunt.findings[:200]:
            ts = h.ts.strftime("%Y-%m-%d %H:%M:%S") if h.ts else "-"
            detail = _short(h.detail, 80).replace("|", "\\|")
            src = f"{os.path.basename(h.log_file)}:{h.line_no}"
            lines.append(f"| {ts} | {h.rule_id} | {h.confidence} | {detail} | `{src}` |")
        lines.append("")
    else:
        lines.append("未命中任何规则。")
        lines.append("")

    if hunt.notes:
        lines.append("## 三、结论与提示")
        lines.append("")
        for n in hunt.notes:
            lines.append(f"- {n}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "注意：成功利用可能既不崩溃也不报错，**日志干净不等于没被打过**。"
        "本报告只能说明「在所提供日志范围内未发现已知特征」，"
        "不能证明主机未被入侵。已确认受影响的主机仍应检查 web 目录、"
        "定时任务、账户与出站连接。"
    )
    lines.append("")
    return "\n".join(lines)
