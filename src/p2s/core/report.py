"""统一报告输出：JSON / Markdown / HTML。"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .redact import redact, redact_obj
from .rules import SEVERITY_ORDER

SEV_LABEL = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}


@dataclass
class ScanResult:
    """一次扫描的聚合结果。"""

    scan_id: str
    kind: str
    started_at: str
    finished_at: str = ""
    target_count: int = 0
    assets: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    host_reports: list[dict] = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
        return counts

    @property
    def risk(self) -> str:
        counts = self.severity_counts
        if counts.get("critical"):
            return "critical"
        if counts.get("high"):
            return "high"
        if counts.get("medium"):
            return "medium"
        if self.assets:
            risky = [a for a in self.assets if a.get("risk") in ("critical", "high")]
            if risky:
                return "high"
        return "low"

    def to_dict(self) -> dict:
        return redact_obj({
            "scan_id": self.scan_id,
            "kind": self.kind,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "risk": self.risk,
            "target_count": self.target_count,
            "severity_counts": self.severity_counts,
            "assets": self.assets,
            "findings": self.findings,
            "host_reports": self.host_reports,
            "coverage": self.coverage,
            "errors": self.errors,
        })


def to_json(result: ScanResult, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def to_markdown(result: ScanResult, path: str | Path) -> Path:
    d = result.to_dict()
    lines: list[str] = []
    lines.append(f"# php2shell 检测报告 `{result.scan_id}`\n")
    lines.append(f"- 扫描类型：{result.kind}")
    lines.append(f"- 开始：{result.started_at}　结束：{result.finished_at}")
    lines.append(f"- 目标数：{result.target_count}　整体风险：**{d['risk'].upper()}**")
    counts = d["severity_counts"]
    if counts:
        lines.append("- 命中分布：" + "　".join(
            f"{SEV_LABEL.get(k, k)} {v}" for k, v in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9))
        ))
    lines.append("")

    if result.assets:
        lines.append("## 资产结论\n")
        lines.append("| 目标 | PHP 版本 | SAPI | 版本状态 | 探测结论 | 风险 |")
        lines.append("|---|---|---|---|---|---|")
        for a in result.assets:
            v = a.get("version_verdict", {})
            lines.append(
                f"| {a.get('url')} | {v.get('version','-')} | {a.get('fingerprint',{}).get('sapi_label','-')} "
                f"| {v.get('status','-')} | {a.get('probe_verdict','-')} | **{a.get('risk','-')}** |"
            )
        lines.append("")

    if result.findings:
        lines.append("## 命中明细\n")
        lines.append("| 规则 | 等级 | 维度 | 时间 | 来源 IP | URI | 证据 |")
        lines.append("|---|---|---|---|---|---|---|")
        for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 9)):
            lines.append(
                f"| {f.get('rule_id')} {f.get('rule_name')} | {SEV_LABEL.get(f.get('severity',''),f.get('severity'))} "
                f"| {f.get('dimension')} | {f.get('ts') or '-'} | {f.get('ip') or '-'} "
                f"| {redact(str(f.get('uri') or '-'))[:60]} | {redact(str(f.get('evidence') or ''))[:110]} |"
            )
        lines.append("")

    if result.host_reports:
        lines.append("## 主机侧检测\n")
        for h in result.host_reports:
            lines.append(f"### {h.get('hostname')}（{h.get('platform')}） 风险 **{h.get('risk','').upper()}**\n")
            for inst in h.get("installs", []):
                lines.append(
                    f"- PHP {inst.get('version')} @ `{inst.get('path')}` "
                    f"SAPI={inst.get('sapi')} → **{inst.get('verdict_status')}**"
                )
            for s in h.get("settings", []):
                mark = "OK " if s.get("ok") else "!! "
                lines.append(f"  - {mark}`{s.get('name')}` = `{s.get('actual')}`（期望 `{s.get('expected')}`）")
            for a in h.get("artifacts", [])[:50]:
                lines.append(f"- **{a.get('severity').upper()}** {a.get('kind')}: `{a.get('path')}` — {a.get('detail')}")
            lines.append("")

    if result.coverage.get("uncovered"):
        lines.append("## 规则覆盖缺口\n")
        lines.append("以下规则因日志缺少相应字段而无法覆盖，建议开启请求体/响应体落盘：\n")
        lines.append(", ".join(f"`{r}`" for r in result.coverage["uncovered"]))
        lines.append("")

    if result.errors:
        lines.append("## 错误\n")
        lines.extend(f"- {e}" for e in result.errors)
        lines.append("")

    lines.append("---\n")
    lines.append("> 处置优先级：先升级 PHP 到 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 并重启 worker；"
                 "无法升级则按官方缓解建议配置并考虑将受影响资产下线。")

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines), encoding="utf-8")
    return p


def to_html(result: ScanResult, path: str | Path) -> Path:
    """极简 HTML 报告（可直接发给客户）。"""
    d = result.to_dict()
    def esc(s: Any) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    rows = "".join(
        f"<tr><td>{esc(a.get('url'))}</td>"
        f"<td>{esc(a.get('version_verdict',{}).get('version','-'))}</td>"
        f"<td>{esc(a.get('fingerprint',{}).get('sapi_label','-'))}</td>"
        f"<td>{esc(a.get('version_verdict',{}).get('status','-'))}</td>"
        f"<td>{esc(a.get('probe_verdict','-'))}</td>"
        f"<td class='risk-{esc(a.get('risk','-'))}'>{esc(a.get('risk','-')).upper()}</td></tr>"
        for a in result.assets
    )
    finding_rows = "".join(
        f"<tr><td>{esc(f.get('rule_id'))}</td><td>{esc(f.get('rule_name'))}</td>"
        f"<td>{esc(f.get('severity'))}</td><td>{esc(f.get('ip') or '-')}</td>"
        f"<td>{esc(redact(str(f.get('evidence') or '')[:160]))}</td></tr>"
        for f in result.findings
    )
    html = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>php2shell 检测报告 {esc(result.scan_id)}</title>
<style>
 body{{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;margin:0;background:#0f1115;color:#e6e6e6}}
 .wrap{{max-width:1200px;margin:0 auto;padding:32px 24px}}
 h1{{font-size:22px;margin:0 0 4px}} .sub{{color:#8b93a1;font-size:13px;margin-bottom:24px}}
 .cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
 .card{{background:#171a21;border:1px solid #232733;border-radius:10px;padding:14px 18px;min-width:130px}}
 .card .k{{color:#8b93a1;font-size:12px}} .card .v{{font-size:22px;font-weight:600;margin-top:4px}}
 table{{width:100%;border-collapse:collapse;background:#141720;border-radius:10px;overflow:hidden;font-size:13px}}
 th,td{{padding:9px 12px;text-align:left;border-bottom:1px solid #1e2230}}
 th{{background:#1b1f29;color:#9aa3b2;font-weight:500}}
 .risk-critical{{color:#ff6b6b;font-weight:700}} .risk-high{{color:#ffa94d;font-weight:700}}
 .risk-medium{{color:#ffd43b}} .risk-low{{color:#69db7c}}
 .note{{margin-top:24px;padding:14px 16px;background:#1a1420;border:1px solid #3a2436;border-radius:10px;font-size:13px;color:#d8c0d8}}
</style></head><body><div class="wrap">
<h1>php2shell 检测报告</h1>
<div class="sub">{esc(result.scan_id)} · {esc(result.kind)} · {esc(result.started_at)} → {esc(result.finished_at)}</div>
<div class="cards">
 <div class="card"><div class="k">整体风险</div><div class="v risk-{esc(d['risk'])}">{esc(d['risk']).upper()}</div></div>
 <div class="card"><div class="k">目标数</div><div class="v">{result.target_count}</div></div>
 <div class="card"><div class="k">命中</div><div class="v">{len(result.findings)}</div></div>
 <div class="card"><div class="k">严重</div><div class="v">{d['severity_counts'].get('critical',0)}</div></div>
 <div class="card"><div class="k">高危</div><div class="v">{d['severity_counts'].get('high',0)}</div></div>
</div>
<h3 style="font-size:15px">资产结论</h3>
<table><thead><tr><th>目标</th><th>PHP</th><th>SAPI</th><th>版本状态</th><th>探测</th><th>风险</th></tr></thead><tbody>{rows}</tbody></table>
<h3 style="font-size:15px;margin-top:24px">命中明细</h3>
<table><thead><tr><th>规则</th><th>名称</th><th>等级</th><th>来源</th><th>证据</th></tr></thead><tbody>{finding_rows}</tbody></table>
<div class="note"><b>处置：</b>唯一完整修复是升级到 PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 并重启全部 worker。
无法升级时按官方缓解建议设置 <code>session.upload_progress.enabled=0</code>、<code>memory_limit=-1</code>、
收紧 <code>post_max_size</code>，PHP 8.5 另需 <code>fatal_error_backtraces=0</code>，并考虑将受影响的互联网暴露资产下线。</div>
</div></body></html>"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(html, encoding="utf-8")
    return p
