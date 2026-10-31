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
    #: 本次扫描的目标（网段 / 主机 / 日志文件名），报告与列表都靠它区分
    target_label: str = ""
    assets: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    host_reports: list[dict] = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    #: 资产变化（新增 / 变更 / 消失），只在设备发现类扫描里产生
    changes: list[dict] = field(default_factory=list)

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
            "target_label": self.target_label,
            "severity_counts": self.severity_counts,
            "assets": self.assets,
            "findings": self.findings,
            "host_reports": self.host_reports,
            "coverage": self.coverage,
            "changes": self.changes,
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
                f"| {a.get('host') or a.get('url')} | {v.get('version','-')} | {a.get('fingerprint',{}).get('sapi_label','-')} "
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
    """客户可读的 HTML 报告：浅色、可打印、结论 + 证据 + 整改建议三段式。"""
    def esc(s: Any) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def badge(risk: str) -> str:
        return {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}.get(risk, risk or "-")

    counts = result.severity_counts
    assets = list(result.assets or [])
    exposed = [a for a in assets if (a.get("version_verdict") or {}).get("status") == "vulnerable"]

    asset_rows = "".join(
        f"<tr><td class='mono'>{esc(a.get('url'))}</td>"
        f"<td>{esc((a.get('version_verdict') or {}).get('version') or '-')}</td>"
        f"<td>{esc((a.get('fingerprint') or {}).get('sapi_label') or '-')}</td>"
        f"<td>{esc((a.get('version_verdict') or {}).get('status') or '-')}</td>"
        f"<td><span class='tag {esc(a.get('risk') or 'low')}'>{badge(a.get('risk'))}</span></td></tr>"
        for a in assets
    ) or "<tr><td colspan='5' class='empty'>本次未发现可评估的 Web 资产</td></tr>"

    finding_rows = "".join(
        f"<tr><td class='mono'>{esc(f.get('rule_id'))}</td><td>{esc(f.get('rule_name'))}</td>"
        f"<td><span class='tag {esc(f.get('severity') or 'low')}'>{badge(f.get('severity'))}</span></td>"
        f"<td class='mono'>{esc(f.get('ip') or '-')}</td>"
        f"<td class='evi'>{esc(redact(str(f.get('evidence') or '')[:200]))}</td></tr>"
        for f in result.findings
    ) or "<tr><td colspan='5' class='empty'>未发现日志侧攻击痕迹</td></tr>"

    # 整改建议：只给真正需要的资产，按"版本→SAPI→复测"三步走，避免套话
    advice: list[str] = []
    for a in exposed:
        vv = a.get("version_verdict") or {}
        ver = vv.get("version") or "未知版本"
        fixed = vv.get("fixed_release") or "官方修复版本"
        sapi = (a.get("fingerprint") or {}).get("sapi_label") or ""
        advice.append(
            f"<li><b>{esc(a.get('url'))}</b>：PHP {esc(ver)} 低于修复基线，升级到 <b>{esc(fixed)}</b>；"
            f"若为发行版包，先核对 changelog 是否已回移补丁。"
            + (f" 该站点以 <code>{esc(sapi)}</code> 方式运行，升级后需重启对应服务。" if sapi else "")
            + " 升级完成后重新扫描，确认状态变为「已修复」。</li>"
        )
    if not advice:
        advice.append("<li>本次未发现低于修复基线的 PHP 资产；建议保持定期复扫，持续覆盖新增资产。</li>")
    advice.append("<li>确认 <code>session.upload_progress.enabled=0</code> 等缓解配置在目标主机上生效"
                  "（需在目标机执行 Agent 采集脚本核实，远程无法判断）。</li>")

    html = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PHP 暴露面检测报告 · {esc(result.scan_id)}</title>
<style>
  :root{{--ink:#111827;--ink2:#4b5563;--ink3:#6b7280;--line:#e5e7eb;--bg:#fff;--soft:#f9fafb;
        --crit:#b42318;--high:#b54708;--mid:#a16207;--low:#067647;--accent:#1d4ed8}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:#f3f4f6;color:var(--ink);
       font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
       -webkit-font-smoothing:antialiased}}
  .page{{max-width:980px;margin:24px auto;background:var(--bg);padding:44px 52px 56px;
        box-shadow:0 1px 3px rgba(16,24,40,.08),0 12px 32px -12px rgba(16,24,40,.16)}}
  header{{border-bottom:2px solid var(--ink);padding-bottom:16px;margin-bottom:26px;
         display:flex;align-items:flex-end;gap:16px}}
  header .t{{flex:1}}
  h1{{font-size:24px;margin:0 0 6px;letter-spacing:-.3px}}
  .meta{{color:var(--ink3);font-size:12.5px;line-height:1.7}}
  .sev{{font-size:12px;color:var(--ink2);border:1px solid var(--line);border-radius:6px;padding:8px 12px}}
  .sev b{{font-size:18px;display:block;line-height:1.2}}
  h2{{font-size:15px;margin:30px 0 12px;padding-left:10px;border-left:3px solid var(--accent);
     line-height:1.2}}
  .kpis{{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0 6px}}
  .kpi{{flex:1 1 120px;border:1px solid var(--line);border-radius:8px;padding:12px 14px;background:var(--soft)}}
  .kpi .k{{font-size:11.5px;color:var(--ink3)}}
  .kpi .v{{font-size:22px;font-weight:640;font-variant-numeric:tabular-nums;margin-top:2px}}
  .kpi.crit .v{{color:var(--crit)}} .kpi.ok .v{{color:var(--low)}}
  table{{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:6px}}
  th{{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:var(--ink3);
     border-bottom:1px solid var(--line);padding:8px 10px;background:var(--soft)}}
  td{{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
  tbody tr:nth-child(even) td{{background:#fcfcfd}}
  .mono{{font-family:ui-monospace,Consolas,monospace;font-size:11.5px}}
  .evi{{color:var(--ink2);word-break:break-all;max-width:420px}}
  .empty{{text-align:center;color:var(--ink3);padding:18px}}
  .tag{{display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:600;
       border:1px solid transparent;white-space:nowrap}}
  .tag.critical{{color:var(--crit);background:#fdf2f1;border-color:#f5d3cf}}
  .tag.high{{color:var(--high);background:#fdf6ec;border-color:#f2ddc0}}
  .tag.medium{{color:var(--mid);background:#fdfaeb;border-color:#eee2b8}}
  .tag.low{{color:var(--low);background:#eef8f2;border-color:#bfe3cd}}
  ol.adv{{margin:6px 0 0 18px;padding:0;font-size:13px;line-height:1.85;color:var(--ink2)}}
  ol.adv li{{margin-bottom:8px}}
  ol.adv code{{font-family:ui-monospace,Consolas,monospace;font-size:11.5px;
              background:var(--soft);border:1px solid var(--line);border-radius:3px;padding:0 4px}}
  footer{{margin-top:34px;padding-top:14px;border-top:1px solid var(--line);
         color:var(--ink3);font-size:11.5px;line-height:1.8}}
  @media print{{
    body{{background:#fff}} .page{{box-shadow:none;margin:0;padding:24px;max-width:none}}
    h2{{break-after:avoid}} tr{{break-inside:avoid}}
  }}
</style></head>
<body><div class="page">
<header>
  <div class="t">
    <h1>PHP 暴露面检测报告</h1>
    <div class="meta">
      扫描编号 <span class="mono">{esc(result.scan_id)}</span> ·
      类型 {esc(result.kind)} · 目标 {getattr(result, 'target_count', 0) or 0} 个<br>
      开始 {esc(result.started_at or '-')} · 结束 {esc(result.finished_at or '-')}
    </div>
  </div>
  <div class="sev">风险等级<b>{badge(result.risk).upper()}</b></div>
</header>

<h2>结论摘要</h2>
<div class="kpis">
  <div class="kpi crit"><div class="k">严重</div><div class="v">{counts.get('critical', 0)}</div></div>
  <div class="kpi"><div class="k">高危</div><div class="v">{counts.get('high', 0)}</div></div>
  <div class="kpi"><div class="k">中危</div><div class="v">{counts.get('medium', 0)}</div></div>
  <div class="kpi ok"><div class="k">低危</div><div class="v">{counts.get('low', 0)}</div></div>
</div>
<div class="meta" style="margin-top:10px">
  共评估 {len(assets)} 个 Web 资产，其中 <b>{len(exposed)}</b> 个 PHP 版本低于修复基线。
</div>

<h2>Web 资产</h2>
<table><thead><tr><th>目标</th><th>PHP 版本</th><th>SAPI</th><th>版本判定</th><th>风险</th></tr></thead>
<tbody>{asset_rows}</tbody></table>

<h2>日志侧发现（{len(result.findings)} 条）</h2>
<table><thead><tr><th>规则</th><th>名称</th><th>级别</th><th>来源</th><th>证据</th></tr></thead>
<tbody>{finding_rows}</tbody></table>

<h2>整改建议</h2>
<ol class="adv">{''.join(advice)}</ol>

<footer>
  本报告基于远程探测与本地采集的事实生成，结论区分「确认受影响 / 无法判定」两类；
  未标注为确认的条目需结合目标主机实际情况复核。<br>
  生成时间 {esc(result.finished_at or result.started_at or '-')} · 由见微 Pinpoint 生成
</footer>
</div></body></html>
"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(html, encoding="utf-8")
    return p
