"""回填历史扫描的 target_label，并重渲染报告。

老记录没存 params，只能用结果里的可见信息反推：
  · discover / host：用资产主机（1 台 → 直接显示；多台 → 「x.x.x.x 等 N 台」）
  · logs：用命中的客户端 IP + 解析条数（日志文件名已无法还原，如实标注）
  · url：用资产 url
这个回填是**尽力而为**，不假装还原了原始参数。
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from p2s.core import report as report_mod  # noqa: E402

SCANS = ROOT / "p2s-data" / "scans"


def guess_label(d: dict) -> str:
    kind = d.get("kind") or ""
    assets = d.get("assets") or []
    hosts = [a.get("host") for a in assets if a.get("host")]
    if kind in ("discover", "host"):
        if len(hosts) == 1:
            return str(hosts[0])
        if hosts:
            return f"{hosts[0]} 等 {len(hosts)} 台"
        hr = (d.get("host_reports") or [{}])[0]
        return str(hr.get("hostname") or "未记录目标")
    if kind == "logs":
        cov = d.get("coverage") or {}
        ips = []
        for f in d.get("findings") or []:
            ip = f.get("ip")
            if ip and ip not in ips:
                ips.append(ip)
        n = cov.get("parsed_records") or 0
        if len(ips) == 1:
            return f"日志（来源 {ips[0]}，{n} 条）"
        if ips:
            return f"日志（{len(ips)} 个来源，{n} 条）"
        return f"日志（{n} 条，历史记录未存文件名）"
    if kind == "agent":
        hr = (d.get("host_reports") or [{}])[0]
        return str(hr.get("hostname") or "Agent 上报")
    if kind == "url":
        return str((assets[0].get("url") if assets else "") or "URL 检测")
    return kind or "-"


def build(d: dict) -> report_mod.ScanResult:
    res = report_mod.ScanResult(scan_id=d.get("scan_id") or "x",
                                kind=d.get("kind") or "discover",
                                started_at=d.get("started_at") or "")
    res.assets = d.get("assets") or []
    res.findings = d.get("findings") or []
    res.target_count = d.get("target_count") or 0
    res.finished_at = d.get("finished_at")
    res.errors = d.get("errors") or []
    res.changes = d.get("changes") or []
    res.coverage = d.get("coverage") or {}
    res.target_label = d.get("target_label") or guess_label(d)
    return res


def prune_dupes(apply: bool = False) -> int:
    """同一 dedupe_key 的多份扫描只保留最新，其余删除（默认只报告不删）。"""
    from p2s.console.deps import _scan_dedupe_key  # 复用同一套指纹口径

    groups: dict[str, list[pathlib.Path]] = {}
    for f in sorted(SCANS.glob("*.json"), key=lambda p: p.stat().st_mtime):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        groups.setdefault(_scan_dedupe_key(d), []).append(f)
    removed = 0
    for files in groups.values():
        if len(files) <= 1:
            continue
        for f in files[:-1]:                     # 保留最新的一份
            removed += 1
            if apply:
                for ext in (".json", ".md", ".html"):
                    (f.parent / (f.stem + ext)).unlink(missing_ok=True)
    verb = "已删除" if apply else "可删除"
    print(f"重复清理：{verb} {removed} 份（{len(groups)} 组中 {sum(1 for v in groups.values() if len(v) > 1)} 组有重复）")
    if not apply:
        print("  这是 dry-run；确认后加 --prune 参数执行")
    return removed


def main() -> int:
    if "--prune" in sys.argv:
        return 0 if prune_dupes(apply=True) >= 0 else 1
    if "--prune-dry" in sys.argv:
        prune_dupes(apply=False)
        return 0
    files = sorted(SCANS.glob("*.json"))
    filled = rerendered = 0
    for f in files:
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not d.get("target_label") or d.get("target_label") in ("未记录目标", "discover"):
            d["target_label"] = guess_label(d)
            f.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
            filled += 1
        try:
            res = build(d)
            report_mod.to_markdown(res, f.with_suffix(".md"))
            report_mod.to_html(res, f.with_suffix(".html"))
            rerendered += 1
        except Exception as e:
            print("  重渲染失败", f.stem, e)
    print(f"完成：补写目标 {filled} 份，重渲染 {rerendered} 份（共 {len(files)}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
