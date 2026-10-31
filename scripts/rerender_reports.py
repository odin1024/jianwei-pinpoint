"""批量重渲染历史报告：把旧的 Markdown / HTML 换成当前版式。

用法：
    python scripts/rerender_reports.py              # 默认重渲染 p2s-data/scans
    python scripts/rerender_reports.py --dir 路径
    python scripts/rerender_reports.py --dry-run    # 只看会改哪些

为什么需要它：报告版式升级后，历史报告仍是旧模板；重新扫描代价太大，
这里直接从已落盘的 scan JSON 重建，内容不变、只换版式。
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from p2s.core import report as report_mod  # noqa: E402


def build(scan: dict) -> report_mod.ScanResult:
    """用最小字段重建 ScanResult —— 只为了复用渲染器，不做任何推断。"""
    res = report_mod.ScanResult(
        scan_id=scan.get("scan_id") or "unknown",
        kind=scan.get("kind") or "discover",
        started_at=scan.get("started_at") or "",
    )
    res.assets = scan.get("assets") or []
    res.findings = scan.get("findings") or []
    res.target_count = scan.get("target_count") or 0
    res.finished_at = scan.get("finished_at")
    res.errors = scan.get("errors") or []
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(ROOT / "p2s-data" / "scans"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    d = pathlib.Path(args.dir)
    if not d.exists():
        print(f"目录不存在：{d}")
        return 1

    files = sorted(d.glob("*.json"))
    if not files:
        print("没有找到扫描记录")
        return 0

    ok = skipped = failed = 0
    for f in files:
        try:
            scan = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            print(f"  跳过 {f.name}：读取失败 {e}")
            skipped += 1
            continue
        if args.dry_run:
            print(f"  会重渲染 {f.stem}")
            ok += 1
            continue
        try:
            res = build(scan)
            report_mod.to_markdown(res, f.with_suffix(".md"))
            report_mod.to_html(res, f.with_suffix(".html"))
            ok += 1
        except Exception as e:                       # 单份失败不能中断整批
            print(f"  失败 {f.stem}：{e}")
            failed += 1

    print(f"\n完成：成功 {ok}，跳过 {skipped}，失败 {failed}（目录 {d}）")
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
