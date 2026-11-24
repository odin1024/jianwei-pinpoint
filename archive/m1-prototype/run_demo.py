"""一键演示：起靶场 → 扫描 → 出报告 → 跑失陷排查

    python run_demo.py
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lab.mock_php import LabServer  # noqa: E402
from p2s.detectors import d6_hunt  # noqa: E402
from p2s.engine import Engine  # noqa: E402
from p2s.report import (  # noqa: E402
    enable_ansi, render_json, render_markdown, render_terminal,
)

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
SAMPLE_LOGS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab", "sample_logs")


def main() -> int:
    enable_ansi()
    lab = LabServer()
    print("启动模拟靶场...")
    personas = lab.start()

    print()
    print("  " + "-" * 72)
    for p in personas:
        print(f"  127.0.0.1:{p.port:<5} {p.title}")
        print(f"  {'':<12} 期望：{p.expect}")
    print("  " + "-" * 72)
    print()

    eng = Engine(profile="standard", timeout=5.0, qps=20.0, quiet=False)
    report = eng.scan_many(lab.targets)
    report.finished_at = time.time()

    print(render_terminal(report, color=True, show_evidence=True))

    # ---- 失陷排查 ----
    hunt = None
    if os.path.isdir(SAMPLE_LOGS):
        print("  失陷排查：扫描样例日志 lab/sample_logs ...")
        hunt = d6_hunt.analyze([SAMPLE_LOGS])
        print(f"  文件 {len(hunt.files)} 个 / 日志行 {hunt.events} / 解析 {hunt.parsed} "
              f"/ 判定 {hunt.verdict.upper()} / 命中 {len(hunt.findings)} 条")
        for h in hunt.findings[:8]:
            ts = h.ts.strftime("%m-%d %H:%M:%S") if h.ts else "-"
            print(f"      {ts}  {h.rule_id}  {h.detail[:64]}")
        print()

    # ---- 落盘 ----
    os.makedirs(OUT_DIR, exist_ok=True)
    md_path = os.path.join(OUT_DIR, "php2shell-report.md")
    json_path = os.path.join(OUT_DIR, "php2shell-result.json")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(report, hunt=hunt, meta={"ticket": "DEMO-LOCAL-LAB"}))
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(render_json(report, hunt=hunt))
    print(f"  报告：{md_path}")
    print(f"  JSON：{json_path}")
    print()

    # ---- 对照期望 ----
    print("  与期望结果对照")
    print("  " + "-" * 72)
    ok = 0
    for p, f in zip(personas, report.findings):
        got = f"{f.verdict.label} / {f.grade.value}"
        hit = f.verdict.value == p.expect_key
        ok += 1 if hit else 0
        flag = "OK  " if hit else "DIFF"
        print(f"  [{flag}] :{p.port}  期望 {p.expect:<22} 实际 {got}")
    print("  " + "-" * 72)
    print(f"  符合期望 {ok}/{len(personas)}")
    print()

    lab.stop()
    return 0 if ok == len(personas) else 1


if __name__ == "__main__":
    raise SystemExit(main())
