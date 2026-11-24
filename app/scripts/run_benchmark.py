"""对基准集跑检测，统计漏报率与误报率。

用法（在能访问目标的环境执行）：
    python -m p2s.cli verify-benchmark --bench data/benchmark.json
或直接：
    python scripts/run_benchmark.py

判定口径
--------
| truth.patched | 检测结论           | 归类   |
|---------------|--------------------|--------|
| False         | 暴露(vulnerable)   | 正确   |
| False         | 已修复/未知        | 漏报   |
| True          | 已修复(patched)    | 正确   |
| True          | 暴露(vulnerable)   | 误报   |
| 任意          | unknown            | 待确认 |
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from p2s.core import discovery  # noqa: E402
from p2s.core.versions import classify  # noqa: E402


def load_bench(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate(bench: dict) -> dict:
    rows = []
    for case in bench["cases"]:
        acc = case["access"]
        truth = case["truth"]
        try:
            prof = discovery.discover(acc["host"], ports=[acc["port"]],
                                      timeout=2.0, http_timeout=8.0)
            got_version = prof.php_version
            if got_version:
                v = classify(got_version)
                # Verdict.status: vulnerable / patched / unknown
                verdict = getattr(v, "status", None) or "unknown"
            else:
                verdict = "unknown"
        except Exception as exc:  # 单点失败不能中断整轮
            got_version, verdict = None, f"error:{type(exc).__name__}"

        if verdict == "unknown" or verdict.startswith("error"):
            outcome = "unknown"
        elif truth["patched"] and verdict == "patched":
            outcome = "correct"
        elif (not truth["patched"]) and verdict == "vulnerable":
            outcome = "correct"
        elif truth["patched"] and verdict == "vulnerable":
            outcome = "false_positive"
        elif (not truth["patched"]) and verdict == "patched":
            outcome = "false_negative"
        else:
            outcome = "unknown"

        rows.append({
            "id": case["id"],
            "endpoint": case["endpoint"],
            "truth_version": truth["php_version"],
            "truth_patched": truth["patched"],
            "got_version": got_version,
            "verdict": verdict,
            "outcome": outcome,
        })

    n = len(rows) or 1
    correct = sum(1 for r in rows if r["outcome"] == "correct")
    fp = sum(1 for r in rows if r["outcome"] == "false_positive")
    fn = sum(1 for r in rows if r["outcome"] == "false_negative")
    unknown = sum(1 for r in rows if r["outcome"] == "unknown")
    return {
        "rows": rows,
        "stats": {
            "total": len(rows),
            "correct": correct,
            "false_positive": fp,
            "false_negative": fn,
            "unknown": unknown,
            "accuracy": round(correct / n, 4),
            "fp_rate": round(fp / n, 4),
            "fn_rate": round(fn / n, 4),
        },
    }


def main() -> int:
    bench_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/benchmark.json")
    if not bench_path.exists():
        print(f"[SKIP] 未找到基准集 {bench_path}（需先在实验场构建）")
        return 0
    bench = load_bench(bench_path)
    res = evaluate(bench)

    print(f"{'用例':16s} {'期望版本':10s} {'实测版本':10s} {'判定':10s} 结果")
    print("-" * 70)
    label = {"correct": "正确", "false_positive": "误报",
             "false_negative": "漏报", "unknown": "待确认"}
    for r in res["rows"]:
        print(f"{r['id']:16s} {r['truth_version']:10s} {str(r['got_version']):10s} "
              f"{r['verdict']:10s} {label[r['outcome']]}")

    s = res["stats"]
    print("\n--- 统计 ---")
    print(f"  用例 {s['total']} · 正确 {s['correct']} · 误报 {s['false_positive']} · "
          f"漏报 {s['false_negative']} · 待确认 {s['unknown']}")
    print(f"  准确率 {s['accuracy']*100:.1f}%  误报率 {s['fp_rate']*100:.1f}%  "
          f"漏报率 {s['fn_rate']*100:.1f}%")

    # 只有"误报"和"漏报"算失败；待确认不算（数据不足时诚实说不确定）
    return 1 if (s["false_positive"] or s["false_negative"]) else 0


if __name__ == "__main__":
    sys.exit(main())