"""基准集：已知真相的检测样本与评测脚本。

用法
----
1. 在能访问目标的环境构建样本（实验场见 `docs/BENCHMARK.md`）；
2. 把 `benchmark.json` 放到 `app/data/`；
3. `python scripts/run_benchmark.py data/benchmark.json`。

判定口径（`Verdict.status`）
---------------------------
| 真相 patched | 检测 status | 归类   |
|--------------|-------------|--------|
| False        | vulnerable  | 正确   |
| False        | patched     | 漏报   |
| True         | patched     | 正确   |
| True         | vulnerable  | 误报   |
| 任意         | unknown     | 待确认 |

只有误报/漏报算失败；待确认不算——数据不足时诚实说不确定，比猜一个好。
"""