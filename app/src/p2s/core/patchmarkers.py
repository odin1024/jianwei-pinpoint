"""补丁标记库：用二进制与运行时标记判定"是否已打补丁"。

存在意义
--------
远端只能读到版本号时会陷入两难：
  · 版本号低于基线 → 可能已被发行版回移补丁（如 Debian 的 8.2.34-1+deb12u2）
  · 版本号达标     → 也可能被降级或伪造

版本号是**声明**，标记是**证据**。本模块只回答一个问题：
"这个 PHP 二进制里有没有 2026-10-21 那次修复引入的东西？"

标记来源（全部实测，不是推测）
------------------------------
`data/markers.json` 由实验场三个分支的官方镜像配对提取：

| 分支 | 未补丁 | 已补丁 |
|---|---|---|
| 8.2 | 8.2.34 | 8.2.35 |
| 8.3 | 8.3.35 | 8.3.36 |
| 8.4 | 8.4.26 | 8.4.27 |

6 条二进制标记在**三个分支上逐一验证过可区分**（见 verification_matrix 字段）。

判定原则
--------
1. 任一条"补丁才有的标记"命中 → `patched`；
2. 任一条"未补丁才有的标记"命中 → `unpatched`；
3. 两者互相矛盾（都命中）→ `conflict`，**不猜**，交给人工；
4. 都没有 → `unknown`。绝不因为"没找到标记"就判成未补丁。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_DATA = Path(__file__).with_name("data") / "markers.json"

_cache: dict | None = None


def load() -> dict:
    """读取标记库（带进程内缓存）。"""
    global _cache
    if _cache is None:
        _cache = json.loads(_DATA.read_text(encoding="utf-8"))
    return _cache


def markers() -> list[dict]:
    return list(load().get("binary_markers") or [])


def runtime_probes() -> list[dict]:
    return list(load().get("runtime_probes") or [])


def branches() -> list[dict]:
    return list(load().get("branches") or [])


def provenance() -> dict:
    return dict(load().get("provenance") or {})


def verify_matrix() -> dict:
    """回传三分支实测矩阵，供"关于"页或审计引用。"""
    return dict(load().get("verification_matrix") or {})


def match_binary(blob: bytes) -> dict:
    """在二进制内容里查找标记。

    Args:
        blob: PHP 可执行文件的原始字节（可能来自本地 agent 采集）。

    Returns:
        {"verdict": "patched"|"unpatched"|"conflict"|"unknown",
         "hits": [命中的标记 id],
         "missing": [未命中的标记 id],
         "evidence": [人类可读的判定说明]}
    """
    hits: list[str] = []
    missing: list[str] = []
    evidence: list[str] = []
    patched_signal = False
    unpatched_signal = False
    weak_hint = False

    for m in markers():
        needle = str(m.get("needle") or "").encode()
        if not needle:
            continue
        present = needle in blob

        if m.get("kind") == "binary_string_absent":
            # 这条标记的含义是「旧字符串应当消失」。
            # 注意：单靠"旧串不在"**不足以**断言已补丁 —— 随便一个非 PHP 文件都不含它。
            # 所以它只提供两个方向：旧串仍在 → 未补丁（强证据）；
            # 旧串消失 → 仅记为弱提示，需配合正向标记才能判 patched。
            if present:
                unpatched_signal = True
                missing.append(m["id"])
                evidence.append(
                    f"{m['id']} 仍含旧版字符串「{m.get('needle')}」：这段代码没有被修复改写")
            else:
                hits.append(m["id"])
                weak_hint = True
            continue

        if present:
            hits.append(m["id"])
            if m.get("verdict_if_present") == "patched":
                patched_signal = True
            evidence.append(f"{m['id']} 命中：{m.get('why', '')}")
        else:
            missing.append(m["id"])

    if patched_signal and unpatched_signal:
        verdict = "conflict"
        evidence.append("补丁标记与未补丁标记同时命中，判定为矛盾，需人工确认")
    elif patched_signal:
        verdict = "patched"
    elif unpatched_signal:
        verdict = "unpatched"
    else:
        verdict = "unknown"
        if weak_hint:
            evidence.append("仅「旧版字符串不存在」这一弱信号，不足以判定已打补丁")
        evidence.append("未命中任何判定性标记：可能是其它构建，或读取的不是 PHP 二进制")

    return {"verdict": verdict, "hits": hits, "missing": missing, "evidence": evidence}


def match_runtime(ini_value_repr: str) -> dict:
    """用 `ini_get('memory_hard_limit_percent')` 的 repr 判定。

    未补丁 → `bool(false)`（指令不存在）
    已补丁 → `string(0) ""`（指令存在但未设置）
    """
    probe = (runtime_probes() or [{}])[0]
    got = (ini_value_repr or "").strip()
    if got == probe.get("patched_value"):
        return {"verdict": "patched", "evidence": [
            f"运行时读到 {got}：指令已注册但未设值，说明这些代码里已有该配置项"]}
    if got == probe.get("unpatched_value"):
        return {"verdict": "unpatched", "evidence": [
            f"运行时读到 {got}：指令不存在，说明该 PHP 未包含 2026-10-21 的修复"]}

    # 用户显式设过值（例如 120）：指令存在且有值 → 已是含修复的版本
    m = re.fullmatch(r'string\(\d+\)\s+"(-?\d+)"', got)
    if m:
        return {"verdict": "patched", "evidence": [
            f"运行时读到 {got}：该指令存在且被设置为 {m.group(1)}，说明已是含修复的版本"]}
    if got.lstrip("-").isdigit():
        return {"verdict": "patched", "evidence": [
            f"运行时读到 {got}：该指令存在且有值，说明已是含修复的版本"]}

    return {"verdict": "unknown", "evidence": [f"运行时值 {got!r} 未匹配已知标记"]}


def summary() -> dict:
    """给界面用的概览。"""
    b = branches()
    return {
        "branches": [{"branch": x["branch"],
                      "unpatched": x["unpatched"]["php_version"],
                      "patched": x["patched"]["php_version"]} for x in b],
        "binary_markers": len(markers()),
        "runtime_probes": len(runtime_probes()),
        "verified_on": provenance().get("verified_on", ""),
        "all_branches_distinguishable": all(
            all(v["unpatched"] != v["patched"] for v in row.values())
            for row in verify_matrix().values()) if verify_matrix() else False,
    }