"""D4 补丁级核验（产品核心差异化）

回答的不是「版本号是多少」，而是「这个运行时到底有没有包含本次修复」。

证据等级（由高到低）：
    1. 包 changelog 命中 CVE 编号        → 可单独定性「已修复」
    2. 二进制构建指纹 / 源码补丁痕迹      → 可单独定性「已修复」
    3. 版本号 + 构建日期组合              → 只能给「受影响」或「无法判定」
    4. 仅远程版本号                       → 只能给线索，必须标注未核验
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ..models import Confidence, DetectionContext, DetectionResult, Evidence
from ..phpversion import fixed_for, parse_version

PATCH_RELEASE_DAY = datetime(2026, 10, 21, tzinfo=timezone.utc)
CVE_RE = re.compile(r"CVE-2026-10961[89]", re.I)

DATE_FORMATS = (
    "%b %d %Y %H:%M:%S",   # Oct 21 2026 10:11:12
    "%b %d %Y",            # Oct 21 2026
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
)


def parse_build_date(text: str | None) -> datetime | None:
    if not text:
        return None
    cleaned = text.strip().split("\n")[0]
    cleaned = re.sub(r"\s+", " ", cleaned)
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def run(ctx: DetectionContext, upstream: list[Evidence]) -> DetectionResult:
    res = DetectionResult(detector="D4")

    versions = [e for e in upstream if e.kind == "version" and e.key == "php.version"]
    build_dates = [e for e in upstream if e.kind == "version" and e.key == "php.build_date"]
    configure = [e for e in upstream if e.key == "php.configure_command"]
    changelogs = [e for e in upstream if e.kind == "changelog"]
    binaries = [e for e in upstream if e.kind == "binary"]

    # ---------- 1. 版本一致性检查（识破版本造假 / 缓存污染）----------
    if len(versions) >= 2:
        seen: dict[str, Evidence] = {}
        for e in versions:
            v = parse_version(str(e.value))
            if v:
                seen[str(v)] = e
        if len(seen) > 1:
            detail = {k: e.source for k, e in seen.items()}
            res.add(Evidence(
                "D4", "behavior", "consistency.version_conflict", detail,
                Confidence.HIGH,
                "不同来源报告的 PHP 版本不一致（可能为头伪造、缓存污染或多版本共存）",
                "behavior", "; ".join(f"{k}←{v}" for k, v in detail.items()),
            ))
            res.notes.append(
                "⚠ 版本来源冲突：" + "、".join(f"{k}({v})" for k, v in detail.items())
                + " — 以 phpinfo/主机事实为准，HTTP 头可信度下调"
            )

    # ---------- 2. 强证据：包 changelog ----------
    for e in changelogs:
        val = e.value if isinstance(e.value, dict) else {"patched": None}
        if val.get("patched") is True:
            res.add(Evidence("D4", "changelog", "php.patch_status",
                             {"patched": True, "verified": True,
                              "method": "package_changelog"},
                             Confidence.CONFIRMED,
                             "包 changelog 命中 CVE 编号，确认已回移补丁",
                             "changelog", e.source_ref or e.method))
            res.notes.append("✓ 补丁级核验通过：通过包 changelog 确认已修复")
            return res

    for e in binaries:
        val = e.value if isinstance(e.value, dict) else {}
        if val.get("patched") is True:
            res.add(Evidence("D4", "binary", "php.patch_status",
                             {"patched": True, "verified": True, "method": "binary_fingerprint"},
                             Confidence.CONFIRMED, "二进制指纹命中补丁构建",
                             "binary", e.source_ref or e.method))
            res.notes.append("✓ 补丁级核验通过：通过二进制指纹确认已修复")
            return res

    # ---------- 3. 明确未打补丁（changelog 存在但无 CVE）----------
    unpatched_logs = [e for e in changelogs
                      if isinstance(e.value, dict) and e.value.get("patched") is False]
    if unpatched_logs:
        res.add(Evidence("D4", "changelog", "php.patch_status",
                         {"patched": False, "verified": True,
                          "method": "package_changelog"},
                         Confidence.HIGH,
                         "包 changelog 未包含该 CVE，判定未修复",
                         "changelog", unpatched_logs[0].source_ref))
        res.notes.append("✗ 补丁级核验结论：包 changelog 无该 CVE，未修复")
        return res

    # ---------- 4. 中等证据：版本 + 构建日期 ----------
    best_version = None
    for e in sorted(versions, key=lambda x: -x.precedence):
        v = parse_version(str(e.value))
        if v:
            best_version = v
            break

    if best_version:
        fixed = fixed_for(best_version)
        bd = None
        for e in build_dates:
            bd = parse_build_date(str(e.value))
            if bd:
                break

        # 构建日期早于补丁发布日，且版本低于修复版 → 确定未修复
        if bd and bd < PATCH_RELEASE_DAY and fixed:
            res.add(Evidence("D4", "changelog", "php.patch_status",
                             {"patched": False, "verified": True,
                              "method": "build_date_before_patch"},
                             Confidence.HIGH,
                             f"构建日期 {bd.date()} 早于补丁发布日 2026-10-21，"
                             f"且版本低于 {fixed}",
                             "changelog", f"Build Date={bd.date()}"))
            res.notes.append("✗ 构建日期早于补丁发布日，不可能包含该修复")
            return res

        # 版本达标但无法证明补丁存在（发行版回移 / 自编译都可能）
        if fixed and best_version.tuple3 >= tuple(int(x) for x in fixed.split(".")):
            res.add(Evidence("D4", "behavior", "php.patch_status",
                             {"patched": None, "verified": False,
                              "method": "version_only", "reason": "version_meets_fixed"},
                             Confidence.LOW,
                             f"版本 {best_version} 达到 {fixed}，但无安装物料证据，"
                             f"无法排除版本字符串被改写或自编译未打补丁",
                             "version_remote", str(best_version)))
            res.notes.append(
                "补丁状态未经安装物料核验：版本达标 ≠ 已修复。"
                "如需确认，请提供主机凭证（--host）以便读取包 changelog 或二进制指纹"
            )
            return res

        # 版本低于修复版且无补丁证据
        res.add(Evidence("D4", "behavior", "php.patch_status",
                         {"patched": False, "verified": True if bd else False,
                          "method": "version_range"},
                         Confidence.HIGH if bd else Confidence.MEDIUM,
                         f"版本 {best_version} 低于修复版 {fixed}，且无补丁证据",
                         "version_remote", str(best_version)))
        res.notes.append(
            "✗ 版本位于受影响区间且无任何补丁证据，判定未修复"
            + ("（构建日期佐证）" if bd else "（仅有版本线索，建议主机侧复核）")
        )
        return res

    res.add(Evidence("D4", "behavior", "php.patch_status",
                     {"patched": None, "verified": False, "method": "no_data"},
                     Confidence.UNKNOWN, "无任何版本或补丁线索，无法核验",
                     "version_remote", ""))
    res.notes.append("无可用版本线索，补丁状态无法判定（UNKNOWN，不等于安全）")
    return res
