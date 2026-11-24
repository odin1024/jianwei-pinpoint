"""判定与评分引擎

职责（03 文档 3.5）：
    1. 证据聚合与冲突消解
    2. 风险评分（0-100）与分级（P0-P3）
    3. 输出置信度与人类可读理由

设计要点：
    不取"多数票"，冲突时取最保守结论并标记 needs_review。
    UNKNOWN 是一等公民，绝不默认判安全。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import (
    Confidence,
    DetectionContext,
    Evidence,
    Grade,
    Finding,
    Verdict,
)
from .phpversion import (
    VersionStatus,
    evaluate,
    fixed_for,
    parse_version,
    support_end,
    upgrade_path,
)
from .rules import grade_for, sapi_weight

PATCH_DAY = "2026-10-21"


@dataclass
class VerdictInput:
    evidences: list[Evidence] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _best_version(evs: list[Evidence]):
    cands = [e for e in evs if e.kind == "version" and e.key == "php.version"]
    if not cands:
        return None, None
    cands.sort(key=lambda e: (e.precedence, e.confidence.score), reverse=True)
    for e in cands:
        v = parse_version(str(e.value))
        if v:
            return v, e
    return None, None


def _best_sapi(evs: list[Evidence]) -> tuple[str, Confidence, Evidence | None]:
    cands = [e for e in evs if e.kind == "sapi" and e.key == "php.sapi"]
    if not cands:
        return "unknown", Confidence.UNKNOWN, None
    # phpinfo / 主机事实优先于远程推断
    cands.sort(key=lambda e: (e.confidence.score, e.precedence), reverse=True)
    best = cands[0]
    return str(best.value or "unknown"), best.confidence, best


def _patch_status(evs: list[Evidence]) -> tuple[bool | None, Confidence, Evidence | None]:
    cands = [
        e for e in evs
        if e.key == "php.patch_status" and e.kind in ("changelog", "binary", "source")
    ]
    if not cands:
        return None, Confidence.UNKNOWN, None
    cands.sort(key=lambda e: e.precedence, reverse=True)
    best = cands[0]
    val = best.value if isinstance(best.value, dict) else {}
    patched = val.get("patched")
    if patched is True:
        return True, Confidence.CONFIRMED, best
    if patched is False:
        return False, best.confidence, best
    return None, Confidence.UNKNOWN, best


def _ini_map(evs: list[Evidence]) -> dict[str, str]:
    out: dict[str, str] = {}
    for e in evs:
        if e.kind == "ini" and e.key.startswith("ini."):
            out[e.key[4:]] = str(e.value)
    return out


def config_exploitability(ini: dict[str, str], ruleset: dict[str, Any]) -> tuple[float, dict[str, float]]:
    """配置可利用性 0-1（04 文档 10.2）。"""
    if not ini:
        return 0.60, {"note": -1.0}  # 无配置数据，给中性偏保守值

    detail: dict[str, float] = {}
    total_w = 0.0
    acc = 0.0

    ml = ini.get("memory_limit")
    if ml is None:
        v = 0.60
    elif ml.strip() in ("-1", "0"):
        v = 0.35
    else:
        v = 1.00
    w = ruleset["config_weights"]["memory_limit"]
    acc += v * w; total_w += w; detail["memory_limit"] = v

    up = ini.get("session.upload_progress.enabled")
    if up is None:
        v = 0.60
    elif up.strip().lower() in ("on", "1", "true"):
        v = 1.00
    else:
        v = 0.45
    w = ruleset["config_weights"]["session.upload_progress.enabled"]
    acc += v * w; total_w += w; detail["session.upload_progress.enabled"] = v

    pms = ini.get("post_max_size")
    if pms is None:
        v = 0.60
    else:
        v = 0.60 if _to_mb(pms) and _to_mb(pms) < 2 else 1.00
    w = ruleset["config_weights"]["post_max_size"]
    acc += v * w; total_w += w; detail["post_max_size"] = v

    mfu = ini.get("max_file_uploads")
    v = 1.00 if mfu is None or (mfu.isdigit() and int(mfu) >= 10) else 0.70
    w = ruleset["config_weights"]["max_file_uploads"]
    acc += v * w; total_w += w; detail["max_file_uploads"] = v

    nest = ini.get("max_input_nesting_level")
    v = 1.00 if nest is None or (nest.isdigit() and int(nest) >= 32) else 0.70
    w = ruleset["config_weights"]["max_input_nesting_level"]
    acc += v * w; total_w += w; detail["max_input_nesting_level"] = v

    # 废弃 INI：这里用 expose_php/display_errors 作为「配置卫生」的代理指标
    hygiene = 1.0
    if ini.get("display_errors", "").lower() in ("on", "1"):
        hygiene = 1.0
    detail["deprecated_ini_proxy"] = hygiene
    w = ruleset["config_weights"]["deprecated_ini"]
    acc += hygiene * w; total_w += w

    return round(acc / total_w, 3) if total_w else 0.6, detail


def _to_mb(size: str) -> float | None:
    s = size.strip().upper()
    mult = {"K": 1 / 1024, "M": 1, "G": 1024}
    for suffix, m in mult.items():
        if s.endswith(suffix):
            try:
                return float(s[:-1]) * m
            except ValueError:
                return None
    try:
        return float(s) / (1024 * 1024)
    except ValueError:
        return None


def _build_remediation(
    verdict: Verdict, version, sapi: str, ruleset: dict[str, Any]
) -> list[dict[str, Any]]:
    """按场景裁剪缓解措施。已修复时只留「重启 worker」与禁用项提示。"""
    items: list[dict[str, Any]] = []
    by_id = {m["id"]: m for m in ruleset["mitigations"]}

    if verdict in (Verdict.VULNERABLE, Verdict.LIKELY_VULNERABLE):
        v = version
        status = evaluate(v)[0] if v else None
        if status == VersionStatus.VULNERABLE_EOL:
            items.append(dict(by_id["eol_migrate"]))
        else:
            up = dict(by_id["upgrade"])
            if v and fixed_for(v):
                up["action"] = f"升级至 {fixed_for(v)} 或更高版本"
                up["target"] = fixed_for(v)
            items.append(up)

        items.append(dict(by_id["disable_upload_progress"]))
        if v and v.branch == (8, 5):
            items.append(dict(by_id["disable_backtraces"]))
        items.append(dict(by_id["memory_limit_disable"]))
        if sapi == "fpm-fcgi":
            items.append(dict(by_id["pm_max_requests"]))
        items.append(dict(by_id["frontend_block"]))
        items.append(dict(by_id["restart_workers"]))
    elif verdict == Verdict.UNKNOWN:
        items.append({
            "id": "collect_evidence", "complete": False, "priority": 1,
            "action": "补采证据：提供主机 SSH 凭证，或检查 phpinfo / 包 changelog",
            "note": "当前证据不足，无法判定。禁止按「无风险」处理",
        })
        items.append(dict(by_id["frontend_block"]))
    else:  # PATCHED / NOT_APPLICABLE
        items.append({
            "id": "keep_watch", "complete": True, "priority": 4,
            "action": "保持监测：日志回溯至 2026-10-17，排查是否在修复前已被利用",
            "note": "补丁只能关门，回答不了「谁进来过」",
        })

    # 两条永久提示，与结论无关
    items.append(dict(by_id["forbid_rlimit"]))
    if verdict in (Verdict.VULNERABLE, Verdict.LIKELY_VULNERABLE):
        items.append(dict(by_id["restrict_exposure"]))

    # 去重 + 排序
    seen = set()
    uniq = []
    for it in sorted(items, key=lambda x: x.get("priority", 9)):
        if it["id"] in seen:
            continue
        seen.add(it["id"])
        uniq.append(it)
    return uniq


def judge(
    ctx: DetectionContext,
    evidences: list[Evidence],
    ruleset: dict[str, Any],
    extra_notes: list[str] | None = None,
    extra_errors: list[str] | None = None,
) -> Finding:
    notes = list(extra_notes or [])
    errors = list(extra_errors or [])

    version, version_ev = _best_version(evidences)
    sapi, sapi_conf, sapi_ev = _best_sapi(evidences)
    patched, patch_conf, patch_ev = _patch_status(evidences)
    ini = _ini_map(evidences)
    exposure = str(ctx.options.get("exposure", "internet"))

    status = VersionStatus.UNPARSEABLE
    status_note = "无版本信息"
    if version:
        status, status_note = evaluate(version)

    verdict: Verdict
    confidence: Confidence
    reason: str

    # ---------- 冲突检测：版本 vs changelog ----------
    conflict = False

    # ---------- 判定主逻辑 ----------
    if patched is True:
        verdict = Verdict.PATCHED
        confidence = Confidence.CONFIRMED
        reason = f"补丁级核验通过（{patch_ev.method if patch_ev else 'n/a'}）：该运行时已包含本次修复"
        if version:
            reason += f"；报告版本 {version}"
    elif patched is False:
        if version and status == VersionStatus.PATCHED:
            # 版本号达标但 changelog 说没打补丁 → 版本造假/自编译
            verdict = Verdict.VULNERABLE
            confidence = Confidence.HIGH
            conflict = True
            reason = (
                f"版本号 {version} 看似达标（≥{fixed_for(version)}），但安装物料证据显示未包含修复，"
                f"判定为版本造假或自编译未打补丁"
            )
        else:
            verdict = Verdict.VULNERABLE
            confidence = patch_conf if patch_conf != Confidence.UNKNOWN else Confidence.HIGH
            reason = f"未修复：{status_note}；且补丁核验未发现修复痕迹"
    elif version is None:
        # 无版本线索：看 SAPI 与 multipart 可达性
        multipart_ok = any(
            e.key == "http.multipart_accepted" and e.value is True for e in evidences
        )
        if sapi in ("apache2handler", "frankenphp") and sapi_conf.score >= 0.6:
            verdict = Verdict.LIKELY_VULNERABLE
            confidence = Confidence.MEDIUM
            reason = (
                f"无法取得版本，但 SAPI 判定为 {sapi}（暴露度最高，应用无关 RCE 已确认），"
                f"按疑似受影响处理"
            )
        elif multipart_ok:
            verdict = Verdict.LIKELY_VULNERABLE
            confidence = Confidence.LOW
            reason = "无法取得版本，但目标接受 multipart 请求（漏洞触发入口可达），按疑似处理"
        else:
            verdict = Verdict.UNKNOWN
            confidence = Confidence.UNKNOWN
            reason = "证据不足：既无版本信息，也无法确认 SAPI 与 multipart 可达性"
    elif status == VersionStatus.PATCHED:
        # 版本达标，但没有安装物料核验
        verdict = Verdict.PATCHED
        confidence = Confidence.MEDIUM
        reason = (
            f"版本 {version} 达到修复版本 {fixed_for(version)}，"
            f"但未经安装物料核验（版本号可被伪造/回移补丁也可保留旧版本号）"
        )
    elif status in (VersionStatus.VULNERABLE, VersionStatus.VULNERABLE_EOL):
        verdict = Verdict.VULNERABLE
        confidence = Confidence.HIGH if version_ev and version_ev.precedence >= 70 else Confidence.MEDIUM
        reason = f"未修复：{status_note}"
    elif status in (VersionStatus.UNKNOWN_BRANCH, VersionStatus.PRERELEASE):
        verdict = Verdict.UNKNOWN
        confidence = Confidence.UNKNOWN
        reason = status_note
    else:
        verdict = Verdict.UNKNOWN
        confidence = Confidence.UNKNOWN
        reason = "无法判定"

    # CLI-only 特殊处理：无 Web 暴露 → 不适用
    if sapi == "cli" and verdict != Verdict.PATCHED:
        verdict = Verdict.NOT_APPLICABLE
        confidence = Confidence.CONFIRMED
        reason = "该 PHP 仅以 CLI 方式运行，无跨请求复用的 worker，不具备可利用条件"

    # ---------- 评分 ----------
    cfg_score, cfg_detail = config_exploitability(ini, ruleset)
    sw, sapi_note = sapi_weight(ruleset, sapi)
    w = ruleset["score_weights"]
    exp_w = ruleset["exposure_weights"].get(exposure, 0.6)

    if status in (VersionStatus.VULNERABLE,):
        version_risk = 0.80
    elif status == VersionStatus.VULNERABLE_EOL:
        version_risk = 1.00
    elif status == VersionStatus.PATCHED:
        version_risk = 0.00
    else:
        version_risk = 0.30

    if patched is True:
        pf = ruleset["patch_factor"]["patched_confirmed"]
    elif verdict == Verdict.PATCHED:
        pf = ruleset["patch_factor"]["patched_suspected"]
    elif verdict == Verdict.UNKNOWN:
        pf = ruleset["patch_factor"]["unknown"]
    else:
        pf = ruleset["patch_factor"]["no_evidence"]

    raw = 100 * (
        w["version_risk"] * version_risk
        + w["sapi_exposure"] * sw
        + w["config_exploitability"] * cfg_score
        + w["exposure"] * exp_w
    ) * pf

    if verdict == Verdict.NOT_APPLICABLE:
        raw = 3.0
    if verdict == Verdict.PATCHED and patched is True:
        raw = min(raw, 5.0)

    risk_score = int(round(max(0.0, min(100.0, raw))))
    grade = Grade(grade_for(ruleset, risk_score)) if risk_score > 0 else Grade.NONE

    # UNKNOWN 不允许被当成"低风险"放过：等级至少 P1，强制驱动补采证据
    if verdict == Verdict.UNKNOWN and grade in (Grade.P2, Grade.P3, Grade.NONE):
        grade = Grade.P1
        notes.append("等级已上调至 P1：无法判定 ≠ 无风险，必须在 24 小时内补采证据")

    # ---------- 补充说明 ----------
    if version:
        se = support_end(version)
        if se == "2026-12-31":
            notes.append("⚠ PHP 8.2 安全支持将于 2026-12-31 到期，需提前规划升级")
        elif se:
            notes.append(f"该分支安全支持至 {se}")
        if status == VersionStatus.VULNERABLE_EOL:
            notes.append("EOL 分支无官方修复，升级路径应为「迁移」而非「打补丁」")
    if sapi_ev and sapi_conf.score <= 0.4:
        notes.append(f"SAPI 为远程推断（{sapi}），建议通过主机核查或 phpinfo 确认")
    if conflict:
        notes.append("⚠ 版本号与安装物料证据冲突，已按保守方向判定并标记需人工复核")
    if verdict == Verdict.PATCHED and patched is True:
        notes.append("补丁只能关门：请回溯 2026-10-17 起日志，确认修复前是否已被利用")

    remediation = _build_remediation(verdict, version, sapi, ruleset)

    return Finding(
        target=ctx.target,
        verdict=verdict,
        confidence=confidence,
        risk_score=risk_score,
        grade=grade,
        reason=reason,
        sapi=sapi,
        php_version=str(version) if version else None,
        factors={
            "version_risk": round(version_risk, 3),
            "sapi_exposure": round(sw, 3),
            "config_exploitability": round(cfg_score, 3),
            "exposure": round(exp_w, 3),
            "patch_factor": round(pf, 3),
        },
        evidences=evidences,
        remediation=remediation,
        notes=notes,
        errors=errors,
    )
