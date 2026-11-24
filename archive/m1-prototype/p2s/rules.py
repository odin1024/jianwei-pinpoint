"""规则库

内置一份 PHP2Shell 规则（与 docs/rules/php2shell-vuln-db.yaml 对应），
同时支持用 --rules 加载外部 JSON 规则包覆盖内置值。

为什么默认内置而不是读 YAML：
    本工具设计为「零第三方依赖」，PyYAML 不是标准库。
    外置规则包的权威格式见 YAML 文档，运行时用 JSON 等价物。
"""

from __future__ import annotations

import json
import os
from typing import Any

RULESET: dict[str, Any] = {
    "id": "php2shell",
    "name": "PHP2Shell (CVE-2026-109618 / CVE-2026-109619)",
    "version": "2026.10.28-1",
    "published_at": "2026-10-21T14:00:00Z",
    "exploitation_seen_since": "2026-10-17",
    "severity": "critical",
    "cvss_v4": 9.2,
    "cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "cves": [
        {"id": "CVE-2026-109618", "ghsa": "GHSA-w8hw-w9fx-j79w", "title": "RCE via OOM corruption"},
        {"id": "CVE-2026-109619", "ghsa": "GHSA-6wmf-4rv5-p3rp", "title": "RCE via stale global state"},
    ],
    # SAPI 权重：官方口径见 01 文档 4.2
    "sapi_matrix": {
        "apache2handler": {"weight": 1.00, "exploitable": "confirmed",
                           "note": "mod_php 无条件执行 request shutdown，请求启动阶段即可触发，已演示默认配置下 RCE"},
        "frankenphp":     {"weight": 1.00, "exploitable": "likely",
                           "note": "源码分析与 mod_php 同构，未验证"},
        "fpm-fcgi":       {"weight": 0.75, "exploitable": "confirmed",
                           "note": "启动失败会杀子进程；109619 的 session 生命周期 RCE 已在 FPM 验证"},
        "litespeed":      {"weight": 0.75, "exploitable": "likely",
                           "note": "模型类似 FPM，应用相关利用可能，未验证"},
        "cgi-fcgi":       {"weight": 0.40, "exploitable": "possible", "note": "未公开分析"},
        "cli-server":     {"weight": 0.50, "exploitable": "possible", "note": "内置开发服务器"},
        "cli":            {"weight": 0.10, "exploitable": "none",
                           "note": "单次执行、进程退出，无跨请求复用"},
        "unknown":        {"weight": 0.60, "exploitable": "unknown", "note": "无法判定 SAPI"},
    },
    # 配置可利用性（04 文档 10.2）
    "config_weights": {
        "memory_limit": 0.35,
        "session.upload_progress.enabled": 0.30,
        "post_max_size": 0.15,
        "max_file_uploads": 0.05,
        "max_input_nesting_level": 0.05,
        "deprecated_ini": 0.10,
    },
    # 评分权重（03 文档 3.5.2）
    "score_weights": {
        "version_risk": 0.40,
        "sapi_exposure": 0.25,
        "config_exploitability": 0.20,
        "exposure": 0.15,
    },
    "patch_factor": {
        "patched_confirmed": 0.05,
        "patched_suspected": 0.35,
        "no_evidence": 1.00,
        "unknown": 0.80,
    },
    "grade_thresholds": [
        (85, "P0"), (65, "P1"), (40, "P2"), (1, "P3"), (0, "NONE"),
    ],
    # 暴露面（资产标签）
    "exposure_weights": {
        "internet": 1.00,
        "internet_waf": 0.70,
        "internal": 0.40,
        "ops_only": 0.10,
        "unknown": 0.60,
    },
    "mitigations": [
        {"id": "upgrade", "complete": True, "priority": 1,
         "action": "升级至 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 或更高版本",
         "note": "官方明确：升级是唯一完整缓解手段"},
        {"id": "eol_migrate", "complete": True, "priority": 1,
         "condition": "version <= 8.1",
         "action": "该分支无官方修复，必须迁移至受支持分支（建议 8.4.x / 8.5.x）"},
        {"id": "disable_upload_progress", "complete": False, "priority": 2,
         "action": "session.upload_progress.enabled=0",
         "note": "仅切断已演示的 session 生命周期路径，不覆盖其他 producer"},
        {"id": "disable_backtraces", "complete": False, "priority": 2,
         "condition": "PHP 8.5", "action": "fatal_error_backtraces=0"},
        {"id": "memory_limit_disable", "complete": False, "priority": 3,
         "action": "memory_limit=-1，并在 Web 服务器/代理层独立限制请求体大小",
         "note": "非完整缓解；若底层 mmap 失败仍可能回到脆弱路径"},
        {"id": "pm_max_requests", "complete": False, "priority": 3,
         "condition": "PHP-FPM", "action": "pm.max_requests=1",
         "note": "打破跨请求复用条件，代价是每请求一次进程启动开销"},
        {"id": "frontend_block", "complete": False, "priority": 3,
         "action": "WAF/反向代理阻断已知攻击模式，限制 multipart part 数、part 内 header 数、请求体大小",
         "note": "可被构造变形绕过，仅作时间窗保护"},
        {"id": "restrict_exposure", "complete": False, "priority": 3,
         "action": "临时下线 / 只读模式 / 收敛至运维网段或 VPN"},
        {"id": "forbid_rlimit", "complete": False, "forbidden": True,
         "action": "禁止使用 RLIMIT_AS / RLIMIT_DATA 做内存限制",
         "note": "达到限制会使 mmap() 失败，重新触发脆弱 longjmp 路径，扩大攻击面"},
        {"id": "restart_workers", "complete": False, "priority": 1,
         "action": "任何配置变更后必须重启全部 PHP worker",
         "note": "运行中的 worker 仍沿用旧配置，未重启等于未生效"},
    ],
    # phpinfo 中需要提取的配置项
    "phpinfo_keys": [
        "PHP Version", "Server API", "Build Date", "Configure Command",
        "Thread Safety", "Loaded Configuration File",
        "memory_limit", "post_max_size", "max_file_uploads",
        "max_input_nesting_level", "enable_post_data_reading", "expose_php",
        "session.upload_progress.enabled", "session.upload_progress.cleanup",
        "fatal_error_backtraces", "display_errors", "open_basedir",
    ],
    "phpinfo_paths": [
        "phpinfo.php", "info.php", "i.php", "test.php", "php_info.php",
        "php.php", "_phpinfo.php", "phpinfo",
    ],
}


def load_ruleset(path: str | None = None) -> dict[str, Any]:
    """加载规则包。无路径则返回内置规则。"""
    if not path:
        return dict(RULESET)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"规则包不存在：{path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    merged = dict(RULESET)
    merged.update(data)
    return merged


def sapi_weight(ruleset: dict[str, Any], sapi: str | None) -> tuple[float, str]:
    key = (sapi or "unknown").lower()
    matrix = ruleset.get("sapi_matrix", {})
    if key in matrix:
        return matrix[key].get("weight", 0.6), matrix[key].get("note", "")
    # 宽松匹配
    for k, v in matrix.items():
        if k != "unknown" and k in key:
            return v.get("weight", 0.6), v.get("note", "")
    return 0.6, "无法确认 SAPI，按中等风险处理"


def grade_for(ruleset: dict[str, Any], score: int) -> str:
    for threshold, grade in ruleset.get("grade_thresholds", []):
        if score >= threshold:
            return grade
    return "P3"
