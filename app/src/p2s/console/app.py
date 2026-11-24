"""p2s Web 控制台 API（FastAPI）。

形态定位：给客户交付时的主要交互界面。
  - 总览：全局风险视图
  - 设备发现：网段/批量主机 -> 设备类型 + PHP 暴露面
  - 资产台账：设备画像持久化、分组、负责人、导出
  - PHP 暴露面：只看跑 PHP 的资产，版本 vs 修复基线矩阵
  - 日志分析 / 本地取证 / 规则中心 / IOC 库 / 报告中心
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel

from .. import __version__ as VERSION
from ..core.ioc import IocLibrary
from ..core.rules import RULES
from ..core.versions import FIXED_RELEASES
from .ui import DASHBOARD_HTML, LOGIN_HTML

app = FastAPI(
    title="p2s — php2shell 检测控制台",
    description="CVE-2026-109618 / CVE-2026-109619 检测与暴露面评估",
    version=VERSION,
)

# 共享底座（路径/存储/鉴权/任务/CSV）已拆到 deps.py
from .deps import *  # noqa: F401,F403,E402


@app.middleware("http")
async def _auth_and_headers(request: Request, call_next):
    path = request.url.path
    if path in _UNAUTH_OK or _session_valid(request.cookies.get(SESSION_COOKIE)):
        response = await call_next(request)
    elif path.startswith("/api/"):
        return JSONResponse({"detail": "未登录或会话已过期"}, status_code=401)
    else:
        return RedirectResponse(url="/login", status_code=302)

    # 控制台是单页 + 内联样式脚本，缓存旧版本会让"改了看不到"，
    # 对 HTML 一律禁缓存；静态资源本来就没有外链，不影响性能。
    # 审计：记录所有写操作（失败不影响主请求）
    try:
        record_audit(request.method, path, response.status_code,
                     ADMIN_USER if _session_valid(request.cookies.get(SESSION_COOKIE)) else "",
                     request.client.host if request.client else "")
    except Exception:
        pass

    ctype = response.headers.get("Content-Type", "")
    if "text/html" in ctype:
        response.headers["Cache-Control"] = "no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


# --------------------------------------------------------------------------
# 存储
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# 模型
# --------------------------------------------------------------------------


class AgentReportIn(BaseModel):
    hostname: str = ""
    data: dict[str, Any] = {}




# --------------------------------------------------------------------------
# 登录
# --------------------------------------------------------------------------
class LoginIn(BaseModel):
    username: str = ADMIN_USER
    password: str = ""


@app.get("/login", response_class=HTMLResponse)
def login_page() -> str:
    return LOGIN_HTML


@app.get("/api/about")
def api_about() -> dict:
    """关于页数据：版本、覆盖范围、能力清单、数据位置、使用边界。

    刻意只返回**可核对的事实**（版本号、规则条数、路径），不放宣传语。
    """
    import platform as _pf
    import sys as _sys

    from .. import __version__
    from ..core import rulebook
    from .deps import DATA_DIR, SCANS_DIR

    st = rulebook.stats()
    scans = len(list(SCANS_DIR.glob("*.json"))) if SCANS_DIR.exists() else 0
    assets = 0
    try:
        ap = DATA_DIR / "assets.json"
        if ap.exists():
            assets = len(json.loads(ap.read_text(encoding="utf-8")))
    except Exception:
        assets = 0

    return {
        "product": "见微 Pinpoint",
        "tagline": "PHP2Shell 暴露面核查与加固",
        "version": __version__,
        "runtime": {
            "python": _pf.python_version(),
            "platform": _pf.platform(),
            "frozen": bool(getattr(_sys, "frozen", False)),
        },
        "scope": {
            "cves": ["CVE-2026-109618", "CVE-2026-109619"],
            "fixed_releases": {"8.5": "8.5.12", "8.4": "8.4.27",
                               "8.3": "8.3.36", "8.2": "8.2.35"},
            "layers": ["PHP ini", "PHP-FPM", "Web 服务器", "systemd", "Kubernetes"],
        },
        "rules": st,
        "data": {"dir": str(DATA_DIR), "assets": assets, "scans": scans},
        "capabilities": [
            {"k": "发现", "v": "端口/协议/指纹/设备识别，证据分 T1/T2/T3 三级"},
            {"k": "判定", "v": "四分支基线 + 补丁标记指纹 + changelog 回移，冲突降级为未知"},
            {"k": "加固", "v": "生成加固包 → 人工执行 → 回执校验；一次性票据 + 计划指纹防篡改"},
            {"k": "取证", "v": "Agent 只读采集安装点/生效配置/痕迹/进程/连接"},
            {"k": "监控", "v": "多条定时计划、失败重试、Webhook 通知"},
        ],
        "boundaries": [
            "平台不主动扫描任何外部地址，只扫描你填写的内网目标",
            "平台不直连业务主机执行命令：加固以「包」交付，由你在目标机执行",
            "配置加固是风险缓解，**不等于修复**；唯一完整修复是升级到修复版本",
            "存储态写入成功 ≠ 运行时生效：必须重启服务并用 phpinfo / 业务请求确认",
        ],
    }


@app.post("/api/login")
def api_login(body: LoginIn) -> Response:
    if not _credentials_ok(body.username, body.password):
        time.sleep(0.4)          # 拖慢暴力破解
        raise HTTPException(status_code=401, detail="口令错误")
    sid = _issue_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        SESSION_COOKIE, sid, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/"
    )
    return resp


@app.post("/api/logout")
def api_logout(request: Request) -> Response:
    sid = request.cookies.get(SESSION_COOKIE)
    if sid:
        with _sessions_lock:
            _sessions.pop(sid, None)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


# --------------------------------------------------------------------------
# 总览
# --------------------------------------------------------------------------
@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "time": datetime.now().isoformat(timespec="seconds"), "version": VERSION}


#: 扫描报告摘要键：列表页只需要这些，不必把每份报告里的 assets/findings 全传出去


@app.get("/api/overview")
def api_overview() -> dict:
    assets = _load_assets()
    scans = _load_scans(50)
    scan_total = len(list(SCANS_DIR.glob("*.json"))) if SCANS_DIR.exists() else 0

    by_type: dict[str, int] = {}
    by_exposure: dict[str, int] = {}
    by_risk: dict[str, int] = {"critical": 0, "medium": 0, "low": 0}
    php_versions: dict[str, int] = {}
    for a in assets:
        by_type[a.get("device_label", "未识别设备")] = by_type.get(a.get("device_label", "未识别设备"), 0) + 1
        exp = a.get("exposure", "unknown")
        by_exposure[exp] = by_exposure.get(exp, 0) + 1
        r = a.get("risk", "low")
        by_risk[r] = by_risk.get(r, 0) + 1
        if a.get("php_version"):
            php_versions[a["php_version"]] = php_versions.get(a["php_version"], 0) + 1

    # 资产变化：从最近若干次扫描的 changes 里聚合
    change_counts = {"new": 0, "changed": 0, "gone": 0}
    recent_changes: list[dict] = []
    for s in scans[:20]:
        for ch in s.get("changes") or []:
            kind = ch.get("kind")
            if kind in change_counts:
                change_counts[kind] += 1
            recent_changes.append(ch)
    recent_changes = recent_changes[:20]

    return {
        "total_assets": len(assets),
        "alive": sum(1 for a in assets if a.get("alive")),
        "php_present": sum(1 for a in assets if a.get("php_present")),
        "exposed": sum(1 for a in assets if a.get("exposure") == "exposed"),
        "patched": sum(1 for a in assets if a.get("exposure") == "patched"),
        "not_php": sum(1 for a in assets if a.get("exposure") == "not_php"),
        "unknown": sum(1 for a in assets if a.get("exposure") == "unknown"),
        "by_type": by_type,
        "by_exposure": by_exposure,
        "by_risk": by_risk,
        "php_versions": php_versions,
        "fixed_releases": FIXED_RELEASES,
        "scan_count": scan_total,
        "config_issues": sum(1 for a in assets if a.get("host_issues")),
        "recent_scans": [_scan_summary(s) for s in scans[:8]],
        "groups": sorted({a.get("group", "default") for a in assets}),
        "changes": change_counts,
        "recent_changes": recent_changes,
    }


# --------------------------------------------------------------------------
# 设备发现
#
# 注意：这里不再保留同步版本的 /api/discover —— 网段扫描是分钟级操作，
# 同步端点会占住线程池、绕过任务队列、也无法取消。统一走 /api/jobs。
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# 资产台账
# --------------------------------------------------------------------------
# 资产台账路由已拆到 assets_api.py
from .assets_api import AssetIn, api_php_exposure  # noqa: F401  兼容再导出（导出接口仍在此文件复用）
from .assets_api import router as assets_router

app.include_router(assets_router)



# --------------------------------------------------------------------------
# 扫描
#
# 只保留 URL 探测的后台执行入口（_run_url）。原先的同步 /api/scan/url、
# /api/scan/logs、/api/scan/host 一律移除：它们绕过任务队列，且 scan/logs
# 直接读任意路径构成任意文件读取。
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# 规则 / IOC / 报告
# --------------------------------------------------------------------------
@app.get("/api/rules")
def api_rules() -> dict:
    return {"count": len(RULES), "rules": [r.to_dict() for r in RULES]}


#: 规则 → 导出用的关键字（Sigma / IDS 只能做字面量匹配，映射到规则的主特征串）
_RULE_KEYWORDS: dict[str, list[str]] = {
    "upload_progress": ["PHP_SESSION_UPLOAD_PROGRESS"],
    "phpsessid_in_body": ["PHPSESSID"],
    "php_in_filename": ["<?php", "<?="],
    "serialized_in_filename": ["|O:", "|C:", "|a:"],
    "oversized_filename": ["Content-Disposition: form-data"],
    "chunked_multipart": ["chunked"],
    "session_path_in_uri": ["sess_"],
    "oom_in_response": ["Allowed memory size"],
    "session_destruction_failed": ["Session object destruction failed"],
    "anomalous_sessionid_length": ["PHPSESSID="],
    "probe_burst": ["PHP_SESSION_UPLOAD_PROGRESS"],
    "scanner_user_agent": ["php2shell", "p2srun"],
    "vulnerable_version_banner": ["X-Powered-By"],
}

#: 规则所需字段 → Suricata 粘性缓冲区
_SURICATA_BUFFER = {
    "body": "http_client_body",
    "req_headers": "http_header",
    "uri": "http_uri",
    "ua": "http_user_agent",
    "resp_body": "file_data",
    "resp_headers": "http_header",
}

_SURICATA_CLASSTYPE = {
    "critical": "web-application-attack",
    "high": "web-application-attack",
    "medium": "policy-violation",
    "low": "misc-activity",
    "info": "misc-activity",
}


def _rule_keywords(matcher: str | None) -> list[str]:
    return _RULE_KEYWORDS.get(matcher or "", ["PHP_SESSION_UPLOAD_PROGRESS"])


def _yaml_quote(s: str) -> str:
    """用 JSON 字符串作 YAML 标量：对 `<?php`、`|O:` 这类字符都安全。"""
    return json.dumps(s, ensure_ascii=False)


def _export_sigma() -> str:
    today = datetime.now().date().isoformat()
    blocks: list[str] = []
    for r in RULES:
        kws = "\n".join(f"      - {_yaml_quote(k)}" for k in _rule_keywords(r.matcher))
        blocks.append(
            "\n".join(
                [
                    "title: " + _yaml_quote(f"p2s {r.id} {r.name}"),
                    "id: " + uuid.uuid5(uuid.NAMESPACE_DNS, r.id).hex,
                    "status: experimental",
                    "description: " + _yaml_quote(r.description),
                    "references:",
                    "  - " + _yaml_quote("https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w"),
                    "  - " + _yaml_quote("https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"),
                    "author: p2s",
                    f"date: {today}",
                    "tags:",
                    "  - cve.2026.109618",
                    "  - cve.2026.109619",
                    "logsource:",
                    "  category: webserver",
                    "detection:",
                    "  keywords:",
                    kws,
                    "  condition: keywords",
                    f"level: {r.severity}",
                    f"# matcher={r.matcher} requires={r.requires} dimension={r.dimension}",
                ]
            )
        )
    return "\n---\n".join(blocks) + "\n"


#: 规则所需字段 → ModSecurity 变量（每条规则取主特征串，单条 SecRule，便于维护）
_MODSEC_VAR = {
    "body": "REQUEST_BODY",
    "req_headers": "REQUEST_HEADERS",
    "uri": "REQUEST_URI",
    "ua": "REQUEST_HEADERS:User-Agent",
    "resp_body": "RESPONSE_BODY",
    "resp_headers": "RESPONSE_HEADERS",
    "any": "REQUEST_URI",
}


def _export_modsecurity() -> str:
    lines = [
        "# p2s — php2shell ModSecurity 规则（自动生成，勿手改）",
        "# 放置到 modsecurity 的 conf.d 目录后 reload 即可",
        "SecRuleEngine On",
        "",
    ]
    for idx, r in enumerate(RULES):
        rule_id = 9900100 + idx * 10
        kw = _rule_keywords(r.matcher)[0].replace('"', '\\"')
        phase = 4 if r.requires in ("resp_body", "resp_headers") else 2
        var = _MODSEC_VAR.get(r.requires, "REQUEST_URI")
        msg = f"p2s {r.id} {r.name}".replace("'", "’")
        lines.append(
            f'SecRule {var} "@contains {kw}" \\\n'
            f'    "id:{rule_id},phase:{phase},pass,log,'
            f"tag:'CVE-2026-109618',tag:'CVE-2026-109619',"
            f"severity:'{r.severity.upper()}',msg:'{msg}'\""
        )
    return "\n".join(lines) + "\n"


def _export_suricata() -> str:
    lines = [
        "# p2s — php2shell Suricata 规则（自动生成）",
        "# 每条规则对应核心 detectors/rules.py 里的一条检测规则",
    ]
    for idx, r in enumerate(RULES):
        kw = _rule_keywords(r.matcher)[0].replace("\\", "\\\\").replace('"', '\\"')
        msg = f"p2s {r.id} {r.name}".replace('"', "'")
        buf = _SURICATA_BUFFER.get(r.requires, "")
        sticky = f" {buf};" if buf else ""
        ctype = _SURICATA_CLASSTYPE.get(r.severity, "misc-activity")
        lines.append(
            f'alert http any any -> any any (msg:"{msg}"; '
            f"flow:established,to_server; content:\"{kw}\"; nocase;{sticky} "
            f"classtype:{ctype}; sid:{9900100 + idx * 10}; rev:1;)"
        )
    return "\n".join(lines)


@app.get("/api/rules/export/{fmt}")
def api_rules_export(fmt: str) -> Response:
    """导出规则：sigma / modsecurity / suricata。

    导出内容由 RULES 数据驱动，不是写死的模板 —— 加一条规则就会多一条导出。
    """
    builders = {
        "sigma": (_export_sigma, "text/yaml; charset=utf-8", "p2s-php2shell.sigma.yml"),
        "modsecurity": (_export_modsecurity, "text/plain; charset=utf-8",
                        "p2s-php2shell-modsecurity.conf"),
        "suricata": (_export_suricata, "text/plain; charset=utf-8",
                     "p2s-php2shell-suricata.rules"),
    }
    if fmt not in builders:
        raise HTTPException(status_code=400, detail="仅支持 sigma / modsecurity / suricata")
    fn, media, filename = builders[fmt]
    return Response(
        content=fn(),
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/ioc")
def api_ioc() -> dict:
    lib = IocLibrary()
    return {
        "summary": lib.summary(),
        "ips": list(lib.ips),
        "domains": list(lib.domains),
        "urls": list(lib.urls),
        "hashes": lib.hashes,
        "user_agents": list(lib.user_agents),
    }


# 扫描/任务路由已拆到 scan_api.py
from .hardening_api import router as hardening_router
from .ops_api import record_audit, start_scheduler
from .ops_api import router as ops_router
from .scan_api import _is_specific_product  # noqa: F401  兼容再导出（测试从这里取）
from .scan_api import router as scan_router

app.include_router(scan_router)
app.include_router(ops_router)
app.include_router(hardening_router)





#: 配置项的期望值（服务端统一判定，避免脚本版本差异导致结论不一致）
# Agent 路由（/api/agent/*、主机报告归一化）已拆到 agent_api.py
# 兼容再导出：测试与外部脚本历史上从 app 导入这两个归一化函数
from .agent_api import (  # noqa: F401
    _normalize_host_report,
    _verdict_from_host_report,
)
from .agent_api import router as agent_router

app.include_router(agent_router)


# --------------------------------------------------------------------------
# 任务中心（长耗时操作走后台队列，支持进度、取消、持久化）
# --------------------------------------------------------------------------




#: 判定"资产发生变化"时比较的字段。
#: 只认会改变结论的字段 —— product/device_label 只是文案（例如"捷普设备（证书域名）"这类
#: 推断标签每次可能微调），把它们算作变化会让"变化"列全亮，失去信号价值。





































# --------------------------------------------------------------------------
# 日志文件上传（客户未必能访问服务器本地路径）
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# 删除与导出
# --------------------------------------------------------------------------


@app.get("/api/php-exposure/export")
def api_php_export() -> Response:
    rows: list[list[Any]] = [[
        "host", "device", "php_version", "sapi", "fixed_release",
        "status", "exposure", "risk", "owner", "group",
    ]]
    for r in api_php_exposure()["rows"]:
        rows.append([
            r.get("host", ""), r.get("device_label", ""), r.get("php_version") or "",
            r.get("sapi") or "", r.get("fixed_release") or "", r.get("status", ""),
            r.get("exposure", ""), r.get("risk", ""), r.get("owner") or "", r.get("group") or "",
        ])
    return _csv_response(rows, "p2s-php-exposure.csv")


@app.get("/api/host/export")
def api_host_export() -> Response:
    assets = _load_assets()
    rows: list[list[Any]] = [[
        "host", "device_type", "device_label", "vendor", "os_hint", "php_present",
        "php_version", "sapi", "exposure", "risk", "group", "owner", "note",
    ]]
    for a in assets:
        rows.append([
            a.get("host", ""), a.get("device_type", ""), a.get("device_label", ""),
            a.get("vendor") or "", a.get("os_hint") or "", a.get("php_present"),
            a.get("php_version") or "", a.get("sapi") or "", a.get("exposure", ""),
            a.get("risk", ""), a.get("group") or "", a.get("owner") or "", a.get("note") or "",
        ])
    return _csv_response(rows, "p2s-host-assets.csv")


# --------------------------------------------------------------------------
# 界面
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return DASHBOARD_HTML

# 定时扫描调度（随进程启动，daemon 线程）
start_scheduler()
