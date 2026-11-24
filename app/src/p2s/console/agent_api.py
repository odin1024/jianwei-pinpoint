"""Agent 路由：采集脚本下载 / 上报入口 / 主机报告归一化。

从 app.py 拆出（第二阶段）。依赖方向是单向的：agent_api → deps，
app.py 只负责 `include_router`，不再持有 Agent 相关逻辑。
"""

from __future__ import annotations

import hmac
import json
import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from ..core import agentkit
from ..core.versions import classify
from .deps import (  # noqa: F401  —— 显式导入，避免星号导入掩盖未定义名
    AGENT_TOKEN,
    _diff_asset,
    _load_assets,
    _lock,
    _new_scan,
    _persist,
    _save_assets,
)

router = APIRouter()

_EXPECTED_SETTINGS = {
    "session.upload_progress.enabled": "0",
    "fatal_error_backtraces": "0",
    "memory_limit": "-1",
    "post_max_size": "8M",
}


def _setting_ok(name: str, actual: str) -> bool:
    a = (actual or "").strip()
    exp = _EXPECTED_SETTINGS.get(name)
    if exp is None:
        return True
    if name == "post_max_size":
        return a.upper() in {"8M", "32M"}
    if name == "memory_limit":
        return a in {"-1", "0"}
    return a.lower() == exp.lower()


def _normalize_host_report(rep: dict) -> dict:
    """把"客户端只报事实"的报告补全为"服务端可判定的结论"。

    现场下载脚本只采集原始事实（版本、SAPI、ini 实际值、changelog 是否命中），
    判定统一在服务端做 —— 这样脚本改版不会改变结论口径。
    """
    installs = rep.get("installs") or []
    changelog_hit = rep.get("php_changelog_hit") or ""

    for i in installs:
        ver = i.get("version")
        if not i.get("verdict_status"):
            v = classify(ver)
            i["verdict_status"] = v.status
            i["needs_action"] = v.needs_action
            i["fixed_release"] = v.fixed_release
            i["reason"] = v.reason
        # 包 changelog 命中 = 发行版已回移补丁，比版本号更可信
        if changelog_hit:
            i["needs_action"] = False
            i["verdict_status"] = "patched"
            i["reason"] = f"包 changelog 命中 CVE（{changelog_hit}），判定已回移补丁"

    settings = rep.get("settings") or []
    # fatal_error_backtraces 只有 PHP 8.5+ 才有；8.3/8.4 上取不到值是正常的，不能报红
    versions = [str(i.get("version") or "") for i in installs]
    has_85 = any(v.startswith("8.5") or v.startswith("9.") for v in versions)
    for s in settings:
        if "ok" in s:
            continue
        name = str(s.get("name") or "")
        if name == "fatal_error_backtraces" and not has_85:
            s["expected"] = ""
            s["ok"] = True
            s.setdefault("note", "PHP 8.5 才有该配置，当前版本不适用")
            continue
        s["expected"] = _EXPECTED_SETTINGS.get(name, "")
        s["ok"] = _setting_ok(name, str(s.get("actual") or ""))
        s.setdefault("note", "")

    return rep


#: 每个配置项的整改动作（给客户看的可执行建议，不是复述问题）
_SETTING_ADVICE = {
    "session.upload_progress.enabled":
        "在 php.ini 设 session.upload_progress.enabled=0 并重启 php-fpm / apache。"
        "这是两条 CVE 共用的主触发点（rfc1867 上传进度处理器在 SAPI 启动阶段就执行，"
        "**不依赖应用是否调用 session_start()**）；最快的临时缓解是在 WAF/反代里"
        "直接拦截 multipart 请求体中的 PHP_SESSION_UPLOAD_PROGRESS 字样。"
        "注意：关闭它只是减少攻击面，"
        "CVE-2026-109618 的 OOM 路径位于 Zend 引擎核心，**唯一完整修复是升级 PHP 到修复版本**",
    "fatal_error_backtraces":
        "在 php.ini 设 fatal_error_backtraces=0（PHP 8.5 起可用），改完重启 php-fpm / apache",
    "memory_limit":
        "在 php.ini 设 memory_limit=-1（不限制），改完重启 php-fpm / apache",
    "post_max_size":
        "在 php.ini 设 post_max_size=8M 或 32M（与业务匹配），改完重启 php-fpm / apache",
}


def _host_evidence(rep: dict, exposure: str) -> list[str]:
    """把主机侧事实转成人能读的证据条目（与远程探测的证据同一展示口径）。"""
    ev: list[str] = []
    for i in rep.get("installs") or []:
        ev.append(
            f"主机侧安装点：{i.get('path')} v{i.get('version')}（{i.get('sapi') or '未知 SAPI'}）"
            f" → {i.get('reason') or i.get('verdict_status')}"
        )
    if rep.get("php_changelog_hit"):
        ev.append(f"包 changelog 命中 CVE：{rep['php_changelog_hit']}")
    for s in rep.get("settings") or []:
        if s.get("ok") is False:
            ev.append(f"生效配置不达标：{s.get('name')} = {s.get('actual') or '空'}（建议 {s.get('expected')}）")
    arts = _strip_self_artifacts(rep.get("artifacts") or [])
    rep["artifacts"] = arts
    if arts:
        ev.append(f"落地痕迹：近 7 天新增可疑文件 {len(arts)} 个（首个：{arts[0].get('path')}）")
    procs = rep.get("processes") or []
    if procs:
        ev.append(f"运行中的 PHP/Apache 进程 {len(procs)} 个（首个：{str(procs[0])[:80]}）")
    ev.append(f"判定方式：主机侧只读取证（非远程推断），结论 = {exposure}")
    return ev


def _remediation(rep: dict, exposure: str) -> list[str]:
    """根据采集到的事实生成整改建议。

    为什么放在服务端而不是脚本里：建议要跟判定口径一致，
    脚本只报事实、判定与建议都应该由一个地方出。
    """
    out: list[str] = []
    installs = rep.get("installs") or []

    if exposure == "exposed":
        bad = [i for i in installs if i.get("needs_action")]
        vers = "、".join(sorted({str(i.get("version") or "?") for i in bad})) or "当前版本"
        fixed = sorted({str(i.get("fixed_release") or "") for i in bad if i.get("fixed_release")})
        target = "、".join(fixed) if fixed else "8.2.35 / 8.3.36 / 8.4.27 / 8.5.12"
        out.append(f"升级 PHP {vers} 到修复版本 {target}；若为发行版包，先确认其 changelog 是否已回移补丁")
        out.append("升级顺序建议：先切流量到备节点 → 升级 → 跑一次本工具的「复扫」确认 exposure 变为已修复")

    for s in rep.get("settings") or []:
        if s.get("ok") is False:
            name = str(s.get("name") or "")
            advice = _SETTING_ADVICE.get(name)
            if advice:
                out.append(f"{name} 当前为 {s.get('actual') or '空'}（建议 {s.get('expected')}）：{advice}")

    if rep.get("php_changelog_hit"):
        out.append("该主机的发行版 changelog 已包含 CVE 修复记录，升级前请勿降级到更低版本；若分支已 EOL，可参考社区回补补丁 https://github.com/Anton-Barinov/php2shell-patches")

    return out


def _verdict_from_host_report(rep: dict) -> tuple[str, str, bool]:
    """把主机侧报告折算成台账口径的 exposure。

    这是"本地检测"相对远程探测的核心增量：远程只能看版本号，
    本地能读到**实际安装的二进制 + 包 changelog + 生效配置**，从而回答
    "这个运行时到底有没有包含修复"。返回 (exposure, 说明, 是否有 PHP)。
    """
    installs = rep.get("installs") or []
    if not installs:
        return "not_php", "主机侧未发现 PHP 安装点", False

    bad = [i for i in installs if i.get("needs_action")]
    if bad:
        vers = "、".join(sorted({str(i.get("version") or "?") for i in bad}))
        return "exposed", f"主机侧确认受影响：PHP {vers} 低于修复基线（以实际安装的二进制为准）", True

    patched = [i for i in installs if i.get("verdict_status") == "patched"]
    if patched and len(patched) == len(installs):
        vers = "、".join(sorted({str(i.get("version") or "?") for i in installs}))
        return "patched", f"主机侧确认已修复：全部 PHP 安装点（{vers}）已达修复基线", True

    unknown = [i for i in installs if i.get("verdict_status") != "patched"]
    vers = "、".join(sorted({str(i.get("version") or "?") for i in (unknown or installs)}))
    return "unknown", f"主机侧见到的 PHP 安装点（{vers}）版本无法判定，需人工确认", True


def _ingest_host_report(rep: dict, host: str, *, source: str = "agent") -> dict:
    """把一份主机侧报告落成扫描记录，并**合并进资产台账**（R-05）。

    以前 agent 上报只写了一条 scan，台账里看不到任何东西 ——
    等于白采了本地证据。现在本地结论会覆盖远程推断。
    """
    exposure, reason, php_present = _verdict_from_host_report(rep)
    now = datetime.now().isoformat(timespec="seconds")

    installs = rep.get("installs") or []
    risk = "critical" if exposure == "exposed" else ("low" if exposure in ("patched", "not_php") else "medium")

    with _lock:
        assets = _load_assets()
        by_host = {a["host"]: a for a in assets}
        old = by_host.get(host) or {}
        rec = dict(old) if old else {
            "id": uuid.uuid4().hex[:12],
            "host": host,
            "group": "default",
            "owner": "",
            "note": "",
            "first_seen": now,
            "device_label": "主机（本地取证）",
            "device_type": "host",
            "product": rep.get("platform") or "",
            "vendor": "",
        }
        rec.update({
            "alive": True,
            "php_present": php_present,
            "php_version": next((str(i.get("version")) for i in installs if i.get("version")), None),
            "sapi": next((i.get("sapi") for i in installs if i.get("sapi")), None) or rec.get("sapi"),
            "exposure": exposure,
            "risk": risk,
            "confidence": 0.95,          # 本地取证置信度高于任何远程推断
            "product_source": "host",
            "vendor_source": rec.get("vendor_source") or "host",
            "evidence_level": "host",
            "host_verified": True,
            "host_reason": reason,
            # 配置风险单独成列，便于总览统计与台账筛选（不再埋在 host_report 里）
            "host_issues": [
                {"name": s.get("name"), "actual": s.get("actual"),
                 "expected": s.get("expected"), "note": s.get("note") or ""}
                for s in (rep.get("settings") or []) if s.get("ok") is False
            ],
            "remediation": _remediation(rep, exposure),
            # 证据必须可追溯：本地结论也要能点开看到"凭什么这么判"
            "evidence": _host_evidence(rep, exposure),
            "host_report": {
                "hostname": rep.get("hostname"),
                "platform": rep.get("platform"),
                "checked_at": rep.get("checked_at"),
                "risk": rep.get("risk"),
                "php_bin": rep.get("php_bin") or "",
                "ini_path": rep.get("ini_path") or "",
                "ini_sha256": rep.get("ini_sha256") or "",
                "ini_candidates": [p for p in str(rep.get("ini_candidates_raw") or "").split() if p],
                "ini_files": _parse_ini_files(rep.get("ini_files_raw") or ""),
                "pool_overrides": _parse_pool_overrides(rep.get("pool_overrides_raw") or ""),
                "installs": installs,
                "settings": rep.get("settings") or [],
                "artifacts": (rep.get("artifacts") or [])[:50],
                "processes": (rep.get("processes") or [])[:30],
                "errors": rep.get("errors") or [],
            },
            "last_checked": now,
            "source": source,
        })
        diff = _diff_asset(old or None, rec)
        if diff:
            rec["change"] = {"at": now, **diff}
            rec.setdefault("change_history", [])
            rec["change_history"] = (old.get("change_history") or [])[-9:] + [rec["change"]]
        by_host[host] = rec
        _save_assets(list(by_host.values()))

    res = _new_scan("agent" if source == "agent" else "host")
    res.target_count = 1
    rep.setdefault("hostname", host)
    res.host_reports = [rep]
    res.assets = [rec]
    if diff:
        res.changes = [{"host": host, "at": now, **diff}]
    for a in rep.get("artifacts", []):
        res.findings.append({
            "rule_id": "P2S-HOST-001",
            "rule_name": f"主机侧痕迹: {a.get('kind')}",
            "severity": a.get("severity", "medium"),
            "dimension": "host",
            "cves": list(("CVE-2026-109618", "CVE-2026-109619")),
            "ts": rep.get("checked_at"),
            "ip": host,
            "uri": a.get("path"),
            "evidence": a.get("detail"),
        })
    _persist(res)
    return {"ok": True, "scan_id": res.scan_id, "host": host, "exposure": exposure,
            "reason": reason, "asset": rec}


@router.post("/api/agent/report")
async def api_agent_report(request: Request) -> dict:
    """Agent 上报入口。

    鉴权：X-P2S-Token（无鉴权的上报端点等于让任何人往台账里投毒）。
    体积：单份报告上限 2 MB，避免一次 POST 打满内存。

    同时接受两种 body 形态：
      · 扁平报告 {"hostname": "...", "installs": [...]} —— 现场下载的脚本发这个
      · 包装格式 {"hostname": "...", "data": {...}} —— Python agent 发这个
    以前只认后者，导致脚本上报被 Pydantic 丢成空报告（真机联调才暴露）。
    """
    token = request.headers.get("x-p2s-token", "")
    if not hmac.compare_digest(token, AGENT_TOKEN):
        raise HTTPException(status_code=401, detail="缺少或错误的 X-P2S-Token")

    raw_body = await request.body()
    if len(raw_body) > 2 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="上报内容过大")
    try:
        raw = json.loads(raw_body.decode("utf-8", "replace") or "{}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="body 不是合法 JSON") from None
    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="body 必须是 JSON 对象")

    nested = raw.get("data")
    data = nested if isinstance(nested, dict) and nested else raw
    # 优先用 IP 作为资产主键：远程扫描也是按 IP 建档，两者才能对上。
    # Agent 脚本常拿不到公网 IP（hostname -I 只有内网地址），此时用请求来源 IP 兜底。
    client_ip = ""
    try:
        client_ip = request.client.host if request.client else ""
    except Exception:
        client_ip = ""
    _ip = str(data.get("ip") or "").strip()
    _name = str(data.get("hostname") or raw.get("hostname") or "").strip()
    # 只有**看起来是 IP** 的来源地址才能当资产主键；否则退回 hostname，
    # 避免把测试客户端名（如 "testclient"）或代理名写进台账。
    import ipaddress as _ipmod
    try:
        _ipmod.ip_address(client_ip)
        _client_is_ip = True
    except ValueError:
        _client_is_ip = False
    host = _ip or (client_ip if _client_is_ip and client_ip not in ("127.0.0.1", "::1") else _name)
    if not host:
        raise HTTPException(status_code=400, detail="缺少主机标识（hostname / ip）")
    _normalize_host_report(data)
    _merge_hostname_alias(_name, host)
    return _ingest_host_report(data, host, source="agent")


@router.get("/api/agent/download")
def api_agent_download(request: Request, os: str = "linux", base: str = "") -> Response:
    """下载可直接运行的采集脚本，平台地址与令牌已注入。

    客户在业务主机上执行后自动上报，无需安装 Python、无需改配置。
    """
    if os not in agentkit.KINDS:
        raise HTTPException(status_code=400, detail="仅支持 os=linux 或 os=windows")
    meta = agentkit.KINDS[os]
    # 默认用当前访问地址；反向代理场景可用 ?base=https://p2s.corp.local 覆盖
    host_url = (base or str(request.base_url)).rstrip("/")
    try:
        text = agentkit.render(os, host_url, AGENT_TOKEN)
    except ValueError as exc:
        # base 是用户可控参数，且会被拼进要在生产主机上执行的脚本，
        # 非法输入必须拒绝生成，不能生成一份带注入的脚本让运维去跑。
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return Response(
        content=text,
        media_type=meta["content_type"],
        headers={"Content-Disposition": f'attachment; filename="{meta["filename"]}"'},
    )


@router.get("/api/agent/kits")
def api_agent_kits(request: Request) -> dict:
    """给界面用的元信息：两种脚本的说明与下载地址。"""
    base = str(request.base_url).rstrip("/")
    return {
        "base_url": base,
        "kits": [
            {"os": k, "label": v["label"], "filename": v["filename"],
             "url": f"{base}/api/agent/download?os={k}"}
            for k, v in agentkit.KINDS.items()
        ],
    }

def _merge_hostname_alias(hostname: str, ip: str) -> None:
    """把按 hostname 建的旧档案合并进 IP 档案（保留 id / first_seen / 处置状态）。"""
    if not hostname or not ip or hostname == ip:
        return
    with _lock:
        assets = _load_assets()
        by_host = {a["host"]: a for a in assets}
        alias = by_host.get(hostname)
        if alias is None:
            return
        target = by_host.get(ip)
        if target is None:
            alias["host"] = ip
            alias["hostname"] = hostname
            _save_assets(assets)
            return
        # 两边都有：保留 IP 档案为主，合并处置状态与首次发现时间
        for key in ("remediation_status", "owner", "ignored_reason", "remediation_updated_at"):
            if alias.get(key) and not target.get(key):
                target[key] = alias[key]
        if alias.get("first_seen") and (not target.get("first_seen")
                                        or alias["first_seen"] < target["first_seen"]):
            target["first_seen"] = alias["first_seen"]
        target["hostname"] = hostname
        assets = [a for a in assets if a.get("host") != hostname]
        _save_assets(assets)

#: Agent 自身产物：不能当成"可疑文件"上报（否则每台机器都会带一条噪声告警）
_SELF_ARTIFACT_HINTS = ("p2s-agent", "p2s_agent", "p2s-agentkit", "run_agent.sh")


def _strip_self_artifacts(arts: list) -> list:
    out = []
    for a in arts:
        name = str((a or {}).get("path") or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
        if any(h in name for h in _SELF_ARTIFACT_HINTS):
            continue
        out.append(a)
    return out

@router.post("/api/agent/import")
async def api_agent_import(payload: dict) -> dict:
    """导入离线采集结果（Agent 在无网/跨网环境用 `--out` 导出的 JSON）。

    场景：云主机访问不到控制台，先在目标机执行
        sh p2s-agent.sh --out report.json
    再把文件带回内网导入。**导入走与在线上报完全相同的归一化与入库逻辑**，
    因此两种方式的结论口径一致。
    """
    rep = payload.get("report") if isinstance(payload.get("report"), dict) else payload
    if not isinstance(rep, dict) or not (rep.get("hostname") or rep.get("installs") is not None):
        raise HTTPException(status_code=400, detail="不是有效的采集报告（缺少 hostname）")
    ip_override = str(payload.get("ip") or "").strip()
    if ip_override:
        rep = {**rep, "ip": ip_override}
    name = str(rep.get("ip") or rep.get("hostname") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="缺少主机标识（hostname / ip）")
    _normalize_host_report(rep)
    _merge_hostname_alias(str(rep.get("hostname") or ""), str(rep.get("ip") or ""))
    res = _ingest_host_report(rep, name, source="agent-offline")
    return {"ok": True, **{k: res.get(k) for k in ("scan_id", "host", "exposure", "reason")}}

def _parse_ini_files(raw: str) -> list[dict]:
    """把 "路径|k=v;k=v;" 的多行串解析成结构化列表。"""
    out: list[dict] = []
    for line in str(raw or "").splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        path, _, rest = line.partition("|")
        vals: dict[str, str] = {}
        for pair in rest.split(";"):
            if "=" not in pair:
                continue
            k, _, v = pair.partition("=")
            if k:
                vals[k.strip()] = v.strip()
        out.append({"path": path.strip(), "values": vals})
    return out


def _parse_pool_overrides(raw: str) -> list[dict]:
    """解析 `grep -H` 输出：`/path/www.conf:php_admin_value[key] = value`。

    返回 [{path, key, value}]，只保留与本漏洞相关的四个键。
    """
    import re as _re

    keys = ("session.upload_progress.enabled", "session.use_only_cookies",
            "session.use_strict_mode", "display_errors")
    out: list[dict] = []
    pat = _re.compile(r"php_(?:admin_)?value\[([^\]]+)\]\s*=\s*(.+)$")
    for line in str(raw or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        path, _, rest = line.partition(":")
        if rest.lstrip().startswith(";"):   # 注释掉的默认配置不算覆盖
            continue
        m = pat.search(rest)
        if not m:
            continue
        key, value = m.group(1).strip(), m.group(2).strip().strip('"')
        if key in keys and value:
            out.append({"path": path.strip(), "key": key, "value": value})
    return out
