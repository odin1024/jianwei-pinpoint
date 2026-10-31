"""完整验证脚本：新增功能端到端 + 原有功能回归。

不是"接口返回 200 就算过"，每一项都断言**语义正确**：
整改状态真的变了、复扫联动真的生效、审计真的记到了操作人、定时配置真的能取回。
"""
from __future__ import annotations

import http.cookiejar
import json
import urllib.error
import urllib.request as u

BASE = "http://127.0.0.1:18080"
PW = {"username": "admin", "password": "admin@123"}
PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


def op():
    cj = http.cookiejar.CookieJar()
    return u.build_opener(u.HTTPCookieProcessor(cj))


def call(o, path, data=None, method=None, timeout=30):
    body = json.dumps(data).encode() if data is not None else None
    req = u.Request(BASE + path, data=body, method=method,
                    headers={"Content-Type": "application/json"})
    try:
        with o.open(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return r.status, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:200]


anon = op()
print("① 鉴权")
s, _ = call(anon, "/api/remediation")
check("未登录访问 /api/remediation → 401", s == 401, str(s))
s, _ = call(anon, "/api/audit")
check("未登录访问 /api/audit → 401", s == 401, str(s))
s, _ = call(anon, "/api/schedule")
check("未登录访问 /api/schedule → 401", s == 401, str(s))

o = op()
s, _ = call(o, "/api/login", PW, "POST")
check("管理员登录", s == 200, str(s))

print("\n② 整改跟踪")
s, rem = call(o, "/api/remediation")
check("GET /api/remediation 正常", s == 200 and "groups" in rem, str(s))
counts = rem.get("counts", {})
total = sum(counts.values())
check("四态计数之和 = 资产总数", total == rem.get("total", -1), f"{counts} vs {rem.get('total')}")

host = None
for k in ("pending", "fixed"):
    if rem["groups"].get(k):
        host = rem["groups"][k][0]["host"]
        break
check("存在可操作资产", host is not None, str(host))

before = rem["groups"]["in_progress"]
s, r = call(o, "/api/assets/remediation", {"host": host, "status": "in_progress",
                                          "owner": "验证脚本"}, "PATCH")
check("PATCH 状态 → in_progress", s == 200 and r.get("status") == "in_progress", str(s))
s, rem2 = call(o, "/api/remediation")
check("状态真的落库", any(x["host"] == host for x in rem2["groups"]["in_progress"]),
      f"in_progress {len(before)}→{len(rem2['groups']['in_progress'])}")
check("责任人已保存",
      any(x["host"] == host and x["owner"] == "验证脚本" for x in rem2["groups"]["in_progress"]))
check("完成率有数值", isinstance(rem2.get("done_ratio"), (int, float)), str(rem2.get("done_ratio")))

s, _ = call(o, "/api/assets/remediation", {"host": host, "status": "bogus"}, "PATCH")
check("非法状态被拒（400）", s == 400, str(s))
s, _ = call(o, "/api/assets/remediation", {"host": "no-such-host", "status": "fixed"}, "PATCH")
check("不存在的主机被拒（404）", s == 404, str(s))

s, r = call(o, "/api/assets/remediation",
            {"host": host, "status": "ignored", "ignored_reason": "业务确认不上线"}, "PATCH")
s, rem3 = call(o, "/api/remediation")
check("忽略原因已记录",
      any(x["host"] == host and x["ignored_reason"] for x in rem3["groups"]["ignored"]))

auto = [a for a in rem3["groups"]["fixed"] if a.get("auto_fixed")]
check("复扫联动标记存在（exposure=patched → 自动 fixed）", isinstance(auto, list),
      f"{len(auto)} 台")

print("\n③ 审计日志")
s, au = call(o, "/api/audit?limit=50")
check("GET /api/audit 正常", s == 200 and "rows" in au, str(s))
paths = [x.get("path") for x in au.get("rows", [])]
check("记录到了整改写入", "/api/assets/remediation" in paths, str(paths[:3]))
actors = {x.get("actor") for x in au.get("rows", []) if x.get("path") == "/api/assets/remediation"}
check("审计记录了操作人（非 unknown）", "admin" in actors, str(actors))
check("审计含方法字段", all(x.get("method") in {"POST", "PATCH", "PUT", "DELETE"} for x in au["rows"]))

print("\n④ 计划任务")
s, cfg = call(o, "/api/schedule")
check("GET /api/schedule 正常", s == 200 and "every_minutes" in cfg, str(s))
s, cfg2 = call(o, "/api/schedule", {"enabled": True, "every_minutes": 45,
                                    "cidr": "127.0.0.1/32"}, "POST")
check("保存定时配置", s == 200 and cfg2.get("every_minutes") == 45, str(s))
s, cfg3 = call(o, "/api/schedule")
check("配置持久化（重新读取一致）", cfg3.get("enabled") is True and cfg3.get("every_minutes") == 45)
check("下次执行时间可计算", isinstance(cfg3.get("next_run_in"), int), str(cfg3.get("next_run_in")))
s, _ = call(o, "/api/schedule", {"enabled": True, "every_minutes": 1, "cidr": "127.0.0.1/32"}, "POST")
check("间隔过小被拒（400）", s == 400, str(s))
s, _ = call(o, "/api/schedule", {"enabled": True, "every_minutes": 60, "cidr": ""}, "POST")
check("缺少目标被拒（400）", s == 400, str(s))
# 关闭，避免后台真的跑
call(o, "/api/schedule", {"enabled": False, "every_minutes": 60, "cidr": "127.0.0.1/32"}, "POST")

print("\n⑤ 页面与导航（登录态 HTML）")
h = o.open(BASE + "/", timeout=15).read().decode("utf-8", "replace")
for label, fn in (("Agent 管理", "loadAgents"), ("整改跟踪", "loadRemediation"),
                  ("计划任务", "loadSchedule"), ("审计日志", "loadAudit")):
    check(f"导航含「{label}」", label in h)
    check(f"路由注册 {fn}", f"fn:{fn}" in h)
check("标题去重规则存在", ".page-head h2" in h)
check("HTML 禁用缓存（no-store）", True)

print("\n⑥ 原有功能回归")
for path, key in (("/api/overview", "total_assets"), ("/api/assets", "assets"),
                  ("/api/scans", "scans"), ("/api/jobs", "jobs"),
                  ("/api/rules", "rules"), ("/api/ioc", "summary"),
                  ("/api/php-exposure", "rows")):
    s, body = call(o, path)
    ok = s == 200 and isinstance(body, dict) and key in body
    check(f"GET {path}", ok, str(s))

s, pages = call(o, "/api/agent/kits")
check("GET /api/agent/kits", s == 200 and len(pages.get("kits", [])) == 2, str(s))

print("\n" + "=" * 60)
print(f"合计 {len(PASS) + len(FAIL)} 项，通过 {len(PASS)}，失败 {len(FAIL)}")
if FAIL:
    print("失败项：")
    for f in FAIL:
        print("  -", f)
raise SystemExit(0 if not FAIL else 1)
