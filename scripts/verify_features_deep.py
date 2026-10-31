"""深度验证：证明"真的会执行"，而不只是接口能返回。

覆盖三件容易假实现的事：
  ① 调度线程到点是否**真的**发起任务（把 last_run 改成过去，等一个 tick）；
  ② 删除报告是否**真的**删文件、且审计里留下 DELETE 记录；
  ③ 复扫联动是否**真的**把已修复资产归到 fixed。
"""
from __future__ import annotations

import http.cookiejar
import json
import pathlib
import time
import urllib.error
import urllib.request as u

BASE = "http://127.0.0.1:18080"
ROOT = pathlib.Path(__file__).resolve().parent.parent
SCANS = ROOT / "p2s-data" / "scans"
SCHED = ROOT / "p2s-data" / "schedule.json"
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


cj = http.cookiejar.CookieJar()
op = u.build_opener(u.HTTPCookieProcessor(cj))


def call(path, data=None, method=None, timeout=60):
    body = json.dumps(data).encode() if data is not None else None
    req = u.Request(BASE + path, data=body, method=method,
                    headers={"Content-Type": "application/json"})
    try:
        with op.open(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return r.status, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:200]


call("/api/login", {"username": "admin", "password": "admin@123"}, "POST")

print("① 调度线程是否真的会触发")
# 造一个"早就该跑"的配置，等一个 tick（线程 30s 检查一次）
cfg = {
    "enabled": True, "every_minutes": 5, "cidr": "127.0.0.1/32", "hosts": [],
    "quick": True, "save": False, "last_run": "2020-01-01T00:00:00", "last_job": "",
}
SCHED.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
before = {j["id"] for j in (call("/api/jobs?limit=200")[1] or {}).get("jobs", [])}
fired = None
for _ in range(12):                      # 最多等 60 秒（两个 tick）
    time.sleep(5)
    jobs = (call("/api/jobs?limit=200")[1] or {}).get("jobs", [])
    new = [j for j in jobs if j["id"] not in before]
    if new:
        fired = new[0]
        break
check("定时任务被自动创建", fired is not None, (fired or {}).get("title", ""))
if fired:
    check("定时任务归入 auto 分组", (fired.get("params") or {}).get("group") == "auto",
          str((fired.get("params") or {}).get("group")))
    check("定时任务记录了 last_job",
          json.loads(SCHED.read_text(encoding="utf-8")).get("last_job") == fired["id"])
# 关掉，避免持续触发
call("/api/schedule", {"enabled": False, "every_minutes": 60, "cidr": "127.0.0.1/32"}, "POST")

print("\n② 删除报告是否真的删文件 + 留审计")
code, job = call("/api/jobs", {"kind": "discover", "hosts": ["127.0.0.1"], "quick": True, "save": True}, "POST")
sid = None
if "id" in job:
    for _ in range(40):
        time.sleep(1)
        st = call("/api/jobs/" + job["id"])[1]
        if st.get("state") in ("done", "failed", "cancelled"):
            sid = (st.get("result") or {}).get("scan_id") or st.get("id")
            break
print("   新扫描:", sid)
check("扫描产生了报告文件", any(SCANS.glob(f"{sid}.*")) if sid else False)
if sid:
    # 先调接口删除，再断言文件消失（顺序反了会误判 404）
    code, _ = call(f"/api/scans/{sid}", None, "DELETE")
    check("DELETE /api/scans 返回 200", code == 200, str(code))
    check("报告文件确实被删除", not any(SCANS.glob(f"{sid}.*")))
    _, au = call("/api/audit?limit=50&q=scans")
    methods = [x.get("method") for x in au.get("rows", []) if x.get("path", "").startswith("/api/scans/")]
    check("审计记录了 DELETE", "DELETE" in methods, str(methods[:3]))

print("\n③ 复扫联动：已修复资产归入 fixed")
_, rem = call("/api/remediation")
fixed_hosts = {a["host"] for a in rem["groups"].get("fixed", [])}
_, assets = call("/api/assets")
patched = {a["host"] for a in assets.get("assets", []) if a.get("exposure") == "patched"}
check("exposure=patched 的资产出现在 fixed 组", patched.issubset(fixed_hosts) or not patched,
      f"patched={sorted(patched)} fixed={sorted(fixed_hosts)}")

print("\n" + "=" * 60)
print(f"合计 {len(PASS) + len(FAIL)} 项，通过 {len(PASS)}，失败 {len(FAIL)}")
for f in FAIL:
    print("  失败:", f)
raise SystemExit(0 if not FAIL else 1)
