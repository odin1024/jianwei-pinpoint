"""通过 GitHub Git Data API 重放本地提交历史（绕过 github.com 的 SNI 阻断）。

背景
----
本地 `github.com:443` 被 SNI 阻断，但 `api.github.com` 可达。
因此不能用 `git push`，改用 REST API 逐层构建：

    blob（文件内容）→ tree（目录快照）→ commit（提交）→ ref（分支）

这样能**保留全部 41 个提交**（而不是压成一个），
代价是每个唯一 blob 一次请求（855 次），耗时约 10-15 分钟。

健壮性
------
- 断点续传：已上传的 blob 与已建的提交记录在 checkpoint.json，中断后重跑会跳过
- 幂等：同名引用已存在时直接复用
- 校验：全部完成后比对远端 tree sha 与本地 `git rev-parse HEAD^{tree}`，
  一致才说明内容**逐字节相同**

安全
----
token 只从 Windows 凭据管理器读取，不写入任何文件、不打印。
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

OWNER = "odin1024"
REPO = "jianwei-pinpoint"
API = f"https://api.github.com/repos/{OWNER}/{REPO}"
CKPT = Path(__file__).with_name("replay_checkpoint.json")
GIT = "git"


# ------------------------------------------------------------------ 凭据
def get_token() -> str:
    """从 Windows 凭据管理器读取 GitHub token。"""
    import ctypes
    from ctypes import wintypes

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
            ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p), ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    advapi = ctypes.windll.advapi32
    ptr = ctypes.c_void_p()
    ok = advapi.CredReadW(ctypes.c_wchar_p("git:https://github.com"),
                          1, 0, ctypes.byref(ptr))
    if not ok:
        raise SystemExit("无法读取凭据管理器中的 GitHub token")
    try:
        c = ctypes.cast(ptr, ctypes.POINTER(CREDENTIAL)).contents
        raw = ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize)
        return raw.decode("utf-16-le")
    finally:
        advapi.CredFree(ptr)


TOKEN = get_token()


# ------------------------------------------------------------------ HTTP
def api(method: str, path: str, body: dict | None = None,
        retries: int = 4) -> dict:
    url = path if path.startswith("http") else API + path
    data = json.dumps(body).encode() if body is not None else None
    last = ""
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "p2s-release",
            "Content-Type": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            body_text = e.read().decode("utf-8", "replace")
            # 422/409 多半是"已存在"，交给调用方判断
            if e.code in (422, 409):
                return {"__error__": e.code, "message": body_text}
            last = f"HTTP {e.code}: {body_text[:200]}"
            if e.code in (401, 403) and "rate limit" not in body_text.lower():
                raise SystemExit(f"认证/权限失败：{last}") from None
            time.sleep(1.5 * (attempt + 1))
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
            time.sleep(1.5 * (attempt + 1))
    raise SystemExit(f"请求失败 {method} {url}：{last}")


# ------------------------------------------------------------------ git
def git(*args: str, binary: bool = False):
    r = subprocess.run([GIT, *args], capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} 失败: "
            f"{r.stderr.decode('utf-8', 'replace')[:300]}") from None
    return r.stdout if binary else r.stdout.decode("utf-8", "replace")


def commits() -> list[str]:
    return git("rev-list", "--reverse", "HEAD").split()


def commit_meta(sha: str) -> dict:
    fmt = "%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%B"
    parts = git("log", "-1", f"--format={fmt}", sha).split("\x00")
    return {
        "author": {"name": parts[0], "email": parts[1], "date": parts[2]},
        "committer": {"name": parts[3], "email": parts[4], "date": parts[5]},
        "message": parts[6].rstrip("\n") or "(no message)",
    }


def changed(sha: str) -> list[tuple[str, str]]:
    """返回 [(status, path)]，status ∈ A/M/D。"""
    out = git("diff-tree", "-r", "--root", "--no-commit-id",
              "--name-status", "--no-renames", sha)
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            rows.append((parts[0][:1], parts[-1]))
    return rows


def blob_sha_at(sha: str, path: str) -> str:
    return git("rev-parse", f"{sha}:{path}").strip()


def blob_content(sha: str, path: str) -> bytes:
    return git("cat-file", "blob", f"{sha}:{path}", binary=True)


def file_mode(sha: str, path: str) -> str:
    out = git("ls-tree", sha, "--", path).strip()
    return out.split()[0] if out else "100644"


def ensure_nonempty() -> None:
    """空仓库无法创建 blob（409），先放一个占位文件激活它。"""
    refs = api("GET", "/git/refs/heads")
    if isinstance(refs, list) and refs:
        print(f"仓库已有 {len(refs)} 个分支引用，无需激活")
        return
    print("仓库为空 —— 放置占位文件以激活 Git 数据接口")
    res = api("PUT", "/contents/.p2s-init", {
        "message": "chore: initialize repository",
        "content": __import__("base64").b64encode(
            b"placeholder for git data api; removed by history replay\n").decode(),
    })
    if "__error__" in res:
        raise SystemExit(f"激活失败：{res['message'][:300]}")
    print("  已创建占位提交:", res.get("commit", {}).get("sha", "?")[:7])


# ------------------------------------------------------------------ 主流程
def main() -> int:
    ck = {"blobs": {}, "commits": {}, "last_tree": None}
    if CKPT.exists():
        ck = json.loads(CKPT.read_text(encoding="utf-8"))
        print(f"发现断点：已上传 {len(ck['blobs'])} 个 blob，"
              f"已建 {len(ck['commits'])} 个提交 —— 继续")
    else:
        print("全新开始")

    ensure_nonempty()

    shas = commits()
    print(f"本地共 {len(shas)} 个提交，目标 {OWNER}/{REPO}")
    total_blobs = 0
    t0 = time.time()

    for idx, sha in enumerate(shas, 1):
        if sha in ck["commits"]:
            ck["last_tree"] = ck["commits"][sha]["tree"]
            continue

        rows = changed(sha)
        entries = []
        for status, path in rows:
            if status == "D":
                entries.append({"path": path, "mode": "100644",
                                "type": "blob", "sha": None})
                continue
            bsha = blob_sha_at(sha, path)
            if bsha not in ck["blobs"]:
                content = blob_content(sha, path)
                res = api("POST", "/git/blobs",
                          {"content": base64.b64encode(content).decode(), "encoding": "base64"})
                if "sha" not in res:
                    raise SystemExit(
                        f"blob 上传失败 {path}（{len(content)} 字节）："
                        f"{str(res)[:300]}")
                ck["blobs"][bsha] = res["sha"]
                total_blobs += 1
            entries.append({"path": path, "mode": file_mode(sha, path),
                            "type": "blob", "sha": ck["blobs"][bsha]})

        tree_body = {"tree": entries}
        if ck["last_tree"]:
            tree_body["base_tree"] = ck["last_tree"]
        tree = api("POST", "/git/trees", tree_body)
        if "__error__" in tree:
            raise SystemExit(f"建 tree 失败（{sha[:7]}）：{tree['message'][:200]}")

        meta = commit_meta(sha)
        parent = list(ck["commits"].values())[-1]["sha"] if ck["commits"] else None
        cbody = {"message": meta["message"], "tree": tree["sha"],
                 "author": meta["author"], "committer": meta["committer"]}
        if parent:
            cbody["parents"] = [parent]
        commit = api("POST", "/git/commits", cbody)
        if "__error__" in commit:
            raise SystemExit(f"建 commit 失败（{sha[:7]}）：{commit['message'][:200]}")

        ck["commits"][sha] = {"sha": commit["sha"], "tree": tree["sha"]}
        ck["last_tree"] = tree["sha"]
        CKPT.write_text(json.dumps(ck, ensure_ascii=False, indent=1), encoding="utf-8")

        subj = meta["message"].splitlines()[0][:60]
        print(f"  [{idx:2d}/{len(shas)}] {sha[:7]} → {commit['sha'][:7]}  "
              f"{len(entries):2d} 文件  {subj}", flush=True)

    # ---- 建立分支引用 ----
    head = ck["commits"][shas[-1]]["sha"]
    print("\n=== 建立 refs/heads/main ===")
    ref = api("POST", "/git/refs", {"ref": "refs/heads/main", "sha": head})
    if "__error__" in ref:
        upd = api("PATCH", "/git/refs/heads/main", {"sha": head, "force": True})
        if "__error__" in upd:
            raise SystemExit(f"更新 main 失败：{upd['message'][:300]}")
        print("  引用已存在，已强制更新:", upd["object"]["sha"][:7])
    else:
        print("  已创建:", ref["object"]["sha"][:7])

    # ---- 设默认分支 ----
    api("PATCH", "", {"default_branch": "main"})

    # ---- 校验 ----
    local_tree = git("rev-parse", "HEAD^{tree}").strip()
    remote = api("GET", f"/git/commits/{head}")
    print("\n=== 校验 ===")
    print(f"  本地 HEAD tree : {local_tree}")
    print(f"  远端 HEAD tree : {remote.get('tree', {}).get('sha')}")
    ok = local_tree == remote.get("tree", {}).get("sha")
    print("  内容一致性:", "✓ 逐字节相同" if ok else "✗ 不一致")
    print(f"\n耗时 {time.time()-t0:.0f}s，上传 blob {total_blobs} 个")
    print(f"仓库地址: https://github.com/{OWNER}/{REPO}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())