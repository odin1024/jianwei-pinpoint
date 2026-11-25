"""增量推送：把本地新提交追加到远端，只上传差异文件。

与 `publish_via_api.py`（全量重放）的区别：
  · 全量重放用于首次发布（远端空库）
  · 本脚本用于日常增量（远端已有一致的历史）

原理：
  远端 HEAD 的 tree 作为 base_tree，只提交差异文件 →
  生成新 commit（parent = 远端 HEAD）→ 更新 refs/heads/main

前置：本地需要有"远端当前 HEAD 对应的本地提交"，
脚本通过 checkpoint 里的映射自动找到它。
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from publish_via_api import CTRL_OWNER, CTRL_REPO, get_token  # noqa: E402

API = f"https://api.github.com/repos/{CTRL_OWNER}/{CTRL_REPO}"
GIT = "git"
TOKEN = get_token()


def api(method: str, path: str, body: dict | None = None) -> dict:
    url = API + path
    data = json.dumps(body).encode() if body is not None else None
    for attempt in range(4):
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
            if e.code in (422, 409):
                return {"__error__": e.code, "message": body_text}
            if e.code in (401, 403):
                raise SystemExit(f"权限失败：{body_text[:200]}") from None
            time.sleep(1.5 * (attempt + 1))
        except Exception:
            time.sleep(1.5 * (attempt + 1))
    raise SystemExit(f"请求失败 {method} {path}")


def git(*args: str, binary: bool = False):
    r = subprocess.run([GIT, *args], capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} 失败："
                         f"{r.stderr.decode('utf-8', 'replace')[:200]}")
    return r.stdout if binary else r.stdout.decode("utf-8", "replace")


def main() -> int:
    ck_path = Path(__file__).with_name("replay_checkpoint.json")
    if not ck_path.exists():
        raise SystemExit("缺少 replay_checkpoint.json —— 先跑一次全量重放")
    ck = json.loads(ck_path.read_text(encoding="utf-8"))
    mapping = ck["commits"]  # local_sha -> {sha, tree}

    # 远端当前 HEAD
    ref = api("GET", "/git/refs/heads/main")
    remote_head = ref["object"]["sha"]
    remote_commit = api("GET", f"/git/commits/{remote_head}")
    remote_tree = remote_commit["tree"]["sha"]
    print(f"远端 HEAD: {remote_head[:7]}  tree={remote_tree[:12]}")

    # 找对应的本地提交（tree 相同）
    local_base = None
    for lsha, info in mapping.items():
        if info["tree"] == remote_tree:
            local_base = lsha
            break
    if local_base is None:
        raise SystemExit("找不到与远端 tree 对应的本地提交 —— 历史已分叉，需要全量重放")

    local_head = git("rev-parse", "HEAD").strip()
    if local_base == local_head:
        print("本地与远端一致，无需推送")
        return 0
    print(f"本地 base={local_base[:7]} → HEAD={local_head[:7]}")

    # 差异文件
    out = git("diff", "--name-status", "--no-renames", local_base, local_head)
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        rows.append((parts[0][:1], parts[-1]))
    if not rows:
        print("没有文件差异")
        return 0
    print(f"差异文件 {len(rows)} 个：")
    for st, path in rows:
        print(f"  {st} {path}")

    # 上传 blob
    entries = []
    for st, path in rows:
        if st == "D":
            entries.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
            continue
        content = git("cat-file", "blob", f"{local_head}:{path}", binary=True)
        res = api("POST", "/git/blobs",
                  {"content": base64.b64encode(content).decode(), "encoding": "base64"})
        if "sha" not in res:
            raise SystemExit(f"blob 上传失败 {path}：{str(res)[:200]}")
        mode_raw = git("ls-tree", local_head, "--", path).strip()
        mode = mode_raw.split()[0] if mode_raw else "100644"
        entries.append({"path": path, "mode": mode, "type": "blob", "sha": res["sha"]})
        print(f"    ↑ {path} ({len(content)} 字节)")

    # 建 tree（以远端 tree 为 base）
    tree = api("POST", "/git/trees", {"base_tree": remote_tree, "tree": entries})
    if "__error__" in tree:
        raise SystemExit(f"建 tree 失败：{tree['message'][:200]}")
    print(f"新 tree: {tree['sha'][:12]}")

    # 建 commit
    fmt = "%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%B"
    parts = git("log", "-1", f"--format={fmt}", local_head).split("\x00")
    commit = api("POST", "/git/commits", {
        "message": parts[6].rstrip("\n") or "(no message)",
        "tree": tree["sha"],
        "parents": [remote_head],
        "author": {"name": parts[0], "email": parts[1], "date": parts[2]},
        "committer": {"name": parts[3], "email": parts[4], "date": parts[5]},
    })
    if "__error__" in commit:
        raise SystemExit(f"建 commit 失败：{commit['message'][:200]}")
    print(f"新 commit: {commit['sha'][:7]}")

    # 更新 ref
    upd = api("PATCH", "/git/refs/heads/main",
              {"sha": commit["sha"], "force": False})
    if "__error__" in upd:
        upd = api("PATCH", "/git/refs/heads/main",
                  {"sha": commit["sha"], "force": True})
    print(f"main → {upd.get('object', {}).get('sha', '?')[:7]}")

    # 记录映射，供下次增量使用
    mapping[local_head] = {"sha": commit["sha"], "tree": tree["sha"]}
    ck["commits"] = mapping
    ck_path.write_text(json.dumps(ck, ensure_ascii=False, indent=1), encoding="utf-8")

    # 校验
    local_tree = git("rev-parse", "HEAD^{tree}").strip()
    remote_tree_now = api("GET", f"/git/commits/{commit['sha']}")["tree"]["sha"]
    ok = local_tree == remote_tree_now
    print(f"\n校验：本地 tree={local_tree[:12]}  远端 tree={remote_tree_now[:12]}")
    print("内容一致性:", "✓ 一致" if ok else "✗ 不一致")
    print(f"仓库: https://github.com/{CTRL_OWNER}/{CTRL_REPO}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())