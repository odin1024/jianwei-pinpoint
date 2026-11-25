# 如何发布到 GitHub

**仓库**：https://github.com/odin1024/jianwei-pinpoint （私有）

## 一、为什么不能直接用 `git push`

本机到 GitHub 的网络实测（2026-11-25）：

| 目标 | 结果 |
|---|---|
| `github.com:443` | ❌ TLS 能握手，但 HTTP 请求失败（**SNI 阻断**）|
| `github.com:22` | ❌ 超时 |
| `ssh.github.com:443` | ❌ TCP 通，SSH 握手被断（重试 3 次全失败）|
| `api.github.com:443` | ✅ HTTP 200 |
| `codeload.github.com` | ✅ 通 |

结论：**不是认证问题**（凭据、SSH key 都没问题），是 `github.com` 这个域名被拦。
所以 `git push` 一定失败，换什么凭据都一样。

## 二、两种可行方式

### 方式 A：配置代理后直推（推荐长期使用）

任何能让 `github.com:443` 正常访问的代理都行。配好后：

```powershell
# 方式 1：给 git 单独配代理
git config --global http.proxy http://127.0.0.1:7890

# 方式 2：只用环境变量（不改配置）
$env:HTTPS_PROXY = "http://127.0.0.1:7890"

git push -u origin main
```

验证代理是否生效：

```powershell
curl.exe -s -o NUL -w "HTTP %{http_code}`n" --max-time 10 https://github.com/
# 期望 200；若是 000 说明代理没生效
```

### 方式 B：走 Git Data API 重放（无代理时使用）

`api.github.com` 可达，因此可以绕开 `github.com`，用 REST API 逐层构建 git 对象：

```
blob（文件内容）→ tree（目录快照）→ commit（提交）→ ref（分支）
```

脚本：`app/scripts/publish_via_api.py`

```powershell
cd app
.\.venv\Scripts\python.exe scripts\publish_via_api.py
```

**特点**：

| 项 | 说明 |
|---|---|
| 保留历史 | 完整重放 41 个提交（不压成 1 个）|
| 断点续传 | 进度写入 `scripts/replay_checkpoint.json`，中断后重跑自动跳过已完成 |
| 幂等 | 引用已存在时强制更新 |
| 自校验 | 完成后比对远端 `HEAD^{tree}` 与本地，一致才算成功 |
| 耗时 | 约 15-20 分钟（855 个唯一 blob，每个一次请求）|
| 凭据 | 从 Windows 凭据管理器读取，不落盘、不打印 |

**限制**：
- 只适合首次推送或整仓同步；日常小改动用方式 A 更省事
- 提交的 sha 会变（因为 author/committer 时间保留但 tree 构建方式不同）
  —— 内容与提交信息一致，但 sha 与本地不同，属于正常现象

## 三、首次发布做了什么（2026-11-25）

1. 用 API 创建私有仓库 `odin1024/jianwei-pinpoint`（`repo` 权限的 OAuth token）
2. 用 `PUT /contents/.p2s-init` 放占位文件 —— **空仓库无法创建 blob**（返回
   `409 Git Repository is empty`），必须先激活
3. 重放 41 个提交：855 个 blob + 41 个 tree + 41 个 commit
4. `PATCH /git/refs/heads/main --force` 指向最后一个提交（覆盖占位提交）
5. 比对 tree sha 确认内容逐字节一致

## 四、验证发布结果

```powershell
# 远端提交数
curl.exe -s -H "Authorization: Bearer $TOKEN" `
  "https://api.github.com/repos/odin1024/jianwei-pinpoint/commits?per_page=1" `
  -D - -o NUL | Select-String "link:"

# 远端 HEAD tree 与本地比对
curl.exe -s -H "Authorization: Bearer $TOKEN" `
  "https://api.github.com/repos/odin1024/jianwei-pinpoint/git/commits/main"
# → 看 "tree"."sha" 是否等于 git rev-parse "HEAD^{tree}"
```

## 五、CI 说明

`.github/workflows/ci.yml` 已随代码推送。首次推送会触发 `test` / `contract` /
`agent-scripts` / `ui-gates` 四个 job。

查看运行结果：仓库页 → **Actions** 标签页。

若 CI 失败，常见原因：
- `ui-gates` 需要 Chrome（ubuntu-latest 预装，一般没问题）
- 网络超时导致 `pip install` 失败（重跑即可）

## 六、安全提醒

1. **不要把 token 写进任何文件**；本文档所有命令都用 `$TOKEN` 变量占位
2. 本次发布用的 OAuth token 是从凭据管理器读的（40 字符，作用域 `gist, repo, workflow`），
   未复制到他处
3. commit 邮箱是 `<你的 GitHub noreply 邮箱>`（含手机号）。**若要改公开仓库**，
   请先改成 `odin1024@users.noreply.github.com`，否则手机号会出现在每个 commit 里
4. 仓库当前是 **私有**。改公开前请复查：
   - `docs/03-情报/` 里的情报是否有第三方版权限制
   - `samples/` 里的日志是否含真实主机信息