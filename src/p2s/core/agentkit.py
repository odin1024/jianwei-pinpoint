"""Agent 采集脚本生成器：现场下载即可运行，无需安装 Python。

设计取舍：
  · 客户业务主机上通常没有 Python，也未必允许装软件。
    所以生成的是**系统自带解释器**就能跑的脚本：Linux 用 POSIX shell，
    Windows 用 Windows PowerShell 5.1（Win7/2008R2 起自带，不依赖 PowerShell 7）。
  · 脚本只做**只读采集**，把原始证据（PHP 安装点、版本、SAPI、生效配置、
    包 changelog 命中）POST 回控制台；**判定由服务端统一计算**，
    避免"脚本版本不同 → 结论不同"。
   · 平台地址与上报令牌在下载时注入，客户拿到就能跑。
"""
from __future__ import annotations

import base64
import json
import re

#: 服务端支持的采集脚本类型
KINDS = {
    "linux": {
        "filename": "p2s-agent.sh",
        "content_type": "text/x-shellscript; charset=utf-8",
        "label": "Linux / macOS / BSD（POSIX sh，含 CentOS / Ubuntu / Debian / Alpine / 麒麟 / macOS / FreeBSD）",
    },
    "windows": {
        "filename": "p2s-agent.ps1",
        "content_type": "text/plain; charset=utf-8",
        "label": "Windows（PowerShell 5.1+，Win7/2008R2 及以上）",
    },
}

#: 脚本里要采集的关键配置项（服务端会补期望值与判定）
INI_KEYS = (
    "memory_limit",
    "post_max_size",
    "max_file_uploads",
    "max_input_nesting_level",
    "session.upload_progress.enabled",
    "fatal_error_backtraces",
    "display_errors",
    "open_basedir",
    "enable_post_data_reading",
)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def render_linux(base_url: str, token: str) -> str:
    """生成 POSIX shell 采集脚本。"""
    ini_keys = " ".join(INI_KEYS)
    return f"""#!/bin/sh
# ==========================================================================
# p2s 主机侧采集脚本（Linux）—— 只读，不修改任何系统配置
# 生成来源：{base_url}
#
# 用法：
#   sh p2s-agent.sh                 # 采集并上报
#   sh p2s-agent.sh --dry-run       # 只打印 JSON，不上报
#   sh p2s-agent.sh --out a.json    # 同时把 JSON 存到本地
#
# 兼容：CentOS/RHEL 6+、Ubuntu 14.04+、Debian 8+、Alpine 3+、麒麟/统信
#       依赖：sh、sed/awk；上报用 curl 或 wget（任一存在即可）
# ==========================================================================
BASE_URL="${{P2S_URL:-{base_url}}}"
TOKEN="${{P2S_TOKEN:-{token}}}"
DRY=0
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --out) shift; OUT="$1" ;;
    *) ;;
  esac
  shift
done

HOST=$(hostname 2>/dev/null || echo unknown)
OS_ID=$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | head -1 | tr -d '"')
OS_VER=$(sed -n 's/^VERSION_ID=//p' /etc/os-release 2>/dev/null | head -1 | tr -d '"')
OS_NAME=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | head -1 | tr -d '"')
KERNEL=$(uname -sr 2>/dev/null)
[ -z "$OS_ID" ] && OS_ID=$(uname -s | tr 'A-Z' 'a-z')

# ---- JSON 转义（不依赖 jq）----
jesc() {{
  printf '%s' "$1" | sed -e 's/\\\\/\\\\\\\\/g' -e 's/"/\\\\"/g' -e 's/\\t/ /g' \\
    | tr -d '\\000-\\010\\013\\014\\016-\\037' | awk 'NR==1{{printf "%s",$0}} NR>1{{printf "\\\\n%s",$0}}'
}}

# ---- 收集 PHP 二进制 ----
PHP_BINS=""
for c in php php8.4 php8.3 php8.2 php8.1 php8.0 php7.4 php7.3 php7.2 php7.0 php5.6; do
  p=$(command -v "$c" 2>/dev/null) && PHP_BINS="$PHP_BINS $p"
done
for p in /usr/bin/php /usr/local/bin/php /usr/local/php/bin/php /opt/php/bin/php \\
         /www/server/php/*/bin/php /usr/local/lsws/lsphp*/bin/php; do
  [ -x "$p" ] && PHP_BINS="$PHP_BINS $p"
done
PHP_BINS=$(printf '%s\\n' $PHP_BINS | sort -u)

INSTALLS=""
for p in $PHP_BINS; do
  [ -n "$INSTALLS" ] && INSTALLS="$INSTALLS,"
  VER=$("$p" -r 'echo PHP_VERSION;' 2>/dev/null)
  SAPI=$("$p" -r 'echo PHP_SAPI;' 2>/dev/null)
  INI=$("$p" --ini 2>/dev/null | sed -n 's/^Loaded Configuration File: *//p' | head -1)
  BIN=$(ls -l "$p" 2>/dev/null | sed -n 's/.*-> //p')
  # 补丁标志：修复版才会引入该 ini 指令（借鉴 php2shell-guard 的做法）
  PF=$("$p" -r 'var_dump(ini_get("memory_hard_limit_percent"));' 2>/dev/null | tr -d '[:cntrl:]')
  [ -z "$BIN" ] && BIN="$p"
  INSTALLS="$INSTALLS{{\\"path\\":\\"$(jesc "$p")\\",\\"real_path\\":\\"$(jesc "$BIN")\\",\\"version\\":\\"$(jesc "$VER")\\",\\"sapi\\":\\"$(jesc "$SAPI")\\",\\"ini\\":\\"$(jesc "$INI")\\"}}"
done

# ---- 生效配置（取第一个 PHP 的 ini_get）----
SETTINGS=""
FIRST=$(printf '%s\\n' $PHP_BINS | head -1)
if [ -n "$FIRST" ]; then
  for k in {ini_keys}; do
    v=$("$FIRST" -r "echo ini_get('$k');" 2>/dev/null)
    [ -n "$SETTINGS" ] && SETTINGS="$SETTINGS,"
    SETTINGS="$SETTINGS{{\\"name\\":\\"$k\\",\\"actual\\":\\"$(jesc "$v")\\"}}"
  done
fi

INI_CANDS=""
for _f in /etc/php/*/fpm/php.ini /etc/php/*/apache2/php.ini /etc/php/*/cli/php.ini /etc/php.ini \
          /www/server/php/*/etc/php.ini /usr/local/php/etc/php.ini; do
  if [ -f "$_f" ]; then
    INI_CANDS="$INI_CANDS $_f"
  fi
done

INI_FILES=""
INI_KEYS_SCAN="session.upload_progress.enabled session.use_only_cookies session.use_strict_mode display_errors"
for _f in $INI_CANDS; do
  _vals=""
  for _k in $INI_KEYS_SCAN; do
    _v=$(grep -E "^[[:space:]]*;?[[:space:]]*$_k[[:space:]]*=" "$_f" 2>/dev/null | head -1 | sed 's/^[^=]*=[[:space:]]*//' | tr -d "[:cntrl:] ")
    _vals="$_vals$_k=$_v;"
  done
  INI_FILES="$INI_FILES$_f|$_vals|
"
done
# ---- 加固包需要的元信息：php 路径 / ini 路径 / ini 的 sha256 ----
PHP_BIN_FIRST="$FIRST"
INI_FIRST=$("$FIRST" --ini 2>/dev/null | sed -n 's/^Loaded Configuration File: *//p' | head -1)
INI_SHA=$(sha256sum "$INI_FIRST" 2>/dev/null | cut -d' ' -f1)

# ---- 包 changelog 是否含 CVE（回移补丁的唯一解）----
CHANGELOG_HIT=""
if command -v rpm >/dev/null 2>&1; then
  for pkg in php php-cli php-common php-fpm; do
    rpm -q --changelog "$pkg" 2>/dev/null | grep -qE 'CVE-2026-10961[89]' && CHANGELOG_HIT="$pkg"
  done
fi
if [ -z "$CHANGELOG_HIT" ] && command -v dpkg >/dev/null 2>&1; then
  for d in /usr/share/doc/php*-common /usr/share/doc/php*; do
    [ -f "$d/changelog.Debian.gz" ] || continue
    zcat "$d/changelog.Debian.gz" 2>/dev/null | grep -qE 'CVE-2026-10961[89]' && CHANGELOG_HIT="$d"
  done
fi
if [ -z "$CHANGELOG_HIT" ] && command -v brew >/dev/null 2>&1; then
  brew list --versions php 2>/dev/null | head -1 > /dev/null && PHP_BREW="$(brew list --versions php 2>/dev/null | head -1)"
fi
if [ -z "$CHANGELOG_HIT" ] && command -v pkg >/dev/null 2>&1; then
  pkg info 'php*' 2>/dev/null | grep -qE 'CVE-2026-10961[89]' && CHANGELOG_HIT="pkg"
fi
if [ -z "$CHANGELOG_HIT" ] && command -v apk >/dev/null 2>&1; then
  apk info -a 'php*' 2>/dev/null | grep -qE 'CVE-2026-10961[89]' && CHANGELOG_HIT="apk"
fi

# ---- worker 进程与启动时间（判断配置是否真生效）----
ps_lines() {{
  ps -eo pid,lstart,args 2>/dev/null && return 0
  ps -axo pid,lstart,command 2>/dev/null && return 0
  ps aux 2>/dev/null && return 0
  return 1
}}
PROCS=$(ps_lines | grep -E 'php-fpm|php-cgi|apache2|httpd' \
        | grep -v grep | head -5 | sed 's/"/ /g')
PROC_JSON=""
[ -n "$PROCS" ] && PROC_JSON=$(printf '"%s"' "$(jesc "$PROCS")")
# stat 的 -c(GNU) / -f(BSD·macOS) 不同，两个都试
stat_mtime() {{
  [ -e "$1" ] || return 1
  stat -c %y "$1" 2>/dev/null && return 0
  stat -f '%Sm' "$1" 2>/dev/null && return 0
  return 1
}}
INI_MTIME=""
[ -n "$FIRST" ] && INI_MTIME=$(stat_mtime "/etc/php.ini" 2>/dev/null || stat_mtime "$(dirname "$(dirname "$FIRST")")/etc/php.ini" 2>/dev/null)

# ---- 可疑落地文件（近 7 天，php/phtml/sh）----
# 注意：下面用 printf 的单引号模板拼 JSON 片段，引号**不能**写成 \" ——
# 单引号里反斜杠会被原样输出，生成的 JSON 里出现 \" 就是非法 JSON（真机上踩过）。
ARTIFACTS=""
SELF_EXCLUDE="p2s-agent|p2s_agent|run_agent.sh"
for d in /tmp /var/tmp /var/www/html /var/www /usr/local/nginx/html /home; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 3 -type f \\( -name '*.php' -o -name '*.phtml' -o -name '*.sh' \\) \\
       -mtime -7 2>/dev/null | head -20 | while read -r f; do
    printf '%s\\n' "$f"
  done
done > /tmp/.p2s_art.$$ 2>/dev/null
ARTIFACTS=$(head -20 /tmp/.p2s_art.$$ 2>/dev/null | grep -Ev "$SELF_EXCLUDE" | while read -r f; do
  case "$f" in */p2s-agent.sh) continue ;; esac
  printf '{{"kind":"recent_script","path":"%s","detail":"近 7 天新增","severity":"medium"}}' "$(jesc "$f")"
  printf ','
done | sed 's/,$//')
rm -f /tmp/.p2s_art.$$ 2>/dev/null

JSON=$(printf '{{"hostname":"%s","ip":"%s","platform":"%s %s","platform_release":"%s",' \\
  "$(jesc "$HOST")" "$(jesc "${{P2S_IP:-}}")" "$(jesc "$OS_ID")" "$(jesc "$OS_VER")" "$(jesc "$KERNEL")")
JSON="$JSON"'"checked_at":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","php_changelog_hit":"'"$(jesc "$CHANGELOG_HIT")"'",'
JSON="$JSON"'"ini_mtime":"'"$(jesc "$INI_MTIME")"'","processes":['"$PROC_JSON"'],'
JSON="$JSON"'"php_bin":"'"$(jesc "$PHP_BIN_FIRST")'","ini_path":"'"$(jesc "$INI_FIRST")'",'
JSON="$JSON"'"ini_sha256":"'"$INI_SHA"'",'
JSON="$JSON"'"ini_candidates_raw":"'"$(jesc "$INI_CANDS")"'",'
JSON="$JSON"'"ini_files_raw":"'"$(jesc "$INI_FILES")"'",'
JSON="$JSON"'"installs":['"$INSTALLS"'],"settings":['"$SETTINGS"'],"artifacts":['"$ARTIFACTS"']}}'

if [ -n "$OUT" ]; then printf '%s' "$JSON" > "$OUT"; echo "已写入 $OUT"; fi
if [ "$DRY" = "1" ]; then printf '%s\\n' "$JSON"; exit 0; fi

URL="$BASE_URL/api/agent/report"
if command -v curl >/dev/null 2>&1; then
  curl -sS -m 30 -X POST "$URL" -H 'Content-Type: application/json' \\
       -H "X-P2S-Token: $TOKEN" --data-binary "$JSON" && echo "" && echo "已上报到 $URL"
elif command -v wget >/dev/null 2>&1; then
  printf '%s' "$JSON" > /tmp/.p2s_body.$$
  wget -q -O - --header='Content-Type: application/json' \\
       --header="X-P2S-Token: $TOKEN" --post-file=/tmp/.p2s_body.$$ "$URL" \\
       && echo "" && echo "已上报到 $URL"
  rm -f /tmp/.p2s_body.$$
else
  echo "未找到 curl 或 wget，无法上报；可用 --out 保存 JSON 后手工上传" >&2
  exit 2
fi
"""


def render_windows(base_url: str, token: str) -> str:
    """生成 Windows PowerShell 采集脚本（PS 5.1 兼容）。"""
    ini_list = ",".join(f'"{k}"' for k in INI_KEYS)
    return f"""# ==========================================================================
# p2s 主机侧采集脚本（Windows）—— 只读，不修改任何系统配置
# 生成来源：{base_url}
#
# 用法（Windows PowerShell 5.1 及以上，Win7/2008R2 起自带）：
#   powershell -ExecutionPolicy Bypass -File .\\p2s-agent.ps1
#   powershell -ExecutionPolicy Bypass -File .\\p2s-agent.ps1 -DryRun
#
# 若执行策略受限，可用：
#   powershell -ExecutionPolicy Bypass -Command "Get-Content .\\p2s-agent.ps1 -Raw | Invoke-Expression"
# ==========================================================================
param(
  [string]$BaseUrl = $env:P2S_URL,
  [string]$Token   = $env:P2S_TOKEN,
  [switch]$DryRun
)

if (-not $BaseUrl) {{ $BaseUrl = "{base_url}" }}
if (-not $Token)   {{ $Token   = "{token}" }}

$ErrorActionPreference = "Continue"
# 中文 Windows 控制台默认 GBK，先切到 UTF-8，否则中文全是乱码
try {{
  [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
  $OutputEncoding = [System.Text.Encoding]::UTF8
}} catch {{ }}
try {{
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11
}} catch {{ }}

$iniKeys = @({ini_list})
$result = [ordered]@{{
  hostname        = $env:COMPUTERNAME
  ip              = ""
  platform        = "Windows"
  platform_release = ""
  checked_at      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  installs        = @()
  settings        = @()
  artifacts       = @()
  processes       = @()
  errors          = @()
}}

try {{
  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
  $result.platform = "Windows $($os.Caption)"
  $result.platform_release = "$($os.Version) build $($os.BuildNumber)"
}} catch {{
  $result.platform = "Windows"
  $result.platform_release = [Environment]::OSVersion.VersionString
}}

# ---- 枚举 PHP：PATH / 常见目录 / 注册表 ----
$cands = New-Object System.Collections.Generic.List[string]
$cmd = Get-Command php.exe -ErrorAction SilentlyContinue
if ($cmd) {{ $cands.Add($cmd.Source) }}
foreach ($root in @("C:\\php", "C:\\xampp\\php", "C:\\wamp64\\bin\\php", "C:\\wamp\\bin\\php",
                    "C:\\laragon\\bin\\php", "C:\\phpstudy_pro\\Extensions", "C:\\Program Files\\PHP")) {{
  if (Test-Path $root) {{
    Get-ChildItem -Path $root -Filter php.exe -Recurse -Depth 3 -ErrorAction SilentlyContinue |
      ForEach-Object {{ $cands.Add($_.FullName) }}
  }}
}}
foreach ($hive in @("HKLM:\\SOFTWARE\\PHP", "HKCU:\\SOFTWARE\\PHP")) {{
  if (Test-Path $hive) {{
    Get-ChildItem $hive -ErrorAction SilentlyContinue | ForEach-Object {{
      $ip = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).InstallPath
      if ($ip) {{
        $exe = Join-Path $ip "php.exe"
        if (Test-Path $exe) {{ $cands.Add($exe) }}
      }}
    }}
  }}
}}

$seen = @{{}}
foreach ($exe in ($cands | Select-Object -Unique)) {{
  if (-not (Test-Path $exe)) {{ continue }}
  if ($seen.ContainsKey($exe.ToLower())) {{ continue }}
  $seen[$exe.ToLower()] = 1
  try {{
    $ver  = (& $exe -r "echo PHP_VERSION;" 2>$null | Out-String).Trim()
    $sapi = (& $exe -r "echo PHP_SAPI;"    2>$null | Out-String).Trim()
    $ini  = (& $exe --ini 2>$null | Select-String "Loaded Configuration File" | Select-Object -First 1)
    $iniPath = ""
    if ($ini) {{ $iniPath = ($ini.Line -split ":", 2)[1].Trim() }}
    $patchFlag = (& $exe -r "var_dump(ini_get('memory_hard_limit_percent'));" 2>$null | Out-String).Trim()
    $result.installs += [ordered]@{{
      path = $exe; real_path = $exe; version = $ver; sapi = $sapi; ini = $iniPath
      patch_flag = $patchFlag
    }}
  }} catch {{
    $result.errors += "读取 $exe 失败: $($_.Exception.Message)"
  }}
}}

# ---- 生效配置（取第一个安装点）----
if ($result.installs.Count -gt 0) {{
  $first = $result.installs[0].path
  foreach ($k in $iniKeys) {{
    try {{
      $v = (& $first -r "echo ini_get('$k');" 2>$null | Out-String).Trim()
      $result.settings += [ordered]@{{ name = $k; actual = $v }}
    }} catch {{ }}
  }}
}}

# ---- 近 7 天可疑落地文件 ----
$since = (Get-Date).AddDays(-7)
foreach ($d in @($env:TEMP, "C:\\Windows\\Temp", "C:\\inetpub\\wwwroot", "C:\\xampp\\htdocs")) {{
  if (-not (Test-Path $d)) {{ continue }}
  Get-ChildItem -Path $d -Include *.php,*.phtml,*.ps1,*.bat -Recurse -Depth 2 -ErrorAction SilentlyContinue |
    Where-Object {{ $_.LastWriteTime -gt $since -and $_.Length -lt 5MB }} |
    Select-Object -First 20 | ForEach-Object {{
      $result.artifacts += [ordered]@{{
        kind = "recent_script"; path = $_.FullName
        detail = "近 7 天新增，$($_.Length) 字节"; severity = "medium"
      }}
    }}
}}

# ---- PHP 相关进程 ----
try {{
  $result.processes = @(Get-CimInstance Win32_Process -Filter "Name LIKE '%php%'" -ErrorAction SilentlyContinue |
    Select-Object -First 10 | ForEach-Object {{ "pid=$($_.ProcessId) $($_.Name) $($_.CommandLine)" -replace "`r|`n", " " }})
}} catch {{ }}

$json = $result | ConvertTo-Json -Depth 6 -Compress
if ($DryRun) {{
  Write-Output $json
  return
}}

$url = "$BaseUrl/api/agent/report"
try {{
  # 必须显式按 UTF-8 字节发送：PS 5.1 默认按 ISO-8859-1 编码 Body，中文证据会变问号
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
  $resp = Invoke-RestMethod -Uri $url -Method Post -Body $bytes `
    -ContentType "application/json; charset=utf-8" `
    -Headers @{{ "X-P2S-Token" = $Token }} -TimeoutSec 30
  Write-Output ("已上报到 " + $url + " -> 结论 " + $resp.exposure + "：" + $resp.reason)
}} catch {{
  Write-Output "上报失败：$($_.Exception.Message)"
  Write-Output "可加 -DryRun 查看将要上报的 JSON"
  exit 2
}}
"""


def render(kind: str, base_url: str, token: str) -> str:
    if kind == "linux":
        return render_linux(base_url, token)
    if kind == "windows":
        # Windows PowerShell 5.1 在**没有 BOM** 时按系统 ANSI（中文 Windows 是 GBK）
        # 解析 .ps1，中文会乱码甚至吞掉换行导致语法错误。必须带 UTF-8 BOM。
        return "\ufeff" + render_windows(base_url, token)
    raise KeyError(kind)


def render_bundle(base_url: str, token: str) -> str:
    """把两份脚本打包成一个自解压的说明文件（纯文本，便于邮件/IM 传递）。"""
    return (
        "p2s 主机侧采集脚本包\n"
        f"平台地址：{base_url}\n"
        "用法：按目标系统选择对应脚本，下载后直接运行，结果自动上报。\n\n"
        + "=" * 78 + "\nLinux 脚本（保存为 p2s-agent.sh）\n" + "=" * 78 + "\n"
        + render_linux(base_url, token)
        + "\n" + "=" * 78 + "\nWindows 脚本（保存为 p2s-agent.ps1）\n" + "=" * 78 + "\n"
        + render_windows(base_url, token)
    )


def _sanity() -> None:
    """生成器自检：占位符必须被替换干净（测试用）。"""
    for kind in KINDS:
        text = render(kind, "http://127.0.0.1:18080", "tok")
        assert "{" * 2 + "base_url" not in text
        assert re.search(r"\bbase_url\b", text) is None
        json.dumps({"ok": bool(text)})


if __name__ == "__main__":  # pragma: no cover
    _sanity()
    print(render_linux("http://127.0.0.1:18080", "TOKEN")[:400])
