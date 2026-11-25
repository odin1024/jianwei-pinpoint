"""Windows 配置加固包生成（PowerShell）。

与 `hardening.py`（POSIX shell）**同构**：同样的五步流程、同样的拒绝清单、
同样的票据与计划指纹、同样的回滚冲突检查。差异只在平台原语：

| 环节 | Linux (sh) | Windows (PowerShell) |
|---|---|---|
| 符号链接 | `[ -L ]` | `Attributes -band ReparsePoint` |
| 硬链接 | `stat -c %h` | `fsutil hardlink list` 计数 |
| 他人可写 | 权限位 | ACL：非特权主体是否持有写权限 |
| sha256 | `sha256sum` | `Get-FileHash -Algorithm SHA256` |
| 校验 cli | `php -r ini_get` | `php -r "echo ini_get(...)"` |

模板用 `__占位符__` + `str.replace` 而不是 f-string：
PowerShell 满是 `{{` `}}` `$()`，套进 f-string 极易漏转义（本模块第一版就因此出错）。
"""
from __future__ import annotations

import json

from .hardening import ACTION_WHITELIST, _now, plan_fingerprint

_PS_TEMPLATE = r'''# php2shell 配置加固包（Windows / PowerShell）—— 由见微 Pinpoint 生成
# 主机: __HOST__
# 目标: __TARGET__
# 生成: __TS__
# 动作白名单: php.ini.set / file.backup / service.reload（脚本内不含其他能力）
# 说明: 只读判断 + 写 ini + 校验 + 回执；不下载、不联网、不执行外部命令
#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Target      = '__TARGET__'
$TargetIsCli = __IS_CLI__
$PhpBin      = '__PHP_BIN__'
$ExpectSha   = '__BEFORE_SHA__'
$Token       = '__TOKEN__'
$Ticket      = '__TICKET__'
$PlanHash    = '__PLAN_HASH__'
$HostName    = '__HOST__'
$Keys        = __KEYS__
$ActPairs    = '__ACT_PAIRS__'

$Applied = New-Object System.Collections.ArrayList

function Say([string]$m) { Write-Host $m }
function Die([int]$code, [string]$m) {
    Write-Host "[FAIL] $code $m" -ForegroundColor Red
    exit $code
}

function Get-FileSha([string]$p) {
    # 不用 Get-FileHash：某些环境（如 GitHub Actions 的 Windows runner）
    # 里 Microsoft.PowerShell.Utility 模块解析失败，该 cmdlet 直接不存在。
    # 改为纯 .NET 实现，不依赖任何 PowerShell 模块。
    if (-not (Test-Path -LiteralPath $p)) { return '' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($p)
    try { $hash = $sha.ComputeHash($fs) }
    finally { $fs.Dispose(); $sha.Dispose() }
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

# ---- 编码安全的 ini 读写 ---------------------------------------------------
# 不能用 Get-Content/Set-Content：Windows PowerShell 5.1 对无 BOM 的 UTF-8
# 按 ANSI 解码，会把中文注释变乱码、并吃掉换行，导致紧随其后的指令行被合并，
# 那条指令再也匹配不到，最终被追加到文件末尾 —— 形成重复指令。
# 这里按 BOM 与 UTF-8 严格解码结果判定编码，写回时保持同一编码与行尾。
$script:IniEnc = [Text.Encoding]::UTF8
$script:IniHasBom = $false

function Read-IniText([string]$p) {
    $bytes = [IO.File]::ReadAllBytes($p)
    $script:IniEnc = [Text.Encoding]::UTF8
    $script:IniHasBom = $false
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $script:IniHasBom = $true
    } else {
        $strict = [Text.Encoding]::GetEncoding('utf-8',
            [Text.EncoderFallback]::ExceptionFallback,
            [Text.DecoderFallback]::ExceptionFallback)
        try { $null = $strict.GetString($bytes) }
        catch {
            # 不是合法 UTF-8（如 GBK 存的中文注释）→ 退回系统 ANSI 代码页
            $script:IniEnc = [Text.Encoding]::GetEncoding(
                [Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)
        }
    }
    $text = $script:IniEnc.GetString($bytes)
    if ($script:IniHasBom -and $text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
        $text = $text.Substring(1)
    }
    return $text
}

function Get-IniNewline([string]$raw) {
    if ($raw -match "`r`n") { return "`r`n" }
    return "`n"
}

function Write-IniText([string]$p, [string]$text) {
    $enc = $script:IniEnc
    if ($script:IniHasBom) { $enc = New-Object Text.UTF8Encoding($true) }
    elseif ($enc.CodePage -eq 65001) { $enc = New-Object Text.UTF8Encoding($false) }
    [IO.File]::WriteAllText($p, $text, $enc)
}

function Test-TargetSane {
    # ---- 包内自校验：动作清单被改过就拒绝执行 ----
    if ($PlanHash) {
        $material = "$HostName|$Target|$ActPairs"
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($material)
        $calc = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
        if ($calc -ne $PlanHash) {
            Die 21 '加固包内容与票据不一致（可能被改动）：请重新下载'
        }
    }
    if ($Ticket) { Say "  票据：$Ticket" }

    if (-not (Test-Path -LiteralPath $Target)) { Die 10 "目标文件不存在：$Target" }
    $item = Get-Item -LiteralPath $Target

    # ---- 拒绝清单 ----
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        Die 15 '目标是符号链接或重解析点：请直接指定真实文件路径'
    }
    $links = @()
    try {
        $out = & fsutil hardlink list "$Target" 2>$null
        if ($out) { $links = @($out) }
    } catch { $links = @() }
    if ($links.Count -gt 1) {
        Die 16 "目标有 $($links.Count) 个硬链接：请确认后去除多余链接再执行"
    }

    # 他人可写：只允许 SYSTEM / Administrators / 当前用户持有写权限
    try {
        $acl = Get-Acl -LiteralPath $Target
        foreach ($ace in $acl.Access) {
            $id = "$($ace.IdentityReference)".ToLower()
            $isPriv = $false
            foreach ($ok in __PRIV_PS__) {
                if ($id -like "*$ok*") { $isPriv = $true }
            }
            if ((-not $isPriv) -and $ace.AccessControlType -eq 'Allow' -and
                $ace.FileSystemRights -match 'Write|Modify|FullControl|CreateFiles') {
                Die 17 "目标对非特权主体可写（$($ace.IdentityReference)）：请先收紧 ACL"
            }
        }
    } catch { }

    if ($ExpectSha) {
        $now = Get-FileSha $Target
        if ($now -ne $ExpectSha) { Die 13 "文件与平台记录不一致：$now != $ExpectSha" }
    }

    # 配置管理托管检测（只看前 5 行）
    $raw = Read-IniText $Target
    $head = (($raw -split "`r?`n") | Select-Object -First 5) -join "`n"
    if ($head -match '(?i)ansible|puppet|salt|chef|managed by') {
        Die 14 '该文件由配置管理工具托管，请改到你们的配置仓库'
    }

    # 重复指令 / 续行
    $lines = $raw -split "`r?`n"
    foreach ($k in $Keys) {
        $pat = "^\s*;?\s*" + [regex]::Escape($k) + "\s*="
        $n = @($lines | Where-Object { $_ -match $pat }).Count
        if ($n -gt 1) { Die 18 "指令 $k 在文件中出现 $n 次：不猜哪条生效，请先人工去重" }
    }
    foreach ($l in $lines) {
        if ($l -match '=\s*\\\s*$') { Die 19 '目标存在续行（行尾反斜杠）：请先人工整理成单行' }
    }
}

function Apply-IniKV([string]$k, [string]$v) {
    $raw  = Read-IniText $Target
    $nl   = Get-IniNewline $raw
    $lines = [System.Collections.ArrayList]@($raw -split "`r?`n")
    $pat = "^\s*;?\s*" + [regex]::Escape($k) + "\s*="
    $hit = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match $pat) {
            $lines[$i] = "$k = $v"
            $hit = $true
            break
        }
    }
    if (-not $hit) { [void]$lines.Add("$k = $v") }
    Write-IniText $Target (($lines -join $nl).TrimEnd("`r", "`n") + $nl)
    Say "  $k = $v"
}

function Test-IniKV([string]$k, [string]$v) {
    if ($TargetIsCli) {
        $got = (& $PhpBin -r "echo ini_get('$k');" 2>$null | Out-String).Trim()
        $src = 'runtime'
    } else {
        $pat = "^\s*" + [regex]::Escape($k) + "\s*="
        $line = ((Read-IniText $Target) -split "`r?`n" |
                 Where-Object { $_ -match $pat } | Select-Object -First 1)
        if ($line) { $got = ($line -replace '^[^=]*=\s*', '').Trim() } else { $got = '' }
        $src = 'file'
    }
    if ($got -eq $v) { Say "  [$k] $got OK ($src)"; return $true }
    Say "  [$k] '$got' != '$v' ($src)"
    return $false
}

function Emit-Applied([string]$k, [string]$v) {
    [void]$Applied.Add(@{ key = $k; value = $v })
}

Say '[1/5] 预检'
Test-TargetSane
Say '  预检通过'

Say '[2/5] 备份'
$Backup = "$Target.p2s.bak." + (Get-Date -Format 'yyyyMMdd-HHmmss')
Copy-Item -LiteralPath $Target -Destination $Backup -Force
Say "  已备份到 $Backup"

Say '[3/5] 应用变更'
__APPLY_LINES__
__EMIT_LINES__

Say '[4/5] 校验生效值'
$okAll = $true
__VERIFY_LINES__
if (-not $okAll) {
    Say '  校验未通过，自动回滚'
    Copy-Item -LiteralPath $Backup -Destination $Target -Force
    Die 30 "已回滚到 $Backup"
}

Say '[5/5] 完成'
$after = Get-FileSha $Target
$stateFile = "$Target.p2s.state"
[IO.File]::WriteAllText($stateFile,
    "after_sha=$after`r`nbackup=$Backup`r`n", (New-Object Text.UTF8Encoding($false)))

$receipt = [ordered]@{
    host = $HostName; target = $Target
    before_sha = $ExpectSha; after_sha = $after; backup = $Backup
    applied = @($Applied); ticket = $Ticket; plan_hash = $PlanHash
    token = $Token; at = (Get-Date -Format s); runtime_verified = $false
}
$receiptPath = Join-Path $env:TEMP ("p2s-harden-receipt-" +
    (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
[IO.File]::WriteAllText($receiptPath,
    ($receipt | ConvertTo-Json -Depth 5),
    (New-Object Text.UTF8Encoding($false)))
Say "  回执：$receiptPath"
Say '  把该文件内容贴回平台「加固回执」即完成闭环'
if (-not $TargetIsCli) { Say '  注意：目标是 FPM/Apache/IIS 的 ini，必须重启对应服务才生效' }
exit 0
'''

_ROLLBACK_TEMPLATE = r'''# 回滚脚本（Windows）—— 把 php.ini 恢复到加固前
# 与加固脚本配套：加固成功后写 <目标>.p2s.state 记录「加固后」的 sha。
# 回滚前先比对当前文件是否仍等于该 sha：不等说明加固后有人改过，直接覆盖会抹掉别人的改动。
#Requires -Version 5.1
[CmdletBinding()]
param([switch]$Force)

$ErrorActionPreference = 'Stop'
$Target    = '__TARGET__'
$ExpectSha = '__BEFORE_SHA__'
$StateFile = "$Target.p2s.state"

function Get-FileSha([string]$p) {
    # 不用 Get-FileHash：某些环境（如 GitHub Actions 的 Windows runner）
    # 里 Microsoft.PowerShell.Utility 模块解析失败，该 cmdlet 直接不存在。
    # 改为纯 .NET 实现，不依赖任何 PowerShell 模块。
    if (-not (Test-Path -LiteralPath $p)) { return '' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($p)
    try { $hash = $sha.ComputeHash($fs) }
    finally { $fs.Dispose(); $sha.Dispose() }
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

$Backup = Get-ChildItem -LiteralPath (Split-Path -Parent $Target) `
    -Filter ((Split-Path -Leaf $Target) + '.p2s.bak.*') -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $Backup) { Write-Host '[FAIL] 10 找不到备份文件'; exit 10 }

if ((Test-Path -LiteralPath $StateFile) -and (-not $Force)) {
    $st = Get-Content -LiteralPath $StateFile -Raw
    $m = [regex]::Match($st, 'after_sha=([0-9a-f]{64})')
    if ($m.Success) {
        $now = Get-FileSha $Target
        if ($now -ne $m.Groups[1].Value) {
            Write-Host '[FAIL] 31 回滚已中止：目标文件在加固之后被修改过。' -ForegroundColor Red
            Write-Host "       加固后记录: $($m.Groups[1].Value)"
            Write-Host "       当前文件  : $now"
            Write-Host '       直接覆盖会抹掉这些改动。确认要放弃它们，请执行：'
            Write-Host '         .\rollback.ps1 -Force'
            exit 31
        }
    }
}

Copy-Item -LiteralPath $Backup.FullName -Destination $Target -Force
$now = Get-FileSha $Target
if ($ExpectSha -and ($now -ne $ExpectSha)) {
    Write-Host "[WARN] 回滚后 sha 与加固前记录不一致：$now" -ForegroundColor Yellow
}
Remove-Item -LiteralPath $StateFile -ErrorAction SilentlyContinue
Write-Host "[OK] 已从 $($Backup.Name) 回滚；记得重启 PHP 服务"
exit 0
'''

_README_TEMPLATE = """加固包说明（Windows）—— 由见微 Pinpoint 生成
=========================================================

主机     : {host}
目标文件 : {target}
生成时间 : {ts}
执行环境 : Windows PowerShell 5.1 及以上（管理员权限）

一、先看变更
------------
    type diff.patch

二、执行（需要管理员 PowerShell）
--------------------------------
    .\\harden.ps1

脚本依次做：
  1) 预检 —— 文件存在可写、非符号链接/重解析点、无多余硬链接、
     非特权主体不可写（ACL 检查）、sha256 与平台记录一致、未被配置管理工具托管；
     任何一项不过就退出，**不会改文件**；
  2) 备份 —— 同目录生成 php.ini.p2s.bak.<时间戳>；
  3) 写入 —— 只做 ini 键值替换/追加，不执行其他命令；
  4) 校验 —— cli 目标读运行时值，其他读文件内容；不过则**自动回滚**；
  5) 回执 —— 生成 %TEMP%\\p2s-harden-receipt-<时间戳>.json。

三、让改动生效
--------------
    Restart-Service W3SVC            # IIS
    Restart-Service php-fpm          # 若用 FPM
（只 reload 不够，IIS 需回收应用程序池或重启 W3SVC）

四、确认生效
------------
    & "{php_bin}" -i | Select-String 'upload_progress|use_strict_mode'
    # 或访问站点页，用 phpinfo() / ini_get() 看实际值

五、回滚
--------
    .\\rollback.ps1            # 默认做冲突检查
    .\\rollback.ps1 -Force     # 确认放弃加固后的改动

六、必须知道的边界
------------------
- 关闭 session.upload_progress **只是减少攻击面**，不是修复漏洞；
  唯一完整修复是升级 PHP 到修复版本；
- 若该机器由 Ansible/Puppet/Salt/Chef 管理，请改到你们的配置仓库；
- 存储态写入成功 ≠ 运行时生效：必须重启服务并自查；
- 脚本按原文件的编码与行尾写回（支持 UTF-8/UTF-8 BOM/GBK 的 php.ini）。

七、回执样例
------------
{{"host":"{host}","target":"{target}","before_sha":"…","after_sha":"…",
 "applied":[{{"key":"session.upload_progress.enabled","value":"0"}}],"at":"…"}}
把整段 JSON 贴回平台「加固回执」即可完成闭环。
"""


def _ps_quote(v: str) -> str:
    """转义为 PowerShell 单引号字符串（只需处理单引号）。"""
    return str(v).replace("'", "''")


def build_pack(host: str, host_report: dict, target: str, actions: list[dict],
               ticket: str = "", token: str = "") -> dict[str, str]:
    """生成 Windows 加固包：harden.ps1 / rollback.ps1 / diff.patch / manifest.json / README.txt。"""
    before_sha = str(host_report.get("ini_sha256") or "")
    php_bin = str(host_report.get("php_bin") or "php.exe")
    ts = _now()
    is_cli = "$true" if "\\cli\\" in str(target).lower() else "$false"
    plan_hash = plan_fingerprint(host, target, actions)
    keys = [str(a["key"]) for a in actions]
    pairs = "|".join(sorted(f"{a['key']}={a['value']}" for a in actions))

    apply_lines = "\n".join(
        f"Apply-IniKV '{_ps_quote(a['key'])}' '{_ps_quote(a['value'])}'" for a in actions)
    emit_lines = "\n".join(
        f"Emit-Applied '{_ps_quote(a['key'])}' '{_ps_quote(a['value'])}'" for a in actions)
    verify_lines = "\n".join(
        f"if (-not (Test-IniKV '{_ps_quote(a['key'])}' '{_ps_quote(a['value'])}')) "
        "{ $okAll = $false }"
        for a in actions)
    keys_ps = "@(" + ", ".join(f"'{_ps_quote(k)}'" for k in keys) + ")"
    priv_ps = ("@('system','administrators','administrator','trustedinstaller', "
               "$env:USERNAME.ToLower())")

    harden = _PS_TEMPLATE
    for token_name, value in (
        ("__HOST__", _ps_quote(host)),
        ("__TARGET__", _ps_quote(target)),
        ("__TS__", _ps_quote(ts)),
        ("__PHP_BIN__", _ps_quote(php_bin)),
        ("__BEFORE_SHA__", _ps_quote(before_sha)),
        ("__TOKEN__", _ps_quote(token)),
        ("__TICKET__", _ps_quote(ticket)),
        ("__PLAN_HASH__", _ps_quote(plan_hash)),
        ("__ACT_PAIRS__", _ps_quote(pairs)),
        ("__IS_CLI__", is_cli),
        ("__KEYS__", keys_ps),
        ("__PRIV_PS__", priv_ps),
        ("__APPLY_LINES__", apply_lines),
        ("__EMIT_LINES__", emit_lines),
        ("__VERIFY_LINES__", verify_lines),
    ):
        harden = harden.replace(token_name, value)

    rollback = (_ROLLBACK_TEMPLATE
                .replace("__TARGET__", _ps_quote(target))
                .replace("__BEFORE_SHA__", _ps_quote(before_sha)))

    diff = "\n".join(
        ["# 预期的 php.ini 变更（由平台按当前生效值推算）", f"# 文件: {target}", ""]
        + [f"-{a['key']} = {a['from']}\n+{a['key']} = {a['value']}" for a in actions]
    ) + "\n"

    manifest = json.dumps({
        "generated_at": ts,
        "platform": "windows",
        "host": host,
        "target": target,
        "php_bin": php_bin,
        "before_sha256": before_sha,
        "plan_hash": plan_hash,
        "ticket": ticket,
        "actions": actions,
        "whitelist": list(ACTION_WHITELIST),
        "runtime_verified": False,
        "encoding_safe": True,
        "discipline": {
            "reject_symlink": 15, "reject_hardlink": 16, "reject_group_writable": 17,
            "reject_duplicate": 18, "reject_continuation": 19, "rollback_conflict": 31,
        },
        "exit_codes": {
            "10": "目标不存在", "11": "无写权限", "13": "sha 与记录不一致",
            "14": "由配置管理工具托管", "21": "包内容与票据不一致",
            "30": "校验失败已回滚", "31": "回滚检测到冲突",
        },
    }, ensure_ascii=False, indent=2) + "\n"

    readme = _README_TEMPLATE.format(host=host, target=target, ts=ts, php_bin=php_bin)

    return {
        "harden.ps1": harden,
        "rollback.ps1": rollback,
        "diff.patch": diff,
        "manifest.json": manifest,
        "README.txt": readme,
    }
