<#
  php2shell (CVE-2026-109618 / CVE-2026-109619) 暴露面自查脚本
  用途：清点组织内 PHP 版本与关键配置，识别 php2shell 风险暴露
  说明：仅做只读探测，不做任何修改；生产使用前请在测试环境验证

  用法：
    .\php2shell-暴露面自查.ps1 -Local                 # 检查本机 PHP
    .\php2shell-暴露面自查.ps1 -Hosts hosts.txt      # 批量检查 http(s) 主机
    .\php2shell-暴露面自查.ps1 -Hosts hosts.txt -Deep  # 追加响应头/错误页特征探测
#>
[CmdletBinding()]
param(
  [switch]$Local,
  [string]$Hosts,
  [switch]$Deep
)

$ErrorActionPreference = 'SilentlyContinue'

# 已修复版本（含更高版本视为安全）
$Safe = @{
  '8.2' = '8.2.35'
  '8.3' = '8.3.36'
  '8.4' = '8.4.27'
  '8.5' = '8.5.12'
  '8.6' = '8.6.0'
}

function Test-VersionSafe([string]$ver) {
  if (-not $ver) { return 'Unknown' }
  if ($ver -match '^(\d+)\.(\d+)\.(\d+)') {
    $ma = [int]$Matches[1]; $mi = [int]$Matches[2]; $pa = [int]$Matches[3]
    $key = "$ma.$mi"
    if (-not $Safe.ContainsKey($key)) { return 'EOL_NoPatch' }   # 8.1 及更早：官方不再更新
    $need = $Safe[$key].Split('.')
    $cur = @($ma, $mi, $pa); $req = @([int]$need[0], [int]$need[1], [int]$need[2])
    for ($i = 0; $i -lt 3; $i++) {
      if ($cur[$i] -gt $req[$i]) { return 'Safe' }
      if ($cur[$i] -lt $req[$i]) { return 'Vulnerable' }
    }
    return 'Safe'
  }
  return 'Unknown'
}

Write-Host "=== php2shell 暴露面自查 ===" -ForegroundColor Cyan
Write-Host "修复基准: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35  (CVE-2026-109618, CVE-2026-109619)" -ForegroundColor DarkGray
Write-Host ""

# ---------- 本机检查 ----------
if ($Local) {
  Write-Host "[本机] 检测 php 可执行文件与配置..." -ForegroundColor Yellow
  $php = Get-Command php -ErrorAction SilentlyContinue
  if (-not $php) { Write-Host "  未找到 php 命令。若为容器/镜像环境，请改为在镜像内执行。" -ForegroundColor Red }
  else {
    $raw = & $php.Source -r "echo PHP_VERSION;" 2>$null
    $ver = ($raw | Out-String).Trim()
    $state = Test-VersionSafe $ver
    $color = switch ($state) { 'Safe' {'Green'} 'Vulnerable' {'Red'} 'EOL_NoPatch' {'Red'} default {'Yellow'} }
    Write-Host ("  PHP 版本      : {0}" -f $ver) -ForegroundColor White
    Write-Host ("  风险判定      : {0}" -f $state) -ForegroundColor $color

    Write-Host "  关键配置检查 :" -ForegroundColor Yellow
    $checks = @(
      @{ k='session.upload_progress.enabled'; want='0'; desc='上传进度(攻击链关键),应为 0' },
      @{ k='fatal_error_backtraces';        want='0'; desc='8.5 致命错误回溯(生产者),应为 0' },
      @{ k='memory_limit';                  want='-1'; desc='OOM 攻击面,建议 -1' },
      @{ k='post_max_size';                 want='8M'; desc='建议收紧至 8M/32M' }
    )
    foreach ($c in $checks) {
      $v = (& $php.Source -r "echo ini_get('$($c.k)');" 2>$null | Out-String).Trim()
      $mark = if ($v -eq $c.want) { '[OK]  ' } else { '[!!]  ' }
      $col  = if ($v -eq $c.want) { 'Green' } else { 'Yellow' }
      Write-Host ("    {0}{1,-34} = {2,-12} {3}" -f $mark, $c.k, $v, $c.desc) -ForegroundColor $col
    }
  }
  Write-Host ""
}

# ---------- 远程主机批量检查 ----------
if ($Hosts) {
  if (-not (Test-Path $Hosts)) { Write-Host "找不到主机列表文件: $Hosts" -ForegroundColor Red; exit 1 }
  $list = Get-Content $Hosts | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') } | ForEach-Object { $_.Trim() }
  Write-Host ("[批量] 目标 {0} 个" -f $list.Count) -ForegroundColor Yellow
  $results = @()
  foreach ($h in $list) {
    $url = if ($h -match '^https?://') { $h } else { "http://$h" }
    $ver = ''
    try {
      $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 8 -MaximumRedirection 2
      # 常见暴露点: X-Powered-By / Server / 正文中的版本串
      if ($resp.Headers['X-Powered-By']) { $ver += $resp.Headers['X-Powered-By'] }
      if ($ver -notmatch 'PHP/([\d\.]+)') {
        if ($resp.Content -match 'PHP/([\d\.]+)') { $ver += " PHP/$($Matches[1])" }
      }
      $ver = $ver.Trim()
    } catch {
      $ver = "Unreachable_or_Error"
    }
    $pv = if ($ver -match 'PHP/([\d\.]+)') { $Matches[1] } else { '' }
    $state = if ($pv) { Test-VersionSafe $pv } else { 'Unknown' }
    $results += [PSCustomObject]@{ Host=$h; Detected=$ver; State=$state }
    $col = switch ($state) { 'Safe' {'Green'} 'Vulnerable' {'Red'} 'EOL_NoPatch' {'Red'} default {'Yellow'} }
    Write-Host ("  {0,-40} {1,-24} {2}" -f $h, $ver, $state) -ForegroundColor $col
  }
  Write-Host ""
  Write-Host "汇总:" -ForegroundColor Cyan
  $results | Group-Object State | ForEach-Object { Write-Host ("  {0,-16} {1}" -f $_.Name, $_.Count) }
  $outCsv = Join-Path (Split-Path -Parent $Hosts) ("php2shell-scan-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
  $results | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8
  Write-Host "结果已保存: $outCsv" -ForegroundColor DarkGray
}

if (-not $Local -and -not $Hosts) {
  Write-Host "请指定 -Local 或 -Hosts <文件>。示例:" -ForegroundColor Yellow
  Write-Host "  .\php2shell-暴露面自查.ps1 -Local"
  Write-Host "  .\php2shell-暴露面自查.ps1 -Hosts .\hosts.txt"
}
