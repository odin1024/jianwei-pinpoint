<#
  启动 p2s Web 控制台（后台常驻）
    .\scripts\start-console.ps1                 # 默认 18080
    .\scripts\start-console.ps1 -Port 19000
  停止： .\scripts\stop-console.ps1
#>
param(
  [int]$Port = 18080,
  [string]$Bind = "127.0.0.1",
  [switch]$Foreground
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
  Write-Host "找不到虚拟环境，请先执行: python -m venv .venv ; pip install -e '.[all]'" -ForegroundColor Red
  exit 1
}

# 端口占用检查
$busy = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($busy) {
  Write-Host "端口 $Port 已被占用 (pid=$($busy[0].OwningProcess))。换个端口: -Port 19000" -ForegroundColor Yellow
  exit 1
}

$logDir = Join-Path $root ".run"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$outLog = Join-Path $logDir "console.out.log"
$errLog = Join-Path $logDir "console.err.log"

if ($Foreground) {
  Write-Host "控制台启动中: http://$Bind`:$Port  (Ctrl+C 退出)" -ForegroundColor Cyan
  & $py -m uvicorn p2s.console.app:app --host $Bind --port $Port --log-level info
  exit 0
}

$p = Start-Process -FilePath $py `
  -ArgumentList "-m","uvicorn","p2s.console.app:app","--host",$Bind,"--port","$Port","--log-level","info" `
  -WorkingDirectory $root -WindowStyle Hidden `
  -RedirectStandardOutput $outLog -RedirectStandardError $errLog -PassThru

Start-Sleep -Seconds 3
$listen = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($listen) {
  Set-Content -Path (Join-Path $root ".p2s-port") -Value $Port -Encoding ASCII
  Write-Host "控制台已启动" -ForegroundColor Green
  Write-Host "  地址: http://$Bind`:$Port" -ForegroundColor Green
  Write-Host "  pid : $($p.Id)"
  Write-Host "  日志: $errLog"
  Write-Host "  停止: .\scripts\stop-console.ps1"
} else {
  Write-Host "启动失败，日志:" -ForegroundColor Red
  Get-Content $errLog -Tail 20 -ErrorAction SilentlyContinue
  exit 1
}
