<#
  启动 p2s Web 控制台（后台常驻）
    .\scripts\start-console.ps1                 # 默认 127.0.0.1:18080
    .\scripts\start-console.ps1 -Port 19000
    .\scripts\start-console.ps1 -Foreground     # 前台运行，Ctrl+C 退出
  停止： .\scripts\stop-console.ps1

  口令：优先读环境变量 P2S_CONSOLE_PASSWORD；未设置时控制台会随机生成并打印在
        .run\console.err.log 里（本脚本启动后会从日志中取出来提示一次）。
#>
param(
  [int]$Port = 18080,
  [string]$Bind = "127.0.0.1",
  [switch]$Foreground
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

# ---- 解释器：优先项目虚拟环境，其次 PATH 里的 python ----
$candidates = @(
  (Join-Path $root ".venv\Scripts\python.exe"),
  (Join-Path $root ".venv\bin\python")
)
$py = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $py) {
  $cmd = Get-Command python -ErrorAction SilentlyContinue
  if ($cmd) { $py = $cmd.Source }
}
if (-not $py) {
  Write-Host "找不到 Python。请先执行: python -m venv .venv ; .\.venv\Scripts\pip install -e '.[all]'" -ForegroundColor Red
  exit 1
}

function Test-Health([int]$p) {
  try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:$p/api/health" -TimeoutSec 2 -UseBasicParsing
    return $r.StatusCode -eq 200
  } catch { return $false }
}

# ---- 端口占用：先判断是不是「我们自己的实例」 ----
$busy = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($busy) {
  if (Test-Health $Port) {
    Write-Host "控制台已在运行: http://${Bind}:$Port (pid=$($busy[0].OwningProcess))" -ForegroundColor Green
    exit 0
  }
  Write-Host "端口 $Port 已被其它进程占用 (pid=$($busy[0].OwningProcess))。换个端口: -Port 19000" -ForegroundColor Yellow
  exit 1
}

$logDir = Join-Path $root ".run"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$outLog = Join-Path $logDir "console.out.log"
$errLog = Join-Path $logDir "console.err.log"

$uvicornArgs = @("-m","uvicorn","p2s.console.app:app","--host",$Bind,"--port","$Port","--log-level","info")

if ($Foreground) {
  Write-Host "控制台启动中: http://${Bind}:$Port  (Ctrl+C 退出)" -ForegroundColor Cyan
  & $py @uvicornArgs
  exit $LASTEXITCODE
}

$p = Start-Process -FilePath $py -ArgumentList $uvicornArgs `
  -WorkingDirectory $root -WindowStyle Hidden `
  -RedirectStandardOutput $outLog -RedirectStandardError $errLog -PassThru

# ---- 等到健康检查通过为止（最多 20s），而不是固定睡 3 秒 ----
$ok = $false
for ($i = 0; $i -lt 40; $i++) {
  Start-Sleep -Milliseconds 500
  if ($p.HasExited) { break }
  if (Test-Health $Port) { $ok = $true; break }
}

if (-not $ok) {
  Write-Host "启动失败（进程 $(if($p.HasExited){'已退出'}else{'未响应健康检查'})），日志：" -ForegroundColor Red
  Get-Content $errLog -Tail 25 -ErrorAction SilentlyContinue
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
  exit 1
}

Set-Content -Path (Join-Path $root ".p2s-port") -Value $Port -Encoding ASCII
Write-Host "控制台已启动" -ForegroundColor Green
Write-Host "  地址: http://${Bind}:$Port"
Write-Host "  pid : $($p.Id)"
Write-Host "  日志: $errLog"
if (-not $env:P2S_CONSOLE_PASSWORD) {
  $line = Select-String -Path $errLog -Pattern '本次启动口令' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($line) {
    Write-Host "  口令: $($line.Line -replace '.*本次启动口令：','')  （或用环境变量 P2S_CONSOLE_PASSWORD 固定）" -ForegroundColor Yellow
  }
}
Write-Host "  停止: .\scripts\stop-console.ps1"
exit 0
