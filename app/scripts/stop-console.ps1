<#
  停止 p2s Web 控制台
#>
$ErrorActionPreference = "SilentlyContinue"
$root = Split-Path -Parent $PSScriptRoot
$portFile = Join-Path $root ".p2s-port"
$port = if (Test-Path $portFile) { [int](Get-Content $portFile | Select-Object -First 1) } else { 18080 }

$conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
if ($conn) {
  $pid_ = $conn[0].OwningProcess
  Write-Host "停止 pid=$pid_ (端口 $port)"
  Stop-Process -Id $pid_ -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
} else {
  # 兜底：按命令行特征找
  Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*p2s.console.app*" } |
    ForEach-Object { Write-Host "停止 pid=$($_.ProcessId)"; Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
if (Test-Path $portFile) { Remove-Item -LiteralPath $portFile -Force }
Write-Host "已停止" -ForegroundColor Green