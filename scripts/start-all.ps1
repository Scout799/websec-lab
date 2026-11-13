# 一键启动全部本地服务（T0110）
# 用法：在仓库根目录执行  powershell -ExecutionPolicy Bypass -File scripts\start-all.ps1
# 可选参数：-DefenseProfile xfo-deny  为 victim 指定防御 profile

param(
    [string]$DefenseProfile = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

$services = @(
    @{ Name = "victim";   Port = 5100 },
    @{ Name = "attacker"; Port = 5200 },
    @{ Name = "partner";  Port = 5300 },
    @{ Name = "auditor";  Port = 5400 }
)

function Test-Port([int]$Port) {
    try {
        $client = New-Object Net.Sockets.TcpClient
        $client.Connect("127.0.0.1", $Port)
        $client.Close()
        return $true
    } catch { return $false }
}

# 环境自检
python -c "import websec_lab" *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] 当前 Python 环境未安装 websec-lab，请先: conda activate Websec" -ForegroundColor Red
    exit 1
}

# victim 数据库初始化
python -m websec_lab db upgrade | Out-Null
Write-Host "[ok] 数据库已就绪" -ForegroundColor Green

foreach ($service in $services) {
    if (Test-Port $service.Port) {
        Write-Host "[skip] $($service.Name) 端口 $($service.Port) 已被占用" -ForegroundColor Yellow
        continue
    }
    $envArgs = @()
    if ($service.Name -eq "victim" -and $DefenseProfile -ne "") {
        $envVars = "`$env:WEBSEC_DEFENSE_PROFILE='$DefenseProfile';"
    } else {
        $envVars = ""
    }
    $command = "$envVars python -m websec_lab run $($service.Name)"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root'; $command"
    Write-Host "[start] $($service.Name) -> http://127.0.0.1:$($service.Port)" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "等待服务就绪..."
foreach ($service in $services) {
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        if (Test-Port $service.Port) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
    }
    $status = if ($ready) { "ready" } else { "timeout" }
    Write-Host ("  {0,-9} {1}" -f $service.Name, $status)
}

Write-Host ""
Write-Host "全部服务:" -ForegroundColor Green
Write-Host "  victim   http://127.0.0.1:5100   (alice / alice-lab)"
Write-Host "  attacker http://127.0.0.1:5200   分屏演示: /demo/classic"
Write-Host "  partner  http://127.0.0.1:5300   合法嵌入: /wallet"
Write-Host "  auditor  http://127.0.0.1:5400   规则库: /api/rules"
