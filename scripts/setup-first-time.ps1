# 首次环境初始化脚本（给拿到代码包的人）
# 用法：解压后进入仓库根目录，执行
#   powershell -ExecutionPolicy Bypass -File scripts\setup-first-time.ps1
# 前置条件：已安装 Python 3.12+ 且在 PATH 中；已安装 Chrome 或 Edge

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

# 1. 检查 Python 版本
python -c "import sys; exit(0 if sys.version_info >= (3, 12) else 1)"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[X] 需要 Python 3.12 或更高版本" -ForegroundColor Red
    Write-Host "    下载: https://www.python.org/downloads/"
    Pop-Location; exit 1
}
Write-Host "[ok] Python 版本检查通过" -ForegroundColor Green

# 2. 创建虚拟环境（已存在则跳过）
if (-Not (Test-Path ".venv")) {
    python -m venv .venv
    Write-Host "[ok] 已创建虚拟环境 .venv" -ForegroundColor Green
} else {
    Write-Host "[skip] 虚拟环境已存在" -ForegroundColor Yellow
}

# 3. 激活虚拟环境并安装依赖
& .venv\Scripts\pip.exe install -r requirements.txt
if ($LASTEXITCODE -ne 0) { Write-Host "[X] 依赖安装失败（检查网络）" -ForegroundColor Red; Pop-Location; exit 1 }
Write-Host "[ok] 依赖安装完成" -ForegroundColor Green

# 4. 安装项目本身（提供 websec-lab 命令）
& .venv\Scripts\pip.exe install --no-deps -e .
if ($LASTEXITCODE -ne 0) { Write-Host "[X] 项目安装失败" -ForegroundColor Red; Pop-Location; exit 1 }
Write-Host "[ok] 项目安装完成" -ForegroundColor Green

# 5. 初始化数据库
& .venv\Scripts\python.exe -m websec_lab db upgrade
Write-Host "[ok] 数据库初始化完成" -ForegroundColor Green

# 6. 检查可用浏览器
& .venv\Scripts\python.exe -m websec_lab doctor | Select-String -Pattern "status|browsers" -Context 0,3

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " 环境就绪！启动方式：" -ForegroundColor Cyan
Write-Host "   .venv\Scripts\python.exe -m websec_lab run victim" -ForegroundColor White
Write-Host "   .venv\Scripts\python.exe -m websec_lab run attacker" -ForegroundColor White
Write-Host " 或一键启动: powershell -File scripts\start-all.ps1" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Pop-Location
