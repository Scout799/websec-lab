# 快速上手（给拿到代码包的人）

从零到跑起来，约 10 分钟。

## 1. 前置条件

| 条件 | 要求 | 检查方法 |
|---|---|---|
| 操作系统 | Windows 10/11 | — |
| Python | 3.12 或更高 | `python --version` |
| 浏览器 | Chrome 或 Edge 任一 | 装过即可，无需配置 |

没有 Python？
到 python.org 下载安装，
安装时勾选 "Add Python to PATH"。

## 2. 自动安装（推荐）

解压代码包，进入仓库根目录，执行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup-first-time.ps1
```

脚本自动完成：

- 检查 Python 版本
- 创建独立虚拟环境 `.venv`
- 安装全部依赖（requirements.txt）
- 安装项目本身（提供 `websec-lab` 命令）
- 初始化数据库
- 检查本机可用浏览器

## 3. 手动安装（等价于脚本内容）

```powershell
cd <解压目录>
python -m venv .venv
.venv\Scripts\pip.exe install -r requirements.txt
.venv\Scripts\pip.exe install --no-deps -e .
.venv\Scripts\python.exe -m websec_lab db upgrade
```

## 4. 启动服务

每个服务一个终端窗口：

```powershell
.venv\Scripts\python.exe -m websec_lab run victim
.venv\Scripts\python.exe -m websec_lab run attacker
.venv\Scripts\python.exe -m websec_lab run partner
.venv\Scripts\python.exe -m websec_lab run auditor
```

嫌麻烦就用一键启动（会自动调用虚拟环境缺失时提示）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-all.ps1
```

## 5. 打开页面

| 地址 | 说明 |
|---|---|
| `http://127.0.0.1:5100` | 受害网站（恒信银行） |
| `http://127.0.0.1:5200` | 攻击网站 |
| `http://127.0.0.1:5300` | 合法合作方 |
| `http://127.0.0.1:5400` | 审计服务 |

登录账号：`alice` / `alice-lab`

必看演示页：

```
http://127.0.0.1:5200/demo/classic
```

左屏点"立即领取"，右屏余额实时变化。

## 6. 常见报错对照

### `websec-lab : 无法将...识别为 cmdlet`

原因：没有安装项目本身，或没用虚拟环境。

解决：

```powershell
.venv\Scripts\pip.exe install --no-deps -e .
```

或者不用命令，直接用模块方式启动：

```powershell
.venv\Scripts\python.exe -m websec_lab run victim
```

### `ModuleNotFoundError: No module named 'websec_lab'`

同上，先安装项目或用 `-m` 方式启动。

### pip 安装依赖很慢或失败

换国内镜像：

```powershell
.venv\Scripts\pip.exe install -r requirements.txt `
  -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### `websec-lab doctor` 显示没有浏览器

项目靠本机安装的 Chrome/Edge 驱动，
不自动下载 Playwright 浏览器。

两种解决：

- 装 Chrome 或 Edge（绝大多数 Windows 已有 Edge）
- 或手动下载 Playwright 浏览器：

```powershell
.venv\Scripts\python.exe -m playwright install chromium
```

### 启动报端口被占用 (5100-5400)

```powershell
netstat -ano | findstr :5100
taskkill /PID <进程号> /F
```

### Python 版本低于 3.12

代码用了 3.12 语法，低版本无法运行。
请安装 3.12+，或用 conda：

```powershell
conda create -n Websec python=3.12 -y
conda activate Websec
```

## 7. 跑测试（确认环境 OK）

```powershell
.venv\Scripts\python.exe -m pytest -q
```

全部通过即环境就绪。

## 8. 更多文档

- 运行手册：`docs/how-to-run.md`
- 攻击实现原理：`docs/attack-implementation.md`
- 项目总览：`docs/project-overview.md`
- 完整 README：仓库根目录 `README.md`
