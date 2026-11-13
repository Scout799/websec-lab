# 快速开始



## 0. 你需要什么

- **Python 3.12 或更高**（`python --version` 确认；Windows 安装时勾选 "Add python.exe to PATH"）
- 能联网一次（装依赖用，之后离线可跑）
- 端口 **5100–5400** 空闲

## 1. 解压后，先自检

```bash
cd websec-lab
python start.py doctor
```

它会检查 Python 版本、依赖、配置文件和端口。有红字按提示处理即可。

## 2. 一键装依赖（只需一次）

```bash
python start.py setup
```

网络慢可以手动用镜像：

```bash
python -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

> 动态审计（auditor 真浏览器验证）还需要浏览器。**装了 Chrome 或 Edge 的机器可以跳过**；没有的话执行一次：
> `python -m playwright install chromium`

## 3. 启动

```bash
python start.py demo
```

Windows 会为每个服务开一个窗口；macOS / Linux 在当前终端后台运行。脚本会等健康检查通过后打印入口。

只想跑某一个服务：

```bash
python start.py run victim
python start.py run attacker
```

## 4. 打开四个入口

| 地址 | 用途 |
|---|---|
| http://127.0.0.1:5100/ | 受害者银行站（测试账号 `alice` / `alice-lab`） |
| http://127.0.0.1:5200/demo/classic | 分屏演示（攻击 + 受害者台账同屏） |
| http://127.0.0.1:5300/wallet | 合作方钱包页（合法嵌入对照） |
| http://127.0.0.1:5400/audit | 审计控制台（填 URL 一键出报告） |

## 5. 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| `python` 找不到 | 用 `py -3.12`（Windows）或 `python3`（macOS/Linux）代替 |
| 端口被占用 | 关掉占用进程，或改 `config/lab.yaml` 里的 `port` |
| 演示页"点了没反应" | victim 防御档被留在拦截档：场景页顶部有黄条和「切回无防御」按钮 |
| 审计报"找不到浏览器" | 执行 `python -m playwright install chromium`，或安装 Chrome |
| 依赖装不上 | 换国内镜像（见第 2 步） |

## 6. 不想用命令行装依赖？

项目根目录也保留了 `pyproject.toml`，可以用 pip 安装成命令：

```bash
python -m pip install -e .
websec-lab doctor
```

装完 `websec-lab` 命令即可全局使用；`start.py` 与它等价，二者任选其一。
