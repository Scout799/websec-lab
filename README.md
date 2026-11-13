# WebSec Clickjacking Lab

点击劫持课程项目：五域 HTTPS 靶场、真实业务状态、分层防御、静态/动态审计与双通道观察。Python 3.12，版本 1.0.0。账户、金额和目标均属于本机虚构实验。

最终数据为 **28 种配置、3 种浏览器、954 例主实验及对照**，另含 **96 例 SameSite 专项**。执行验收与攻击成功采用不同字段，定义见最终报告。

## 文档

- 运行手册：[docs/how-to-run.md](docs/how-to-run.md)
- 架构与威胁模型：[docs/architecture.md](docs/architecture.md)、[docs/threat-model.md](docs/threat-model.md)
- 七类场景与技术差异：[docs/scenario-fingerprints.md](docs/scenario-fingerprints.md)
- 开发说明：[docs/development.md](docs/development.md)

> 课程交付物（报告、PPT、演示视频、实验数据）与开题材料不随本仓库发布，仅保存在本地 `课程材料/` 目录。

## 免安装运行（发给别人用这个）

把项目压缩包解压到任意目录，**不需要 `pip install .`、不需要 `websec-lab` 命令**：

```bash
python start.py setup     # 首次：安装依赖
python start.py demo      # 一条命令启动四个服务
```

`start.py` 会把 `src/` 加入 `sys.path` 再调用同一套 CLI，所以 `python start.py run victim`、`python start.py audit-report ...` 与安装后的 `websec-lab ...` 完全等价。打包给别人时用：

```bash
python tools/make_portable.py    # 生成 dist/websec-lab-portable-<日期>.zip
```

压缩包只含源码与配置（约 0.4 MB），不含 `.websec-local`、`artifacts`、数据库和缓存。拿到包的人按 [README_快速开始.md](README_快速开始.md) 操作即可。

## Windows 安装

已有 Websec 环境直接激活；新机器执行：

```powershell
conda create -n Websec python=3.12 pip openssl -y
conda activate Websec
python -m pip install -r requirements.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m playwright install firefox ffmpeg
websec-lab doctor
```

Chrome、Edge 使用本机安装；Firefox 使用 Playwright 配套版本。可设置 `WEBSEC_CHROME_PATH`、`WEBSEC_EDGE_PATH`、`WEBSEC_FIREFOX_PATH`。轮子包含页面和静态资源；配置目录保留在工程根目录，命令在此目录执行。锁定文件包括运行、开发和报告依赖，浏览器二进制单独安装。

```powershell
python -m websec_lab.https_lab setup --trust
python -m websec_lab.https_lab start --profile https-samesite-none
python -m websec_lab.https_lab status
python -m websec_lab.https_lab browser --browser chrome
```

首次信任会导入名为 WebSec Local Lab CA 的当前用户证书，Windows 可能弹出确认窗口。每台机器生成自己的 CA。TLS 与主机名检查开启，域名只在独立浏览器内映射；直接在日常浏览器输入 `.test` 可能无法解析。

HTTPS 域名为 victim.test、same.victim.test、attacker.test、partner.test、audit.test，端口 8443。后端回环端口 15100–15400。原有 HTTP 服务使用 5100–5400，入口见 `websec-lab run --help`。

## 三分钟演示

1. 在目标页用 `alice / alice-lab` 登录。
2. 在独立实验浏览器访问 `https://attacker.test:8443/`，选择透明覆盖并点击诱导按钮。
3. 返回目标站交易历史，核对模拟交易和余额，解释实际由目标 iframe 接收点击。
4. 切换 csp-none 重试，核对业务未改变。
5. 切换 https-partner-allowlist，比较诱导来源阻断与 `https://partner.test:8443/payment` 明确支付正常执行。

切换配置先停止服务，再启动新配置；重新登录并刷新页面：

```powershell
python -m websec_lab.https_lab stop
python -m websec_lab.https_lab start --profile csp-none
```

手动服务使用 `.websec-local/https.sqlite3`；正式矩阵使用临时独立数据库并逐例重置。策略定义见 [defense.yaml](config/defense.yaml)。

## 审计

```powershell
websec-lab analyze https://victim.test:8443/lab/quick-transfer --ancestor https://attacker.test:8443
websec-lab audit-report https://victim.test:8443/lab/quick-transfer --ancestor https://attacker.test:8443 --probe-origin https://attacker.test:8443 --browser chrome --scenario overlay --click --signals --out artifacts/manual-audit
```

`--scenario` 为 overlay、clip 或 multistep，`--browser` 为 chrome、msedge 或 firefox。默认登录虚构账户并使用本地状态令牌。`--signals` 创建独立实验编号，收集两种信号。报告输出 JSON/Markdown/HTML。

静态与动态使用实际响应、同一会话条件和明确来源对齐。framing=allowed 表示可嵌入，sensitive_action_triggered 依据服务端变化；证据不足为 unknown/inconclusive。窗口扩展入口在攻击服务首页。

## 重现实验

先停止手动 HTTPS 服务；固定端口实验不能同时执行：

```powershell
python -m websec_lab.https_lab stop
python -m websec_lab.experiments.final_matrix --repeats 3 --out artifacts/reproduced-final
python -m websec_lab.experiments.final_matrix --profiles none xfo-deny --browsers chrome --repeats 1 --out artifacts/quick-check
```

SameSite 入口和参数见 [专项手册](docs/https-samesite.md)。交付数据的独立复核与图表再生：

```powershell
python scripts/verify_samesite_results.py
python scripts/finalize_results.py
```

后者明确读取四个保留来源：首轮主矩阵、frame-busting 修复复测、合法支付正常对照、HTTPS 来源修正复测。检查 954 个唯一用例并重建统计，保留首次失败和替换原因。新实验的数据输出到新目录，不自动覆盖发布数据。

主矩阵使用同站不同源 same.victim.test，包含 837 个 iframe 攻击、54 个窗口攻击、36 个合法组件检查和 27 个正常交互。跨站效果另由 96 例 SameSite 专项观察。任一业务变化与完整授权加转账分别保存。

## Docker / Linux

已安装 Docker/Compose 的机器在工程根目录执行：

```bash
docker compose up -d --build --wait
docker compose exec -T lab python scripts/container_smoke.py
docker compose logs --tail 60
docker compose down
```

镜像包含 Linux Chromium、Nginx、OpenSSL 与用户 NSS 信任工具，默认 https-partner-allowlist。Linux HTTPS 审计使用独立临时普通浏览器配置，显式允许实验用第三方 Cookie，并在结束后清理。运行数据与证据使用独立命名卷，仅向宿主机回环发布 8443。更换配置：

```bash
WEBSEC_DEFENSE_PROFILE=https-samesite-none docker compose up -d --force-recreate --wait
```

PowerShell 先设置 `$env:WEBSEC_DEFENSE_PROFILE='https-samesite-none'`。容器烟雾在容器内检查五域 TLS、真实 Chromium、诱导来源阻断和合作方组件。容器默认不导入宿主机 CA；浏览器手动演示优先使用原生方案。

## 检查与材料生成

```powershell
python -m pytest -q
python -m ruff check src tests scripts tools
python -m black --check src tests scripts tools
python scripts/clean_install_smoke.py
python scripts/rehearse_demo.py
python scripts/build_final_report.py
python scripts/record_demo.py
```

录屏和系统演练使用独立临时数据库，开始前停止手动服务。两轮自动化演练不代替小组人工作答和彩排。审计耗时包括启动与等待，不是防御造成的业务页面延迟。

PPT 源 `tools/build_presentation.mjs` 使用作者机器的 Codex Artifact Tool 制作运行时，可用其环境变量适配路径。运行靶场、实验或阅读 PPT 不需要制作工具；修订最终 PPT 时选择新的输出文件名。

## 目录

| 路径 | 内容 |
| --- | --- |
| src/websec_lab | 四个服务（victim / attacker / partner / auditor）与策略、审计、实验模块 |
| config | lab.yaml（服务与端口）、defense.yaml（28 种防御档）、experiments.yaml |
| 	ests | 回归测试（路由、语料、审计单元与真实浏览器端到端） |
| scripts | 冒烟脚本、HTTPS 实验室、一键启动 start_all.py |
| migrations | 数据库迁移；首次运行执行 python start.py db upgrade |
| docs | 运行手册、架构、威胁模型、场景指纹 |
| 	ools | 打包与数据整理脚本 |

运行产物（data/、rtifacts/）和课程交付物不在本仓库内；数据库会在首次运行时自动创建。

源码 MIT 见 [LICENSE](LICENSE)，第三方声明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。CI 工作流已配置；远程 CI 不属于本地执行成功的声明。
