# 项目运行手册

> 环境：Windows + PowerShell 7 + Conda 环境 `Websec`
> 仓库：`E:\Codex-Projet\Web安全`

## 0. 准备（每次开始前）

```powershell
conda activate Websec
cd E:\Codex-Projet\Web安全
```

## 1. 模式一：HTTP 回环模式（日常演示）

### 1.1 一键启动

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-all.ps1
```

脚本会自动完成：

- 初始化数据库（`websec-lab db upgrade`）
- 在四个新窗口启动四个服务
- 等待健康检查通过后打印访问地址

可选参数：切换 victim 防御

```powershell
.\scripts\start-all.ps1 -DefenseProfile xfo-deny
```

### 1.2 手动启动（四个终端）

```powershell
websec-lab db upgrade      # 首次运行才需要
websec-lab run victim      # 终端1 → http://127.0.0.1:5100
websec-lab run attacker    # 终端2 → http://127.0.0.1:5200
websec-lab run partner     # 终端3 → http://127.0.0.1:5300
websec-lab run auditor     # 终端4 → http://127.0.0.1:5400
```

### 1.3 服务入口

| 地址 | 用途 |
|---|---|
| `http://127.0.0.1:5100` | victim「恒信银行」 |
| `http://127.0.0.1:5200` | attacker 攻击场景库 |
| `http://127.0.0.1:5300` | partner 合法嵌入方 |
| `http://127.0.0.1:5400` | auditor 审计服务 |

测试账号：

| 用户名 | 密码 | 初始余额 |
|---|---|---|
| `alice` | `alice-lab` | ¥1,000.00 |
| `bob` | `bob-lab` | ¥250.00 |
| `merchant` | `merchant-lab` | ¥500.00 |

### 1.4 重点页面

| 地址 | 说明 |
|---|---|
| `/demo/classic`（5200） | 分屏演示，最直观 |
| `/`（5200） | 攻击场景列表 S1–S7 |
| `/scenarios/overlay/run?debug=1` | 透明覆盖，红框显示 iframe |
| `/wallet`（5300） | partner 钱包，嵌入 victim 组件 |
| `/api/rules`（5400） | 审计规则库 WS001–WS012 |

### 1.5 切换防御（演示攻防对照）

**方式一（推荐）：演示页下拉框，免终端**

打开 `http://127.0.0.1:5200/demo/classic`，
右上角"防御"下拉框直接选择并即时生效
（无防御 / XFO / CSP 白名单 / 两阶段确认 / 纵深防御等），
切换后 iframe 自动按新策略重载。

**方式二：环境变量（需重启 victim）**

1. 停掉 victim（Ctrl+C）
2. 设置防御后重启：

```powershell
$env:WEBSEC_DEFENSE_PROFILE = "xfo-deny"
websec-lab run victim
```

3. 打开同一个攻击页，攻击不再生效
4. 演示完清除变量：

```powershell
Remove-Item Env:WEBSEC_DEFENSE_PROFILE
```

常用防御 profile：

- `none`：无防御基线
- `xfo-deny` / `xfo-sameorigin`：XFO 防御
- `csp-none` / `csp-self`：CSP 防御
- `csp-partner-allowlist`：合作方白名单
- `confirm-reconfirm`：两阶段确认
- `business-hardened`：业务纵深防御全开
- 完整列表：`websec-lab config` 输出的 defense 段

### 1.6 重置演示数据

```powershell
curl.exe -s -X POST http://127.0.0.1:5100/api/test/reset `
  -H "X-Websec-Test-Token: local-lab-only"
```

余额恢复 ¥1,000.00，交易记录清空。

## 2. 模式二：HTTPS 多域模式（SameSite 实验）

首次使用先安装根证书信任：

```powershell
.\scripts\https-lab.ps1 setup -TrustRoot
```

常用命令：

```powershell
.\scripts\https-lab.ps1 start     # 启动 Nginx 网关 + 五域证书 + 后端
.\scripts\https-lab.ps1 status    # 查看网关与后端状态
.\scripts\https-lab.ps1 browser   # 打开实验浏览器（已信任本地 CA）
.\scripts\https-lab.ps1 stop      # 全部停止
```

切换防御 profile：

```powershell
.\scripts\https-lab.ps1 browser -Profile https-samesite-strict
```

默认 profile 为 `https-samesite-lax`。

## 3. 自动化审计工具

不需要手动开浏览器，直接命令行：

```powershell
# 静态分析：响应头解析 + 风险规则 + 修复建议
websec-lab analyze http://127.0.0.1:5100/login `
  --ancestor http://127.0.0.1:5200

# 动态审计：真实浏览器登录→嵌入→点击→核对业务状态
websec-lab audit http://127.0.0.1:5100/lab/quick-transfer --click

# 合并报告：静态+动态一起出 JSON/Markdown/HTML
websec-lab audit-report http://127.0.0.1:5100/lab/quick-transfer --click
```

报告输出在 `artifacts\reports\<运行编号>\`，
HTML 为单文件自包含，可直接打开展示。

## 4. 实验矩阵

```powershell
# 按 config/experiments.yaml 的规格自动执行
websec-lab experiments

# 自定义输出目录
websec-lab experiments --out artifacts\experiments\my-run
```

输出物（`artifacts\experiments\<时间戳>\`）：

- `results.csv` / `results.json`：逐例原始数据
- `summary.json` / `summary.md`：指标汇总
- `attack_outcomes.svg` / `metric_cards.svg`：图表

## 5. 测试与验证脚本

```powershell
pytest                          # 全量测试（325 项）
python scripts/m3_smoke.py      # 七个攻击场景
python scripts/m4_smoke.py      # 合法嵌入 + 多级嵌套
python scripts/m5_smoke.py      # 12 组攻防对照
python scripts/m6_smoke.py      # 静态分析 13 profile
python scripts/m7_smoke.py      # 动态审计 + 移动视口
python scripts/m8_smoke.py      # 合并报告三格式
```

注意：这些脚本自带临时服务，无需先启动任何服务。

## 6. 演示视频

- 已录好的：`artifacts\demo-video\project_demo.webm`
- 重录命令：

```powershell
python scripts/record_demo_video.py
```

格式为 webm（Chrome/Edge/VLC 可直接播放）。
插入 PPT 前需自行转换为 MP4。

## 7. 推荐演示流程（约 5 分钟）

1. `scripts\start-all.ps1` 一键启动
2. 浏览器登录 alice
3. 打开 `http://127.0.0.1:5200/demo/classic`
4. 点「立即领取试用装」→ 右侧余额实时变化
5. 开「透视」开关，展示透明 iframe
6. 切 `xfo-deny` 重启 victim，再点一次 → 攻击失效
7. `websec-lab audit-report ... --click` 出报告展示
8. 演示结束重置数据

> 换场景演示时：每招在受害者「交易记录」里留下的**备注不同**（`S2 overlay` / `S5 frame-busting` …），
> **金额也不同**，点完打开交易记录即可说明"这是哪一招打的"。对照表见 `docs/scenario-fingerprints.md`。

## 7.1 补充演示：光标劫持（cursorjacking）

不属于 S1–S7，是一个独立的感知演示页：`http://127.0.0.1:5200/demo/cursor`
（也可从「场景列表」或「分屏演示」页进入）。

- 做什么：`cursor: none` 隐藏真实光标，用 DOM 画一个假光标并整体偏移 +180/+96 像素；
  你以为光标在「领取 88 元红包」上，真实指针其实压在「确认转账 ¥8.88」上。
- 怎么演：把鼠标移到"领取红包"（屏幕上那个是假光标）→ 点下去 → 底部提示
  "劫持成功：你以为点的是领取红包，实际命中确认转账"。
- 对照：点「关闭位移」再点诱饵 → 只会命中诱饵，说明差异来自位移而不是页面本身。
- 它不需要 iframe，所以 **XFO / CSP frame-ancestors 对它无效**——正好用来说明
  "框架控制层防御有覆盖边界"。

## 8. 常见问题

**攻击页点击没反应？**

- 确认当前浏览器已登录 alice
- 确认 victim 没开防御（`xfo-deny` 等会阻断嵌入）
- URL 不需要带 origin 参数，默认就是本机回环

**端口被占用？**

- 检查 5100–5400 是否有残留进程
- 或直接重启电脑后重试

**想查所有防御配置？**

```powershell
websec-lab config
```

输出的 `defense.available_profiles` 即完整列表。
