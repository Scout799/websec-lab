# M7 浏览器动态审计器说明

更新时间：2026-11-04（审计判定修复）

## 架构

```text
run_dynamic_audit(DynamicAuditConfig)
  ├─ BrowserSession        # chrome/msedge/firefox + desktop/mobile 视口 + trace
  ├─ EvidenceCollector     # console / pageerror / CSP / 网络 / 截图 / 失败现场
  ├─ probe harness（临时 auditor 服务，/probe/embed）
  │    ├─ variant=visible  # 普通嵌入（探针）
  │    └─ variant=overlay  # 透明居中覆盖（点击劫持验证）
  ├─ 登录（可选）           # 表单登录 + storage_state 持久化
  ├─ framing 判定           # 多信号：load 计数 + 控制台阻断消息 + 超时兜底
  ├─ clickjacking 判定      # 坐标点击 + victim 测试 API 前后状态对比
  └─ 证据落盘               # artifacts/auditor/<run_id>/result.json + 截图 + 日志
```

| 模块 | 职责 |
|---|---|
| [dynamic/session.py](../src/websec_lab/auditor/dynamic/session.py) | 浏览器/上下文/页面生命周期；通道解析（本机 Chrome/Edge/Firefox）；桌面与移动视口 |
| [dynamic/collectors.py](../src/websec_lab/auditor/dynamic/collectors.py) | 控制台/页面错误/CSP 违规/网络记录（有界）；截图与失败现场（截图 + HTML + 报告） |
| [dynamic/probe_routes.py](../src/websec_lab/auditor/dynamic/probe_routes.py) | harness 页面：只允许嵌入本地目标；load 计数写入 title 供驱动读取 |
| [dynamic/runner.py](../src/websec_lab/auditor/dynamic/runner.py) | 编排：登录、多信号嵌入判定、坐标点击与业务状态验证、重试与现场保留 |
| [dynamic/models.py](../src/websec_lab/auditor/dynamic/models.py) | 统一结果结构（JSON 可序列化） |

## 多信号判定（T0709）

Chromium 下被阻断与成功跨域加载的 iframe 页内信号相同（contentDocument 均为 null），因此动态判定组合：

1. **控制台阻断消息**：识别 XFO 拒绝及生效的 `frame-ancestors` 违规，并排除 Report-Only 和普通脚本等资源的 CSP 违规。
2. **真实文档证据**：通过 Playwright 检查子框架 URL、文档就绪状态和成功的 HTTP 文档响应，确认 `allowed`。仅触发 `load` 不足以证明成功加载；503 或错误页面返回 `unknown`。
3. **记录响应**：保存文档响应 URL、状态码和保留多值的响应头，供合并报告在实际来源上重新推导静态权限。
4. **超时兜底**：缺少可确认的证据时返回 `unknown`；frame-busting 已跳出框架的情况保留单独信号。

点击劫持判定以 victim 测试 API 的转账/授权/余额变化为准。iframe 重载仅是辅助信号，不能单独证明表单提交。一次点击未触发操作时记录该观察结果，不自动归因于业务层防御。

合并报告结论：`vulnerable`=已观察到业务变化；`protected`=本次来源的嵌入被浏览器阻断；`partial`=允许嵌入但本次点击未改变业务；`embeddable`=确认可嵌入但未验证业务操作；`inconclusive`=证据不足或动态运行失败。所有结论仅限本次来源、浏览器和操作。

## 使用

```powershell
# 完整审计：登录 + 嵌入判定 + 点击验证
websec-lab audit http://127.0.0.1:5100/lab/quick-transfer --click

# 公开目标、移动视口、带 trace
websec-lab audit http://127.0.0.1:5100/login --no-login --viewport mobile --trace
websec-lab audit <url> --json          # 完整 JSON 结果
```

Python API：`from websec_lab.auditor.dynamic import DynamicAuditConfig, run_dynamic_audit`。

证据目录 `artifacts/auditor/<run_id>/`：`result.json`、`framing_probe.png`、`clickjacking_before/after.png`、`console_log.json`、`network_log.json`、`storage_state.json`、可选 `trace.zip`，失败时额外保留 `failure_<step>.png/.html/_report.json`。

## 验证结果（2026-10-24）

以下为历史基线。2026-11-04 修复后的结果见 [修复验证记录](audit-fix-2026-11-04.md)。

`scripts/m7_smoke.py` 对 7 个防御 profile + 1 个合法来源用例跑完整动态审计，结果与 M5 真实攻击、M6 静态判定三方一致：

| Profile | framing | 点击触发敏感操作 |
|---|---|---|
| none（移动视口） | allowed | 是 |
| xfo-deny / csp-none / csp-partner-allowlist | blocked（归因 xfo/csp） | 否 |
| csp-partner-allowlist + harness 绑定白名单端口 5300 | **allowed**（合法来源通过，T0705） | — |
| confirm-reconfirm | allowed | 否（两阶段挡住单击） |
| confirm-token | allowed | 是（已知局限，与 M5 结论一致） |
| frame-busting-hidden | allowed | 否（页面隐藏） |

测试：4 项真实浏览器端到端（登录/嵌入/点击/证据持久化 + 合法来源 + 公开目标）+ 13 项单元/harness 测试；全量 204 项通过，M3 烟雾无回归。

## 已知边界

- 视频录制需要 Playwright 的 ffmpeg 二进制，当前环境下载源不可用（trace 与网络日志不受影响）；
- Firefox/Edge 通道已实现解析但端到端仅在 Chrome 155 上实测；
- harness 只代表单一嵌入来源；多级嵌套（A 嵌 B 嵌目标）的动态验证待 M4 partner 站点接入后补充。
