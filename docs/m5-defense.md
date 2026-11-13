# M5 防御策略矩阵说明

更新时间：2026-10-22

## 机制

所有防御通过 [config/defense.yaml](../config/defense.yaml) 中命名 profile 描述，一个开关即可整体切换，业务代码零改动：

- 环境变量：`WEBSEC_DEFENSE_PROFILE=xfo-deny websec-lab run victim`
- 应用工厂：`create_app(test_config={"DEFENSE_PROFILE": "xfo-deny"})`
- `websec-lab config` 会输出当前激活的 profile 与全部可用列表

优先级：显式指定 > 环境变量 > `default_profile`（当前为 `none`，即 M3 攻击基线）。

## Profile 一览

| 类别 | Profile | 效果 |
|---|---|---|
| 基线 | `none` | 无嵌入防御（M3 攻击复现状态） |
| 响应头 | `xfo-deny` / `xfo-sameorigin` | X-Frame-Options 拒绝全部 / 仅同源 |
| 响应头 | `csp-none` / `csp-self` | CSP frame-ancestors 现代等价形式 |
| 白名单 | `csp-partner-allowlist` | 仅 self 与 partner 来源可嵌入 |
| 白名单错误 | `csp-partner-allowlist-attacker` | 白名单误含攻击者来源 |
| 一致性 | `xfo-csp-consistent` / `xfo-csp-conflict` | XFO 与 CSP 一致 / 互相矛盾 |
| 错误配置 | `broken-duplicate-xfo` / `broken-invalid-xfo` / `broken-wide-csp` / `broken-duplicate-csp` | 重复头、非法值、通配白名单、多 CSP 头 |
| 对照 | `csp-report-only` | Report-Only：只报告不阻断 |
| Cookie | `samesite-strict` / `samesite-none` / `cookie-hardened` | SameSite/Secure/HttpOnly 组合 |
| 业务 | `confirm-reconfirm` / `confirm-token` / `reauth` / `business-hardened` | 两阶段确认 / 一次性令牌 / 重新认证 / 全开 |
| 前端 | `frame-busting` / `frame-busting-hidden` | 经典弹出式 / 隐藏式 frame-busting |
| 窗口 | `coop-same-origin` | Cross-Origin-Opener-Policy |

错误配置 profile 是故意构造的样本，同时作为 M6 静态策略分析器的测试语料。

## 真实浏览器攻防对照结果（Chrome 155，2026-10-22）

`scripts/m5_smoke.py` 在 12 组 profile × 场景组合上重放了 M3 攻击基线：

| Profile | S2 透明覆盖攻击结果 | 结论 |
|---|---|---|
| `none` | 转账成功 | 基线成立 |
| `xfo-deny` | 阻断 | XFO DENY 有效 |
| `csp-none` | 阻断 | CSP frame-ancestors 有效 |
| `csp-partner-allowlist` | 阻断 | 攻击者不在白名单 |
| `xfo-csp-conflict` | 阻断 | XFO DENY 仍然生效，冲突配置徒增混淆 |
| `csp-report-only` | 转账成功 | Report-Only 不阻断（如实记录） |
| `confirm-reconfirm` | 单击停留在详情页 | 两阶段确认挡住单击攻击 |
| `confirm-token` | 转账成功一次 | 一次性令牌挡重放、不挡"活点击"（如实记录） |
| `business-hardened` | 单击停留在详情页 | 纵深组合有效 |
| `frame-busting` | 转账成功 | 经典 top.location 被 Chrome 无手势导航策略拦截（如实记录） |
| `frame-busting-hidden` | 阻断 | 隐藏式基线在本次实验中守住 |
| `frame-busting` + S5 沙箱 | 转账成功 | `sandbox="allow-forms allow-same-origin"`（无 allow-scripts）中和脚本型防御（对照成立） |

探针（S1）在全部阻断型 profile 下均给出 `blocked` 判定：Chromium 下被阻断的 iframe 与跨域成功加载的 `contentDocument` 同为 `null`，页内信号不足以区分，最终判定结合了驱动侧捕获的控制台消息（XFO："Refused to display…"；CSP："violates the following Content Security Policy directive…"）。这一多信号结论将由 M7 动态审计器正式产品化。

## 实验中的四个"如实发现"

1. **CSP Report-Only 不是防御**：只产生违规报告，攻击照常完成。价值在于灰度观察策略影响。
2. **一次性令牌挡得住重放、挡不住活点击**：透明覆盖点击提交的是带有效令牌的真实表单；令牌的单次使用性在重放/CSRF 场景才体现。业务防御必须与响应头防御组合。
3. **经典 frame-busting 在现代 Chrome 中不可靠**：页面加载时的跨域顶层导航被浏览器"无用户手势"策略拦截（控制台可见 Unsafe attempt 消息），攻击不被打断；隐藏式变体（默认 display:none、同帧检测后再显示）在本次实验中守住了嵌入场景，代价是依赖 JS。
4. **sandbox 与 SameSite 的意外交互**：`sandbox="allow-forms"`（无 allow-same-origin）会把 iframe 变成 opaque origin，SameSite=Lax 的会话 Cookie 不随其 POST 发送，表单被 CSRF 校验拒绝（"The CSRF session token is missing"）；而加上 `allow-same-origin` 后会话恢复、且只要仍不含 `allow-scripts`，脚本型 frame-busting 依旧被禁用——这正是 S5 使用的标准绕过配置。

## 已知边界

- 127.0.0.1 上 victim 与 attacker 属于同一 site，SameSite 防御的真实跨站效果需在 `.test` 多域部署后由 M9 实验验证；
- `samesite-none`、`cookie-hardened` 在纯 HTTP 下会破坏会话（浏览器要求 SameSite=None 配 Secure；Secure Cookie 不经明文发送），属于教学样本，不要在浏览器烟雾测试中使用；
- COOP 头已实现并通过快照测试，但针对窗口型攻击（双击劫持）的对照实验待 M3 扩展任务 T0310 完成后补充。
