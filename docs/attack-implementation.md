# 点击劫持各功能实现说明

> 配套 [how-to-run.md](how-to-run.md) 使用。
> 每个功能按「目标 → 原理 → 关键实现 → 如何验证」说明。
> 代码根目录：`src/websec_lab/`

## 0. 公共基础设施（所有攻击共用）

### 0.1 场景注册表与参数校验

文件：`attacker/scenarios.py`

- 每个攻击是一个 `ScenarioDefinition`
- 字段含编号、标题、模板、目标路径白名单、默认参数
- 运行页参数（透明度、尺寸、偏移、金额）全部服务端校验
- 数值超出范围会被钳制，非法值直接 400
- 目标 origin 只能取配置白名单，防指向外部网站

### 0.2 对齐契约（攻击成败的几何基础）

文件：`victim/templates/victim/lab_quick_transfer.html`

- victim 快捷确认页的按钮精确位于视口正中心
- 页面用 flex 居中，表头绝对定位在顶部
- 所有覆盖类攻击都依赖这个契约
- 契约有专项测试保护，改版两次均未破坏

### 0.3 运行记录与事件回传

文件：`attacker/runstore.py`、`static/js/attack-report.js`

- 每次运行分配唯一运行编号（run_id）
- 页面 JS 把 iframe 加载、点击后跳转等事件
  通过令牌保护的 API 回传
- 事件同时追加写入 `artifacts/attacker/runs.jsonl`
- 审计与实验脚本用同一事件流做证据

---

## 1. S1 嵌入探针（probe）

目标：判断目标页当前是否允许被第三方嵌入。

原理：用可见 iframe 直接加载目标页，采集信号。

关键实现（`attacker/run/probe.html`）：

- iframe 正常可见加载目标 URL
- 页内记录 load 事件和 contentDocument 访问结果
- Chromium 下被阻断与成功加载的页内信号相同
  （contentDocument 都是 null），页内无法独立判定
- 最终判定由驱动侧（Playwright）捕获控制台消息：
  - XFO 阻断 → "Refused to display..."
  - CSP 阻断 → "violates the following CSP directive..."
  - Report-Only 消息含 "report-only" 字样，排除

验证：`python scripts/m6_smoke.py`（13 个防御 profile 全对）。

## 2. S2 透明 iframe 覆盖（overlay）——核心攻击

目标：一次诱导点击 = 一次真实敏感操作。

原理：

- 诱导按钮上面叠一个完全透明的 iframe
- iframe 里是 victim 的转账确认页
- 点击落在最顶层元素（iframe）内的确认按钮上

关键实现（`attacker/run/overlay.html`）：

- iframe 样式：`opacity:0`、`z-index:40`、无边框
- JS 对齐：iframe 中心 = 诱导按钮中心（对齐契约）
- 窗口 resize 时重新对齐
- 点击后 iframe 内表单提交 → 页面跳转
- JS 通过 load 计数感知跳转，上报"攻击可能成功"
- `debug=1` 时透明度提到 0.35 并显示红色虚线框

为什么会成功（三个条件同时满足）：

- 受害者浏览器持有 victim 登录会话（Cookie）
- iframe 内表单自带合法 CSRF 令牌
- 点击是用户真实手势，服务器视角完全正常

验证：`scripts/m3_smoke.py`（转账真实发生，余额减少）。

## 3. S3 界面裁剪（clip）

目标：证明攻击不依赖整页透明。

原理：只露出目标确认按钮那一小块区域。

关键实现（`attacker/run/clip.html`）：

- 外层裁剪窗口：固定宽高 + `overflow:hidden`
- 内层 iframe 尺寸远大于窗口
- iframe 定位使按钮区域（iframe 中心）落在窗口中心
- 整个窗口再对齐到诱导按钮上
- 视觉上只看到一个"正常按钮"，实为 victim 按钮切片

验证：m3 烟雾中 clip 场景转账成功。

## 4. S4 多步骤诱导（multistep）

目标：串联两个敏感动作（授权 + 转账）。

原理：两次诱导点击之间自动切换 iframe 目标并重新对齐。

关键实现（`attacker/run/multistep.html`）：

- 步骤表内嵌页面：第 1 步授权页、第 2 步转账页
- 状态机由 iframe load 计数驱动：
  - load 1 = 页面就绪
  - load 2 = 表单已提交（点击生效）
- 第 1 次点击提交授权后，JS 自动切换 iframe 源
  到转账页并重新对齐，诱导文案同步更换
- 第 2 次点击完成转账

验证：m3 烟雾断言授权 +1 且转账 +1。

## 5. S5 沙箱绕过 frame-busting（bust）

目标：证明纯前端 frame-busting 可被绕过。

原理：

- victim 用 JS 检测"被嵌入"并弹出（navigate 变体）
  或整页隐藏（hide 变体）
- sandbox 属性禁用 iframe 内脚本执行
- 脚本不能跑 = 弹出/隐藏逻辑失效
- 但表单提交不需要 JS，点击仍然有效

关键实现（`attacker/run/bust.html`）：

- iframe 加 `sandbox="allow-forms allow-same-origin"`
- 不加 `allow-scripts` → victim 的 busting 脚本被禁
- 必须加 `allow-same-origin`，否则 iframe 变 opaque origin
  SameSite=Lax 会话 Cookie 不随 POST 发送，攻击反而失败
- 这个组合（加表单+同源、不加脚本）就是标准绕过配置

对照结论（实验实测）：

- 经典 navigate 变体：现代 Chrome 拦截无手势顶层导航
  攻击反而能继续 → 纯前端防御不可靠
- hide 变体：页面保持隐藏，攻击被挡住，但依赖 JS

验证：`scripts/m5_smoke.py` 的 frame-busting 两用例。

## 6. S6 滚动重定位（scroll）

目标：利用"滚到页面底部才出现按钮"的心理降低戒备。

关键实现（`attacker/run/scroll.html`）：

- 构造长文章，诱导按钮（"继续阅读"）在页面底部
- 覆盖 iframe 用 `position:fixed`（视口定位）
- 监听 scroll 事件，按钮进入视口时才对齐并显示
- 滚动过程中 iframe 始终跟随按钮位置
- 对齐后上报 `aligned_after_scroll` 事件

验证：m3 烟雾中 scroll_into_view 后点击转账成功。

## 7. S7 移动端 tapjacking（tap）

目标：移动触摸场景下的点击劫持。

关键实现（`attacker/run/tap.html`）：

- 页面做成手机屏外形（外框 + 刘海 + 红包诱导）
- 大号触摸按钮降低误触门槛
- 对齐逻辑与桌面版完全一致（中心对中心）
- 验证用 Playwright 的 `touchscreen.tap()` 真实触摸事件
- 上下文开启 `is_mobile` + `has_touch` 模拟移动视口

验证：m3 烟雾 tap 场景（移动上下文内登录→点击→转账）。

## 8. Double Clickjacking（双窗口时序攻击）

目标：不依赖 iframe 的新机制攻击。

原理：

- 攻击者开两个窗口（或利用窗口切换）
- 第 1 次点击触发内容切换/焦点转移
- 在时间窗口内第 2 次点击落在敏感操作上
- frame-ancestors/XFO 对此"沉默"（没有嵌入行为）

关键实现（`attacker/window_lab.py`）：

- 受控双窗口对 + 连续坐标点击编排
- 两次点击都走浏览器输入协议（非 DOM 合成事件）
- 矩阵中为 window 类用例（54 例）

验证：正式矩阵 `artifacts/final-matrix-v2/`（window 用例）。

---

## 9. 配套功能

### 9.1 分屏演示模式

文件：`attacker/demo.py`、`templates/attacker/demo_classic.html`

- 左侧攻击页 + 右侧受害者账户实况
- 服务端代理 victim 测试 API（规避跨域，白名单限制）
- 事件解说时间线自动生成
- 透视开关显示透明 iframe
- 一键重置、未登录引导

### 9.2 防御切换

文件：`defense/profiles.py`、`config/defense.yaml`

- 24+ 命名防御 profile
- 环境变量一键切换，业务代码零改动
- `partner` 占位符在启动时展开为真实合作方来源

### 9.3 审计工具

- 静态：`auditor/analyzer.py`（12 条规则）
- 动态：`auditor/dynamic/runner.py`（真实浏览器）
- 合并：`auditor/report.py`（三格式报告）

---

## 10. 一页速查表

| 场景 | 一句话原理 | 关键代码 |
|---|---|---|
| S1 探针 | 可见嵌入 + 多信号判定 | run/probe.html |
| S2 覆盖 | 透明 iframe 中心对齐 | run/overlay.html |
| S3 裁剪 | overflow:hidden 只露按钮 | run/clip.html |
| S4 多步 | load 计数驱动状态机 | run/multistep.html |
| S5 沙箱 | sandbox 禁脚本留表单 | run/bust.html |
| S6 滚动 | fixed 定位跟随滚动 | run/scroll.html |
| S7 移动 | 触摸版中心对齐 | run/tap.html |
| 双击 | 双窗口时序 + 真实输入 | window_lab.py |
