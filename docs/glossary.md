# 术语表（T0009）

| 术语 | 英文 | 定义 | 与相邻概念的区别 |
|---|---|---|---|
| 点击劫持 | Clickjacking | 攻击者用透明/伪装的嵌入层覆盖诱导页面，使受害者在不知情下对目标站点的真实控件完成点击 | 与 CSRF 的区别：点击由受害者真实发出（携带真实会话与 CSRF 令牌），不是伪造请求 |
| UI 伪装 | UI Redressing | 点击劫持的别名，强调"界面被重新着装/覆盖"的视觉欺骗本质 | — |
| 界面裁剪 | UI Clipping / Cropping | 只露出目标页面的一小块区域，让受害者误以为那是攻击者页面的一部分 | 是点击劫持的一种实现手法（本项目 S3） |
| 拖拽劫持 | Drag-and-Drop Jacking | 诱导受害者拖动内容到目标的可拖放区域完成敏感操作 | 本项目未实现：victim 无拖拽式敏感操作（范围决策） |
| 触摸劫持 | Tapjacking | 移动端触摸场景下的点击劫持，利用大号触摸目标降低误触门槛 | 本项目 S7 场景 |
| 多步诱导 | Multi-step Clickjacking | 多次诱导点击之间切换/重对齐嵌入层，串联完成多步敏感流程 | 单击攻击（S2/S3）只需一次点击 |
| Frame Busting | Frame Busting | 页面内用 JS 检测"被嵌入"并弹出/隐藏自身的传统客户端防御 | 现代浏览器可能拦截其顶层导航；本项目验证了 navigate 与 hide 两种变体的边界 |
| X-Frame-Options | XFO | 响应头，`DENY` 拒绝一切嵌入、`SAMEORIGIN` 仅允许同源；`ALLOW-FROM` 已废弃 | 不支持白名单来源列表，被 CSP frame-ancestors 取代 |
| CSP frame-ancestors | Content Security Policy: frame-ancestors | 现代嵌入控制指令，支持来源白名单，校验整条祖先链；多策略按交集执行 | 表达力强于 XFO，是 OWASP 当前推荐 |
| SameSite Cookie | SameSite | Cookie 属性，`Strict/Lax` 限制跨站请求携带会话；`None` 需配合 `Secure` | 防御的是"跨站请求携带会话"，与嵌入阻断互补 |
| Report-Only | Content-Security-Policy-Report-Only | 只上报违规不阻断的策略模式 | 不是防御，是灰度观察工具（本项目 M5/M9 实验证明） |
| 沙箱 iframe | sandboxed iframe | `sandbox` 属性限制 iframe 能力；无 `allow-scripts` 时禁用脚本，无 `allow-same-origin` 时为 opaque origin | 可用于中和 frame-busting（本项目 S5）；opaque origin 会使 SameSite 判定变为跨站 |
| 不透明源 | Opaque Origin | 沙箱/数据 URL 框架的"null"来源，与任何站点都不同源 | 本项目实测发现其与 SameSite=Lax 的交互（会话 Cookie 不随 POST 发送） |
| 祖先链 | Ancestor Chain | 从顶层窗口到直接父级的全部嵌入来源序列 | frame-ancestors 对整条链逐一校验（本项目 M4 多级嵌套实验验证） |
| 静态分析 | Static Policy Analysis | 仅凭响应头推导嵌入权限与风险（本项目 M6） | 不执行浏览器，快但无法发现业务层行为 |
| 动态验证 | Dynamic Verification | 真实浏览器加载、点击并核对业务状态（本项目 M7） | 慢但给出行为事实；与静态结果的一致率是本项目核心指标 |
