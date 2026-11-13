"""Build a Chinese final report using independently verified measurements."""

# ruff: noqa: E501

from __future__ import annotations

import json
from importlib.metadata import version
from pathlib import Path

import markdown

from websec_lab.auditor.dynamic.session import BrowserSession

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "deliverables"


def table(headers, rows):
    return "\n".join(
        [
            "| " + " | ".join(headers) + " |",
            "| " + " | ".join("---" for _ in headers) + " |",
            *("| " + " | ".join(str(v) for v in row) + " |" for row in rows),
        ]
    )


def main():
    summary = json.loads(
        (ROOT / "artifacts/final-results/summary.json").read_text(encoding="utf-8")
    )
    rows = json.loads((ROOT / "artifacts/final-results/results.json").read_text(encoding="utf-8"))
    verification = json.loads((ROOT / "artifacts/final-results/verification.json").read_text())
    assert verification["passed"]
    profile_table = table(
        ["配置", "业务变化 / 27", "单击转账 / 9", "完整两步 / 9"],
        [
            [
                p,
                f"{d['desktop_actions']}/27",
                f"{d['overlay_transfers']}/9",
                f"{d['multistep_full']}/9",
            ]
            for p, d in summary["profile_stats"].items()
        ],
    )
    ablation_table = table(
        ["通道", "标记攻击尝试", "覆盖成功攻击", "正常对照误报"],
        [
            [
                name,
                f"{d['detected_attempts']}/{d['attempts']}",
                f"{d['successful_attack_detections']}/{d['successful_attacks']}",
                f"{d['false_positives']}/{d['normal_controls']}",
            ]
            for name, d in zip(
                ["CSP 报告", "页面交互", "两通道并集"], summary["ablations"].values(), strict=True
            )
        ],
    )
    browser_table = table(
        ["浏览器", "实际版本", "桌面核心攻击有业务变化"],
        [
            [b, ", ".join(d["versions"]), f"{d['actions']}/{d['n']}"]
            for b, d in summary["browsers"].items()
        ],
    )
    partner_table = table(
        ["配置", "框架允许", "实际组件可用"],
        [
            [p, f"{d['allowed']}/{d['n']}", f"{d['functional']}/{d['n']}"]
            for p, d in summary["legitimate"].items()
        ],
    )
    window_rows = [r for r in rows if r["kind"] == "window"]
    window_table = table(
        ["配置", "发生转账", "交互通道标记", "CSP 通道标记"],
        [
            [
                p,
                f"{sum(r['attack_triggered'] for r in window_rows if r['profile']==p)}/9",
                f"{sum(r['channels']['interaction_detected'] for r in window_rows if r['profile']==p)}/9",
                f"{sum(r['channels']['csp_detected'] for r in window_rows if r['profile']==p)}/9",
            ]
            for p in dict.fromkeys(r["profile"] for r in window_rows)
        ],
    )
    normal_table = table(
        ["正常交互", "例数", "交互规则标记"],
        [
            [
                scenario,
                sum(r["scenario"] == scenario for r in rows),
                sum(
                    r["channels"]["interaction_detected"] for r in rows if r["scenario"] == scenario
                ),
            ]
            for scenario in ("direct-normal", "fast-focus-normal", "legitimate-embedded-payment")
        ],
    )
    dependencies = table(
        ["依赖", "版本"],
        [
            [p, version(p)]
            for p in ["Flask", "SQLAlchemy", "playwright", "requests", "pytest", "ruff", "black"]
        ],
    )
    text = f"""# 点击劫持的分析与防御

## 最终技术报告

Web 安全课程项目 · 三人小组 · 版本 1.0.0 · 整理日期：2026-11-07

## 摘要

本项目把点击劫持评估建立在完整证据链上：先检查来源是否允许嵌入，再观察会话是否携带、用户点击是否落到目标控件，最后以服务端交易、授权和余额变化确认影响。平台包含受害业务、诱导页面、合法合作方与审计服务，以五域 HTTPS 支持同站不同源和跨站对照。

最终实验覆盖 {summary['profiles']} 种配置、Chrome/Edge/Firefox 三种浏览器及三次重复，共 {summary['rows']} 个独立用例；另有 96 个 SameSite 专项用例。全部最终用例通过流程与证据检查。静态与动态在 {summary['consistency']['n']} 个具有双侧结论的嵌入检查上保持一致；该指标仅表示可嵌入性判断，并不等于攻击风险识别率。双通道分析分别统计攻击尝试、成功攻击和正常对照，展示策略报告与交互信号的互补性，同时保留合法嵌入误报和窗口路径漏报。

## 1. 问题与目标

点击劫持是一种用户界面重定向攻击。受害者看到诱导页面，却点击到覆盖在相同位置的目标站点控件。典型场景中，目标页面被加载到 iframe，浏览器使用受害者会话提交目标站点自身的表单。攻击方无需读取目标页 DOM，跨源同源策略也不会阻止用户点击已渲染的框架。[1][2]

本项目围绕四个问题展开：（1）如何用真实浏览器稳定复现覆盖、裁剪和多步骤诱导；（2）框架、Cookie 和业务层机制各自控制哪些条件；（3）静态配置预测是否符合指定来源与会话下的浏览器行为；（4）CSP 报告和页面交互能观察哪些攻击路径，正常行为又会产生哪些相似信号。

项目成果是可复核的工程平台、实验数据与分析方法。本文不把规则组合或工具集成宣称为新的攻击原理，也不以课程实验代替互联网总体测量。

## 2. 威胁模型与系统实现

### 2.1 参与方与站点关系

| 域名 | 角色 | 与 victim.test 的关系 |
| --- | --- | --- |
| victim.test | 虚构银行、转账与授权 | 目标站点 |
| same.victim.test | 诱导服务别名 | 同站、不同源 |
| attacker.test | 诱导服务 | 跨站、不同源 |
| partner.test | 合法钱包和支付组件 | 跨站、精确白名单来源 |
| audit.test | 探针及审计服务 | 独立来源 |

Nginx 在 8443 端口终止 TLS，后端端口 15100–15400 分别运行四个 Flask 服务。原生模式后端和网关绑定回环地址；容器内网关对容器网络监听，由 Compose 仅发布到宿主机 127.0.0.1。证书包含五域 SAN，CA 验证、主机名验证与 SNI 保持开启。域名映射只作用于独立浏览器，不修改系统 hosts。端口变化属于源的变化，不能据此判定跨站。

攻击者控制本地诱导页面、框架的样式和窗口布局。受害者使用虚构账户 alice，初始密码 alice-lab。攻击不假设 XSS、目标服务器失陷或读取跨域 DOM 的能力。自动化驱动可检查目标框架以收集证据；发动核心攻击时使用诱导按钮中心的页面坐标，不能用驱动侧 DOM 权限代替攻击步骤。

### 2.2 受害业务与真实结果

受害站提供登录、账户余额、转账记录、第三方授权和业务日志。快捷转账固定模拟收款人 bob、金额 123 分。测试 API 受本地令牌保护，负责状态查询与重置；每种配置使用独立临时数据库，每例清零并重新建立浏览器会话。

单步转账成立需新增一条交易且余额减少 123 分；多步骤完整成立需同时新增授权和转账。只发生授权的多步骤用例计入“任一业务变化”，不能计为完整两步成功。iframe load、控制台消息、截图和页面事件均不替代服务端状态。

### 2.3 攻击场景

| 场景 | 实现 | 本轮输入预算 |
| --- | --- | --- |
| overlay | 近透明 iframe 覆盖诱导按钮 | 一次坐标点击 |
| clip | 裁剪容器只露出目标确认区域 | 一次坐标点击 |
| multistep | 分别加载授权与转账目标 | 每个目标一次，共两次 |
| 窗口连续点击 | 诱导弹窗第一次按下鼠标时关闭，随后点击目标窗口同坐标 | 两次页面坐标点击 |

场景库还提供嵌入探针、沙箱、滚动和移动视口演示。最终核心矩阵仅统计上述三类 iframe 攻击，移动视口作为单独扩展。移动结果来自浏览器设备模拟，不是物理手机测量。

### 2.4 分层防御

框架层实现 XFO DENY/SAMEORIGIN、CSP frame-ancestors 精确白名单及 Report-Only；错误配置覆盖无效/重复头、宽泛来源和 XFO/CSP 冲突。会话层控制 SameSite、Secure 与 HttpOnly。业务层实现两阶段确认、一次性令牌和敏感操作重新认证。脚本层保留顶层导航式和隐藏式 frame-busting；COOP 用于窗口关系对照。

两种白名单错误配置同时列出旧 HTTP 实验来源和当前 HTTPS 同站诱导来源，保证正式实验测试的来源确实落在错误白名单中。现代浏览器对有效 enforcing CSP 与 XFO 的处理依据标准并由实验验证。[1][3][4]

## 3. 自动化审计与双通道观察

### 3.1 静态与动态审计

静态分析获取响应头及 Cookie 属性，解析 XFO、CSP 多策略交集、来源匹配和策略冲突，输出规则编号、证据及建议。动态审计在指定来源建立探针，登录目标站，收集真正加载的文档响应、浏览器阻断信息和截图，再执行坐标点击与服务端状态核对。

比较阶段使用动态会话中的文档响应，避免把匿名请求的登录页与认证后的目标页混为一谈。iframe load 对被阻断文档也可能发生；没有实际文档或阻断依据时结果为 unknown。Report-Only 消息不能被当作 enforcing 阻断。

导航式 frame-busting 可能把探针的顶层页面跳转到银行。审计器此时停止诱导点击，记录界面已经离开探针，并检查业务变化；不会继续点击已直接显示的目标按钮。嵌入允许与脚本后续动作分别记录。

### 3.2 两种信号与关联规则

通道一接收 CSP 报告，兼容传统 csp-report 与 Reporting API 数据结构，提取 frame-ancestors、路径和时间。通道二由目标页面脚本采集窗口焦点、可见性、可信点击和敏感控件标记。控件自身获得焦点不等于窗口重新获焦，采集器对此明确区分。

记录按 32 位 run_id 隔离；路径不保存查询串。分析将“嵌入框架中的可信敏感点击”或“窗口获焦后 300ms 内的可信敏感点击”标为可疑；CSP 与交互证据按路径和 2 秒接收时间窗关联。融合判定采用两通道并集。业务变化和用例攻击标签均不作为检测输入。

检测通道用于解释观察到的活动，服务端状态用于确认业务影响，两者保持独立。页面脚本上报不是防篡改安全日志；本项目也没有将它用于自动封禁真实用户。

## 4. 实验设置与复核方法

{browser_table}

最终矩阵组成如下：

| 类别 | 设计 | 例数 |
| --- | --- | --- |
| 桌面核心攻击 | 28 配置 × 3 攻击 × 3 浏览器 × 3 重复 | 756 |
| 移动视口 | 3 配置 × 3 攻击 × 3 浏览器 × 3 重复 | 81 |
| 合法组件嵌入 | 4 配置 × 3 浏览器 × 3 重复 | 36 |
| 窗口路径 | 6 配置 × 3 浏览器 × 3 重复 | 54 |
| 正常交互 | 直接、快速切窗、明确嵌入支付，各 9 例 | 27 |
| 合计 | 单独标记每种类别 | 954 |

SameSite 专项另含 2 浏览器 × 4 Cookie 配置 × 2 站点关系 × 2 第三方 Cookie 设置 × 3 重复，共 96 例。它与主矩阵使用不同问题、分母与观测字段，不能直接混成一个攻击成功率。

主矩阵主要使用同站不同源的 same.victim.test，控制 SameSite 对会话的干扰；跨站效果在专项实验中独立验证。浏览器审计会话显式允许第三方 Cookie，专项则分别开启与关闭限制。

原始 945 例首轮保留在 final-matrix-v2，其中 18 例发生 frame-busting 判定错误。修复后仅重跑受影响的 18 例；增加 9 例合法支付正常对照；另将 HTTP 来源未匹配 HTTPS 的两种配置完整重跑 54 例。最终汇总按 case_id 合并，provenance.json 保存输入哈希、替换用例和原因，既不删除首次失败，也不把重跑当成新增样本。

独立复核检查完整笛卡尔矩阵、唯一 case_id/run_id、源 JSON/CSV 一致性、业务增量、浏览器版本、原始事件与分析结论及截图。最终 {summary['rows']} 例全部通过，保留 {verification['screenshots']} 张截图。重复来自同一套本地应用和固定交互，不代表独立用户抽样，本文报告计数而不据此推断互联网总体概率。

## 5. 结果与分析

### 5.1 防御矩阵与业务影响

{profile_table}

“业务变化”涵盖转账或授权的任一种变化；“完整两步”要求授权与转账都发生。分母分别为每配置 27 个桌面核心用例、9 个覆盖单击用例、9 个多步骤用例。配置间既有机制对照，也有错误配置样本，不能平均汇总为真实网站的风险比例。

![防御配置对照](figures/defense-comparison.png)

XFO/CSP 的框架限制作用于嵌入条件；一次性令牌验证的是合法表单条件，攻击者借用用户点击时仍可能通过。二次确认与重新认证的结果只对应本轮交互预算和已登录状态。隐藏式脚本能够阻止部分交互，但还需考虑组件功能与脚本执行条件。[2][5]

其中 samesite-none 的 0/27 来自缺少 Secure 导致 Cookie 被拒绝、登录态无法建立，它是功能失效对照。reauth 在本轮刚完成登录的有效窗口内仍可执行操作。评价应结合实际条件和合法功能，不能根据零成功数或配置名称直接排列机制强弱。

### 5.2 浏览器差异

![浏览器差异](figures/browser-comparison.png)

按配置、浏览器和场景检查差异，避免以总和掩盖行为。导航式 frame-busting 在本轮 Chrome/Edge 中移除诱导界面，而 Firefox 的具体行为以该配置原始结果为准；不能将其中一种浏览器结果外推为脚本普遍有效。全部 {summary['consistency']['n']} 个有效静态/动态嵌入对照中有 {summary['consistency']['agree']} 个一致，该结论不包含没有嵌入检查的顶层窗口和正常直接操作。

### 5.3 SameSite 跨站专项

| Cookie | 同站 iframe | 跨站 iframe，允许 3PC | 跨站 iframe，阻止 3PC |
| --- | --- | --- | --- |
| Strict + Secure | 发送有效会话 | 不发送 | 不发送 |
| Lax + Secure | 发送有效会话 | 不发送 | 不发送 |
| None + Secure | 发送有效会话 | 发送有效会话 | 不发送 |
| None，无 Secure | 拒绝保存 | 拒绝保存 | 拒绝保存 |

96/96 专项用例通过预期、TLS、网络 Cookie 原因、业务变化和四张截图的独立复核。跨站顶层 GET 对照进一步区分 Lax 与 Strict。Strict/Lax 不能代替同站不同源的嵌入控制；HttpOnly 防止脚本直接读 Cookie，也不会阻止浏览器自动发送 Cookie。[6]

### 5.4 合法合作方兼容性

{partner_table}

框架允许和组件可用是两个指标。Lax 配置下跨站组件可能加载登录页，即使框架本身没有被 CSP 拒绝；None+Secure 与精确 partner 白名单在允许第三方 Cookie 的实验条件下恢复认证组件。该条件不会消除真实浏览器用户设置的约束。

### 5.5 窗口连续点击

{window_table}

输入模型为第一次可信页面坐标点击关闭诱导弹窗，随后使目标窗口前置，在同一页面坐标执行第二次可信点击。保留实际间隔与三个阶段截图。浏览器协议驱动两次输入，不等同于操作系统全局坐标的一次硬件双击，也不能据此声称绕过所有浏览器或窗口管理器。此扩展用于验证框架限制与顶层交互的边界，并参考公开窗口重定向思路。[7]

### 5.6 双通道消融与正常对照

{ablation_table}

![双通道消融](figures/channel-ablation.png)

攻击尝试分母包含核心、移动和窗口用例；成功攻击分母只包含产生业务变化的攻击用例。融合并集扩大了被观察到的尝试范围，但不能自动提高所有成功攻击的覆盖率。CSP 可以观察被阻断的尝试与 Report-Only 违规；它通常不能观察不受 frame-ancestors 约束的顶层窗口路径。

{normal_table}

明确展示收款人和金额的合法嵌入支付同样产生“框架中的敏感点击”，因此被当前交互规则标记。这说明规则检测的是可疑交互形态，不能独立识别用户意图。实际汇报保留这类误报，不把正常支付伪装成攻击样本。窗口路径缺少焦点信号时则可能漏报，不能用已经发生的转账反向补造检测信号。

### 5.7 审计执行耗时

![审计执行耗时](figures/audit-duration.png)

时间包含浏览器启动、登录、显式等待、点击、状态查询和证据写入。它反映审计任务的执行成本，不是 CSP 等防御机制给业务页面带来的延迟，也不是经随机化基线测量的性能开销。三次重复用于复核确定性操作，不能据此夸大统计精度。

## 6. 工程质量、部署与复现

依赖采用 Python 3.12 和精确 requirements.lock。关键包版本如下：

{dependencies}

Windows 原生入口为 `python -m websec_lab.https_lab`，负责证书、固定哈希 Windows Nginx、独立浏览器和服务生命周期。Linux 提供 Dockerfile、Compose、非 root 应用用户、运行与证据独立卷、HTTPS 健康检查和真实 Chromium 烟雾脚本。Linux 网关版本以发行版实际安装值记录。

最终测试记录、Linux 验收记录与清洁环境检查分别见交付目录中的验收材料，具体通过数量以相应机器输出为准。CI 工作流已配置 Windows/Linux 单元检查和 Docker 冒烟任务；未发布或触发远程 CI，不能把配置文件当作远端成功记录。

完整复现命令、账户、配置切换、报告路径与演示恢复步骤见 README 和交付操作手册。新增环境生成自身 CA 与密钥，交付包不包含私钥、浏览器个人配置、运行数据库或 Linux 验证虚拟磁盘。源码采用 MIT，依赖和工具保留各自许可证。

## 7. 成果与后续方向

最终成果包括：五域 HTTPS 靶场、三类核心攻击和窗口扩展、28 配置的分层对照、静态/动态审计、双通道采集、954 例主实验与 96 例专项数据、独立复核脚本、统计图表、答辩材料及可复现部署。

工程的主要价值是把配置、浏览器观察和业务结果连接起来，使“存在保护头”“实际无法嵌入”“点击未形成操作”“产生可疑信号”分别得到可检查的证据。后续可在保持正常嵌入对照的基础上引入合作方意图声明，并对物理窗口输入、真实移动设备及更多浏览器设置开展额外测量。这些扩展不计入本次已完成结果。

## 参考文献

[1] Calzavara S, Roth S, Rabitti A, Backes M, Stock B. A Tale of Two Headers: A Formal Analysis of Inconsistent Click-Jacking Protection on the Web[C]//29th USENIX Security Symposium. 2020: 683–697. https://www.usenix.org/conference/usenixsecurity20/presentation/calzavara

[2] Huang L S, Moshchuk A, Wang H J, Schechter S, Jackson C. Clickjacking: Attacks and Defenses[C]//21st USENIX Security Symposium. 2012: 413–428. https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/huang

[3] Ross D, Gondrom T. HTTP Header Field X-Frame-Options[S/OL]. RFC 7034. IETF, 2013[2026-11-07]. https://www.rfc-editor.org/rfc/rfc7034

[4] W3C. Content Security Policy Level 3: frame-ancestors[EB/OL].[2026-11-07]. https://www.w3.org/TR/CSP3/#directive-frame-ancestors

[5] OWASP. Clickjacking Defense Cheat Sheet[EB/OL].[2026-11-07]. https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html

[6] MDN Web Docs. Set-Cookie header[EB/OL].[2026-11-07]. https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie

[7] Yibelo P. DoubleClickjacking: A New Era of UI Redressing[EB/OL]. 2024[2026-11-07]. https://www.evil.blog/2024/12/doubleclickjacking-what.html

## 附录：数据入口

`artifacts/final-results/results.json` 与 results.csv 为最终逐例数据；summary.json 为聚合结果；verification.json 为独立复核；provenance.json 保存原始来源与替换原因。各行 evidence_dir 指向实际截图、原始信号、合并报告与浏览器日志。SameSite 原始数据和独立复核位于 `artifacts/samesite-https/`。误报、漏报及首次失败记录均保留。
"""
    OUT.mkdir(exist_ok=True)
    report = OUT / "点击劫持项目最终报告.md"
    report.write_text(text, encoding="utf-8")
    (ROOT / "docs/final-report.md").write_text(
        text.replace("](figures/", "](../deliverables/figures/"), encoding="utf-8"
    )
    html = """<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>点击劫持最终报告</title>
    <style>@page{size:A4;margin:19mm 17mm}*{box-sizing:border-box}body{font-family:'Microsoft YaHei',sans-serif;color:#10233f;font-size:11pt;line-height:1.7;max-width:1000px;margin:24px auto}h1{font-size:28pt}h2{font-size:18pt;border-bottom:1px solid #aac3e5;margin-top:26px;break-after:avoid}h3{font-size:13pt;break-after:avoid}p{orphans:3;widows:3}table{border-collapse:collapse;width:100%;font-size:9pt;margin:14px 0}th{background:#e5ecf6}td,th{border:1px solid #bac7d8;padding:7px;text-align:left;overflow-wrap:anywhere}tr{break-inside:avoid}thead{display:table-header-group}img{max-width:100%;max-height:190mm;object-fit:contain;display:block;margin:18px auto}img[src*=defense-comparison]{max-height:112mm}pre{white-space:pre-wrap;background:#eef2f8;padding:12px;font-size:9pt}code{overflow-wrap:anywhere}a{color:#2563eb} @media print{body{margin:0;max-width:none}img{break-inside:avoid}}</style>"""
    html += markdown.markdown(text, extensions=["tables", "fenced_code", "toc"])
    html += "</html>"
    html_path = OUT / "点击劫持项目最终报告.html"
    html_path.write_text(html, encoding="utf-8")
    with BrowserSession() as browser:
        browser.page.goto(html_path.as_uri(), wait_until="networkidle")
        browser.page.pdf(
            path=str(OUT / "点击劫持项目最终报告.pdf"),
            format="A4",
            print_background=True,
            display_header_footer=True,
            header_template="<span></span>",
            footer_template='<div style="font-size:9px;width:100%;text-align:center;color:#58677d">WebSec 1.0.0 · <span class="pageNumber"></span> / <span class="totalPages"></span></div>',
        )
    print(report)


if __name__ == "__main__":
    main()
