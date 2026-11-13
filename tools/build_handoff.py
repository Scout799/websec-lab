"""Create presentation notes, runbook and editable SVG engineering diagrams."""

# ruff: noqa: E501

import html
import json
import shutil
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "deliverables"
NS = {"a": "http://schemas.openxmlformats.org/drawingml/2006/main"}


def diagrams():
    def svg(title, boxes, edges):
        content = [
            '<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="760" viewBox="0 0 1280 760"><defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10Z" fill="#58677d"/></marker></defs><rect width="1280" height="760" fill="#f8fafc"/>',
            f'<text x="55" y="67" font-family="Microsoft YaHei,sans-serif" font-size="34" font-weight="bold" fill="#10233f">{html.escape(title)}</text>',
        ]
        for x1, y1, x2, y2, label in edges:
            content.append(
                f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#58677d" stroke-width="2" marker-end="url(#arrow)"/>'
            )
            if label:
                content.append(
                    f'<text x="{(x1+x2)/2+7}" y="{(y1+y2)/2-7}" font-family="Microsoft YaHei,sans-serif" font-size="18" fill="#58677d">{html.escape(label)}</text>'
                )
        for x, y, w, h, text, fill in boxes:
            content.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}"/>')
            for i, line in enumerate(text.split("\n")):
                content.append(
                    f'<text x="{x+18}" y="{y+34+i*31}" font-family="Microsoft YaHei,sans-serif" font-size="23" fill="white">{html.escape(line)}</text>'
                )
        return "\n".join(content) + "</svg>"

    blue, navy, orange = "#2563eb", "#10233f", "#d95c37"
    definitions = {
        "architecture": (
            "五域 HTTPS 与四服务架构",
            [
                (
                    55,
                    125,
                    1170,
                    85,
                    "独立实验浏览器：victim / same.victim / attacker / partner / audit.test",
                    navy,
                ),
                (400, 280, 480, 85, "Nginx :8443 · SAN + CA + SNI", blue),
                (55, 440, 260, 100, "Victim :15100\n会话 / 转账 / 授权", blue),
                (355, 440, 260, 100, "Attacker :15200\n覆盖 / 裁剪 / 窗口", orange),
                (655, 440, 260, 100, "Partner :15300\n合法组件 / 支付", blue),
                (955, 440, 270, 100, "Auditor :15400\n静态 / 动态 / 报告", navy),
                (55, 635, 400, 80, "SQLite 状态与独立重置", navy),
                (700, 635, 525, 80, "实验编号 / CSP 与交互 / 原始证据", navy),
            ],
            [
                (640, 210, 640, 280, "TLS"),
                (530, 365, 185, 440, ""),
                (600, 365, 485, 440, ""),
                (680, 365, 785, 440, ""),
                (750, 365, 1090, 440, ""),
                (185, 540, 255, 635, "业务状态"),
                (1090, 540, 970, 635, "审计证据"),
                (315, 490, 700, 635, "目标页信号"),
            ],
        ),
        "attack-flow": (
            "一次诱导点击如何形成业务影响",
            [
                (60, 180, 250, 105, "受害者访问诱导页\n看到奖励按钮", blue),
                (365, 180, 250, 105, "目标 iframe 覆盖\n控件位于同一坐标", orange),
                (670, 180, 250, 105, "真实点击目标控件\n提交其合法表单", blue),
                (975, 180, 250, 105, "服务器检查条件\n写入模拟交易", navy),
                (
                    165,
                    440,
                    420,
                    125,
                    "可见：诱导奖励\n实际：确认向 bob 转账\n浏览器代用户携带会话",
                    orange,
                ),
                (690, 440, 490, 125, "独立核对：交易 +1\n余额 -123 分\n多步骤还需核对授权", navy),
            ],
            [
                (310, 232, 365, 232, ""),
                (615, 232, 670, 232, ""),
                (920, 232, 975, 232, ""),
                (490, 285, 375, 440, ""),
                (1100, 285, 940, 440, ""),
            ],
        ),
        "defense-decision": (
            "分层评估与结果判定",
            [
                (60, 145, 310, 90, "框架：来源是否允许？", blue),
                (60, 300, 310, 90, "会话：身份是否有效？", blue),
                (60, 455, 310, 90, "业务：确认条件满足？", blue),
                (60, 620, 310, 80, "服务端状态有变化？", navy),
                (690, 145, 510, 90, "拒绝嵌入；记录浏览器阻断依据", orange),
                (690, 300, 510, 90, "无有效会话；检查登录页与 Cookie", orange),
                (690, 455, 510, 90, "未完成操作；核对具体交互预算", orange),
                (690, 620, 510, 80, "状态证明影响；信号单独评价", navy),
            ],
            [
                (215, 235, 215, 300, "是"),
                (215, 390, 215, 455, "是"),
                (215, 545, 215, 620, "是"),
                (370, 190, 690, 190, "否"),
                (370, 345, 690, 345, "否"),
                (370, 500, 690, 500, "否"),
                (370, 660, 690, 660, ""),
            ],
        ),
    }
    for name, args in definitions.items():
        (OUT / "figures" / f"{name}.svg").write_text(svg(*args), encoding="utf-8")


def main():
    OUT.mkdir(exist_ok=True)
    (OUT / "figures").mkdir(exist_ok=True)
    diagrams()
    pptx = OUT / "点击劫持项目答辩.pptx"
    rows = []
    with zipfile.ZipFile(pptx) as package:
        for number in range(1, 21):
            slide = ET.fromstring(package.read(f"ppt/slides/slide{number}.xml"))
            title = next(slide.iterfind(".//a:t", NS)).text
            note = ET.fromstring(package.read(f"ppt/notesSlides/notesSlide{number}.xml"))
            content = " ".join(t.text or "" for t in note.iterfind(".//a:t", NS))
            member = (
                "成员一"
                if number <= 6
                else "成员二" if number <= 11 else "成员三" if number <= 18 else "共同"
            )
            rows.append(f"### 第 {number} 页：{title}（{member}）\n\n{content}\n")
    guide = """# 三人汇报与操作手册

版本 1.0.0，2026-11-07。姓名在确定汇报顺序后替换“成员一/二/三”。工程已经统一完成，以下按讲解内容划分，每位成员都应能解释证据与演示结果。

## 汇报安排

| 成员 | PPT | 建议时间 | 需要掌握的代码与证据 |
| --- | --- | --- | --- |
| 一 | 1–6 | 约 5 分钟，含攻击演示 | attacker 场景、dynamic/runner.py、服务端转账和授权状态、窗口输入模型 |
| 二 | 7–11 | 约 5 分钟，含防御切换 | defense.yaml、defense/profiles.py、SameSite 96 例、合法组件结果 |
| 三 | 12–18 | 约 6 分钟，含审计结果 | auditor/report.py、victim/telemetry.py、954 例与消融、Docker/复核 |
| 共同 | 19–20 | 约 1 分钟 | 成果、结论与交接 |

预留 2–3 分钟问答，总计约 20 分钟。若限时 10 分钟，保留 1、3、4、5、7、9、11、12、14、16、20 页，现场演示换成已录制视频中的对应片段。

## 演示前检查

1. 进入解压后的工程目录，激活 Conda Websec，执行 `websec-lab doctor`。
2. 确认 8443 和 15100–15400 未被其他实验占用。停止本项目已有手动服务，不关闭无关程序。
3. 原生启动 `python -m websec_lab.https_lab start --profile https-samesite-none`，再执行 status。
4. 用 `python -m websec_lab.https_lab browser --browser chrome` 打开独立浏览器，确认无证书错误。
5. 准备 PPT、PDF、视频与一份 HTML 审计报告，断网时也可阅读。

## 现场演示脚本

### 成员一：点击由谁接收

在 victim.test 登录 alice / alice-lab，记录余额。打开 attacker.test 首页，选择透明覆盖，点击奖励。切回银行交易历史，说明页面上看见的是诱导控件，而鼠标命中透明目标框架中的银行确认按钮。浏览器并未把事件转发到另一网站；目标控件本来就在相同屏幕位置。

打开调试透明度只为说明层叠位置，再恢复默认透明效果。展示一例 result.json 的 transfers_delta=1、balance_cents_delta=-123。多步骤必须同时讲授权和转账。窗口扩展说明两次输入由浏览器坐标协议发送，不宣称已验证任意系统全局硬件双击。

### 成员二：防御与合法功能

执行 stop，再 start --profile csp-none，重新登录并刷新诱导页。重复点击，查看浏览器阻断与无新增交易。随后切换 https-partner-allowlist，展示诱导来源仍被拒绝，而 partner.test/payment 明确标明收款人和金额，合法支付能执行。

解释 CSP 的来源白名单与 SameSite 的站点关系：same.victim.test 同站不同源，Strict/Lax 仍可能发送会话；attacker.test 跨站 iframe 不满足 Lax/Strict。精确白名单只控制嵌入，组件能否登录还取决于 Cookie 与用户的第三方 Cookie 设置。

### 成员三：审计与结果

按 README 的 audit-report 命令使用 --click --signals，打开生成 HTML。依次指出静态嵌入预测、实际浏览器文档/阻断、业务前后状态、原始双通道事件。说明 954 个用例执行通过不等于 954 次攻击成功。

演示 data/summary.json 与 channel-ablation 图。融合标记 657/891 个攻击尝试，覆盖成功攻击 414/459，正常误报 10/27。明确嵌入支付 9/9 被规则标记，窗口攻击成功也可能没有任何通道命中，不能用业务成功反向制造信号。

## 备用视频

video/点击劫持攻防演示.mp4 为实际 HTTPS 浏览器录制，内嵌中文字幕、无配音。依次展示无框架限制、CSP 拒绝和精确合作方白名单。video/chapter-*/verification.json 保存前后状态；画面中的解释条只用于说明，不执行或伪造目标业务。播放时由对应成员讲解。

## 两次彩排

已执行的脚本 `scripts/rehearse_demo.py` 包含 Chrome 与 Firefox 两轮自动系统演练，各依次完成易受攻击、阻断和合作方检查，记录在 artifacts/finalization/rehearsals/summary.json。它没有替三位同学完成口头彩排。

第一次人工彩排按页计时，逐个回答“这项结果由哪个字段证明”，记录含糊表述。第二次人工彩排模拟现场失败，用视频和离线报告继续讲解，每位成员回答一题来自其他模块的问题。完成后由小组在下方自行记录实际日期。

- 人工彩排一：待小组记录。
- 人工彩排二：待小组记录。

## 常见问题与答题证据

| 问题 | 回答与证据 |
| --- | --- |
| 为什么用户点的是攻击页面？ | 用户受骗访问诱导页，实际接收点击的是覆盖的目标 iframe 控件；看见什么和命中什么分离。见攻击流程图和视频。 |
| 同源策略为什么没挡住？ | 它限制跨源读取 DOM，不禁止嵌入后由用户直接点击目标控件。攻击脚本未读取目标 DOM。 |
| 与 CSRF 的差别？ | 此处用户点击目标站点自己的合法表单，可携带有效令牌。一次性令牌对照仍可能转账，见 confirm-token。 |
| iframe load 能证明安全吗？ | 不能，阻断或错误文档也可能触发；需要实际文档响应、阻断信息和业务状态。 |
| 有 CSP 就一定拦住？ | 取决于 enforcing、指令和值及真实来源；Report-Only 不阻断，错误白名单可放行。 |
| XFO 与 CSP 冲突谁生效？ | 以有效 enforcing frame-ancestors 与实际浏览器执行为依据。正式 xfo-csp-conflict 配置允许 HTTPS 诱导来源，尽管 XFO DENY，仍能完成操作。 |
| SameSite 与 SameOrigin 一样吗？ | 不同。协议和可注册域决定此实验站点关系，源还包含完整主机和端口。见五域表及 96 例专项。 |
| HttpOnly 能防点击劫持吗？ | 它限制脚本读 Cookie；浏览器仍可自动携带会话。 |
| 二次确认为什么有效？ | 在本轮固定输入预算下增加了未满足的业务步骤；不能说任意多次诱导都被彻底解决。 |
| reauth 为什么仍然成功？ | 本轮刚完成有效登录，重新认证窗口条件已满足。不能把“配置了 reauth”误写成每次强制重新输入密码。 |
| 静态动态一致 100% 是检测准确率吗？ | 是 873 个具有双方结论的可嵌入性检查，不是意图识别率，也不包含窗口路径。 |
| 双通道融合是不是更准确？ | 本轮扩大尝试覆盖，但成功攻击覆盖未超出交互通道，误报仍为 10/27。见三种分母的消融表。 |
| 为什么合法支付也报警？ | 当前规则标记嵌入中的敏感点击，无法独立知道用户意图；9/9 合法嵌入对照刻画这一边界。 |
| 为什么窗口攻击没有报告？ | frame-ancestors 约束框架，顶层窗口不一定产生 CSP 报告；无界面焦点事件也可能不出现。 |
| 是否实现新的 DoubleClickjacking？ | 实现了受控窗口连续点击扩展，明确输入模型；没有宣称新的攻击原理或任意 OS 全局复现。 |
| 为什么需要 HTTPS？ | Secure、None Cookie 以及可信会话对照需要真实 TLS；本项目不关闭证书校验。 |
| 为什么主实验和专项要分开？ | 主实验控制同站会话条件，专项改变跨站与第三方 Cookie 设置，研究变量和分母不同。 |
| 如何保证数字未挑选？ | 保留首次 945 例、18 例修复复测、9 个正常支付、54 例配置复测；按 case_id 合并，来源哈希与替换原因公开。 |
| 什么是创新点？ | 课程成果是证据链、平台和系统对照；不把集成现有机制写成学术首创。 |
| 是否真的在 Linux 跑过？ | 看 artifacts/finalization/linux-* 验收日志；CI 配置文件不能代替真实执行结果。 |

## 故障恢复

- 域名打不开：使用独立实验浏览器，检查 status；普通浏览器没有本机 `.test` 映射。
- 证书错误：检查当前机器生成的 CA 和系统时钟，重新按 README 初始化信任，保留正常 TLS 校验。
- 登录页替代组件：检查 SameSite、Secure 与第三方 Cookie 设置，区分 framing 允许和组件可用。
- 页面改变未生效：停止并启动对应 profile，重新登录和刷新目标与诱导页。
- 端口冲突：先停止本项目已启动服务，确认占用归属；不要关闭其他项目的进程。
- 现场环境故障：播放离线视频，打开已生成 HTML 和逐例业务状态继续说明。

## 逐页讲稿

"""
    (OUT / "三人汇报与操作手册.md").write_text(guide + "\n".join(rows), encoding="utf-8")
    (OUT / "验收记录").mkdir(exist_ok=True)
    for filename in [
        "dependency-licenses.json",
        "pytest-final.log",
        "pytest-final.xml",
        "clean-install-smoke.json",
    ]:
        shutil.copy2(ROOT / "artifacts/finalization" / filename, OUT / "验收记录" / filename)
    (OUT / "data/presentation-contents.json").write_text(
        json.dumps(
            {"slides": 20, "speaker_notes": 20, "editable_charts": 1, "editable_tables": 7},
            indent=2,
        ),
        encoding="utf-8",
    )
    print(OUT / "三人汇报与操作手册.md")


if __name__ == "__main__":
    main()
