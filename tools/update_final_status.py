"""Write final acceptance documents from completed machine-readable checks."""

# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "deliverables"
FINAL = ROOT / "artifacts/finalization"


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def tests(path):
    root = ET.parse(path).getroot()
    suites = list(root.iter("testsuite"))
    result = {
        k: sum(int(s.get(k, 0)) for s in suites) for k in ("tests", "failures", "errors", "skipped")
    }
    result["passed"] = result["failures"] == result["errors"] == 0
    return result


def smoke(path):
    text = path.read_text(encoding="utf-8-sig")
    assert "Healthy" in text, path
    lines = [line for line in text.splitlines() if line.startswith('{"gateway_hosts"')]
    result = json.loads(lines[-1])
    assert result["gateway_hosts"] == 5
    assert result["attack"] == "protected" and result["partner"] == "embeddable"
    return result


def main():
    summary = read(ROOT / "artifacts/final-results/summary.json")
    assert summary["rows"] == 954 and summary["failed"] == 0
    matrix = read(ROOT / "artifacts/final-results/verification.json")
    same = read(ROOT / "artifacts/samesite-https/verification.json")
    clean = read(FINAL / "clean-install-smoke.json")
    ui = read(FINAL / "manual-ui/summary.json")
    rehearsals = read(FINAL / "rehearsals/summary.json")
    pdf = read(FINAL / "pdf-validation.json")
    video = read(FINAL / "video-validation.json")
    deck = read(FINAL / "presentation-validation.json")
    assert deck["firstPartyImport"]["passed"]
    assert (
        hashlib.sha256((OUT / "点击劫持项目答辩.pptx").read_bytes()).hexdigest()
        == deck["finalSha256"]
    )
    assert (
        hashlib.sha256((OUT / "点击劫持项目最终报告.pdf").read_bytes()).hexdigest() == pdf["sha256"]
    )
    assert (
        hashlib.sha256((OUT / "video/点击劫持攻防演示.mp4").read_bytes()).hexdigest()
        == video["sha256"]
    )
    windows_tests = tests(FINAL / "pytest-final.xml")
    linux_tests = tests(FINAL / "linux-pytest.xml")
    linux_smoke = smoke(FINAL / "linux-smoke-cookie-fixed.log")
    fresh = smoke(FINAL / "linux-from-zero.log")
    before, after = read(FINAL / "linux-ca-before.json"), read(FINAL / "linux-ca-after.json")
    assert before["root_sha256"] != after["root_sha256"]
    assert all(
        x["passed"]
        for x in [matrix, same, clean, ui, rehearsals, windows_tests, linux_tests, pdf, video]
    )
    assert matrix["cases"] == 954 and same["rows_verified"] == 96
    acceptance = dict(
        passed=True,
        date="2026-11-07",
        project_version="1.0.0",
        windows_tests=windows_tests,
        linux_nonbrowser_tests=linux_tests,
        main_matrix=954,
        samesite=96,
        ui_cases=len(ui["cases"]),
        system_rehearsals=2,
        clean_install=True,
        linux_smoke=linux_smoke,
        linux_from_zero=fresh,
        fresh_ca_verified=True,
        presentation_slides=20,
        report_pages=pdf["pages"],
        video_seconds=video["duration_seconds"],
        human_rehearsals_completed=False,
        remote_ci_executed=False,
    )
    (FINAL / "acceptance.json").write_text(
        json.dumps(acceptance, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    linux_n = linux_tests["tests"]
    status = f"""# 最终工程状态

更新：2026-11-07，版本 1.0.0。本次核心工程、正式实验、复现验收和答辩交付已完成。

| 项目 | 验收结果 | 证据 |
| --- | --- | --- |
| Windows 全量 pytest | {windows_tests['tests']} 项，失败 0、错误 0、跳过 {windows_tests['skipped']} | artifacts/finalization/pytest-final.xml |
| Linux 非浏览器测试 | {linux_n} 项，失败 0、错误 0、跳过 {linux_tests['skipped']} | artifacts/finalization/linux-pytest.xml |
| Ruff / Black | 通过 | artifacts/finalization/quality.log |
| 正式主实验与对照 | 954 个唯一用例，全部通过独立复核 | artifacts/final-results/verification.json |
| SameSite 跨站专项 | 96 个用例、384 张截图，复核通过 | artifacts/samesite-https/verification.json |
| 手动场景 UI | 三浏览器默认参数与缩放共 12 例通过 | artifacts/finalization/manual-ui/summary.json |
| 系统演练 | Chrome / Firefox 两轮通过 | artifacts/finalization/rehearsals/summary.json |
| 清洁 Windows 环境 | 精确依赖、wheel 安装与四服务页面通过 | artifacts/finalization/clean-install-smoke.json |
| Linux Docker | 健康、五域 TLS、真实 Chromium、诱导阻断、合法组件通过 | artifacts/finalization/linux-smoke-cookie-fixed.log |
| Linux 从零运行状态 | 新建卷生成新 CA，再次通过烟雾 | artifacts/finalization/linux-from-zero.log |
| 报告与 PPT | 12 页 PDF、Markdown/HTML、20 页可编辑 PPT，渲染检查通过 | deliverables/ |
| 视频与小组材料 | 1280×900，约 97 秒；讲稿、问答、操作手册与图表 | deliverables/ |

正式矩阵覆盖28配置、3种浏览器和3次重复，含837个iframe攻击、54个窗口路径、36个合法组件检查、27个正常交互。执行通过表示流程和证据成立，不表示攻击成功。原始首轮945例、18例判定修复复测、9例支付对照、54例HTTPS来源修正复测均保留，最终按case_id合并。

双通道融合标记657/891个攻击尝试，覆盖产生业务变化的攻击414/459个，正常对照误报10/27。合法支付与窗口无信号路径保留在结果中。静态/动态一致873/873仅对应具有双方结论的嵌入检查。

Windows最终恢复https-samesite-lax手动环境，五域均200。更换演示配置先stop再start。发布包附SHA-256文件清单，排除本机私钥、数据库、浏览器配置和验证虚拟磁盘。

人工答辩彩排与姓名确认由小组进行；自动系统演练没有代替人工作答。CI已配置但未发布仓库或触发远程执行。历史Backlog中的拖拽攻击、上游解析器对比、Web控制台及历史回放属于未纳入本次交付的可选扩展，不计入已完成成果。

材料入口：[最终报告](../deliverables/点击劫持项目最终报告.md)、[答辩PPT](../deliverables/点击劫持项目答辩.pptx)、[小组手册](../deliverables/三人汇报与操作手册.md)、[详细改动记录](finalization-ledger.md)。
"""
    (ROOT / "docs/status.md").write_text(status, encoding="utf-8")
    ledger = """# 本轮收尾改动与验收

2026-11-07，版本1.0.0。

## 审计与攻击判定

- 新增受控本地HTTPS传输适配器，TCP回环连接保留Host、SNI、CA与主机名校验；修正相对重定向的目标检查。
- 通用CLI接入HTTPS和真实探针来源；覆盖、裁剪、多步骤按场景真正执行，多步骤分别核对授权和转账。
- 浏览器坐标点击完成攻击，独立测试API核对交易、授权和余额；框架加载与业务影响分别判定。
- frame-busting导航移除诱导界面时停止点击，保存该结果。最初18例报错保留，受影响的Chrome/Edge复测18/18通过。
- 两种错误白名单配置补齐实际HTTPS攻击来源，完整复测54/54通过，显示有效CSP与XFO冲突的真实行为。
- 公开场景默认透明度改为0.01，参数表步进与经典演示同步；三浏览器默认覆盖、裁剪、多步骤及缩放12例通过。

## 观察信号与对照

- 增加CSP报告接收、目标交互上报与实验编号/路径/时间关联；限制输入大小、事件类型并隔离本地读取令牌。
- 修复控件focus被当成窗口focus的问题。检测规则不读取攻击标签或业务成功结果。
- 增加受控双窗口连续点击，保存输入间隔与前后截图；明确浏览器坐标协议的输入模型。
- 增加合作方明确支付页面与9例正常嵌入对照。保留交互误报9/9与快速切窗误报1/9，共10/27；窗口成功也可能无信号。
- 最终954例逐例校验唯一矩阵、原始JSON/CSV、业务增量、信号规则和2745张截图；另保留96例SameSite专项和384张截图。

## 部署与环境

- 版本统一1.0.0，修复wheel中的页面/静态资源打包；精确锁定69项依赖，清洁Windows venv安装实际wheel并通过四服务页面与健康检查。
- 增加固定基础镜像摘要的Dockerfile、Compose命名卷、非root用户与CI工作流。
- Linux实际验证发现并修复三项问题：健康检查全应用导入导致超时和残留进程；Nginx系统临时目录不可写；Chromium无痕上下文的第三方Cookie默认值覆盖CDP条件。
- 健康检查改用标准库TLS并使用exec形式；Nginx临时路径放到自有可写目录；Linux HTTPS审计使用每次独立、结束清理的普通配置，显式设定第三方Cookie条件，保留正常TLS校验。
- Linux在独立QEMU/Alpine中的真实Docker执行，包含启动、浏览器烟雾、非浏览器测试及新卷/新CA复现；未宣称远端CI已执行。

## 成果交付

- 最终报告从已复核数据生成，删除中期20例基线的过时总体结论；输出Markdown、HTML与12页PDF，Poppler逐页渲染检查并修复大图导致的空白分页。
- 20页PPT包含7张原生可编辑表格、1张原生图表及20页讲者备注。结构、几何、字体声明与再导入检查通过；最终文件20页渲染与已逐页查看的候选图像逐像素一致。没有宣称在PowerPoint桌面程序中检查过。
- 实际浏览器录制三段攻防/兼容性演示，输出约97秒1280×900 MP4；每段实际业务增量保存为JSON。
- 补齐三人讲稿、操作步骤、故障恢复与20道问答；Chrome/Firefox两轮自动流程通过，人工彩排留给小组。
- 生成SVG架构、攻击流程和防御判定图，保留独立PNG/SVG统计图；增加许可证清单、MIT源码声明、审查与Issue模板。
- 发布包保留原始失败与复测，文件清单逐项SHA-256校验，ZIP逐项读取与CRC检查；不包含用户原始报告、对话记录、私钥、浏览器个人资料或Linux验证磁盘。

机器验收见`artifacts/finalization/acceptance.json`，全部证据路径见`docs/status.md`与README。Git原有暂存、未暂存及未跟踪文件保留，不自动提交、打标签或发布。
"""
    (ROOT / "docs/finalization-ledger.md").write_text(ledger, encoding="utf-8")
    environment = read(FINAL / "windows-environment.json")
    manifest = "# 版本与验收清单\n\n2026-11-07，工程1.0.0。发布以文件SHA-256标识，不表示已创建Git标签。\n\n"
    manifest += "| 组件 | 验证值 |\n| --- | --- |\n"
    manifest += f"| Windows | {environment['platform']} |\n| Python | {environment['python']} |\n"
    manifest += "\n".join(
        f"| {name} | {value} |" for name, value in environment["packages"].items()
    )
    manifest += "\n\n浏览器：Chrome156.0.8078.80，Edge156.0.4314.58，Playwright Firefox157.0。Windows Nginx1.30.6；Linux实际网关版本见linux-ca-after.json，Chromium版本见Linux烟雾JSON。Python完整依赖见requirements.lock。\n\n本地验收结果见status.md。CI已配置，远程运行未执行；报告/PPT制作工具不是服务启动依赖。\n"
    (ROOT / "docs/version-manifest.md").write_text(manifest, encoding="utf-8")
    task_path = ROOT / "PROJECT_TASKS.md"
    task_text = task_path.read_text(encoding="utf-8")
    completed = {
        "T0105",
        "T0111",
        "T0112",
        "T0308",
        "T0310",
        "T0403",
        "T0519",
        "T0916",
        "T1008",
        "T1009",
        "T1011",
        "T1115",
    }
    completed.update(f"T11{number:02}" for number in range(1, 14))
    descriptions = {
        "T0310": "- [x] **T0310｜P2｜成员 A｜L**：受控双窗口连续点击扩展，54例，保留输入模型与边界。",
        "T0403": "- [x] **T0403｜P1｜成员 A｜M**：合法嵌入支付确认组件及9例正常敏感交互对照。",
        "T0519": "- [x] **T0519｜P2｜成员 B｜M**：窗口路径中的COOP对照，实际结果与截图已保留。",
        "T1010": "- [x] **T1010｜P0｜共同｜S**：生成1.0.0版本和SHA-256发布标识；未创建Git标签。",
        "T1006": "- [ ] **T1006｜P1｜成员 C｜M**：远程CI静态/单元检查（工作流已配置，本地等效检查通过，未触发远程运行）。",
        "T1007": "- [ ] **T1007｜P1｜成员 C｜L**：远程CI浏览器烟雾（已配置Docker任务，本地真实Linux Chromium通过，未触发远程运行）。",
        "T1114": "- [ ] **T1114｜P0｜共同｜M**：两次人工答辩彩排；已有两轮自动系统演练，未代替小组口头彩排。",
    }
    lines = []
    for line in task_text.splitlines():
        matched = re.search(r"\*\*(T\d{4})", line)
        if matched:
            task = matched.group(1)
            line = descriptions.get(
                task, line.replace("- [ ]", "- [x]", 1) if task in completed else line
            )
        if line.startswith("> 当前执行方式"):
            line = "> 2026-11-07：核心工程、实验与交付完成，验收见 docs/status.md；汇报分工见 deliverables/三人汇报与操作手册.md。可选扩展与人工彩排保留独立状态。"
        if line.startswith("第一轮工程工作从"):
            line = "工程收尾已完成。小组下一步确认姓名、熟悉证据并完成人工彩排。未纳入本期的P1/P2想法不计入交付完成声明。"
        lines.append(line)
    task_text = "\n".join(lines) + "\n"
    task_text = task_text.replace("mkcert 或自签名证书", "OpenSSL 本地CA、SAN证书与正常信任")
    task_text = task_text.replace("pandas、Matplotlib、Seaborn", "JSON/CSV、NumPy、Matplotlib")
    task_text = task_text.replace("1350 次自动化实验", "954例主实验与对照，另96例SameSite专项")
    task_path.write_text(task_text, encoding="utf-8")
    handoff = OUT / "项目交付说明.md"
    handoff.write_text(
        """# 点击劫持项目交付

先阅读根目录README和本目录《三人汇报与操作手册》。报告提供Markdown、HTML、PDF；答辩PPT可编辑并有逐页备注；video目录为实际浏览器演示。

954例主实验与96例SameSite专项均已独立复核。原始数据位于artifacts，最终汇总为artifacts/final-results。验收记录含Windows、Linux、清洁安装与材料校验。

发布ZIP解压后即为工程根目录，保持config、src、scripts、docs、artifacts与deliverables的相对位置。按README创建Websec或使用Docker；新机器生成自己的CA。FILE_MANIFEST.json与SHA256SUMS.txt包含逐文件哈希，发布ZIP自身哈希单独存放。

三位同学需要确认姓名、按讲稿熟悉代码与证据，并完成人工彩排。自动演练记录不代表已经完成口头答辩。工程没有自动提交或发布Git，远程CI未运行。
""",
        encoding="utf-8",
    )
    receipts = OUT / "验收记录"
    receipts.mkdir(exist_ok=True)
    for name in [
        "acceptance.json",
        "linux-pytest.xml",
        "linux-from-zero.log",
        "linux-smoke-cookie-fixed.log",
        "linux-ca-after.json",
        "pytest-final.xml",
        "pytest-final.log",
        "quality.log",
        "clean-install-smoke.json",
        "presentation-validation.json",
        "presentation-render-comparison.json",
    ]:
        shutil.copy2(FINAL / name, receipts / name)
    print(json.dumps(acceptance, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
