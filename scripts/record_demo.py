"""Record actual HTTPS browser interactions and encode a captioned demonstration."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote

import imageio_ffmpeg

from websec_lab.auditor.dynamic.session import BrowserSession
from websec_lab.experiments.final_matrix import VICTIM, state
from websec_lab.https_lab import HttpsLab
from websec_lab.transport import lab_session

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "deliverables/video"


def caption(page, text):
    page.evaluate(
        """text => { let el=document.getElementById('demo-caption');
        if(!el){el=document.createElement('div');el.id='demo-caption';document.body.append(el);}
        el.textContent=text;Object.assign(el.style,{position:'fixed',top:'12px',left:'24px',
        right:'24px',padding:'18px',background:'#10233fee',color:'white',border:'1px solid #648bc6',
        font:'22px Microsoft YaHei,sans-serif',zIndex:2147483647,whiteSpace:'pre-line',
        pointerEvents:'none',lineHeight:'1.6'}); }""",
        text,
    )


def chapter(profile, title, directory, partner=False):
    clips = []
    with tempfile.TemporaryDirectory(prefix="websec-video-") as tmp:  # noqa: SIM117
        with HttpsLab(profile, Path(tmp) / "demo.sqlite3"), lab_session() as session:
            with BrowserSession(https_lab=True, record_video_dir=directory) as browser:
                page = browser.page
                page.set_content(
                    "<html lang='zh-CN'><body style='background:#10233f'></body></html>"
                )
                caption(page, title + "\n本机虚构账户与金额；浏览器 TLS 验证开启")
                page.wait_for_timeout(4500)
                page.goto(VICTIM + "/login", wait_until="load")
                page.get_by_label("用户名").fill("alice")
                page.get_by_label("密码").fill("alice-lab")
                page.get_by_role("button", name="登录").click()
                page.get_by_role("heading", name="你好，alice").wait_for()
                caption(page, "受害者已登录银行。随后访问诱导页面，身份仍由浏览器管理。")
                page.wait_for_timeout(4500)
                before = state(session)
                target = VICTIM + "/lab/quick-transfer"
                page.goto(
                    "https://attacker.test:8443/probe/embed?target="
                    + quote(target)
                    + "&variant=overlay&opacity=0.01",
                    wait_until="load",
                )
                caption(
                    page,
                    "页面显示“立即领取”。透明 iframe 位于按钮上方。\n"
                    "鼠标按页面坐标点击，未调用目标表单的 DOM click。",
                )
                page.wait_for_timeout(5500)
                box = page.locator("#decoy-button").bounding_box()
                page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2, steps=20)
                page.wait_for_timeout(1800)
                page.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
                page.wait_for_timeout(1500)
                after = state(session)
                delta = {key: after[key] - before[key] for key in before}
                expected = 1 if profile == "https-samesite-none" else 0
                assert delta["transfers"] == expected and delta["balance_cents"] == -123 * expected
                caption(
                    page,
                    f"{title}\n服务端核对：新增转账 {delta['transfers']} 笔；"
                    f"余额变化 {delta['balance_cents']} 分。",
                )
                page.screenshot(path=str(directory / "attack-result.png"))
                page.wait_for_timeout(6500)
                if partner:
                    page.goto("https://partner.test:8443/payment", wait_until="load")
                    caption(
                        page,
                        "同一白名单配置允许 partner.test 合法嵌入。\n"
                        "页面明确显示收款人 bob 和金额 ¥1.23。",
                    )
                    page.wait_for_timeout(5500)
                    normal_before = state(session)
                    page.frame_locator("#payment-component").locator(
                        ".quick-card input[type=submit]"
                    ).click()
                    page.wait_for_timeout(1500)
                    assert state(session)["transfers"] - normal_before["transfers"] == 1
                    caption(
                        page,
                        "合法合作方中的明确支付操作执行成功。\n嵌入权限与会话条件共同决定功能是否可用。",
                    )
                    page.screenshot(path=str(directory / "partner-result.png"))
                    page.wait_for_timeout(6500)
                video = page.video
                browser.context.close()
                clips.append(video.path())
                (directory / "verification.json").write_text(
                    json.dumps(
                        dict(profile=profile, before=before, after=after, delta=delta, passed=True),
                        indent=2,
                    ),
                    encoding="utf-8",
                )
    return clips


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    clips = []
    for index, (profile, title) in enumerate(
        [
            ("https-samesite-none", "实验一：无框架限制，点击触发模拟转账"),
            ("csp-none", "实验二：CSP 拒绝嵌入，转账未发生"),
            ("https-partner-allowlist", "实验三：精确白名单拒绝诱导来源，允许合法合作方"),
        ],
        1,
    ):
        directory = OUT / f"chapter-{index}"
        directory.mkdir(exist_ok=True)
        clips.extend(chapter(profile, title, directory, partner=index == 3))
    playlist = OUT / "concat.txt"
    playlist.write_text(
        "\n".join("file '" + str(p).replace("\\", "/").replace("'", "'\\''") + "'" for p in clips),
        encoding="utf-8",
    )
    output = OUT / "点击劫持攻防演示.mp4"
    subprocess.run(
        [
            imageio_ffmpeg.get_ffmpeg_exe(),
            "-y",
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            str(playlist),
            "-c:v",
            "libx264",
            "-crf",
            "22",
            "-pix_fmt",
            "yuv420p",
            "-movflags",
            "+faststart",
            str(output),
        ],
        check=True,
        capture_output=True,
    )
    assert output.stat().st_size > 100000
    print(output)


if __name__ == "__main__":
    main()
