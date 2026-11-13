"""Record a narrated, interaction-visible browser demo video of the project.

Everything runs in-process (victim + attacker + auditor harness), and the
recording emphasizes the interaction itself: a visible synthetic cursor
with click ripples (headless recordings have no OS cursor), character-by-
character typing, slow deliberate mouse movement and readable pacing.

Usage:
    python scripts/record_demo_video.py [--out artifacts/demo-video]
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import Browser, BrowserContext, Locator, Page

from websec_lab.auditor.dynamic import LoginConfig, StateCheckConfig
from websec_lab.auditor.report import run_combined_audit, write_html_report
from websec_lab.browser import discover_browsers

sys.path.insert(0, str(Path(__file__).resolve().parent))
from m3_smoke import LabServers  # noqa: E402

VIDEO_WIDTH, VIDEO_HEIGHT = 1280, 800

# Injected into every page: a visible cursor that tracks mousemove plus a
# red ripple animation on every click, so viewers can follow each action.
CURSOR_INIT_SCRIPT = """
(() => {
  if (window.__demoCursorInstalled) return;
  window.__demoCursorInstalled = true;
  const style = document.createElement('style');
  style.textContent = `
    #demo-cursor { position: fixed; left: -100px; top: -100px; z-index: 2147483647;
      pointer-events: none; width: 26px; height: 26px;
      transition: left .07s linear, top .07s linear; }
    #demo-cursor svg { width: 100%; height: 100%;
      filter: drop-shadow(0 2px 5px rgba(0,0,0,.55)); }
    .demo-click-ripple { position: fixed; z-index: 2147483646; pointer-events: none;
      width: 52px; height: 52px; border-radius: 50%; border: 4px solid #ff4d4f;
      transform: translate(-50%, -50%); animation: demo-ripple .65s ease-out forwards; }
    @keyframes demo-ripple {
      from { opacity: 1; transform: translate(-50%,-50%) scale(.35); }
      to   { opacity: 0; transform: translate(-50%,-50%) scale(1.5); } }
  `;
  document.addEventListener('DOMContentLoaded', () => {
    document.documentElement.appendChild(style);
    const cursor = document.createElement('div');
    cursor.id = 'demo-cursor';
    cursor.innerHTML = '<svg viewBox="0 0 24 24"><path d="M4 2l15 8.6-6.4 1.6L9.5 20.4z"'
      + ' fill="#1a73e8" stroke="#ffffff" stroke-width="1.6" stroke-linejoin="round"/></svg>';
    document.documentElement.appendChild(cursor);
    const move = (e) => {
      cursor.style.left = e.clientX + 'px';
      cursor.style.top = e.clientY + 'px';
    };
    window.addEventListener('mousemove', move, true);
    window.addEventListener('pointerdown', (e) => {
      const ripple = document.createElement('div');
      ripple.className = 'demo-click-ripple';
      ripple.style.left = e.clientX + 'px';
      ripple.style.top = e.clientY + 'px';
      document.documentElement.appendChild(ripple);
      setTimeout(() => ripple.remove(), 750);
    }, true);
  });
})();
"""

TITLE_CSS = """
body { margin:0; height:100vh; display:flex; align-items:center; justify-content:center;
       background:#0d1524; color:#fff; font-family:"Segoe UI","Microsoft YaHei",sans-serif; }
.card { text-align:center; max-width: 900px; }
.eyebrow { color:#f0a23c; letter-spacing:.3em; font-size:15px; margin-bottom:16px; }
h1 { font-size:40px; margin:0 0 20px; }
p { color:#9fb0c8; font-size:19px; margin:0; line-height:1.9; }
"""


def title_card(page: Page, act: str, title: str, subtitle: str, dwell_ms: int = 3400) -> None:
    page.set_content(f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
        <style>{TITLE_CSS}</style></head><body><div class="card">
          <p class="eyebrow">{act}</p><h1>{title}</h1><p>{subtitle}</p>
        </div></body></html>""")
    page.wait_for_timeout(dwell_ms)


def slow_move(page: Page, x: float, y: float, steps: int = 24, per_step_ms: int = 16) -> None:
    """Move the mouse to (x, y) with visible, human-like interpolation."""

    current = page.evaluate("() => [0, 0]")  # no-op to keep evaluation warm
    del current
    page.mouse.move(x, y, steps=steps)
    for _ in range(steps):
        page.wait_for_timeout(per_step_ms)


def click_locator(page: Page, locator: Locator, hover_ms: int = 700) -> None:
    box = locator.bounding_box()
    assert box is not None, "locator has no box"
    target_x = box["x"] + box["width"] / 2
    target_y = box["y"] + box["height"] / 2
    page.mouse.move(target_x - 140, target_y - 90, steps=10)
    page.wait_for_timeout(150)
    page.mouse.move(target_x, target_y, steps=22)
    page.wait_for_timeout(hover_ms)
    page.mouse.click(target_x, target_y)
    page.wait_for_timeout(450)


def type_into(page: Page, locator: Locator, text: str, delay_ms: int = 110) -> None:
    click_locator(page, locator, hover_ms=350)
    locator.press_sequentially(text, delay=delay_ms)
    page.wait_for_timeout(350)


def record(browser: Browser, lab: LabServers, defended_origin: str, report_html: Path) -> Path:
    context: BrowserContext = browser.new_context(
        viewport={"width": VIDEO_WIDTH, "height": VIDEO_HEIGHT},
        record_video_dir=str(VIDEO_OUT_DIR),
        record_video_size={"width": VIDEO_WIDTH, "height": VIDEO_HEIGHT},
    )
    context.add_init_script(CURSOR_INIT_SCRIPT)
    page = context.new_page()
    page.set_default_timeout(20_000)

    # ---- Act 1: the victim bank (visible typing + clicking) ----
    title_card(
        page,
        "第一幕 · 攻击目标",
        "恒信银行（本地实验靶场）",
        "受害者 alice 正在登录网银 —— 注意：她只打开了银行自己的页面",
    )
    page.goto(f"{lab.victim_origin}/login", wait_until="domcontentloaded")
    page.wait_for_timeout(1200)
    type_into(page, page.get_by_label("用户名"), "alice")
    type_into(page, page.get_by_label("密码"), "alice-lab")
    click_locator(page, page.get_by_role("button", name="登录"))
    page.get_by_role("heading", name="你好，alice").wait_for()
    page.wait_for_timeout(2600)
    click_locator(page, page.get_by_role("link", name="交易记录"))
    page.wait_for_timeout(2600)

    # ---- Act 2: the attack, click by click ----
    title_card(
        page,
        "第二幕 · 点击劫持（无防御）",
        "一次“领奖品”的点击 = 一笔真实转账",
        "左：受害者看到的诱导页　右：victim 服务器上的账户实况与事件解说",
    )
    page.goto(f"{lab.attacker_origin}/demo/classic")
    page.wait_for_function(
        "document.getElementById('balance').textContent.includes('1000.00')", timeout=10_000
    )
    page.wait_for_timeout(2200)
    # 指针先扫过右侧账户区，再移向左侧诱导按钮——观众能看清"点的是哪里"
    right = page.locator(".account-card").bounding_box()
    if right:
        page.mouse.move(right["x"] + right["width"] / 2, right["y"] + 40, steps=14)
        page.wait_for_timeout(900)
    click_locator(page, page.locator("#decoy-button"), hover_ms=1100)
    page.wait_for_selector("#attack-banner:not([hidden])", timeout=15_000)
    page.wait_for_timeout(2800)
    click_locator(page, page.locator("#xray-toggle"))  # 透视开关：看清透明 iframe
    page.wait_for_timeout(4500)

    # ---- Act 3: defense blocks the same click ----
    title_card(
        page,
        "第三幕 · 防御生效",
        "一条环境变量：WEBSEC_DEFENSE_PROFILE=xfo-deny",
        "同样的攻击页：嵌入被拒绝（iframe 空白），点击不再产生任何转账",
    )
    page.goto(f"{lab.attacker_origin}/demo/classic?origin={defended_origin}&debug=1")
    page.wait_for_selector("#victim-frame")
    page.wait_for_timeout(3000)
    click_locator(page, page.locator("#decoy-button"), hover_ms=1000)
    page.wait_for_timeout(3800)
    balance = page.locator("#balance").inner_text()
    assert balance.strip() == "¥1000.00", balance  # untouched
    # 指针指向右侧余额，强调"什么都没发生"
    bal = page.locator("#balance").bounding_box()
    if bal:
        page.mouse.move(bal["x"] + bal["width"] / 2, bal["y"] + 10, steps=16)
        page.wait_for_timeout(2200)

    # ---- Act 4: the combined audit report ----
    title_card(
        page,
        "第四幕 · 自动化审计",
        "一条命令：websec-lab audit-report <url> --click",
        "静态响应头分析 + 真实浏览器动态验证 合并为一份带截图证据的报告",
    )
    page.goto(report_html.as_uri())
    page.wait_for_timeout(2600)
    for _ in range(8):
        page.mouse.wheel(0, 360)
        page.wait_for_timeout(800)
    page.wait_for_timeout(2600)

    video_path = Path(page.video.path())
    context.close()
    return video_path


def main() -> int:
    global VIDEO_OUT_DIR
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="artifacts/demo-video")
    args = parser.parse_args()

    from playwright.sync_api import sync_playwright

    installed = [item for item in discover_browsers() if item.channel == "chrome"]
    if not installed:
        raise SystemExit("No local Chrome available")
    executable = installed[0].executable_path

    VIDEO_OUT_DIR = Path(args.out).resolve()
    VIDEO_OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("[1/4] 启动本地靶场（无防御 + xfo-deny 两套 victim）...", flush=True)
    workspace = Path(tempfile.mkdtemp(prefix="demo-video-"))
    lab = LabServers(workspace)
    lab.reset_victim()
    defended = LabServers(
        Path(tempfile.mkdtemp(prefix="demo-video-def-")), defense_profile="xfo-deny"
    )
    defended.reset_victim()
    origins = list(lab.attacker_app.config["ATTACKER_VICTIM_ORIGINS"])
    if defended.victim_origin not in origins:
        origins.append(defended.victim_origin)
    lab.attacker_app.config["ATTACKER_VICTIM_ORIGINS"] = origins

    print("[2/4] 预生成合并审计报告（不录制）...", flush=True)
    report = run_combined_audit(
        target_url=f"{lab.victim_origin}/lab/quick-transfer",
        ancestors=["http://127.0.0.1:5200"],
        click=True,
        login=LoginConfig(origin=lab.victim_origin, username="alice", password="alice-lab"),
        state_check=StateCheckConfig(
            victim_origin=lab.victim_origin, username="alice", token="local-lab-only"
        ),
        evidence_root=Path(tempfile.mkdtemp(prefix="demo-video-ev-")),
        poll_timeout_s=8.0,
    )
    report_html = write_html_report(report, VIDEO_OUT_DIR / "audit_report_sample.html")
    # The report's click check consumed the baseline transfer — reset so the
    # recorded demo starts from a clean ¥1,000.00 account.
    lab.reset_victim()

    print("[3/4] 录制演示视频（可见光标 + 点击波纹 + 逐字输入）...", flush=True)
    started = time.monotonic()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=str(executable), headless=True)
        video = record(browser, lab, defended.victim_origin, report_html)
        browser.close()
    duration = time.monotonic() - started

    final_path = VIDEO_OUT_DIR / "project_demo.webm"
    shutil.move(str(video), final_path)

    print(f"[4/4] 完成：{final_path}")
    print(f"  大小 {final_path.stat().st_size / 1_048_576:.1f} MB · 全程约 {duration:.0f} 秒")
    print(f"  样例报告：{report_html}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
