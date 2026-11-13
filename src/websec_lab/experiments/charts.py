"""Dependency-free SVG charts for the M9 experiment outputs (T0914/T0915)."""

from __future__ import annotations

from pathlib import Path

BAR_HEIGHT = 26
GAP = 10
LEFT = 210
TOP = 70
WIDTH = 880


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def attack_outcome_chart(per_profile: dict[str, dict[str, object]], total_cases: int) -> str:
    """Horizontal bars: one per profile, colored by observed outcome.

    Outcomes per profile are aggregated into three buckets — attack fully
    blocked (green), no sensitive action confirmed in this attempt (amber),
    attack succeeded (red).
    """

    profiles = list(per_profile)
    body_height = len(profiles) * (BAR_HEIGHT + GAP)
    height = TOP + body_height + 56

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" '
        f'viewBox="0 0 {WIDTH} {height}" font-family="Segoe UI, Microsoft YaHei, sans-serif">'
    )
    parts.append(f'<rect width="{WIDTH}" height="{height}" fill="#ffffff"/>')
    parts.append(
        f'<text x="{LEFT}" y="34" font-size="17" font-weight="700" fill="#16325c">'
        "各防御配置下的攻击结果（真实浏览器，M9 实验矩阵）</text>"
    )
    parts.append(
        f'<text x="{LEFT}" y="54" font-size="12" fill="#64748b">'
        f"共 {total_cases} 组攻击实验 · "
        f"绿色=嵌入被阻断 琥珀=未证实触发敏感操作 红色=攻击成功</text>"
    )

    chart_width = WIDTH - LEFT - 40
    y = TOP
    for profile in profiles:
        stats = per_profile[profile]
        cases = int(stats["cases"])  # type: ignore[arg-type]
        blocked = int(stats["dynamic_blocked"])  # type: ignore[arg-type]
        triggered = int(stats["attack_triggered"])  # type: ignore[arg-type]
        partial = cases - blocked - triggered

        parts.append(
            f'<text x="{LEFT - 12}" y="{y + BAR_HEIGHT - 8}" font-size="12.5" '
            f'text-anchor="end" fill="#334155">{_escape(profile)}</text>'
        )
        segment_x = LEFT
        for count, color in (
            (blocked, "#2e9e5b"),
            (partial, "#d9a13b"),
            (triggered, "#c4384a"),
        ):
            if count <= 0:
                continue
            segment_width = max(chart_width * count / cases, 4 if count else 0)
            parts.append(
                f'<rect x="{segment_x}" y="{y}" width="{segment_width:.1f}" '
                f'height="{BAR_HEIGHT}" rx="5" fill="{color}"/>'
            )
            if count > 0 and segment_width > 22:
                parts.append(
                    f'<text x="{segment_x + segment_width / 2:.1f}" y="{y + 17.5}" '
                    'font-size="12" font-weight="700" fill="#ffffff" '
                    f'text-anchor="middle">{count}</text>'
                )
            segment_x += segment_width
        y += BAR_HEIGHT + GAP

    legend_y = height - 24
    for offset, color, label in (
        (0, "#2e9e5b", "嵌入被阻断"),
        (130, "#d9a13b", "未证实触发"),
        (260, "#c4384a", "攻击成功"),
    ):
        parts.append(
            f'<rect x="{LEFT + offset}" y="{legend_y - 11}" '
            f'width="12" height="12" rx="3" fill="{color}"/>'
        )
        parts.append(
            f'<text x="{LEFT + offset + 18}" y="{legend_y}" '
            f'font-size="12" fill="#475569">{label}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def metric_cards_chart(metrics: dict[str, object]) -> str:
    """A compact metric summary rendered as SVG cards."""

    cards: list[tuple[str, str, str]] = []
    for key, label in (
        ("attack_success_rate", "总体攻击成功率"),
        ("illegal_embed_block_rate", "非法嵌入阻断率"),
        ("static_dynamic_consistency", "静态/动态一致率"),
    ):
        value = metrics.get(key)
        cards.append((label, f"{value * 100:.1f}%" if isinstance(value, float) else "—", "#16325c"))
    detection = metrics.get("detection") or {}
    detection_rate = detection.get("detection_rate") if isinstance(detection, dict) else None
    cards.append(
        (
            "静态检测率（WS001）",
            f"{detection_rate * 100:.1f}%" if isinstance(detection_rate, float) else "—",
            "#16325c",
        )
    )
    legit = metrics.get("legit_embed_pass_rate")
    cards.append(
        (
            "合法嵌入通过率",
            f"{legit * 100:.1f}%" if isinstance(legit, float) else "—",
            "#0d6b4a",
        )
    )

    card_width, card_height = 160, 84
    gap = 14
    total_width = len(cards) * card_width + (len(cards) - 1) * gap
    height = 130
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="{height}" '
        f'font-family="Segoe UI, Microsoft YaHei, sans-serif">'
    ]
    for index, (label, value, color) in enumerate(cards):
        x = index * (card_width + gap)
        parts.append(
            f'<rect x="{x}" y="14" width="{card_width}" height="{card_height}" rx="10" '
            f'fill="#f8fafc" stroke="#dbe3ef"/>'
        )
        parts.append(
            f'<text x="{x + card_width / 2}" y="48" font-size="12" fill="#64748b" '
            f'text-anchor="middle">{_escape(label)}</text>'
        )
        parts.append(
            f'<text x="{x + card_width / 2}" y="80" font-size="22" font-weight="800" '
            f'fill="{color}" text-anchor="middle">{value}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def write_chart(svg: str, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(svg, encoding="utf-8")
    return path
