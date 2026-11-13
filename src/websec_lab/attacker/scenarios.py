"""Scenario registry and parameter validation for the attacker application.

Every scenario only embeds the configured local victim origin and a
per-scenario whitelist of victim paths, so the lab can never be reused
as an arbitrary iframe wrapper.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlencode

MAX_DECOY_TEXT = 60
MAX_QUERY_VALUE = 80

OPACITY_MIN = 0.0
OPACITY_MAX = 1.0
IFRAME_WIDTH_RANGE = (200, 1600)
IFRAME_HEIGHT_RANGE = (150, 1200)
WINDOW_WIDTH_RANGE = (60, 800)
WINDOW_HEIGHT_RANGE = (40, 600)
OFFSET_RANGE = (-2000, 2000)
AMOUNT_CENTS_RANGE = (1, 50_000)

ALLOWED_QUERY_KEYS = ("amount_cents", "recipient", "client", "note")

# The note travels into the victim's ledger, so keep it to a short ASCII tag
# ("S5 frame-busting") that stays readable in a URL and in a table.
NOTE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")


class ScenarioParamError(ValueError):
    """Raised when scenario run parameters are missing or invalid."""


@dataclass(frozen=True, slots=True)
class ScenarioDefinition:
    """Static description of one clickjacking scenario."""

    scenario_id: str
    seq: str
    title: str
    summary: str
    template: str
    victim_paths: tuple[str, ...]
    default_victim_path: str
    default_opacity: float
    default_decoy_text: str
    # One-line statement of what this technique does differently from the
    # baseline overlay, shown on the run page so a single click is not
    # mistaken for "the same attack again".
    technique: str
    # Every scenario books a different amount on the victim ledger, so the
    # transaction history itself identifies which technique produced it.
    fingerprint_amount_cents: int
    # Short ASCII tag written into the victim's transfer note, e.g.
    # "S5 frame-busting", so the ledger says which technique it was.
    ledger_note: str
    # The single ingredient this technique depends on, quoted on the run
    # page and on the post-click verdict card.
    key_component: str

    def allows_path(self, path: str) -> bool:
        return path in self.victim_paths


PROBE = ScenarioDefinition(
    scenario_id="probe",
    seq="S1",
    title="iframe 嵌入探针",
    summary="可见加载目标页面，采集多信号判断目标当前是否允许被嵌入，是后续动态审计的基础。",
    template="attacker/run/probe.html",
    victim_paths=("/lab/quick-transfer", "/dashboard", "/login"),
    default_victim_path="/lab/quick-transfer",
    default_opacity=1.0,
    default_decoy_text="检测嵌入能力",
    technique="可见加载目标页并采集嵌入信号，不覆盖、不诱导点击（对照组）",
    fingerprint_amount_cents=123,
    ledger_note="S1 probe",
    key_component="可见加载目标页，不做覆盖、不诱导点击",
)

OVERLAY = ScenarioDefinition(
    scenario_id="overlay",
    seq="S2",
    title="透明 iframe 按钮覆盖",
    summary="将近透明的目标页覆盖在诱导按钮上方，用户点击诱导按钮时实际触发了目标的敏感操作。",
    template="attacker/run/overlay.html",
    victim_paths=("/lab/quick-transfer", "/lab/quick-grant"),
    default_victim_path="/lab/quick-transfer",
    default_opacity=0.01,
    default_decoy_text="立即领取试用装",
    technique="把整页压到 1% 透明度盖在诱饵按钮下，点诱饵即点目标按钮",
    fingerprint_amount_cents=123,
    ledger_note="S2 overlay",
    key_component="整页压到 1% 透明度 + 几何居中对齐",
)

CLIP = ScenarioDefinition(
    scenario_id="clip",
    seq="S3",
    title="界面裁剪与局部控件暴露",
    summary="用裁剪窗口只露出目标确认按钮的一小块区域，覆盖在诱导文案的按钮位置上完成误导点击。",
    template="attacker/run/clip.html",
    victim_paths=("/lab/quick-transfer",),
    default_victim_path="/lab/quick-transfer",
    default_opacity=1.0,
    default_decoy_text="立即充值",
    technique="不压透明度，改用裁剪窗口只露出目标按钮那一块区域",
    fingerprint_amount_cents=456,
    ledger_note="S3 clip",
    key_component="260×64 裁剪窗口，只露出目标按钮那一块",
)

MULTISTEP = ScenarioDefinition(
    scenario_id="multistep",
    seq="S4",
    title="多步骤连续诱导",
    summary="两次诱导点击之间自动切换并重新对齐 iframe，依次完成目标授权与转账两个敏感动作。",
    template="attacker/run/multistep.html",
    victim_paths=("/lab/quick-grant", "/lab/quick-transfer"),
    default_victim_path="/lab/quick-grant",
    default_opacity=0.01,
    default_decoy_text="拆开第 1 个礼盒",
    technique="两步诱导：先切入授权页点一次，再切到转账页点第二次",
    fingerprint_amount_cents=789,
    ledger_note="S4 multistep",
    key_component="两步状态机：授权页点一次 → 自动切到转账页再点一次",
)

BUST = ScenarioDefinition(
    scenario_id="bust",
    seq="S5",
    title="frame-busting 沙箱绕过对照",
    summary=(
        "目标启用 JavaScript frame-busting 时普通嵌入会被弹回；"
        "使用 sandbox 禁用目标页脚本后，透明覆盖攻击照常生效，验证纯前端防御的局限。"
    ),
    template="attacker/run/bust.html",
    victim_paths=("/lab/quick-transfer",),
    default_victim_path="/lab/quick-transfer",
    default_opacity=0.01,
    default_decoy_text="领取会员奖励",
    technique="目标有 frame-busting 时加 sandbox 禁用其脚本，覆盖照常生效",
    fingerprint_amount_cents=555,
    ledger_note="S5 frame-busting",
    key_component='sandbox="allow-forms allow-same-origin" 禁用目标脚本',
)

SCROLL = ScenarioDefinition(
    scenario_id="scroll",
    seq="S6",
    title="滚动后控件重定位",
    summary=(
        "长页面诱导用户向下滚动，滚动到“继续阅读”按钮时透明 iframe 才与目标按钮对齐，"
        "规避页面顶部的警惕心理。"
    ),
    template="attacker/run/scroll.html",
    victim_paths=("/lab/quick-transfer",),
    default_victim_path="/lab/quick-transfer",
    default_opacity=0.01,
    default_decoy_text="继续阅读精彩内容",
    technique="长页滚动到底部才对齐目标按钮，避开页面顶部的警惕",
    fingerprint_amount_cents=666,
    ledger_note="S6 scroll",
    key_component="覆盖层固定定位，滚动到底部才与目标按钮对齐",
)

TAP = ScenarioDefinition(
    scenario_id="tap",
    seq="S7",
    title="移动端 tapjacking",
    summary="移动视口下的触摸式点击劫持：大号触摸按钮更易误触，透明 iframe 对齐逻辑与桌面版一致。",
    template="attacker/run/tap.html",
    victim_paths=("/lab/quick-transfer",),
    default_victim_path="/lab/quick-transfer",
    default_opacity=0.01,
    default_decoy_text="点我领取新人红包",
    technique="移动视口 + 大号触摸按钮，靠误触完成点击",
    fingerprint_amount_cents=888,
    ledger_note="S7 tapjacking",
    key_component="移动视口 390×844 + 触摸输入",
)

SCENARIOS: dict[str, ScenarioDefinition] = {
    scenario.scenario_id: scenario
    for scenario in (PROBE, OVERLAY, CLIP, MULTISTEP, BUST, SCROLL, TAP)
}


def get_scenario(scenario_id: str) -> ScenarioDefinition:
    try:
        return SCENARIOS[scenario_id]
    except KeyError as exc:
        available = ", ".join(sorted(SCENARIOS))
        raise ScenarioParamError(
            f"Unknown scenario {scenario_id!r}. Available: {available}"
        ) from exc


def sorted_scenarios() -> list[ScenarioDefinition]:
    return sorted(SCENARIOS.values(), key=lambda item: item.seq)


def allowed_victim_origins(public_origin: str, port: int) -> list[str]:
    """Origins the scenarios may embed: the configured victim origin plus
    loopback variants used by local tests."""

    origins = [public_origin.rstrip("/")]
    for host in ("127.0.0.1", "localhost"):
        candidate = f"http://{host}:{port}"
        if candidate not in origins:
            origins.append(candidate)
    return origins


def _clamp(value: int, bounds: tuple[int, int]) -> int:
    low, high = bounds
    return max(low, min(value, high))


def _parse_int(raw: str | None, fallback: int) -> int:
    if raw is None or raw == "":
        return fallback
    try:
        return int(raw)
    except ValueError as exc:
        raise ScenarioParamError(f"Parameter value is not an integer: {raw!r}") from exc


def _parse_bool(raw: str | None) -> bool:
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}


def _parse_victim_query(
    args: Mapping[str, str], default_amount_cents: int = 123, default_note: str = ""
) -> dict[str, str]:
    query: dict[str, str] = {"amount_cents": str(default_amount_cents), "recipient": "bob"}
    if default_note:
        query["note"] = default_note
    for key in ALLOWED_QUERY_KEYS:
        if key not in args:
            continue
        raw = str(args[key]).strip()
        if not raw or len(raw) > MAX_QUERY_VALUE:
            raise ScenarioParamError(f"Invalid value for parameter {key!r}")
        if key == "amount_cents":
            try:
                cents = int(raw)
            except ValueError as exc:
                raise ScenarioParamError("amount_cents must be an integer") from exc
            cents = _clamp(cents, AMOUNT_CENTS_RANGE)
            query[key] = str(cents)
        elif key == "recipient":
            query[key] = raw.lower()
        elif key == "note":
            if not NOTE_PATTERN.fullmatch(raw):
                raise ScenarioParamError("note must be a short tag such as 'S5 frame-busting'")
            query[key] = raw
        else:
            query[key] = raw
    return query


@dataclass(frozen=True, slots=True)
class ScenarioParams:
    """Validated runtime parameters for one scenario execution."""

    scenario_id: str
    victim_base: str
    victim_path: str
    victim_query: dict[str, str]
    opacity: float
    iframe_width: int
    iframe_height: int
    offset_x: int
    offset_y: int
    window_width: int
    window_height: int
    debug: bool
    decoy_text: str
    decoy_step_labels: tuple[str, str]
    lab_run: str = ""

    def victim_url(self, path: str | None = None, query: Mapping[str, str] | None = None) -> str:
        target_path = self.victim_path if path is None else path
        effective_query = dict(self.victim_query if query is None else query)
        if self.lab_run:
            effective_query["lab_run"] = self.lab_run
        url = f"{self.victim_base}{target_path}"
        if effective_query:
            url = f"{url}?{urlencode(effective_query)}"
        return url

    def as_dict(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "victim_base": self.victim_base,
            "victim_path": self.victim_path,
            "victim_query": dict(self.victim_query),
            "opacity": self.opacity,
            "iframe_width": self.iframe_width,
            "iframe_height": self.iframe_height,
            "offset_x": self.offset_x,
            "offset_y": self.offset_y,
            "window_width": self.window_width,
            "window_height": self.window_height,
            "debug": self.debug,
            "decoy_text": self.decoy_text,
            "decoy_step_labels": list(self.decoy_step_labels),
        }


def parse_run_params(
    scenario: ScenarioDefinition,
    args: Mapping[str, str],
    allowed_origins: list[str],
) -> ScenarioParams:
    """Validate and clamp query-string parameters for one scenario run."""

    default_origin = allowed_origins[0]
    requested_origin = (args.get("origin") or "").strip().rstrip("/")
    if requested_origin and requested_origin not in allowed_origins:
        allowed_display = ", ".join(allowed_origins)
        raise ScenarioParamError(
            f"origin must be one of the configured local victim origins: {allowed_display}"
        )

    victim_path = (args.get("path") or "").strip() or scenario.default_victim_path
    if not scenario.allows_path(victim_path):
        allowed_display = ", ".join(scenario.victim_paths)
        raise ScenarioParamError(
            f"Scenario {scenario.scenario_id!r} only embeds: {allowed_display}"
        )

    opacity_raw = args.get("opacity")
    try:
        opacity = scenario.default_opacity if opacity_raw in (None, "") else float(opacity_raw)
    except ValueError as exc:
        raise ScenarioParamError("opacity must be a number between 0 and 1") from exc
    opacity = round(max(OPACITY_MIN, min(OPACITY_MAX, opacity)), 3)

    iframe_width = _clamp(_parse_int(args.get("iframe_w"), 340), IFRAME_WIDTH_RANGE)
    iframe_height = _clamp(_parse_int(args.get("iframe_h"), 360), IFRAME_HEIGHT_RANGE)
    window_width = _clamp(_parse_int(args.get("window_w"), 260), WINDOW_WIDTH_RANGE)
    window_height = _clamp(_parse_int(args.get("window_h"), 64), WINDOW_HEIGHT_RANGE)
    offset_x = _clamp(_parse_int(args.get("offset_x"), 0), OFFSET_RANGE)
    offset_y = _clamp(_parse_int(args.get("offset_y"), 0), OFFSET_RANGE)

    decoy_text = (args.get("decoy") or "").strip()[:MAX_DECOY_TEXT] or scenario.default_decoy_text
    step1 = (args.get("decoy_step1") or "").strip()[:MAX_DECOY_TEXT] or "拆开第 1 个礼盒"
    step2 = (args.get("decoy_step2") or "").strip()[:MAX_DECOY_TEXT] or "确认收货并领取"
    from websec_lab.victim.telemetry import RUN_PATTERN

    lab_run = args.get("lab_run", "")
    if lab_run and not RUN_PATTERN.fullmatch(lab_run):
        raise ScenarioParamError("lab_run must be 32 lowercase hexadecimal characters")

    return ScenarioParams(
        scenario_id=scenario.scenario_id,
        victim_base=requested_origin or default_origin,
        victim_path=victim_path,
        victim_query=_parse_victim_query(
            args, scenario.fingerprint_amount_cents, scenario.ledger_note
        ),
        opacity=opacity,
        iframe_width=iframe_width,
        iframe_height=iframe_height,
        offset_x=offset_x,
        offset_y=offset_y,
        window_width=window_width,
        window_height=window_height,
        debug=_parse_bool(args.get("debug")),
        decoy_text=decoy_text,
        decoy_step_labels=(step1, step2),
        lab_run=lab_run,
    )
