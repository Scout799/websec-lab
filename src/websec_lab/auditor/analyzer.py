"""Static framing-policy analyzer (T0606/T0607/T0614).

Given one normalized response (headers + cookies) and an ancestor chain
(outermost first, immediate parent last), the analyzer derives:

- per-ancestor embedding decisions from XFO and CSP frame-ancestors,
- the findings catalog rules triggered by this response,
- an origin-permission matrix over the lab's configured origins,
- an evidence-traceable risk score.

XFO evaluation follows RFC 7034 semantics: DENY blocks everything and
SAMEORIGIN requires every ancestor to be same-origin with the target.
Multiple enforcing CSP policies intersect: each policy must allow each
ancestor. An enforcing frame-ancestors directive overrides XFO in modern
browsers; Report-Only policies do not override XFO.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from websec_lab.auditor.headers import HeaderMap
from websec_lab.auditor.origins import Origin, parse_origin
from websec_lab.auditor.parsers import CspAnalysis, ParsedHeaders, XfoPolicy
from websec_lab.auditor.rules import Finding, risk_score


@dataclass(frozen=True, slots=True)
class AncestorDecision:
    origin: str
    allowed: bool
    blocked_by: tuple[str, ...]  # subset of {"xfo", "csp"}
    detail: str

    def as_dict(self) -> dict[str, object]:
        return {
            "origin": self.origin,
            "allowed": self.allowed,
            "blocked_by": list(self.blocked_by),
            "detail": self.detail,
        }


@dataclass(slots=True)
class AnalysisResult:
    target_url: str
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    headers: dict[str, list[str]] = field(default_factory=dict)
    parsed: ParsedHeaders | None = None
    findings: list[Finding] = field(default_factory=list)
    decisions: list[AncestorDecision] = field(default_factory=list)
    permission_matrix: list[dict[str, object]] = field(default_factory=list)
    risk: dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "target_url": self.target_url,
            "final_url": self.final_url,
            "redirect_chain": list(self.redirect_chain),
            "headers": self.headers,
            "xfo": self.parsed.xfo.as_dict() if self.parsed and self.parsed.xfo else None,
            "csp": self.parsed.csp.as_dict() if self.parsed else None,
            "cookies": [
                cookie.as_dict() for cookie in (self.parsed.cookies if self.parsed else [])
            ],
            "findings": [finding.as_dict() for finding in self.findings],
            "decisions": [decision.as_dict() for decision in self.decisions],
            "permission_matrix": list(self.permission_matrix),
            "risk": dict(self.risk),
        }


def _evaluate_xfo(xfo: XfoPolicy, ancestors: list[Origin], target: Origin) -> tuple[bool, str]:
    effective = xfo.effective_value
    if effective is None:
        return True, "XFO 缺少有效值，未产生限制"
    if effective == "deny":
        return False, "X-Frame-Options: DENY 拒绝任何嵌入"
    same_origin = all(ancestor.same_origin(target) for ancestor in ancestors)
    if same_origin:
        return True, "X-Frame-Options: SAMEORIGIN 且全部祖先同源"
    return False, "X-Frame-Options: SAMEORIGIN 且存在非同源祖先"


def _evaluate_csp(csp: CspAnalysis, ancestors: list[Origin], target: Origin) -> tuple[bool, str]:
    if not csp.has_enforcing_frame_ancestors:
        return True, "无生效的 frame-ancestors 策略"
    blocked = [ancestor for ancestor in ancestors if not csp.allows(ancestor, target)]
    if not blocked:
        return True, "全部祖先都被 frame-ancestors 放行"
    return False, f"frame-ancestors 拒绝了 {len(blocked)} 个祖先链来源"


def _collect_findings(parsed: ParsedHeaders, target: Origin) -> list[Finding]:
    findings: list[Finding] = []
    xfo = parsed.xfo
    csp = parsed.csp

    has_protection = (xfo is not None and xfo.effective_value is not None) or (
        csp.has_enforcing_frame_ancestors
    )
    if not has_protection:
        findings.append(
            Finding.from_rule("WS001", "响应中未发现 X-Frame-Options 或生效的 frame-ancestors")
        )

    if xfo is not None:
        if xfo.duplicates:
            values = ", ".join(xfo.values)
            findings.append(Finding.from_rule("WS003", f"发现多个 XFO 值：{values}"))
        if xfo.obsolete_allow_from:
            findings.append(
                Finding.from_rule("WS004", f"值 {xfo.values[0]!r} 使用废弃的 ALLOW-FROM 语法")
            )
        if xfo.invalid_values:
            findings.append(
                Finding.from_rule("WS002", f"非法 XFO 值：{', '.join(xfo.invalid_values)}")
            )

    enforcing_policies = [policy for policy in csp.enforcing if policy.has_frame_ancestors]
    if len(csp.enforcing) > 1:
        findings.append(
            Finding.from_rule("WS006", f"发现 {len(csp.enforcing)} 个强制 CSP 策略（按交集执行）")
        )
    for policy in enforcing_policies:
        if policy.malformed:
            findings.append(Finding.from_rule("WS011", f"策略语法畸形：{policy.raw}"))
        if "*" in policy.sources or "*.test" in policy.sources:
            findings.append(Finding.from_rule("WS007", f"宽泛来源出现在：{policy.raw}"))
    if not csp.enforcing and csp.report_only:
        findings.append(
            Finding.from_rule("WS008", f"只有 Report-Only 策略：{csp.report_only[0].raw}")
        )

    if xfo is not None and xfo.effective_value is not None and enforcing_policies:
        # Both mechanisms active: detect semantic conflicts (T0607) by
        # comparing their decisions over every interesting probe origin —
        # the target, the lab origins, and origins named by the policies.
        probes: list[Origin] = [target]
        default_probes = [
            "http://partner.test:5300",
            "http://attacker.test:5200",
            "http://127.0.0.1:5300",
            "http://127.0.0.1:5200",
        ]
        for candidate in default_probes:
            try:
                probes.append(parse_origin(candidate))
            except ValueError:  # pragma: no cover - constants are valid
                continue
        for policy in enforcing_policies:
            for source in policy.sources:
                if "://" in source:
                    try:
                        probes.append(parse_origin(source))
                    except ValueError:
                        continue

        divergent = None
        for probe in probes:
            xfo_allows, _ = _evaluate_xfo(xfo, [probe], target)
            csp_allows = csp.allows(probe, target)
            if xfo_allows != csp_allows:
                divergent = (
                    f"对来源 {probe}：XFO 判定={xfo_allows} 与 frame-ancestors 判定={csp_allows}"
                )
                break

        if divergent is not None:
            findings.append(Finding.from_rule("WS005", divergent))
        else:
            findings.append(Finding.from_rule("WS012", "两套机制对所有探针来源判定一致"))

    for cookie in parsed.cookies:
        if cookie.same_site_none_without_secure:
            findings.append(
                Finding.from_rule("WS009", f"Cookie {cookie.name!r} SameSite=None 且无 Secure")
            )
        if not cookie.http_only or not cookie.secure:
            missing = [
                attribute
                for attribute, present in (
                    ("HttpOnly", cookie.http_only),
                    ("Secure", cookie.secure),
                )
                if not present
            ]
            findings.append(
                Finding.from_rule("WS010", f"Cookie {cookie.name!r} 缺少 {'/'.join(missing)}")
            )
    return findings


def _decide(parsed: ParsedHeaders, ancestors: list[Origin], target: Origin) -> AncestorDecision:
    if parsed.csp.has_enforcing_frame_ancestors:
        xfo_allows, xfo_detail = True, "生效的 frame-ancestors 优先，浏览器忽略 XFO"
    else:
        xfo_allows, xfo_detail = (
            _evaluate_xfo(parsed.xfo, ancestors, target) if parsed.xfo else (True, "无 XFO 头")
        )
    csp_allows, csp_detail = _evaluate_csp(parsed.csp, ancestors, target)
    blocked_by = tuple(
        mechanism for mechanism, allows in (("xfo", xfo_allows), ("csp", csp_allows)) if not allows
    )
    allowed = xfo_allows and csp_allows
    detail = f"{xfo_detail}；{csp_detail}"
    return AncestorDecision(
        origin=ancestors[-1].__str__() if ancestors else "",
        allowed=allowed,
        blocked_by=blocked_by,
        detail=detail,
    )


def analyze_response(
    headers: HeaderMap,
    set_cookies: tuple[str, ...],
    target_url: str,
    ancestors: list[str],
    matrix_origins: list[str] | None = None,
    redirect_chain: tuple[str, ...] = (),
    final_url: str | None = None,
) -> AnalysisResult:
    """Analyze one normalized response against an ancestor chain."""

    target = parse_origin(final_url or target_url)
    chain = [parse_origin(origin) for origin in ancestors]

    parsed = ParsedHeaders.from_headers(headers, set_cookies)
    result = AnalysisResult(
        target_url=target_url,
        final_url=final_url or target_url,
        redirect_chain=list(redirect_chain),
        headers=headers.as_dict(),
        parsed=parsed,
    )

    result.findings = _collect_findings(parsed, target)
    result.risk = risk_score(result.findings)

    if chain:
        result.decisions.append(_decide(parsed, chain, target))

    # Origin-permission matrix (T0614): single-level embedding decision per
    # candidate origin, defaulting to the lab's interesting origins.
    candidates = matrix_origins or [
        str(target),
        "http://partner.test:5300",
        "http://127.0.0.1:5300",
        "http://attacker.test:5200",
        "http://127.0.0.1:5200",
        "https://foreign.example.org",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            candidate_origin = parse_origin(candidate)
        except ValueError:
            continue
        decision = _decide(parsed, [candidate_origin], target)
        result.permission_matrix.append(
            {
                "origin": str(candidate_origin),
                "allowed": decision.allowed,
                "blocked_by": list(decision.blocked_by),
                "detail": decision.detail,
            }
        )
    return result
