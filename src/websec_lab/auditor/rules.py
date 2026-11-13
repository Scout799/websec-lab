"""Rule catalog with IDs, severities and remediation advice (T0610).

Every finding the analyzer emits references one catalog rule, and the risk
score is a transparent sum of rule weights so any score can be traced back
to its evidence (T0615).
"""

from __future__ import annotations

from dataclasses import dataclass

Severity = str  # "info" | "low" | "medium" | "high"

SEVERITY_WEIGHTS: dict[str, int] = {"info": 0, "low": 8, "medium": 20, "high": 40}
GRADE_BANDS = ((0, 15, "low"), (16, 39, "medium"), (40, 69, "high"), (70, 100, "critical"))


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    severity: Severity
    title: str
    description: str
    remediation: str


RULES: dict[str, Rule] = {
    rule.rule_id: rule
    for rule in (
        Rule(
            "WS001",
            "high",
            "无任何嵌入防护",
            "响应缺少 X-Frame-Options 与生效的 CSP frame-ancestors，任意站点均可嵌入本页。",
            "添加 X-Frame-Options: DENY，或使用 CSP frame-ancestors 明确允许的来源。",
        ),
        Rule(
            "WS002",
            "medium",
            "X-Frame-Options 值非法",
            "非 DENY/SAMEORIGIN 的值会被现代浏览器当作无效头忽略，起不到保护作用。",
            "只使用 DENY 或 SAMEORIGIN；如需按来源放行请改用 CSP frame-ancestors。",
        ),
        Rule(
            "WS003",
            "low",
            "重复的 X-Frame-Options 头",
            "多个 XFO 头的取值行为在不同浏览器间不一致，属于歧义配置。",
            "确保反向代理与应用只输出一个 X-Frame-Options 头。",
        ),
        Rule(
            "WS004",
            "medium",
            "使用已废弃的 ALLOW-FROM",
            "ALLOW-FROM 已被现代浏览器废弃并忽略，等于没有防护。",
            "改用 CSP frame-ancestors <来源> 实现按来源放行。",
        ),
        Rule(
            "WS005",
            "medium",
            "XFO 与 CSP frame-ancestors 语义冲突",
            "两套机制的判定不一致：浏览器会同时执行两者（取更严格结果），冲突配置徒增维护风险。",
            "让 XFO 与 frame-ancestors 表达同一意图，或只保留 CSP frame-ancestors。",
        ),
        Rule(
            "WS006",
            "info",
            "存在多个 CSP 策略",
            "多个 CSP 策略按交集执行：每个策略都必须放行，配置意图容易误判。",
            "合并为单一策略，明确最终交集语义。",
        ),
        Rule(
            "WS007",
            "high",
            "frame-ancestors 使用通配符",
            "frame-ancestors *（或宽泛主机通配）实际上允许任意来源嵌入。",
            "将来源收敛为明确的 origin 白名单。",
        ),
        Rule(
            "WS008",
            "medium",
            "仅 Report-Only 无强制策略",
            "Content-Security-Policy-Report-Only 只上报不阻断，页面仍可被嵌入。",
            "验证策略影响后切换为强制 Content-Security-Policy。",
        ),
        Rule(
            "WS009",
            "medium",
            "SameSite=None 且缺少 Secure",
            "浏览器会拒绝没有 Secure 的 SameSite=None Cookie，会话可能异常失效。",
            "为 SameSite=None 的 Cookie 同时设置 Secure，并只在 HTTPS 下使用。",
        ),
        Rule(
            "WS010",
            "low",
            "会话 Cookie 缺少 HttpOnly/Secure",
            "缺少 HttpOnly 使 Cookie 可被脚本读取；缺少 Secure 允许明文传输。",
            "为会话类 Cookie 同时启用 HttpOnly 与 Secure。",
        ),
        Rule(
            "WS011",
            "info",
            "frame-ancestors 配置畸形",
            "指令重复、'none' 与其他来源混用等畸形写法会导致整个指令被浏览器丢弃。",
            "修正 CSP 语法，避免同名指令与 'none' 混用。",
        ),
        Rule(
            "WS012",
            "info",
            "XFO 与 CSP 配置一致",
            "X-Frame-Options 与 CSP frame-ancestors 语义一致，属于健康的纵深配置。",
            "保持两套机制同步维护。",
        ),
    )
}


def get_rule(rule_id: str) -> Rule:
    return RULES[rule_id]


@dataclass(frozen=True, slots=True)
class Finding:
    """One triggered rule with its concrete evidence."""

    rule_id: str
    severity: Severity
    title: str
    evidence: str
    remediation: str

    @classmethod
    def from_rule(cls, rule_id: str, evidence: str) -> Finding:
        rule = get_rule(rule_id)
        return cls(
            rule_id=rule.rule_id,
            severity=rule.severity,
            title=rule.title,
            evidence=evidence,
            remediation=rule.remediation,
        )

    def as_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


def risk_score(findings: list[Finding]) -> dict[str, object]:
    """Additive, evidence-traceable score: sum of rule weights capped at 100."""

    score = sum(SEVERITY_WEIGHTS.get(finding.severity, 0) for finding in findings)
    score = min(score, 100)
    grade = "info"
    for low, high, label in GRADE_BANDS:
        if low <= score <= high:
            grade = label
            break
    return {
        "score": score,
        "grade": grade if score > 0 else "info",
        "contributions": [
            {"rule_id": finding.rule_id, "weight": SEVERITY_WEIGHTS.get(finding.severity, 0)}
            for finding in findings
            if SEVERITY_WEIGHTS.get(finding.severity, 0) > 0
        ],
    }
