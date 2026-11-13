"""Parametrized tests over the M6 policy corpus (T0612/T0613)."""

from pathlib import Path

import pytest
import yaml

from websec_lab.auditor.analyzer import analyze_response
from websec_lab.auditor.headers import HeaderMap

CORPUS_PATH = Path(__file__).parent / "corpus" / "policy_corpus.yaml"


def _load_corpus() -> list[dict]:
    with CORPUS_PATH.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


CORPUS = _load_corpus()


@pytest.mark.parametrize("case", CORPUS, ids=[case["name"] for case in CORPUS])
def test_corpus_case(case: dict) -> None:
    result = analyze_response(
        headers=HeaderMap(case.get("headers") or {}),
        set_cookies=tuple(case.get("set_cookies") or []),
        target_url=case["url"],
        ancestors=case["ancestors"],
        matrix_origins=[],
    )

    expected = case["expected"]
    decision = result.decisions[0]
    assert decision.allowed == (expected["decision"] == "allowed"), decision.detail
    assert sorted(decision.blocked_by) == sorted(expected["blocked_by"])
    assert sorted(finding.rule_id for finding in result.findings) == sorted(expected["rule_ids"])


def test_corpus_covers_every_rule_at_least_once() -> None:
    triggered: set[str] = set()
    for case in CORPUS:
        triggered.update(case["expected"]["rule_ids"])

    from websec_lab.auditor.rules import RULES

    catalog_ids = set(RULES)
    assert catalog_ids == triggered, (
        f"rule coverage mismatch; never exercised: {sorted(catalog_ids - triggered)}, "
        f"unknown in corpus: {sorted(triggered - catalog_ids)}"
    )


def test_permission_matrix_reflects_allowlist() -> None:
    result = analyze_response(
        headers=HeaderMap(
            {"content-security-policy": ["frame-ancestors 'self' http://partner.test:5300"]}
        ),
        set_cookies=(),
        target_url="http://victim.test:5100/lab/quick-transfer",
        ancestors=["http://partner.test:5300"],
        matrix_origins=[
            "http://victim.test:5100",
            "http://partner.test:5300",
            "http://attacker.test:5200",
        ],
    )

    matrix = {row["origin"]: row["allowed"] for row in result.permission_matrix}
    assert matrix["http://victim.test:5100"] is True
    assert matrix["http://partner.test:5300"] is True
    assert matrix["http://attacker.test:5200"] is False


def test_result_serializes_to_json_shape() -> None:
    result = analyze_response(
        headers=HeaderMap({"x-frame-options": ["DENY"]}),
        set_cookies=("sid=1; HttpOnly; SameSite=Lax",),
        target_url="http://victim.test:5100/x",
        ancestors=["http://attacker.test:5200"],
        redirect_chain=("http://victim.test:5100/login",),
    )

    payload = result.as_dict()
    assert payload["xfo"]["effective_value"] == "deny"
    assert payload["decisions"][0]["allowed"] is False
    assert payload["risk"]["score"] >= 0
    assert payload["redirect_chain"] == ["http://victim.test:5100/login"]
    assert payload["cookies"][0]["name"] == "sid"
