"""Service-level tests for the auditor API (fetch mode + offline mode)."""

import tempfile
import threading
from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from flask.testing import FlaskClient
from werkzeug.serving import make_server

from websec_lab.auditor import create_app as create_auditor_app

CORPUS_PATH = Path(__file__).parent / "corpus" / "policy_corpus.yaml"


@pytest.fixture
def auditor_client() -> FlaskClient:
    app = create_auditor_app(test_config={"TESTING": True})
    return app.test_client()


def _start_victim(profile: str) -> int:
    from websec_lab.config import load_settings
    from websec_lab.extensions import db
    from websec_lab.victim import create_app as create_victim_app
    from websec_lab.victim.services import seed_lab_data

    workspace = Path(tempfile.mkdtemp(prefix=f"auditor-victim-{profile}-"))
    settings = replace(load_settings(), database_path=workspace / "victim.sqlite3")
    app = create_victim_app(
        settings=settings,
        test_config={"DEFENSE_PROFILE": profile},
    )
    with app.app_context():
        db.create_all()
        seed_lab_data()
    server = make_server("127.0.0.1", 0, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return int(server.port)


def test_rules_endpoint_lists_catalog(auditor_client: FlaskClient) -> None:
    payload = auditor_client.get("/api/rules").get_json()

    rule_ids = {rule["rule_id"] for rule in payload["rules"]}
    assert {"WS001", "WS005", "WS009"} <= rule_ids
    assert all(rule["remediation"] for rule in payload["rules"])


def test_offline_analyze_matches_corpus(auditor_client: FlaskClient) -> None:
    with CORPUS_PATH.open("r", encoding="utf-8") as handle:
        corpus = yaml.safe_load(handle)
    case = next(item for item in corpus if item["name"] == "xfo-csp-conflict-detected")

    response = auditor_client.post(
        "/api/analyze",
        json={
            "url": case["url"],
            "headers": case["headers"],
            "ancestors": case["ancestors"],
        },
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["decisions"][0]["allowed"] is (case["expected"]["decision"] == "allowed")
    assert payload["decisions"][0]["blocked_by"] == case["expected"]["blocked_by"]
    assert [finding["rule_id"] for finding in payload["findings"]] == ["WS005"]


def test_offline_analyze_validates_input(auditor_client: FlaskClient) -> None:
    missing_url = auditor_client.post("/api/analyze", json={"headers": {}})
    assert missing_url.status_code == 400

    bad_ancestors = auditor_client.post(
        "/api/analyze",
        json={"url": "http://victim.test:5100/x", "headers": {}, "ancestors": "nope"},
    )
    assert bad_ancestors.status_code == 400

    bad_url = auditor_client.post("/api/analyze", json={"url": "ftp://x", "headers": {}})
    assert bad_url.status_code == 400


def test_fetch_analyze_rejects_non_local_target(auditor_client: FlaskClient) -> None:
    response = auditor_client.get("/api/analyze", query_string={"url": "https://real.example.com/"})

    assert response.status_code == 400
    assert response.get_json()["error"] == "fetch_failed"


def test_fetch_analyze_blocks_under_xfo_deny(auditor_client: FlaskClient) -> None:
    port = _start_victim("xfo-deny")
    target = f"http://127.0.0.1:{port}/lab/quick-transfer"

    response = auditor_client.get(
        "/api/analyze",
        query_string={"url": target, "ancestor": "http://127.0.0.1:5200"},
    )

    assert response.status_code == 200
    payload = response.get_json()
    # Unauthenticated GET redirects to /login; the redirect chain must be recorded.
    assert payload["fetch"]["status_code"] == 200
    assert payload["redirect_chain"], payload["redirect_chain"]
    assert payload["decisions"][0]["allowed"] is False
    assert "xfo" in payload["decisions"][0]["blocked_by"]


def test_fetch_analyze_allows_under_no_defense(auditor_client: FlaskClient) -> None:
    port = _start_victim("none")
    target = f"http://127.0.0.1:{port}/login"

    response = auditor_client.get(
        "/api/analyze",
        query_string={"url": target, "ancestor": "http://127.0.0.1:5200"},
    )

    payload = response.get_json()
    assert payload["decisions"][0]["allowed"] is True
    assert any(finding["rule_id"] == "WS001" for finding in payload["findings"])


def test_health_endpoints_keep_shell_contract(auditor_client: FlaskClient) -> None:
    health = auditor_client.get("/healthz").get_json()
    readiness = auditor_client.get("/readyz").get_json()

    assert health["service"] == "auditor"
    assert readiness["status"] == "ready"
    assert readiness["local_only"] is True


def test_audit_console_page_and_live_state(auditor_client: FlaskClient, monkeypatch) -> None:
    page = auditor_client.get("/audit")
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    assert 'name="target"' in body
    assert 'id="live-balance"' in body

    from types import SimpleNamespace

    def fake_get(url, headers=None, timeout=None):  # type: ignore[no-untyped-def]
        assert url.endswith("/api/test/state/alice")
        return SimpleNamespace(
            status_code=200,
            json=lambda: {
                "account": {"balance_cents": 99877},
                "transfers": [],
                "grants": [],
            },
        )

    monkeypatch.setattr("requests.get", fake_get)
    state = auditor_client.get("/audit/state?username=alice")
    assert state.status_code == 200
    assert state.get_json()["account"]["balance_cents"] == 99877

    rejected = auditor_client.get("/audit/state?username=../etc")
    assert rejected.status_code == 400
