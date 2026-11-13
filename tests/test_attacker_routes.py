import json
import re
from dataclasses import replace
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient

from websec_lab.attacker import create_app as create_attacker_app
from websec_lab.config import ConfigurationError, load_settings

RUN_ID_PATTERN = re.compile(r"运行编号 <strong>([0-9a-f]{6,32})</strong>")
EVENT_HEADERS = {"X-Websec-Test-Token": "test-token", "Content-Type": "application/json"}


def _create_run(attacker_client: FlaskClient, scenario_id: str) -> str:
    page = attacker_client.get(f"/scenarios/{scenario_id}/run")
    assert page.status_code == 200
    match = RUN_ID_PATTERN.search(page.get_data(as_text=True))
    assert match is not None
    return match.group(1)


def test_index_lists_all_scenarios(attacker_client: FlaskClient) -> None:
    page = attacker_client.get("/")
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    titles = (
        "iframe 嵌入探针",
        "透明 iframe 按钮覆盖",
        "界面裁剪与局部控件暴露",
        "多步骤连续诱导",
        "frame-busting 沙箱绕过对照",
        "滚动后控件重定位",
        "移动端 tapjacking",
    )
    for title in titles:
        assert title in body
    assert page.headers["X-Content-Type-Options"] == "nosniff"


def test_scenario_detail_renders_launch_form(attacker_client: FlaskClient) -> None:
    page = attacker_client.get("/scenarios/overlay")
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    assert "启动场景" in body
    assert "iframe 透明度" in body
    assert "/lab/quick-transfer" in body


def test_unknown_scenario_returns_404(attacker_client: FlaskClient) -> None:
    assert attacker_client.get("/scenarios/ghosting").status_code == 404
    assert attacker_client.get("/scenarios/ghosting/run").status_code == 404


def test_run_page_embeds_whitelisted_victim_url(attacker_client: FlaskClient) -> None:
    page = attacker_client.get("/scenarios/overlay/run")
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    # The configured default origin is the loopback variant so the lab works
    # out of the box without hosts-file setup.
    assert 'src="http://127.0.0.1:5100/lab/quick-transfer' in body
    assert 'id="victim-frame"' in body
    assert "S2" in body


def test_run_page_shows_post_click_verdict_card(attacker_client: FlaskClient) -> None:
    """Every scenario must be able to say what it was, after the click."""

    page = attacker_client.get("/scenarios/clip/run", base_url="http://127.0.0.1:5200")
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    assert 'id="ws-verdict"' in body
    assert "本次点击判定" in body
    assert "S3 界面裁剪" in body
    assert "260×64" in body
    assert "/static/js/verdict.js" in body


def test_run_page_accepts_loopback_origin(attacker_client: FlaskClient) -> None:
    page = attacker_client.get(
        "/scenarios/overlay/run", query_string={"origin": "http://127.0.0.1:5100"}
    )
    body = page.get_data(as_text=True)

    assert page.status_code == 200
    assert 'src="http://127.0.0.1:5100/lab/quick-transfer' in body


def test_run_page_rejects_foreign_origin(attacker_client: FlaskClient) -> None:
    response = attacker_client.get(
        "/scenarios/overlay/run", query_string={"origin": "https://evil.example"}
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_scenario_params"


def test_run_page_rejects_foreign_path(attacker_client: FlaskClient) -> None:
    response = attacker_client.get("/scenarios/overlay/run", query_string={"path": "/admin"})

    assert response.status_code == 400
    assert "only embeds" in response.get_json()["detail"]


def test_run_page_debug_mode_annotates_frame(attacker_client: FlaskClient) -> None:
    page = attacker_client.get("/scenarios/overlay/run", query_string={"debug": "1"})
    body = page.get_data(as_text=True)

    assert "debug-outline" in body
    assert "调试模式" in body


def test_events_endpoint_requires_token(attacker_client: FlaskClient) -> None:
    run_id = _create_run(attacker_client, "overlay")
    denied = attacker_client.post(
        f"/api/runs/{run_id}/events",
        json={"type": "page_ready"},
        headers={"X-Websec-Test-Token": "wrong"},
    )
    assert denied.status_code == 403


def test_event_round_trip_is_recorded(attacker_client: FlaskClient) -> None:
    run_id = _create_run(attacker_client, "overlay")

    accepted = attacker_client.post(
        f"/api/runs/{run_id}/events",
        json={"type": "iframe_load", "sequence": 1},
        headers=EVENT_HEADERS,
    )
    assert accepted.status_code == 200
    assert accepted.get_json()["event_count"] == 1

    detail = attacker_client.get(f"/api/runs/{run_id}")
    payload = detail.get_json()
    assert detail.status_code == 200
    assert payload["run_id"] == run_id
    assert payload["scenario"] == "overlay"
    assert payload["params"]["victim_path"] == "/lab/quick-transfer"
    assert [event["type"] for event in payload["events"]] == ["iframe_load"]
    assert payload["events"][0]["sequence"] == 1
    assert "reported_at" in payload["events"][0]


def test_event_validation_rejects_bad_payloads(attacker_client: FlaskClient) -> None:
    run_id = _create_run(attacker_client, "probe")

    missing_type = attacker_client.post(
        f"/api/runs/{run_id}/events", json={"foo": 1}, headers=EVENT_HEADERS
    )
    assert missing_type.status_code == 400

    not_object = attacker_client.post(
        f"/api/runs/{run_id}/events", json=[1, 2, 3], headers=EVENT_HEADERS
    )
    assert not_object.status_code == 400


def test_event_for_unknown_run_returns_404(attacker_client: FlaskClient) -> None:
    response = attacker_client.post(
        "/api/runs/deadbeef/events", json={"type": "page_ready"}, headers=EVENT_HEADERS
    )
    assert response.status_code == 404


def test_list_runs_summarizes_created_runs(attacker_client: FlaskClient) -> None:
    run_id = _create_run(attacker_client, "clip")
    response = attacker_client.get("/api/runs", query_string={"limit": 5})

    payload = response.get_json()
    assert response.status_code == 200
    matching = [run for run in payload["runs"] if run["run_id"] == run_id]
    assert len(matching) == 1
    assert matching[0]["events"] == 0
    assert matching[0]["scenario"] == "clip"


def test_runs_journal_persists_records(attacker_app: Flask, tmp_path: Path) -> None:
    journal = tmp_path / "artifacts" / "attacker" / "runs.jsonl"
    with attacker_app.test_client() as client:
        run_id = _create_run(client, "overlay")
        client.post(
            f"/api/runs/{run_id}/events",
            json={"type": "page_ready"},
            headers=EVENT_HEADERS,
        )

    lines = journal.read_text(encoding="utf-8").strip().splitlines()
    kinds = [json.loads(line)["kind"] for line in lines]
    assert kinds == ["run", "event"]


def test_health_and_readiness(attacker_client: FlaskClient) -> None:
    health = attacker_client.get("/healthz").get_json()
    readiness = attacker_client.get("/readyz").get_json()

    assert health["status"] == "ok"
    assert health["service"] == "attacker"
    assert readiness["status"] == "ready"
    assert readiness["local_only"] is True
    assert "http://127.0.0.1:5100" in readiness["victim_origins"]
    assert "http://localhost:5100" in readiness["victim_origins"]


def test_attacker_refuses_non_local_configuration(tmp_path: Path) -> None:
    settings = replace(load_settings(), local_only=False, artifact_dir=tmp_path)
    with pytest.raises(ConfigurationError, match="local_only"):
        create_attacker_app(settings=settings)
