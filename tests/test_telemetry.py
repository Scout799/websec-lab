import pytest

from websec_lab.auditor.fetch import FetchError, _resolve_url
from websec_lab.victim.telemetry import correlate

RUN = "a" * 32


def event(channel, **values):
    return {"channel": channel, "received_at": 100, "path": "/lab/quick-transfer", **values}


def test_channels_cover_complementary_attack_signals():
    csp = event("csp", directive="frame-ancestors")
    click = event("interaction", type="click", sensitive=True, trusted=True, in_frame=True)
    assert correlate([csp])["csp_detected"] is True
    assert correlate([csp])["interaction_detected"] is False
    assert correlate([click])["csp_detected"] is False
    assert correlate([click])["interaction_detected"] is True
    result = correlate([csp, click])
    assert result["fused_detected"] is True
    assert len(result["correlated_pairs"]) == 1


@pytest.mark.parametrize(
    "trusted,sensitive,framed,focus,expected",
    [
        (True, True, True, -1, True),
        (True, True, False, 100, True),
        (True, True, False, 1000, False),
        (False, True, True, 50, False),
        (True, False, True, 50, False),
        (True, True, False, -1, False),
    ],
)
def test_interaction_rule_observes_focus_and_sensitive_controls(
    trusted, sensitive, framed, focus, expected
):
    result = correlate(
        [
            event(
                "interaction",
                type="click",
                trusted=trusted,
                sensitive=sensitive,
                in_frame=framed,
                since_focus_ms=focus,
            )
        ]
    )
    assert result["interaction_detected"] is expected


def test_unrelated_path_or_time_is_not_joined():
    csp = event("csp", directive="frame-ancestors")
    click = event(
        "interaction", type="click", sensitive=True, trusted=True, in_frame=True, received_at=105
    )
    assert correlate([csp, click])["correlated_pairs"] == []
    click.update(received_at=100, path="/another")
    assert correlate([csp, click])["correlated_pairs"] == []


def test_report_receiver_validation_and_read_authorization(victim_client):
    assert victim_client.post("/telemetry/csp?run_id=bad", json={}).status_code == 400
    assert (
        victim_client.post(
            f"/telemetry/csp?run_id={RUN}",
            json={
                "csp-report": {
                    "effective-directive": "frame-ancestors",
                    "document-uri": "https://victim.test:8443/lab/quick-transfer?secret=omitted",
                }
            },
        ).status_code
        == 204
    )
    assert victim_client.get(f"/telemetry/runs/{RUN}").status_code == 403
    result = victim_client.get(
        f"/telemetry/runs/{RUN}", headers={"X-Websec-Test-Token": "test-token"}
    )
    assert result.status_code == 200
    assert result.json["analysis"]["csp_detected"] is True
    assert "secret" not in str(result.json)
    assert (
        victim_client.post(f"/telemetry/events?run_id={RUN}", json={"type": "unknown"}).status_code
        == 400
    )


def test_reporting_header_is_run_scoped_and_does_not_drop_policy(victim_factory):
    client = victim_factory("csp-none").test_client()
    response = client.get(f"/login?lab_run={RUN}")
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert f"report-uri /telemetry/csp?run_id={RUN}" in response.headers["Content-Security-Policy"]
    assert "report-uri" not in client.get("/login").headers["Content-Security-Policy"]


def test_telemetry_disabled_outside_local_lab(victim_factory):
    assert (
        victim_factory(local_only=False).test_client().get("/telemetry/client.js").status_code
        == 404
    )


def test_relative_redirects_preserve_directory_and_reject_network_path_escape():
    assert _resolve_url("https://victim.test/a/b", "next") == "https://victim.test/a/next"
    with pytest.raises(FetchError):
        _resolve_url("https://victim.test/a", "//outside.example/path")
