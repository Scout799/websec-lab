import pytest

from websec_lab.attacker.scenarios import (
    SCENARIOS,
    ScenarioParamError,
    allowed_victim_origins,
    get_scenario,
    parse_run_params,
    sorted_scenarios,
)

ORIGINS = allowed_victim_origins("http://victim.test:5100", 5100)


def test_registry_contains_core_scenarios() -> None:
    assert set(SCENARIOS) == {
        "probe",
        "overlay",
        "clip",
        "multistep",
        "bust",
        "scroll",
        "tap",
    }
    assert [item.seq for item in sorted_scenarios()] == [
        "S1",
        "S2",
        "S3",
        "S4",
        "S5",
        "S6",
        "S7",
    ]
    templates = [item.template for item in SCENARIOS.values()]
    assert len(templates) == len(set(templates))


def test_get_scenario_rejects_unknown_id() -> None:
    with pytest.raises(ScenarioParamError, match="Unknown scenario"):
        get_scenario("side-channel")


def test_each_booking_scenario_has_its_own_ledger_fingerprint() -> None:
    """Every attacking technique must be identifiable in the victim ledger.

    All scenarios end in the same kind of business change, so the amount they
    book is what lets a viewer tell "this deduction is S5" apart from S2.
    The probe embeds without clicking, so it books nothing and is excluded.
    """

    amounts = {
        scenario.scenario_id: scenario.fingerprint_amount_cents
        for scenario in SCENARIOS.values()
        if scenario.scenario_id != "probe"
    }
    assert len(amounts) == len(set(amounts.values())), amounts
    assert all(value > 0 for value in amounts.values())


def test_parse_uses_the_scenario_fingerprint_amount_by_default() -> None:
    assert parse_run_params(SCENARIOS["overlay"], {}, ORIGINS).victim_query["amount_cents"] == "123"
    assert parse_run_params(SCENARIOS["bust"], {}, ORIGINS).victim_query["amount_cents"] == "555"
    assert parse_run_params(SCENARIOS["tap"], {}, ORIGINS).victim_query["amount_cents"] == "888"


def test_parse_carries_the_technique_tag_into_the_victim_query() -> None:
    params = parse_run_params(SCENARIOS["bust"], {}, ORIGINS)

    assert params.victim_query["note"] == "S5 frame-busting"
    assert "note=S5+frame-busting" in params.victim_url()


def test_parse_rejects_a_malformed_technique_tag() -> None:
    with pytest.raises(ScenarioParamError, match="note"):
        parse_run_params(SCENARIOS["overlay"], {"note": "<script>alert(1)</script>"}, ORIGINS)


def test_each_scenario_states_what_it_does_differently() -> None:
    techniques = [scenario.technique for scenario in SCENARIOS.values()]
    assert all(techniques)
    assert len(techniques) == len(set(techniques))


def test_allowed_victim_origins_include_loopback_variants() -> None:
    assert ORIGINS[0] == "http://victim.test:5100"
    assert "http://127.0.0.1:5100" in ORIGINS
    assert "http://localhost:5100" in ORIGINS


def test_parse_defaults_for_overlay() -> None:
    params = parse_run_params(SCENARIOS["overlay"], {}, ORIGINS)

    assert params.victim_base == "http://victim.test:5100"
    assert params.victim_path == "/lab/quick-transfer"
    assert params.opacity == 0.01
    assert params.debug is False
    assert params.decoy_text == "立即领取试用装"
    assert params.victim_query == {
        "amount_cents": "123",
        "recipient": "bob",
        "note": "S2 overlay",
    }
    assert params.victim_url() == (
        "http://victim.test:5100/lab/quick-transfer?amount_cents=123&recipient=bob&note=S2+overlay"
    )


def test_parse_accepts_configured_loopback_origin() -> None:
    params = parse_run_params(SCENARIOS["overlay"], {"origin": "http://127.0.0.1:5100"}, ORIGINS)
    assert params.victim_base == "http://127.0.0.1:5100"


def test_parse_rejects_foreign_origin() -> None:
    with pytest.raises(ScenarioParamError, match="origin"):
        parse_run_params(SCENARIOS["overlay"], {"origin": "https://evil.example"}, ORIGINS)


def test_parse_rejects_path_outside_whitelist() -> None:
    with pytest.raises(ScenarioParamError, match="only embeds"):
        parse_run_params(SCENARIOS["overlay"], {"path": "/admin"}, ORIGINS)


def test_parse_clamps_numeric_parameters() -> None:
    params = parse_run_params(
        SCENARIOS["clip"],
        {
            "opacity": "3",
            "iframe_w": "10",
            "iframe_h": "9999",
            "window_w": "5",
            "window_h": "9999",
            "offset_x": "-99999",
            "offset_y": "99999",
        },
        ORIGINS,
    )

    assert params.opacity == 1.0
    assert params.iframe_width == 200
    assert params.iframe_height == 1200
    assert params.window_width == 60
    assert params.window_height == 600
    assert params.offset_x == -2000
    assert params.offset_y == 2000


def test_parse_rejects_non_numeric_values() -> None:
    with pytest.raises(ScenarioParamError, match="integer"):
        parse_run_params(SCENARIOS["overlay"], {"iframe_w": "wide"}, ORIGINS)
    with pytest.raises(ScenarioParamError, match="opacity"):
        parse_run_params(SCENARIOS["overlay"], {"opacity": "ghost"}, ORIGINS)


def test_parse_clamps_transfer_amount_and_keeps_recipient_lowercased() -> None:
    params = parse_run_params(
        SCENARIOS["overlay"],
        {"amount_cents": "999999", "recipient": "MERCHANT"},
        ORIGINS,
    )
    assert params.victim_query["amount_cents"] == "50000"
    assert params.victim_query["recipient"] == "merchant"


def test_parse_rejects_invalid_amount_cents() -> None:
    with pytest.raises(ScenarioParamError, match="amount_cents"):
        parse_run_params(SCENARIOS["overlay"], {"amount_cents": "free"}, ORIGINS)


def test_decoy_text_is_capped_and_defaults_applied() -> None:
    params = parse_run_params(SCENARIOS["overlay"], {"decoy": "x" * 200}, ORIGINS)
    assert len(params.decoy_text) == 60

    empty = parse_run_params(SCENARIOS["overlay"], {"decoy": "   "}, ORIGINS)
    assert empty.decoy_text == "立即领取试用装"


def test_debug_flag_accepts_common_truthy_spellings() -> None:
    assert parse_run_params(SCENARIOS["overlay"], {"debug": "1"}, ORIGINS).debug is True
    assert parse_run_params(SCENARIOS["overlay"], {"debug": "true"}, ORIGINS).debug is True
    assert parse_run_params(SCENARIOS["overlay"], {"debug": "0"}, ORIGINS).debug is False


def test_victim_url_overrides_path_and_query() -> None:
    params = parse_run_params(SCENARIOS["multistep"], {}, ORIGINS)
    grant_url = params.victim_url(path="/lab/quick-grant")
    assert grant_url.startswith("http://victim.test:5100/lab/quick-grant?")

    custom = params.victim_url(query={"client": "Lab Partner Demo"})
    assert custom == "http://victim.test:5100/lab/quick-grant?client=Lab+Partner+Demo"


def test_multistep_default_labels() -> None:
    params = parse_run_params(SCENARIOS["multistep"], {}, ORIGINS)
    assert params.decoy_step_labels == ("拆开第 1 个礼盒", "确认收货并领取")


def test_params_as_dict_is_serializable_snapshot() -> None:
    params = parse_run_params(SCENARIOS["clip"], {}, ORIGINS)
    snapshot = params.as_dict()

    assert snapshot["scenario_id"] == "clip"
    assert snapshot["victim_path"] == "/lab/quick-transfer"
    assert snapshot["decoy_step_labels"] == ["拆开第 1 个礼盒", "确认收货并领取"]
