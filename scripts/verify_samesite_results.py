"""Independently audit complete HTTPS matrix artifacts and business-state evidence."""

import argparse
import csv
import json
from itertools import product
from pathlib import Path


def verify(output: Path, repeats: int = 3) -> dict:
    rows = json.loads((output / "results.json").read_text(encoding="utf-8"))
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    with (output / "results.csv").open(encoding="utf-8-sig", newline="") as handle:
        csv_rows = list(csv.DictReader(handle))
    profiles = {
        "https-samesite-strict": "Strict",
        "https-samesite-lax": "Lax",
        "https-samesite-none": "None",
        "samesite-none": "insecure",
    }
    dimensions = ("browser", "profile", "relation", "third_party_policy", "repeat")
    expected_keys = set(
        product(
            ("chrome", "msedge"),
            profiles,
            ("same-site", "cross-site"),
            ("allow", "block"),
            range(1, repeats + 1),
        )
    )
    keys = [tuple(row[k] for k in dimensions) for row in rows]
    assert len(rows) == len(set(keys)) == len(expected_keys), "Missing or duplicate cases"
    assert set(keys) == expected_keys, "Unexpected matrix dimensions"
    assert summary["rows"] == summary["passed"] == len(rows) and summary["failed"] == 0
    assert summary["certificate_errors_ignored"] is False
    assert len(csv_rows) == len(rows)
    for row, csv_row in zip(rows, csv_rows, strict=True):
        label = "-".join(str(row[k]) for k in dimensions)
        kind = profiles[row["profile"]]
        secure = kind != "insecure"
        same_site = row["relation"] == "same-site"
        expect_frame = secure and (
            same_site or (kind == "None" and row["third_party_policy"] == "allow")
        )
        expect_top = secure and (same_site or kind in {"Lax", "None"})
        assert row["ok"] is True and "error" not in row, label
        assert row["tls_verified"] is True, label
        assert row["cookie_stored"] is secure, label
        if secure:
            attributes = row["cookie_attributes"]
            assert attributes == {
                "sameSite": kind,
                "secure": True,
                "httpOnly": True,
                "domain": "victim.test",
            }, label
        for key in ("authenticated", "session_cookie_sent", "attack_triggered"):
            assert row[key] is expect_frame, (label, key)
        observation = row["session_observation"]
        assert observation["scheme"] == "https", label
        assert observation["sec_fetch_site"] == row["relation"], label
        assert observation["authenticated"] is expect_frame, label
        assert observation["session_cookie_present"] is expect_frame, label
        assert row["transfer_delta"] == (1 if expect_frame else 0), label
        assert row["balance_delta_cents"] == (-123 if expect_frame else 0), label
        top = row["top_level_observation"]
        assert row["top_level_authenticated"] is expect_top, label
        assert top["authenticated"] is expect_top, label
        assert top["session_cookie_present"] is expect_top, label
        assert top["sec_fetch_site"] == row["relation"], label
        assert top["scheme"] == "https", label
        assert row["click_surface"] == "victim-frame", label
        assert row["attack_opacity"] == 0.01, label
        reasons = {
            reason
            for request in row["cookie_network_evidence"]
            for cookie in request["cookies"]
            for reason in cookie["blocked_reasons"]
        }
        rejected = {
            reason for item in row["rejected_cookies"] for reason in item["blocked_reasons"]
        }
        if kind == "insecure":
            assert "SameSiteNoneInsecure" in rejected, label
        if not same_site and row["third_party_policy"] == "allow" and kind in {"Strict", "Lax"}:
            assert f"SchemefulSameSite{kind}" in reasons, (label, reasons)
        if not same_site and kind == "None" and row["third_party_policy"] == "block":
            assert "UserPreferences" in reasons, (label, reasons)
        evidence = output / "evidence" / label
        assert json.loads((evidence / "result.json").read_text(encoding="utf-8")) == row, label
        for filename in ("session.png", "before-click.png", "attack.png", "top-level.png"):
            assert (evidence / filename).stat().st_size > 0, (label, filename)
        for field, value in csv_row.items():
            assert value == str(row.get(field, "")), (label, field)
    result = {
        "rows_verified": len(rows),
        "checks": [
            "complete unique matrix",
            "TLS and stored cookie attributes",
            "iframe and top-level server observations",
            "exact business deltas",
            "browser blocking reasons",
            "JSON/CSV consistency",
            "four screenshots per case",
        ],
        "passed": True,
    }
    (output / "verification.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("artifacts/samesite-https"))
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    print(json.dumps(verify(args.out, args.repeats), indent=2))
