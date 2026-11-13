from flask.testing import FlaskClient


def test_landing_and_protected_dashboard(victim_client: FlaskClient) -> None:
    landing = victim_client.get("/")
    protected = victim_client.get("/dashboard")

    assert landing.status_code == 200
    assert "点击劫持靶场".encode() in landing.data
    assert protected.status_code == 302
    assert "/login" in protected.headers["Location"]


def test_login_failure_and_success(victim_client: FlaskClient, login) -> None:  # type: ignore[no-untyped-def]
    rejected = login(password="wrong")
    accepted = login()

    assert "用户名或密码错误".encode() in rejected.data
    assert "你好，alice".encode() in accepted.data


def test_profile_email_update(victim_client: FlaskClient, login) -> None:  # type: ignore[no-untyped-def]
    login()
    response = victim_client.post(
        "/profile",
        data={"email": "alice.changed@example.com"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "邮箱已更新".encode() in response.data
    state = victim_client.get(
        "/api/test/state/alice", headers={"X-Websec-Test-Token": "test-token"}
    ).get_json()
    assert state["user"]["email"] == "alice.changed@example.com"


def test_transfer_flow_changes_server_state(victim_client: FlaskClient, login) -> None:  # type: ignore[no-untyped-def]
    login()
    response = victim_client.post(
        "/transfer",
        data={"recipient_username": "bob", "amount": "15.25", "note": "route test"},
        follow_redirects=True,
    )

    assert "模拟转账 #1 已完成".encode() in response.data
    state = victim_client.get(
        "/api/test/state/alice", headers={"X-Websec-Test-Token": "test-token"}
    ).get_json()
    assert state["account"]["balance_cents"] == 98_475
    assert state["transfers"][0]["amount_cents"] == 1525


def test_invalid_transfer_keeps_balance(
    victim_client: FlaskClient, login
) -> None:  # type: ignore[no-untyped-def]
    login()
    response = victim_client.post(
        "/transfer",
        data={"recipient_username": "alice", "amount": "1.00", "note": "invalid"},
        follow_redirects=True,
    )
    assert "不能向自己转账".encode() in response.data

    state = victim_client.get(
        "/api/test/state/alice", headers={"X-Websec-Test-Token": "test-token"}
    ).get_json()
    assert state["account"]["balance_cents"] == 100_000


def test_authorization_create_and_revoke(victim_client: FlaskClient, login) -> None:  # type: ignore[no-untyped-def]
    login()
    created = victim_client.post(
        "/authorizations",
        data={"client_name": "Calendar Demo", "scope": "profile:read"},
        follow_redirects=True,
    )
    assert "权限已记录".encode() in created.data

    state = victim_client.get(
        "/api/test/state/alice", headers={"X-Websec-Test-Token": "test-token"}
    ).get_json()
    grant_id = state["grants"][0]["id"]
    revoked = victim_client.post(f"/authorizations/{grant_id}/revoke", follow_redirects=True)
    assert "授权已撤销".encode() in revoked.data


def test_test_api_requires_token_and_can_reset(victim_client: FlaskClient) -> None:
    assert victim_client.get("/api/test/state/alice").status_code == 403
    assert (
        victim_client.get(
            "/api/test/state/alice", headers={"X-Websec-Test-Token": "wrong"}
        ).status_code
        == 403
    )

    reset = victim_client.post("/api/test/reset", headers={"X-Websec-Test-Token": "test-token"})
    assert reset.status_code == 200
    assert reset.get_json()["seed_users_created"] == 3


def test_health_and_database_readiness(victim_client: FlaskClient) -> None:
    assert victim_client.get("/healthz").get_json()["status"] == "ok"
    readiness = victim_client.get("/readyz")
    assert readiness.status_code == 200
    assert readiness.get_json()["database"] == "available"


def test_audit_page_logout_and_activity_cleanup(
    victim_client: FlaskClient, login
) -> None:  # type: ignore[no-untyped-def]
    login()
    audit = victim_client.get("/audit-log")
    assert audit.status_code == 200
    assert b"session.login" in audit.data

    cleaned = victim_client.post(
        "/delete-data", data={"confirmation": "DELETE"}, follow_redirects=True
    )
    assert "实验活动数据已清理".encode() in cleaned.data

    logged_out = victim_client.post("/logout", follow_redirects=True)
    assert "已退出测试账户".encode() in logged_out.data
    assert "登录测试账户".encode() in logged_out.data


def test_login_honors_safe_local_next(victim_client) -> None:  # type: ignore[no-untyped-def]
    response = victim_client.post(
        "/login",
        query_string={"next": "http://127.0.0.1:5200/demo/classic"},
        data={"username": "alice", "password": "alice-lab"},
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "http://127.0.0.1:5200/demo/classic"


def test_login_rejects_open_redirect_next(victim_client) -> None:  # type: ignore[no-untyped-def]
    response = victim_client.post(
        "/login",
        query_string={"next": "https://evil.example/steal"},
        data={"username": "alice", "password": "alice-lab"},
    )
    assert response.status_code == 302
    assert "evil.example" not in response.headers["Location"]
