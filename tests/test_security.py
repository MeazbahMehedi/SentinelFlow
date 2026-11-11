import pytest

from sentinelflow.accounts import canonical_email
from sentinelflow.security import LoginLimiter, TooManyAttempts


def csrf(client):
    client.get("/")
    with client.session_transaction() as s:
        return s.get("csrf")


def login(app, username, password):
    c = app.test_client()
    c.get("/login")
    with c.session_transaction() as s:
        token = s["csrf"]
    response = c.post(
        "/login", data={"csrf_token": token, "username": username, "password": password}
    )
    return c, response


@pytest.mark.parametrize(
    "address,expected",
    [
        ("Student@Example.COM", "student@example.com"),
        ("first.last+lab@uni.edu.cn", "first.last+lab@uni.edu.cn"),
        ("AN.ALYST+x@googlemail.com", "analyst@gmail.com"),
    ],
)
def test_canonical_email(address, expected):
    assert canonical_email(address) == expected


@pytest.mark.parametrize(
    "address",
    [
        "no-at-sign",
        "a@b",
        "a@@b.com",
        "a..b@example.com",
        "a@-bad.com",
        "a@example.123",
        "<a>@x.com",
    ],
)
def test_invalid_email(address):
    with pytest.raises(ValueError):
        canonical_email(address)


def test_register_with_non_gmail_address(client, app):
    c = app.test_client()
    c.get("/register")
    with c.session_transaction() as s:
        token = s["csrf"]
    r = c.post(
        "/register",
        data={
            "csrf_token": token,
            "username": "researcher",
            "email": "Researcher@Uni.edu",
            "password": "research-password-123",
        },
    )
    assert r.status_code == 302
    assert (
        app.extensions["identities"].one("SELECT email FROM users WHERE username='researcher'")[
            "email"
        ]
        == "researcher@uni.edu"
    )


def test_limiter_blocks_account_after_failures():
    limiter = LoginLimiter(address_limit=100, account_limit=3)
    for _ in range(3):
        limiter.check("1.1.1.1", "user:1")
        limiter.failure("1.1.1.1", "user:1")
    with pytest.raises(TooManyAttempts):
        limiter.check("2.2.2.2", "user:1")
    limiter.check("1.1.1.1", "user:2")


def test_successful_login_does_not_reset_address_budget():
    """Regression: signing in to your own account used to clear the address counter."""
    limiter = LoginLimiter(address_limit=5, account_limit=100)
    for _ in range(5):
        limiter.check("1.1.1.1", "user:victim")
        limiter.failure("1.1.1.1", "user:victim")
        limiter.success("user:attacker")
    with pytest.raises(TooManyAttempts):
        limiter.check("1.1.1.1", "user:victim")


def test_login_throttled_over_http(client, app):
    for _ in range(8):
        _, r = login(app, "analyst", "wrong-password-000")
        assert r.status_code == 200
    _, r = login(app, "analyst", "test-password-12345")
    assert r.status_code == 429


def test_password_change_signs_out_other_browsers(client, token, app):
    other, r = login(app, "analyst", "test-password-12345")
    assert r.status_code == 302 and other.get("/").status_code == 200
    client.post(
        "/settings/password",
        data={
            "csrf_token": token,
            "current_password": "test-password-12345",
            "new_password": "rotated-password-123",
        },
    )
    assert client.get("/").status_code == 200
    assert other.get("/").status_code == 302
    assert other.get("/api/snapshot").status_code == 401


def test_revoke_other_sessions(client, token, app):
    other, _ = login(app, "analyst", "test-password-12345")
    assert other.get("/").status_code == 200
    client.post("/account/sessions/revoke", data={"csrf_token": token})
    assert client.get("/").status_code == 200
    assert other.get("/").status_code == 302


def test_identity_database_holds_no_traffic(client, app):
    tables = {
        r["name"]
        for r in app.extensions["identities"].rows(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert {"users", "profiles"} <= tables
    assert not tables & {"packets", "alerts", "sessions", "replay_packets"}
