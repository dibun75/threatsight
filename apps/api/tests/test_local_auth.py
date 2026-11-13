import pytest

from threatsight_api.config import Settings, get_settings
from threatsight_api.local_auth.passwords import PasswordRejected, hash_password, needs_rehash, validate_password, verify_password


@pytest.fixture(autouse=True)
def _clear_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_passwords_are_bounded_and_not_reversible() -> None:
    with pytest.raises(PasswordRejected):
        validate_password("short-password")
    with pytest.raises(PasswordRejected):
        validate_password("x" * 129)
    with pytest.raises(PasswordRejected):
        validate_password("passwordpassword")
    secret = "a correct horse battery staple"
    encoded = hash_password(secret)
    assert secret not in encoded
    assert encoded.startswith("$argon2id$")
    assert verify_password(secret, encoded) is True
    assert verify_password("a different horse battery staple", encoded) is False
    assert verify_password(secret, None) is False
    assert needs_rehash(encoded) is False
    validate_password("пароль достаточно длинный")


def test_logout_cookie_deletion_is_in_the_past_for_every_variant() -> None:
    from starlette.responses import Response

    from threatsight_api.oidc import expire_browser_cookies, presented_session_tokens

    response = Response(status_code=204)
    expire_browser_cookies(response)
    cookies = [value.decode() for key, value in response.raw_headers if key == b"set-cookie"]
    assert len(cookies) == 9
    assert all("01 Jan 1970" in item and "Max-Age=0" in item and "Path=/" in item for item in cookies)
    assert any(item.startswith('threatsight_session=""') and "HttpOnly" in item and "Secure" not in item for item in cookies)
    assert any(item.startswith("__Host-threatsight_session=") and "Secure" in item and "HttpOnly" in item for item in cookies)
    assert presented_session_tokens("threatsight_session=one; threatsight_session=two; __Host-threatsight_session=three") == ["one", "two", "three"]


def test_production_accepts_only_the_host_cookie() -> None:
    from threatsight_api.oidc import presented_authentication_token

    assert presented_authentication_token(
        {"threatsight_session": "legacy", "__Host-threatsight_session": "current"},
        production=True,
    ) == "current"
    assert presented_authentication_token({"threatsight_session": "legacy"}, production=True) == ""
    assert presented_authentication_token({"threatsight_session": "legacy"}, production=False) == "legacy"


def test_production_login_sets_host_cookies_and_retires_legacy_names(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.responses import JSONResponse

    from threatsight_api.api.local_auth import _cookies

    monkeypatch.setenv("THREATSIGHT_ENV", "production")
    get_settings.cache_clear()
    response = JSONResponse({})
    _cookies(response, "opaque-token")
    cookies = [value.decode() for key, value in response.raw_headers if key == b"set-cookie"]
    live = [item for item in cookies if "Max-Age=0" not in item]
    session = next(item for item in live if item.startswith("__Host-threatsight_session="))
    csrf = next(item for item in live if item.startswith("__Host-threatsight_csrf="))
    assert "Secure" in session and "HttpOnly" in session and "Path=/" in session and "SameSite=lax" in session and "Domain=" not in session
    assert "Secure" in csrf and "HttpOnly" not in csrf and "Domain=" not in csrf
    assert any(item.startswith("threatsight_session=") and "Max-Age=0" in item and "01 Jan 1970" in item for item in cookies)
    assert "opaque-token" not in "\n".join(item for item in cookies if "Max-Age=0" in item)


def test_configured_web_origin_is_a_browser_write_origin() -> None:
    from threatsight_api.authz import allowed_browser_origins

    settings = Settings(cors_origins="http://localhost:3001", web_origins="https://threatsight.io")
    origins = allowed_browser_origins(settings)
    assert "https://threatsight.io" in origins
    assert "http://localhost:3001" in origins
    assert "https://evil.example" not in origins
    with pytest.raises(ValueError, match="THREATSIGHT_WEB_ORIGINS"):
        Settings(web_origins="*").validate_runtime_security()


def test_production_accepts_local_and_rejects_the_public_demo() -> None:
    Settings(
        env="production",
        auth_mode="local",
        database_url="postgresql+psycopg://threatsight:strong-secret@postgres:5432/threatsight",
        cors_origins="https://threatsight.example",
        openapi_enabled=False,
    ).validate_runtime_security()
    with pytest.raises(ValueError, match="local or oidc"):
        Settings(env="production", auth_mode="public_demo", public_demo=True).validate_runtime_security()
    with pytest.raises(ValueError, match="local or oidc"):
        Settings(env="production", auth_mode="development").validate_runtime_security()
