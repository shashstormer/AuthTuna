import pytest
from unittest.mock import patch, MagicMock
from authtuna.core.encryption import encryption_utils

@pytest.mark.asyncio
async def test_passkey_registration_flow(fastapi_client, auth_tuna_async, authenticated_user):
    # 1. Login/Session
    session = await auth_tuna_async.sessions.create(authenticated_user.id, "127.0.0.1", "US", "Chrome")
    cookies = {"session_token": session.get_cookie_string()}
    await auth_tuna_async.roles.assign_to_user(authenticated_user.id, "User", assigner_id="system", scope="global")

    # 2. Get Register Options
    response = await fastapi_client.post("/passkeys/register-options", cookies=cookies)
    assert response.status_code == 200
    options = response.json()
    assert "challenge" in options
    assert "user" in options
    assert options["user"]["name"] == authenticated_user.username

    # 3. Register Passkey (Mock verification)
    with patch("authtuna.routers.passkey.auth_service.passkeys.core.verify_registration") as mock_verify:
        # Mock return value of verify_registration
        mock_verify.return_value = {
            "credential_id": b"test_cred_id",
            "public_key": b"test_pub_key",
            "sign_count": 0,
            "aaguid": b"test_aaguid"
        }

        payload = {
            "name": "My Passkey",
            "registration_response": {
                "id": "test_id",
                "rawId": "test_raw_id",
                "response": {},
                "type": "public-key"
            }
        }
        response = await fastapi_client.post("/passkeys/register", json=payload, cookies=cookies)
        assert response.status_code == 201
        assert response.json()["verified"] is True

    # 4. List Passkeys
    response = await fastapi_client.get("/passkeys/", cookies=cookies)
    assert response.status_code == 200
    passkeys = response.json()
    assert len(passkeys) == 1
    assert passkeys[0]["name"] == "My Passkey"

    # 5. Delete Passkey
    cred_id_b64 = passkeys[0]["id"]
    response = await fastapi_client.delete(f"/passkeys/{cred_id_b64}", cookies=cookies)
    assert response.status_code == 204

    # 6. Verify Deleted
    response = await fastapi_client.get("/passkeys/", cookies=cookies)
    assert len(response.json()) == 0

@pytest.mark.asyncio
async def test_passkey_login_flow(fastapi_client, auth_tuna_async, authenticated_user):
    # Setup: Register a passkey directly in DB
    cred_data = {
        "credential_id": b"test_cred_id_login",
        "public_key": b"test_pub_key",
        "sign_count": 0,
        "aaguid": b"test_aaguid"
    }
    await auth_tuna_async.passkeys.save_new_credential(authenticated_user.id, cred_data, "Login Key")

    # 1. Get Login Options
    response = await fastapi_client.post("/passkeys/login-options")
    assert response.status_code == 200
    options = response.json()
    assert "challenge" in options

    # 2. Login with Passkey (Mock verification)
    with patch("authtuna.routers.passkey.auth_service.passkeys.core.verify_authentication") as mock_verify:
        mock_verify.return_value = 1 # New sign count

        payload = {
            "response": {
                "id": encryption_utils.base64url_encode(b"test_cred_id_login"),
                "rawId": "test_raw_id",
                "response": {},
                "type": "public-key"
            }
        }
        # We need to maintain the session cookie for the challenge?
        # No, login-options sets a session cookie (with challenge).
        # We need to pass that cookie back.
        cookies = response.cookies
        
        response = await fastapi_client.post("/passkeys/login", json=payload, cookies=cookies)
        assert response.status_code == 200
        assert "Login successful" in response.json()["message"]
        assert "session_token" in response.cookies
