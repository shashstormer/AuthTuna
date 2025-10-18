import pytest
from httpx import AsyncClient
from fastapi import status
from unittest.mock import patch, AsyncMock

@pytest.mark.asyncio
async def test_generate_registration_options(fastapi_client: AsyncClient, authenticated_user):
    """
    Test that the server can generate registration options for an authenticated user.
    """
    with patch('authtuna.integrations.fastapi_integration.get_current_user', return_value=authenticated_user):
        response = await fastapi_client.post("/passkeys/register-options")
        assert response.status_code == status.HTTP_200_OK
        assert "challenge" in response.json()
        assert "rp" in response.json()

# Gonna add more tests later...
# Verifying a successful registration
# Generating options
# Verifying success
