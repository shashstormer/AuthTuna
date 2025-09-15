from unittest.mock import Mock
from authtuna.helpers import (
    get_remote_address,
    get_device_data,
    is_username_valid,
    is_password_valid,
    sanitize_username,
)
import pytest


@pytest.mark.asyncio
async def test_get_remote_address():
    """Tests for various IP address headers."""
    # Test with Cloudflare header
    request = Mock(headers={"CF-Connecting-IP": "192.168.1.1"}, client=None)
    assert await get_remote_address(request) == "192.168.1.1"

    # Test with X-Forwarded-For header
    request = Mock(headers={"X-Forwarded-For": "203.0.113.1"}, client=None)
    assert await get_remote_address(request, other_ip_headers=["X-Forwarded-For"]) == "203.0.113.1"

    # Test fallback to client host
    request = Mock(headers={}, client=Mock(host="127.0.0.1"))
    assert await get_remote_address(request) == "127.0.0.1"

    # Test default IP
    request = Mock(headers={}, client=None)
    assert await get_remote_address(request) == "127.0.0.1"

@pytest.mark.asyncio
async def test_get_device_data():
    """Test device data parsing."""
    headers = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        "CF-IPCity": "Mountain View",
        "CF-IPCountry": "US",
    }
    request = Mock(headers=headers)
    device_data = await get_device_data(request)
    assert device_data["device"] == "Chrome on Windows"
    assert device_data["region"] == "Mountain View, US"

@pytest.mark.asyncio
async def test_is_username_valid():
    assert await is_username_valid("validuser") == {}
    assert "error" in await is_username_valid("sh")
    assert "error" in await is_username_valid("with space")
    assert "error" in await is_username_valid("invalid!")
    assert {} == await is_username_valid("axa_y")


@pytest.mark.asyncio
async def test_is_password_valid():
    assert await is_password_valid("ValidPass1") == {}
    assert "error" in await is_password_valid("short")
    assert "error" in await is_password_valid("nouppercase")
    assert "error" in await is_password_valid("NOLOWERCASE")
    assert "error" in await is_password_valid("")

def test_sanitize_username():
    assert sanitize_username(" User With Spaces ") == "Userwithspaces"
    assert sanitize_username("user-123_test") == "User123test"
    assert sanitize_username("!@#$%^&*()") == ""
