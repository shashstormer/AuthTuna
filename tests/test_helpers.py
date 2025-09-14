import pytest
from authtuna.helpers import is_username_valid, is_email_valid, is_password_valid, sanitize_username, generate_random_username, user_agent_to_human_readable

@pytest.mark.asyncio
async def test_username_validation():
    assert await is_username_valid("ab") == {"error": "Username must be at least 3 characters"}
    assert await is_username_valid("a b c") == {"error": "Username cannot contain spaces"}
    assert await is_username_valid("abc$") == {"error": "Username must contain alphanumeric characters only"}
    assert await is_username_valid("ab1") == {"error": "Username must have atleast 3 alphabets"}
    assert await is_username_valid("abc") == {}
    assert await is_username_valid("abc_123") == {}

@pytest.mark.asyncio
async def test_email_validation():
    assert await is_email_valid("user@example.com") == {"error": "Email must end with one of the following domains: gmail.com"}
    assert await is_email_valid("user@gmail.com") is None

@pytest.mark.asyncio
async def test_password_validation():
    assert await is_password_valid("short") == {"error": "Password must be at least 8 characters"}
    assert await is_password_valid("abcdefgh$") == {"error": "Password must contain at least one letter and one number"}
    assert await is_password_valid("abcdefgh") == {"error": "Password must contain at least one uppercase letter"}
    assert await is_password_valid("ABCDEFGH1") == {"error": "Password must contain at least one lowercase letter"}
    assert await is_password_valid("abcdefgh1") == {"error": "Password must contain at least one uppercase letter"}
    assert await is_password_valid("Abcdefg1") == {}


def test_sanitize_and_generate_username():
    assert sanitize_username("John Doe!") == "Johndoe"
    uname = generate_random_username()
    assert uname.startswith("user-") and len(uname) > 5

@pytest.mark.asyncio
async def test_user_agent_to_human_readable():
    ua = await user_agent_to_human_readable("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
    assert "Chrome" in ua or "Windows" in ua
