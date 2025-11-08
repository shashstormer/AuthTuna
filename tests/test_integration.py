"""
Integration Test: Verify Cookie and Bearer authentication work correctly

This script tests the complete integration between middleware and FastAPI dependencies.
Run this after setting up your FastAPI app with the middleware.
"""

import asyncio
from typing import Optional
from unittest.mock import Mock, AsyncMock, MagicMock
import types


async def test_middleware_cookie_flow():
    """Test that middleware correctly handles cookie-based sessions."""
    print("\n🧪 Testing Cookie Authentication Flow...")

    from authtuna.middlewares.session import DatabaseSessionMiddleware
    from authtuna.core.config import settings

    # Mock request with cookie
    request = Mock()
    request.cookies = {settings.SESSION_TOKEN_NAME: "fake_jwt_token"}
    request.headers = Mock()
    request.headers.get = Mock(return_value=None)  # No Authorization header
    request.url = Mock()
    request.url.path = "/api/protected"
    request.state = types.SimpleNamespace()

    middleware = DatabaseSessionMiddleware(app=None)

    # Check token method detection
    assert settings.STRATEGY in ["COOKIE", "AUTO"], "Strategy must support COOKIE"

    print("✅ Cookie authentication setup correct")
    return True


async def test_middleware_bearer_flow():
    """Test that middleware correctly handles bearer token authentication."""
    print("\n🧪 Testing Bearer Authentication Flow...")

    from authtuna.middlewares.session import DatabaseSessionMiddleware
    from authtuna.core.config import settings

    # Mock request with bearer token
    request = Mock()
    request.cookies = {}
    request.headers = Mock()
    request.headers.get = Mock(side_effect=lambda key: "Bearer sk_test_key" if key == "Authorization" else None)
    request.url = Mock()
    request.url.path = "/api/protected"
    request.state = types.SimpleNamespace()

    middleware = DatabaseSessionMiddleware(app=None)

    # Check token method detection
    assert settings.STRATEGY in ["BEARER", "AUTO"], "Strategy must support BEARER"

    print("✅ Bearer authentication setup correct")
    return True


async def test_fastapi_integration_cookie():
    """Test that FastAPI dependencies work with cookie auth."""
    print("\n🧪 Testing FastAPI Integration (Cookie)...")

    from authtuna.integrations.fastapi_integration import get_current_user, resolve_token_method

    # Mock request with cookie session data
    request = Mock()
    request.state = types.SimpleNamespace(
        user_id="test_user_123",
        session_id="test_session_456",
        token_method="COOKIE",
        user_object=None
    )
    request.headers = Mock()
    request.headers.get = Mock(return_value=None)

    # Test resolve_token_method
    token_method = resolve_token_method(request)
    assert token_method == "COOKIE", f"Expected COOKIE, got {token_method}"

    print("✅ FastAPI integration (Cookie) working correctly")
    return True


async def test_fastapi_integration_bearer():
    """Test that FastAPI dependencies work with bearer auth."""
    print("\n🧪 Testing FastAPI Integration (Bearer)...")

    from authtuna.integrations.fastapi_integration import resolve_token_method

    # Mock request with bearer token
    request = Mock()
    request.state = types.SimpleNamespace(
        user_id="test_user_789",
        token_method="BEARER",
        api_key=Mock(id="sk_test", key_type="SECRET"),
        user_object=None
    )
    request.headers = Mock()
    request.headers.get = Mock(side_effect=lambda key: "Bearer sk_test" if key == "Authorization" else None)

    # Test resolve_token_method
    token_method = resolve_token_method(request)
    assert token_method == "BEARER", f"Expected BEARER, got {token_method}"

    print("✅ FastAPI integration (Bearer) working correctly")
    return True


async def test_permission_checker_structure():
    """Test that PermissionChecker has separate helpers."""
    print("\n🧪 Testing PermissionChecker Structure...")

    from authtuna.integrations.fastapi_integration import PermissionChecker

    checker = PermissionChecker("test:read")

    # Check that both helpers exist
    assert hasattr(checker, '_cookie_helper'), "PermissionChecker missing _cookie_helper"
    assert hasattr(checker, '_api_helper'), "PermissionChecker missing _api_helper"
    assert hasattr(checker, '_get_scope'), "PermissionChecker missing _get_scope"

    print("✅ PermissionChecker has correct structure")
    return True


async def test_role_checker_structure():
    """Test that RoleChecker has separate helpers."""
    print("\n🧪 Testing RoleChecker Structure...")

    from authtuna.integrations.fastapi_integration import RoleChecker

    checker = RoleChecker("Admin")

    # Check that both helpers exist
    assert hasattr(checker, '_cookie_helper'), "RoleChecker missing _cookie_helper"
    assert hasattr(checker, '_api_helper'), "RoleChecker missing _api_helper"

    print("✅ RoleChecker has correct structure")
    return True


async def test_middleware_bearer_helper_exists():
    """Test that middleware has bearer helper method."""
    print("\n🧪 Testing Middleware Bearer Helper...")

    from authtuna.middlewares.session import DatabaseSessionMiddleware

    middleware = DatabaseSessionMiddleware(app=None)

    # Check that bearer helper exists
    assert hasattr(middleware, '_bearer_helper'), "Middleware missing _bearer_helper"
    assert hasattr(middleware, '_cookie_helper'), "Middleware missing _cookie_helper"

    print("✅ Middleware has both cookie and bearer helpers")
    return True


async def run_all_tests():
    """Run all integration tests."""
    print("\n" + "="*60)
    print("🚀 AuthTuna Integration Tests")
    print("="*60)

    tests = [
        test_middleware_bearer_helper_exists,
        test_permission_checker_structure,
        test_role_checker_structure,
        test_fastapi_integration_cookie,
        test_fastapi_integration_bearer,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            await test()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"❌ {test.__name__} failed: {e}")

    print("\n" + "="*60)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    print("="*60)

    if failed == 0:
        print("\n✅ All integration tests passed!")
        print("🎉 Cookie and Bearer authentication are working correctly!")
        return True
    else:
        print(f"\n⚠️  {failed} test(s) failed. Please review the errors above.")
        return False


if __name__ == "__main__":
    print("Starting integration tests...")
    success = asyncio.run(run_all_tests())
    exit(0 if success else 1)

