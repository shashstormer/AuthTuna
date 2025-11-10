"""
AuthTuna
========

A high-performance, async-first authorization and session management library for Python, with first-class FastAPI support.

AuthTuna provides a robust, multi-layered security foundation for modern web applications. It is designed for developers who need to build complex, multi-tenant systems without compromising on security or performance. The library combines a powerful hierarchical permission model with an advanced, stateful session management system to actively defend against a wide range of modern threats.

- FastAPI-first integration: ready-to-use dependencies and session middleware.
- Async SQLAlchemy models and managers for Users, Roles, Permissions, Sessions, Tokens, MFA, Social Accounts.
- Dual-state session model: server-side sessions + JWT cookie with rotating random_string and periodic DB verification.
- Session hijack detection: region/device fingerprint checks, IP tracking, automatic invalidation.
- Extensible RBAC with scoped permissions (e.g., "project:read" with scope_from_path).
- SQL-first design with PostgreSQL and SQLite support.

While the core is framework-agnostic and future adapters are possible, the officially supported and actively maintained integration is FastAPI.
"""

__version__ = "0.1.11"
__author__ = "shashstormer"
__description__ = "A robust, multi-layered security foundation for modern web applications"

import importlib
import threading

from fastapi import FastAPI

from .core.config import settings, init_settings, Theme, ThemeMode


# Was implementing RPC-based middleware so that we will not have to add database conn string on every instance but didnt work, will try again in future.
# def _start_rpc_server_bg():
#     if not settings.RPC_ENABLED:
#         return
#     import asyncio
#     try:
#         server_mod = importlib.import_module('authtuna.rpc.server')
#         serve = getattr(server_mod, 'serve', None)
#         if serve:
#             loop = asyncio.new_event_loop()
#             asyncio.set_event_loop(loop)
#             loop.run_until_complete(serve())
#     except Exception as e:
#         import warnings
#         warnings.warn(f"Failed to auto-start RPC server: {e}")
#
#
# if getattr(settings, 'RPC_AUTOSTART', False):
#     t = threading.Thread(target=_start_rpc_server_bg, daemon=True)
#     t.start()


def init_app(app: FastAPI, session_middleware_kwargs=None):
    """
    New wrapper to initialize AuthTuna with a FastAPI app instance and all routers.
    :param session_middleware_kwargs: {region_kwargs: dict = None,
            public_routes: Union[Set[str], Callable[[Request], bool]] = None,
            raise_errors: bool = False,
            public_docs: bool = True}
    :param app:
    :return:
    """
    from authtuna.routers import admin_router, auth_router, social_router, mfa_router, ui_router, passkey_router, passwordless_router
    from authtuna.middlewares import DatabaseSessionMiddleware
    from starlette.middleware.sessions import SessionMiddleware

    app.add_middleware(DatabaseSessionMiddleware, **(session_middleware_kwargs or {}))
    app.add_middleware(SessionMiddleware, settings.ENCRYPTION_PRIMARY_KEY.get_secret_value())
    if settings.ONLY_MIDDLEWARE:
        return
    app.include_router(auth_router)
    if settings.PASSWORDLESS_LOGIN_ENABLED:
        app.include_router(passwordless_router)
    app.include_router(social_router)
    if settings.MFA_ENABLED:
        app.include_router(mfa_router)
    if settings.ADMIN_ROUTES_ENABLED:
        app.include_router(admin_router)
    if settings.UI_ENABLED:
        app.include_router(ui_router)
    if settings.PASSKEYS_ENABLED:
        app.include_router(passkey_router)


__all__ = [
    "settings",
    "init_settings",
    "init_app"
]
