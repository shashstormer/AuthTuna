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

__version__ = "0.0.1"
__author__ = "shashstormer"
__description__ = "A robust, multi-layered security foundation for modern web applications"

from .core.config import settings, init_settings
# Setting was getting insta initialized as soon as module import so commenting out other imports
# from .core.database import DatabaseManager, db_manager, User # Like this module prepares all instances (initialization and other stuff) for connection as soon as import so...
# from .middlewares.session import DatabaseSessionMiddleware
# from .routers import auth_router, social_router

__all__ = [
    "settings",
    "init_settings",
    # "DatabaseManager",
    # "db_manager",
    # "User",
    # "DatabaseSessionMiddleware",
    # "auth_router",
    # "social_router",
]
