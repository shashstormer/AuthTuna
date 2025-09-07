"""
AuthTuna - A high-performance, framework-agnostic authorization and session management library for Python.
"""

__version__ = "0.0.1"
__author__ = "shashstormer"
__description__ = "A robust, multi-layered security foundation for modern web applications"

from .core.database import DatabaseManager, db_manager, User
from .core.config import settings
from .middlewares.session import DatabaseSessionMiddleware
from .routers import auth_router, social_router

__all__ = [
    "DatabaseManager",
    "settings",
    "db_manager",
    "User",
    "DatabaseSessionMiddleware",
    "auth_router",
    "social_router",
]
