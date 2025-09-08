"""
AuthTuna - A high-performance, framework-agnostic authorization and session management library for Python.
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
