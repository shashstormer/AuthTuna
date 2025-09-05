"""
AuthTuna - A high-performance, framework-agnostic authorization and session management library for Python.
"""

__version__ = "0.0.1"
__author__ = "shashstormer"
__description__ = "A robust, multi-layered security foundation for modern web applications"

# from .core.authorizer import Authorizer
# from .core.security import SecurityManager
from .core.database import DatabaseManager
from .core.config import settings
# from .helpers.mailer import Mailer

__all__ = [
    # "Authorizer",
    # "SecurityManager",
    "DatabaseManager",
    "settings",
    # "Mailer"
]
