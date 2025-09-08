# authtuna/core/exceptions.py (a new file)

class AuthTunaError(Exception):
    """Base exception for the AuthTuna library."""
    pass


class UserAlreadyExistsError(AuthTunaError):
    """Raised when trying to register a user that already exists."""
    pass


class InvalidCredentialsError(AuthTunaError):
    """Raised on login failure due to wrong username/password."""
    pass


class EmailNotVerifiedError(AuthTunaError):
    """Raised when a user tries to log in without a verified email."""
    pass


class UserNotFoundError(AuthTunaError):
    """Raised when a user is not found."""
    pass


class InvalidTokenError(AuthTunaError):
    """Raised when a token is invalid, used, or malformed."""
    pass


class TokenExpiredError(AuthTunaError):
    """
    Raised when a token has expired.
    Contains the new token if one was generated.
    """

    def __init__(self, message, new_token_id=None):
        super().__init__(message)
        self.new_token_id = new_token_id


class RateLimitError(AuthTunaError):
    """Raised when an action is performed too frequently."""
    pass


class SessionNotFoundError(AuthTunaError):
    """Raised when a session ID is not found in the database."""
    pass


class RoleNotFoundError(AuthTunaError):
    """Raised when a role is not found in the database."""
    pass


class PermissionNotFoundError(AuthTunaError):
    """Raised when a permission is not found in the database."""
    pass


class OperationForbiddenError(AuthTunaError):
    """Raised when an operation is forbidden."""
    pass
