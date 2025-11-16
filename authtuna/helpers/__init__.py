import string

from fastapi import Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from ua_parser import user_agent_parser

from authtuna.core import InvalidEmailError, UserSuspendedError
from authtuna.core.config import settings
from authtuna.core.database import Session as DBSession, User
from authtuna.core.encryption import encryption_utils


async def get_remote_address(request: Request, default_ip: str = "127.0.0.1", use_cf_connecting_ip: bool = True,
                             other_ip_headers: list = None):
    """
    THIS WORKS FOR FASTAPI AS I NEEDED THAT...
    Retrieves the remote address of the client making the request. By default, it
    returns the IP address contained in the `CF-Connecting-IP` header if present.
    If the `CF-Connecting-IP` header is absent, it falls back to the client's
    host IP. If neither a client nor its host IP can be determined, the address
    defaults to `127.0.0.1`.

    :param other_ip_headers: Additional headers to check for the remote IP address ex ["X-Forwarded-For", ... or ur rev proxy hdrs].
    :param use_cf_connecting_ip: Whether to use the `CF-Connecting-IP` header if present.
    :param default_ip: Default IP address to use if the client's host IP cannot be determined.
    :param request: The incoming HTTP request object containing information
        about the client connection.
    :type request: Request
    :return: The remote IP address as a string.
    :rtype: str
    """
    if use_cf_connecting_ip:
        if request.headers.get("CF-Connecting-IP"):
            return request.headers.get("CF-Connecting-IP")
    if other_ip_headers:
        for header in other_ip_headers:
            if request.headers.get(header):
                return request.headers.get(header)
    if not request.client or not request.client.host:
        return default_ip
    return request.client.host


async def get_device_region(request: Request, ip_city_header: str = "CF-IPCity",
                            ip_country_header: str = "CF-IPCountry", default_unfound: str = "Unknown"):
    return request.headers.get(ip_city_header, default_unfound) + ", " + request.headers.get(ip_country_header,
                                                                                             default_unfound)


async def get_device_data(request: Request, region_kwargs=None, ):
    return {
        "device": await user_agent_to_human_readable(request.headers.get("user-agent", "Unknown")),
        "region": await get_device_region(request, **(region_kwargs or {}))
    }


async def is_username_valid(username):
    """
    Check if the provided username adheres to the defined validation rules.

    The function validates that the username meets the following criteria:
    1. It must have at least 3 characters in total.
    2. It does not contain spaces.
    3. It includes only alphanumeric characters and optionally underscores or hyphens.
    4. It contains at least 3 alphabetic characters.

    :param username: The username string to validate.
    :type username: str
    :return: A dictionary with the result of the validation. Returns an empty
        dictionary if valid, otherwise contains error messages indicating
        the specific rule(s) not met.
    :rtype: dict
    """
    if len(username) < 3:
        return {"error": "Username must be at least 3 characters"}
    length = 0
    for char in username:
        if char in ["_", "-"]:
            continue
        if char == " ":
            return {"error": "Username cannot contain spaces"}
        if not char.isalnum():
            return {"error": "Username must contain alphanumeric characters only"}
        if char.isalpha():
            length += 1
    if length < 3:
        return {"error": "Username must have atleast 3 alphabets"}
    return {}


async def is_email_valid(email, raise_on_invalid: bool = True):
    """
    Validates if the given email address ends with one of the allowed domains.

    This function checks whether the email address provided ends with any of the
    domains specified in the application's allowed domain list. If the email
    address does not match the allowed domains, it returns a dictionary containing
    an error message. Otherwise, it returns None, indicating that the email is valid.

    :param raise_on_invalid: Raises InvalidEmailError if email is invalid and raise_on_invalid is True.
    :param email: The email address to validate.
    :type email: str
    :return: A dictionary with an error message if the email is invalid, or None if valid.
    :rtype: dict or None
    """
    email_domain = email.split("@")[1]
    if "*" not in settings.EMAIL_DOMAINS:
        if not any(email_domain == allowed_domain for allowed_domain in settings.EMAIL_DOMAINS):
            emsg = {"error": "Email must end with one of the following domains: " + ", ".join(settings.EMAIL_DOMAINS)}
            if raise_on_invalid:
                raise InvalidEmailError(emsg)
            return emsg
    return None


async def user_agent_to_human_readable(user_agent):
    """
    Converts a user agent string into a human-readable format.

    This asynchronous function parses the user agent string to extract
    details about the user agent's family and the operating system's
    family, then returns a human-readable summary combining this
    information.

    :param user_agent: The user agent string to parse.
    :type user_agent: str
    :return: A human-readable string describing the user agent's family
        and operating system's family.
    :rtype: str
    """
    device = user_agent_parser.Parse(user_agent)
    ua = device["user_agent"]["family"] + " on " + device["os"]["family"]
    return ua


async def is_password_valid(password):
    """
    Validate password complexity:
    - At least 8 characters
    - Contains at least one letter and one number
    - Contains at least one uppercase and one lowercase letter
    Returns {} if valid, otherwise {'error': <message>}.
    """
    if len(password) < 8:
        return {"error": "Password must be at least 8 characters"}
    # If any non-alphanumeric characters are present, fail on letter/number requirement
    if not any(ch.isalnum() for ch in password):
        return {"error": "Password must contain at least one letter and one number"}
    if not any(ch.isupper() for ch in password):
        return {"error": "Password must contain at least one uppercase letter"}
    if not any(ch.islower() for ch in password):
        return {"error": "Password must contain at least one lowercase letter"}
    has_digit = any(ch.isdigit() for ch in password)
    has_alpha = any(ch.isalpha() for ch in password)
    if not (has_digit and has_alpha):
        return {"error": "Password must contain at least one letter and one number"}
    return {}


async def create_session_and_set_cookie(user: User, request: Request, response: Response, db: AsyncSession):
    """
    Helper function to create a new database session, save it, and set the session cookie.
    """
    # if isinstance(db, DatabaseManager):
    if not user.is_active:
        raise UserSuspendedError("This account has been suspended and cannot create new sessions.")
    if True:
        async with db as db:
            device_data = await get_device_data(request)
            new_session = DBSession(
                session_id=encryption_utils.gen_random_string(32),
                user_id=user.id,
                region=device_data["region"],
                device=device_data["device"],
                create_ip=await get_remote_address(request),
                last_ip=await get_remote_address(request)
            )
            db.add(new_session)
            await db.commit()

            response.set_cookie(
                key=settings.SESSION_TOKEN_NAME,
                value=new_session.get_cookie_string(),
                samesite=settings.SESSION_SAME_SITE,
                secure=settings.SESSION_SECURE,
                httponly=True,
                max_age=settings.SESSION_ABSOLUTE_LIFETIME_SECONDS,
                domain=settings.SESSION_COOKIE_DOMAIN,
            )
    else:
        raise ValueError(f"db must be an instance of DatabaseManager, got {type(db)}")

def sanitize_username(username: str) -> str:
    """
    Sanitizes a string to contain only alphanumeric characters.
    Removes spaces and other symbols. Result is capitalized with the rest lowercased.
    """
    if not username:
        return ""
    filtered = "".join(char for char in username if char.isalnum())
    lowered = filtered.lower()
    return lowered.capitalize() if lowered else ""


def generate_random_username(prefix: str = "user") -> str:
    """Generates a random username with an optional prefix."""
    random_string = encryption_utils.gen_random_string(12, string.digits)  # Generate a short, random string
    return f"{prefix}-{random_string}"

def is_permission_name_valid(permission: str) -> bool:
    """
    Validates if the permission name contains only alphanumeric characters, underscores, or hyphens.

    :param permission: The permission name to validate.
    :type permission: str
    :return: True if the permission name is valid, False otherwise.
    :rtype: bool
    """
    for char in permission:
        if not (char.isalnum() or char in ["_", "-", ":"]):
            return False
    return True
