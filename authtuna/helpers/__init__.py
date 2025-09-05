from fastapi import Request
from ua_parser import user_agent_parser
from authtuna.core.config import settings


async def get_remote_address(request: Request, default_ip: str = "127.0.0.1", use_cf_connecting_ip: bool = True, other_ip_headers: list = None):
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


async def get_device_region(request: Request, ip_city_header: str = "CF-IPCity", ip_country_header: str = "CF-IPCountry", default_unfound: str = "Unknown"):
    return request.headers.get(ip_city_header, default_unfound) + ", " + request.headers.get(ip_country_header, default_unfound)


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


async def is_email_valid(email):
    """
    Validates if the given email address ends with one of the allowed domains.

    This function checks whether the email address provided ends with any of the
    domains specified in the application's allowed domain list. If the email
    address does not match the allowed domains, it returns a dictionary containing
    an error message. Otherwise, it returns None, indicating that the email is valid.

    :param email: The email address to validate.
    :type email: str
    :return: A dictionary with an error message if the email is invalid, or None if valid.
    :rtype: dict or None
    """
    if not any(email.endswith(allowed_domain) for allowed_domain in settings.EMAIL_DOMAINS):
        return {"error": "Email must end with one of the following domains: " + ", ".join(settings.EMAIL_DOMAINS)}
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
    Checks the validity of a given password based on the defined constraints. The function
    ensures the password meets minimum requirements such as length, inclusion of alphanumeric
    characters, and the presence of uppercase and lowercase letters.

    :param password: The password string to validate
    :type password: str
    :return: A dictionary containing the error message if the password is invalid, or an
             empty dictionary if the password meets all requirements
    :rtype: dict
    """
    if len(password) < 8:
        return {"error": "Password must be at least 8 characters"}
    if any(not i.isalnum() for i in password):
        return {"error": "Password must contain at least one letter and one number"}
    if any(i.islower() for i in password):
        return {"error": "Password must contain at least one lowercase letter"}
    if any(i.isupper() for i in password):
        return {"error": "Password must contain at least one uppercase letter"}
    return {}
