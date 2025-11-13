from typing import Optional, Literal

from fastapi import Depends, HTTPException, status, Request

from authtuna import settings
from authtuna.core.database import User, db_manager
from authtuna.manager.asynchronous import AuthTunaAsync

# The primary asynchronous service used by FastAPI dependencies.
auth_service = AuthTunaAsync(db_manager)


async def get_current_user(request: Request, allow_public_key=False) -> User:
    """
    FastAPI dependency that retrieves the current user based on the user_id
    populated by the session middleware.

    Supports both COOKIE sessions (middleware-populated request.state.user_id)
    and BEARER API keys. For BEARER, validates the API key and caches the
    ApiKey object at request.state.api_key and the user object at
    request.state.user_object.
    """
    if hasattr(request.state, "user_object") and request.state.user_object is not None:
        return request.state.user_object

    # Determine token method: prefer explicit state but infer when missing for backwards compatibility
    token_method = getattr(request.state, 'token_method', None)
    user_id = getattr(request.state, "user_id", None)
    # COOKIE-backed session path
    if token_method == "COOKIE":
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        try:
            user = await auth_service.users.get_by_id(user_id, with_relations=True)
            if not user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found for this session")
            request.state.user_object = user
            return user
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Could not retrieve user: {e}")

    # BEARER token path
    if token_method == "BEARER":
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        token = auth_header.split(" ", 1)[1]
        if not allow_public_key:
            if token.startswith(settings.API_KEY_PREFIX_PUBLISHABLE):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Publishable API keys cannot be used for this request")
        try:
            api_key = await auth_service.api.validate_key(token)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
        if not api_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
        # Cache api_key and load user
        request.state.api_key = api_key
        user = await auth_service.users.get_by_id(api_key.user_id, with_relations=True)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found for this API key")
        request.state.user_object = user
        return user

    # If token_method is None or unrecognized
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


async def get_current_user_optional(request: Request) -> Optional[User]:
    """
    Does the exact same thing as get current user but doesn't throw error if not authenticated.
    :param request:
    :return:
    """
    try:
        return await get_current_user(request)
    except HTTPException as e:
        # Treat both explicit 'Not authenticated' and invalid api key as unauthenticated
        if e.detail in ("Not authenticated", "Invalid API key"):
            return None
        raise



def get_user_ip(request: Request) -> str:
    """
    If you using this obvio you have included the session middleware which sets this so ...
    """
    return request.state.user_ip_address


def get_scope_helper(request: Request, scope_from_path: Optional[str], raise_error: bool, scope_prefix: Optional[str]) -> str:
    """Helper to extract scope from request path parameters."""
    scope = "global"
    if scope_from_path:
        path_param_value = request.path_params.get(scope_from_path)
        if not path_param_value:
            if raise_error:
                raise HTTPException(
                        status_code=500,
                        detail=f"Scope parameter '{scope_from_path}' not found in URL path."
                    )
            return None
        prefix = scope_prefix or scope_from_path.replace('_id', '')
        scope = f"{prefix}:{path_param_value}"
    elif scope_prefix:
        scope = scope_prefix
    return scope


class PermissionChecker:
    """
    A dependency factory class for checking user permissions. This class relies on the
    efficient `has_permission` method in the service layer.
    """

    def __init__(
            self,
            *permissions: str,
            mode: Literal['AND', 'OR'] = 'AND',
            scope_prefix: Optional[str] = None,
            scope_from_path: Optional[str] = None,
            raise_error: bool = True
    ):
        self.permissions = permissions
        self.mode = mode
        self.scope_prefix = scope_prefix
        self.scope_from_path = scope_from_path
        self.raise_error = raise_error

    def _get_scope(self, request) -> Optional[str]:
        """Helper to extract scope from request path parameters."""
        return get_scope_helper(
            request=request,
            scope_from_path=self.scope_from_path,
            raise_error=self.raise_error,
            scope_prefix=self.scope_prefix
        )

    async def _cookie_helper(self, request: Request, user: User) -> Optional[User]:
        """Handle permission checks for COOKIE-based authentication."""
        if not user:
            if self.raise_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                )
            return None

        scope = self._get_scope(request)
        if scope is None:
            return None

        # Use the normal has_permission which checks the user's roles
        if self.mode == 'AND':
            for perm in self.permissions:
                has_perm = await auth_service.roles.has_permission(user.id, perm, scope)
                if not has_perm:
                    if self.raise_error:
                        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing required permission: '{perm}'")
                    return None
        else:  # OR
            has_at_least_one_perm = False
            for perm in self.permissions:
                if await auth_service.roles.has_permission(user.id, perm, scope):
                    has_at_least_one_perm = True
                    break
            if not has_at_least_one_perm:
                if self.raise_error:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"User must have at least one of: {', '.join(self.permissions)}")
                return None
        return user

    async def _api_helper(self, request: Request, user: User) -> Optional[User]:
        """Handle permission checks for BEARER token (API key) authentication."""
        if not user:
            if self.raise_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                )
            return None

        scope = self._get_scope(request)
        if scope is None:
            return None

        # Ensure api_key is loaded
        api_key = getattr(request.state, 'api_key', None)
        if not api_key:
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                if self.raise_error:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
                return None
            token = auth_header.split(" ", 1)[1]
            api_key = await auth_service.api.validate_key(token)
            if not api_key:
                if self.raise_error:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
                return None
            request.state.api_key = api_key

        # Dynamic master key handling: treat MASTER keys like COOKIE sessions (evaluate user's current roles/permissions)
        if getattr(api_key, 'key_type', '').upper() == 'MASTER':
            # Use the same permission resolution as COOKIE users (dynamic based on user's current roles)
            if self.mode == 'AND':
                for perm in self.permissions:
                    has_perm = await auth_service.roles.has_permission(user.id, perm, scope)
                    if not has_perm:
                        if self.raise_error:
                            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing required permission: '{perm}'")
                        return None
            else:  # OR
                has_at_least_one_perm = False
                for perm in self.permissions:
                    if await auth_service.roles.has_permission(user.id, perm, scope):
                        has_at_least_one_perm = True
                        break
                if not has_at_least_one_perm:
                    if self.raise_error:
                        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"User must have at least one of: {', '.join(self.permissions)}")
                    return None
            return user

        # Build a set of scopes granted to the key
        key_scopes = {s.scope for s in api_key.api_key_scopes}

        async def key_has_permission(perm_name: str) -> bool:
            # Check each candidate scope derived from requested scope (including global)
            candidates = ['global']
            parts = []
            if scope and scope != 'global':
                parts = scope.split('/') if '/' in scope else [scope]
            # Build paths similar to has_permission
            if parts:
                current = ''
                for p in parts:
                    current = f"{current}/{p}" if current else p
                    candidates.append(current)
            # For each candidate scope, ensure the key grants it and the user actually has the permission in that scope
            for cand in candidates:
                if cand in key_scopes:
                    # user has role with perm in that scope? re-use existing has_permission check restricted to exact scope
                    if await auth_service.roles.has_permission(user.id, perm_name, cand):
                        return True
            return False

        if self.mode == 'AND':
            for perm in self.permissions:
                if not await key_has_permission(perm):
                    if self.raise_error:
                        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing required permission: '{perm}'")
                    return None
        else:  # OR
            ok = False
            for perm in self.permissions:
                if await key_has_permission(perm):
                    ok = True
                    break
            if not ok:
                if self.raise_error:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"User must have at least one of: {', '.join(self.permissions)}")
                return None
        return user

    async def __call__(self, request: Request, user: User = Depends(get_current_user_optional)) -> Optional[User]:
        token_method = resolve_token_method(request)
        if token_method == "COOKIE":
            return await self._cookie_helper(request, user)
        elif token_method == "BEARER":
            return await self._api_helper(request, user)
        # Default deny
        if self.raise_error:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return None



class RoleChecker:
    """
    A dependency factory for checking if a user has specific roles.

    This implementation prefers a pre-loaded user object on request.state (as set by
    middleware or another dependency). If unavailable, it falls back to fetching the
    user by request.state.user_id. If neither is present, it raises 401.
    """

    def __init__(self, *roles: str,
                 mode: Literal['AND', 'OR'] = 'AND',
                 scope_prefix: Optional[str] = None,
                 scope_from_path: Optional[str] = None,
                 raise_error: bool = True):
        self.roles = set(roles)
        self.mode = mode
        self.scope_prefix = scope_prefix
        self.scope_from_path = scope_from_path
        self.raise_error = raise_error

    def _get_scope(self, request) -> Optional[str]:
        """Helper to extract scope from request path parameters."""
        return get_scope_helper(
            request=request,
            scope_from_path=self.scope_from_path,
            raise_error=self.raise_error,
            scope_prefix=self.scope_prefix
        )

    async def _cookie_helper(self, request: Request) -> Optional[User]:
        """Handle role checks for COOKIE-based authentication."""
        if self.raise_error:
            user = await get_current_user(request)
        else:
            user = await get_current_user_optional(request)
            if user is None:
                return None

        scope = self._get_scope(request)
        if scope is None:
            return None

        # Cache role id->name mapping
        request.state.id_role_map = {}
        role_id_to_name = {r.id: r.name for r in user.roles}
        request.state.id_role_map.update(role_id_to_name)

        # Build candidate scopes: global + hierarchical paths
        candidates = ['global']
        if scope and scope != 'global':
            parts = scope.split('/') if '/' in scope else [scope]
            current = ''
            for p in parts:
                current = f"{current}/{p}" if current else p
                candidates.append(current)

        def user_has_role_in_scope(role_name: str) -> bool:
            for cand in candidates:
                for assoc in user.role_associations:
                    if assoc.scope == cand:
                        name = role_id_to_name.get(assoc.role_id)
                        if name == role_name:
                            return True
            return False

        if self.mode == 'AND':
            for required in self.roles:
                if not user_has_role_in_scope(required):
                    if self.raise_error:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"User must have all roles: {', '.join(self.roles)}"
                        )
                    return None
        else:  # OR
            if not any(user_has_role_in_scope(required) for required in self.roles):
                if self.raise_error:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"User lacks required role(s). Requires at least one of: {', '.join(self.roles)}"
                    )
                return None
        request.state.user_object = user
        return user

    async def _api_helper(self, request: Request) -> Optional[User]:
        """Handle role checks for BEARER token (API key) authentication."""
        if self.raise_error:
            user = await get_current_user(request)
        else:
            user = await get_current_user_optional(request)
            if user is None:
                return None

        # Ensure api_key is loaded
        api_key = getattr(request.state, 'api_key', None)
        if not api_key:
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                if self.raise_error:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
                return None
            token = auth_header.split(" ", 1)[1]
            api_key = await auth_service.api.validate_key(token)
            if not api_key:
                if self.raise_error:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
                return None
            request.state.api_key = api_key

        scope = self._get_scope(request)
        if scope is None:
            return None
        candidates = ['global']
        if scope and scope != 'global':
            parts = scope.split('/') if '/' in scope else [scope]
            current = ''
            for p in parts:
                current = f"{current}/{p}" if current else p
                candidates.append(current)
        async with db_manager.get_db() as db:
            role_scope_list = await api_key.load_scope_role_names(db)

        role_scope_pairs = {
            (rs['role_name'], rs['scope'])
            for rs in role_scope_list
            if rs.get('role_name') and rs.get('scope') is not None
        }

        def api_role_has_name(role_name: str) -> bool:
            for cand in candidates:
                if (role_name, cand) in role_scope_pairs:
                    return True
            return False

        if self.mode == 'OR':
            for required in self.roles:
                if api_role_has_name(required):
                    request.state.user_object = user
                    return user
            if self.raise_error:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"User lacks required role(s). Requires at least one of: {', '.join(self.roles)}"
                )
            return None
        else:
            for required in self.roles:
                if not api_role_has_name(required):
                    if self.raise_error:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"User lacks required role(s). Requires: {', '.join(self.roles)}"
                        )
                    return None
            request.state.user_object = user
            return user

    async def __call__(self, request: Request) -> Optional[User]:
        token_method = resolve_token_method(request)
        if token_method == "COOKIE":
            return await self._cookie_helper(request)
        elif token_method == "BEARER":
            return await self._api_helper(request)
        # default deny
        if self.raise_error:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return None


def resolve_token_method(request: Request) -> Optional[str]:
    """Infer and cache the token method (COOKIE or BEARER) on the request.state.
    Gracefully handles when middleware didn't set it (e.g., in unit tests).
    """
    return getattr(request.state, 'token_method', None)
