import grpc
from concurrent import futures
import os
import asyncio
from authtuna.rpc import authtuna_pb2, authtuna_pb2_grpc
from authtuna.core.encryption import EncryptionUtils
from authtuna.core.config import settings
from authtuna.core.database import DatabaseManager, User
from authtuna.manager.asynchronous import UserManager, RoleManager, PermissionManager, SessionManager, TokenManager, AuditManager
from authtuna.core.mfa import MFAManager

# Use config for secure token and address
RPC_AUTH_TOKEN = settings.RPC_TOKEN.get_secret_value()
RPC_ADDRESS = settings.RPC_ADDRESS
RPC_TLS_CERT_FILE = settings.RPC_TLS_CERT_FILE
RPC_TLS_KEY_FILE = settings.RPC_TLS_KEY_FILE

encryption_utils = EncryptionUtils()

def user_to_proto(user: User):
    if not user:
        return None
    return authtuna_pb2.User(
        id=user.id or "",
        username=user.username or "",
        email=user.email or "",
        mfa_enabled=getattr(user, "mfa_enabled", False),
        suspended=not getattr(user, "is_active", True),
    )

def role_to_proto(role):
    if not role:
        return None
    return authtuna_pb2.Role(
        id=getattr(role, 'id', ''),
        name=getattr(role, 'name', ''),
        description=getattr(role, 'description', ''),
        system=getattr(role, 'system', False),
        level=getattr(role, 'level', 0),
    )

def permission_to_proto(permission):
    if not permission:
        return None
    return authtuna_pb2.Permission(
        id=getattr(permission, 'id', ''),
        name=getattr(permission, 'name', ''),
        description=getattr(permission, 'description', ''),
    )

def session_to_proto(session):
    if not session:
        return None
    return authtuna_pb2.Session(
        session_id=getattr(session, 'session_id', ''),
        user_id=getattr(session, 'user_id', ''),
        create_ip=getattr(session, 'create_ip', ''),
        last_ip=getattr(session, 'last_ip', ''),
        region=getattr(session, 'region', ''),
        device=getattr(session, 'device', ''),
        active=getattr(session, 'active', False),
    )

def token_to_proto(token):
    if not token:
        return None
    return authtuna_pb2.Token(
        id=getattr(token, 'id', ''),
        user_id=getattr(token, 'user_id', ''),
        purpose=getattr(token, 'purpose', ''),
        etime=getattr(token, 'etime', 0.0),
        used=getattr(token, 'used', False),
    )

def audit_event_to_proto(event):
    if not event:
        return None
    return authtuna_pb2.AuditEvent(
        id=getattr(event, 'id', ''),
        user_id=getattr(event, 'user_id', ''),
        event_type=getattr(event, 'event_type', ''),
        timestamp=getattr(event, 'timestamp', 0.0),
        ip_address=getattr(event, 'ip_address', ''),
        details=str(getattr(event, 'details', '')),
    )

# Initialize real DB manager and user manager
_db_manager = DatabaseManager()
_user_manager = UserManager(_db_manager)
# Initialize all managers
_role_manager = RoleManager(_db_manager)
_permission_manager = PermissionManager(_db_manager)
_session_manager = SessionManager(_db_manager)
_token_manager = TokenManager(_db_manager)
_audit_manager = AuditManager(_db_manager)
_mfa_manager = MFAManager(_db_manager)

class AuthTunaService(authtuna_pb2_grpc.AuthTunaServiceServicer):
    def Authenticate(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        user = loop.run_until_complete(_user_manager.get_by_username(request.username))
        if user and EncryptionUtils.verify_password(request.password, user.password_hash):
            token = encryption_utils.create_jwt_token({"username": user.username, "email": user.email, "mfa_enabled": user.mfa_enabled})
            return authtuna_pb2.AuthResponse(token=token, error="")
        return authtuna_pb2.AuthResponse(token="", error="Invalid credentials.")

    def GetUserInfo(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        payload = encryption_utils.decode_jwt_token(request.token)
        if payload:
            return authtuna_pb2.UserInfoResponse(username=payload["username"], email=payload["email"], mfa_enabled=payload["mfa_enabled"], error="")
        return authtuna_pb2.UserInfoResponse(username="", email="", mfa_enabled=False, error="Invalid token.")

    def GetUserById(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        user = loop.run_until_complete(_user_manager.get_by_id(request.id))
        if user:
            return authtuna_pb2.UserResponse(user=user_to_proto(user), error="")
        return authtuna_pb2.UserResponse(user=None, error="User not found.")

    def GetUserByEmail(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        user = loop.run_until_complete(_user_manager.get_by_email(request.email))
        if user:
            return authtuna_pb2.UserResponse(user=user_to_proto(user), error="")
        return authtuna_pb2.UserResponse(user=None, error="User not found.")

    def CreateUser(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        try:
            user = loop.run_until_complete(_user_manager.create(
                email=request.email,
                username=request.username,
                password=request.password,
                ip_address="rpc-server"
            ))
            return authtuna_pb2.UserResponse(user=user_to_proto(user), error="")
        except Exception as e:
            return authtuna_pb2.UserResponse(user=None, error=str(e))

    def UpdateUser(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        update_data = {}
        if request.username:
            update_data["username"] = request.username
        if request.email:
            update_data["email"] = request.email
        if request.password:
            update_data["password"] = request.password
        try:
            user = loop.run_until_complete(_user_manager.update(request.id, update_data, ip_address="rpc-server"))
            return authtuna_pb2.UserResponse(user=user_to_proto(user), error="")
        except Exception as e:
            return authtuna_pb2.UserResponse(user=None, error=str(e))

    def DeleteUser(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(_user_manager.delete(request.id, ip_address="rpc-server"))
            return authtuna_pb2.UserResponse(user=None, error="")
        except Exception as e:
            return authtuna_pb2.UserResponse(user=None, error=str(e))

    def SuspendUser(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        try:
            user = loop.run_until_complete(_user_manager.suspend_user(request.id, request.admin_id, request.reason))
            return authtuna_pb2.UserResponse(user=user_to_proto(user), error="")
        except Exception as e:
            return authtuna_pb2.UserResponse(user=None, error=str(e))

    def UnsuspendUser(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        try:
            user = loop.run_until_complete(_user_manager.unsuspend_user(request.id, request.admin_id, request.reason))
            return authtuna_pb2.UserResponse(user=user_to_proto(user), error="")
        except Exception as e:
            return authtuna_pb2.UserResponse(user=None, error=str(e))

    def ListUsers(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        users = loop.run_until_complete(_user_manager.list(skip=request.skip, limit=request.limit))
        return authtuna_pb2.UserListResponse(users=[user_to_proto(u) for u in users if u], error="")

    def SearchUsers(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        users = loop.run_until_complete(_user_manager.basic_search_users(identity=request.identity, skip=request.skip, limit=request.limit))
        return authtuna_pb2.UserListResponse(users=[user_to_proto(u) for u in users if u], error="")

    def GetAllRoles(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        roles = loop.run_until_complete(_role_manager.get_all_roles())
        return authtuna_pb2.RoleListResponse(roles=[role_to_proto(r) for r in roles if r], error="")

    def GetRoleByName(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        role = loop.run_until_complete(_role_manager.get_by_name(request.name))
        if role:
            return authtuna_pb2.RoleResponse(role=role_to_proto(role), error="")
        return authtuna_pb2.RoleResponse(role=None, error="Role not found.")

    def CreateRole(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        try:
            role = loop.run_until_complete(_role_manager.create(
                name=request.name,
                description=request.description,
                system=request.system,
                level=request.level if request.level else None
            ))
            return authtuna_pb2.RoleResponse(role=role_to_proto(role), error="")
        except Exception as e:
            return authtuna_pb2.RoleResponse(role=None, error=str(e))

    def AssignRoleToUser(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(_role_manager.assign_to_user(
                user_id=request.user_id,
                role_name=request.role_name,
                assigner_id=request.assigner_id,
                scope=request.scope or 'none'
            ))
            return authtuna_pb2.RoleResponse(role=None, error="")
        except Exception as e:
            return authtuna_pb2.RoleResponse(role=None, error=str(e))

    def RemoveRoleFromUser(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(_role_manager.remove_from_user(
                user_id=request.user_id,
                role_name=request.role_name,
                remover_id=request.remover_id,
                scope=request.scope or 'none'
            ))
            return authtuna_pb2.RoleResponse(role=None, error="")
        except Exception as e:
            return authtuna_pb2.RoleResponse(role=None, error=str(e))

    def GetUsersForRole(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        users = loop.run_until_complete(_role_manager.get_users_for_role(request.name))
        # users is a list of dicts with username and scope
        user_objs = []
        for u in users:
            # Only username and scope, so create a minimal User proto
            user_objs.append(authtuna_pb2.User(username=u.get('username', ''), id='', email='', mfa_enabled=False, suspended=False))
        return authtuna_pb2.UserListResponse(users=user_objs, error="")

    def GetPermissionByName(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        permission = loop.run_until_complete(_permission_manager.get_by_name(request.name))
        if permission:
            return authtuna_pb2.PermissionResponse(permission=permission_to_proto(permission), error="")
        return authtuna_pb2.PermissionResponse(permission=None, error="Permission not found.")

    def CreatePermission(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        try:
            permission = loop.run_until_complete(_permission_manager.create(
                name=request.name,
                description=request.description
            ))
            return authtuna_pb2.PermissionResponse(permission=permission_to_proto(permission), error="")
        except Exception as e:
            return authtuna_pb2.PermissionResponse(permission=None, error=str(e))

    def GetSessionById(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        session = loop.run_until_complete(_session_manager.get_by_id(request.session_id))
        if session:
            return authtuna_pb2.SessionResponse(session=session_to_proto(session), error="")
        return authtuna_pb2.SessionResponse(session=None, error="Session not found.")

    def CreateSession(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        try:
            session = loop.run_until_complete(_session_manager.create(
                user_id=request.user_id,
                ip_address=request.create_ip,
                region=request.region,
                device=request.device
            ))
            return authtuna_pb2.SessionResponse(session=session_to_proto(session), error="")
        except Exception as e:
            return authtuna_pb2.SessionResponse(session=None, error=str(e))

    def TerminateSession(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        try:
            result = loop.run_until_complete(_session_manager.terminate(request.session_id, ip_address="rpc-server"))
            return authtuna_pb2.SessionResponse(session=None, error="" if result else "Session not found or already terminated.")
        except Exception as e:
            return authtuna_pb2.SessionResponse(session=None, error=str(e))

    def ListSessionsForUser(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        sessions = loop.run_until_complete(_session_manager.get_all_for_user(request.id, session_id=""))
        return authtuna_pb2.SessionListResponse(sessions=[session_to_proto(s) for s in sessions if s], error="")

    def CreateToken(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        try:
            token = loop.run_until_complete(_token_manager.create(
                user_id=request.user_id,
                purpose=request.purpose,
                expiry_seconds=int(request.etime) if request.etime else None
            ))
            return authtuna_pb2.TokenResponse(token=token_to_proto(token), error="")
        except Exception as e:
            return authtuna_pb2.TokenResponse(token=None, error=str(e))

    def ValidateToken(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        from sqlalchemy.ext.asyncio import AsyncSession
        try:
            # Validate expects a db session, so we create one
            async def validate():
                async with _db_manager.get_db() as db:
                    user = await _token_manager.validate(db, request.id, request.purpose, ip_address="rpc-server")
                    return user
            user = loop.run_until_complete(validate())
            return authtuna_pb2.UserResponse(user=user_to_proto(user), error="")
        except Exception as e:
            return authtuna_pb2.UserResponse(user=None, error=str(e))

    def GetEventsForUser(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        events = loop.run_until_complete(_audit_manager.get_events_for_user(request.user_id, skip=request.skip, limit=request.limit))
        return authtuna_pb2.AuditEventListResponse(events=[audit_event_to_proto(e) for e in events if e], error="")

    def GetEventsByType(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        events = loop.run_until_complete(_audit_manager.get_events_by_type(request.event_type, skip=request.skip, limit=request.limit))
        return authtuna_pb2.AuditEventListResponse(events=[audit_event_to_proto(e) for e in events if e], error="")

    def SetupTOTP(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        user = loop.run_until_complete(_user_manager.get_by_id(request.user_id))
        if not user:
            return authtuna_pb2.MFASetupResponse(secret="", uri="", error="User not found.")
        try:
            secret, uri = loop.run_until_complete(_mfa_manager.setup_totp(user, request.issuer_name))
            return authtuna_pb2.MFASetupResponse(secret=secret, uri=uri, error="")
        except Exception as e:
            return authtuna_pb2.MFASetupResponse(secret="", uri="", error=str(e))

    def VerifyAndEnableTOTP(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        user = loop.run_until_complete(_user_manager.get_by_id(request.user_id))
        if not user:
            return authtuna_pb2.MFAResponse(success=False, error="User not found.")
        try:
            result = loop.run_until_complete(_mfa_manager.verify_and_enable_totp(user, request.code))
            return authtuna_pb2.MFAResponse(success=True, error="" if not result else ", ".join(result))
        except Exception as e:
            return authtuna_pb2.MFAResponse(success=False, error=str(e))

    def DisableMFA(self, request, context):
        if not self._is_authorized(context):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid RPC token.")
        loop = asyncio.get_event_loop()
        user = loop.run_until_complete(_user_manager.get_by_id(request.id))
        if not user:
            return authtuna_pb2.MFAResponse(success=False, error="User not found.")
        try:
            loop.run_until_complete(_mfa_manager.disable_mfa(user))
            return authtuna_pb2.MFAResponse(success=True, error="")
        except Exception as e:
            return authtuna_pb2.MFAResponse(success=False, error=str(e))

    def _is_authorized(self, context):
        for key, value in context.invocation_metadata():
            if key == "authorization" and value == f"Bearer {RPC_AUTH_TOKEN}":
                return True
        return False

def serve():
    if not settings.RPC_ENABLED:
        print("AuthTuna RPC server is disabled by configuration.")
        return
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    authtuna_pb2_grpc.add_AuthTunaServiceServicer_to_server(AuthTunaService(), server)
    if RPC_TLS_CERT_FILE and RPC_TLS_KEY_FILE:
        with open(RPC_TLS_CERT_FILE, 'rb') as f:
            cert = f.read()
        with open(RPC_TLS_KEY_FILE, 'rb') as f:
            key = f.read()
        server_credentials = grpc.ssl_server_credentials(((key, cert),))
        server.add_secure_port(RPC_ADDRESS, server_credentials)
        print(f"AuthTuna RPC server running on {RPC_ADDRESS} (TLS enabled)")
    else:
        server.add_insecure_port(RPC_ADDRESS)
        print(f"AuthTuna RPC server running on {RPC_ADDRESS} (INSECURE, no TLS)")
    server.start()
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        print("Shutting down AuthTuna RPC server.")
        server.stop(0)

if __name__ == "__main__":
    serve()
