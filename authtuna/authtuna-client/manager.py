import grpc
from grpc import aio
from authtuna.rpc import authtuna_pb2, authtuna_pb2_grpc
from typing import Optional, List, Dict, Any
from .config import settings

# gRPC-backed manager classes for authtuna-client will be implemented here

class AuthTunaClientBase:
    def __init__(self, address: str, token: str, tls: bool = False, cert_file: Optional[str] = None):
        self.address = address
        self.token = token
        if tls and cert_file:
            with open(cert_file, 'rb') as f:
                creds = grpc.ssl_channel_credentials(f.read())
            self.channel = aio.secure_channel(address, creds)
        else:
            self.channel = aio.insecure_channel(address)
        self.stub = authtuna_pb2_grpc.AuthTunaServiceStub(self.channel)

    def _auth_metadata(self):
        return [('authorization', f'Bearer {self.token}')]

class UserManagerClient(AuthTunaClientBase):
    def __init__(self):
        super().__init__(settings.RPC_ADDRESS, settings.RPC_TOKEN.get_secret_value(), tls=settings.RPC_USE_TLS, cert_file=settings.RPC_TLS_CERT_FILE)

    async def get_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.UserIdRequest(id=user_id)
        resp = await self.stub.GetUserById(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return resp.user

    async def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.UserEmailRequest(email=email)
        resp = await self.stub.GetUserByEmail(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return resp.user

    async def create(self, username: str, email: str, password: str) -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.CreateUserRequest(username=username, email=email, password=password)
        resp = await self.stub.CreateUser(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return resp.user

    async def update(self, user_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.UpdateUserRequest(id=user_id, **update_data)
        resp = await self.stub.UpdateUser(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return resp.user

    async def delete(self, user_id: str) -> bool:
        req = authtuna_pb2.DeleteUserRequest(id=user_id)
        resp = await self.stub.DeleteUser(req, metadata=self._auth_metadata())
        return not bool(resp.error)

    async def list(self, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        req = authtuna_pb2.ListUsersRequest(skip=skip, limit=limit)
        resp = await self.stub.ListUsers(req, metadata=self._auth_metadata())
        if resp.error:
            return []
        return list(resp.users)

class RoleManagerClient(AuthTunaClientBase):
    def __init__(self):
        super().__init__(settings.RPC_ADDRESS, settings.RPC_TOKEN.get_secret_value(), tls=settings.RPC_USE_TLS, cert_file=settings.RPC_TLS_CERT_FILE)

    async def has_permission(self, user_id: str, permission: str, scope: str = "global") -> bool:
        req = authtuna_pb2.PermissionCheckRequest(user_id=user_id, permission=permission, scope=scope)
        resp = await self.stub.HasPermission(req, metadata=self._auth_metadata())
        return resp.has_permission

    async def get_all_roles(self) -> List[Dict[str, Any]]:
        req = authtuna_pb2.Empty()
        resp = await self.stub.GetAllRoles(req, metadata=self._auth_metadata())
        if resp.error:
            return []
        return list(resp.roles)

    async def get_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.RoleNameRequest(name=name)
        resp = await self.stub.GetRoleByName(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return resp.role

    async def create(self, name: str, description: str = '', system: bool = False, level: int = 0) -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.Role(name=name, description=description, system=system, level=level)
        resp = await self.stub.CreateRole(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return resp.role

    async def assign_to_user(self, user_id: str, role_name: str, assigner_id: str, scope: str = 'none') -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.AssignRoleRequest(user_id=user_id, role_name=role_name, assigner_id=assigner_id, scope=scope)
        resp = await self.stub.AssignRoleToUser(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return resp.role

    async def remove_from_user(self, user_id: str, role_name: str, remover_id: str, scope: str = 'none') -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.RemoveRoleRequest(user_id=user_id, role_name=role_name, remover_id=remover_id, scope=scope)
        resp = await self.stub.RemoveRoleFromUser(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return resp.role

    async def get_users_for_role(self, name: str) -> List[Dict[str, Any]]:
        req = authtuna_pb2.RoleNameRequest(name=name)
        resp = await self.stub.GetUsersForRole(req, metadata=self._auth_metadata())
        if resp.error:
            return []
        return list(resp.users)

class SessionManagerClient(AuthTunaClientBase):
    def __init__(self):
        super().__init__(settings.RPC_ADDRESS, settings.RPC_TOKEN.get_secret_value(), tls=settings.RPC_USE_TLS, cert_file=settings.RPC_TLS_CERT_FILE)

    async def get_by_id(self, session_id: str) -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.SessionIdRequest(session_id=session_id)
        resp = await self.stub.GetSessionById(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return resp.session

    async def terminate(self, session_id: str) -> bool:
        req = authtuna_pb2.TerminateSessionRequest(session_id=session_id)
        resp = await self.stub.TerminateSession(req, metadata=self._auth_metadata())
        return not bool(resp.error)

    async def create(self, user_id: str, ip_address: str, region: str, device: str) -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.CreateSessionRequest(user_id=user_id, ip_address=ip_address, region=region, device=device)
        resp = await self.stub.CreateSession(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return resp.session

    async def list_for_user(self, user_id: str) -> List[Dict[str, Any]]:
        req = authtuna_pb2.UserIdRequest(id=user_id)
        resp = await self.stub.ListSessionsForUser(req, metadata=self._auth_metadata())
        if resp.error:
            return []
        return list(resp.sessions)

class PermissionManagerClient(AuthTunaClientBase):
    def __init__(self):
        super().__init__(settings.RPC_ADDRESS, settings.RPC_TOKEN.get_secret_value(), tls=settings.RPC_USE_TLS, cert_file=settings.RPC_TLS_CERT_FILE)

    async def get_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.PermissionNameRequest(name=name)
        resp = await self.stub.GetPermissionByName(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return resp.permission

    async def create(self, name: str, description: str = '') -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.Permission(name=name, description=description)
        resp = await self.stub.CreatePermission(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return resp.permission

class TokenManagerClient(AuthTunaClientBase):
    def __init__(self):
        super().__init__(settings.RPC_ADDRESS, settings.RPC_TOKEN.get_secret_value(), tls=settings.RPC_USE_TLS, cert_file=settings.RPC_TLS_CERT_FILE)

    async def create(self, user_id: str, purpose: str, etime: int = 0) -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.Token(user_id=user_id, purpose=purpose, etime=etime)
        resp = await self.stub.CreateToken(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return resp.token

    async def validate(self, token_id: str, purpose: str) -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.TokenIdRequest(id=token_id, purpose=purpose)
        resp = await self.stub.ValidateToken(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return resp.user

class MFAManagerClient(AuthTunaClientBase):
    def __init__(self):
        super().__init__(settings.RPC_ADDRESS, settings.RPC_TOKEN.get_secret_value(), tls=settings.RPC_USE_TLS, cert_file=settings.RPC_TLS_CERT_FILE)

    async def setup_totp(self, user_id: str, issuer_name: str) -> Optional[Dict[str, Any]]:
        req = authtuna_pb2.MFASetupRequest(user_id=user_id, issuer_name=issuer_name)
        resp = await self.stub.SetupTOTP(req, metadata=self._auth_metadata())
        if resp.error:
            return None
        return {"secret": resp.secret, "uri": resp.uri}

    async def verify_and_enable_totp(self, user_id: str, code: str) -> bool:
        req = authtuna_pb2.MFAVerifyRequest(user_id=user_id, code=code)
        resp = await self.stub.VerifyAndEnableTOTP(req, metadata=self._auth_metadata())
        return resp.success and not resp.error

    async def disable_mfa(self, user_id: str) -> bool:
        req = authtuna_pb2.UserIdRequest(id=user_id)
        resp = await self.stub.DisableMFA(req, metadata=self._auth_metadata())
        return resp.success and not resp.error

class AuditManagerClient(AuthTunaClientBase):
    def __init__(self):
        super().__init__(settings.RPC_ADDRESS, settings.RPC_TOKEN.get_secret_value(), tls=settings.RPC_USE_TLS, cert_file=settings.RPC_TLS_CERT_FILE)

    async def get_events_for_user(self, user_id: str, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        req = authtuna_pb2.AuditUserRequest(user_id=user_id, skip=skip, limit=limit)
        resp = await self.stub.GetEventsForUser(req, metadata=self._auth_metadata())
        if resp.error:
            return []
        return list(resp.events)

    async def get_events_by_type(self, event_type: str, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        req = authtuna_pb2.AuditTypeRequest(event_type=event_type, skip=skip, limit=limit)
        resp = await self.stub.GetEventsByType(req, metadata=self._auth_metadata())
        if resp.error:
            return []
        return list(resp.events)

# Additional manager clients (RoleManagerClient, SessionManagerClient, etc.) can be implemented similarly.
