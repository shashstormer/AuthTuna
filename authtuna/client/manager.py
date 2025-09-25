import grpc
from authtuna.rpc import authtuna_pb2, authtuna_pb2_grpc
from typing import Optional, List, Dict, Any
from .config import settings
from .exceptions import RPCError

# gRPC-backed manager classes for authtuna-client will be implemented here

class AuthTunaClientBase:
    def __init__(self, address: str, token: str, tls: bool = False, cert_file: Optional[str] = None):
        self.address = address
        self.token = token
        if tls and cert_file:
            with open(cert_file, 'rb') as f:
                creds = grpc.ssl_channel_credentials(f.read())
            self.channel = grpc.secure_channel(address, creds)
        else:
            self.channel = grpc.insecure_channel(address)
        self.stub = authtuna_pb2_grpc.AuthTunaServiceStub(self.channel)

    def _auth_metadata(self):
        return [('authorization', f'Bearer {self.token}')]

class UserManagerClient(AuthTunaClientBase):
    def __init__(self):
        super().__init__(settings.RPC_ADDRESS, settings.RPC_TOKEN.get_secret_value(), tls=settings.RPC_USE_TLS, cert_file=settings.RPC_TLS_CERT_FILE)

    def get_by_id(self, user_id: str) -> Dict[str, Any]:
        req = authtuna_pb2.UserIdRequest(id=user_id)
        resp = self.stub.GetUserById(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.user

    def get_by_email(self, email: str) -> Dict[str, Any]:
        req = authtuna_pb2.UserEmailRequest(email=email)
        resp = self.stub.GetUserByEmail(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.user

    def create(self, username: str, email: str, password: str) -> Dict[str, Any]:
        req = authtuna_pb2.CreateUserRequest(username=username, email=email, password=password)
        resp = self.stub.CreateUser(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.user

    def update(self, user_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        req = authtuna_pb2.UpdateUserRequest(id=user_id, **update_data)
        resp = self.stub.UpdateUser(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.user

    def delete(self, user_id: str) -> bool:
        req = authtuna_pb2.DeleteUserRequest(id=user_id)
        resp = self.stub.DeleteUser(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return True

    def list(self, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        req = authtuna_pb2.ListUsersRequest(skip=skip, limit=limit)
        resp = self.stub.ListUsers(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return [u for u in resp.users]

class RoleManagerClient(AuthTunaClientBase):
    def __init__(self):
        super().__init__(settings.RPC_ADDRESS, settings.RPC_TOKEN.get_secret_value(), tls=settings.RPC_USE_TLS, cert_file=settings.RPC_TLS_CERT_FILE)

    def get_all_roles(self) -> List[Dict[str, Any]]:
        from google.protobuf.empty_pb2 import Empty
        resp = self.stub.GetAllRoles(Empty(), metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return [r for r in resp.roles]

    def get_by_name(self, name: str) -> Dict[str, Any]:
        req = authtuna_pb2.RoleNameRequest(name=name)
        resp = self.stub.GetRoleByName(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.role

    def create(self, name: str, description: str = '', system: bool = False, level: int = 0) -> Dict[str, Any]:
        req = authtuna_pb2.Role(name=name, description=description, system=system, level=level)
        resp = self.stub.CreateRole(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.role

    def assign_to_user(self, user_id: str, role_name: str, assigner_id: str, scope: str = 'none') -> Dict[str, Any]:
        req = authtuna_pb2.AssignRoleRequest(user_id=user_id, role_name=role_name, assigner_id=assigner_id, scope=scope)
        resp = self.stub.AssignRoleToUser(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.role

    def remove_from_user(self, user_id: str, role_name: str, remover_id: str, scope: str = 'none') -> Dict[str, Any]:
        req = authtuna_pb2.RemoveRoleRequest(user_id=user_id, role_name=role_name, remover_id=remover_id, scope=scope)
        resp = self.stub.RemoveRoleFromUser(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.role

    def get_users_for_role(self, name: str) -> List[Dict[str, Any]]:
        req = authtuna_pb2.RoleNameRequest(name=name)
        resp = self.stub.GetUsersForRole(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return [u for u in resp.users]

class SessionManagerClient(AuthTunaClientBase):
    def __init__(self):
        super().__init__(settings.RPC_ADDRESS, settings.RPC_TOKEN.get_secret_value(), tls=settings.RPC_USE_TLS, cert_file=settings.RPC_TLS_CERT_FILE)

    def get_by_id(self, session_id: str) -> Dict[str, Any]:
        req = authtuna_pb2.SessionIdRequest(session_id=session_id)
        resp = self.stub.GetSessionById(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.session

    def create(self, user_id: str, create_ip: str, region: str = '', device: str = '') -> Dict[str, Any]:
        req = authtuna_pb2.Session(user_id=user_id, create_ip=create_ip, region=region, device=device)
        resp = self.stub.CreateSession(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.session

    def terminate(self, session_id: str) -> bool:
        req = authtuna_pb2.SessionIdRequest(session_id=session_id)
        resp = self.stub.TerminateSession(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return True

    def list_for_user(self, user_id: str) -> List[Dict[str, Any]]:
        req = authtuna_pb2.UserIdRequest(id=user_id)
        resp = self.stub.ListSessionsForUser(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return [s for s in resp.sessions]

class PermissionManagerClient(AuthTunaClientBase):
    def __init__(self):
        super().__init__(settings.RPC_ADDRESS, settings.RPC_TOKEN.get_secret_value(), tls=settings.RPC_USE_TLS, cert_file=settings.RPC_TLS_CERT_FILE)

    def get_by_name(self, name: str) -> Dict[str, Any]:
        req = authtuna_pb2.PermissionNameRequest(name=name)
        resp = self.stub.GetPermissionByName(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.permission

    def create(self, name: str, description: str = '') -> Dict[str, Any]:
        req = authtuna_pb2.Permission(name=name, description=description)
        resp = self.stub.CreatePermission(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.permission

class TokenManagerClient(AuthTunaClientBase):
    def __init__(self):
        super().__init__(settings.RPC_ADDRESS, settings.RPC_TOKEN.get_secret_value(), tls=settings.RPC_USE_TLS, cert_file=settings.RPC_TLS_CERT_FILE)

    def create(self, user_id: str, purpose: str, etime: int = 0) -> Dict[str, Any]:
        req = authtuna_pb2.Token(user_id=user_id, purpose=purpose, etime=etime)
        resp = self.stub.CreateToken(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.token

    def validate(self, token_id: str, purpose: str) -> Dict[str, Any]:
        req = authtuna_pb2.TokenIdRequest(id=token_id, purpose=purpose)
        resp = self.stub.ValidateToken(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.user

class MFAManagerClient(AuthTunaClientBase):
    def __init__(self):
        super().__init__(settings.RPC_ADDRESS, settings.RPC_TOKEN.get_secret_value(), tls=settings.RPC_USE_TLS, cert_file=settings.RPC_TLS_CERT_FILE)

    def setup_totp(self, user_id: str, issuer_name: str) -> Dict[str, Any]:
        req = authtuna_pb2.MFASetupRequest(user_id=user_id, issuer_name=issuer_name)
        resp = self.stub.SetupTOTP(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return {"secret": resp.secret, "uri": resp.uri}

    def verify_and_enable_totp(self, user_id: str, code: str) -> bool:
        req = authtuna_pb2.MFAVerifyRequest(user_id=user_id, code=code)
        resp = self.stub.VerifyAndEnableTOTP(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.success

    def disable_mfa(self, user_id: str) -> bool:
        req = authtuna_pb2.UserIdRequest(id=user_id)
        resp = self.stub.DisableMFA(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return resp.success

class AuditManagerClient(AuthTunaClientBase):
    def __init__(self):
        super().__init__(settings.RPC_ADDRESS, settings.RPC_TOKEN.get_secret_value(), tls=settings.RPC_USE_TLS, cert_file=settings.RPC_TLS_CERT_FILE)

    def get_events_for_user(self, user_id: str, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        req = authtuna_pb2.AuditUserRequest(user_id=user_id, skip=skip, limit=limit)
        resp = self.stub.GetEventsForUser(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return [e for e in resp.events]

    def get_events_by_type(self, event_type: str, skip: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        req = authtuna_pb2.AuditTypeRequest(event_type=event_type, skip=skip, limit=limit)
        resp = self.stub.GetEventsByType(req, metadata=self._auth_metadata())
        if resp.error:
            raise RPCError(resp.error)
        return [e for e in resp.events]

# Additional manager clients (RoleManagerClient, SessionManagerClient, etc.) can be implemented similarly.
