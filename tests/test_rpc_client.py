import unittest
from unittest.mock import MagicMock, patch, ANY

from authtuna.client.manager import (
    UserManagerClient, RoleManagerClient, SessionManagerClient,
    PermissionManagerClient, TokenManagerClient, MFAManagerClient, AuditManagerClient
)
from authtuna.client.exceptions import RPCError
from authtuna.rpc import authtuna_pb2


class BaseClientTest(unittest.TestCase):
    CLIENT_CLASS = None
    MANAGER_NAME = ""

    @patch('authtuna.client.config.settings')
    @patch('authtuna.client.manager.grpc')
    def setUp(self, mock_grpc, mock_settings):
        # Mock settings to avoid dependency on actual config files
        mock_settings.RPC_ADDRESS = 'localhost:50051'
        mock_settings.RPC_TOKEN.get_secret_value.return_value = 'test_token'
        mock_settings.RPC_USE_TLS = False

        if self.CLIENT_CLASS:
            self.manager = self.CLIENT_CLASS()
            self.mock_stub = MagicMock()
            self.manager.stub = self.mock_stub


class TestUserManagerClient(BaseClientTest):
    CLIENT_CLASS = UserManagerClient
    MANAGER_NAME = "user_manager"

    def test_get_by_id_success(self):
        user_proto = authtuna_pb2.User(id='1', username='test', email='test@test.com')
        response = authtuna_pb2.UserResponse(user=user_proto, error="")
        self.mock_stub.GetUserById.return_value = response
        user = self.manager.get_by_id('1')
        self.assertEqual(user.id, '1')
        self.assertEqual(user.username, 'test')
        self.mock_stub.GetUserById.assert_called_once_with(
            authtuna_pb2.UserIdRequest(id='1'), metadata=ANY
        )

    def test_get_by_id_failure(self):
        response = authtuna_pb2.UserResponse(user=None, error="User not found")
        self.mock_stub.GetUserById.return_value = response
        with self.assertRaises(RPCError) as context:
            self.manager.get_by_id('1')
        self.assertEqual(str(context.exception), "User not found")

    def test_delete_success(self):
        response = authtuna_pb2.UserResponse(user=None, error="")
        self.mock_stub.DeleteUser.return_value = response
        result = self.manager.delete('1')
        self.assertTrue(result)

    def test_delete_failure(self):
        response = authtuna_pb2.UserResponse(user=None, error="Permission denied")
        self.mock_stub.DeleteUser.return_value = response
        with self.assertRaises(RPCError) as context:
            self.manager.delete('1')
        self.assertEqual(str(context.exception), "Permission denied")


class TestRoleManagerClient(BaseClientTest):
    CLIENT_CLASS = RoleManagerClient
    MANAGER_NAME = "role_manager"

    def test_get_all_roles_success(self):
        role_proto = authtuna_pb2.Role(id='1', name='admin')
        response = authtuna_pb2.RoleListResponse(roles=[role_proto], error="")
        self.mock_stub.GetAllRoles.return_value = response
        roles = self.manager.get_all_roles()
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].id, '1')

    def test_get_all_roles_failure(self):
        response = authtuna_pb2.RoleListResponse(roles=[], error="Database offline")
        self.mock_stub.GetAllRoles.return_value = response
        with self.assertRaises(RPCError) as context:
            self.manager.get_all_roles()
        self.assertEqual(str(context.exception), "Database offline")


class TestSessionManagerClient(BaseClientTest):
    CLIENT_CLASS = SessionManagerClient
    MANAGER_NAME = "session_manager"

    def test_list_for_user_success(self):
        session_proto = authtuna_pb2.Session(session_id='s1', user_id='u1')
        response = authtuna_pb2.SessionListResponse(sessions=[session_proto], error="")
        self.mock_stub.ListSessionsForUser.return_value = response
        sessions = self.manager.list_for_user('u1')
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].session_id, 's1')
        self.mock_stub.ListSessionsForUser.assert_called_once_with(
            authtuna_pb2.UserIdRequest(id='u1'), metadata=ANY
        )

    def test_list_for_user_failure(self):
        response = authtuna_pb2.SessionListResponse(sessions=[], error="User not found")
        self.mock_stub.ListSessionsForUser.return_value = response
        with self.assertRaises(RPCError) as context:
            self.manager.list_for_user('u1')
        self.assertEqual(str(context.exception), "User not found")


class TestPermissionManagerClient(BaseClientTest):
    CLIENT_CLASS = PermissionManagerClient
    MANAGER_NAME = "permission_manager"

    def test_create_failure(self):
        response = authtuna_pb2.PermissionResponse(permission=None, error="Already exists")
        self.mock_stub.CreatePermission.return_value = response
        with self.assertRaises(RPCError) as context:
            self.manager.create("perm1", "description")
        self.assertEqual(str(context.exception), "Already exists")

class TestTokenManagerClient(BaseClientTest):
    CLIENT_CLASS = TokenManagerClient
    MANAGER_NAME = "token_manager"

    def test_validate_failure(self):
        response = authtuna_pb2.UserResponse(user=None, error="Token expired")
        self.mock_stub.ValidateToken.return_value = response
        with self.assertRaises(RPCError) as context:
            self.manager.validate("token123", "password_reset")
        self.assertEqual(str(context.exception), "Token expired")


class TestMFAManagerClient(BaseClientTest):
    CLIENT_CLASS = MFAManagerClient
    MANAGER_NAME = "mfa_manager"

    def test_verify_and_enable_totp_failure(self):
        response = authtuna_pb2.MFAResponse(success=False, error="Invalid code")
        self.mock_stub.VerifyAndEnableTOTP.return_value = response
        with self.assertRaises(RPCError) as context:
            self.manager.verify_and_enable_totp("user1", "123456")
        self.assertEqual(str(context.exception), "Invalid code")


class TestAuditManagerClient(BaseClientTest):
    CLIENT_CLASS = AuditManagerClient
    MANAGER_NAME = "audit_manager"

    def test_get_events_by_type_failure(self):
        response = authtuna_pb2.AuditEventListResponse(events=[], error="Invalid event type")
        self.mock_stub.GetEventsByType.return_value = response
        with self.assertRaises(RPCError) as context:
            self.manager.get_events_by_type("invalid_type")
        self.assertEqual(str(context.exception), "Invalid event type")


if __name__ == '__main__':
    unittest.main()