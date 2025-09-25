import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock, patch

import grpc
from google.protobuf.empty_pb2 import Empty

from authtuna.rpc import authtuna_pb2
from authtuna.rpc.server import AuthTunaService
from authtuna.core.database import Role, Permission, AuditEvent, User, Token, Session


class TestAuthTunaServiceAsync(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.service = AuthTunaService()
        self.context = MagicMock()
        self.context.invocation_metadata.return_value = [('authorization', 'Bearer test_token')]

        # Patch the authorization check to always pass for these tests
        self.auth_patcher = patch('authtuna.rpc.server.AuthTunaService._is_authorized', return_value=True)
        self.mock_is_authorized = self.auth_patcher.start()

    def tearDown(self):
        self.auth_patcher.stop()

    @patch('authtuna.rpc.server._role_manager', new_callable=AsyncMock)
    async def test_get_all_roles_rpc(self, mock_role_manager):
        # Arrange
        mock_roles = [
            Role(id=1, name='admin', description='Administrator', system=True, level=10),
            Role(id=2, name='user', description='Standard User', system=False, level=1)
        ]
        mock_role_manager.get_all_roles.return_value = mock_roles

        # Act
        response = await self.service.GetAllRoles(Empty(), self.context)

        # Assert
        self.assertEqual(len(response.roles), 2)
        self.assertEqual(response.roles[0].id, '1')
        self.assertEqual(response.roles[0].name, 'admin')
        self.assertEqual(response.roles[1].id, '2')
        self.assertEqual(response.roles[1].name, 'user')
        self.assertEqual(response.error, "")
        mock_role_manager.get_all_roles.assert_called_once()

    @patch('authtuna.rpc.server._permission_manager', new_callable=AsyncMock)
    async def test_get_permission_by_name_rpc(self, mock_permission_manager):
        # Arrange
        mock_permission = Permission(id=1, name='test:perm', description='A test permission')
        mock_permission_manager.get_by_name.return_value = mock_permission
        request = authtuna_pb2.PermissionNameRequest(name='test:perm')

        # Act
        response = await self.service.GetPermissionByName(request, self.context)

        # Assert
        self.assertEqual(response.permission.id, '1')
        self.assertEqual(response.permission.name, 'test:perm')
        self.assertEqual(response.error, "")
        mock_permission_manager.get_by_name.assert_called_once_with('test:perm')

    @patch('authtuna.rpc.server._token_manager', new_callable=AsyncMock)
    async def test_create_token_rpc(self, mock_token_manager):
        # Arrange
        mock_token = Token(id='test_token_id', user_id='test_user_id', purpose='test_purpose', etime=123.45)
        mock_token_manager.create.return_value = mock_token
        request = authtuna_pb2.Token(user_id='test_user_id', purpose='test_purpose', etime=123)

        # Act
        response = await self.service.CreateToken(request, self.context)

        # Assert
        self.assertEqual(response.token.id, 'test_token_id')
        self.assertEqual(response.token.user_id, 'test_user_id')
        self.assertEqual(response.error, "")
        mock_token_manager.create.assert_called_once_with(
            user_id='test_user_id', purpose='test_purpose', expiry_seconds=123
        )

    @patch('authtuna.rpc.server._db_manager')
    @patch('authtuna.rpc.server._token_manager', new_callable=AsyncMock)
    async def test_validate_token_rpc(self, mock_token_manager, mock_db_manager):
        # Arrange
        mock_user = User(id='test_user_id', username='testuser', email='test@test.com')
        mock_token_manager.validate.return_value = mock_user

        async_db_session = AsyncMock()
        mock_db_manager.get_db.return_value.__aenter__.return_value = async_db_session

        request = authtuna_pb2.TokenIdRequest(id='test_token_id', purpose='test_purpose')

        # Act
        response = await self.service.ValidateToken(request, self.context)

        # Assert
        self.assertEqual(response.user.id, 'test_user_id')
        self.assertEqual(response.user.username, 'testuser')
        self.assertEqual(response.error, "")
        mock_token_manager.validate.assert_called_once_with(
            async_db_session, 'test_token_id', 'test_purpose', ip_address="rpc-server"
        )

    @patch('authtuna.rpc.server._user_manager', new_callable=AsyncMock)
    async def test_get_user_by_id_rpc(self, mock_user_manager):
        # Arrange
        mock_user = User(id='test_user_id', username='testuser', email='test@test.com')
        mock_user_manager.get_by_id.return_value = mock_user
        request = authtuna_pb2.UserIdRequest(id='test_user_id')

        # Act
        response = await self.service.GetUserById(request, self.context)

        # Assert
        self.assertEqual(response.user.id, 'test_user_id')
        self.assertEqual(response.user.username, 'testuser')
        self.assertEqual(response.error, "")
        mock_user_manager.get_by_id.assert_called_once_with('test_user_id')

    @patch('authtuna.rpc.server.encryption_utils')
    @patch('authtuna.rpc.server._session_manager', new_callable=AsyncMock)
    async def test_get_session_by_id_rpc(self, mock_session_manager, mock_encryption_utils):
        # Arrange
        mock_session = Session(session_id='test_session_id', user_id='test_user_id')
        mock_session_manager.get_by_id.return_value = mock_session
        mock_encryption_utils.decode_jwt_token.return_value = {"session": "test_session_id"}
        request = authtuna_pb2.SessionIdRequest(session_id='jwt_session_token')

        # Act
        response = await self.service.GetSessionById(request, self.context)

        # Assert
        self.assertEqual(response.session.session_id, 'test_session_id')
        self.assertEqual(response.error, "")
        mock_session_manager.get_by_id.assert_called_once_with('test_session_id')
        mock_encryption_utils.decode_jwt_token.assert_called_once_with('jwt_session_token')


if __name__ == '__main__':
    unittest.main()