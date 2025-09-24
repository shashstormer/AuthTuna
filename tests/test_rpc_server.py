import pytest
import grpc
import threading
import time
import importlib
import os
from authtuna.rpc import authtuna_pb2, authtuna_pb2_grpc
from authtuna.rpc import server as rpc_server
from authtuna.core.config import settings, init_settings

# Use a test token and address for the test server
test_token = "test-token"
test_address = "localhost:50055"

os.environ["AUTHTUNA_NO_ENV"] = "false"
os.environ["RPC_ENABLED"] = "true"
os.environ["RPC_TOKEN"] = test_token
os.environ["RPC_ADDRESS"] = test_address

@pytest.fixture(scope="session", autouse=True)
def setup_rpc_server():
    importlib.reload(rpc_server)
    init_settings(RPC_ENABLED=True, RPC_TOKEN=test_token, RPC_ADDRESS=test_address)
    # Start the server in a background thread
    thread = threading.Thread(target=rpc_server.serve, daemon=True)
    thread.start()
    time.sleep(1)  # Wait for server to start
    yield
    # No explicit shutdown; server thread will exit with test process

@pytest.fixture
def rpc_channel():
    channel = grpc.insecure_channel(test_address)
    yield channel
    channel.close()

@pytest.fixture
def rpc_stub(rpc_channel):
    return authtuna_pb2_grpc.AuthTunaServiceStub(rpc_channel)

def test_authenticate_invalid(rpc_stub):
    # Should fail with invalid credentials
    metadata = [("authorization", f"Bearer {test_token}")]
    req = authtuna_pb2.AuthRequest(username="nouser", password="badpass")
    resp = rpc_stub.Authenticate(req, metadata=metadata)
    assert resp.token == ""
    assert resp.error

def test_get_user_by_id_not_found(rpc_stub):
    metadata = [("authorization", f"Bearer {test_token}")]
    req = authtuna_pb2.UserIdRequest(id="nonexistent")
    resp = rpc_stub.GetUserById(req, metadata=metadata)
    assert resp.user is None
    assert resp.error

def test_list_users_empty(rpc_stub):
    metadata = [("authorization", f"Bearer {test_token}")]
    req = authtuna_pb2.ListUsersRequest(skip=0, limit=10)
    resp = rpc_stub.ListUsers(req, metadata=metadata)
    assert isinstance(resp.users, list)
    assert resp.error == ""

def test_create_user_and_get(rpc_stub):
    metadata = [("authorization", f"Bearer {test_token}")]
    # Create user
    req = authtuna_pb2.CreateUserRequest(username="testuser", email="test@example.com", password="testpass")
    resp = rpc_stub.CreateUser(req, metadata=metadata)
    assert resp.user.username == "testuser"
    assert resp.user.email == "test@example.com"
    # Get user by email
    req2 = authtuna_pb2.UserEmailRequest(email="test@example.com")
    resp2 = rpc_stub.GetUserByEmail(req2, metadata=metadata)
    assert resp2.user.username == "testuser"
    assert resp2.user.email == "test@example.com"

def test_update_user(rpc_stub):
    metadata = [("authorization", f"Bearer {test_token}")]
    # Create user
    req = authtuna_pb2.CreateUserRequest(username="updateuser", email="update@example.com", password="pass")
    resp = rpc_stub.CreateUser(req, metadata=metadata)
    user_id = resp.user.id
    # Update user
    req2 = authtuna_pb2.UpdateUserRequest(id=user_id, username="updated", email="updated@example.com", password="newpass")
    resp2 = rpc_stub.UpdateUser(req2, metadata=metadata)
    assert resp2.user.username == "updated"
    assert resp2.user.email == "updated@example.com"

def test_delete_user(rpc_stub):
    metadata = [("authorization", f"Bearer {test_token}")]
    # Create user
    req = authtuna_pb2.CreateUserRequest(username="deluser", email="del@example.com", password="pass")
    resp = rpc_stub.CreateUser(req, metadata=metadata)
    user_id = resp.user.id
    # Delete user
    req2 = authtuna_pb2.DeleteUserRequest(id=user_id)
    resp2 = rpc_stub.DeleteUser(req2, metadata=metadata)
    assert resp2.error == ""
    # Try to get deleted user
    req3 = authtuna_pb2.UserIdRequest(id=user_id)
    resp3 = rpc_stub.GetUserById(req3, metadata=metadata)
    assert resp3.user is None
    assert resp3.error

def test_create_role_and_get(rpc_stub):
    metadata = [("authorization", f"Bearer {test_token}")]
    req = authtuna_pb2.Role(name="testr", description="desc", system=False, level=1)
    resp = rpc_stub.CreateRole(req, metadata=metadata)
    assert resp.role.name == "testr"
    assert resp.role.description == "desc"
    # Get role by name
    req2 = authtuna_pb2.RoleNameRequest(name="testr")
    resp2 = rpc_stub.GetRoleByName(req2, metadata=metadata)
    assert resp2.role.name == "testr"

def test_get_all_roles(rpc_stub):
    metadata = [("authorization", f"Bearer {test_token}")]
    from google.protobuf.empty_pb2 import Empty
    resp = rpc_stub.GetAllRoles(Empty(), metadata=metadata)
    assert isinstance(resp.roles, list)
    assert any(r.name == "testr" for r in resp.roles)

def test_assign_and_remove_role(rpc_stub):
    metadata = [("authorization", f"Bearer {test_token}")]
    # Create user and role
    user_resp = rpc_stub.CreateUser(authtuna_pb2.CreateUserRequest(username="roleuser", email="roleuser@example.com", password="pass"), metadata=metadata)
    user_id = user_resp.user.id
    role_resp = rpc_stub.CreateRole(authtuna_pb2.Role(name="assignr", description="desc", system=False, level=1), metadata=metadata)
    # Assign role
    assign_req = authtuna_pb2.AssignRoleRequest(user_id=user_id, role_name="assignr", assigner_id="admin", scope="global")
    assign_resp = rpc_stub.AssignRoleToUser(assign_req, metadata=metadata)
    assert assign_resp.error == ""
    # Remove role
    remove_req = authtuna_pb2.RemoveRoleRequest(user_id=user_id, role_name="assignr", remover_id="admin", scope="global")
    remove_resp = rpc_stub.RemoveRoleFromUser(remove_req, metadata=metadata)
    assert remove_resp.error == ""

def test_create_permission_and_get(rpc_stub):
    metadata = [("authorization", f"Bearer {test_token}")]
    req = authtuna_pb2.Permission(name="perm1", description="desc")
    resp = rpc_stub.CreatePermission(req, metadata=metadata)
    assert resp.permission.name == "perm1"
    assert resp.permission.description == "desc"
    # Get permission by name
    req2 = authtuna_pb2.PermissionNameRequest(name="perm1")
    resp2 = rpc_stub.GetPermissionByName(req2, metadata=metadata)
    assert resp2.permission.name == "perm1"

def test_create_and_terminate_session(rpc_stub):
    metadata = [("authorization", f"Bearer {test_token}")]
    # Create user
    user_resp = rpc_stub.CreateUser(authtuna_pb2.CreateUserRequest(username="sessuser", email="sess@example.com", password="pass"), metadata=metadata)
    user_id = user_resp.user.id
    # Create session
    req = authtuna_pb2.Session(user_id=user_id, create_ip="127.0.0.1", region="test", device="testdev")
    resp = rpc_stub.CreateSession(req, metadata=metadata)
    assert resp.session.user_id == user_id
    session_id = resp.session.session_id
    # Get session by id
    req2 = authtuna_pb2.SessionIdRequest(session_id=session_id)
    resp2 = rpc_stub.GetSessionById(req2, metadata=metadata)
    assert resp2.session.session_id == session_id
    # Terminate session
    resp3 = rpc_stub.TerminateSession(req2, metadata=metadata)
    assert resp3.error == "" or "terminated" in resp3.error
    # List sessions for user
    req4 = authtuna_pb2.UserIdRequest(id=user_id)
    resp4 = rpc_stub.ListSessionsForUser(req4, metadata=metadata)
    assert isinstance(resp4.sessions, list)

def test_create_and_validate_token(rpc_stub):
    metadata = [("authorization", f"Bearer {test_token}")]
    # Create user
    user_resp = rpc_stub.CreateUser(authtuna_pb2.CreateUserRequest(username="tokenuser", email="token@example.com", password="pass"), metadata=metadata)
    user_id = user_resp.user.id
    # Create token
    req = authtuna_pb2.Token(user_id=user_id, purpose="test", etime=3600)
    resp = rpc_stub.CreateToken(req, metadata=metadata)
    assert resp.token.user_id == user_id
    token_id = resp.token.id
    # Validate token
    req2 = authtuna_pb2.TokenIdRequest(id=token_id, purpose="test")
    resp2 = rpc_stub.ValidateToken(req2, metadata=metadata)
    assert resp2.user.id == user_id

def test_mfa_setup_and_disable(rpc_stub):
    metadata = [("authorization", f"Bearer {test_token}")]
    # Create user
    user_resp = rpc_stub.CreateUser(authtuna_pb2.CreateUserRequest(username="mfauser", email="mfa@example.com", password="pass"), metadata=metadata)
    user_id = user_resp.user.id
    # Setup TOTP
    req = authtuna_pb2.MFASetupRequest(user_id=user_id, issuer_name="TestIssuer")
    resp = rpc_stub.SetupTOTP(req, metadata=metadata)
    assert resp.secret
    assert resp.uri
    # Disable MFA
    req2 = authtuna_pb2.UserIdRequest(id=user_id)
    resp2 = rpc_stub.DisableMFA(req2, metadata=metadata)
    assert resp2.success

def test_get_events_for_user_and_type(rpc_stub):
    metadata = [("authorization", f"Bearer {test_token}")]
    # Create user
    user_resp = rpc_stub.CreateUser(authtuna_pb2.CreateUserRequest(username="audituser", email="audit@example.com", password="pass"), metadata=metadata)
    user_id = user_resp.user.id
    # Get events for user
    req = authtuna_pb2.AuditUserRequest(user_id=user_id, skip=0, limit=10)
    resp = rpc_stub.GetEventsForUser(req, metadata=metadata)
    assert isinstance(resp.events, list)
    # Get events by type
    req2 = authtuna_pb2.AuditTypeRequest(event_type="login", skip=0, limit=10)
    resp2 = rpc_stub.GetEventsByType(req2, metadata=metadata)
    assert isinstance(resp2.events, list)
