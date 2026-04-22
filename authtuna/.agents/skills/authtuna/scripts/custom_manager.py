from authtuna.core.hooks import Events
from authtuna.integrations import auth_service
import logging

logger = logging.getLogger(__name__)

# Pattern: Using Hooks for custom side effects
async def welcome_email_hook(user, **kwargs):
    """
    Triggers automatically when a new user is created.
    'kwargs' contains context like 'ip_address' and 'background_tasks'.
    """
    logger.info(f"Sending welcome email to {user.username} ({user.id})")
    # your_email_service.send(user.get_email(), "Welcome!")

# Register the hook
auth_service.hooks.register(Events.USER_CREATED, welcome_email_hook)


# Pattern: Extending AuthTuna with custom logic via a wrapper
class MyAuthService:
    def __init__(self, auth_tuna):
        self.auth = auth_tuna
        
    async def signup_with_bonus(self, email, username, password):
        # 1. Standard creation
        user = await self.auth.users.create(email, username, password)
        
        # 2. Custom logic (e.g., granting a starter role or credits)
        await self.auth.roles.assign_to_user(user.id, "BetaTester", assigner_id="system")
        
        return user

# Usage
# custom_service = MyAuthService(auth_service)
# await custom_service.signup_with_bonus("user@example.com", "user", "pass")
