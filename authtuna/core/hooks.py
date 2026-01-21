import asyncio
import logging
from typing import Callable, Dict, List, Any, Awaitable

logger = logging.getLogger(__name__)

class HookManager:
    """
    Manages registration and execution of asynchronous hooks for various events.
    Allows extending the authentication flow without modifying core logic.
    """
    def __init__(self):
        self._hooks: Dict[str, List[Callable[..., Awaitable[Any]]]] = {}

    def on(self, event_name: str):
        """Decorator to register a hook for an event."""
        def decorator(func: Callable[..., Awaitable[Any]]):
            self.register(event_name, func)
            return func
        return decorator

    def register(self, event_name: str, func: Callable[..., Awaitable[Any]]):
        """Register a function as a hook for an event."""
        if event_name not in self._hooks:
            self._hooks[event_name] = []
        self._hooks[event_name].append(func)
        logger.debug(f"Registered hook '{func.__name__}' for event '{event_name}'")

    async def trigger(self, event_name: str, **kwargs):
        """
        Trigger all hooks for an event concurrently.
        Hooks are awaited. failures are logged but do not stop other hooks (unless desired?).
        """
        hooks = self._hooks.get(event_name, [])
        if not hooks:
            return

        logger.debug(f"Triggering {len(hooks)} hooks for event '{event_name}'")
        
        # Execute hooks sequentially to avoid race conditions in database mutations if they share session?
        # Or concurrently? If they operate on the same user object attached to a session, concurrency might be risky if they flush.
        # Let's run sequentially for safety in consistency.
        for hook in hooks:
            try:
                await hook(**kwargs)
            except Exception as e:
                logger.error(f"Error executing hook '{hook.__name__}' for event '{event_name}': {e}", exc_info=True)
                # We might want to re-raise if it's a critical logic? 
                # For now, let's log and continue to prioritize system stability.

# Standard Event Names
class Events:
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_LOGGED_IN = "user_logged_in"
    
    SOCIAL_ACCOUNT_CONNECTED = "social_account_connected"
    
    ORG_CREATED = "org_created"
    TEAM_CREATED = "team_created"
