"""
Implicit Session Service
========================
This module provides a wrapper around standard ADK Session Services (like VertexAiSessionService).
It implements the "Get or Create" pattern, ensuring that stateless triggers (like Pub/Sub)
can interact with stateful agents without needing a prior handshake or login step.
"""

from typing import Any, Optional, Dict
from typing_extensions import override

from google.adk.sessions import BaseSessionService
from google.adk.sessions import Session
from google.adk.events import Event

class ImplicitSessionService(BaseSessionService):
    """
    A session service that proxies another BaseSessionService instance.
    It automatically creates a new session if one is not found for the user.
    """

    def __init__(self, proxied_service: BaseSessionService):
        if not isinstance(proxied_service, BaseSessionService):
            raise TypeError("proxied_service must be an instance of BaseSessionService")
        self._proxied_service = proxied_service

    @override
    async def get_session(
        self,
        *,
        app_name: str,
        user_id: str,
        session_id: str,
        config: Optional[Any] = None,
    ) -> Session:
        """
        Retrieves an existing session or creates a new one if none exist.
        
        Logic:
          1. List all active sessions for this user.
          2. If sessions exist, resume the most recent one (Sticky Session).
          3. If NO sessions exist, create a brand new one automatically.
        """
        sessions_list = await self._proxied_service.list_sessions(
            app_name=app_name,
            user_id=user_id,
        )

        if sessions_list.sessions:
            existing_session_id = sessions_list.sessions[0].id
            session = await self._proxied_service.get_session(
                app_name=app_name,
                user_id=user_id,
                session_id=existing_session_id,
                config=config
            )
        else:
            # Create a new session with an empty state
            session = await self._proxied_service.create_session(
                app_name=app_name,
                user_id=user_id,
                state=None,
            )
        return session

    @override
    async def create_session(self, *, app_name: str, user_id: str, state: Optional[dict[str, Any]] = None, session_id: Optional[str] = None) -> Session:
        return await self._proxied_service.create_session(app_name=app_name, user_id=user_id, state=state, session_id=session_id)

    @override
    async def list_sessions(self, *, app_name: str, user_id: str) -> Any:
        return await self._proxied_service.list_sessions(app_name=app_name, user_id=user_id)

    @override
    async def delete_session(self, *, app_name: str, user_id: str, session_id: str) -> None:
        await self._proxied_service.delete_session(app_name=app_name, user_id=user_id, session_id=session_id)

    @override
    async def append_event(self, session: Session, event: Event) -> Event:
        return await self._proxied_service.append_event(session, event)
