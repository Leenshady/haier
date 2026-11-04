"""Haier cloud client package.

Groups the components that communicate with the Haier cloud:

* :class:`HaierHttpClient` -- REST calls (homes, devices, digital models, scenes).
* :class:`HaierWebSocketClient` -- real-time device push channel.
* :class:`HaierCoordinator` -- owns the token, WebSocket and command dispatch.
* :class:`HaierOAuth2Implementation` -- OAuth2 authorize / token / refresh flow.
* :func:`generate_ag_client_id` -- builds the per-install client identifier.
"""

from .http_client import HaierAPIError, HaierHttpClient
from .oauth2 import HaierOAuth2Implementation
from .utils import generate_ag_client_id

__all__ = [
    "HaierAPIError",
    "HaierHttpClient",
    "HaierOAuth2Implementation",
    "generate_ag_client_id",
]
