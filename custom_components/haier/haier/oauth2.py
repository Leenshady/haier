"""Haier OAuth2 implementation for Home Assistant."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.network import NoURLAvailableError, get_url

from ..const import (
    API_ENDPOINT_MAP,
    API_HOSTS_MAP,
    APP_ID,
    APP_VERSION,
    DOMAIN,
    OAUTH2_AUTH_URL,
    OAUTH2_CALLBACK_PATH,
    OAUTH2_CALLBACK_URL,
    OAUTH2_CLIENT_ID,
)
from .http_client import HaierAPIError
from .utils import mask_token, validate_construct_token

_LOGGER = logging.getLogger(__name__)


def get_redirect_uri(hass: HomeAssistant) -> str:
    """按 HA 的对外访问地址动态推导 OAuth 回调地址。

    海尔只注册了一个回调值（见 ``OAUTH2_CALLBACK_URL``），且换 token 时会逐字符
    比对。所以回调地址不能写死成某个主机名：换个部署环境（改端口、换域名、
    容器里换主机名）就会在 code 换 token 那一步被 ``invalid_grant`` 拒掉。

    这里优先用 ``external_url``，没有配置时回落到 HA 探测到的 ``internal_url``
    （Home Assistant OS 默认安装就是 ``http://homeassistant.local:8123``），
    两者都拿不到时回落到注册值本身。

    :param hass: Home Assistant 实例
    :return: 完整的回调地址
    """
    try:
        base_url = get_url(
            hass,
            prefer_external=True,
            allow_internal=True,
            allow_cloud=False,
            allow_ip=True,
        )
    except NoURLAvailableError:
        _LOGGER.debug("no HA url available, fall back to registered callback")
        return OAUTH2_CALLBACK_URL

    return f"{base_url.rstrip('/')}{OAUTH2_CALLBACK_PATH}"


def is_registered_callback(redirect_uri: str) -> bool:
    """判断回调地址是否与海尔注册值一致。

    服务端做的是逐字符比较，这里保持一致（只容忍末尾斜杠差异）。

    :param redirect_uri: 待校验的回调地址
    :return: 是否可用
    """
    return redirect_uri.rstrip("/") == OAUTH2_CALLBACK_URL.rstrip("/")


class HaierOAuth2Implementation(config_entry_oauth2_flow.AbstractOAuth2Implementation):
    """Haier OAuth2 implementation."""

    def __init__(self, hass: HomeAssistant, ag_client_id: str, region: str) -> None:
        """Initialize the implementation."""
        self.hass = hass
        self._domain = DOMAIN
        self._region = region
        self._ag_client_id = ag_client_id

    @property
    def name(self) -> str:
        """Name of the implementation."""
        return f"Haier Home ({self._region})"

    @property
    def domain(self) -> str:
        """Domain that is providing the implementation."""
        return self._domain

    @property
    def client_id(self) -> str:
        """Client ID."""
        return self._ag_client_id

    @property
    def authorize_url(self) -> str:
        """Authorize URL."""
        return OAUTH2_AUTH_URL

    @property
    def token_url(self) -> str:
        """Token URL."""
        host = API_HOSTS_MAP[self._region]
        return f"https://{host}{API_ENDPOINT_MAP['token']}"

    @property
    def scope(self) -> list[str]:
        """Scope for the OAuth2 request."""
        return []

    @property
    def redirect_uri(self) -> str:
        """Redirect URI, derived from HA's own external/internal URL."""
        return get_redirect_uri(self.hass)

    async def async_generate_authorize_url(self, flow_id: str) -> str:
        """Generate authorize URL."""
        from urllib.parse import urlencode

        from homeassistant.helpers.config_entry_oauth2_flow import _encode_jwt

        state = _encode_jwt(self.hass, {"flow_id": flow_id, "redirect_uri": self.redirect_uri})
        params = {
            "redirect_uri": self.redirect_uri,
            "client_id": OAUTH2_CLIENT_ID,
            "response_type": "code",
            "state": state,
        }
        return f"{self.authorize_url}?{urlencode(params)}"

    async def async_resolve_external_data(self, external_data: dict[str, Any]) -> dict[str, Any]:
        """Resolve external data to token."""
        code = external_data.get("code")
        if not code:
            raise ValueError("Missing 'code' in OAuth callback data")

        _LOGGER.debug("Resolving OAuth authorization code for region %s", self._region)

        data = {
            "code": code,
            "clientId": self._ag_client_id,
            "redirectUri": self.redirect_uri,
            "grantType": "authorization_code",
        }
        body_str = json.dumps(data)
        timestamp = str(int(time.time() * 1000))

        headers = {
            "Connection": "keep-alive",
            "Content-Type": "application/json;charset=utf-8",
            "appId": APP_ID,
            "appVersion": APP_VERSION,
            "clientId": self._ag_client_id,
            "Accept-Language": "zh",
            "timestamp": timestamp,
            "User-Agent": "Apache-HttpClient/4.5.14 (Java/1.8.0_442)",
        }

        session = async_get_clientsession(self.hass)
        async with session.post(self.token_url, data=body_str, headers=headers) as resp:
            # Check HTTP status first so non-JSON error pages do not shadow
            # the real HTTP-level failure with a JSONDecodeError.
            resp.raise_for_status()
            result = await resp.json()

            if result.get("retCode") != "00000":
                raise HaierAPIError(
                    error_code=result.get("retCode"),
                    error_message=result.get("retInfo", "Token request failed"),
                )
            token_data = result.get("data", {})
            token = validate_construct_token(token_data)
            # Token initially issued by the OAuth authorization flow.
            _LOGGER.debug(
                "OAuth token issued: %s (region=%s)",
                mask_token(token.get("access_token")),
                self._region,
            )
            return token

    async def _async_refresh_token(self, token: dict[str, Any]) -> dict[str, Any]:
        """Refresh access token."""
        host = API_HOSTS_MAP[self._region]
        refresh_url = (
            f"https://{host}{API_ENDPOINT_MAP.get('refresh_token', API_ENDPOINT_MAP['token'])}"
        )
        refresh_token = token.get("refresh_token")
        if not refresh_token:
            raise ValueError("No refresh token available")

        _LOGGER.debug("Refreshing OAuth token for region %s", self._region)

        data = {
            "refreshToken": refresh_token,
            "clientId": self._ag_client_id,
            "grantType": "refresh_token",
        }
        body_str = json.dumps(data)
        timestamp = str(int(time.time() * 1000))

        headers = {
            "Connection": "keep-alive",
            "Content-Type": "application/json;charset=utf-8",
            "appId": APP_ID,
            "appVersion": APP_VERSION,
            "clientId": self._ag_client_id,
            "Accept-Language": "zh",
            "timestamp": timestamp,
            "User-Agent": "Apache-HttpClient/4.5.14 (Java/1.8.0_442)",
        }

        session = async_get_clientsession(self.hass)
        async with session.post(refresh_url, data=body_str, headers=headers) as resp:
            # Check HTTP status first so non-JSON error pages do not shadow
            # the real HTTP-level failure with a JSONDecodeError.
            resp.raise_for_status()
            result = await resp.json()

            if result.get("retCode") != "00000":
                raise HaierAPIError(
                    error_code=result.get("retCode"),
                    error_message=result.get("retInfo", "Token refresh failed"),
                )

            token_data = result.get("data", {})
            token = validate_construct_token(token_data)
            # Refreshed on demand with the stored refresh_token.
            _LOGGER.debug(
                "OAuth token refreshed via refresh_token: %s (region=%s)",
                mask_token(token.get("access_token")),
                self._region,
            )
            return token
