import json
import logging
import time
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.device_registry import DeviceEntry
from homeassistant.helpers.event import async_track_time_interval

from .const import (
    DOMAIN,
    SUPPORTED_PLATFORMS,
    FILTER_TYPE_EXCLUDE,
    TOKEN_BUFFER_INTERVAL,
)
from .core.client import (
    APP_SOURCE_OAUTH,
    HaierClient,
    HaierClientException,
)
from .core.config import (
    AccountConfig,
    DeviceFilterConfig,
    EntityFilterConfig,
    PreferencesConfig,
)
from .core.device_gateway import HaierDeviceGateway
from .core.migration import CONFIG_ENTRY_MIGRATOR
from .core.runtime import HaierRuntimeData
from .services import async_setup_services, async_unload_services

_LOGGER = logging.getLogger(__name__)

# 网页授权 token 的刷新节流：entry_id -> 上次刷新时间戳。
# 防止“刷新拿到的有效期比缓冲窗口还短”时陷入 刷新->重载->刷新 的死循环。
_OAUTH_REFRESHED_AT: dict[str, int] = {}
_OAUTH_REFRESH_GUARD_SECONDS = 300


_ENTRY_TITLE_PREFIX = 'Haier - '
# 旧版本经 Options 换号后标题写成 'Haier: {账号}'，解析时一并兼容
_LEGACY_TITLE_PREFIX = 'Haier: '


def _build_entry_unique_id(entry: ConfigEntry) -> str | None:
    """按「登录方式:账号标识」生成唯一键。

    网页授权只拿得到 userId，账号密码登录只拿得到手机号，两套体系无法换算，
    所以唯一键带上前缀区分来源。

    账号标识优先取 entry.data['identity']（新条目写入）；老条目没有这个字段，
    只能从 title 里取（格式为 "Haier - {账号标识}"，历史上有过 "Haier: "
    的写法，两种都认）。用户手动改过标题的老条目会取不到，此时返回 None，
    该条目保持无 unique_id，不会被误拦。

    :param entry: 配置条目
    :return: 唯一键，取不到时返回 None
    """
    account = entry.data.get('account') or {}
    if isinstance(account, str):
        try:
            account = json.loads(account)
        except ValueError:
            account = {}

    identity = str(entry.data.get('identity') or '').strip()
    if not identity:
        title = entry.title or ''
        for prefix in (_ENTRY_TITLE_PREFIX, _LEGACY_TITLE_PREFIX):
            if title.startswith(prefix):
                identity = title[len(prefix):].strip()
                break

    if not identity:
        return None

    scope = 'oauth' if account.get('app_source') == APP_SOURCE_OAUTH else 'phone'
    return '{}:{}'.format(scope, identity)


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """迁移旧版配置。"""
    if not CONFIG_ENTRY_MIGRATOR.migrate(hass, entry):
        return False

    # 老条目没有 unique_id，补上之后重复添加才会被 config flow 拦下
    if not entry.unique_id:
        unique_id = _build_entry_unique_id(entry)
        if unique_id:
            hass.config_entries.async_update_entry(entry, unique_id=unique_id)
            _LOGGER.info('配置条目补齐 unique_id: %s', unique_id)

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    # 定时更新token
    try:
        cancel_token_updater = await token_updater(hass, entry)
    except HaierClientException as err:
        raise ConfigEntryNotReady('Haier authentication failed') from err

    account_cfg = AccountConfig(hass, entry)
    preferences_cfg = PreferencesConfig(hass, entry)
    client = HaierClient(hass, account_cfg.client_id, account_cfg.token, account_cfg.app_source)

    devices = await client.get_devices()
    _LOGGER.info('共获取到{}个设备'.format(len(devices)))

    gateway = HaierDeviceGateway(hass, client, account_cfg.token, entry.entry_id)

    # 每个条目一份运行时状态。原先放在 hass.data[DOMAIN] 里，多个条目会互相
    # 覆盖设备列表与任务槽位，卸载任一条目还会把整块数据删掉。
    runtime = HaierRuntimeData(
        entry_id=entry.entry_id,
        client=client,
        devices=devices,
        gateway=gateway,
        ignore_device_offline=preferences_cfg.ignore_device_offline,
        cancel_token_updater=cancel_token_updater,
    )
    entry.runtime_data = runtime

    await hass.config_entries.async_forward_entry_setups(entry, SUPPORTED_PLATFORMS)

    # 实体完成注册后再启动网关，避免初始快照事件无人监听。
    runtime.gateway_task = hass.async_create_background_task(
        gateway.connect(devices),
        'haier-gateway-{}'.format(entry.entry_id)
    )

    entry.async_on_unload(entry.add_update_listener(entry_update_listener))

    async_setup_services(hass)

    return True

async def _try_update_oauth_token(hass: HomeAssistant, entry: ConfigEntry, cfg: AccountConfig) -> bool:
    """
    刷新网页授权（OAuth2）账户的token，刷新成功返回True
    这类token由 ha.haier.net 的OAuth2端点签发，与 zj 网关不互通，
    刷新必须回到签发端点，且clientId须与授权时一致（即 account.client_id）
    :param hass:
    :param entry:
    :param cfg:
    :return:
    """
    now = int(time.time())
    remaining = cfg.expires_at - now

    # 剩余有效期大于缓冲窗口时不做无谓刷新
    if remaining > TOKEN_BUFFER_INTERVAL:
        return False

    # 刚刷新过就不再刷，避免刷新结果的有效期过短时反复重载
    if now - _OAUTH_REFRESHED_AT.get(entry.entry_id, 0) < _OAUTH_REFRESH_GUARD_SECONDS:
        _LOGGER.debug('web-auth token refreshed recently, skip')
        return False

    client = HaierClient(hass, cfg.client_id, cfg.token, cfg.app_source)

    try:
        token_info = await client.oauth_refresh_token(cfg.refresh_token)
    except HaierClientException as err:
        # 已过期且刷新失败：refresh_token 已失效，只能重新授权。
        # 交给 HA 拉起 reauth 流程，否则条目会一直用死 token 空转。
        if remaining <= 0:
            raise ConfigEntryAuthFailed(
                'web-auth token expired, re-authorization required'
            ) from err

        # 只是提前续期没成功，现有token仍然可用，下一轮再试，不打断集成
        _LOGGER.warning('web-auth token refresh failed, keep current token: %s', err)
        return False

    cfg.token = token_info.token
    cfg.refresh_token = token_info.refresh_token
    cfg.expires_at = int(time.time()) + token_info.expires_in
    cfg.save()
    _OAUTH_REFRESHED_AT[entry.entry_id] = now

    _LOGGER.info('web-auth token refreshed, expires_in={}'.format(token_info.expires_in))

    return True


async def token_updater(hass: HomeAssistant, entry: ConfigEntry):
    """
    token更新器
    :param hass:
    :param entry:
    :return:
    """
    async def try_update_token():
        """
        尝试刷新token，刷新成功返回True，如refresh_token无效则会抛出异常
        :return:
        """
        _LOGGER.debug("try update token...")

        cfg = AccountConfig(hass, entry)

        # 网页授权账户的token归属 ha 网关，不能用 zj 的账号接口和刷新接口
        if cfg.app_source == APP_SOURCE_OAUTH:
            return await _try_update_oauth_token(hass, entry, cfg)

        client = HaierClient(hass, cfg.client_id, cfg.token, cfg.app_source)

        token_valid = True
        try:
            await client.get_user_info()
        except HaierClientException:
            token_valid = False

        # token有效且里过期时间大于1天时不更新token
        if token_valid and cfg.expires_at - int(time.time()) > TOKEN_BUFFER_INTERVAL:
            return False

        token_info = await client.refresh_token(cfg.refresh_token)
        cfg.token = token_info.token
        cfg.refresh_token = token_info.refresh_token
        cfg.expires_at = int(time.time()) + token_info.expires_in
        cfg.save()

        return True

    async def task(now):
        try:
            if await try_update_token():
                _LOGGER.info('token refreshed, reload integration...')
                await hass.config_entries.async_reload(entry.entry_id)
            else:
                _LOGGER.debug('token is valid')
        except ConfigEntryAuthFailed:
            # 续期失败且 token 已过期：让用户重新授权，别静默空转
            _LOGGER.warning('token expired, starting re-authorization')
            entry.async_start_reauth(hass)
        except HaierClientException:
            _LOGGER.warning('token refresh authentication failed')
        except Exception:
            _LOGGER.exception('token update failed')

    # 手动执行一次更新
    await try_update_token()

    # 每1小时检查一次token有效性，若token刷新则重载集成
    return async_track_time_interval(hass, task, timedelta(hours=1))

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry):
    if not await hass.config_entries.async_unload_platforms(entry, SUPPORTED_PLATFORMS):
        return False

    runtime: HaierRuntimeData | None = getattr(entry, 'runtime_data', None)
    if runtime is not None:
        # 停止token更新
        if runtime.cancel_token_updater:
            runtime.cancel_token_updater()
            _LOGGER.info('token updater stopped')

        # 断开网关
        if runtime.gateway_task:
            runtime.gateway_task.cancel()
            _LOGGER.info('gateway task cancelled')

    # 服务是 domain 级的，只在最后一个条目卸载时注销，
    # 否则另一个条目还在跑却调不到 send_raw_command
    if not [
        item for item in hass.config_entries.async_entries(DOMAIN)
        if item.entry_id != entry.entry_id
    ]:
        async_unload_services(hass)

    # 刷新节流是按 entry 记的，条目卸载后这条记录没有意义了
    _OAUTH_REFRESHED_AT.pop(entry.entry_id, None)

    return True


async def entry_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    _LOGGER.info('reload haier integration...')
    await hass.config_entries.async_reload(entry.entry_id)

async def async_remove_config_entry_device(hass: HomeAssistant, config: ConfigEntry, device: DeviceEntry) -> bool:
    device_id = list(device.identifiers)[0][1]

    _LOGGER.info('Device [{}] removing...'.format(device_id))

    runtime: HaierRuntimeData | None = getattr(config, 'runtime_data', None)
    target_device = None
    for item in runtime.devices if runtime is not None else []:
        if item.id.lower() == device_id.lower():
            target_device = item
            break

    if target_device is None:
        _LOGGER.error('Device [{}] not found'.format(device_id))
        return False

    cfg = DeviceFilterConfig(hass, config)
    if cfg.filter_type == FILTER_TYPE_EXCLUDE:
        cfg.add_device(target_device.id)
    else:
        cfg.remove_device(target_device.id)

    cfg.save()

    _LOGGER.info('Device [{}] removed'.format(device_id))

    return True

async def async_register_entity(hass: HomeAssistant, entry: ConfigEntry, async_add_entities, platform, setup) -> None:
    runtime: HaierRuntimeData = entry.runtime_data
    entities = []
    for device in runtime.devices:
        if DeviceFilterConfig.is_skip(hass, entry, device.id):
            continue

        for attribute in device.attributes:
            if attribute.platform != platform:
                continue

            if EntityFilterConfig.is_skip(hass, entry, device.id, attribute.key):
                continue

            entities.append(setup(device, attribute, runtime))

    async_add_entities(entities)
