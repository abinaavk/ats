"""Alert channels: ntfy, Telegram and a generic webhook. HTTPS only, no redirects, secrets never echoed.

Settings live in the private cluster registry (the same trust level as the server keys). API and UI only ever see
masked values; saving a masked value keeps the stored secret.
"""
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

MASK = '********'
DEFAULT = {'ntfy': {'url': '', 'token': ''}, 'telegram': {'token': '', 'chat_id': ''}, 'webhook': {'url': ''},
           'enabled': {'ntfy': False, 'telegram': False, 'webhook': False},
           'thresholds': {'failures': 3, 'disk': 90, 'memory': 95},
           'watch': {'kinds': ['deployment', 'service', 'health', 'backup'], 'failed_units': True, 'ignore_units': []}}
KINDS = ('deployment', 'service', 'health', 'backup', 'disk')    # what a server's collector can raise; disk is covered by the threshold
SECRET_FIELDS = {'ntfy': ('token',), 'telegram': ('token',), 'webhook': ('url',)}
LEVEL = {'down': ('high', 'rotating_light'), 'warn': ('high', 'warning'), 'recovered': ('default', 'white_check_mark'), 'info': ('default', 'information_source')}


class NotifyError(ValueError):
    """A delivery failure described without the URL or token."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def urlopen(request, timeout):
    return urllib.request.build_opener(NoRedirect).open(request, timeout=timeout)


def _https(value, label):
    if not isinstance(value, str) or len(value) > 400:
        raise ValueError(f'{label} must be an https:// address')
    parts = urlsplit(value.strip())
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.fragment or len(parts.hostname) > 253:
        raise ValueError(f'{label} must be an https:// address without credentials')
    return value.strip()


def validate(config):
    """Return a clean copy of a settings dict, or raise ValueError saying which field is wrong."""
    if not isinstance(config, dict):
        raise ValueError('Settings must be an object')
    result = json.loads(json.dumps(DEFAULT))
    ntfy, telegram, webhook = (config.get(k) or {} for k in ('ntfy', 'telegram', 'webhook'))
    if ntfy.get('url'):
        result['ntfy']['url'] = _https(ntfy['url'], 'The ntfy address')
    if ntfy.get('token'):
        if not isinstance(ntfy['token'], str) or not re.fullmatch(r'[A-Za-z0-9_.-]{4,200}', ntfy['token']):
            raise ValueError('The ntfy token has unexpected characters')
        result['ntfy']['token'] = ntfy['token']
    if telegram.get('token'):
        if not isinstance(telegram['token'], str) or not re.fullmatch(r'\d{5,12}:[A-Za-z0-9_-]{30,60}', telegram['token']):
            raise ValueError('The Telegram bot token looks wrong (expected 123456:ABC…)')
        result['telegram']['token'] = telegram['token']
    if telegram.get('chat_id') not in (None, ''):
        if not isinstance(telegram['chat_id'], (str, int)) or isinstance(telegram['chat_id'], bool) or not re.fullmatch(r'-?\d{1,20}|@[A-Za-z0-9_]{4,64}', str(telegram['chat_id'])):
            raise ValueError('The Telegram chat id must be a number or @channelname')
        result['telegram']['chat_id'] = str(telegram['chat_id'])
    if webhook.get('url'):
        result['webhook']['url'] = _https(webhook['url'], 'The webhook address')
    enabled = config.get('enabled') or {}
    for channel in result['enabled']:
        value = enabled.get(channel, False)
        if not isinstance(value, bool):
            raise ValueError(f'enabled.{channel} must be true or false')
        result['enabled'][channel] = value
    limits = config.get('thresholds') or {}
    for key, low, high in (('failures', 1, 20), ('disk', 50, 99), ('memory', 50, 99)):
        value = limits.get(key, DEFAULT['thresholds'][key])
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f'The {key} threshold must be between {low} and {high}')
        result['thresholds'][key] = value
    watch = config.get('watch') or {}
    if not isinstance(watch, dict):
        raise ValueError('watch must be an object')
    kinds = watch.get('kinds', DEFAULT['watch']['kinds'])
    if not isinstance(kinds, list) or any(k not in KINDS for k in kinds) or len(set(kinds)) != len(kinds):
        raise ValueError('Choose alert kinds from: ' + ', '.join(KINDS))
    result['watch']['kinds'] = [k for k in KINDS if k in kinds]
    flag = watch.get('failed_units', True)
    if not isinstance(flag, bool):
        raise ValueError('failed_units must be true or false')
    result['watch']['failed_units'] = flag
    ignore = watch.get('ignore_units', [])
    if isinstance(ignore, str):
        ignore = ignore.replace(',', ' ').split()
    if not isinstance(ignore, list) or len(ignore) > 50 or any(not isinstance(u, str) or not re.fullmatch(r'[A-Za-z0-9@_.:-]{1,100}\.(service|socket|timer|mount)', u) for u in ignore):
        raise ValueError('Ignored units must look like name.service (up to 50, separated by spaces or commas)')
    result['watch']['ignore_units'] = sorted(set(ignore))
    if result['enabled']['ntfy'] and not result['ntfy']['url']:
        raise ValueError('Enter the ntfy address before turning ntfy on')
    if result['enabled']['telegram'] and not (result['telegram']['token'] and result['telegram']['chat_id']):
        raise ValueError('Enter the Telegram bot token and chat id before turning Telegram on')
    if result['enabled']['webhook'] and not result['webhook']['url']:
        raise ValueError('Enter the webhook address before turning it on')
    return result


def load(store):
    saved = store.kv_get('notify')
    try:
        return validate(saved) if saved else json.loads(json.dumps(DEFAULT))
    except ValueError:
        return json.loads(json.dumps(DEFAULT))


def mask(config):
    """The same settings with every secret replaced by a placeholder (or empty when unset)."""
    result = json.loads(json.dumps(config))
    for channel, fields in SECRET_FIELDS.items():
        for field in fields:
            if result[channel].get(field):
                result[channel][field] = MASK
    return result


def save(store, incoming):
    """Validate and store settings; a field sent back as the mask keeps its stored value."""
    current = load(store)
    merged = json.loads(json.dumps(incoming if isinstance(incoming, dict) else {}))
    for channel, fields in SECRET_FIELDS.items():
        for field in fields:
            if (merged.get(channel) or {}).get(field) == MASK:
                merged[channel][field] = current[channel][field]
    clean = validate(merged)
    store.kv_set('notify', clean)
    return mask(clean)


def _post(url, body, headers, timeout, opener=None):
    request = urllib.request.Request(url, data=body, headers=headers, method='POST')
    try:
        with (opener or urlopen)(request, timeout) as response:
            if not 200 <= response.status < 300:
                raise NotifyError(f'HTTP {response.status}')
    except urllib.error.HTTPError as exc:
        raise NotifyError(f'HTTP {exc.code}') from None
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        raise NotifyError(type(getattr(exc, 'reason', exc)).__name__) from None


def _ascii(text):
    return text.encode('ascii', 'replace').decode()[:120]


def send(config, title, message, level='info', timeout=10, opener=None):
    """Deliver to every enabled channel. Returns {channel: {'ok': bool, 'error': str|None}}; one failure never stops the others."""
    outcome = {}
    priority, tag = LEVEL.get(level, LEVEL['info'])
    for channel, enabled in config['enabled'].items():
        if not enabled:
            continue
        try:
            if channel == 'ntfy':
                headers = {'Title': _ascii(title), 'Priority': priority, 'Tags': tag, 'User-Agent': 'ATS-Monitor/1'}
                if config['ntfy']['token']:
                    headers['Authorization'] = 'Bearer ' + config['ntfy']['token']
                _post(config['ntfy']['url'], message.encode(), headers, timeout, opener)
            elif channel == 'telegram':
                body = json.dumps({'chat_id': config['telegram']['chat_id'], 'text': f'{title}\n{message}'}).encode()
                _post(f"https://api.telegram.org/bot{config['telegram']['token']}/sendMessage", body,
                      {'Content-Type': 'application/json', 'User-Agent': 'ATS-Monitor/1'}, timeout, opener)
            elif channel == 'webhook':
                body = json.dumps({'title': title, 'message': message, 'level': level, 'at': int(time.time())}).encode()
                _post(config['webhook']['url'], body, {'Content-Type': 'application/json', 'User-Agent': 'ATS-Monitor/1'}, timeout, opener)
            outcome[channel] = {'ok': True, 'error': None}
        except NotifyError as exc:
            outcome[channel] = {'ok': False, 'error': str(exc)}
    return outcome
