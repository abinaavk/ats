"""One Local webhook receiver; explicit repository/server/service routing only."""
import asyncio
import hashlib
import hmac
import json
import re
import time
from ats_cluster import Store, remote


def route(store, target, headers, body):
    node = store.node()
    if not node or node['role'] != 'local':
        raise ValueError('Only a configured primary Local accepts webhooks')
    payload = json.loads(body)
    if not isinstance(payload, dict) or not isinstance(payload.get('repository'), dict):
        raise ValueError('Repository required')
    repository = payload['repository'].get('full_name')
    if not isinstance(repository, str):
        raise ValueError('Full repository identity required')
    with store.db() as db:
        row = db.execute('SELECT * FROM routes WHERE repository=? COLLATE NOCASE', (repository,)).fetchone()
    if not row:
        raise ValueError('No explicit mapping')
    row = dict(row)
    if target not in ('/webhook', '/webhook/'+row['service']):
        raise ValueError('Destination does not match explicit mapping')
    sig = headers.get('x-hub-signature-256', '')
    expected = 'sha256='+hmac.new(row['secret'].encode(), body, hashlib.sha256).hexdigest()
    if not re.fullmatch('sha256=[0-9a-f]{64}', sig) or not hmac.compare_digest(sig, expected):
        raise PermissionError('Invalid GitHub signature')
    event = headers.get('x-github-event')
    if event not in ('push', 'ping'):
        raise ValueError('Only push and ping events supported')
    if event == 'ping':
        return row, payload, None
    if payload.get('ref') != 'refs/heads/'+row['branch'] or payload.get('deleted') is True:
        raise ValueError('Ref does not match mapping or branch was deleted')
    if not isinstance(payload.get('after'), str) or not re.fullmatch('[0-9a-f]{40,64}', payload.get('after', '')):
        raise ValueError('Invalid commit identity')
    delivery = headers.get('x-github-delivery', '')
    if not re.fullmatch('[A-Za-z0-9_-]{1,100}', delivery):
        raise ValueError('Delivery identity required')
    server = store.server(row['server_id'])
    if not server['connected']:
        raise ConnectionError('Destination disconnected')
    # Atomic delivery AND content deduplication: changing a delivery header cannot replay a push.
    fingerprint = hashlib.sha256(body).hexdigest()
    with store.db() as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT 1 FROM seen WHERE scope=? AND nonce IN (?,?)', ('webhook', delivery, fingerprint)).fetchone():
            return row, payload, False
        data = json.dumps(dict(route=row, payload=payload, delivery=delivery))
        for nonce in (delivery, fingerprint):
            db.execute('INSERT INTO seen VALUES(?,?,?,\'pending\',?)', ('webhook', nonce, time.time(), data))
    return row, payload, delivery


async def receive(a, target, headers, body):
    store = Store()
    try:
        mapping, payload, delivery = route(store, target, headers, body)
    except PermissionError:
        return 401, 'Unauthorized'
    except (ValueError, TypeError):
        return 400, 'Invalid or unmapped delivery'
    except ConnectionError:
        return 503, 'Mapped server disconnected'
    if delivery is None:
        return 200, 'OK'
    if delivery is False:
        return 200, 'Duplicate delivery; inspect recorded status before retrying'
    # The delivery is durable before acknowledgement. The daemon worker owns execution.
    task = asyncio.create_task(process(a, store, delivery))
    a._WEBHOOK_TASKS.add(task)
    task.add_done_callback(a._WEBHOOK_TASKS.discard)
    return 202, 'Accepted'


async def process(a, store, delivery):
    with store.db() as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT * FROM seen WHERE scope=\'webhook\' AND nonce=? AND state=\'pending\'', (delivery,)).fetchone()
        if not row:
            return
        db.execute('UPDATE seen SET state=\'running\' WHERE scope=\'webhook\' AND nonce=?', (delivery,))
    data = json.loads(row['result']); mapping = data['route']
    status = 'failed'
    try:
        server = store.server(mapping['server_id'])
        if server['local']:
            service = a.get_service_by_name(mapping['service'])
            repo = (service or {}).get('repo_url', '').removesuffix('.git').replace('git@github.com:', 'https://github.com/').removeprefix('https://github.com/')
            if not service or service['branch'] != mapping['branch'] or repo.lower() != mapping['repository'].lower():
                raise ValueError('Local service/branch no longer matches mapping')
            if not service.get('auto_update', 1):
                raise ValueError('Local auto update disabled')
            await asyncio.to_thread(a.service_git_update, mapping['service'], service, a._logger_log)
            result = {'updated': True}
        else:
            result = await asyncio.to_thread(remote, server, {'kind': 'http', 'method': 'POST',
                'path': '/api/manage/services/'+mapping['service']+'/action',
                'body': {'action': 'update'}, 'delivery': delivery,
                'repository': mapping['repository'], 'branch': mapping['branch']})
            if result.get('status', 500) >= 400:
                raise ValueError('Global deployment request failed')
        status = 'updated' if server['local'] else 'dispatched'
    except Exception:
        # Do not blindly retry an operation whose result may be ambiguous.
        result = {'error': 'Delivery failed or outcome unknown; inspect destination before a manual retry'}
    with store.db() as db:
        db.execute('UPDATE seen SET state=?,result=? WHERE scope=\'webhook\' AND nonce=?', (status, json.dumps(result), delivery))
    a.record_webhook_event(mapping['service'], 'push', data['payload']['ref'], data['payload']['after'],
                           status, json.dumps(result)[:500], delivery=delivery, signature='verified')


async def recover(a):
    store = Store()
    # An interrupted running delivery has an uncertain outcome and requires operator inspection.
    with store.db() as db:
        db.execute('UPDATE seen SET state=\'interrupted\' WHERE scope=\'webhook\' AND state=\'running\'')
        rows = db.execute('SELECT nonce,result FROM seen WHERE scope=\'webhook\' AND state=\'pending\'').fetchall()
    for row in rows:
        data = json.loads(row['result'])
        if row['nonce'] == data['delivery']:
            await process(a, store, row['nonce'])
