"""Off-host copies of the registry backup: encrypted only, chunked, verified, fetched back, over a real TLS Global."""
import base64
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import ats_cluster as cluster
import ats_registry_backup as backups
import test_cluster

HAVE_OPENSSL = os.system('openssl version >/dev/null 2>&1') == 0
PASS = 'a long enough passphrase'


@unittest.skipUnless(HAVE_OPENSSL, 'openssl not installed')
class OffsiteTests(unittest.TestCase):
    setUp = test_cluster.TLSIntegrationTests.setUp

    def prepare(self):
        self.local = cluster.Store(Path(self.temp.name) / 'local.db')
        self.local.configure('local', 'Primary', webhook='hooks.example.com')
        self.local.pair(self.node['id'], 'Remote', self.origin, self.node['secret'])
        self.stored = backups.offsite_dir(self.global_store, False)

    def small_chunks(self, size=2000):
        patcher = mock.patch.object(backups, 'CHUNK', size)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_copy_travels_in_chunks_arrives_intact_and_comes_back_byte_for_byte(self):
        self.prepare()
        self.small_chunks()
        results = backups.push_offsite(self.local, PASS)
        result = results[self.node['id']]
        self.assertTrue(result['ok'], result)
        files = list(self.stored.glob('registry-*.sqlite3.enc'))
        self.assertEqual(len(files), 1)
        self.assertEqual(oct(files[0].stat().st_mode & 0o777), '0o600')
        self.assertEqual(oct(self.stored.stat().st_mode & 0o777), '0o700')
        data = files[0].read_bytes()
        self.assertTrue(data.startswith(backups.MAGIC) and len(data) > 2 * backups.CHUNK)          # really several chunks
        for secret in (self.node['secret'], self.local.node()['secret']):
            self.assertNotIn(secret.encode(), data)                                                # the Global never holds a readable key
        self.assertEqual(list(self.stored.glob('.incoming-*')), [])
        listed = cluster.remote(self.local.server(self.node['id']), {'kind': 'backup.list'})['backups']
        self.assertEqual([b['name'] for b in listed], [files[0].name])
        out = Path(self.temp.name) / 'back.enc'
        got = backups.fetch_offsite(self.local, self.local.server(self.node['id']), None, out)
        self.assertEqual((out.read_bytes(), got['name']), (data, files[0].name))
        info = backups.describe(out, PASS)
        self.assertEqual((info['role'], info['name']), ('local', 'Primary'))
        self.assertEqual(backups.offsite_status(self.local)[self.node['id']]['ok'], True)

    def test_unencrypted_data_never_leaves_the_local_and_is_refused_by_the_global_even_if_sent(self):
        self.prepare()
        plain = backups.create(self.local)
        with self.assertRaisesRegex(ValueError, 'Only an encrypted backup'):
            backups.push_file(self.local, plain['path'])
        with self.assertRaisesRegex(ValueError, 'Off-host copies are always encrypted'):
            backups.push_offsite(self.local)
        # A modified client that skips the check: the Global still refuses the first chunk.
        body = {'kind': 'backup.put', 'name': 'registry-20260101-000000.sqlite3.enc', 'index': 0, 'total': 1,
                'data': base64.b64encode(Path(plain['path']).read_bytes()).decode(), 'sha256': 'x'}
        with self.assertRaisesRegex(cluster.TransportError, 'Only encrypted backups are accepted'):
            cluster.remote(self.local.server(self.node['id']), body)
        self.assertEqual(list(self.stored.glob('registry-*')) if self.stored.exists() else [], [])

    def test_corruption_disorder_bad_names_and_oversize_store_nothing(self):
        self.prepare()
        self.small_chunks(1000)
        encrypted = backups.create(self.local, Path(self.temp.name) / 'registry-20260101-000000.sqlite3.enc', PASS)
        blob = Path(encrypted['path']).read_bytes()
        server, name = self.local.server(self.node['id']), 'registry-20260101-000000.sqlite3.enc'
        total = -(-len(blob) // 1000)

        def put(index, data=None, sha=None, total_=total, name_=name):
            raw = blob[index * 1000:(index + 1) * 1000] if data is None else data
            return cluster.remote(server, {'kind': 'backup.put', 'name': name_, 'index': index, 'total': total_,
                                           'data': base64.b64encode(raw).decode(), 'sha256': sha or hashlib.sha256(blob).hexdigest()})
        with self.assertRaisesRegex(cluster.TransportError, 'in order'):
            put(1)                                                                              # the first chunk must come first
        put(0)
        with self.assertRaisesRegex(cluster.TransportError, 'in order'):
            put(2)                                                                              # and none may be skipped
        for index in range(1, total - 1):
            put(index)
        with self.assertRaisesRegex(cluster.TransportError, 'checksum'):
            put(total - 1, sha='0' * 64)
        self.assertEqual(list(self.stored.glob('registry-*')), [])                              # a bad copy never appears under the real name
        self.assertEqual(list(self.stored.glob('.incoming-*')), [])
        for bad in ('../x.enc', 'registry-1.enc', 'registry-20260101-000000.sqlite3', name + '/../y', 'x' * 300):
            with self.assertRaises(cluster.TransportError, msg=bad):
                put(0, name_=bad)
        with self.assertRaisesRegex(cluster.TransportError, 'larger|not valid'):
            put(0, total_=100000)
        with self.assertRaisesRegex(cluster.TransportError, 'chunk size'):
            put(0, data=blob[:500])                                                             # only the last chunk may be short
        for bad in ({'data': '!!!notbase64'}, {'index': True}, {'index': -1}, {'index': 5, 'total': 2}, {'total': 0}):
            body = {'kind': 'backup.put', 'name': name, 'index': 0, 'total': 3, 'data': 'AAAA', 'sha256': 'x'}
            body.update(bad)
            with self.assertRaises(cluster.TransportError, msg=bad):
                cluster.remote(server, body)

    def test_the_last_ten_are_kept_and_reading_is_limited_to_real_backup_names(self):
        self.prepare()
        folder = backups.offsite_dir(self.global_store)
        for day in range(1, 13):
            (folder / f'registry-202001{day:02d}-000000.sqlite3.enc').write_bytes(backups.MAGIC + b'x')
        self.small_chunks()
        backups.push_offsite(self.local, PASS)
        names = sorted(p.name for p in folder.glob('registry-*'))
        self.assertEqual(len(names), backups.OFFSITE_KEEP)
        self.assertNotIn('registry-20200101-000000.sqlite3.enc', names)
        (folder / 'notes.txt').write_text('mine')
        outside = Path(self.temp.name) / 'secret.enc'
        outside.write_bytes(backups.MAGIC + b'secret')
        (folder / 'registry-20190101-000000.sqlite3.enc').symlink_to(outside)
        server = self.local.server(self.node['id'])
        for bad in ('../secret.enc', str(outside), 'notes.txt', 'registry-20190101-000000.sqlite3.enc', 'registry-20180101-000000.sqlite3.enc'):
            with self.assertRaises(cluster.TransportError, msg=bad):
                cluster.remote(server, {'kind': 'backup.get', 'name': bad, 'index': 0})
        with self.assertRaises(cluster.TransportError):
            cluster.remote(server, {'kind': 'backup.get', 'name': names[-1], 'index': 99999})
        self.assertTrue((folder / 'notes.txt').exists())

    def test_one_unreachable_global_does_not_stop_the_others_and_failure_is_recorded(self):
        self.prepare()
        other = cluster.Store(Path(self.temp.name) / 'other-global.db')
        node = other.configure('global', 'Second', 'https://other.example.com')
        with mock.patch.object(cluster.Store, '_verified', return_value={}):
            self.local.pair(node['id'], 'Second', 'https://other.example.com', node['secret'])
        real = cluster.remote

        def call(server, payload, timeout=None):
            if server['id'] == node['id']:
                raise cluster.TransportError('other.example.com refused the connection.', 'refused')
            return real(server, payload, timeout=timeout)
        self.small_chunks()
        results = backups.push_offsite(self.local, PASS, call=call)
        self.assertEqual((results[self.node['id']]['ok'], results[node['id']]['ok']), (True, False))
        self.assertIn('refused', results[node['id']]['error'])
        self.assertEqual(len(list(self.stored.glob('registry-*'))), 1)
        self.assertEqual(backups.offsite_status(self.local)[node['id']]['server'], 'Second')

    def test_no_connected_global_means_a_plain_error_and_a_local_cannot_receive(self):
        local = cluster.Store(Path(self.temp.name) / 'lonely.db')
        local.configure('local', 'Lonely', webhook='hooks.example.com')
        with self.assertRaisesRegex(ValueError, 'No connected Global'):
            backups.push_offsite(local, PASS)
        with self.assertRaisesRegex(ValueError, 'Only a Global'):
            backups.receive(local, {'name': 'registry-20260101-000000.sqlite3.enc', 'index': 0, 'total': 1, 'data': '', 'sha256': ''})

    def test_the_daily_worker_sends_a_copy_only_when_it_made_an_encrypted_backup(self):
        self.prepare()
        self.small_chunks()
        passfile = Path(self.temp.name) / 'pass'
        passfile.write_text(PASS + '\n')
        with mock.patch.dict(os.environ, {'ATS_REGISTRY_BACKUP_PASSPHRASE_FILE': str(passfile)}):
            record = backups.run_scheduled(self.local)
        self.assertTrue(record['encrypted'] and record['error'] is None)
        self.assertEqual(len(list(self.stored.glob('registry-*'))), 1)
        (Path(self.temp.name) / 'plainroot').mkdir()
        other = cluster.Store(Path(self.temp.name) / 'plainroot' / 'plain.db')
        other.configure('local', 'Plain', webhook='hooks.example.com')
        other.pair(self.node['id'], 'Remote', self.origin, self.node['secret'])
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('ATS_REGISTRY_BACKUP_PASSPHRASE_FILE', None)
            self.assertFalse(backups.run_scheduled(other)['encrypted'])
        self.assertEqual(len(list(self.stored.glob('registry-*'))), 1)                        # plain backups stay on their own disk

    def test_fetch_refuses_to_overwrite_and_checks_what_came_back(self):
        self.prepare()
        self.small_chunks()
        backups.push_offsite(self.local, PASS)
        server = self.local.server(self.node['id'])
        existing = Path(self.temp.name) / 'mine'
        existing.write_text('precious')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            backups.fetch_offsite(self.local, server, None, existing)
        self.assertEqual(existing.read_text(), 'precious')
        real = cluster.remote

        def tampered(server, payload, timeout=None):
            result = real(server, payload, timeout=timeout)
            if payload['kind'] == 'backup.get' and payload['index'] == 1:
                result = dict(result, data=base64.b64encode(b'x' * backups.CHUNK).decode())
            return result
        out = Path(self.temp.name) / 'tampered'
        with self.assertRaisesRegex(ValueError, 'checksum'):
            backups.fetch_offsite(self.local, server, None, out, call=tampered)
        self.assertFalse(out.exists())
        with self.assertRaisesRegex(ValueError, 'holds no copies'):
            backups.fetch_offsite(self.local, server, None, out, call=lambda s, p, timeout=None: {'backups': []})


if __name__ == '__main__':
    unittest.main()
