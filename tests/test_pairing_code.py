"""One-time pairing codes and in-channel key rotation, over a real TLS Global listener."""
import http.client
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import ats_cluster as cluster
import ats_remote
import test_cluster


class CodeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = cluster.Store(Path(self.tmp.name) / 'global.db')
        self.node = self.store.configure('global', 'Global', 'https://api.example.com')

    def test_a_code_works_once_and_hands_over_the_pairing_details(self):
        code, expires = self.store.make_pair_code(10)
        self.assertRegex(code, r'^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$')
        self.assertTrue(540 < expires - time.time() <= 600)
        bundle = self.store.redeem_pair_code(code)
        self.assertEqual((bundle['id'], bundle['secret'], bundle['role']), (self.node['id'], self.node['secret'], 'global'))
        with self.assertRaisesRegex(ValueError, 'Invalid or expired'):
            self.store.redeem_pair_code(code)

    def test_codes_are_stored_only_as_hashes_and_typing_is_forgiving(self):
        code, _ = self.store.make_pair_code()
        with self.store.db() as db:
            stored = [r[0] for r in db.execute('SELECT hash FROM pair_codes')]
        self.assertTrue(all(len(h) == 64 for h in stored))
        self.assertNotIn(code.replace('-', ''), ' '.join(stored))
        self.assertEqual(self.store.redeem_pair_code(' ' + code.lower().replace('-', ' ') + ' ')['id'], self.node['id'])

    def test_expired_wrong_malformed_and_foreign_codes_are_rejected_alike(self):
        code, _ = self.store.make_pair_code(1)
        with self.store.db() as db:
            db.execute('UPDATE pair_codes SET expires=?', (time.time() - 1,))
        for bad in (code, 'AAAA-BBBB-CCCC', '', 'short', 'x' * 100, 'AAAA-BBBB-CCC0', None, 12345, ['a']):
            with self.store.db() as db:
                db.execute('DELETE FROM pair_attempts')                       # this test is about rejection, not the rate limit
            with self.assertRaisesRegex(ValueError, 'Invalid or expired'):
                self.store.redeem_pair_code(bad)
        local = cluster.Store(Path(self.tmp.name) / 'local.db')
        local.configure('local', 'Local', webhook='hooks.example.com')
        with self.assertRaises(ValueError):
            local.make_pair_code()
        with self.assertRaisesRegex(ValueError, 'Invalid or expired'):
            local.redeem_pair_code(code)

    def test_guessing_is_rate_limited_and_limits_apply_to_creation(self):
        for _ in range(8):
            with self.assertRaisesRegex(ValueError, 'Invalid or expired'):
                self.store.redeem_pair_code('AAAA-BBBB-CCCC')
        code, _ = self.store.make_pair_code()
        with self.assertRaises(cluster.RateLimited):
            self.store.redeem_pair_code(code)                      # even the right code waits out the lockout
        with self.store.db() as db:
            db.execute('UPDATE pair_attempts SET at=at-120')
        self.assertEqual(self.store.redeem_pair_code(code)['id'], self.node['id'])
        for minutes in (0, 61, True, '5', None):
            with self.assertRaises(ValueError):
                self.store.make_pair_code(minutes)
        for _ in range(5):
            self.store.make_pair_code()
        with self.assertRaisesRegex(ValueError, 'Five pairing codes'):
            self.store.make_pair_code()


class OverTLS(unittest.TestCase):
    setUp = test_cluster.TLSIntegrationTests.setUp

    def local(self):
        local = cluster.Store(Path(self.temp.name) / 'local.db')
        local.configure('local', 'Local', webhook='hooks.example.com')
        return local

    def test_pairing_with_a_code_needs_no_key_to_be_copied(self):
        local = self.local()
        code, _ = self.global_store.make_pair_code()
        health = local.pair_by_code(self.origin, code)
        self.assertEqual(health['role'], 'global')
        saved = local.server(self.node['id'])
        self.assertEqual((saved['secret'], saved['domain'], saved['connected']), (self.node['secret'], self.origin, 1))
        self.assertEqual(cluster.remote(saved, {'kind': 'health'})['server_id'], self.node['id'])
        with self.assertRaisesRegex(cluster.TransportError, 'wrong, already used or expired') as caught:
            local.pair_by_code(self.origin, code)
        self.assertEqual(caught.exception.code, 'auth')
        self.assertNotIn(self.node['secret'], str(caught.exception))

    def test_a_chosen_name_is_used_and_attempts_are_limited_over_the_wire(self):
        local = self.local()
        code, _ = self.global_store.make_pair_code()
        local.pair_by_code(self.origin, code, 'Build box')
        self.assertEqual(local.server(self.node['id'])['name'], 'Build box')
        for _ in range(8):
            with self.assertRaises(cluster.TransportError):
                cluster.pair_remote(self.origin, 'AAAA-BBBB-CCCC')
        with self.assertRaisesRegex(cluster.TransportError, 'too many pairing attempts') as caught:
            cluster.pair_remote(self.origin, 'AAAA-BBBB-CCCC')
        self.assertEqual(caught.exception.code, 'ratelimit')

    def test_only_a_pairing_request_may_be_unsigned(self):
        def post(payload):
            conn = http.client.HTTPSConnection('localhost', self.http.server_port, timeout=10)
            conn.request('POST', '/v1/request', json.dumps(payload), {'Content-Type': 'application/json'})
            response = conn.getresponse()
            status, body = response.status, json.loads(response.read())
            conn.close()
            return status, body
        for payload in ({'kind': 'health'}, {'kind': 'term.open'}, {'kind': 'http', 'method': 'GET', 'path': '/api/manage/services'},
                        {'kind': 'rotate'}, {'kind': 'pair'}, {'kind': 'pair', 'code': 5}, {'kind': 'pair', 'code': 'x' * 100}):
            status, body = post(payload)
            self.assertEqual(status, 401, payload)
            self.assertEqual(set(body), {'ok', 'error', 'server_time'})
        self.assertEqual(post({'kind': 'pair', 'code': 'AAAA-BBBB-CCCC'})[0], 403)

    def test_rotation_over_the_channel_keeps_both_sides_in_step(self):
        local = self.local()
        local.pair(self.node['id'], 'Remote', self.origin, self.node['secret'])
        old = self.node['secret']
        result = local.rotate_global(self.node['id'])
        fresh = self.global_store.node()['secret']
        self.assertNotEqual(fresh, old)
        self.assertEqual(local.server(self.node['id'])['secret'], fresh)
        self.assertEqual(result['grace_seconds'], cluster.KEY_GRACE)
        self.assertEqual(json.loads(self.pairing.read_text())['secret'], fresh)             # the export carries the new key
        self.assertEqual(cluster.remote(local.server(self.node['id']), {'kind': 'health'})['role'], 'global')
        # The old key still works for the grace period, never beyond it, and a revoke ends it at once.
        self.assertEqual(cluster.remote(dict(self.server, secret=old), {'kind': 'health'})['role'], 'global')
        with self.global_store.db() as db:
            db.execute('UPDATE previous_key SET until=?', (time.time() - 1,))
        with self.assertRaises(cluster.TransportError):
            cluster.remote(dict(self.server, secret=old), {'kind': 'health'})

    def test_revoking_ends_the_grace_period_and_a_failed_verification_changes_nothing(self):
        local = self.local()
        local.pair(self.node['id'], 'Remote', self.origin, self.node['secret'])
        old = self.node['secret']
        local.rotate_global(self.node['id'])
        local.connection(self.node['id'], 'revoke')
        self.assertIsNone(self.global_store.previous_key())
        with self.assertRaises(cluster.TransportError):
            cluster.remote(dict(self.server, secret=old), {'kind': 'health'})
        # A verification failure on the Local side must leave the saved key alone, and it must still work during the grace period.
        local2 = cluster.Store(Path(self.temp.name) / 'local2.db')
        local2.configure('local', 'Local2', webhook='hooks2.example.com')
        current = self.global_store.node()
        local2.pair(current['id'], 'Remote', self.origin, current['secret'])
        before = local2.server(current['id'])
        with patch.object(cluster.Store, '_verified', side_effect=ValueError('boom')):
            with self.assertRaisesRegex(ValueError, 'old key still works'):
                local2.rotate_global(current['id'])
        self.assertEqual(local2.server(current['id'])['secret'], before['secret'])
        self.assertEqual(cluster.remote(local2.server(current['id']), {'kind': 'health'})['role'], 'global')

    def test_rotation_is_refused_for_disconnected_or_local_entries(self):
        local = self.local()
        local.pair(self.node['id'], 'Remote', self.origin, self.node['secret'])
        local.connection(self.node['id'], 'disconnect')
        with self.assertRaisesRegex(ValueError, 'Reconnect this server'):
            local.rotate_global(self.node['id'])
        with self.assertRaises(ValueError):
            local.rotate_global(local.node()['id'])


if __name__ == '__main__':
    unittest.main()
