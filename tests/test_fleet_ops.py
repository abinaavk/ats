"""Registry backups, alert channels and the fleet watcher."""
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import time
import unittest
from unittest import mock

import ats_cluster as cluster
import ats_fleet
import ats_notify
import ats_registry_backup as backups

HAVE_OPENSSL = os.system('openssl version >/dev/null 2>&1') == 0


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = cluster.Store(self.root / 'registry.sqlite3')
        self.node = self.store.configure('global', 'Global One', 'https://api.example.com')


class BackupTests(Base):
    def test_backup_is_private_consistent_and_described(self):
        made = backups.create(self.store)
        path = Path(made['path'])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        info = backups.describe(path)
        self.assertEqual((info['id'], info['role'], info['name']), (self.node['id'], 'global', 'Global One'))
        self.assertFalse(info['encrypted'])
        self.assertEqual(list(path.parent.glob('.*')), [])               # no half-written leftovers

    def test_restore_returns_the_registry_to_the_backed_up_state_with_a_safety_copy(self):
        made = backups.create(self.store)
        self.store.make_pair_code()
        self.store.kv_set('marker', 'after')
        done = backups.restore(self.store, made['path'])
        self.assertTrue(Path(done['safety_copy']).is_file())
        self.assertIsNone(self.store.kv_get('marker'))
        self.assertEqual(self.store.node()['secret'], self.node['secret'])
        safety = sqlite3.connect(done['safety_copy'])
        self.assertEqual(safety.execute("SELECT value FROM kv WHERE key='marker'").fetchone()[0], '"after"')
        safety.close()

    def test_bad_files_and_foreign_identities_never_touch_the_live_registry(self):
        junk = self.root / 'junk.sqlite3'
        junk.write_bytes(b'not a database at all' * 50)
        empty = self.root / 'empty.sqlite3'
        sqlite3.connect(empty).execute('CREATE TABLE x(a)').connection.close()
        for bad in (junk, empty, self.root / 'missing'):
            with self.assertRaises(ValueError):
                backups.restore(self.store, bad)
        other = cluster.Store(self.root / 'other.sqlite3')
        other.configure('global', 'Other', 'https://other.example.com')
        theirs = backups.create(other, self.root / 'theirs.sqlite3')
        with self.assertRaisesRegex(ValueError, 'different server'):
            backups.restore(self.store, theirs['path'])
        self.assertEqual(self.store.node()['id'], self.node['id'])
        self.assertEqual(backups.restore(self.store, theirs['path'], force=True)['name'], 'Other')

    def test_existing_output_is_never_overwritten_and_short_passphrases_are_refused(self):
        target = self.root / 'mine.sqlite3'
        target.write_text('precious')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            backups.create(self.store, target)
        self.assertEqual(target.read_text(), 'precious')
        with self.assertRaisesRegex(ValueError, 'at least 8'):
            backups.create(self.store, passphrase='short')

    @unittest.skipUnless(HAVE_OPENSSL, 'openssl not installed')
    def test_encrypted_backup_hides_the_keys_and_needs_the_right_passphrase(self):
        made = backups.create(self.store, passphrase='correct horse battery')
        data = Path(made['path']).read_bytes()
        self.assertTrue(made['encrypted'] and backups.is_encrypted(made['path']))
        self.assertNotIn(self.node['secret'].encode(), data)
        self.assertNotIn(b'SQLite format', data)
        with self.assertRaisesRegex(ValueError, 'passphrase is required'):
            backups.describe(made['path'])
        with self.assertRaisesRegex(ValueError, 'Wrong passphrase'):
            backups.describe(made['path'], 'wrong passphrase!')
        self.assertEqual(backups.describe(made['path'], 'correct horse battery')['id'], self.node['id'])
        self.assertEqual(backups.restore(self.store, made['path'], 'correct horse battery')['name'], 'Global One')
        self.assertEqual(list(self.root.glob('.ats-*')), [])

    def test_scheduled_backup_runs_daily_prunes_and_records_failures(self):
        first = backups.run_scheduled(self.store)
        self.assertIsNone(first['error'])
        self.assertIsNone(backups.run_scheduled(self.store))             # newest is fresh: nothing to do
        folder = backups.directory(self.store)
        for day in range(1, 10):
            (folder / f'registry-2020010{day}-000000.sqlite3').write_bytes(b'x')
        backups.prune(self.store)
        self.assertEqual(len(backups.listing(self.store)), backups.KEEP)
        self.assertEqual(backups.listing(self.store)[0]['name'], Path(first['path']).name)
        with mock.patch.object(backups, 'create', side_effect=OSError('disk full')):
            failed = backups.run_scheduled(self.store, now=time.time() + 2 * backups.INTERVAL)
        self.assertIn('disk full', failed['error'])
        self.assertIn('disk full', backups.status(self.store)['last']['error'])

    def test_unrelated_files_in_the_backup_folder_are_ignored_by_pruning(self):
        folder = backups.directory(self.store)
        keep = folder / 'notes.txt'
        keep.write_text('mine')
        for day in range(1, 10):
            (folder / f'registry-2020010{day}-000000.sqlite3').write_bytes(b'x')
        backups.prune(self.store)
        self.assertTrue(keep.exists())


class FakeResponse:
    def __init__(self, status=200):
        self.status = status
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


class NotifyTests(Base):
    CONFIG = {'ntfy': {'url': 'https://ntfy.example.com/topic', 'token': 'tk_secretvalue'},
              'telegram': {'token': '123456789:' + 'A' * 35, 'chat_id': '-1001234'},
              'webhook': {'url': 'https://hooks.example.com/abc?key=hidden'},
              'enabled': {'ntfy': True, 'telegram': True, 'webhook': True}}

    def test_settings_are_validated_masked_and_keep_secrets_when_resubmitted(self):
        shown = ats_notify.save(self.store, self.CONFIG)
        text = json.dumps(shown)
        for secret in ('tk_secretvalue', 'A' * 35, 'key=hidden'):
            self.assertNotIn(secret, text)
        shown['thresholds']['disk'] = 80
        again = ats_notify.save(self.store, shown)                       # masks go back unchanged
        stored = ats_notify.load(self.store)
        self.assertEqual((stored['ntfy']['token'], stored['webhook']['url'], stored['thresholds']['disk']), ('tk_secretvalue', 'https://hooks.example.com/abc?key=hidden', 80))
        self.assertEqual(again['ntfy']['token'], ats_notify.MASK)

    def test_unsafe_or_incomplete_settings_are_rejected(self):
        cases = [{'ntfy': {'url': 'http://ntfy.example.com/x'}}, {'webhook': {'url': 'https://user:pw@h.example.com'}},
                 {'webhook': {'url': 'file:///etc/passwd'}}, {'telegram': {'token': 'nope'}}, {'telegram': {'chat_id': 'a b'}},
                 {'enabled': {'ntfy': True}}, {'enabled': {'telegram': 'yes'}}, {'thresholds': {'disk': 10}}, {'thresholds': {'failures': True}}, 'x']
        for case in cases:
            with self.assertRaises(ValueError, msg=case):
                ats_notify.validate(case)

    def test_delivery_formats_and_failures_are_isolated_per_channel(self):
        config = ats_notify.validate(self.CONFIG)
        seen = []

        def opener(request, timeout):
            seen.append((request.full_url, request.headers, request.data))
            if 'telegram' in request.full_url:
                raise ats_notify.NotifyError('HTTP 401')
            return FakeResponse()
        outcome = ats_notify.send(config, 'Server ✓ down', 'it broke', 'down', opener=opener)
        self.assertEqual({k: v['ok'] for k, v in outcome.items()}, {'ntfy': True, 'telegram': False, 'webhook': True})
        self.assertEqual(outcome['telegram']['error'], 'HTTP 401')
        ntfy = next(x for x in seen if 'ntfy' in x[0])
        self.assertEqual(ntfy[1]['Authorization'], 'Bearer tk_secretvalue')
        self.assertEqual(ntfy[1]['Priority'], 'high')
        self.assertTrue(ntfy[1]['Title'].isascii())
        self.assertEqual(json.loads(next(x for x in seen if 'hooks' in x[0])[2])['level'], 'down')
        for secret in ('tk_secretvalue', 'A' * 35, 'hidden'):
            self.assertNotIn(secret, json.dumps(outcome))

    def test_watch_settings_are_validated_and_survive_a_round_trip(self):
        shown = ats_notify.save(self.store, {'watch': {'kinds': ['service', 'deployment'], 'ignore_units': 'a.service, b.timer', 'failed_units': False}})
        self.assertEqual(shown['watch'], {'kinds': ['deployment', 'service'], 'failed_units': False, 'ignore_units': ['a.service', 'b.timer']})
        self.assertEqual(ats_notify.save(self.store, shown)['watch'], shown['watch'])
        for bad in ({'kinds': ['nope']}, {'kinds': 'service'}, {'kinds': ['service', 'service']}, {'ignore_units': ['rm -rf /']}, {'ignore_units': ['x.service'] * 51},
                    {'failed_units': 'yes'}, {'ignore_units': 5}):
            with self.assertRaises(ValueError, msg=bad):
                ats_notify.validate({'watch': bad})

    def test_redirects_are_not_followed(self):
        self.assertIsNone(ats_notify.NoRedirect().redirect_request(None, None, 302, 'x', {}, 'https://elsewhere.example.com'))


class FleetTests(Base):
    def setUp(self):
        super().setUp()
        self.store = cluster.Store(self.root / 'local.sqlite3')
        self.store.configure('local', 'Local', webhook='hooks.example.com')
        self._pair()
        self.sent = []
        self.down = False
        self.disk = 40

    def _pair(self):
        with mock.patch.object(cluster.Store, '_verified', return_value={}):
            self.store.pair('b' * 32, 'Remote', 'https://api.example.com', 'c' * 64)

    def data(self):
        return {'metrics': {'cpu_percent': 12.0, 'memory': {'used_percent': 30.0}, 'disks': [{'used_percent': self.disk}]},
                'host': {'uptime': 99}, 'ats': {'short': 'abc1234'}, 'companion': {'short': 'def5678'}}

    def probe(self, server):
        return (False, None, 'refused') if self.down else (True, self.data(), None)

    def run_cycle(self, at):
        return ats_fleet.cycle(self.store, now=at, probe=self.probe, send=lambda *a: self.sent.append(a) or {'ntfy': {'ok': True, 'error': None}},
                               local=lambda: self.data())

    def enable(self):
        ats_notify.save(self.store, {'ntfy': {'url': 'https://ntfy.example.com/t'}, 'enabled': {'ntfy': True}, 'thresholds': {'failures': 3}})

    def test_one_dropped_check_is_not_an_outage_but_three_are_and_recovery_is_announced_once(self):
        self.enable()
        self.run_cycle(1000)
        self.down = True
        self.assertEqual(self.run_cycle(1060), [])
        self.assertEqual(self.run_cycle(1120), [])
        down = self.run_cycle(1180)
        self.assertEqual([k for k, _, _ in down], ['down'])
        self.assertEqual(self.run_cycle(1240), [])                       # no repeat every minute
        self.down = False
        self.assertEqual([k for k, _, _ in self.run_cycle(1300)], ['recovered'])
        self.assertEqual(self.run_cycle(1360), [])
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(self.sent[0][3], 'down')
        state = self.store.kv_get('fleet_state')['b' * 32]
        self.assertEqual((state['status'], state['metrics']['disk']), ('up', 40))

    def test_a_long_outage_is_repeated_only_every_six_hours(self):
        self.enable()
        self.down = True
        for t in (0, 60, 120):
            self.run_cycle(t)
        self.assertEqual(self.run_cycle(120 + 3600), [])
        self.assertEqual([k for k, _, _ in self.run_cycle(120 + ats_fleet.REPEAT_DOWN)], ['still_down'])

    def test_disk_pressure_alerts_once_and_clears_with_hysteresis(self):
        self.enable()
        self.disk = 95
        first = self.run_cycle(0)
        self.assertEqual(len(first), 2)                                  # Local and the remote both cross the limit
        self.assertEqual(self.run_cycle(60), [])
        self.disk = 88
        self.assertEqual(self.run_cycle(120), [])                        # inside the hysteresis band: still flagged
        self.disk = 70
        self.assertEqual({k for k, _, _ in self.run_cycle(180)}, {'recovered'})

    def test_no_channel_means_no_send_but_events_are_still_recorded(self):
        self.down = True
        for t in (0, 60, 120):
            self.run_cycle(t)
        self.assertEqual(self.sent, [])
        self.assertEqual(self.store.kv_get('fleet_events')[-1]['kind'], 'down')

    def test_disconnected_servers_are_not_probed_or_alerted(self):
        self.store.connection('b' * 32, 'disconnect')
        called = []
        ats_fleet.cycle(self.store, now=0, probe=lambda s: called.append(s) or (False, None, 'x'), send=lambda *a: None, local=lambda: self.data())
        self.assertEqual(called, [])
        self.assertEqual(self.store.kv_get('fleet_state')['b' * 32]['status'], 'disabled')

    def test_old_globals_without_status_fall_back_to_a_health_check(self):
        calls = []

        def remote(server, payload, timeout=None):
            calls.append(payload['kind'])
            if payload['kind'] == 'status':
                raise cluster.TransportError('Unsupported request kind', 'adapter')
            return {'role': 'global'}
        with mock.patch.object(cluster, 'remote', remote):
            ok, data, error = ats_fleet.probe(self.store.server('b' * 32))
        self.assertTrue(ok and data['legacy'])
        self.assertEqual(calls, ['status', 'health'])

    def with_findings(self, units=(), alerts=()):
        data = self.data()
        data['host']['failed_units'] = list(units)
        data['alerts'] = [{'key': k, 'name': n, 'kind': kind, 'message': m} for k, n, kind, m in alerts]
        return data

    def cycle_with(self, at, data):
        self.findings = data
        return ats_fleet.cycle(self.store, now=at, probe=lambda server: (True, self.findings, None), send=lambda *a: self.sent.append(a) or {}, local=lambda: self.data())

    def test_failed_units_are_announced_once_and_again_when_they_clear(self):
        self.enable()
        first = self.cycle_with(0, self.with_findings(units=['atopacct.service', 'morphic.service']))
        self.assertEqual([(k, 'atopacct.service' in m and 'morphic.service' in m) for k, _, m in first], [('warn', True)])   # existing problems are not silent
        self.assertEqual(self.cycle_with(60, self.with_findings(units=['atopacct.service', 'morphic.service'])), [])        # and not repeated
        added = self.cycle_with(120, self.with_findings(units=['atopacct.service', 'morphic.service', 'nginx.service']))
        self.assertIn('nginx.service', added[0][2]); self.assertNotIn('morphic', added[0][2])
        cleared = self.cycle_with(180, self.with_findings(units=['atopacct.service']))
        self.assertEqual(cleared[0][0], 'recovered')
        self.assertIn('morphic.service', cleared[0][2])
        state = self.store.kv_get('fleet_state')['b' * 32]['metrics']
        self.assertEqual(state['failed'], ['atopacct.service'])

    def test_ignored_units_and_the_off_switch_silence_them(self):
        ats_notify.save(self.store, {'ntfy': {'url': 'https://ntfy.example.com/t'}, 'enabled': {'ntfy': True}, 'watch': {'ignore_units': 'atopacct.service morphic.service'}})
        self.assertEqual(self.cycle_with(0, self.with_findings(units=['atopacct.service', 'morphic.service'])), [])
        self.assertEqual([k for k, _, _ in self.cycle_with(60, self.with_findings(units=['atopacct.service', 'x.service']))], ['warn'])
        self.assertEqual(self.cycle_with(120, self.with_findings(units=['atopacct.service'])) [0][0], 'recovered')   # a real one clearing is still news
        ats_notify.save(self.store, {'ntfy': {'url': 'https://ntfy.example.com/t'}, 'enabled': {'ntfy': True}, 'watch': {'failed_units': False}})
        self.assertEqual(self.cycle_with(180, self.with_findings(units=['brand-new.service'])), [])

    def test_deployment_and_other_collector_alerts_are_announced_by_kind(self):
        self.enable()
        deploy = ('site:deployment', 'site', 'deployment', 'Deployment failed')
        disk = ('host:disk', 'SYSTEM', 'disk', 'Storage disk is 91% used')
        first = self.cycle_with(0, self.with_findings(alerts=[deploy, disk]))
        self.assertEqual(len(first), 1)                                                      # disk is excluded by default: the threshold covers it
        self.assertIn('deployment problem with site: Deployment failed', first[0][2])
        self.assertEqual(self.cycle_with(60, self.with_findings(alerts=[deploy, disk])), [])
        cleared = self.cycle_with(120, self.with_findings(alerts=[disk]))
        self.assertEqual((cleared[0][0], 'cleared' in cleared[0][2]), ('recovered', True))
        ats_notify.save(self.store, {'ntfy': {'url': 'https://ntfy.example.com/t'}, 'enabled': {'ntfy': True}, 'watch': {'kinds': ['disk']}})
        self.assertEqual(len(self.cycle_with(180, self.with_findings(alerts=[disk, deploy]))), 1)       # kinds are the operator's choice

    def test_older_globals_and_a_down_server_leave_the_findings_alone(self):
        self.enable()
        self.cycle_with(0, self.with_findings(units=['a.service']))
        self.assertEqual(ats_fleet.cycle(self.store, now=60, probe=lambda s: (True, {'legacy': True, 'role': 'global'}, None), send=lambda *a: {}, local=lambda: self.data()), [])
        ats_fleet.cycle(self.store, now=120, probe=lambda s: (False, None, 'refused'), send=lambda *a: {}, local=lambda: self.data())
        self.assertEqual(self.cycle_with(180, self.with_findings(units=['a.service'])), [])       # still failing, still not repeated

    def test_the_local_servers_own_findings_are_watched_too(self):
        self.enable()
        mine = self.with_findings(units=['local-thing.service'])
        found = ats_fleet.cycle(self.store, now=0, probe=self.probe, send=lambda *a: {}, local=lambda: mine)
        self.assertTrue(any('local-thing.service' in m for _, _, m in found))

    def test_snapshot_probes_everything_but_saves_and_sends_nothing(self):
        self.enable()
        self.down = True
        result = ats_fleet.snapshot(self.store, probe=self.probe, local=lambda: self.data(), now=500)
        self.assertEqual({v['status'] for v in result.values()}, {'up', 'down'})
        down = result['b' * 32]
        self.assertEqual((down['status'], down['metrics'], down['error']), ('down', None, 'refused'))
        self.assertIsNone(self.store.kv_get('fleet_state'))
        self.assertEqual(self.sent, [])
        self.store.connection('b' * 32, 'disconnect')
        self.assertEqual(ats_fleet.snapshot(self.store, probe=self.probe, local=lambda: self.data())['b' * 32]['status'], 'disabled')

    def test_removed_servers_leave_no_state_behind(self):
        self.run_cycle(0)
        with self.store.db() as db:
            db.execute('DELETE FROM servers WHERE id=?', ('b' * 32,))
        self.run_cycle(60)
        self.assertNotIn('b' * 32, self.store.kv_get('fleet_state'))


if __name__ == '__main__':
    unittest.main()
