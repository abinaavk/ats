"""Credential recovery keeps the selected server and explicit routes consistent."""
from pathlib import Path
import secrets
import sqlite3
from unittest.mock import patch
import ats_cluster as cluster
import ats_remote
import test_cluster
import unittest


class CredentialTests(unittest.TestCase):
    setUp = test_cluster.TLSIntegrationTests.setUp
    # Inherit the real TLS fixture, not the original test cases.
    def local(self):
        local = cluster.Store(Path(self.temp.name)/'local.db')
        local.configure('local', 'Local', webhook='hooks.example.com')
        local.pair(self.node['id'], 'Remote', self.origin, self.node['secret'])
        local.mapping('owner/repo',self.node['id'],'service','main',secrets.token_hex(32))
        return local

    def rotate(self, identity=False):
        key = secrets.token_hex(32)
        sid = secrets.token_hex(16) if identity else self.node['id']
        with self.global_store.db() as db:
            db.execute('UPDATE node SET id=?,secret=?', (sid,key))
        return sid,key

    def test_replace_id_preserves_routes_and_disabled_state(self):
        local=self.local();local.connection(self.node['id'],'disconnect')
        sid,key=self.rotate(True)
        local.replace_credentials(self.node['id'],sid,'Updated',self.origin,key)
        self.assertFalse(local.server(sid)['connected'])
        self.assertEqual(local.server(sid)['secret'],key)
        with local.db() as db:
            self.assertEqual(db.execute('SELECT server_id FROM routes').fetchone()[0],sid)
        with self.assertRaises(ValueError):local.server(self.node['id'])
        local.connection(sid,'reconnect')
        self.assertEqual(cluster.remote(local.server(sid),{'kind':'health'})['server_id'],sid)

    def test_pairing_file_finds_its_saved_server_by_id_then_address_then_name(self):
        local=self.local()
        sid,key=self.rotate(True)
        # The Global was reinstalled: new ID and key, same HTTPS address.
        bundle={'id':sid,'name':'Reinstalled','domain':self.origin,'secret':key}
        self.assertEqual(local.find_server(bundle),self.node['id'])
        self.assertEqual(local.find_server(dict(bundle,domain='https://other.example.com',name='remote')),self.node['id'])
        with self.assertRaisesRegex(ValueError,'No saved Global matches'):
            local.find_server(dict(bundle,domain='https://other.example.com',name='unrelated'))
        self.assertEqual(local.find_server(dict(bundle,id=self.node['id'],domain='nonsense')),self.node['id'])
        with self.assertRaisesRegex(ValueError,'JSON object'):local.find_server([])

    def test_cli_replace_credentials_detects_the_server_without_an_id(self):
        import json,sys,os
        from unittest.mock import patch
        import ats_server_cli as cli
        local=self.local();sid,key=self.rotate(True)
        bundle=Path(self.temp.name)/'new.json'
        bundle.write_text(json.dumps({'id':sid,'name':'Remote','domain':self.origin,'secret':key}))
        with patch.object(sys,'argv',['ats','replace-credentials','--pairing-file',str(bundle)]),patch.object(cli,'Store',return_value=local):
            cli.main()
        self.assertEqual(local.server(sid)['secret'],key)
        with self.assertRaises(ValueError):local.server(self.node['id'])
        with local.db() as db:
            self.assertEqual(db.execute('SELECT server_id FROM routes').fetchone()[0],sid)

    def test_bad_new_key_leaves_old_entry_and_routes_intact(self):
        local=self.local();before=local.server(self.node['id'])
        with self.assertRaises(ValueError):
            local.replace_credentials(self.node['id'],self.node['id'],'Bad',self.origin,'0'*64)
        self.assertEqual(local.server(self.node['id']),before)
        with local.db() as db:self.assertEqual(db.execute('SELECT server_id FROM routes').fetchone()[0],self.node['id'])

    def test_update_key_in_place_keeps_enabled_state_and_rejects_old_key(self):
        local=self.local();sid,key=self.rotate()
        local.replace_credentials(sid,sid,'Remote',self.origin,key)
        self.assertTrue(local.server(sid)['connected'])
        with self.assertRaises(ValueError):cluster.remote(self.server,{'kind':'health'})
        self.assertEqual(cluster.remote(local.server(sid),{'kind':'health'})['role'],'global')

    def test_unconfirmed_revoke_cannot_be_reconnected_or_paired_with_old_key(self):
        local=self.local()
        with patch('ats_cluster.remote',side_effect=OSError('offline')):
            with self.assertRaises(OSError):local.connection(self.node['id'],'revoke')
        with self.assertRaisesRegex(ValueError,'unconfirmed'):local.connection(self.node['id'],'reconnect')
        with self.assertRaisesRegex(ValueError,'Rotate'):local.pair(self.node['id'],'Remote',self.origin,self.node['secret'])
        sid,key=self.rotate()
        local.replace_credentials(sid,sid,'Remote',self.origin,key)
        self.assertFalse(local.server(sid)['revocation_pending'])
        self.assertFalse(local.server(sid)['connected'])
        local.connection(sid,'reconnect')

    def test_disconnect_during_reconnect_wins(self):
        local=self.local();local.connection(self.node['id'],'disconnect')
        original=cluster.remote
        def delayed(server,payload):
            result=original(server,payload)
            local.connection(server['id'],'disconnect')
            return result
        with patch('ats_cluster.remote',side_effect=delayed),self.assertRaisesRegex(ValueError,'changed'):
            local.connection(self.node['id'],'reconnect')
        self.assertFalse(local.server(self.node['id'])['connected'])

    def test_replacement_during_revoke_reply_is_not_erased(self):
        local=self.local();original=cluster.remote
        def delayed(server,payload):
            result=original(server,payload)
            fresh=self.global_store.node()
            with patch('ats_cluster.remote',side_effect=original):
                local.replace_credentials(server['id'],fresh['id'],'Remote',self.origin,fresh['secret'])
            return result
        with patch('ats_cluster.remote',side_effect=delayed),self.assertRaisesRegex(ValueError,'changed'):
            local.connection(self.node['id'],'revoke')
        self.assertEqual(local.server(self.node['id'])['secret'],self.global_store.node()['secret'])
        self.assertFalse(local.server(self.node['id'])['connected'])

    def test_stale_authenticated_revoke_cannot_rotate_new_key(self):
        old=self.global_store.node();sid,key=self.rotate()
        with self.assertRaises(ValueError):ats_remote.dispatch(self.global_store,{'kind':'revoke'},old)
        self.assertEqual(self.global_store.node()['secret'],key)

    def test_identity_collision_rolls_back_name_domain_and_routes(self):
        local=self.local();before=local.server(self.node['id'])
        sid,key=self.rotate(True)
        with local.db() as db:
            db.execute('INSERT INTO servers(id,name,domain,secret) VALUES(?,?,?,?)',(sid,'Other','https://other.example.com','e'*64))
        with self.assertRaises(sqlite3.IntegrityError):local.replace_credentials(self.node['id'],sid,'Remote',self.origin,key)
        self.assertEqual(local.server(self.node['id']),before)

    def test_non_global_health_is_rejected(self):
        local=self.local();before=local.server(self.node['id'])
        with patch('ats_cluster.remote',return_value={'server_id':self.node['id'],'role':'local'}):
            with self.assertRaises(ValueError):local.replace_credentials(self.node['id'],self.node['id'],'Bad',self.origin,self.node['secret'])
        self.assertEqual(local.server(self.node['id']),before)

