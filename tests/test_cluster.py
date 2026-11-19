import concurrent.futures
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import ats_cluster as c
import ats_remote
import ats_routing


class ClusterTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.store=c.Store(Path(self.temp.name)/'cluster.db')
        self.local=self.store.configure('local','Primary',webhook='hooks.example.com')
        self.secret=secrets.token_hex(32)

    def mapping(self):
        self.store.mapping('owner/repo',self.local['id'],'service','main',self.secret)

    def delivery(self, nonce='delivery', **payload):
        data={'repository':{'full_name':'owner/repo'},'ref':'refs/heads/main','after':'a'*40,**payload}
        body=json.dumps(data).encode()
        headers={'x-github-event':'push','x-github-delivery':nonce,'x-hub-signature-256':'sha256='+hmac.new(self.secret.encode(),body,hashlib.sha256).hexdigest()}
        return headers,body

    def test_identity_persistence_private_storage_exactly_one_primary(self):
        self.assertEqual(self.local['id'],self.store.configure('local','Renamed',webhook='hooks.example.com')['id'])
        self.assertEqual(len(self.store.servers()),1)
        self.assertEqual(os.stat(self.store.path).st_mode & 0o777,0o600)
        self.assertNotIn('secret',self.store.servers()[0])
        with self.assertRaises(ValueError):self.store.configure('global','Wrong','https://x.example.com')
        with self.assertRaises(ValueError):self.store.connection(self.local['id'],'disconnect')

    def test_concurrent_configuration_preserves_one_identity(self):
        path=Path(self.temp.name)/'concurrent.db'
        store=c.Store(path)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            nodes=list(pool.map(lambda _:store.configure('local','Local',webhook='hooks.example.com'),range(4)))
        self.assertEqual(len({n['id'] for n in nodes}),1)
        self.assertEqual(len(store.servers()),1)

    def test_explicit_mapping_replacement_and_uniqueness(self):
        self.mapping()
        self.store.mapping('owner/repo',self.local['id'],'new-service','release',secrets.token_hex(32),replace=True)
        with self.store.db() as db:
            row=db.execute('SELECT service,branch FROM routes').fetchone()
        self.assertEqual(tuple(row),('new-service','release'))
        with self.assertRaises(ValueError):self.store.mapping('owner/missing',self.local['id'],'other','main',secrets.token_hex(32),replace=True)

    def test_adapter_output_and_timeout_are_bounded(self):
        with self.assertRaises(ValueError):ats_remote.execute([sys.executable,'-c','import time;time.sleep(2)'],{},timeout=0.1)
        with self.assertRaises(ValueError):ats_remote.execute([sys.executable,'-c','print("x"*5000000)'],{})

    def test_https_origin_restrictions(self):
        for value in ['http://example.com','https://u:p@example.com','https://example.com/x','https://example.com?x=y','https://a.example/#x','https://a..example']:
            with self.subTest(value=value),self.assertRaises(ValueError):c.domain(value)

    def test_duplicate_mapping_and_ambiguous_service_rejected(self):
        self.mapping()
        for repo,service in [('owner/repo','other'),('owner/other','service')]:
            with self.assertRaises(sqlite3.IntegrityError):self.store.mapping(repo,self.local['id'],service,'main',secrets.token_hex(32))

    def test_explicit_repository_and_destination_only(self):
        self.mapping();h,b=self.delivery()
        row,_,delivery=ats_routing.route(self.store,'/webhook/service',h,b)
        self.assertEqual(row['server_id'],self.local['id']);self.assertEqual(delivery,'delivery')
        for body,path in [(json.dumps({'repository':{'name':'service'}}).encode(),'/webhook'),(b,'/webhook/other')]:
            with self.assertRaises(ValueError):ats_routing.route(self.store,path,h,body)

    def test_bad_signature_ref_event_commit_and_deleted_rejected(self):
        self.mapping();h,b=self.delivery();h['x-hub-signature-256']='sha256='+'f'*64
        with self.assertRaises(PermissionError):ats_routing.route(self.store,'/webhook',h,b)
        for values in [{'ref':'refs/heads/other'},{'deleted':True},{'after':'nope'},{'repository':{'full_name':'other/repo'}}]:
            h,b=self.delivery(**values)
            with self.assertRaises(ValueError):ats_routing.route(self.store,'/webhook',h,b)
        h,b=self.delivery();h['x-github-event']='issues'
        with self.assertRaises(ValueError):ats_routing.route(self.store,'/webhook',h,b)

    def test_dedup_survives_reopen_and_changed_delivery_header(self):
        self.mapping();h,b=self.delivery()
        self.assertEqual(ats_routing.route(self.store,'/webhook',h,b)[2],'delivery')
        h['x-github-delivery']='another'
        self.assertIs(ats_routing.route(c.Store(self.store.path),'/webhook',h,b)[2],False)

    def test_concurrent_deliveries_claim_exactly_once(self):
        self.mapping();h,b=self.delivery()
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results=list(pool.map(lambda _:ats_routing.route(self.store,'/webhook',h,b)[2],range(6)))
        self.assertEqual(results.count('delivery'),1)
        self.assertEqual(results.count(False),5)

    def test_global_has_no_webhook_and_unique_credentials(self):
        global_store=c.Store(Path(self.temp.name)/'global.db')
        n=global_store.configure('global','Remote','https://api.example.com')
        other=c.Store(Path(self.temp.name)/'other.db').configure('global','Other','https://other.example.com')
        self.assertNotEqual(n['secret'],other['secret']);self.assertNotEqual(n['id'],other['id'])
        h,b=self.delivery()
        with self.assertRaises(ValueError):ats_routing.route(global_store,'/webhook',h,b)
        with self.assertRaises(ValueError):global_store.configure('global','Remote','https://api.example.com',webhook='bad.example.com')

    def test_cli_global_and_tunnel_conflicts(self):
        env={**os.environ,'ATS_CLUSTER_DB':self.temp.name+'/cli.db'}
        def run(*args):
            return subprocess.run([sys.executable,str(Path(__file__).resolve().parents[1]/'app.py'),'server',*args],env=env,capture_output=True,text=True)
        bundle=self.temp.name+'/pair.json'
        r=run('configure','--role','global','--name','Remote','--api-domain','https://api.example.com','--pairing-file',bundle)
        self.assertEqual(r.returncode,0,r.stderr)
        n=json.loads(Path(bundle).read_text());self.assertNotIn(n['secret'],r.stdout+r.stderr)
        self.assertEqual(os.stat(bundle).st_mode & 0o777,0o600)
        self.assertEqual(run('show').returncode,0)
        self.assertNotIn(n['secret'],run('show').stdout)
        env['ATS_CLUSTER_DB']=self.temp.name+'/local-cli.db'
        cf=Path(self.temp.name)/'cf.yml';cf.write_text('ingress:\n - hostname: hooks.example.com\n   service: http://localhost:9999\n')
        args=('configure','--role','local','--name','Local','--webhook-host','hooks.example.com','--cloudflare-config',str(cf))
        before=cf.read_text();self.assertNotEqual(run(*args).returncode,0)
        self.assertEqual(run(*args,'--confirm-existing-route').returncode,0)
        self.assertEqual(cf.read_text(),before)
        cf.write_text(before+before.split('ingress:\n')[1]);self.assertNotEqual(run(*args,'--confirm-existing-route').returncode,0)


class TLSIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name);cert=root/'cert.pem';key=root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,capture_output=True)
        self.env=patch.dict(os.environ,{'SSL_CERT_FILE':str(cert)});self.env.start();self.addCleanup(self.env.stop)
        self.global_store=c.Store(root/'global.db');self.node=self.global_store.configure('global','Remote','https://localhost')
        self.http=ats_remote.Server(('127.0.0.1',0),self.global_store)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key)
        self.http.socket=ctx.wrap_socket(self.http.socket,server_side=True)
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.http.server_close);self.addCleanup(self.http.shutdown)
        self.origin='https://localhost:'+str(self.http.server_port)
        self.server=dict(id=self.node['id'],secret=self.node['secret'],domain=self.origin,local=0,connected=1)

    def request(self,body,headers,path='/v1/request'):
        conn=http.client.HTTPSConnection('localhost',self.http.server_port,timeout=5)
        conn.request('POST',path,body,headers);r=conn.getresponse();status=r.status;r.read();conn.close();return status

    def test_real_https_pair_disconnect_reconnect_and_revoke(self):
        local=c.Store(Path(self.temp.name)/'local.db');local.configure('local','Local',webhook='hooks.example.com')
        self.assertEqual(local.pair(self.node['id'],'Remote',self.origin,self.node['secret'])['server_id'],self.node['id'])
        local.connection(self.node['id'],'disconnect')
        with self.assertRaises(ValueError):c.remote(local.server(self.node['id']),{'kind':'health'})
        local.connection(self.node['id'],'reconnect');self.assertEqual(c.remote(local.server(self.node['id']),{'kind':'health'})['role'],'global')
        local.connection(self.node['id'],'revoke')
        with self.assertRaises(ValueError):c.remote(self.server,{'kind':'health'})
        self.assertIsNone(self.global_store.node()['secret'])

    def test_tampering_replay_timestamp_and_wrong_server(self):
        body=b'{"kind":"health"}';headers=c.signed_headers(self.node['secret'],self.node['id'],body)
        self.assertEqual(self.request(body,headers),200);self.assertEqual(self.request(body,headers),401)
        for changes in [{'X-ATS-Server':'a'*32},{'X-ATS-Time':'0'},{'X-ATS-Signature':'0'*64}]:
            h=c.signed_headers(self.node['secret'],self.node['id'],body);h.update(changes)
            self.assertEqual(self.request(body,h),401)
        self.assertEqual(self.request(b'{"kind":"revoke"}',c.signed_headers(self.node['secret'],self.node['id'],body)),401)
        self.assertEqual(self.request(body,c.signed_headers(self.node['secret'],self.node['id'],body,path='/other')),401)
        self.assertEqual(self.request(body,c.signed_headers(self.node['secret'],self.node['id'],body,method='GET')),401)

    def test_unauthorized_oversized_unknown_route(self):
        self.assertEqual(self.request(b'{}',{}),401)
        self.assertEqual(self.request(b'',{'Content-Length':str(c.MAX_BODY+1)}),413)
        self.assertEqual(self.request(b'{}',{},'/other'),400)
        bad=dict(self.server,domain=self.origin.replace('localhost','127.0.0.1'))
        with self.assertRaises(ssl.SSLCertVerificationError):c.remote(bad,{'kind':'health'})
