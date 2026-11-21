"""Installation failures must preserve unrelated routes, credentials and services."""
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import yaml
from ats_cluster import Store
import ats_global_setup as setup
import ats_server_cli as cli


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.home=self.root/'home';self.home.mkdir();(self.home/'ats.db').touch()
        self.cf=self.root/'cloudflared.yml'
        self.config={'tunnel':'existing-tunnel','credentials-file':'/private/tunnel.json','originRequest':{'connectTimeout':'5s'},'ingress':[
            {'hostname':'app.example.com','service':'http://localhost:8000'}, {'service':'http_status:404'}]}
        self.cf.write_text(yaml.safe_dump(self.config))
        self.settings=self.root/'ats.yml';self.settings.write_text(yaml.safe_dump({'ats_home':str(self.home),'cloudflare_config':str(self.cf)}))
        self.adapter=self.root/'remote_host.py';self.adapter.write_text('# installed adapter\n')
        self.unitdir=self.root/'units';self.unitdir.mkdir()
        self.env=patch.dict(os.environ,{'ATS_CONFIG_FILE':str(self.settings),'ATS_CLUSTER_DB':str(self.root/'registry.db')},clear=True)
        self.env.start();self.addCleanup(self.env.stop)
        self.store=Store();self.node=self.store.configure('global','Global','https://api.example.com')
        self.units={};self.calls=[];self.fail=None
        self.options=dict(monitor_adapter=str(self.adapter),unit_dir=str(self.unitdir),runner=self.fake_run)
        self.rootcheck=patch.object(setup,'require_root');self.rootcheck.start();self.addCleanup(self.rootcheck.stop)
        self.health=[]

    def fake_run(self,argv,**kwargs):
        self.calls.append(argv)
        if self.fail and self.fail(argv):raise ValueError('injected failure')
        out=''
        if argv[:2]==['systemctl','list-unit-files']:out='\n'.join(k+' enabled' for k in self.units)
        elif argv[:2]==['systemctl','show']:
            name=argv[2]
            if name=='cloudflared.service':props={'ActiveState':'active','ExecStart':'cloudflared --config '+str(self.cf)+' tunnel run'}
            elif name in self.units:props=self.units[name]
            else:props={'LoadState':'not-found'}
            out='\n'.join(k+'='+v for k,v in props.items())
        elif argv[:2] in (['systemctl','start'],['systemctl','restart']) and argv[2]!='cloudflared.service':
            self.units[argv[2]]={'LoadState':'loaded','ActiveState':'active','UnitFileState':'enabled','ExecStart':str(Path(cli.__file__).parent/'app.py')+' --daemon','Environment':'ATS_CLUSTER_DB='+self.store.path,'FragmentPath':str(self.unitdir/argv[2])}
        return subprocess.CompletedProcess(argv,0,out,'')

    def verify(self,plan,**kwargs):self.health.append(kwargs)
    def plan(self,**kwargs):return setup.build_plan(self.store,**{**self.options,**kwargs})
    def apply(self,**kwargs):return setup.apply(self.store,health=self.verify,**{**self.options,**kwargs})

    def test_plan_is_read_only_reuses_configuration_and_redacts_key(self):
        before=self.cf.read_bytes();plan=self.plan()
        summary=setup.public_plan(plan)
        self.assertEqual(self.cf.read_bytes(),before)
        self.assertFalse(plan['destination'].exists())
        self.assertNotIn(self.node['secret'],json.dumps(summary))
        self.assertIn('ATS_CLOUDFLARE_CONFIG='+str(self.cf),plan['full_unit'])
        self.assertEqual(plan['node'],self.node)

    def test_apply_and_repeat_keep_identity_and_other_routes(self):
        result=self.apply()
        updated=yaml.safe_load(self.cf.read_bytes())
        self.assertEqual(updated['ingress'][0],self.config['ingress'][0])
        self.assertEqual(updated['ingress'][-1],self.config['ingress'][-1])
        self.assertEqual(updated['credentials-file'],self.config['credentials-file'])
        self.assertEqual(self.store.node(),self.node)
        self.assertEqual(result['loopback_health'],'verified')
        self.calls=[]
        again=self.apply()
        self.assertFalse(again['service_change']);self.assertFalse(again['route_change'])
        self.assertFalse(any(c[:2]==['systemctl','restart'] for c in self.calls))

    def test_existing_service_reused_by_dropin_original_preserved(self):
        original=self.unitdir/'ats-server2.service';original.write_text('[Service]\n# operator unit\n')
        self.units['ats-server2.service']={'LoadState':'loaded','ActiveState':'active','UnitFileState':'enabled','ExecStart':str(Path(cli.__file__).parent/'app.py')+' --daemon','Environment':'ATS_CLUSTER_DB='+self.store.path}
        plan=self.plan();self.assertTrue(plan['existing']);self.assertEqual(plan['unit'],'ats-server2.service')
        self.apply()
        self.assertEqual(original.read_text(),'[Service]\n# operator unit\n')
        self.assertTrue((self.unitdir/'ats-server2.service.d'/'60-ats-global.conf').exists())

    def test_invalid_route_never_writes_or_restarts(self):
        for rule in [{'hostname':'api.example.com','service':'http://localhost:9999'},
                     {'hostname':'*.example.com','service':'http://localhost:8000'},
                     {'service':'http_status:404'}]:
            config=copy.deepcopy(self.config);config['ingress'].insert(0,rule)
            self.cf.write_text(yaml.safe_dump(config));before=self.cf.read_bytes()
            with self.assertRaises(ValueError):self.apply()
            self.assertEqual(self.cf.read_bytes(),before)
        self.assertFalse(any(c[:2]==['systemctl','restart'] for c in self.calls))

    def test_existing_api_route_narrowed_without_dropping_access_settings(self):
        config=copy.deepcopy(self.config)
        config['ingress'].insert(0,{'hostname':'api.example.com','service':'http://127.0.0.1:9997','originRequest':{'access':{'required':True}}})
        updated=setup.api_route(config,'api.example.com',9997)
        self.assertEqual(updated['ingress'][0]['originRequest'],config['ingress'][0]['originRequest'])
        self.assertEqual(updated['ingress'][0]['path'],'^/v1/request$')

    def test_validation_failure_leaves_files_and_service_untouched(self):
        before=self.cf.read_bytes();self.fail=lambda c:c[0]=='cloudflared'
        with self.assertRaises(ValueError):self.apply()
        self.assertEqual(self.cf.read_bytes(),before);self.assertEqual(list(self.unitdir.iterdir()),[])
        self.assertFalse(any(c[:2]==['systemctl','daemon-reload'] for c in self.calls))

    def test_start_failure_rolls_back_and_disables_new_unit(self):
        before=self.cf.read_bytes();self.fail=lambda c:c[:2]==['systemctl','start']
        with self.assertRaisesRegex(ValueError,'restored'):self.apply()
        self.assertEqual(self.cf.read_bytes(),before)
        self.assertFalse((self.unitdir/('ats-global-'+self.node['id']+'.service')).exists())
        self.assertTrue(any(c[:2]==['systemctl','disable'] for c in self.calls))

    def test_cloudflare_failure_restores_files(self):
        before=self.cf.read_bytes();failed=False
        def once(argv):
            nonlocal failed
            if argv==['systemctl','restart','cloudflared.service'] and not failed:failed=True;return True
            return False
        self.fail=once
        with self.assertRaisesRegex(ValueError,'restored'):self.apply()
        self.assertEqual(self.cf.read_bytes(),before)
        self.assertEqual(self.calls.count(['systemctl','restart','cloudflared.service']),2)

    def test_occupied_port_does_not_compete_with_terminal_daemon(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen()
            with self.assertRaisesRegex(ValueError,'occupied'):self.apply(port=listener.getsockname()[1])
        self.assertFalse(any(c[:2]==['systemctl','start'] for c in self.calls))

    def test_symlink_config_and_occupied_managed_destination_rejected(self):
        link=self.root/'link.yml';link.symlink_to(self.cf)
        with self.assertRaises(ValueError):self.plan(config_path=str(link))
        plan=self.plan();plan['destination'].write_text('operator data')
        with self.assertRaisesRegex(ValueError,'occupied'):self.apply()
        self.assertEqual(plan['destination'].read_text(),'operator data')

    def test_public_failure_keeps_verified_loopback_service(self):
        def health(plan,**kwargs):
            if kwargs.get('public'):raise OSError('DNS pending')
        result=setup.apply(self.store,health=health,**self.options)
        self.assertTrue(result['public_health'].startswith('unverified'))
        self.assertFalse(any(c[:2]==['systemctl','stop'] for c in self.calls))

    def test_changed_configuration_during_validation_aborts(self):
        original=self.fake_run
        def runner(argv,**kwargs):
            result=original(argv,**kwargs)
            if argv[0]=='systemd-analyze':self.cf.write_text('# concurrent edit\n'+self.cf.read_text())
            return result
        with self.assertRaisesRegex(ValueError,'changed'):self.apply(runner=runner)
        self.assertTrue(self.cf.read_text().startswith('# concurrent edit'))
        self.assertFalse(any(c[:2]==['systemctl','daemon-reload'] for c in self.calls))

    def test_ambiguous_daemons_are_rejected(self):
        props={'LoadState':'loaded','ActiveState':'active','UnitFileState':'enabled','ExecStart':str(Path(cli.__file__).parent/'app.py')+' --daemon','Environment':'ATS_CLUSTER_DB='+self.store.path}
        self.units={'ats-one.service':props,'ats-two.service':props}
        with self.assertRaisesRegex(ValueError,'Multiple'):self.apply()

    def test_reuse_existing_adapter_state_and_port(self):
        state=self.root/'old-state'
        props={'LoadState':'loaded','ActiveState':'active','UnitFileState':'enabled','ExecStart':str(Path(cli.__file__).parent/'app.py')+' --daemon','Environment':f'ATS_CLUSTER_DB={self.store.path} ATS_REMOTE_PORT=9988 ATS_SECURITY_DB={state}/security.sqlite3 ATS_MONITOR_JOBS_DIR={state}/jobs'}
        self.units={'ats-server2.service':props}
        plan=self.plan()
        self.assertEqual(plan['port'],9988)
        self.assertEqual(plan['adapter_env']['ATS_SECURITY_DB'],str(state/'security.sqlite3'))

    def test_existing_interpreter_is_preserved(self):
        props={'LoadState':'loaded','ActiveState':'active','UnitFileState':'enabled',
               'ExecStart':'{ path=/opt/venv/bin/python3 ; argv[]=/opt/venv/bin/python3 '+str(Path(cli.__file__).parent/'app.py')+' --daemon ; }',
               'Environment':'ATS_CLUSTER_DB='+self.store.path}
        self.units={'ats-server2.service':props}
        plan=self.plan()
        self.assertIn('ExecStart="/opt/venv/bin/python3"',plan['full_unit'])
        self.assertTrue(plan['adapter_env']['ATS_CLI'].startswith('/opt/venv/bin/python3 '))

    def test_zero_port_and_wrong_config_are_rejected(self):
        with self.assertRaisesRegex(ValueError,'port'):self.plan(port=0)
        self.units={'ats-server2.service':{'LoadState':'loaded','ActiveState':'active','UnitFileState':'enabled',
            'ExecStart':str(Path(cli.__file__).parent/'app.py')+' --daemon',
            'Environment':'ATS_CLUSTER_DB='+self.store.path+' ATS_CONFIG_FILE=/different.yml'}}
        with self.assertRaisesRegex(ValueError,'different ATS_CONFIG_FILE'):self.plan()

    def test_rollback_does_not_overwrite_concurrent_operator_edit(self):
        def health(plan,**kwargs):
            self.cf.write_text('# operator replacement\n')
            raise ValueError('health failed')
        with patch.object(setup.time,'sleep'),self.assertRaisesRegex(ValueError,'operator attention'):
            setup.apply(self.store,health=health,**self.options)
        self.assertEqual(self.cf.read_text(),'# operator replacement\n')

    def test_rollback_continues_when_config_becomes_nonregular(self):
        def health(plan, **kwargs):
            if self.cf.is_file():
                self.cf.unlink()
                self.cf.mkdir()
            raise ValueError('health failed')
        with patch.object(setup.time, 'sleep'), self.assertRaisesRegex(ValueError, 'operator attention'):
            setup.apply(self.store, health=health, **self.options)
        self.assertTrue(self.cf.is_dir())
        self.assertTrue(any(c[:2] == ['systemctl', 'stop'] for c in self.calls))
        self.assertTrue(any(c[:2] == ['systemctl', 'disable'] for c in self.calls))

    def test_setup_command_preview_does_not_apply_and_missing_pair_file_is_clear(self):
        import contextlib,io,sys
        with patch.object(sys,'argv',['ats','setup']),patch('ats_global_setup.build_plan',return_value=self.plan()), \
                patch('ats_global_setup.apply') as apply,contextlib.redirect_stdout(io.StringIO()):
            cli.main();apply.assert_not_called()
        with patch.object(sys,'argv',['ats','replace-credentials','--server-id',self.node['id']]), \
                contextlib.redirect_stderr(io.StringIO()) as error,self.assertRaises(SystemExit):
            cli.main()
        self.assertIn('--pairing-file is required',error.getvalue())


if __name__=='__main__':unittest.main()
