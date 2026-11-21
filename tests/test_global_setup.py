"""Installation failures must preserve unrelated routes, credentials and services."""
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
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
        self.adapter_report={'ok':True}
        sleep=patch.object(setup.time,'sleep');sleep.start();self.addCleanup(sleep.stop)

    def fake_run(self,argv,**kwargs):
        self.calls.append(argv)
        if self.fail and self.fail(argv):raise ValueError('injected failure')
        out='';code=0
        if argv[:2]==['systemctl','list-unit-files']:
            # Real systemd exits 1 when the pattern matches no unit file (a fresh Global).
            out='\n'.join(k+' enabled' for k in self.units);code=0 if self.units else 1
            if code and kwargs.get('check',True):raise ValueError('systemctl list-unit-files failed')
        elif len(argv)==3 and argv[2]=='--check':out=json.dumps(self.adapter_report)
        elif argv[:2]==['systemctl','show']:
            name=argv[2]
            if name=='cloudflared.service':props={'ActiveState':'active','ExecStart':'cloudflared --config '+str(self.cf)+' tunnel run'}
            elif name in self.units:props=self.units[name]
            else:props={'LoadState':'not-found'}
            out='\n'.join(k+'='+v for k,v in props.items())
        elif argv[:2] in (['systemctl','start'],['systemctl','restart']) and argv[2]!='cloudflared.service':
            self.units[argv[2]]={'LoadState':'loaded','ActiveState':'active','UnitFileState':'enabled','ExecStart':str(Path(cli.__file__).parent/'app.py')+' --daemon','Environment':'ATS_CLUSTER_DB='+self.store.path,'FragmentPath':str(self.unitdir/argv[2])}
        return subprocess.CompletedProcess(argv,code,out,'')

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
        before=self.cf.read_bytes();restarts=0
        def broken(argv):
            nonlocal restarts
            if argv==['systemctl','restart','cloudflared.service']:
                restarts+=1;return restarts<=setup.TUNNEL_RETRIES
            return argv==['systemctl','is-active','cloudflared.service'] and restarts<=setup.TUNNEL_RETRIES
        self.fail=broken
        with self.assertRaisesRegex(ValueError,'restored'):self.apply()
        self.assertEqual(self.cf.read_bytes(),before)
        # Every bounded retry is tried, then the previous route file is restarted once.
        self.assertEqual(self.calls.count(['systemctl','restart','cloudflared.service']),setup.TUNNEL_RETRIES+1)

    def test_slow_tunnel_start_that_systemd_recovers_is_not_a_failure(self):
        failed=False
        def once(argv):
            nonlocal failed
            if argv==['systemctl','restart','cloudflared.service'] and not failed:failed=True;return True
            return False
        self.fail=once
        result=self.apply()
        self.assertEqual(result['route_change'],True)
        self.assertNotEqual(self.cf.read_bytes(),yaml.safe_dump(self.config).encode())
        self.assertIn(['systemctl','is-active','cloudflared.service'],self.calls)

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

    def verify_with_real_systemd(self, directory, unit):
        import shutil
        if not shutil.which('systemd-analyze'):
            self.skipTest('systemd-analyze is not installed')
        result=subprocess.run(['systemd-analyze','verify',str(directory/unit)],capture_output=True,text=True,timeout=60)
        # Warnings about unrelated host units are not ours; a fatal error in this unit is.
        mine=[l for l in result.stderr.splitlines() if unit in l or str(directory) in l]
        self.assertEqual(mine,[],result.stderr)

    def test_generated_unit_is_accepted_by_real_systemd(self):
        # Regression: a quoted WorkingDirectory= made systemd reject every generated unit.
        plan=self.plan()
        self.assertNotIn('WorkingDirectory="',plan['full_unit'])
        self.assertRegex(plan['full_unit'],r'(?m)^WorkingDirectory=/')
        directory=self.root/'real-unit';directory.mkdir()
        (directory/'ats-global-check.service').write_text(plan['full_unit'])
        self.verify_with_real_systemd(directory,'ats-global-check.service')

    def test_generated_dropin_for_an_existing_daemon_is_accepted_by_real_systemd(self):
        app=str(Path(cli.__file__).parent/'app.py')
        name='ats-existing.service'
        self.units[name]={'LoadState':'loaded','ActiveState':'active','UnitFileState':'enabled','ExecStart':app+' --daemon',
                          'Environment':'ATS_CLUSTER_DB='+self.store.path,'FragmentPath':str(self.unitdir/name)}
        plan=self.plan(unit=name)
        self.assertTrue(plan['existing'])
        directory=self.root/'real-dropin';(directory/(name+'.d')).mkdir(parents=True)
        (directory/name).write_text('[Unit]\nDescription=operator unit\n[Service]\nExecStart='+sys.executable+' '+app+' --daemon\n')
        (directory/(name+'.d')/'60-ats-global.conf').write_bytes(plan['unit_content'])
        self.assertNotIn(b'WorkingDirectory="',plan['unit_content'])
        self.verify_with_real_systemd(directory,name)

    def test_unit_path_is_literal_not_quoted(self):
        self.assertEqual(cli.unit_path('/opt/my ats'),'/opt/my ats')
        self.assertEqual(cli.unit_path('/opt/100%'),'/opt/100%%')
        for bad in ('relative/path','/x\ny'):
            with self.assertRaises(ValueError):cli.unit_path(bad)

    def test_fresh_global_without_any_ats_unit_can_be_planned(self):
        # systemd exits 1 for list-unit-files with no match; that must not abort first-time setup.
        self.assertEqual(self.units,{})
        plan=self.plan()
        self.assertFalse(plan['existing'])
        self.assertEqual(plan['unit'],'ats-global-'+self.node['id']+'.service')

    def test_bus_failure_listing_units_is_still_reported(self):
        def broken(argv,**kwargs):
            if argv[:2]==['systemctl','list-unit-files']:
                return subprocess.CompletedProcess(argv,1,'','Failed to connect to bus')
            return self.fake_run(argv,**kwargs)
        with self.assertRaisesRegex(ValueError,'systemd'):
            setup.build_plan(self.store,**{**self.options,'runner':broken})

    def test_existing_localhost_route_is_accepted_and_normalised(self):
        self.config['ingress'].insert(1,{'hostname':'api.example.com','service':'http://localhost:9997'})
        self.cf.write_text(yaml.safe_dump(self.config))
        plan=self.plan()
        routes=yaml.safe_load(plan['cf_content'])['ingress']
        mine=[r for r in routes if r.get('hostname')=='api.example.com']
        self.assertEqual(mine,[{'hostname':'api.example.com','path':'^/v1/request$','service':'http://127.0.0.1:9997'}])
        self.config['ingress'][1]['service']='http://localhost:9000'
        self.cf.write_text(yaml.safe_dump(self.config))
        with self.assertRaisesRegex(ValueError,'routes elsewhere'):self.plan()

    def test_tunnel_service_config_discovery(self):
        def props(start,user='root'):return {'ActiveState':'active','ExecStart':start,'User':user}
        setup.check_tunnel_config(props('cloudflared tunnel --config '+str(self.cf)+' run'),self.cf)
        # No --config: only cloudflared's default locations are acceptable.
        setup.check_tunnel_config(props('cloudflared tunnel run'),Path('/etc/cloudflared/config.yml'))
        setup.check_tunnel_config(props('cloudflared tunnel run'),Path('/root/.cloudflared/config.yml'))
        with self.assertRaisesRegex(ValueError,'default locations'):setup.check_tunnel_config(props('cloudflared tunnel run'),self.cf)
        with self.assertRaisesRegex(ValueError,'different config'):setup.check_tunnel_config(props('cloudflared tunnel --config /other.yml run'),self.cf)
        with self.assertRaisesRegex(ValueError,'Token-managed'):setup.check_tunnel_config(props('cloudflared tunnel run --token abc'),self.cf)

    def test_adapter_self_check_failure_changes_nothing(self):
        before=self.cf.read_bytes()
        self.adapter_report={'ok':False,'problems':["Python module 'flask' is missing for /usr/bin/python3"]}
        with self.assertRaisesRegex(ValueError,"module 'flask' is missing"):self.apply()
        self.assertEqual(self.cf.read_bytes(),before)
        self.assertFalse(any(c[:2] in (['systemctl','start'],['systemctl','enable'],['systemctl','daemon-reload']) for c in self.calls))
        self.assertEqual(list(self.unitdir.iterdir()),[])

    def test_subprocesses_never_inherit_the_terminal_and_an_old_companion_is_named(self):
        # Regression: an older remote_host.py reads stdin for any invocation; with an inherited
        # terminal, doctor/setup hung until the timeout and reported "inspect the host locally".
        old=self.root/'old_remote_host.py'
        old.write_text('import json,sys\njson.load(sys.stdin)\n')
        r=setup.run([sys.executable,str(old),'--check'],check=False)
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(r.stdout,'')
        plan=self.plan()
        plan['adapter_env']=dict(plan['adapter_env'],ATS_MONITOR_ADAPTER=str(old))
        with self.assertRaisesRegex(ValueError,'no adapter self-check'):setup.adapter_check(plan)
        with patch('subprocess.run',side_effect=subprocess.TimeoutExpired(['x'],1)),self.assertRaisesRegex(ValueError,'older version'):
            setup.run([sys.executable,str(old),'--check'])

    def test_outdated_companion_without_self_check_is_explained(self):
        self.adapter_report=None
        with self.assertRaisesRegex(ValueError,'no adapter self-check'):self.apply()

    def test_adapter_check_uses_scratch_state_and_the_daemon_interpreter(self):
        seen={}
        def capture(argv,**kwargs):
            if len(argv)==3 and argv[2]=='--check':seen.update(argv=argv,env=kwargs['env'])
            return self.fake_run(argv,**kwargs)
        plan=self.plan()
        setup.adapter_check(plan,capture)
        self.assertEqual(seen['argv'][0],plan['interpreter'])
        self.assertNotIn(plan['adapter_env']['ATS_SECURITY_DB'],seen['env'].values())
        self.assertTrue(seen['env']['ATS_SECURITY_DB'].startswith(tempfile.gettempdir()))
        self.assertEqual(seen['env']['ATS_CLUSTER_DB'],self.store.path)
        self.assertNotIn(self.node['secret'],json.dumps(seen['env']))

    def test_missing_companion_is_reported_with_the_install_option(self):
        options={k:v for k,v in self.options.items() if k!='monitor_adapter'}
        fake_checkout=self.root/'elsewhere'/'ats_server_cli.py'
        with patch.object(cli,'__file__',str(fake_checkout)),patch.object(setup,'DEFAULT_MONITOR_DIR',str(self.root/'opt-ats-monitor')):
            with self.assertRaisesRegex(setup.MonitorMissing,'--install-monitor'):setup.build_plan(self.store,**options)

    def test_install_monitor_is_a_new_pinned_hookless_checkout(self):
        if self.root.stat().st_uid!=0:self.skipTest('needs a root-owned parent directory')
        target=self.root/'opt-ats-monitor'
        def git(argv,**kwargs):
            self.calls.append(argv)
            if argv[1]=='clone':
                target.mkdir();(target/'remote_host.py').write_text('# adapter\n')
            return subprocess.CompletedProcess(argv,0,'abc123def456\n' if argv[-1]=='HEAD' else '','')
        adapter,head=setup.install_monitor(git,destination=str(target))
        self.assertEqual((adapter,head),(str(target/'remote_host.py'),'abc123def456'))
        clone=[c for c in self.calls if c[:2]==['git','clone']][0]
        self.assertEqual(clone[2],'--no-checkout')
        self.assertTrue(any('core.hooksPath=/dev/null' in c for c in self.calls if c[0]=='git' and len(c)>2))
        with self.assertRaisesRegex(ValueError,'already exists'):setup.install_monitor(git,destination=str(target))
        with self.assertRaisesRegex(ValueError,'https'):setup.install_monitor(git,repo='http://x/y.git',destination=str(self.root/'other'))
        with self.assertRaisesRegex(ValueError,'ref'):setup.install_monitor(git,ref='../x',destination=str(self.root/'other'))

    def test_failed_install_leaves_no_partial_directory_and_names_private_repo_fix(self):
        target=self.root/'monitor'
        if self.root.stat().st_uid!=0:self.skipTest('needs a root-owned parent directory')
        def broken(argv,**kwargs):
            if argv[1]=='clone':target.mkdir();raise ValueError('git clone failed')
            return subprocess.CompletedProcess(argv,0,'','')
        with self.assertRaisesRegex(ValueError,'private'):setup.install_monitor(broken,destination=str(target))
        self.assertFalse(target.exists())

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
