"""Real ATS --api through the Flask bridge against a disposable fake host."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parent))
import harness
ROOT=Path(__file__).resolve().parents[1]

class HostAPI(unittest.TestCase):
    def setUp(self):
        self.env=harness.load_app();self.a=self.env.app
        root=Path(self.env.root);self.systemd=root/'systemd';self.systemd.mkdir();self.rotate=root/'rotate';self.rotate.mkdir()
        self.a.SYSTEMD_DIR=str(self.systemd);self.a.LOGROTATE_DIR=str(self.rotate)
        self.fake('git', '''#!/usr/bin/env python3
import os,sys
from pathlib import Path
args=sys.argv[1:]
with open(os.environ['FAKE_STATE']+'/calls.log','a') as f:f.write('git '+' '.join(args)+'\\n')
if os.getenv('FAIL_CLONE') and args[0]=='clone':sys.exit(1)
if args[0]=='clone':
 p=Path(args[-1]);p.mkdir(exist_ok=True);(p/'package.json').write_text('{}');(p/'Dockerfile').write_text('FROM scratch');(p/'app.py').write_text('app=None')
if args[0]=='rev-parse':print('abc1234')
if args[0]=='rev-list':print('0 0')
if args[0]=='log':print('fixture commit')
if args[0]=='pull':print('Updating abc..def')
''')
        self.fake('docker', '''#!/bin/sh
echo "docker $*" >> "$FAKE_STATE/calls.log"
if [ "$FAIL_BUILD" = 1 ] && [ "$1" = build ]; then exit 1; fi
if [ "$1" = info ]; then echo 27.0; fi
exit 0
''')
        self.fake('systemctl', '''#!/bin/sh
echo "systemctl $*" >> "$FAKE_STATE/calls.log"
if [ "$FAIL_ACTION" = "$1" ]; then echo "injected failure" >&2; exit 1; fi
case "$1" in
stop) echo inactive > "$FAKE_STATE/active_$2";;
start|restart) echo active > "$FAKE_STATE/active_$2";;
is-active) if [ -f "$FAKE_STATE/active_$2" ]; then cat "$FAKE_STATE/active_$2"; else echo inactive; fi;;
show) echo 0;;
status) echo "Active: active (running)";;
esac
exit 0
''')
        fixture=root/'fixture.py'
        fixture.write_text('import os\nos.geteuid=lambda:0\nexec(compile(open('+repr(str(ROOT/'app.py'))+').read(),'+repr(str(ROOT/'app.py'))+',"exec"),globals())\nSYSTEMD_DIR='+repr(str(self.systemd))+'\nLOGROTATE_DIR='+repr(str(self.rotate))+'\nhealth_check_deployment=lambda *a,**k:True\nRESTART_SETTLE_SECONDS=0\n')
        launcher=root/'launch.py'
        launcher.write_text('import sys\nsys.path.insert(0,'+repr(str(ROOT))+')\nfrom ats_headless import main\nsys.exit(main('+repr(str(fixture))+'))\n')
        self.cli=[sys.executable,str(launcher)]
        self.envvar=mock.patch.dict(os.environ,{'ATS_CLI':shlex.join(self.cli),'ATS_MONITOR_JOBS_DIR':str(root/'jobs')});self.envvar.start()
    def tearDown(self):self.envvar.stop();self.env.close()
    def fake(self,name,body):
        p=Path(self.env.bin)/name;p.write_text(body);p.chmod(0o755)
    def api(self,op,args=None,ok=True):
        r=subprocess.run(self.cli+['--api',op],input=json.dumps(args or {}),text=True,capture_output=True,timeout=30)
        records=[json.loads(l) for l in r.stdout.splitlines()]
        self.assertEqual(sum(x['t']=='result' for x in records),1,(r.stdout,r.stderr))
        result=records[-1];self.assertEqual(result['ok'],ok,(result,r.stderr));self.assertEqual(r.returncode,0 if ok else 1)
        return result['data'] if ok else result
    def deploy(self,name='demo',runtime='node'):
        return self.api('services.deploy',dict(name=name,domain=name+'.example.com',repo_url='https://token@github.com/o/r.git',runtime=runtime,env={'TOKEN':'private-value'}))
    def test_complete_service_and_backup_flow(self):
        deployed=self.deploy();self.assertEqual(deployed['runtime'],'node')
        self.assertTrue((self.systemd/'demo.service').is_file())
        self.assertNotIn('token@',json.dumps(self.api('services.list')))
        d=self.api('services.get',{'name':'demo'});self.assertEqual(d['env'],{'TOKEN':'private-value'});self.assertEqual(len(d['webhook']['secret']),64)
        d=self.api('services.config.set',{'name':'demo','workers':3,'max_memory_mb':1024,'cpu_quota':100,'branch':'release','env':{'FLAG':'yes'}})
        self.assertEqual(d['workers'],3);self.assertEqual(d['env'],{'FLAG':'yes'});self.assertTrue(d['restarted'])
        self.api('services.action',{'name':'demo','action':'update'});self.assertIn('git pull --ff-only origin release',self.env.calls())
        for action in ('stop','start','restart'):self.api('services.action',{'name':'demo','action':action})
        log=Path(d['path'])/'logs'/'stdout.log';log.write_text('INFO ready\nERROR broken\n')
        self.assertEqual(self.api('services.logs',{'name':'demo','grep':'error'})['lines'],['ERROR broken'])
        self.api('services.logs.clear',{'name':'demo','source':'stdout'});self.assertEqual(log.read_text(),'')
        database=Path(self.env.storage)/'database'/'demo';(database/'db.sqlite').write_text('original')
        b=self.api('backups.create',{'name':'demo'});(database/'db.sqlite').write_text('changed')
        self.api('backups.restore',{'name':'demo','filename':b['filename'],'source':'local'});self.assertEqual((database/'db.sqlite').read_text(),'original')
        self.api('webhook.set',{'name':'demo','auto_update':False});self.assertFalse(self.api('webhook.get',{'name':'demo'})['service']['auto_update'])
        self.api('services.redeploy',{'name':'demo','repo_url':'https://github.com/o/replacement.git'})
        self.api('services.delete',{'name':'demo','confirm':'wrong'},ok=False)
        self.api('services.delete',{'name':'demo','confirm':'demo','delete_files':True,'delete_backups':False})
        self.assertFalse(Path(d['path']).exists());self.assertEqual(self.api('services.list')['services'],[])
    def test_docker_webhook_update_rebuilds_and_rollback(self):
        self.deploy(runtime='docker');before=self.env.calls().count('docker build')
        self.api('webhook.test',{'name':'demo'});self.assertGreater(self.env.calls().count('docker build'),before)
        self.assertEqual(self.api('webhook.get',{'name':'demo'})['service']['last_events'][0]['result'],'updated')
        with mock.patch.dict(os.environ,{'FAIL_BUILD':'1'}):self.api('services.deploy',dict(name='broken',domain='broken.example.com',repo_url='https://github.com/o/r',runtime='docker'),ok=False)
        self.assertFalse((Path(self.env.storage)/'api'/'broken').exists());self.assertFalse((self.systemd/'broken.service').exists())
    def test_settings_and_atomic_config_failure(self):
        self.deploy();self.api('settings.set',{'domains':['example.com','example.org'],'main_domain':'example.org','defaults':{'workers':6}})
        self.assertEqual(self.api('settings.get')['defaults']['workers'],6)
        self.api('settings.set',{'storage_root':'/etc/ats'},ok=False)
        self.api('services.config.set',{'name':'demo','port':99999},ok=False)
        self.assertEqual(self.api('services.get',{'name':'demo'})['port'],8000)
        self.api('cloudflare.sync');self.assertEqual(self.api('cloudflare.status')['missing'],[])
    def test_python_deploy_and_no_first_run_prompt(self):
        shim = '#!'+sys.executable+'\n' + "import os,sys\nfrom pathlib import Path\nif sys.argv[1:3]==['-m','venv'] and len(sys.argv)>3 and sys.argv[3]!='--help':\n p=Path(sys.argv[3])/'bin';p.mkdir(parents=True);f=p/'python';f.write_text('#!/bin/sh\\nexit 0\\n');f.chmod(0o755)\nelse:os.execv("+repr(sys.executable)+",["+repr(sys.executable)+"]+sys.argv[1:])\n"
        self.fake('python3',shim)
        result=self.deploy(runtime='python')
        unit=(self.systemd/'demo.service').read_text()
        self.assertIn('/venv/bin/gunicorn',unit);self.assertIn('--bind 127.0.0.1:8000',unit)
        self.assertEqual(result['runtime'],'python')
        absent=Path(self.env.root)/'absent.yml'
        with mock.patch.dict(os.environ,{'ATS_CONFIG_FILE':str(absent)}):
            error=self.api('services.list',ok=False)
        self.assertEqual(error['code'],'not_configured');self.assertFalse(absent.exists())
    def test_encrypted_drive_backup_and_restore(self):
        self.deploy()
        database=Path(self.env.storage)/'database'/'demo';(database/'data.db').write_text('sensitive database')
        b=self.api('backups.create',{'name':'demo','gdrive':True})
        self.assertEqual(b['location'],'gdrive')
        uploaded=Path(self.env.state)/'remote'/'backups'/'demo'/b['filename']
        self.assertTrue(uploaded.read_bytes().startswith(b'ENCRYPTED:'))
        (database/'data.db').write_text('modified')
        self.api('backups.restore',{'name':'demo','filename':b['filename'],'source':'gdrive'})
        self.assertEqual((database/'data.db').read_text(),'sensitive database')
        self.api('backups.delete',{'filename':b['filename'],'source':'gdrive'})
    def test_configuration_rolls_back_on_restart_failure(self):
        self.deploy();before=(self.systemd/'demo.service').read_text()
        with mock.patch.dict(os.environ,{'FAIL_ACTION':'restart'}):self.api('services.config.set',{'name':'demo','max_memory_mb':2048},ok=False)
        self.assertEqual((self.systemd/'demo.service').read_text(),before)
        self.assertEqual(self.api('services.get',{'name':'demo'})['max_memory_mb'],512)
    def test_storage_change_keeps_previous_backups_accessible(self):
        self.deploy();database=Path(self.env.storage)/'database'/'demo';(database/'data.db').write_text('preserved')
        backup=self.api('backups.create',{'name':'demo'})
        newroot=Path(self.env.root)/'other';newroot.mkdir()
        self.api('settings.set',{'storage_root':str(newroot)})
        (database/'data.db').write_text('changed')
        self.api('backups.restore',{'name':'demo','filename':backup['filename'],'source':'local'})
        self.assertEqual((database/'data.db').read_text(),'preserved')
    def test_flask_bridge_uses_real_headless_cli(self):
        monitor=ROOT.parent/'ats-monitor'
        if not monitor.is_dir():self.skipTest('sibling ats-monitor checkout unavailable')
        sys.path.insert(0,str(monitor))
        try:import manage_api
        except ImportError:self.skipTest('Flask is required for cross-repository bridge check')
        self.deploy()
        result=manage_api.ats_call('services.get',{'name':'demo'})
        self.assertEqual(result['name'],'demo');self.assertEqual(result['runtime'],'node')
        result=manage_api.ats_call('services.config.set',{'name':'demo','workers':5});self.assertEqual(result['workers'],5)
if __name__=='__main__':unittest.main()
