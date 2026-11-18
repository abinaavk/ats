"""Protocol and runtime boundary tests; no host services required."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import ats_manage_runtime as runtime
import ats_headless

class RuntimeTests(unittest.TestCase):
    def test_env_boundary(self):
        value={'TOKEN':'literal $HOME `date` "q" = value','_EMPTY':''}
        self.assertEqual(runtime.environment(value),value)
        for bad in ({'BAD-NAME':'x'},{'1KEY':'x'},{'KEY':'a\nb'},{'KEY':'a\0b'},{'KEY':1},{'KEY':'x'*4097},{'K'+str(i):'' for i in range(201)}):
            with self.subTest(bad=str(bad)[:50]),self.assertRaises((ValueError,TypeError)):
                runtime.environment(bad)
    def test_storage_boundary(self):
        for bad in ('relative','/opt/../etc','/opt/%n','/opt/space here','/opt/a\nExecStart=/bin/false'):
            with self.subTest(path=bad),self.assertRaises(ValueError):runtime.safe_path(bad)
    def test_atomic_rollback(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'env';p.write_text('old')
            with mock.patch.object(runtime.os,'replace',side_effect=OSError('disk full')):
                with self.assertRaises(OSError):runtime.atomic(str(p),'new')
            self.assertEqual(p.read_text(),'old');self.assertEqual(len(list(Path(d).iterdir())),1)
            runtime.atomic(str(p),'new');self.assertEqual(p.stat().st_mode&0o777,0o600)
    def test_docker_unit(self):
        a=types.SimpleNamespace(SERVICE_USER='ats',SERVICE_GROUP='ats',get_service_path=lambda root,name:root+'/api/'+name,ServiceConfig=lambda **k:types.SimpleNamespace(**k))
        s=dict(name='demo',port=8080,domain='demo.example.com',storage_path='/opt',repo_url='https://github.com/o/r',workers=2,max_memory_mb=512,cpu_quota=50,runtime='docker',container_port=3000)
        with mock.patch.object(runtime.shutil,'which',return_value='/usr/bin/docker'):unit=runtime.unit(a,s)
        for required in ('127.0.0.1:8080:3000','--memory 512m','--cpus 0.5','--restart no','--env-file /opt/api/demo/.ats.docker.env','/opt/database/demo:/data','ExecStop=','NoNewPrivileges=true'):self.assertIn(required,unit)
        self.assertNotIn('--detach',unit)

class ProtocolTests(unittest.TestCase):
    def invoke(self,payload='{}',failure=None,source='print("import noise")'):
        fake=types.ModuleType('ats_api');calls=[]
        def run(app,op,args):
            calls.append((op,args));print('operation noise')
            if failure:raise failure
            return {'services':[]}
        fake.run=run
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'app.py';p.write_text(source)
            out,err=io.StringIO(),io.StringIO()
            with mock.patch.dict(sys.modules,{'ats_api':fake}),mock.patch.object(sys,'argv',['app.py','--api','services.list']),mock.patch.object(sys,'stdin',io.StringIO(payload)),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                status=ats_headless.main(str(p))
            events=[json.loads(line) for line in out.getvalue().splitlines()]
            self.assertEqual(sum(e['t']=='result' for e in events),1)
            return status,events[-1],calls,err.getvalue()
    def test_clean_protocol_and_noisy_import(self):
        status,result,calls,err=self.invoke()
        self.assertEqual(status,0);self.assertTrue(result['ok']);self.assertEqual(calls,[('services.list',{})]);self.assertIn('import noise',err);self.assertIn('operation noise',err)
    def test_invalid_input_does_not_dispatch(self):
        for bad in ('{','[]','null','"text"','{}'+' '*262144):
            with self.subTest(payload=bad[:10]):
                status,result,calls,_=self.invoke(bad);self.assertEqual(status,1);self.assertEqual(result['code'],'validation');self.assertFalse(calls)
    def test_distinct_failures(self):
        class ServiceBusyError(Exception):pass
        for error,code in ((ValueError('bad port'),'validation'),(ServiceBusyError('updating'),'busy'),(RuntimeError('not_configured: setup'),'not_configured')):
            _,result,_,_=self.invoke(failure=error);self.assertEqual(result['code'],code)
    def test_import_exit_is_machine_readable(self):
        status,result,calls,_=self.invoke(source='raise SystemExit("setup refused")')
        self.assertEqual(status,1);self.assertFalse(result['ok']);self.assertFalse(calls)
if __name__=='__main__':unittest.main()
