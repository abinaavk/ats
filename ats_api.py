"""Headless ATS queries and backup operations; returns JSON-serializable data."""
import contextlib
import collections
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import zipfile
import ats_manage_runtime as runtime

LIMITS={'workers':[1,32],'max_memory_mb':[64,65536],'cpu_quota':[5,800]}

def service(a,args):
    return runtime.row(a,args.get('name',''))


def settings(a):
    cfg=a._ats_load_config_file()
    main=cfg.get('main_domain',a.MAIN_DOMAIN)
    defaults=dict(runtime='python',branch='main',workers=min((os.cpu_count() or 1)*2+1,8),max_memory_mb=512,cpu_quota=50,container_port=8000)
    defaults.update(cfg.get('defaults') or {})
    return dict(storage_root=cfg.get('default_storage',a.DEFAULT_STORAGE),domains=cfg.get('domains') or [main],main_domain=main,
                defaults=defaults,cloudflare_config=cfg.get('cloudflare_config',a.CLOUDFLARE_CONFIG),cloudflared_service=cfg.get('cloudflared_service',a.CLOUDFLARED_SERVICE),
                service_user=a.SERVICE_USER,ats_home=a.ATS_HOME,webhook={'domain':'webhook.'+main,'port':a.WEBHOOK_PORT},gdrive={'remote':a.GDRIVE_REMOTE,'retention_days':a.GDRIVE_RETENTION_DAYS},limits=LIMITS)


def set_settings(a,args):
    if set(args)-{'storage_root','domains','main_domain','defaults','cloudflare_config','cloudflared_service'}:raise ValueError('Unknown settings field')
    with runtime.global_lock(a):
        old=settings(a);new=dict(old,**args);defaults=dict(old['defaults'],**args.get('defaults',{}));new['defaults']=defaults
        domains=new['domains']
        if not isinstance(domains,list) or not 1<=len(domains)<=50:raise ValueError('Save between 1 and 50 domains')
        domains=list(dict.fromkeys(a._check_domain_format(d) for d in domains))
        if new['main_domain'] not in domains:raise ValueError('main_domain must be one of the saved domains')
        new['storage_root']=runtime.safe_path(a.validate_storage(new['storage_root']))
        if set(defaults)-{'runtime','branch','workers','max_memory_mb','cpu_quota','container_port'}:raise ValueError('Unknown default field')
        if defaults['runtime'] not in ('python','node','docker'):raise ValueError('Invalid default runtime')
        a.validate_branch(defaults['branch']);a.validate_workers(defaults['workers']);a.validate_memory(defaults['max_memory_mb']);a.validate_cpu(defaults['cpu_quota'])
        cp=defaults['container_port']
        if isinstance(cp,bool) or not isinstance(cp,int) or not 1<=cp<=65535:raise ValueError('Invalid container port')
        runtime.safe_path(new['cloudflare_config'])
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}',new['cloudflared_service']):raise ValueError('Invalid cloudflared service name')
        cfg=a._ats_load_config_file();cfg.update(default_storage=new['storage_root'],domains=domains,main_domain=new['main_domain'],defaults=defaults,cloudflare_config=new['cloudflare_config'],cloudflared_service=new['cloudflared_service'])
        runtime.atomic(a.CONFIG_FILE,a.yaml.safe_dump(cfg,sort_keys=False))
        a.DEFAULT_STORAGE=new['storage_root'];a.BACKUP_DIR=os.path.join(a.DEFAULT_STORAGE,'backups');a.MAIN_DOMAIN=new['main_domain'];a.CLOUDFLARE_CONFIG=new['cloudflare_config'];a.CLOUDFLARED_SERVICE=new['cloudflared_service'];a.cloudflare=a.CloudflareManager(a.CLOUDFLARE_CONFIG)
        a.audit_log('SETTINGS_UPDATE','SYSTEM',{'fields':sorted(args)})
        return settings(a)


def command(argv,timeout=20):
    return subprocess.run(argv,capture_output=True,text=True,timeout=timeout,stdin=subprocess.DEVNULL)


def routes(a):
    try:
        with open(a.CLOUDFLARE_CONFIG) as f:value=a.yaml.safe_load(f) or {}
        return value.get('ingress',[])
    except (OSError,ValueError):return []


def summary(a,s):
    result={k:v for k,v in s.items() if k not in ('webhook_secret',)}
    result['repo_url']=a.redact_repo_url(s['repo_url'])
    result['path']=a.get_service_path(s['storage_path'],s['name'])
    try:status=command(['systemctl','is-active',s['name']]).stdout.strip()
    except (OSError,subprocess.SubprocessError):status='unknown'
    result.update(status=status or 'unknown',healthy=status=='active',auto_update=bool(s.get('auto_update',1)),webhook_configured=bool(s.get('webhook_secret')))
    last=a.db.query('SELECT * FROM deployments WHERE service_name=? ORDER BY id DESC LIMIT 1',(s['name'],),fetch_one=True)
    result['last_deploy']=dict(last) if last else None
    return result


def read_env(a,s):
    directory,_=runtime.paths(a,s);path=Path(directory)/'.ats.docker.env'
    if not path.is_file() or path.is_symlink():return {}
    with path.open() as f:return dict(line.rstrip('\n').split('=',1) for line in f if '=' in line)


def detail(a,s):
    result=summary(a,s);directory,_=runtime.paths(a,s)
    def git(args):
        try:return runtime.user(a,['git']+args,directory,timeout=10)
        except Exception:return ''
    counts=git(['rev-list','--left-right','--count','HEAD...@{upstream}']).split()
    result['git']={'commit':git(['rev-parse','--short','HEAD']),'subject':git(['log','-1','--format=%s']),'branch':s.get('branch') or 'main','dirty':bool(git(['status','--porcelain'])),'ahead':int(counts[0]) if counts and counts[0].isdigit() else 0,'behind':int(counts[1]) if len(counts)>1 and counts[1].isdigit() else 0}
    found=next((r for r in routes(a) if r.get('hostname')==s['domain']),{})
    result['cloudflare']={'route_present':bool(found),'correct':found.get('service') in (f'http://localhost:{s["port"]}',f'http://127.0.0.1:{s["port"]}')}
    backup=a.db.query('SELECT COUNT(*) AS n,MAX(timestamp) AS last FROM backups WHERE service_name=?',(s['name'],),fetch_one=True)
    result['backups']={'count':backup['n'],'last':backup['last']}
    result['webhook']=dict(a.get_webhook_info(s['name']),last_events=a.list_webhook_events(s['name'],20))
    result['env']=read_env(a,s)
    result['docker']={'image':'ats-'+s['name']+':latest','container':'ats-'+s['name'],'container_port':s.get('container_port') or 8000} if s['runtime']=='docker' else None
    cfg=settings(a);result['defaults']=cfg['defaults'];result['limits']=LIMITS
    try:
        with open(a._unit_path(s['name'])) as f:result['unit_file']=f.read(262144)
    except OSError:result['unit_file']=''
    return result


def webhook(a,args):
    cfg=settings(a);host=cfg['webhook']['domain'];entries=routes(a)
    result={'listener':{'url':'https://'+host,'port':a.WEBHOOK_PORT,'bind':a.webhook_bind_address(),'active':a.check_port_listening(a.WEBHOOK_PORT),'route_present':any(r.get('hostname')==host for r in entries)}}
    if args.get('name'):
        s=service(a,args);result['service']=dict(a.get_webhook_info(s['name']),last_events=a.list_webhook_events(s['name'],20))
    return result


def logs(a,args,clear=False):
    s=service(a,args);source=args.get('source','stdout');name=s['name']
    if source not in ('stdout','stderr','access','error','journal'):raise ValueError('Invalid log source')
    count=args.get('lines',300)
    if isinstance(count,bool) or not isinstance(count,int) or not 1<=count<=5000:raise ValueError('lines must be between 1 and 5000')
    grep=args.get('grep','')
    if not isinstance(grep,str) or len(grep)>200:raise ValueError('Invalid log filter')
    directory,_=runtime.paths(a,s);root=Path(directory)/'logs'
    if root.is_symlink():raise ValueError('Logs directory cannot be a symlink')
    sources=[]
    for key in ('stdout','stderr','access','error'):
        p=root/(key+'.log');exists=p.is_file() and not p.is_symlink()
        sources.append({'id':key,'label':key.title(),'exists':exists,'size_bytes':p.stat().st_size if exists else 0})
    sources.append({'id':'journal','label':'Journal','exists':True,'size_bytes':0})
    if clear:
        if source=='journal':raise ValueError('Per-service journal cannot be cleared')
        with a.service_lock(name):
            p=root/(source+'.log')
            if p.exists():
                fd=os.open(p,os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW);os.close(fd)
            a.audit_log('LOGS_CLEAR',name,{'source':source})
        return {'cleared':True}
    if source=='journal':
        r=command(['journalctl','-u',name,'-n',str(count),'--no-pager','-o','short-iso'])
        if r.returncode:raise a.ServiceOpError(r.stderr[-500:])
        lines=r.stdout.splitlines();size=len(r.stdout.encode())
    else:
        p=root/(source+'.log');size=p.stat().st_size if p.exists() else 0;lines=[]
        if p.exists():
            fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb') as f:
                f.seek(max(0,size-4*1024*1024))
                if f.tell():f.readline(4*1024*1024)
                lines=f.read(4*1024*1024).decode('utf-8','replace').splitlines()[-count:]
    if grep:lines=[line for line in lines if grep.casefold() in line.casefold()]
    return {'source':source,'lines':lines,'size_bytes':size,'sources':sources}


def dependencies(a):
    result={}
    for key in ('git','python3','node','npm','docker','cloudflared','rclone','openssl'):
        good=bool(shutil.which(key));version=''
        if good:
            try:
                r=command([key,'version' if key=='openssl' else '--version'],timeout=10);good=r.returncode==0;version=(r.stdout or r.stderr).splitlines()[0][:200]
            except (OSError,subprocess.SubprocessError,IndexError):good=False
        result[key]={'ok':good,'version':version,'hint':'' if good else 'Install '+key+' on the host'}
    try:result['venv']={'ok':command(['python3','-m','venv','--help']).returncode==0}
    except (OSError,subprocess.SubprocessError):result['venv']={'ok':False}
    try:
        rc,_,_=a.run_as_gaia(['docker','info','--format','{{.ServerVersion}}'],capture=True,timeout=10)
        result['docker_access']={'ok':rc==0,'hint':'' if rc==0 else 'The service user needs access to the Docker daemon'}
    except Exception:result['docker_access']={'ok':False,'hint':'Docker is unavailable to the configured service user'}
    return result


def filename(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}',value):raise ValueError('Invalid backup filename')
    return value


def backup_path(a,name):
    name=filename(name)
    record=a.db.query("SELECT local_path FROM backups WHERE filename=? AND location='local' ORDER BY id DESC LIMIT 1",(name,),fetch_one=True)
    p=Path(record['local_path']) if record and record['local_path'] else Path(a.BACKUP_DIR)/name
    if p.is_symlink():raise ValueError('Backup cannot be a symlink')
    if not p.is_file():raise a.ServiceOpError('Backup not found','notfound')
    return p


def remote(a,name,file=None):
    a.validate_service_name(name)
    return a.GDRIVE_FOLDER+'/'+name+('/'+filename(file) if file else '')


def sync_drive_inventory(a,name):
    """Cache legacy Drive inventory from this service's own remote directory."""
    if not shutil.which('rclone'): return
    try:
        response=command(['rclone','lsjson',remote(a,name),'--files-only'],timeout=15)
        if response.returncode: return
        entries=json.loads(response.stdout)
        if not isinstance(entries,list): return
        for entry in entries:
            leaf=filename(entry.get('Name',''))
            if entry.get('IsDir') or not leaf.endswith(('.zip','.zip.enc')): continue
            existing=a.db.query("SELECT id FROM backups WHERE service_name=? AND filename=? AND location='gdrive'",(name,leaf),fetch_one=True)
            if not existing:
                size=entry.get('Size',0)
                if not isinstance(size,int) or size<0: continue
                runtime.sql(a,'INSERT INTO backups(service_name,filename,size_bytes,checksum,location,encrypted,timestamp) VALUES (?,?,?,?,?,?,?)',(name,leaf,size,None,'gdrive',int(leaf.endswith('.enc')),entry.get('ModTime') or ''))
    except (ValueError,TypeError,OSError,subprocess.SubprocessError):
        # An unavailable optional remote must not hide local backups.
        return


def backup_list(a,args):
    params=(args['name'],) if args.get('name') else ()
    if params:
        service(a,args)
        sync_drive_inventory(a,params[0])
    values=[dict(r) for r in a.db.query('SELECT * FROM backups'+(' WHERE service_name=?' if params else '')+' ORDER BY timestamp DESC',params,fetch_all=True)]
    for value in values:value['encrypted']=bool(value.get('encrypted'))
    return {'backups':values}


def backup_create(a,args):
    s=service(a,args);gd=args.get('gdrive',False)
    if not isinstance(gd,bool):raise ValueError('gdrive must be boolean')
    with a.service_lock(s['name']):
        output=a.create_local_backup(s)
        if not output:raise a.ServiceOpError('No database files were backed up')
        path=backup_path(a,Path(output).name)
        if not gd:return {'filename':path.name,'size_bytes':path.stat().st_size,'location':'local'}
        with tempfile.TemporaryDirectory(prefix='ats-backup-') as temp:
            enc=Path(temp)/(path.name+'.enc')
            if not a._encrypt_file(str(path),str(enc)) or not enc.is_file() or not enc.stat().st_size:raise a.ServiceOpError('Encryption failed; nothing was uploaded')
            r=command(['rclone','copy',str(enc),remote(a,s['name']),'--bwlimit',a.RCLONE_BWLIMIT],timeout=3600)
            if r.returncode:raise a.ServiceOpError('Drive upload failed: '+r.stderr[-500:])
            runtime.sql(a,'INSERT INTO backups(service_name,filename,size_bytes,checksum,location,encrypted) VALUES (?,?,?,?,?,?)',(s['name'],enc.name,enc.stat().st_size,a.calculate_file_hash(str(enc)),'gdrive',1))
            a.audit_log('BACKUP_UPLOAD',s['name'],{'filename':enc.name})
            return {'filename':enc.name,'size_bytes':enc.stat().st_size,'location':'gdrive'}


def find_backup(a,args):
    if 'id' in args:
        try:bid=int(args['id'])
        except (ValueError,TypeError):raise ValueError('Invalid backup id')
        value=a.db.query('SELECT * FROM backups WHERE id=?',(bid,),fetch_one=True)
    else:value=a.db.query('SELECT * FROM backups WHERE filename=? AND location=?',(filename(args.get('filename')),args.get('source','local')),fetch_one=True)
    if not value:raise a.ServiceOpError('Backup not found','notfound')
    return dict(value)


def backup_restore(a,args):
    s=service(a,args);b=find_backup(a,args);name=s['name']
    if b['service_name']!=name:raise ValueError('Backup belongs to a different service')
    source=args.get('source','local')
    if source not in ('local','gdrive') or b['location']!=source:raise ValueError('Backup source does not match its record')
    _,database=runtime.paths(a,s);destination=Path(database)
    if destination.is_symlink():raise ValueError('Database path cannot be a symlink')
    with a.service_lock(name),tempfile.TemporaryDirectory(prefix='ats-restore-') as temp:
        archive=backup_path(a,b['filename']) if source=='local' else Path(temp)/filename(b['filename'])
        if source=='gdrive':
            r=command(['rclone','copy',remote(a,name,b['filename']),temp,'--bwlimit',a.RCLONE_BWLIMIT],timeout=3600)
            if r.returncode:raise a.ServiceOpError('Drive download failed: '+r.stderr[-500:])
        if b.get('checksum') and a.calculate_file_hash(str(archive))!=b['checksum']:raise a.ServiceOpError('Backup checksum mismatch')
        if b['encrypted']:
            decrypted=Path(temp)/'backup.zip'
            if not a._decrypt_file(str(archive),str(decrypted)):raise a.ServiceOpError('Decryption failed')
            archive=decrypted
        destination.parent.mkdir(parents=True,exist_ok=True)
        stage=Path(tempfile.mkdtemp(prefix='.ats-restore-',dir=destination.parent));previous=Path(str(stage)+'-previous');was_active=a.check_systemd_active(name);swapped=False
        try:
            with zipfile.ZipFile(archive) as zf:a._plan_zip_extraction(zf,str(stage))
            a._safe_extract_zip(str(archive),str(stage))
            for root,dirs,files in os.walk(stage):
                shutil.chown(root,user=a.SERVICE_USER,group=a.SERVICE_GROUP);os.chmod(root,0o750)
                for leaf in files:
                    p=Path(root)/leaf;shutil.chown(p,user=a.SERVICE_USER,group=a.SERVICE_GROUP);p.chmod(0o660)
            if was_active:a._systemctl('stop',name)
            if destination.exists():destination.rename(previous)
            stage.rename(destination);swapped=True
            if was_active:a._systemctl_and_verify('start',name)
            a.audit_log('RESTORE_SUCCESS',name,{'filename':b['filename']})
            if previous.exists():shutil.rmtree(previous)
            return {'restored':True}
        except Exception:
            if swapped and destination.exists():shutil.rmtree(destination)
            if previous.exists():previous.rename(destination)
            if was_active:
                try:a._systemctl_and_verify('start',name)
                except Exception:pass
            a.audit_log('RESTORE_FAILED',name,{'filename':b['filename']})
            raise
        finally:
            if stage.exists():shutil.rmtree(stage)


def backup_delete(a,args):
    b=find_backup(a,args);name=a.validate_service_name(b['service_name'])
    with a.service_lock(name):
        if b['location']=='local':backup_path(a,b['filename']).unlink()
        else:
            r=command(['rclone','deletefile',remote(a,name,b['filename'])],timeout=120)
            if r.returncode:raise a.ServiceOpError('Drive deletion failed: '+r.stderr[-500:])
        runtime.sql(a,'DELETE FROM backups WHERE id=?',(b['id'],));a.audit_log('BACKUP_DELETE',name,{'filename':b['filename']})
        return {'deleted':True}


def run(a,op,args):
    if op=='settings.get':return settings(a)
    if op=='settings.set':return set_settings(a,args)
    if op=='services.list':return {'services':[summary(a,dict(s)) for s in a.db.query('SELECT * FROM services ORDER BY name',fetch_all=True)]}
    if op=='services.get':return detail(a,service(a,args))
    if op=='services.status_text':return {'text':a.service_systemd_status(service(a,args)['name'])}
    if op in ('services.logs','services.logs.clear'):return logs(a,args,op.endswith('.clear'))
    if op in ('system.dependencies','docker.info'):
        deps=dependencies(a)
        return deps if op=='system.dependencies' else {'available':deps['docker']['ok'],'version':deps['docker']['version'],'access':deps['docker_access']['ok'],'hint':deps['docker_access'].get('hint')}
    if op=='domains.check':
        domain=a._check_domain_format(args.get('domain',''))
        return {'valid':True,'taken_by':a.domain_in_use(domain),'in_cloudflare':any(r.get('hostname')==domain for r in routes(a))}
    if op=='ports.suggest':
        used={s['port'] for s in a.db.query('SELECT port FROM services',fetch_all=True)}
        for port in range(8000,65536):
            if port in used:continue
            with socket.socket() as sock:
                try:sock.bind(('0.0.0.0',port))
                except OSError:continue
                return {'port':port}
        raise a.ServiceOpError('No available port')
    if op in ('webhook.get','webhook.set'):
        if op=='webhook.set':
            s=service(a,args)
            with a.service_lock(s['name']):
                for key in ('auto_update','rotate_secret'):
                    if key in args and not isinstance(args[key],bool):raise ValueError(key+' must be boolean')
                if 'auto_update' in args:a.set_auto_update(s['name'],args['auto_update'])
                if args.get('rotate_secret'):a.rotate_webhook_secret(s['name'])
        return webhook(a,args)
    if op=='backups.list':return backup_list(a,args)
    if op=='backups.create':return backup_create(a,args)
    if op=='backups.restore':return backup_restore(a,args)
    if op=='backups.delete':return backup_delete(a,args)
    return runtime.run(a,op,args)
