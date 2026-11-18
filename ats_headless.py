"""NDJSON entry point. Import the interactive app with stdout isolated."""
import contextlib
import importlib.util
import json
import os
import re
import sys


def main(path):
    output = sys.stdout
    def emit(event):
        output.write(json.dumps(event, ensure_ascii=True) + '\n')
        output.flush()
    try:
        if len(sys.argv) != 3:
            raise ValueError('usage: app.py --api <operation>')
        raw = sys.stdin.read(262145)
        if len(raw) > 262144:
            raise ValueError('request exceeds 256 KiB')
        args = json.loads(raw) if raw.strip() else {}
        if not isinstance(args, dict):
            raise ValueError('request must be a JSON object')
        with contextlib.redirect_stdout(sys.stderr):
            spec = importlib.util.spec_from_file_location('ats_headless_app', path)
            app = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = app
            spec.loader.exec_module(app)
            def log(message, level='info'):
                emit({'t': 'log', 'm': app.redact_repo_url(str(message)), 'lvl': level})
            app.api_emit = emit
            app.api_log = log
            import ats_api
            data = ats_api.run(app, sys.argv[2], args)
        emit({'t': 'result', 'ok': True, 'data': data})
        return 0
    except (Exception, SystemExit) as error:
        code = getattr(error, 'code', 'failed')
        if isinstance(error, (ValueError, TypeError, KeyError)):
            code = 'validation'
        if error.__class__.__name__ == 'ServiceBusyError':
            code = 'busy'
        if str(error).startswith('not_configured:'):
            code = 'not_configured'
        if code not in ('validation', 'conflict', 'notfound', 'not_configured', 'busy', 'unsupported', 'failed'):
            code = 'failed'
        message = 'ATS could not initialize; inspect stderr for permission or setup errors' if isinstance(error, SystemExit) and isinstance(error.code, int) else str(error)
        message = re.sub(r'(https?://)[^/\s@]+@', r'\1***@', message)
        emit({'t': 'result', 'ok': False, 'code': code, 'error': message or 'ATS could not start; inspect stderr'})
        return 1
