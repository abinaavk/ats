"""Run ATS Global planning/doctor/apply under the interpreter the rehearsal Global uses (see rehearse.py)."""
import json
import os
import sys

sys.path.insert(0, os.environ['REHEARSAL_ATS'])
import ats_cluster
import ats_doctor
import ats_global_setup as gs
import ats_server_cli as cli

mode = sys.argv[1]
store = ats_cluster.Store()
opts = dict(unit_dir=os.environ['E2E_UNITS'], state_dir=os.environ['E2E_ADAPTER_STATE'])
if os.environ.get('E2E_ADAPTER') and mode != 'apply_install':
    opts['monitor_adapter'] = os.environ['E2E_ADAPTER']
if mode == 'doctor':
    report = ats_doctor.run(store, **opts)
    print(report.text())
    sys.exit(1 if report.failed else 0)
elif mode == 'plan':
    print(json.dumps(gs.public_plan(gs.build_plan(store, **opts)), indent=2))
elif mode == 'apply':
    result = gs.apply(store, **opts)
    print(json.dumps(result, indent=2))
    cli.print_setup_summary(store, result)
