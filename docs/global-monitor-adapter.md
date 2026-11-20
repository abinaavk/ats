# Global Monitor adapter setup

The Global ATS daemon listens on loopback port 9997. Signed health requests can
succeed while management requests fail: the latter invoke the companion
`ats-monitor/remote_host.py`. The adapter runs as a private subprocess, without
starting a public Monitor web server.

Use `server adapter` to preview the six settings for an existing daemon. Use
`server service` with the same options to preview a complete new daemon unit.
Both use the current interpreter and ATS checkout, read the existing ATS config
for `ats_home`, and preserve an explicit `ATS_HOME`, `ATS_CLI` or `ATS_MODULE_DIR`.
They never import Monitor, create adapter state, install a unit, restart a
service, reconnect, or rotate pairing credentials. Keep the existing instance's
`ATS_CONFIG_FILE`, `ATS_CLUSTER_DB` and, if used, `ATS_INSTANCE` when invoking them.

## Install the reviewed companion

Install `abinaavk/ats-monitor` at the reviewed revision in a root-owned directory
with root-controlled parents. Server2's reviewed companion is commit
`a752cac67da80ae9aae3d5cff1876b16a8bc20cd`. For a new installation, after applicable
production approval, these commands stop if the destination already exists:

```sh
sudo sh -eu <<'SH'
test ! -e /opt/ats-monitor-server2
test ! -L /opt/ats-monitor-server2
GIT_TERMINAL_PROMPT=0 git clone --no-checkout https://github.com/abinaavk/ats-monitor.git /opt/ats-monitor-server2
git -c core.hooksPath=/dev/null -C /opt/ats-monitor-server2 checkout --detach a752cac67da80ae9aae3d5cff1876b16a8bc20cd
git -C /opt/ats-monitor-server2 rev-parse HEAD
SH
```

Confirm the printed revision matches. Use the host's already authorized GitHub
access; do not put credentials in a URL. The daemon interpreter must have both
ATS and Monitor requirements installed. Package installation or upgrades are a
separate deployment change. Distribution metadata alone does not prove that
runtime imports work. Keep this Monitor checkout free of `ats.db`, which its
legacy data lookup would otherwise prefer over `ATS_HOME`.

## Preview settings for Server2

On the verified Server2 installation, run from `/home/abi/ats` with the updated ATS
source and existing interpreter. Capture only successful output to a temporary
file; review it before installing anything:

```sh
sudo env ATS_CONFIG_FILE=/etc/ats/config.yml ATS_CLUSTER_DB=/etc/ats/cluster.sqlite3 \
  /usr/bin/python3.12 /home/abi/ats/app.py server adapter \
  --monitor-adapter /opt/ats-monitor-server2/remote_host.py \
  --adapter-state-dir /var/lib/ats-server2-adapter
```

The resulting `[Service]` drop-in includes these settings:

| Setting | Server2 value |
| --- | --- |
| `ATS_MONITOR_ADAPTER` | `/opt/ats-monitor-server2/remote_host.py` |
| `ATS_MODULE_DIR` | `/home/abi/ats` |
| `ATS_CLI` | `/usr/bin/python3.12 /home/abi/ats/app.py` |
| `ATS_HOME` | `/home/abi/ats`, read from the existing config |
| `ATS_SECURITY_DB` | `/var/lib/ats-server2-adapter/security.sqlite3` |
| `ATS_MONITOR_JOBS_DIR` | `/var/lib/ats-server2-adapter/jobs` |

Without `--adapter-state-dir`, both `ATS_SECURITY_DB` and
`ATS_MONITOR_JOBS_DIR` must already be explicitly set to absolute paths. Full
service previews also preserve these two settings when inherited. No private
pairing key is printed. The drop-in retains existing `ExecStart`, root service
user, restart policy, port, config and registry settings. It adds `UMask=0077`
and file/directory preflight checks. A plain Global service preview warns when
the adapter file is absent.

## Apply and verify in the approved maintenance window

Use the existing service. Do not start another daemon against the same instance.
Preserve its unit and any existing drop-in before modifying them. For a new
private state destination, first confirm it is unoccupied, then create the
root-owned directories with mode 0700:

```sh
sudo install -d -m 0700 /var/lib/ats-server2-adapter /var/lib/ats-server2-adapter/jobs
```

Save the reviewed preview to
`/etc/systemd/system/ats-server2.service.d/50-monitor-adapter.conf`. Verify the
complete service with `systemd-analyze verify`, then perform the approved
`systemctl daemon-reload` and single restart. This interrupts management and may
resume queued or scheduled work. Repository push/merge authorization does not
authorize this host deployment. Do not blindly re-run installation over existing
paths.

Verify the active PID owns `127.0.0.1:9997`. Send independently signed health and
read-only service-list requests through both loopback and the public HTTPS
origin. Check identity, `management_ready: true`, HTTP 200, and the adapter's
successful `/api/manage/services` response. Preserve secrets locally; share only
status and identity-match booleans. A file-based readiness flag alone does not
verify adapter imports, ATS CLI access or data routing.

If verification fails, restore the previous drop-in (or remove only the new
drop-in if none existed), reload systemd and perform the approved rollback
restart. Preserve the checkout and private state for diagnosis. Do not rotate
keys to repair an adapter failure.

After Global adapter reads pass, separately verify the Local saved credential
and connection state before authorizing reconnection. Confirm a service read and
a reversible approved test-service write/readback through Local Monitor target
Global correctly. Previously unconfirmed revocation remains a separate issue;
keep Server2 disconnected until that is resolved. Boot enablement does not prove
actual reboot recovery.
