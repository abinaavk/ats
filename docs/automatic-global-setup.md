# Automatic Global setup and credential recovery

Update ATS on both Local and Global before updating Monitor. The Global remains
an authenticated task executor: Local selects the server and forwards allowed
operations over signed HTTPS; Global reuses ATS's existing operation engine.
Global never starts a GitHub webhook receiver.

## Quick path

On a new Global, as root, from the ATS checkout:

```sh
sudo python3 app.py server configure --role global --name 'Build server' --api-domain https://api.example.com
sudo python3 app.py server setup --apply --install-monitor
sudo python3 app.py server doctor
```

`--install-monitor` is only needed when the Monitor companion is not installed yet. The
Global needs **only Flask** (plus optional `psutil`) for the companion: its adapter runs
headless and does not import Socket.IO or gevent. If Flask is missing, setup stops *before
changing anything* and names the exact package for the interpreter it will use, for example
`apt-get install python3-flask python3-psutil`, or
`<python> -m pip install -r /opt/ats-monitor/requirements-adapter.txt`.

Then copy the private pairing file to the Local operator and add it in Monitor
**Settings → Servers** (you can paste the whole file; the fields fill themselves).

## Set up a configured Global

From the existing ATS checkout and Python environment, preserve the instance's
`ATS_CONFIG_FILE` and `ATS_CLUSTER_DB` settings. Inspect the detected setup:

```sh
sudo python3 app.py server setup
```

Then install it with one command:

```sh
sudo python3 app.py server setup --apply
```

Interactive option **12 → Set up Global API service and tunnel** provides the
same preview and install flow. Initial interactive Global configuration offers
the installation after saving identity. Headless configuration supports
`server configure --role global --name NAME --api-domain https://HOST --apply`.
Existing ID and key are preserved; repeated setup does not rotate credentials.

The installer reads the saved `cloudflare_config`, `cloudflared_service` and
`ats_home`; environment overrides still win. It finds an existing ATS daemon
using this checkout and registry among `ats*.service` units, or creates a named
`ats-global-<ID>.service`. For a custom name, supply `--unit NAME.service`.
It reuses the existing adapter environment, port and private state where known.
Otherwise it discovers one installed Monitor companion at a standard path;
use `--monitor-adapter /absolute/path/remote_host.py` if missing or ambiguous.
The Monitor companion and its dependencies must already be installed; setup
does not download executable code or install packages as root.

A healthy, locally managed Cloudflare tunnel service must already exist and
explicitly reference that config file. ATS adds only the Global hostname's
`^/v1/request$` route to the loopback listener. It preserves tunnel credentials,
other routes, their policy fields and the final catch-all. YAML formatting and
comments may change; the original bytes are backed up. A matching broad API
route is narrowed. Conflicting hostnames, covering wildcard routes, duplicate
ATS daemons, occupied ports and foreign destination files stop setup.

`cloudflared tunnel --config FILE ingress validate` and `systemd-analyze verify`
run before active files change. ATS writes a managed drop-in for an existing
operator unit, preserving the original unit. It enables automatic startup and
`Restart=always`, starts/restarts the API when needed, verifies signed health
and an actual adapter service-list read, then restarts Cloudflare only when its
route changed. A second run with unchanged files performs verification without
restarting services. Credentials never appear in the generated service or
console output.

The result reports loopback and public verification separately. DNS records,
Cloudflare account login and token-managed dashboard tunnels are not created or
changed. If public verification fails, the verified local service remains
running and the command reports that DNS/edge connectivity is still unverified.
See [Cloudflare configuration documentation](https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/configuration-file/).

## What setup checks before it changes anything

1. The Monitor companion is found (standard paths) or installed with `--install-monitor`.
2. `remote_host.py --check` runs under the daemon's interpreter with scratch state: Flask is
   importable, Monitor starts, the jobs directory is usable and the ATS CLI lists services.
3. `cloudflared ... ingress validate` and `systemd-analyze verify` pass on the candidates.
4. The running tunnel really reads the Cloudflare file being edited: it names it with
   `--config`, or the file is one of cloudflared's default locations. Token-managed tunnels
   are refused (their routes live in the Cloudflare dashboard).

`--install-monitor` clones `--monitor-repo` (default the `ats-monitor` repository) into a **new**
root-owned directory (default `/opt/ats-monitor`, change with `--monitor-dir`) with hooks
disabled, checks out `--monitor-ref` (default `origin/main`) and prints the resulting revision.
It refuses an existing directory and a parent that is not root-owned. A private repository
needs read access on the Global first (deploy key or `gh auth login`). It never installs
Python packages. The companion runs as root, so only install from a repository you control.

An existing route for the API hostname is accepted when it already points at the same
loopback port, whether spelled `localhost` or `127.0.0.1`; it is narrowed to `^/v1/request$`.
If cloudflared is slow to restart, setup waits for systemd to bring it up and retries a
bounded number of times before rolling back.

## Health check: `server doctor`

`server doctor` is read-only and prints one line per check with the fix for each problem
(`--json` for scripts; exit status 1 if anything failed).

On a **Global** it checks the pairing file (private, current key), clock sync, the service
(installed, active, enabled), the tunnel route, the listening port, the Monitor adapter, and
signed health plus an adapter service read on loopback and on the public HTTPS origin.
On the **Local** it signs a health request and a service read to every paired Global and
reports the cause of each failure: wrong ID/passkey, clock skew, Cloudflare blocking,
missing tunnel route, stopped daemon or tunnel, DNS, TLS or a missing adapter. The same
reasons appear in Monitor's Settings → Servers and in selected-server errors.

## Failure recovery

Validation failures leave active files untouched. Failures after installation
restore the previous service/tunnel file bytes and restart the affected old
services, or stop/disable a newly installed service. Private backups are under
`setup-backups-<ID>` beside the registry. Rollback failure is reported explicitly
with that location; inspect the host before retrying. Newly created empty
private directories and backup evidence are retained. The installer does not
claim to reverse work a service performed while running.

Environment-file-based daemon units require resolving their settings explicitly
before automatic setup. Existing adapter state must be root-owned and private
(mode 0700 directories). Real reboot recovery remains an operator verification.

## Replace credentials on an existing Local entry

Generate a fresh private pairing file on Global with `server rotate` when a key
needs rotation. Keep its stable ID unless replacing/recovering the Global itself.
In Monitor **Settings → Servers → Update ID and passkey**, enter the current
Global ID, HTTPS origin and new private key. The password field is cleared after
submission and no key is written to browser storage. This verifies the supplied
credentials; it does not rotate Global remotely or expose stored keys.

The CLI equivalent on Local is:

```sh
sudo python3 app.py server replace-credentials --pairing-file /private/current-pairing.json
```

`--server-id` is optional: the saved server is found by the file's ID, then its HTTPS address,
then its name. Pass `--server-id` to be explicit. CLI option 12 → **Update saved Global ID /
passkey** does the same and asks you to confirm which saved server it found. The Global's
exported pairing file always carries its current key, including right after a remote revoke.

Successful replacement preserves enabled/disconnected state. A changed ID
atomically migrates explicit webhook mappings; it never merges two existing
servers. Old jobs and stale browser requests keep the old ID and fail closed.
Review previous jobs before changing identity. A failed verification preserves
the old record and mappings. Reconnect after verifying the replacement if the
entry was disconnected.

Unconfirmed revocation is now persistent and visible. Reconnect and re-pairing
with the same key are blocked until fresh credentials verify. Connection updates
use a revision check so a delayed reconnect/revoke/edit cannot undo a newer
operator action. The existing TLS verification, per-request signatures,
identity binding, timestamp window and nonce replay checks remain mandatory.
