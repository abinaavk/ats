# Automatic Global setup and credential recovery

Update ATS on both Local and Global before updating Monitor. The Global remains
an authenticated task executor: Local selects the server and forwards allowed
operations over signed HTTPS; Global reuses ATS's existing operation engine.
Global never starts a GitHub webhook receiver.

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
sudo python3 app.py server replace-credentials --server-id EXISTING_ID --pairing-file /private/current-pairing.json
```

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
