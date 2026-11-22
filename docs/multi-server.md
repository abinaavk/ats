# Primary Local and Global servers

The primary Local runs Monitor and the only GitHub webhook receiver. Every Global
has a stable random identity and an independent 256-bit management key. Requests
bind the HTTP method, path, exact body hash, destination identity, timestamp and
nonce. Nonces persist across workers/restarts. HTTPS certificate verification is
mandatory; redirects are never followed.

## Operator preparation

Review and approve the ATS and Monitor PRs before installation. This document is
setup guidance, not authorization to deploy, restart services, provision storage,
change Cloudflare or configure GitHub. Back up the existing ATS configuration and
database privately. Configure storage, repository access, sudo policy and TLS as
operator tasks. Keep the primary Local available as the control point.

Install both repositories on each Global: ATS supplies deployment operations;
Monitor supplies its existing host/Docker/database/log/metrics route adapters.
Only Local needs a browser-facing Monitor process. Global does **not** need to run
a public Monitor login server. Install Monitor's Python requirements in the Python
interpreter used by ATS. Set `ATS_MODULE_DIR` to the installed ATS repository and
`ATS_MONITOR_ADAPTER` to the absolute `ats-monitor/remote_host.py` path.
`ATS_CLI` must identify that server's existing ATS CLI, and its existing
`ATS_CONFIG_FILE`/`ATS_INSTANCE`, service identity, storage and backup settings must
be correct. Never point multiple physical servers at the same jobs directory.

`ATS_CLUSTER_DB` defaults to `/etc/ats/cluster.sqlite3`. It contains private keys
and deduplication state and is always mode 0600. On Local, provision its directory
and file so the Monitor service identity owns them; the root ATS CLI can also
access the same file. Set the **same absolute path** in Local Monitor and ATS's
service environments. On Global, only its ATS service identity needs access.
Keep the containing directory private (0700), outside static files, repositories
and public backups. Do not relax it to world-readable. Use an OS/encrypted disk
or private encrypted backup for the registry; keys are not application-encrypted.
An operator with access to the service account or root can read them.

## Launch-time setup for existing installations

Launching `sudo python3 app.py` interactively now checks Local/Global settings
before entering the menu or starting workers, including when the older ATS
configuration already exists. It asks for missing mode, server name and the
role-specific endpoint. Local setup uses the configured Cloudflare file to check
hostname conflicts and requires explicit confirmation to reuse an existing route.
Global setup asks for an HTTPS API origin and automatically exports its private pairing file;
it never starts a webhook receiver. Invalid input can be corrected immediately.
Cancelling setup exits before workers start. Existing valid settings, identities
and credentials are reused on later launches.

Use the same `ATS_CONFIG_FILE`, `ATS_INSTANCE` and `ATS_CLUSTER_DB` environment
as the service when completing setup. Daemon launches never prompt for these new
settings: incomplete setup fails before background work with an actionable
message. Explicit `server configure` remains available for unattended provisioning.
The setup check validates stored configuration, not public DNS/TLS or remote
connectivity. Cloudflare routes, storage, GitHub setup and service restarts remain
operator actions. A damaged identity/credential must be restored from the private
registry rather than silently replaced.

## Configure Local

```sh
python3 app.py server configure --role local --name 'Primary Local' \
  --webhook-host hooks.example.com --cloudflare-config /path/to/cloudflared.yml
python3 app.py server show
```

Omit options in a TTY for role/name/hostname guidance. Headless setup fails when
required inputs are missing. The command reads the actual tunnel ingress and
checks the chosen hostname against existing ATS service domains. Duplicate
hostname entries are rejected. An existing exact or covering wildcard route
requires inspection and `--confirm-existing-route`. **No command here rewrites
tunnel configuration.** The operator must verify ingress ordering, the route's
actual destination, DNS and port use, then configure the hostname to reach the
Local listener (default loopback port 9999). Inspect other ATS instances and
separate Cloudflare configurations on the host as well.

The existing `--daemon` runs the existing operations/backup workers and the Local
receiver. Receiver startup requires a configured Local identity. ATS does not
modify Cloudflare routes during listener or daemon startup.

## Configure Global and pair

```sh
python3 app.py server configure --role global --name 'Build server' \
  --api-domain https://api.build.example.com
```

The default pairing file is `files/pairing.json` inside the installed ATS checkout:
for `/ats/app.py`, it is `/ats/files/pairing.json`. The path is independent of your
current working directory.
The directory is private (0700), the JSON is private (0600), and `files/` is ignored
by Git. Keep it outside any web server's static roots and public backup archives.
The cluster database remains the source of identity and credentials; the JSON is
a private export for pairing, not a replacement configuration database.

Global configuration, normal interactive startup and daemon startup create a
missing default export automatically without rotating the saved identity or key.
Reconfiguring the name/API origin updates the export while preserving credentials.
An existing default file must be private and belong to this same identity;
symlinks, malformed files and foreign identities are rejected
without overwriting the file. Separate configured Global instances
must use separate checkouts. ATS secures the opened `files/` directory to
0700 before exporting. Because app.py requires root, root startup also takes
ownership of this managed directory when the checkout belongs to the login user
(for example `/home/abi/ats/files` owned by UID 1000). An existing private export
may belong to root or that directory's original owner and must match the registry
identity. Validation happens before ownership changes. Root takes ownership of the validated
existing export before the directory so interrupted repairs can be retried; the
refreshed atomic 0600 export also belongs to root. Other files, including old private exports, keep their
contents and ownership. There is no recursive chown/chmod and no ownership change
to the checkout itself. Non-root exports still reject foreign-owned directories.
Read-only filesystems or failed permission repairs require operator correction. Use the same
runtime user as the existing installation. Preserve the registry and pairing files;
do not delete them or rotate credentials to fix a permissions error.

Upgrades from the previous `files/.json` or `root/.json` locations export the existing registry
identity and key to `files/pairing.json` on the next Global startup or `server export`.
No credential rotation or re-pairing is needed. The registry stays authoritative;
the old private files are retained for operator-controlled recovery and
remain ignored by Git. ATS never imports credentials from those old exports.

Choose **12 — Server Configuration** in the ATS CLI to configure name/endpoint,
export the pairing file, explicitly rotate a Global key, list/pair Global servers,
or disconnect/reconnect/revoke them from Local. Rotation/revocation requires an
explicit confirmation. The screen shows the file path and never prints the key.
Roles remain fixed after initial configuration. Re-pair in Local after rotation.

Headless recovery of a missing export preserves credentials:

```sh
python3 app.py server export
```

`--pairing-file /private/build-pair.json` remains available for an explicit export
or configuration. Explicit paths are created exclusively and must not exist;
the default managed path is refreshed atomically. `server rotate` without that
option refreshes the default file. Rotation changes the key only when export
succeeds; it is never required merely to recreate a missing file.

The JSON contains identity, API origin and pairing key. Transfer it to the Local operator through a secure channel. It is
never printed. Do not put it in a repository, issue, shell history, chat or public
artifact. The key is a management credential, not a human account password.

### Missing Global hostname in Cloudflare config.yml

`server configure` saves the API origin in the private cluster registry, not in
`/etc/ats/config.yml` or the Cloudflare tunnel YAML. Global setup now displays the
required API-only ingress rule. It intentionally does not edit tunnel files or
restart Cloudflare. Inspect the active tunnel configuration using option **12 →
9 — Check Global API tunnel route**, or run:

```sh
python3 app.py server tunnel --cloudflare-config /path/to/active/config.yml
```

For an origin of `https://server2.gaiasentinel.online` and default API port, the
operator-managed rule is:

```yaml
- hostname: server2.gaiasentinel.online
  path: ^/v1/request$
  service: http://127.0.0.1:9997
```

Place it before any covering hostname, wildcard or catch-all rule in `ingress`;
retain existing tunnel credentials, application routes and the final catch-all.
Use `--port` or `ATS_REMOTE_PORT` if the management listener uses another port.
The check reports missing/conflicting/shadowed routes; a matching rule only
confirms the inspected YAML, not the active service's chosen file or connectivity.
It never prints credentials or rewrites YAML. Other paths on this hostname must
remain denied, and the operator must inspect later wildcard rules too. Configure
DNS and validate ingress/TLS manually using the [Cloudflare configuration guide](https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/configuration-file/), then apply/restart only with the applicable
operator authorization. This route reaches Global's authenticated management API;
it does not create a GitHub webhook receiver. Pair/reconnect from Local only after
HTTPS reaches the correct Global identity.

The operator must configure a TLS reverse proxy to forward only `/v1/request`
to `127.0.0.1:9997`, without redirects. Set proxy request/header/body/idle limits
and protect the origin against general network abuse. The ATS management
listener binds loopback, has bounded reads, concurrent connections, operations,
output and timeouts, and verifies HMAC before dispatch. Never expose the loopback
listener directly or bypass HTTPS verification. `ATS_REMOTE_PORT` can select a
different loopback port for `--daemon`.

After an applicable restart approval, use `server serve` (or the existing
`--daemon` with the Global configuration). Both reuse ATS scheduled operations
and backup workers, and Global starts **no webhook receiver**, creates no public
webhook URL, and changes no webhook tunnel route. Global API TLS routing is a
separate operator-managed API route, not another GitHub webhook endpoint.

On Local:

```sh
python3 app.py server pair --pairing-file /private/build-pair.json
```

Alternatively, open Monitor → Settings → Servers and enter the private file's
name, ID, HTTPS origin and key. Pairing performs a signed HTTPS health exchange
and verifies the destination identity before saving. Names, domains and identities
are unique in the primary registry. Pairing again with the same identity updates
its name/domain/credentials after validation. The browser retains only an active
server ID; credentials stay on the server and in the transient password input.
Remove transferred pairing files securely under your private-file retention
policy after setup.

## Repository mappings and GitHub

### Easiest ways to create a mapping

```sh
# A Local service that already has a GitHub webhook: reuse its repository, branch and secret.
# GitHub keeps working with no change (same payload URL and secret).
sudo python3 app.py server map --from-service SERVICE

# Any server (including a Global): generate a fresh secret, shown once, and print what GitHub needs.
sudo python3 app.py server map --repository owner/repo --server-id SERVER_ID --service SERVICE --generate-secret
```

Manage's per-service webhook secret is only honoured by the central receiver once the service is mapped.
Manage's Webhook tab shows whether it is (**Central receiver: mapped / not mapped**) and the exact command when not.
The `--secret-file` form below still works. A delivery that fails after acceptance is recorded with its real
reason (for example a missing service directory or a rejected passkey), not a generic message.

Create a separate random GitHub webhook secret in a private file, for example by
using an operator secret manager. It must contain a 64-character random hex key.
Register each destination **explicitly** on Local:

```sh
python3 app.py server map --repository owner/repository \
  --server-id GLOBAL_OR_LOCAL_ID --service service-name --branch main \
  --secret-file /private/repository-webhook-secret
```

On GitHub, manually configure the repository's push webhook to the primary
`https://hooks.example.com/webhook` (or `/webhook/service-name`), JSON content,
and that mapping's secret. Only authenticated `ping` and matching-branch `push`
events are accepted. The payload needs `repository.full_name`, the exact tracked
ref, a commit identity and a delivery identity. Deleted refs are rejected.
There is no repository-name guessing or implicit Local fallback. Duplicate
repository mappings and multiple repositories targeting one server/service are
rejected. API requests carry an explicit selected server; Global additionally
checks the destination service's current repository, branch and auto-update flag
before starting the existing update job. Local uses `service_git_update` and its
existing service lock. Local service repository and branch must match too.

The mapping secret is authoritative for the central receiver. Existing
per-service secrets are not automatically imported. Legacy webhook deployments
must create explicit mappings before enabling this change. To change a mapping, stop deliveries, inspect the destination and run `server map`
with all destination fields plus `--replace-mapping`. The flag requires an existing
repository mapping and still enforces unique destinations and secrets. Remove a
mapping using `server unmap --repository owner/repository`. Reconfigure GitHub
secrets together with the corresponding registry entry. Do not assume an
old per-service secret rotation changes the central mapping.

## Selection and long operations

Monitor uses one target identity per page lifetime. Selection is saved across
navigation. Switching reloads the document, aborts requests and destroys old
data, panels, confirmations, polling and sockets. The previous server's detached
jobs keep running there and can be viewed by switching back. A disconnected,
revoked, missing or unknown target produces an error with no Local fallback.
Account/Devices/Themes remain primary browser administration; host settings and
all host data/operations target the selected server. The Terminal tab and the Docker
shell also work on a Global (see *Terminals on a Global* below); a remote selection never gets a
shell on the Local.

## Terminals on a Global

The Monitor relays a browser terminal to the Global over the same signed HTTPS route as every other
call (`term.open`, `term.read` long poll, `term.input`, `term.resize`, `term.close`): no extra tunnel
route, port or WebSocket is needed, and the request signature, destination identity and replay checks
apply to each call.

* The shell runs as the **ATS service user** (or `ATS_TERMINAL_USER`), never as root. If that user is root,
  terminals stay disabled unless you set `ATS_TERMINAL_ALLOW_ROOT=1` deliberately.
* At most 3 terminals per Global; idle ones close after 10 minutes; closing the browser tab ends the shell.
* Keystrokes and output are relayed in memory only. The Global's journal records only that a session opened or
  closed (`terminal <id> opened (shell) as <user>`).
* `ATS_TERMINAL=off` in the daemon environment disables terminals on that Global. `server doctor` and the
  Servers page show whether a Global's terminal is available and why not.
* A Global must run this ATS version; an older one answers with a hint to update.

## Disconnect, reconnect and revoke

Use Settings → Servers, or `server disconnect|reconnect|revoke --server-id ID` on
Local. Disconnect prevents dispatch but keeps the key. Reconnect validates the
same HTTPS destination and identity. Revoke first removes the key on the reachable
Global, then removes the Local copy. Offline revocation cannot claim success:
rotate the key on the Global operator console and leave Local disconnected.

```sh
python3 app.py server rotate --pairing-file /private/fresh-pair.json
```

Rotation invalidates the old key immediately; pair the fresh file on Local.
The primary Local cannot be disconnected, revoked or silently replaced.

## Delivery recovery and limits

GitHub delivery IDs **and exact signed payload hashes** persist indefinitely for
replay protection. Concurrent duplicate deliveries claim one record atomically.
Pending Local deliveries survive process restart and the Local daemon recovers
them before accepting new events. Global deployment delivery IDs are independently
deduplicated, returning the original job result/ID when available.

Never blindly retry a mutation after a timeout. A crash during a running delivery
or ambiguous network outcome requires checking the destination's job and deployment
history. Such records are marked interrupted/failed rather than deploying twice.
A failed dispatch is visible in Local webhook event history; Global job IDs and
logs are viewed on that Global through Monitor. `dispatched` means the Global
accepted a job, not that deployment succeeded. Job polling reports its final
status and logs. Exact repeated pushes remain deduplicated; after inspection use
Monitor's explicit Update action to retry. Registry replay rows need operator
storage monitoring; they are deliberately not pruned automatically.

Validation uses temporary TLS certificates, host fixtures and fake system tools.
Production hosts, Cloudflare routes, public TLS termination and real GitHub
webhook delivery remain unverified until an authorized operator tests them.

## Server tools (delete, tunnel config, Docker and rclone)

The operations behind Manage's delete, Cloudflare config editor and one-click installs are `services.delete`, `cloudflare.config.get` /
`cloudflare.config.set` and `system.install` (only `docker` and `rclone`, from the apt or dnf packages, as root). All three report progress steps
and run on the selected server, including a Global through the signed channel. `services.delete` is idempotent; see the Monitor's `docs/manage.md`.

For version updates, pairing codes, key rotation, the fleet overview, alerts and registry backups see [fleet-operations.md](fleet-operations.md).
