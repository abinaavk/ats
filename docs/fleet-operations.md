# Fleet operations

Everything here builds on the signed Local ↔ Global channel described in [multi-server.md](multi-server.md). Nothing opens a new port or a new tunnel route.

## Versions and updating a Global

Every Global reports the commit of its ATS checkout and of its Monitor companion (`status` request). Monitor shows them in the **Fleet overview** and flags a Global that is not on the same ATS commit as the Local.

**Update** (Monitor → Settings → Servers → Fleet overview) sends an `update` request. On the Global it:

1. refuses if the checkout is not a git repository or has local changes (nothing is touched),
2. fetches the tracked branch (`ATS_UPDATE_BRANCH`, else the current branch, else `main`),
3. applies a **fast-forward only** (a detached checkout is moved to the new commit),
4. imports/compiles the new code; if that fails the previous commit is restored,
5. re-executes the daemon in place (same PID, arguments and environment) once the reply is sent.

A Global running an ATS from before this feature cannot update itself; update it once by hand (`git pull`, restart ATS). The Local itself is updated with `git pull` and a restart (Monitor cannot restart itself).

## Pairing with a one-time code

```bash
sudo python3 app.py server pair-code            # on the Global; prints e.g. K7QM-4TXD-9WPA (10 minutes, one use)
sudo python3 app.py server pair --domain https://api.example.com --code K7QM-4TXD-9WPA   # on the Local
```

Monitor has the same form under *Add a Global server*. The code is stored on the Global only as a hash, works once, expires (1–60 minutes, default 10), at most five are active, and the unsigned redeem request is limited to 8 attempts per minute. The returned details are verified with a signed health request before anything is saved. Pairing files still work.

## Rotating a Global's key

```bash
sudo python3 app.py server rotate-global --server-id ID     # on the Local; Monitor: server card → Rotate key
```

The Global creates a new key over the signed channel; the Local verifies it with that key before saving it. The **old key keeps working for 10 minutes**, so an interruption cannot lock either side out; revoking or rotating by hand ends the grace period at once. The Global's pairing file is refreshed with the new key.

## Fleet overview and alerts

The ATS daemon on the Local probes every connected Global each minute (`status`, falling back to `health` for older Globals) and keeps the result in the registry. Monitor shows CPU, memory, the fullest disk, uptime and version for every server; **Check now** probes immediately without saving anything.

Alerts also cover what each server's own collector finds: a **failed systemd unit**, and the **deployment / service / health / backup** problems ATS already tracks for each service (`ops_alerts`). Each is announced once when it first appears and once when it clears; problems that already exist when a server is first seen are announced once so they are not silent. Choose the kinds, and list units to **ignore** (for example a long-dead `atopacct.service`), under Alerts → *What to tell me about*. Disk is left to the threshold below, so it is not reported twice.

Alerts go to any of: **ntfy**, **Telegram**, or a generic **webhook** (https only, redirects never followed; tokens are stored in the registry and never shown again). A Global is *down* after N failed checks (default 3), announced once, announced again as *recovered*, and mentioned again only every 6 hours while it stays down. Disk and memory thresholds (default 90 % / 95 %) alert once and clear with 5 % hysteresis. Failed deliveries are recorded and shown in `server doctor`.

## Registry backups

The registry (`cluster.sqlite3`) holds every identity and key. The daemon backs it up daily to `registry-backups/` next to it (mode 0600 in a 0700 directory) and keeps seven. You can also run:

```bash
sudo python3 app.py server backup [--output FILE] [--encrypt | --passphrase-file FILE]
sudo python3 app.py server backups
sudo python3 app.py server restore --input FILE [--passphrase-file FILE] [--yes] [--force]
```

Backups use SQLite's online backup, so they are consistent while ATS runs. `--encrypt` uses `openssl` AES-256 with PBKDF2; set `ATS_REGISTRY_BACKUP_PASSPHRASE_FILE` to encrypt the daily ones too. A restore checks the file first, refuses a backup from a different server identity unless `--force`, and keeps a `pre-restore-*` copy of what it replaces. Restart ATS (and Monitor) afterwards. Backups are never served to the browser and cannot be restored from Monitor.

### Off-host copies

A backup that lives only on the disk it protects is lost with that disk. The Local can therefore push **encrypted** copies of its registry to every connected Global over the signed channel:

```bash
sudo python3 app.py server backup-push [--passphrase-file FILE]       # send now (prompts when run in a terminal)
sudo python3 app.py server backup-fetch [--server-id ID] [--backup-name NAME] --output FILE   # bring one back
sudo python3 app.py server restore --input FILE --passphrase-file FILE                          # then restore it as usual
```

With `ATS_REGISTRY_BACKUP_PASSPHRASE_FILE` set, the daily backup is encrypted and pushed automatically. Copies are never sent in the clear: the Local refuses a plain backup, and a Global refuses any file that is not an `openssl` encrypted one, so a Global never holds a readable key. Files travel in checksummed chunks, are stored under `offsite-backups/` (0600 in a 0700 directory), appear under their real name only once complete and verified, and the newest 10 are kept (16 MB limit). `server doctor` and Monitor show when the last copy went and whether it worked.

## Webhook mappings in Monitor

Create (secret shown once, with the payload URL GitHub needs), delete, and **Test** a mapping from the server card. A test sends a signed GitHub `ping` through the same checks as a real delivery, checks the public webhook address answers, that the Global is reachable and that the service exists there. It never deploys anything.

## Audit trail

Monitor records which signed-in device did what, on which server and when: service deploy/edit/delete/actions, package installs, tunnel config edits and restores, settings changes, terminal opens, key rotations, updates, mapping changes, backups. Only names are recorded (server, service, package, backup file); never keystrokes, terminal output, file contents, request bodies or secrets. It appears under Settings → Devices → Security activity.

## Doctor additions

`server doctor` also reports Docker (installed, daemon reachable), rclone (installed, remotes configured), terminal availability on this server and on each Global, version differences, registry backup age and alert delivery. Missing optional tools are warnings that name the fix; a Docker that is installed but not answering is a failure.

## Cloudflare config backups

The tunnel config editor keeps timestamped copies. `cloudflare.config.backups` lists them (newest first, with the hostnames each routes) and `cloudflare.config.restore` puts one back through the same validation, backup-first, atomic write and automatic roll-back as an edit. Only files named like the editor's own backups are offered; symlinks are never followed.

## Tests and CI

Both repositories run their unit suites on every pull request (`.github/workflows/tests.yml`; as root, like a server). The full-stack rehearsal (`tests/rehearsal/rehearse.py`) needs root and port 443, so it is run by hand before a release.
