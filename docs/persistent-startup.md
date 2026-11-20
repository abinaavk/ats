# Persistent ATS Local and Global startup

Interactive CLI use ends when its terminal closes. The Global control listener belongs to the persistent `app.py --daemon` process, alongside its operation worker and backup scheduler. Its loopback port is `ATS_REMOTE_PORT`, default 9997. Local uses the same daemon entry for its webhook receiver.

From the existing ATS checkout and Python environment, preserving the host's `ATS_CONFIG_FILE`, `ATS_CLUSTER_DB`, `ATS_INSTANCE`, and `ATS_MONITOR_ADAPTER`, preview a unit:

```sh
sudo -E /absolute/path/to/python /absolute/path/to/ats/app.py server service --port 9997
```

Option 12 also offers this preview. It does not install or start anything. Review the printed interpreter, configuration and database paths. The Global `ATS_MONITOR_ADAPTER` must point to the installed Monitor `remote_host.py` to serve data and management requests; health alone does not verify that adapter. The interpreter needs both ATS and Monitor dependencies.

Use an existing ATS daemon unit if present. Do not run duplicate daemons against one configuration. After reviewing and approving installation, save the unit under `/etc/systemd/system/ats-server2.service`, run `systemctl daemon-reload`, then `systemctl enable --now ats-server2.service`. `Restart=always` retries exits; it does not repair invalid configuration or detect a hung process. The root runtime must remain root.

Verify `systemctl is-active` and `systemctl is-enabled`, then `ss -ltnp 'sport = :9997'`. An unsigned request must be rejected, not granted access. Through the paired Local Monitor, verify Global health, service reads, and one safe approved write on a test service. Confirm the operation occurs on Global and Local stays untouched. Verify restart and boot behavior on the host in an approved maintenance window. Preserve identities, config and tunnel credentials.

The tunnel must independently route the Global HTTPS `/v1/request` endpoint to `http://127.0.0.1:9997`. A running listener does not prove tunnel connectivity. Do not increase systemd timeouts or force a tunnel protocol without checking its current journal and network context.

Disconnect is a Local setting and works without Global connectivity. Reconnect verifies a live signed health request. Revoke requires reaching Global to invalidate its old key; an unreachable Global cannot confirm revocation. A successful revoke rotates the Global key and removes Local's copy. Export a fresh private pairing file on Global to pair again. For a legacy revocation that left a NULL key, use the explicit `server rotate` command and re-pair; arbitrary damaged keys are still rejected.

Health and revocation use 5- and 10-second transport timeouts respectively. Actual management requests retain their longer operation timeout. Registry permission, endpoint, TLS, tunnel and adapter failures still need operator repair.
