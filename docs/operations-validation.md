# Operations feature validation

The monitor and ATS changes must be installed together, ATS first. Preserve the
existing ATS configuration, database and backup encryption key. Restart ATS and
the monitor using the server's existing deployment procedure.

## Automated checks

The test environment uses disposable instance directories and simulated host
commands. The monitor bridge itself and the ATS headless API are exercised as
real code. Browser checks use Chromium with desktop and phone viewports.

The baseline before this change passed 100 ATS tests and 38 monitor bridge tests.
Feature-specific results are recorded in the pull request review.

These checks cannot establish that the production systemd units, Docker daemon,
Cloudflare tunnel, Drive credentials or GitHub webhook deliveries work on the
server. Phone viewport simulation does not exercise a physical phone keyboard.

## Server verification after an approved merge

Use a disposable service with a small repository and a test database.

1. Confirm that the collector reports recent successful samples. Stop it once
   and verify that Manage shows stale or unavailable observations.
2. Deploy a commit, push a second commit and update. Check each operation's live
   stages and recorded commit and result. Roll back to the first successful
   deployment. Confirm the code changes and the database remains unchanged.
3. Push to the configured branch through a correctly signed GitHub delivery.
   Inspect the webhook result, then test a wrong secret and a different branch.
   Neither rejected delivery should deploy code.
4. Configure a health path that returns success, then one that fails. Verify
   latency, repeated failure state and the resulting alert; restore the path
   and verify recovery. Check resource history after several collector cycles.
5. Configure a short backup schedule. Confirm a backup appears, its verification
   result is reported, and retention applies to scheduled backups only. Verify
   that disabling the schedule prevents later scheduled runs.
6. Perform an actual restore of the test database from the scheduled backup.
   Archive verification alone does not prove application-level recovery.
7. Change a resource limit and restart the service. Confirm both actions appear
   in activity history without environment values or webhook secrets.

Scheduled operations and alerts depend on the collector running. Alert delivery
is in the Manage interface; this change does not configure external messaging.

## Mobile installation

PWA metadata is linked from both login and the authenticated dashboard, with
192px/512px icons, an Apple touch icon, standalone display and the existing root
start URL. Android browsers can expose an Install app control; iPhone users get
Add to Home Screen instructions. Installation availability depends on browser
support and requires HTTPS in production. Existing authentication still applies.
See [MDN installation guidance](https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/Guides/Making_PWAs_installable).

The root-scoped worker caches only a generic offline document. Dashboard pages,
service responses, terminal traffic, credentials and mutations are never stored
in its cache. Navigation uses the network first; network failure shows a clear
reconnect page. Server actions are never queued for later execution.

After an approved deployment, verify installation on Android Chrome and iPhone
Safari, launch from the home screen, sign in, rotate the phone and check the
bottom navigation. Disconnect, relaunch, confirm the reconnect page, reconnect
and retry. Physical installations are not covered by desktop browser simulation.
