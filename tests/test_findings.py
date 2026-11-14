"""
Tests for the 8 code-review findings (stdlib unittest, no pytest).

Everything runs against a temporary ATS_HOME with fake executables first on
PATH (see harness.py) and os.geteuid patched to 0. No real systemd, Docker,
git remote, Google Drive or GitHub is involved.

Run (PyYAML must be importable, e.g. via PYTHONPATH):

    PYTHONPATH=/path/with/pyyaml python3 -m unittest discover -s tests -v
"""
import ast
import asyncio
import hashlib
import hmac
import inspect
import io
import json
import logging
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402

REAL_SLEEP = time.sleep


def slurp(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def spit(path, data, mode="w"):
    with open(path, mode) as f:
        f.write(data)


def free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class AppTestCase(unittest.TestCase):
    """Loads one fresh app.py per test class and resets state between tests."""

    @classmethod
    def setUpClass(cls):
        cls.env = harness.load_app()
        cls.app = cls.env.app
        cls.systemd_dir = os.path.join(cls.env.root, "systemd")
        os.makedirs(cls.systemd_dir, exist_ok=True)
        cls.app.SYSTEMD_DIR = cls.systemd_dir

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def setUp(self):
        app = self.app
        for table in ("services", "backups", "deployments", "metrics_history", "remote_configs", "webhook_events"):
            app.db.query(f"DELETE FROM {table}")
        for name in os.listdir(self.env.state):
            path = os.path.join(self.env.state, name)
            if os.path.isdir(path):
                import shutil
                shutil.rmtree(path)
            else:
                os.remove(path)
        if os.path.isdir(app.LOCKS_DIR):
            for n in os.listdir(app.LOCKS_DIR):
                os.remove(os.path.join(app.LOCKS_DIR, n))
        for key in [k for k in os.environ if k.startswith("FAKE_") and k != "FAKE_STATE"]:
            del os.environ[key]
        patcher = mock.patch.object(app.time, "sleep", lambda s: None)
        patcher.start()
        self.addCleanup(patcher.stop)

    # ---- helpers -----------------------------------------------------------
    def setenv(self, key, value="1"):
        os.environ[key] = value
        self.addCleanup(os.environ.pop, key, None)

    def add_service(self, name="svc", port=18001, domain=None, runtime="node", branch="main",
                    secret="s3cret-" + "a" * 24, auto_update=1, repo_url=None):
        app = self.app
        domain = domain or f"{name}.example.com"
        repo_url = repo_url or f"https://github.com/o/{name}.git"
        app.db.query(
            "INSERT INTO services (name, port, domain, storage_path, repo_url, workers, max_memory_mb, cpu_quota, "
            "runtime, branch, webhook_secret, auto_update) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (name, port, domain, self.env.storage, repo_url, 2, 256, 50, runtime, branch, secret, auto_update))
        api_dir = os.path.join(self.env.storage, "api", name)
        log_dir = os.path.join(api_dir, "logs")
        db_dir = os.path.join(self.env.storage, "database", name)
        for d in (api_dir, log_dir, db_dir):
            os.makedirs(d, exist_ok=True)
        cfg = app.ServiceConfig(name=name, port=port, domain=domain, storage_path=self.env.storage,
                                repo_url=repo_url, workers=2, max_memory_mb=256, cpu_quota=50, runtime=runtime)
        with open(os.path.join(self.systemd_dir, f"{name}.service"), "w") as f:
            f.write(app.generate_systemd_service(cfg, api_dir, log_dir, db_dir))
        return dict(app.db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True))

    def unit_text(self, name="svc"):
        return slurp(os.path.join(self.systemd_dir, f"{name}.service"))

    def fake_input(self, answers):
        """Patch builtins.input with a queue of answers ('' once exhausted)."""
        queue = list(answers)
        asked = []

        def _input(prompt=""):
            asked.append(prompt)
            return queue.pop(0) if queue else ""
        p = mock.patch("builtins.input", _input)
        p.start()
        self.addCleanup(p.stop)
        p2 = mock.patch.object(self.app.os, "system", lambda *_: 0)
        p2.start()
        self.addCleanup(p2.stop)
        return asked


# ==============================================================================
#  Finding 1 + 5: webhook authentication, limits, parsing
# ==============================================================================

def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class WebhookTests(AppTestCase, unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.server = await asyncio.start_server(self.app.handle_webhook, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()

    async def raw(self, data: bytes, read_timeout=5):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(data)
        await writer.drain()
        try:
            resp = await asyncio.wait_for(reader.read(65536), read_timeout)
        finally:
            writer.close()
        status = int(resp.split(b" ", 2)[1]) if resp else 0
        return status, resp

    async def post(self, path, body=b"", headers=None, secret=None, event="push", method="POST"):
        hdrs = {"Content-Type": "application/json", "Content-Length": str(len(body))}
        if event is not None:
            hdrs["X-GitHub-Event"] = event
        if secret is not None:
            hdrs["X-Hub-Signature-256"] = sign(secret, body)
        hdrs.update(headers or {})
        head = f"{method} {path} HTTP/1.1\r\nHost: x\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        return await self.raw(head.encode("latin-1") + body)

    def push_body(self, ref="refs/heads/main", repo="svc"):
        return json.dumps({"ref": ref, "after": "a" * 40, "repository": {"name": repo}}).encode()

    async def wait_for_result(self, name="svc", expect=None, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            events = self.app.list_webhook_events(name, 1)
            if events and events[0]["result"] != "accepted" and (expect is None or events[0]["result"] == expect):
                return events[0]
            await asyncio.sleep(0.05)
        self.fail(f"webhook event never reached {expect or 'a final result'}: {self.app.list_webhook_events(name, 3)}")

    # ---- finding 1 ----------------------------------------------------------
    async def test_valid_signature_push_updates_in_background(self):
        self.add_service()
        body = self.push_body()
        status, _ = await self.post("/webhook/svc", body, secret="s3cret-" + "a" * 24)
        self.assertEqual(status, 202)
        ev = await self.wait_for_result(expect="updated")
        self.assertEqual(ev["event"], "push")
        self.assertEqual(ev["ref"], "refs/heads/main")
        self.assertEqual(ev["commit"], "a" * 40)
        calls = self.env.calls()
        self.assertIn("git pull", calls)
        self.assertIn("systemctl restart svc", calls)
        row = self.app.db.query("SELECT status FROM deployments WHERE service_name='svc'", fetch_one=True)
        self.assertEqual(row["status"], "success")

    async def test_wrong_secret_is_401_and_recorded_without_update(self):
        self.add_service()
        status, resp = await self.post("/webhook/svc", self.push_body(), secret="not-the-secret")
        self.assertEqual(status, 401)
        self.assertNotIn(b"signature", resp.lower().split(b"\r\n\r\n", 1)[1])      # no detail in the body
        ev = self.app.list_webhook_events("svc", 1)[0]
        self.assertEqual(ev["result"], "rejected_signature")
        self.assertNotIn("git pull", self.env.calls())

    async def test_missing_and_malformed_signature_headers_are_401(self):
        self.add_service()
        body = self.push_body()
        status, _ = await self.post("/webhook/svc", body)                                  # no header
        self.assertEqual(status, 401)
        status, _ = await self.post("/webhook/svc", body, headers={"X-Hub-Signature-256": "sha1=abcd"})
        self.assertEqual(status, 401)
        status, _ = await self.post("/webhook/svc", body, headers={"X-Hub-Signature-256": "sha256=zzé"})
        self.assertEqual(status, 401)
        self.assertNotIn("git pull", self.env.calls())

    async def test_signature_over_a_different_body_is_rejected(self):
        self.add_service()
        good = self.push_body()
        status, _ = await self.post("/webhook/svc", good + b" ", headers={
            "X-Hub-Signature-256": sign("s3cret-" + "a" * 24, good)})
        self.assertEqual(status, 401)

    async def test_service_without_secret_is_403(self):
        self.add_service(secret="")
        self.app.db.query("UPDATE services SET webhook_secret='' WHERE name='svc'")
        status, _ = await self.post("/webhook/svc", self.push_body(), secret="anything")
        self.assertEqual(status, 403)
        self.assertEqual(self.app.list_webhook_events("svc", 1)[0]["result"], "rejected_signature")
        self.assertNotIn("git pull", self.env.calls())

    async def test_unknown_service_is_401_and_not_recorded(self):
        status, _ = await self.post("/webhook/nope", self.push_body(), secret="x")
        self.assertEqual(status, 401)
        self.assertEqual(self.app.db.query("SELECT COUNT(*) c FROM webhook_events", fetch_one=True)["c"], 0)

    async def test_ping_returns_200_when_signed(self):
        self.add_service()
        body = b'{"zen": "hi"}'
        status, _ = await self.post("/webhook/svc", body, secret="s3cret-" + "a" * 24, event="ping")
        self.assertEqual(status, 200)
        self.assertNotIn("git pull", self.env.calls())
        status, _ = await self.post("/webhook/svc", body, secret="wrong", event="ping")
        self.assertEqual(status, 401)                       # ping is authenticated too

    async def test_push_to_other_branch_is_ignored(self):
        self.add_service(branch="main")
        status, _ = await self.post("/webhook/svc", self.push_body(ref="refs/heads/feature"),
                                    secret="s3cret-" + "a" * 24)
        self.assertEqual(status, 200)
        self.assertEqual(self.app.list_webhook_events("svc", 1)[0]["result"], "ignored_branch")
        self.assertNotIn("git pull", self.env.calls())

    async def test_tracked_branch_follows_the_service_branch(self):
        self.add_service(branch="release")
        status, _ = await self.post("/webhook/svc", self.push_body(ref="refs/heads/release"),
                                    secret="s3cret-" + "a" * 24)
        self.assertEqual(status, 202)
        await self.wait_for_result(expect="updated")

    async def test_non_push_event_is_ignored(self):
        self.add_service()
        status, _ = await self.post("/webhook/svc", b"{}", secret="s3cret-" + "a" * 24, event="issues")
        self.assertEqual(status, 200)
        self.assertEqual(self.app.list_webhook_events("svc", 1)[0]["result"], "ignored_event")
        self.assertNotIn("git pull", self.env.calls())

    async def test_auto_update_off_verifies_signature_but_does_not_update(self):
        self.add_service(auto_update=0)
        status, _ = await self.post("/webhook/svc", self.push_body(), secret="s3cret-" + "a" * 24)
        self.assertEqual(status, 200)
        self.assertEqual(self.app.list_webhook_events("svc", 1)[0]["result"], "accepted")
        status, _ = await self.post("/webhook/svc", self.push_body(), secret="bad")
        self.assertEqual(status, 401)
        self.assertNotIn("git pull", self.env.calls())

    async def test_repo_name_fallback_still_requires_that_services_secret(self):
        self.add_service(name="svc", repo_url="https://github.com/o/portfolio-repo.git", secret="A" * 40)
        self.add_service(name="other", port=18002, repo_url="https://github.com/o/other.git", secret="B" * 40)
        body = self.push_body(repo="portfolio-repo")
        status, _ = await self.post("/webhook", body, secret="B" * 40)     # other service's secret
        self.assertEqual(status, 401)
        status, _ = await self.post("/webhook", body, secret="A" * 40)
        self.assertEqual(status, 202)
        await self.wait_for_result("svc", expect="updated")

    async def test_busy_service_records_busy_and_skips_update(self):
        self.add_service()
        with self.app.service_lock("svc"):
            status, _ = await self.post("/webhook/svc", self.push_body(), secret="s3cret-" + "a" * 24)
            self.assertEqual(status, 202)
            ev = await self.wait_for_result(expect="busy")
        self.assertIn("busy", ev["message"])
        self.assertNotIn("git pull", self.env.calls())

    async def test_failed_update_is_recorded_as_failed(self):
        self.add_service()
        self.setenv("FAKE_GIT_FAIL")
        status, _ = await self.post("/webhook/svc", self.push_body(), secret="s3cret-" + "a" * 24)
        self.assertEqual(status, 202)
        await self.wait_for_result(expect="failed")

    # ---- finding 5 ----------------------------------------------------------
    async def test_oversize_declared_body_is_413(self):
        self.add_service()
        head = (b"POST /webhook/svc HTTP/1.1\r\nHost: x\r\nX-GitHub-Event: push\r\n"
                + f"Content-Length: {self.app.WEBHOOK_MAX_BODY + 1}\r\n\r\n".encode())
        status, _ = await self.raw(head)
        self.assertEqual(status, 413)

    async def test_oversize_real_body_is_413(self):
        self.add_service()
        body = b"x" * (2 * 1024 * 1024)
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(b"POST /webhook/svc HTTP/1.1\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n")
        try:
            writer.write(body)
            await writer.drain()
        except ConnectionError:
            pass
        resp = await asyncio.wait_for(reader.read(1024), 5)
        writer.close()
        self.assertIn(b" 413 ", resp.split(b"\r\n")[0])

    async def test_body_exactly_at_the_cap_is_accepted_for_reading(self):
        self.add_service()
        body = b"x" * self.app.WEBHOOK_MAX_BODY                       # not JSON, but within the cap
        status, _ = await self.post("/webhook/svc", body, secret="s3cret-" + "a" * 24)
        self.assertEqual(status, 400)                                  # authenticated, then invalid JSON

    async def test_bad_content_length_values_are_400(self):
        self.add_service()
        for bad in ("-1", "abc", "1.5", "+5", "", "0x10", "99999999999999999999"):
            head = f"POST /webhook/svc HTTP/1.1\r\nContent-Length: {bad}\r\n\r\n".encode()
            status, _ = await self.raw(head)
            self.assertIn(status, (400, 413), f"Content-Length {bad!r} -> {status}")
        status, _ = await self.raw(b"POST /webhook/svc HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx")
        self.assertEqual(status, 400)

    async def test_chunked_encoding_is_refused(self):
        self.add_service()
        status, _ = await self.raw(b"POST /webhook/svc HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        self.assertEqual(status, 411)

    async def test_slow_request_times_out(self):
        self.add_service()
        with mock.patch.object(self.app, "WEBHOOK_READ_TIMEOUT", 0.3):
            status, _ = await self.raw(b"POST /webhook/svc HTTP/1.1\r\nContent-Length: 50\r\n\r\nshort", read_timeout=3)
        self.assertEqual(status, 408)

    async def test_truncated_body_is_400(self):
        self.add_service()
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(b"POST /webhook/svc HTTP/1.1\r\nContent-Length: 50\r\n\r\nshort")
        await writer.drain()
        writer.write_eof()
        resp = await asyncio.wait_for(reader.read(1024), 3)
        writer.close()
        self.assertIn(b" 400 ", resp.split(b"\r\n")[0])

    async def test_invalid_service_names_in_url_are_rejected_before_use(self):
        self.add_service()
        records = []

        class Collect(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())
        handler = Collect(level=logging.DEBUG)
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)
        bad_names = ["a%20b", "../etc", "x" * 65, "a;b", "na$me", "a.b", "%0a%0dINJECT", "\x1b[31mred", "a%0a"]
        for n in bad_names:
            status, _ = await self.post(f"/webhook/{n}", b"{}", secret="x")
            self.assertEqual(status, 404, n)
        status, _ = await self.post("/webhook/svc/extra/segments", b"{}", secret="x")
        self.assertEqual(status, 404)
        self.assertEqual(self.app.db.query("SELECT COUNT(*) c FROM webhook_events", fetch_one=True)["c"], 0)
        self.assertTrue(records)
        for line in records:                                   # nothing raw/unsafe reaches the log
            self.assertNotRegex(line, r"[\x00-\x1f\x7f]")
        self.assertEqual(self.env.calls().strip(), "")         # and no service was touched

    async def test_non_post_and_garbage_requests(self):
        self.add_service()
        status, _ = await self.post("/webhook/svc", b"", method="GET")
        self.assertEqual(status, 405)
        status, _ = await self.raw(b"NONSENSE\r\n\r\n")
        self.assertEqual(status, 400)
        status, _ = await self.raw(b"POST /" + b"a" * 100000 + b" HTTP/1.1\r\n\r\n")
        self.assertIn(status, (400, 431))

    async def test_control_characters_in_headers_are_sanitised_everywhere(self):
        self.add_service()
        evil = "push\x07\x1b[31m-fake"
        status, _ = await self.post("/webhook/svc", self.push_body(), secret="s3cret-" + "a" * 24, event=evil)
        self.assertEqual(status, 200)                     # unknown event type -> ignored_event
        ev = self.app.list_webhook_events("svc", 1)[0]
        self.assertNotRegex(ev["event"], r"[\x00-\x1f\x7f]")
        audit = slurp(self.app.AUDIT_FILE)
        self.assertNotIn("\x1b", audit)
        self.assertNotIn("\x07", audit)

    # ---- helpers / plumbing -------------------------------------------------
    def test_default_bind_is_loopback_and_overridable(self):
        os.environ.pop("ATS_WEBHOOK_BIND", None)
        self.assertEqual(self.app.webhook_bind_address(), "127.0.0.1")
        self.setenv("ATS_WEBHOOK_BIND", "10.1.2.3")
        self.assertEqual(self.app.webhook_bind_address(), "10.1.2.3")
        src = inspect.getsource(self.app.start_webhook_server)
        self.assertNotIn("0.0.0.0", src)

    def test_sanitize_for_log(self):
        s = self.app.sanitize_for_log
        self.assertEqual(s("a\nb\r\x00c\x1b[0m"), "a b  c [0m")
        self.assertEqual(len(s("x" * 1000, 50)), 53)
        self.assertEqual(s(None), "")

    def test_verify_signature_unit(self):
        v = self.app.verify_webhook_signature
        good = sign("k", b"body")
        self.assertTrue(v("k", b"body", good))
        self.assertFalse(v("k", b"body2", good))
        self.assertFalse(v("", b"body", good))
        self.assertFalse(v("k", b"body", None))
        self.assertFalse(v("k", b"body", good.replace("sha256=", "sha1=")))

    def test_event_retention_keeps_last_200_per_service(self):
        self.add_service(name="svc")
        self.add_service(name="other", port=18002)
        for i in range(230):
            self.app.record_webhook_event("svc", "push", "refs/heads/main", None, "accepted", f"m{i}")
        self.app.record_webhook_event("other", "push", None, None, "accepted", "x")
        n = self.app.db.query("SELECT COUNT(*) c FROM webhook_events WHERE service_name='svc'", fetch_one=True)["c"]
        self.assertEqual(n, 200)
        newest = self.app.list_webhook_events("svc", 1)[0]
        self.assertEqual(newest["message"], "m229")
        self.assertEqual(self.app.db.query(
            "SELECT COUNT(*) c FROM webhook_events WHERE service_name='other'", fetch_one=True)["c"], 1)

    def test_rotate_secret_and_auto_update_helpers(self):
        self.add_service()
        old = self.app.get_webhook_info("svc")["secret"]
        new = self.app.rotate_webhook_secret("svc")
        self.assertNotEqual(old, new)
        self.assertRegex(new, r"^[0-9a-f]{64}$")
        self.assertEqual(self.app.get_webhook_info("svc")["secret"], new)
        self.app.set_auto_update("svc", False)
        self.assertFalse(self.app.get_webhook_info("svc")["auto_update"])
        with self.assertRaises(ValueError):
            self.app.rotate_webhook_secret("missing")
        self.assertNotIn(new, slurp(self.app.AUDIT_FILE))          # secrets never audited

    def test_webhook_menu_shows_url_and_secret_and_rotates(self):
        self.add_service(secret="Z" * 40)
        self.fake_input(["1", "yes", "", "0"])
        out = io.StringIO()
        with redirect_stdout(out):
            self.app.manage_webhook_menu("svc")
        text = out.getvalue()
        self.assertIn("https://webhook.example.com/webhook/svc", text)
        self.assertIn("Z" * 40, text)
        self.assertNotEqual(self.app.get_webhook_info("svc")["secret"], "Z" * 40)


class SchemaMigrationTests(unittest.TestCase):
    """services.container_port/auto_update/webhook_secret + webhook_events (spec 2.6/2.7)."""

    @classmethod
    def setUpClass(cls):
        cls.env = harness.load_app()

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def test_old_database_is_migrated_idempotently_and_secrets_backfilled(self):
        import sqlite3
        path = os.path.join(self.env.root, "old.db")
        conn = sqlite3.connect(path)
        conn.execute("""CREATE TABLE services (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
            port INTEGER UNIQUE NOT NULL, domain TEXT UNIQUE NOT NULL, storage_path TEXT NOT NULL,
            repo_url TEXT NOT NULL, workers INTEGER DEFAULT 4, max_memory_mb INTEGER DEFAULT 512,
            cpu_quota INTEGER DEFAULT 50, status TEXT DEFAULT 'active', health_check_failures INTEGER DEFAULT 0,
            last_health_check TIMESTAMP, deployment_hash TEXT, runtime TEXT DEFAULT 'python',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        conn.execute("INSERT INTO services (name, port, domain, storage_path, repo_url) VALUES ('a',1,'a.x.com','/o','r')")
        conn.execute("INSERT INTO services (name, port, domain, storage_path, repo_url) VALUES ('b',2,'b.x.com','/o','r')")
        conn.commit()
        conn.close()

        app = self.env.app
        app.DatabaseManager(path)
        conn = sqlite3.connect(path)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(services)")}
        self.assertTrue({"branch", "container_port", "auto_update", "webhook_secret"} <= cols)
        rows = conn.execute("SELECT name, auto_update, webhook_secret, branch FROM services ORDER BY name").fetchall()
        secrets_seen = set()
        for name, auto, secret, branch in rows:
            self.assertEqual(auto, 1)
            self.assertRegex(secret, r"^[0-9a-f]{64}$")
            self.assertEqual(branch, "main")
            secrets_seen.add(secret)
        self.assertEqual(len(secrets_seen), 2)                         # distinct per service
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("webhook_events", tables)
        ev_cols = [r[1] for r in conn.execute("PRAGMA table_info(webhook_events)")]
        self.assertEqual(ev_cols, ["id", "service_name", "timestamp", "event", "ref", "commit_sha", "result", "message"])
        conn.close()

        app.DatabaseManager(path)                                       # second run: no change, no error
        conn = sqlite3.connect(path)
        again = {n: s for n, s in conn.execute("SELECT name, webhook_secret FROM services")}
        self.assertEqual(set(again.values()), secrets_seen)
        conn.close()


# ==============================================================================
#  Finding 2 + 3: backup encryption
# ==============================================================================

class BackupEncryptionTests(AppTestCase):

    def setUp(self):
        super().setUp()
        self.svc = self.add_service()
        with open(os.path.join(self.env.storage, "database", "svc", "data.db"), "wb") as f:
            f.write(b"database-bytes")
        if os.path.exists(self.app.ENCRYPTION_KEY_FILE):
            os.remove(self.app.ENCRYPTION_KEY_FILE)
        self.mkdtemps = []
        real = tempfile.mkdtemp

        def spy(*a, **k):
            d = real(*a, **k)
            self.mkdtemps.append(d)
            return d
        p = mock.patch.object(self.app.tempfile, "mkdtemp", spy)
        p.start()
        self.addCleanup(p.stop)

    def remote_files(self):
        root = os.path.join(self.env.state, "remote")
        found = []
        for d, _, files in os.walk(root):
            found.extend(os.path.join(d, f) for f in files)
        return found

    def assert_nothing_uploaded(self):
        self.assertEqual(self.remote_files(), [])
        for line in self.env.argv_log("rclone").splitlines():
            self.assertFalse(line.startswith("copy "), f"rclone upload attempted: {line}")

    def test_successful_backup_uploads_only_the_encrypted_file(self):
        ok, summary = self.app.backup_gdrive_now()
        self.assertTrue(ok, summary)
        files = self.remote_files()
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].endswith(".zip.enc"))
        self.assertTrue(slurp(files[0], "rb").startswith(b"ENCRYPTED:"))
        for d in self.mkdtemps:                                          # scratch dir is gone
            self.assertFalse(os.path.exists(d))

    def test_encryption_failure_fails_the_backup_and_never_uploads_plaintext(self):
        self.setenv("FAKE_OPENSSL_ENC_FAIL")
        ok, summary = self.app.backup_gdrive_now()
        self.assertFalse(ok)
        self.assertIn("failed", summary.lower())
        self.assert_nothing_uploaded()
        calls = self.env.calls().splitlines()
        self.assertEqual([c for c in calls if c.startswith("systemctl") and " svc" in c],
                         ["systemctl stop svc", "systemctl start svc"])  # service is back up
        for d in self.mkdtemps:
            self.assertFalse(os.path.exists(d))                          # plaintext zip removed
        self.assertIn("refusing to upload", slurp(self.app.BACKUP_LOG))

    def test_key_generation_failure_fails_the_backup_and_never_uploads(self):
        self.setenv("FAKE_OPENSSL_RAND_FAIL")
        self.assertIsNone(self.app._get_or_create_key())
        self.assertFalse(os.path.exists(self.app.ENCRYPTION_KEY_FILE))
        ok, _ = self.app.backup_gdrive_now()
        self.assertFalse(ok)
        self.assert_nothing_uploaded()

    def test_empty_key_output_is_refused(self):
        self.setenv("FAKE_OPENSSL_RAND_EMPTY")
        self.assertIsNone(self.app._get_or_create_key())
        self.assertFalse(os.path.exists(self.app.ENCRYPTION_KEY_FILE))
        self.assertFalse(self.app._encrypt_file(__file__, os.path.join(self.env.root, "out.enc")))
        ok, _ = self.app.backup_gdrive_now()
        self.assertFalse(ok)
        self.assert_nothing_uploaded()

    def test_empty_key_file_is_replaced_not_used(self):
        spit(self.app.ENCRYPTION_KEY_FILE, "")
        key = self.app._get_or_create_key()
        self.assertRegex(key, r"^[0-9a-f]{64}$")
        self.assertEqual(slurp(self.app.ENCRYPTION_KEY_FILE), key)

    def test_encrypt_requires_a_nonempty_output_file(self):
        # openssl "succeeds" (rc 0) but leaves an empty file -> must not count as encrypted
        fake = os.path.join(self.env.bin, "openssl")
        original = slurp(fake)
        self.addCleanup(spit, fake, original)
        with open(fake, "w") as f:
            f.write("#!/bin/sh\nif [ \"$1\" = rand ]; then echo " + "ab" * 32 + "; exit 0; fi\n"
                    "out=''; while [ $# -gt 0 ]; do [ \"$1\" = -out ] && out=$2; shift; done; : > \"$out\"; exit 0\n")
        out = os.path.join(self.env.root, "empty.enc")
        self.assertFalse(self.app._encrypt_file(__file__, out))
        self.assertFalse(os.path.exists(out))

    def test_key_is_passed_via_file_not_on_the_command_line(self):
        ok, _ = self.app.backup_gdrive_now()
        self.assertTrue(ok)
        key = slurp(self.app.ENCRYPTION_KEY_FILE).strip()
        log = self.env.argv_log("openssl")
        enc_lines = [l for l in log.splitlines() if l.startswith("enc")]
        self.assertTrue(enc_lines)
        for line in enc_lines:
            self.assertIn(f"-pass file:{self.app.ENCRYPTION_KEY_FILE}", line)
            self.assertNotIn("pass:", line.replace("file:", ""))
            self.assertNotIn(key, line)
        self.assertNotIn(key, log)
        # decrypt path too
        enc = os.path.join(self.env.root, "x.enc")
        dec = os.path.join(self.env.root, "x.dec")
        with open(os.path.join(self.env.root, "x"), "wb") as f:
            f.write(b"hello")
        self.assertTrue(self.app._encrypt_file(os.path.join(self.env.root, "x"), enc))
        self.assertTrue(self.app._decrypt_file(enc, dec))
        self.assertEqual(slurp(dec, "rb"), b"hello")
        self.assertNotIn(key, self.env.argv_log("openssl"))

    def test_key_file_is_created_atomically_with_0600(self):
        real_open = os.open
        seen = []

        def spy(path, flags, mode=0o777, *a, **k):
            if path == self.app.ENCRYPTION_KEY_FILE:
                seen.append((flags, mode))
            return real_open(path, flags, mode, *a, **k)
        with mock.patch.object(self.app.os, "open", spy):
            key = self.app._get_or_create_key()
        self.assertTrue(key)
        self.assertEqual(len(seen), 1)
        flags, mode = seen[0]
        self.assertTrue(flags & os.O_EXCL and flags & os.O_CREAT and flags & os.O_WRONLY)
        self.assertEqual(mode, 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.app.ENCRYPTION_KEY_FILE).st_mode), 0o600)

    def test_decrypt_never_creates_a_key(self):
        self.assertFalse(self.app._decrypt_file(__file__, os.path.join(self.env.root, "o")))
        self.assertFalse(os.path.exists(self.app.ENCRYPTION_KEY_FILE))


# ==============================================================================
#  Finding 4: per-service lock
# ==============================================================================

class ServiceLockTests(AppTestCase):

    def holder_process(self, name):
        os.makedirs(self.app.LOCKS_DIR, exist_ok=True)
        code = ("import fcntl, os, sys, time\n"
                "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\n"
                "fcntl.flock(fd, fcntl.LOCK_EX)\nprint('locked', flush=True)\ntime.sleep(60)\n")
        proc = subprocess.Popen([sys.executable, "-c", code, os.path.join(self.app.LOCKS_DIR, f"{name}.lock")],
                                stdout=subprocess.PIPE, text=True)
        def reap():
            proc.kill()
            proc.wait()
            proc.stdout.close()
        self.addCleanup(reap)
        self.assertEqual(proc.stdout.readline().strip(), "locked")
        return proc

    def test_lock_file_location_and_in_process_exclusion(self):
        with self.app.service_lock("svc"):
            self.assertTrue(os.path.exists(os.path.join(self.app.ATS_HOME, "locks", "svc.lock")))
            with self.assertRaises(self.app.ServiceBusyError):
                with self.app.service_lock("svc"):
                    pass
            with self.app.service_lock("another"):        # different services do not contend
                pass
        with self.app.service_lock("svc"):                  # released afterwards
            pass

    def test_lock_is_per_process_via_flock(self):
        self.add_service()
        proc = self.holder_process("svc")
        with self.assertRaises(self.app.ServiceBusyError):
            self.app.service_git_update("svc", self.app.get_service_by_name("svc"), lambda *a: None)
        self.assertNotIn("git pull", self.env.calls())
        proc.kill()
        proc.wait()
        res = self.app.service_git_update("svc", self.app.get_service_by_name("svc"), lambda *a: None)
        self.assertTrue(res["updated"])

    def test_every_mutating_operation_reports_busy(self):
        svc = self.add_service()
        ops = [
            lambda: self.app.service_restart("svc", svc, lambda *a: None),
            lambda: self.app.service_stop("svc", svc, lambda *a: None),
            lambda: self.app.service_start("svc", svc, lambda *a: None),
            lambda: self.app.service_git_update("svc", svc, lambda *a: None),
            lambda: self.app.service_reinstall_deps("svc", svc, lambda *a: None),
            lambda: self.app.service_update_config("svc", svc, cpu_quota=60, log=lambda *a: None),
            lambda: self.app.service_redeploy("svc", svc, "https://github.com/o/x.git", "main", lambda *a: None),
        ]
        proc = self.holder_process("svc")
        for op in ops:
            with self.assertRaises(self.app.ServiceBusyError):
                op()
        self.assertEqual(self.env.calls().strip(), "")        # nothing ran
        proc.kill()

    def test_concurrent_updates_exactly_one_wins(self):
        svc = self.add_service()
        self.setenv("FAKE_GIT_SLEEP", "1")
        outcomes = []

        def run():
            try:
                outcomes.append(self.app.service_git_update("svc", svc, lambda *a: None)["message"])
            except self.app.ServiceBusyError:
                outcomes.append("busy")
        a = threading.Thread(target=run)
        a.start()
        REAL_SLEEP(0.4)
        b = threading.Thread(target=run)
        b.start()
        a.join()
        b.join()
        self.assertEqual(sorted(outcomes), ["Service restarted with new code", "busy"])
        self.assertEqual(self.env.calls().count("git pull"), 1)

    def test_cli_wrapper_prints_a_clear_busy_message(self):
        svc = self.add_service()
        self.fake_input([""])
        out = io.StringIO()
        with self.app.service_lock("svc"), redirect_stdout(out):
            asyncio.run(self.app.direct_update("svc", svc))
        self.assertIn("busy", out.getvalue())
        self.assertNotIn("git pull", self.env.calls())

    def test_async_guard_is_safe_across_tasks(self):
        svc = self.add_service()
        self.setenv("FAKE_GIT_SLEEP", "1")

        async def go():
            return await asyncio.gather(self.app._do_git_update("svc", svc), self.app._do_git_update("svc", svc))
        results = asyncio.run(go())
        self.assertEqual(sorted(results), [False, True])

    def test_deploy_takes_the_lock_too(self):
        os.environ.pop("FAKE_X", None)
        self.fake_input(["busyname", "", "", "", ""])
        out = io.StringIO()
        with self.app.service_lock("busyname"), redirect_stdout(out):
            asyncio.run(self.app.deploy_service_async())
        self.assertIn("busy", out.getvalue())
        self.assertIsNone(self.app.db.query("SELECT 1 FROM services WHERE name='busyname'", fetch_one=True))


# ==============================================================================
#  Finding 6: restore temp dir + safe extraction
# ==============================================================================

def make_zip(path, members):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members:
            if isinstance(data, zipfile.ZipInfo):
                zf.writestr(data, "target")
            else:
                zf.writestr(name, data)


class RestoreTests(AppTestCase):

    def setUp(self):
        super().setUp()
        self.svc = self.add_service()
        self.db_dir = os.path.join(self.env.storage, "database", "svc")
        with open(os.path.join(self.db_dir, "data.db"), "wb") as f:
            f.write(b"old")

    # ---- safe extraction -----------------------------------------------------
    def test_safe_extract_accepts_normal_archives(self):
        z = os.path.join(self.env.root, "ok.zip")
        make_zip(z, [("data.db", b"new"), ("sub/dir/file.txt", b"x")])
        dest = os.path.join(self.env.root, "dest")
        self.assertEqual(self.app._safe_extract_zip(z, dest), 2)
        self.assertEqual(slurp(os.path.join(dest, "data.db"), "rb"), b"new")
        self.assertEqual(slurp(os.path.join(dest, "sub/dir/file.txt"), "rb"), b"x")

    def test_safe_extract_rejects_absolute_paths_dotdot_and_symlinks(self):
        dest = os.path.join(self.env.root, "dest2")
        outside = os.path.join(self.env.root, "pwned")
        link = zipfile.ZipInfo("link")
        link.external_attr = (0o120777 << 16)
        escape_via_link = [("link", link), ("link/inner.txt", b"x")]
        cases = {
            "absolute": [("/etc/ats-evil", b"x")],
            "dotdot": [("../pwned", b"x")],
            "nested dotdot": [("a/../../pwned", b"x")],
            "backslash dotdot": [("..\\pwned", b"x")],
            "symlink": escape_via_link,
        }
        for label, members in cases.items():
            z = os.path.join(self.env.root, "bad.zip")
            make_zip(z, members)
            with self.assertRaises(ValueError, msg=label):
                self.app._safe_extract_zip(z, dest)
            self.assertFalse(os.path.exists(outside), label)
            self.assertFalse(os.path.exists("/etc/ats-evil"), label)
        self.assertFalse(os.path.exists(os.path.join(dest, "a")))             # validated before extracting anything

    def test_safe_extract_refuses_to_write_through_existing_symlink(self):
        dest = os.path.join(self.env.root, "dest3")
        os.makedirs(dest)
        target = os.path.join(self.env.root, "victim")
        os.symlink(target, os.path.join(dest, "data.db"))
        z = os.path.join(self.env.root, "ok2.zip")
        make_zip(z, [("data.db", b"new")])
        with self.assertRaises(ValueError):
            self.app._safe_extract_zip(z, dest)
        self.assertFalse(os.path.exists(target))

    # ---- restore flow --------------------------------------------------------
    def put_remote_backup(self, members, name="svc-20250101_000000.zip.enc"):
        plain = os.path.join(self.env.root, "plain.zip")
        make_zip(plain, members)
        remote_dir = os.path.join(self.env.state, "remote", "backups", "svc")
        os.makedirs(remote_dir, exist_ok=True)
        with open(os.path.join(remote_dir, name), "wb") as f:
            f.write(b"ENCRYPTED:" + slurp(plain, "rb"))
        return name

    def run_drive_restore(self, answers):
        self.app._get_or_create_key()
        self.fake_input([str(self.svc["id"])] + answers)
        out = io.StringIO()
        with redirect_stdout(out):
            asyncio.run(self.app.restore_from_drive())
        return out.getvalue()

    def rclone_download_dest(self):
        for line in self.env.argv_log("rclone").splitlines():
            parts = line.split()
            if parts[0] == "copy" and parts[1].startswith("gdrive:"):
                return parts[2]
        self.fail("no rclone download seen")

    def test_drive_restore_uses_private_mkdtemp_and_cleans_up(self):
        self.put_remote_backup([("data.db", b"restored")])
        modes = []
        real = tempfile.mkdtemp

        def spy(*a, **k):
            d = real(*a, **k)
            modes.append((d, k.get("prefix"), stat.S_IMODE(os.stat(d).st_mode)))
            return d
        with mock.patch.object(self.app.tempfile, "mkdtemp", spy):
            out = self.run_drive_restore(["1", "RESTORE"])
        self.assertIn("Restore successful", out)
        self.assertEqual(slurp(os.path.join(self.db_dir, "data.db"), "rb"), b"restored")
        self.assertTrue([d for d in os.listdir(os.path.dirname(self.db_dir)) if d.startswith("svc_pre_restore_")])
        self.assertEqual(len(modes), 1)
        d, prefix, mode = modes[0]
        self.assertEqual(prefix, "ats-restore-")
        self.assertEqual(mode, 0o700)
        dest = self.rclone_download_dest()
        self.assertEqual(dest, d)
        self.assertNotEqual(dest, "/tmp")
        self.assertFalse(os.path.exists(dest))                              # removed in finally
        self.assertNotIn("/tmp/svc-", self.env.argv_log("rclone"))

    def test_drive_restore_cleans_up_when_restore_fails_and_rolls_back(self):
        self.put_remote_backup([("../evil", b"x"), ("data.db", b"restored")])
        out = self.run_drive_restore(["1", "RESTORE"])
        self.assertIn("Restore failed", out)
        self.assertEqual(slurp(os.path.join(self.db_dir, "data.db"), "rb"), b"old")   # untouched
        self.assertFalse(os.path.exists(self.rclone_download_dest()))
        self.assertFalse(os.path.exists(os.path.join(self.env.storage, "database", "evil")))
        self.assertNotIn("systemctl stop svc", self.env.calls())             # rejected before stopping

    def test_drive_restore_cleans_up_on_decrypt_failure(self):
        remote_dir = os.path.join(self.env.state, "remote", "backups", "svc")
        os.makedirs(remote_dir)
        with open(os.path.join(remote_dir, "svc-1.zip.enc"), "wb") as f:
            f.write(b"not encrypted at all")
        out = self.run_drive_restore(["1"])
        self.assertIn("Decryption failed", out)
        self.assertFalse(os.path.exists(self.rclone_download_dest()))

    def test_unsafe_remote_file_names_are_not_offered(self):
        self.put_remote_backup([("data.db", b"restored")])
        self.setenv("FAKE_RCLONE_LSF_EXTRA", "../evil.zip,/abs/evil.zip,sub/")
        out = self.run_drive_restore(["0"])
        self.assertIn("svc-20250101_000000.zip.enc", out)
        self.assertNotIn("evil", out)

    def test_local_restore_validates_archive_before_touching_service(self):
        z = os.path.join(self.env.root, "local.zip")
        make_zip(z, [("/abs", b"x")])
        self.fake_input(["RESTORE"])
        out = io.StringIO()
        with redirect_stdout(out):
            asyncio.run(self.app._do_restore(self.svc, z, "local.zip"))
        self.assertIn("Restore failed", out.getvalue())
        self.assertNotIn("systemctl stop svc", self.env.calls())
        self.assertEqual(slurp(os.path.join(self.db_dir, "data.db"), "rb"), b"old")

    def test_restore_reports_busy_without_touching_anything(self):
        z = os.path.join(self.env.root, "local2.zip")
        make_zip(z, [("data.db", b"new")])
        self.fake_input(["RESTORE"])
        out = io.StringIO()
        with self.app.service_lock("svc"), redirect_stdout(out):
            asyncio.run(self.app._do_restore(self.svc, z, "local2.zip"))
        self.assertIn("busy", out.getvalue())
        self.assertEqual(slurp(os.path.join(self.db_dir, "data.db"), "rb"), b"old")
        self.assertNotIn("systemctl", self.env.calls())

    def test_no_predictable_tmp_paths_remain(self):
        src = inspect.getsource(self.app)
        self.assertNotRegex(src, r'os\.path\.join\("/tmp"')
        self.assertNotIn('"/tmp",', src.replace('# Private scratch dir', ''))


# ==============================================================================
#  Finding 7: validation + SQL
# ==============================================================================

class ValidationTests(AppTestCase):

    def test_git_url(self):
        v = self.app.validate_git_url
        self.assertEqual(v("https://github.com/o/r.git"), "https://github.com/o/r.git")
        self.assertEqual(v("https://tok@github.com/o/r.git"), "https://tok@github.com/o/r.git")
        self.assertEqual(v("git@github.com:o/r.git"), "git@github.com:o/r.git")
        for bad in ["http://github.com/o/r.git", "ftp://x/y", "", "https://", "git@nocolon", "ext::sh -c id",
                    "https://github.com/o/r .git", "https://github.com/o/r.git\n", "https://x/\x00y",
                    "https://x/y\tz", "-https://x", "file:///etc/passwd", "https://" + "a" * 3000]:
            with self.assertRaises(ValueError, msg=repr(bad)):
                v(bad)

    def test_domain_format(self):
        v = self.app.validate_domain
        self.assertEqual(v("Api.Example.COM"), "api.example.com")
        self.assertEqual(v("a-b.c-d.example.org"), "a-b.c-d.example.org")
        for bad in ["a..b.com", ".a.com", "a.com.", "-a.com", "a-.com", "a.-b.com", "a.b-.com", "x" * 64 + ".com",
                    ".".join(["a" * 60] * 5) + ".com", "nodots", "a.c", "a.c0m", "a b.com", "a_b.com", "",
                    "a.com\n", "ünï.com", "a.123"]:
            with self.assertRaises(ValueError, msg=repr(bad)):
                v(bad)
        ok_63 = "a" * 63 + ".com"
        self.assertEqual(v(ok_63), ok_63)
        ok_253 = ".".join(["a" * 61] * 4 + ["com"])
        self.assertLessEqual(len(ok_253), 253)
        self.assertEqual(v(ok_253), ok_253)

    def test_domain_uniqueness_is_checked_after_lowercasing(self):
        self.add_service(name="svc", domain="taken.example.com")
        for variant in ("taken.example.com", "TAKEN.example.com", "Taken.Example.Com"):
            with self.assertRaises(ValueError, msg=variant):
                self.app.validate_domain(variant)
        self.assertEqual(self.app.validate_domain("TAKEN.example.com", exclude_name="svc"), "taken.example.com")

    def test_storage_blocks_sub_paths_and_symlinks(self):
        blocked = self.app._storage_path_blocked
        for p in ["/", "/bin", "/boot", "/dev", "/etc", "/etc/ssl", "/lib", "/lib64", "/lib64/x", "/lib32/a",
                  "/proc", "/proc/1", "/root", "/root/.ssh", "/run", "/run/user", "/sbin", "/sys", "/sys/fs",
                  "/usr", "/usr/local/bin", "/var", "/var/log", "/var/lib/dpkg", "/var/lib", "/var/www2/x",
                  "/var/libx", "/var/lib/atsx/../x"]:
            self.assertTrue(blocked(os.path.normpath(p)) if ".." in p else blocked(p), p)
        for p in ["/var/www", "/var/www/site", "/var/lib/ats", "/var/lib/ats-prod/data", "/var/lib/atsfoo",
                  "/opt", "/opt/apps", "/srv", "/data", "/home/gaia", "/tmp/x", "/mnt/disk"]:
            self.assertFalse(blocked(p), p)
        with self.assertRaises(ValueError) as cm:
            self.app.validate_storage("/etc")
        self.assertIn("Restricted", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            self.app.validate_storage("/etc/ssl")
        self.assertIn("Restricted", str(cm.exception))
        with self.assertRaises(ValueError):
            self.app.validate_storage("/usr/bin")
        # symlink pointing into a blocked tree is resolved first
        link = os.path.join(self.env.root, "sneaky")
        os.symlink("/etc", link)
        with self.assertRaises(ValueError) as cm:
            self.app.validate_storage(link)
        self.assertIn("Restricted", str(cm.exception))
        link2 = os.path.join(self.env.root, "sneaky2")
        os.symlink("/usr/share", link2)
        with self.assertRaises(ValueError):
            self.app.validate_storage(link2 + "/")
        ok = os.path.join(self.env.root, "fine")
        os.makedirs(ok)
        self.assertEqual(self.app.validate_storage(ok), os.path.realpath(ok))
        with self.assertRaises(ValueError):
            self.app.validate_storage(os.path.join(self.env.root, "missing"))

    def test_range_validators(self):
        a = self.app
        self.assertEqual(a.validate_workers("1"), 1)
        self.assertEqual(a.validate_workers(" 32 "), 32)
        self.assertEqual(a.validate_memory("64"), 64)
        self.assertEqual(a.validate_memory(65536), 65536)
        self.assertEqual(a.validate_cpu("5"), 5)
        self.assertEqual(a.validate_cpu("800"), 800)
        bad = {
            a.validate_workers: ["0", "33", "-1", "abc", "1.5", "", None, True, "1e3", "٣"],
            a.validate_memory: ["63", "65537", "-512", "x", "512MB", None, False],
            a.validate_cpu: ["4", "801", "0", "-50", "fifty", "50%", None],
        }
        for fn, values in bad.items():
            for v in values:
                with self.assertRaises(ValueError, msg=f"{fn.__name__}({v!r})"):
                    fn(v)

    def test_update_config_rejects_out_of_range_before_changing_anything(self):
        svc = self.add_service()
        before = self.unit_text()
        for kwargs in ({"cpu_quota": "9999"}, {"max_memory_mb": "1"}, {"workers": "0"}, {"workers": "abc"},
                       {"domain": "a..b.com"}, {"port": "80"}, {"port": "abc"}):
            with self.assertRaises(ValueError, msg=str(kwargs)):
                self.app.service_update_config("svc", svc, log=lambda *a: None, **kwargs)
        self.assertEqual(self.unit_text(), before)
        self.assertEqual(self.env.calls().strip(), "")
        row = self.app.db.query("SELECT cpu_quota, max_memory_mb FROM services WHERE name='svc'", fetch_one=True)
        self.assertEqual((row["cpu_quota"], row["max_memory_mb"]), (50, 256))

    def test_deploy_rejects_out_of_range_resources(self):
        for answers in (
            ["bad1", "", "1", "bad1", "18301", "https://github.com/o/r.git", "main", "2", "99"],
            ["bad2", "", "1", "bad2", "18302", "https://github.com/o/r.git", "main", "2", "", "10"],
            ["bad3", "", "1", "bad3", "18303", "https://github.com/o/r.git", "main", "2", "", "", "1"],
            ["bad4", "", "1", "bad4", "18304", "http://github.com/o/r.git"],
            ["bad5", "", "1", "bad5", "18305", "https://github.com/o/r.git", "--upload-pack=evil"],
        ):
            self.fake_input(answers)
            out = io.StringIO()
            with redirect_stdout(out):
                asyncio.run(self.app.deploy_service_async())
            self.assertIn("DEPLOYMENT FAILED", out.getvalue(), answers)
            self.assertIsNone(self.app.db.query(f"SELECT 1 FROM services WHERE name='{answers[0]}'", fetch_one=True))
        self.assertNotIn("git clone", self.env.calls())

    def test_service_name_validation(self):
        v = self.app.validate_service_name
        self.assertEqual(v("my-service_1"), "my-service_1")
        for bad in ["", "a b", "a/b", "../x", "x" * 65, "a;b", "é", "a\n"]:
            with self.assertRaises(ValueError, msg=repr(bad)):
                v(bad)

    def test_branch_validation(self):
        v = self.app.validate_branch
        for ok in ["main", "feature/x-1", "release_1.2"]:
            self.assertEqual(v(ok), ok)
        for bad in ["", "-x", "--upload-pack=evil", "a b", "a..b", "a;b", "x" * 101]:
            with self.assertRaises(ValueError, msg=bad):
                v(bad)

    def test_sql_is_parameterised_or_allow_listed(self):
        with self.assertRaises(ValueError):
            self.app.table_row_count("services; DROP TABLE services")
        with self.assertRaises(ValueError):
            self.app.table_row_count("sqlite_master")
        self.assertEqual(self.app.table_row_count("services"), 0)
        src = slurp(harness.APP_PY)
        for no, line in enumerate(src.splitlines(), 1):
            if re.search(r'\bf"[^"]*\b(SELECT .* FROM|INSERT INTO|UPDATE \w+ SET|DELETE FROM|DROP TABLE|PRAGMA )', line) and "{" in line:
                self.assertIn("allow-listed identifier", line, f"f-string SQL at line {no}: {line.strip()}")
        self.assertNotIn("'-{days} days'", src)

    def test_cleanup_query_binds_days(self):
        self.add_service()
        self.app.db.query("INSERT INTO backups (service_name, filename, size_bytes, checksum, timestamp) "
                          "VALUES ('svc', 'old.zip', 1, 'x', datetime('now', '-30 days'))")
        self.app.db.query("INSERT INTO backups (service_name, filename, size_bytes, checksum) "
                          "VALUES ('svc', 'new.zip', 1, 'x')")
        rows = self.app.db.query("SELECT filename FROM backups WHERE timestamp < datetime('now', ?)",
                                 ("-7 days",), fetch_all=True)
        self.assertEqual([r["filename"] for r in rows], ["old.zip"])


# ==============================================================================
#  Finding 8: shared operations, thin wrappers, exception hygiene
# ==============================================================================

class SharedOperationTests(AppTestCase):

    def collect(self):
        msgs = []
        return msgs, (lambda m, level="info": msgs.append((level, m)))

    def test_restart_stop_start_return_results_and_use_log_callback(self):
        svc = self.add_service()
        msgs, log = self.collect()
        out = io.StringIO()
        with redirect_stdout(out):
            r = self.app.service_restart("svc", svc, log)
            s = self.app.service_stop("svc", svc, log)
            t = self.app.service_start("svc", svc, log)
        self.assertEqual(out.getvalue(), "")                         # nothing printed when a log callback is given
        self.assertEqual((r["ok"], r["status"]), (True, "active"))
        self.assertEqual(s["status"], "inactive")
        self.assertEqual(t["status"], "active")
        self.assertTrue(any(level == "success" for level, _ in msgs))
        calls = self.env.calls()
        for action in ("restart", "stop", "start"):
            self.assertIn(f"systemctl {action} svc", calls)

    def test_default_log_prints(self):
        svc = self.add_service()
        out = io.StringIO()
        with redirect_stdout(out):
            self.app.service_restart("svc", svc)
        self.assertIn("Service restarted successfully", out.getvalue())

    def test_failures_raise_instead_of_printing(self):
        svc = self.add_service()
        self.setenv("FAKE_SYSTEMCTL_FAIL", "restart")
        with self.assertRaises(self.app.ServiceOpError):
            self.app.service_restart("svc", svc, lambda *a: None)
        del os.environ["FAKE_SYSTEMCTL_FAIL"]
        spit(os.path.join(self.env.state, "active_svc"), "failed")      # restart "works" but unit is down
        with self.assertRaises(self.app.ServiceOpError) as cm:
            self.app.service_restart("svc", svc, lambda *a: None)
        self.assertIn("not active", str(cm.exception))

    def test_git_update_variants(self):
        svc = self.add_service()
        r = self.app.service_git_update("svc", svc, lambda *a: None)
        self.assertEqual((r["ok"], r["updated"]), (True, True))
        self.assertIn("systemctl restart svc", self.env.calls())
        self.setenv("FAKE_GIT_UPTODATE")
        before = self.env.calls().count("restart")
        r = self.app.service_git_update("svc", svc, lambda *a: None)
        self.assertEqual(r["updated"], False)
        self.assertEqual(self.env.calls().count("restart"), before)
        del os.environ["FAKE_GIT_UPTODATE"]
        self.setenv("FAKE_GIT_FAIL")
        with self.assertRaises(self.app.ServiceOpError):
            self.app.service_git_update("svc", svc, lambda *a: None)

    def test_reinstall_deps_node_and_python(self):
        node = self.add_service(name="n1", runtime="node", port=18010)
        with self.assertRaises(self.app.ServiceOpError) as cm:
            self.app.service_reinstall_deps("n1", node, lambda *a: None)
        self.assertEqual(cm.exception.code, "notfound")
        spit(os.path.join(self.env.storage, "api", "n1", "package.json"), "{}")
        r = self.app.service_reinstall_deps("n1", node, lambda *a: None)
        self.assertEqual(r["runtime"], "node")
        self.assertIn("npm install --production", self.env.calls())

        py = self.add_service(name="p1", runtime="python", port=18011)
        d = os.path.join(self.env.storage, "api", "p1")
        spit(os.path.join(d, "requirements.txt"), "flask\n")
        with self.assertRaises(self.app.VenvMissingError) as cm:
            self.app.service_reinstall_deps("p1", py, lambda *a: None)
        self.assertEqual(cm.exception.code, "venv_missing")
        os.makedirs(os.path.join(d, "venv", "bin"))
        pip = os.path.join(d, "venv", "bin", "pip3")
        spit(pip, "#!/bin/sh\necho \"pip $*\" >> \"$FAKE_STATE/calls.log\"\n"
                  "echo 'Successfully installed flask click itsdangerous'\n")
        os.chmod(pip, 0o755)
        r = self.app.service_reinstall_deps("p1", py, lambda *a: None)
        self.assertEqual((r["runtime"], r["rebuilt_venv"], r["packages_installed"]), ("python", False, 3))
        self.assertIn("install -r requirements.txt", self.env.calls())
        self.assertNotIn("systemctl restart p1", self.env.calls())         # restart is the caller's choice

    def test_status_and_resource_usage(self):
        svc = self.add_service()
        self.assertIn("fake unit", self.app.service_systemd_status("svc", svc))
        with mock.patch.object(self.app, "psutil", None):
            with self.assertRaises(self.app.ServiceOpError) as cm:
                self.app.service_resource_usage("svc", svc)
            self.assertEqual(cm.exception.code, "unsupported")

        class Proc:
            def __init__(self, pid): pass
            def cpu_percent(self, interval=0): return 12.5
            def memory_info(self): return mock.Mock(rss=50 * 1024 * 1024)
            def num_threads(self): return 4
            def children(self, recursive=False): return [1, 2]
        fake_psutil = mock.Mock(Process=Proc)
        with mock.patch.object(self.app, "psutil", fake_psutil), \
                mock.patch.object(self.app, "get_service_pid", return_value=None):
            self.assertFalse(self.app.service_resource_usage("svc", svc)["running"])
        with mock.patch.object(self.app, "psutil", fake_psutil), \
                mock.patch.object(self.app, "get_service_pid", return_value=4242):
            u = self.app.service_resource_usage("svc", svc)
        self.assertEqual((u["pid"], u["cpu_percent"], u["memory_mb"], u["threads"], u["children"]),
                         (4242, 12.5, 50.0, 4, 2))

    def test_update_config_resources_domain_and_port(self):
        svc = self.add_service()
        self.app.cloudflare.add_route("svc.example.com", 18001)
        res = self.app.service_update_config("svc", svc, cpu_quota="75", max_memory_mb="1024", workers="3",
                                             log=lambda *a: None)
        self.assertTrue(res["restarted"])
        unit = self.unit_text()
        self.assertIn("CPUQuota=75%", unit)
        self.assertIn("MemoryMax=1024M", unit)
        self.assertIn("MemoryHigh=921M", unit)
        row = res["service"]
        self.assertEqual((row["cpu_quota"], row["max_memory_mb"], row["workers"]), (75, 1024, 3))
        self.assertIn("systemctl restart svc", self.env.calls())

        res = self.app.service_update_config("svc", svc, domain="New.Example.com", log=lambda *a: None)
        self.assertEqual(res["service"]["domain"], "new.example.com")
        cf = slurp(self.env.cf_config)
        self.assertIn("new.example.com", cf)
        self.assertNotIn("svc.example.com", cf)

        new_port = free_port()
        res = self.app.service_update_config("svc", svc, port=str(new_port), log=lambda *a: None)
        self.assertEqual(res["service"]["port"], new_port)
        self.assertIn(f'Environment="PORT={new_port}"', self.unit_text())          # node unit; python uses --bind
        self.assertIn(f"http://localhost:{new_port}", slurp(self.env.cf_config))
        audit = [json.loads(l) for l in slurp(self.app.AUDIT_FILE).splitlines()]
        port_event = [e for e in audit if e["action"] == "CONFIG_PORT"][-1]
        self.assertEqual((port_event["metadata"]["old_port"], port_event["metadata"]["new_port"]), (18001, new_port))

    def test_redeploy_replaces_code_and_updates_db(self):
        svc = self.add_service()
        spit(os.path.join(self.env.storage, "api", "svc", "OLD"), "x")
        msgs, log = self.collect()
        res = self.app.service_redeploy("svc", svc, "https://tok123@github.com/o/new.git", "dev", log)
        self.assertTrue(res["ok"] and res["started"])
        self.assertEqual(res["repo_url"], "https://***@github.com/o/new.git")
        row = self.app.db.query("SELECT repo_url, branch FROM services WHERE name='svc'", fetch_one=True)
        self.assertEqual((row["repo_url"], row["branch"]), ("https://tok123@github.com/o/new.git", "dev"))
        self.assertFalse(os.path.exists(os.path.join(self.env.storage, "api", "svc", "OLD")))
        self.assertTrue(os.path.exists(os.path.join(self.env.storage, "api", "svc", "app.py")))
        self.assertIn("git clone -b dev https://tok123@github.com/o/new.git svc", self.env.calls())
        audit = slurp(self.app.AUDIT_FILE)
        self.assertNotIn("tok123", audit)                                  # credentials never audited
        for _, m in msgs:
            self.assertNotIn("tok123", m)
        for bad in ("http://github.com/o/x.git", "https://x/y z"):
            with self.assertRaises(ValueError):
                self.app.service_redeploy("svc", svc, bad, "main", log)
        with self.assertRaises(ValueError):
            self.app.service_redeploy("svc", svc, "https://github.com/o/x.git", "--evil", log)

    def test_shared_functions_have_the_documented_signatures(self):
        names = ["service_restart", "service_stop", "service_start", "service_git_update", "service_reinstall_deps",
                 "service_systemd_status", "service_resource_usage", "service_update_config", "service_redeploy"]
        for n in names:
            fn = getattr(self.app, n)
            params = list(inspect.signature(fn).parameters)
            self.assertEqual(params[:2], ["name", "svc"], n)
            self.assertTrue(fn.__doc__, n)
            self.assertFalse(inspect.iscoroutinefunction(fn), n)
            if n not in ("service_systemd_status", "service_resource_usage"):
                self.assertIn("log", params, n)
            src = inspect.getsource(fn)
            self.assertNotIn("input(", src, n)                                # no prompts in shared code
            self.assertNotRegex(src, r"(?<![\w.])print\(", n)

    # ---- interactive wrappers stay thin and keep their behaviour -------------
    def test_service_operations_menu_dispatches_to_shared_functions(self):
        svc = self.add_service()
        for choice, fn in [("1", "service_restart"), ("3", "service_start")]:
            self.fake_input([str(svc["id"]), choice, ""])
            with mock.patch.object(self.app, fn, return_value={"ok": True}) as m, redirect_stdout(io.StringIO()):
                asyncio.run(self.app.service_operations())
            self.assertEqual(m.call_count, 1, fn)
            self.assertEqual(m.call_args[0][0], "svc")

    def test_manage_service_menu_dispatches_to_the_same_functions(self):
        svc = self.add_service()
        self.fake_input(["1", ""])
        with mock.patch.object(self.app, "service_restart", return_value={"ok": True}) as m, \
                redirect_stdout(io.StringIO()):
            asyncio.run(self.app.manage_service("svc", svc))
        self.assertEqual(m.call_count, 1)
        self.fake_input(["2", "no", ""])
        with mock.patch.object(self.app, "service_stop") as m, redirect_stdout(io.StringIO()) as out:
            asyncio.run(self.app.manage_service("svc", svc))
        self.assertEqual(m.call_count, 0)                                  # "no" cancels

    def test_menu_stop_requires_yes_and_runs_the_service_stop(self):
        svc = self.add_service()
        self.fake_input([str(svc["id"]), "2", "yes", ""])
        out = io.StringIO()
        with redirect_stdout(out):
            asyncio.run(self.app.service_operations())
        self.assertIn("Service stopped", out.getvalue())
        self.assertIn("systemctl stop svc", self.env.calls())

    def test_menu_update_configuration_still_works_interactively(self):
        self.add_service()
        self.fake_input(["3", "60", "512", "", "0"])
        with redirect_stdout(io.StringIO()):
            self.app.update_service_config("svc")
        row = self.app.db.query("SELECT cpu_quota, max_memory_mb FROM services WHERE name='svc'", fetch_one=True)
        self.assertEqual((row["cpu_quota"], row["max_memory_mb"]), (60, 512))
        self.fake_input(["3", "5000", "", "", "0"])
        out = io.StringIO()
        with redirect_stdout(out):
            self.app.update_service_config("svc")
        self.assertIn("Update failed", out.getvalue())
        row = self.app.db.query("SELECT cpu_quota FROM services WHERE name='svc'", fetch_one=True)
        self.assertEqual(row["cpu_quota"], 60)

    def test_menu_redeploy_requires_confirmation_word(self):
        svc = self.add_service()
        self.fake_input([str(svc["id"]), "9", "https://github.com/o/new.git", "main", "nope", ""])
        with redirect_stdout(io.StringIO()) as out:
            asyncio.run(self.app.service_operations())
        self.assertNotIn("git clone", self.env.calls())
        self.fake_input([str(svc["id"]), "9", "https://github.com/o/new.git", "main", "REDEPLOY", ""])
        out = io.StringIO()
        with redirect_stdout(out):
            asyncio.run(self.app.service_operations())
        self.assertIn("REDEPLOYMENT COMPLETE", out.getvalue())
        self.assertIn("git clone", self.env.calls())

    # ---- deploy shows the webhook secret ------------------------------------
    def test_deploy_stores_branch_and_secret_and_prints_github_settings(self):
        self.fake_input(["depl", "", "1", "depl", "18222", "https://github.com/o/depl.git", "dev", "2", "", "", "", ""])
        with mock.patch.object(self.app, "check_port_listening", lambda port, timeout=1.0: timeout == 2.0):
            out = io.StringIO()
            with redirect_stdout(out):
                asyncio.run(self.app.deploy_service_async())
        text = out.getvalue()
        self.assertIn("DEPLOYMENT SUCCESSFUL", text, text[-1500:])
        row = self.app.db.query("SELECT * FROM services WHERE name='depl'", fetch_one=True)
        self.assertEqual(row["branch"], "dev")
        self.assertRegex(row["webhook_secret"], r"^[0-9a-f]{64}$")
        self.assertEqual(row["auto_update"], 1)
        self.assertIn("https://webhook.example.com/webhook/depl", text)
        self.assertIn(row["webhook_secret"], text)
        self.assertIn("application/json", text)
        self.assertTrue(os.path.exists(os.path.join(self.systemd_dir, "depl.service")))
        self.assertNotIn(row["webhook_secret"], slurp(self.app.AUDIT_FILE))

    # ---- exception hygiene --------------------------------------------------
    def test_no_bare_except_and_no_get_event_loop(self):
        tree = ast.parse(slurp(harness.APP_PY))
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                self.assertIsNotNone(node.type, f"bare except at line {node.lineno}")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get_event_loop":
                self.fail(f"get_event_loop() at line {node.lineno}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
