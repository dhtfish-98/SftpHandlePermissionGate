"""Real SSH/SFTP v3 round trips against a loopback server."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

import paramiko
from paramiko.sftp import CMD_CLOSE, CMD_READ, CMD_WRITE, int64

from sftp_handle_permission_gate import AuditLog, GateServer, PermissionState
from weak_baseline import write_through_read_grant


FIXTURE = b"authorized-read-only-evidence\n"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SftpRoundTripTest(unittest.TestCase):
    def setUp(self) -> None:
        build_dir = os.environ.get("SFTP_GATE_BUILD_DIR")
        if not build_dir:
            raise RuntimeError("SFTP_GATE_BUILD_DIR must point to Build output")
        Path(build_dir).mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="sftp-gate-", dir=build_dir)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "files"
        self.root.mkdir()
        self.evidence = self.root / "evidence.txt"
        self.evidence.write_bytes(FIXTURE)
        self.before = digest(self.evidence)
        self.audit = AuditLog(self.base / "audit.jsonl")
        self.policy = PermissionState({
            "reader": frozenset({"read"}),
            "editor": frozenset({"read", "write"}),
        })
        self.credentials = {"reader": "reader-credential", "editor": "editor-credential"}
        self.server = GateServer(self.root, self.credentials, self.policy, self.audit).start()
        self.addCleanup(self.server.stop)
        self.assertEqual("127.0.0.1", self.server.address[0])

    def client(self, account: str = "reader"):
        transport = paramiko.Transport(self.server.address)
        transport.connect(
            hostkey=self.server.host_key,
            username=account,
            password=self.credentials[account],
        )
        sftp = paramiko.SFTPClient.from_transport(transport)
        self.assertEqual(3, paramiko.sftp._VERSION)
        self.addCleanup(transport.close)
        self.addCleanup(sftp.close)
        return sftp

    def events(self) -> list[dict]:
        return [json.loads(line) for line in self.audit.path.read_text().splitlines()]

    def assert_unchanged(self) -> None:
        self.assertEqual(self.before, digest(self.evidence))

    def test_reader_can_read_and_audit_matches(self):
        sftp = self.client()
        with sftp.file("/evidence.txt", "rb") as opened:
            self.assertEqual(FIXTURE, opened.read())
        self.assert_unchanged()
        events = self.events()
        self.assertTrue(any(e["action"] == "open" and e["decision"] == "allow" for e in events))
        self.assertTrue(any(e["action"] == "handle_read" and e["decision"] == "allow" for e in events))
        self.assertTrue(all("credential" not in json.dumps(e) for e in events))

    def test_reader_write_open_and_direct_write_on_read_handle_denied(self):
        sftp = self.client()
        with self.assertRaises(OSError):
            sftp.file("/evidence.txt", "r+b")
        with sftp.file("/evidence.txt", "rb") as opened:
            with self.assertRaises(OSError):
                sftp._request(CMD_WRITE, opened.handle, int64(0), b"tamper")
        self.assert_unchanged()
        events = self.events()
        self.assertTrue(any(e["action"] == "open" and e["decision"] == "deny" for e in events))
        self.assertTrue(any(e["action"] == "handle_write" and e["decision"] == "deny" for e in events))

    def test_reader_rename_and_posix_rename_denied(self):
        sftp = self.client()
        with self.assertRaises(OSError):
            sftp.rename("/evidence.txt", "/renamed.txt")
        with self.assertRaises(OSError):
            sftp.posix_rename("/evidence.txt", "/renamed.txt")
        self.assert_unchanged()
        self.assertFalse((self.root / "renamed.txt").exists())
        events = self.events()
        self.assertEqual(2, sum(e["action"] == "rename" and e["decision"] == "deny" for e in events))

    def test_closed_handle_reuse_denied_and_logged(self):
        sftp = self.client()
        opened = sftp.file("/evidence.txt", "rb")
        handle = opened.handle
        opened.close()
        with self.assertRaises(OSError):
            sftp._request(CMD_READ, handle, int64(0), 1)
        with self.assertRaises(OSError):
            sftp._request(CMD_WRITE, handle, int64(0), b"tamper")
        with self.assertRaises(OSError):
            sftp._request(CMD_CLOSE, handle)
        self.assert_unchanged()
        events = self.events()
        self.assertEqual(3, sum(e["reason"] == "invalid_handle" for e in events))

    def test_live_revocation_blocks_existing_read_handle(self):
        sftp = self.client()
        with sftp.file("/evidence.txt", "rb") as opened:
            self.assertEqual(FIXTURE, opened.read())
            self.policy.replace("reader", frozenset())
            with self.assertRaises(OSError):
                opened.seek(0)
                opened.read(1)
        self.assert_unchanged()
        self.assertTrue(any(e["action"] == "handle_read" and e["decision"] == "deny" for e in self.events()))

    def test_policy_upgrade_does_not_upgrade_old_handle(self):
        sftp = self.client()
        with sftp.file("/evidence.txt", "rb") as opened:
            self.policy.replace("reader", frozenset({"read", "write"}))
            with self.assertRaises(OSError):
                sftp._request(CMD_WRITE, opened.handle, int64(0), b"tamper")
            self.assertEqual(FIXTURE, opened.read())
        self.assert_unchanged()

    def test_cross_connection_handle_reuse_denied(self):
        first = self.client()
        second = self.client()
        with first.file("/evidence.txt", "rb") as opened:
            with self.assertRaises(OSError):
                second._request(CMD_READ, opened.handle, int64(0), 1)
        self.assert_unchanged()
        self.assertTrue(any(e["reason"] == "invalid_handle" for e in self.events()))

    def test_editor_can_write_and_rename_but_old_path_handle_expires(self):
        sftp = self.client("editor")
        with sftp.file("/evidence.txt", "r+b") as opened:
            opened.write(b"EDIT")
            opened.flush()
            sftp.rename("/evidence.txt", "/renamed.txt")
            with self.assertRaises(OSError):
                opened.seek(0)
                opened.read(1)
        self.assertFalse(self.evidence.exists())
        self.assertEqual(b"EDIT" + FIXTURE[4:], (self.root / "renamed.txt").read_bytes())
        self.assertTrue(any(e["action"] == "rename" and e["decision"] == "allow" for e in self.events()))

    def test_path_escape_and_symlink_rejected(self):
        (self.root / "renamed.txt").symlink_to(self.evidence)
        sftp = self.client()
        for path in ("/../evidence.txt", "/renamed.txt", "evidence.txt"):
            with self.assertRaises(OSError):
                sftp.file(path, "rb")
        self.assert_unchanged()

    def test_many_simultaneous_reader_denials_leave_hash_unchanged(self):
        def worker(_):
            transport = paramiko.Transport(self.server.address)
            try:
                transport.connect(
                    hostkey=self.server.host_key,
                    username="reader",
                    password=self.credentials["reader"],
                )
                sftp = paramiko.SFTPClient.from_transport(transport)
                try:
                    with sftp.file("/evidence.txt", "rb") as opened:
                        if opened.read() != FIXTURE:
                            return False
                        try:
                            sftp._request(CMD_WRITE, opened.handle, int64(0), b"tamper")
                        except OSError:
                            return True
                        return False
                finally:
                    sftp.close()
            finally:
                transport.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            self.assertEqual([True] * 12, list(pool.map(worker, range(12))))
        self.assert_unchanged()
        self.assertEqual(12, sum(e["action"] == "handle_write" and e["decision"] == "deny" for e in self.events()))

    def test_wrong_password_rejected(self):
        transport = paramiko.Transport(self.server.address)
        try:
            with self.assertRaises(paramiko.AuthenticationException):
                transport.connect(hostkey=self.server.host_key, username="reader", password="incorrect")
        finally:
            transport.close()
        self.assertTrue(any(e["action"] == "authenticate" and e["decision"] == "deny" for e in self.events()))

    def test_disconnected_handle_cannot_be_used_after_server_restart(self):
        first = self.client()
        opened = first.file("/evidence.txt", "rb")
        old_handle = opened.handle
        first.close()
        self.server.stop()
        self.server = GateServer(self.root, self.credentials, self.policy, self.audit).start()
        self.addCleanup(self.server.stop)
        restarted = self.client()
        with self.assertRaises(OSError):
            restarted._request(CMD_READ, old_handle, int64(0), 1)
        self.assert_unchanged()
        self.assertTrue(any(e["reason"] == "invalid_handle" for e in self.events()))

    def test_test_only_weak_counterexample_modifies_a_separate_copy(self):
        weak_copy = self.base / "weak-copy.txt"
        weak_copy.write_bytes(FIXTURE)
        write_through_read_grant(weak_copy, b"BROKEN")
        self.assertNotEqual(self.before, digest(weak_copy))
        self.assert_unchanged()


if __name__ == "__main__":
    unittest.main()
