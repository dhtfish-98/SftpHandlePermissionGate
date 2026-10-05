"""Loopback-only SFTP v3 server with account and per-handle checks."""

from __future__ import annotations

import hmac
import json
import os
import socket
import stat
import threading
import time
from pathlib import Path

import paramiko
from paramiko import AUTH_FAILED, AUTH_SUCCESSFUL, OPEN_SUCCEEDED
from paramiko.sftp import (
    CMD_CLOSE,
    CMD_FSETSTAT,
    CMD_FSTAT,
    CMD_READ,
    CMD_WRITE,
    SFTP_NO_SUCH_FILE,
    SFTP_OK,
    SFTP_PERMISSION_DENIED,
)


ALLOWED_NAMES = frozenset({"evidence.txt", "renamed.txt"})
MAX_IO = 256 * 1024


class AuditLog:
    """Append-only experiment decisions without credentials or handle values."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._sequence = 0

    def record(self, account: str, action: str, decision: str, reason: str) -> None:
        with self._lock:
            self._sequence += 1
            event = {
                "sequence": self._sequence,
                "account": account,
                "action": action,
                "decision": decision,
                "reason": reason,
            }
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())


class PermissionState:
    """A mutable policy so a live handle can be checked after revocation."""

    def __init__(self, permissions: dict[str, frozenset[str]]):
        self._permissions = dict(permissions)
        self._lock = threading.RLock()

    @property
    def transaction(self):
        """Serialize policy changes and service-owned file operations."""
        return self._lock

    def permits(self, account: str, action: str) -> bool:
        with self._lock:
            return action in self._permissions.get(account, frozenset())

    def replace(self, account: str, permissions: frozenset[str]) -> None:
        with self._lock:
            self._permissions[account] = permissions


class _Authentication(paramiko.ServerInterface):
    def __init__(self, credentials: dict[str, str], audit: AuditLog):
        self._credentials = credentials
        self._audit = audit
        self.account = ""

    def check_auth_password(self, username: str, password: str) -> int:
        expected = self._credentials.get(username)
        accepted = expected is not None and hmac.compare_digest(expected, password)
        if accepted:
            self.account = username
        self._audit.record(username, "authenticate", "allow" if accepted else "deny", "password")
        return AUTH_SUCCESSFUL if accepted else AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session" and self.account:
            return OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class _GuardedHandle(paramiko.SFTPHandle):
    def __init__(
        self,
        flags: int,
        file_obj,
        account: str,
        name: str,
        identity: tuple[int, int],
        root_fd: int,
        policy: PermissionState,
        audit: AuditLog,
    ):
        super().__init__(flags)
        self.readfile = file_obj
        self.writefile = file_obj
        self._account = account
        self._name = name
        self._identity = identity
        self._root_fd = root_fd
        self._policy = policy
        self._audit = audit
        self._read_granted = (flags & os.O_ACCMODE) != os.O_WRONLY
        self._write_granted = (flags & os.O_ACCMODE) != os.O_RDONLY
        self._closed = False

    def _still_same_file(self) -> bool:
        try:
            current = os.stat(self._name, dir_fd=self._root_fd, follow_symlinks=False)
        except OSError:
            return False
        return stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == self._identity

    def read(self, offset: int, length: int):
        with self._policy.transaction:
            if (
                self._closed
                or not self._read_granted
                or not self._policy.permits(self._account, "read")
                or not self._still_same_file()
                or offset < 0
                or not 0 < length <= MAX_IO
            ):
                self._audit.record(self._account, "handle_read", "deny", "handle_or_policy")
                return SFTP_PERMISSION_DENIED
            response = super().read(offset, length)
            self._audit.record(self._account, "handle_read", "allow", "bound_handle")
            return response

    def write(self, offset: int, data: bytes) -> int:
        with self._policy.transaction:
            if (
                self._closed
                or not self._write_granted
                or not self._policy.permits(self._account, "write")
                or not self._still_same_file()
                or offset < 0
                or len(data) > MAX_IO
            ):
                self._audit.record(self._account, "handle_write", "deny", "handle_or_policy")
                return SFTP_PERMISSION_DENIED
            response = super().write(offset, data)
            self._audit.record(self._account, "handle_write", "allow", "bound_handle")
            return response

    def stat(self):
        with self._policy.transaction:
            if self._closed or not self._policy.permits(self._account, "read") or not self._still_same_file():
                self._audit.record(self._account, "handle_stat", "deny", "handle_or_policy")
                return SFTP_PERMISSION_DENIED
            return paramiko.SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))

    def chattr(self, attr) -> int:
        self._audit.record(self._account, "handle_chattr", "deny", "unsupported_mutation")
        return SFTP_PERMISSION_DENIED

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._audit.record(self._account, "handle_close", "allow", "closed")
            super().close()


class _SFTPInterface(paramiko.SFTPServerInterface):
    def __init__(self, server, root: Path, policy: PermissionState, audit: AuditLog):
        super().__init__(server)
        self.account = server.account
        self._root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        self._policy = policy
        self._audit = audit

    def session_ended(self) -> None:
        os.close(self._root_fd)
        self._audit.record(self.account, "session_end", "allow", "disconnected")

    @staticmethod
    def _name(path: str) -> str | None:
        if not path.startswith("/") or path.count("/") != 1:
            return None
        name = path[1:]
        return name if name in ALLOWED_NAMES else None

    def _deny(self, action: str, reason: str = "policy") -> int:
        self._audit.record(self.account, action, "deny", reason)
        return SFTP_PERMISSION_DENIED

    def open(self, path: str, flags: int, attr):
        with self._policy.transaction:
            name = self._name(path)
            mode = flags & os.O_ACCMODE
            wants_read = mode != os.O_WRONLY
            wants_write = mode != os.O_RDONLY
            if name is None:
                return self._deny("open", "path")
            if flags & (os.O_CREAT | os.O_EXCL | os.O_TRUNC | os.O_APPEND):
                return self._deny("open", "destructive_flag")
            if (wants_read and not self._policy.permits(self.account, "read")) or (
                wants_write and not self._policy.permits(self.account, "write")
            ):
                return self._deny("open", "policy")
            safe_flags = mode | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(name, safe_flags, dir_fd=self._root_fd)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    os.close(fd)
                    return self._deny("open", "not_regular")
                file_obj = os.fdopen(fd, "r+b" if mode == os.O_RDWR else "wb" if wants_write else "rb", buffering=0)
            except OSError:
                return self._deny("open", "missing_or_link")
            handle = _GuardedHandle(
                flags,
                file_obj,
                self.account,
                name,
                (info.st_dev, info.st_ino),
                self._root_fd,
                self._policy,
                self._audit,
            )
            self._audit.record(self.account, "open", "allow", "bound_handle")
            return handle

    def stat(self, path: str):
        name = self._name(path)
        if name is None or not self._policy.permits(self.account, "read"):
            return self._deny("stat", "path_or_policy")
        try:
            info = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
        except OSError:
            return SFTP_NO_SUCH_FILE
        if not stat.S_ISREG(info.st_mode):
            return self._deny("stat", "not_regular")
        self._audit.record(self.account, "stat", "allow", "file")
        return paramiko.SFTPAttributes.from_stat(info)

    def lstat(self, path: str):
        return self.stat(path)

    def rename(self, oldpath: str, newpath: str) -> int:
        with self._policy.transaction:
            old_name = self._name(oldpath)
            new_name = self._name(newpath)
            if not self._policy.permits(self.account, "write"):
                return self._deny("rename", "policy")
            if old_name is None or new_name is None or old_name == new_name:
                return self._deny("rename", "path")
            try:
                old_info = os.stat(old_name, dir_fd=self._root_fd, follow_symlinks=False)
                if not stat.S_ISREG(old_info.st_mode):
                    return self._deny("rename", "not_regular")
                try:
                    os.stat(new_name, dir_fd=self._root_fd, follow_symlinks=False)
                    return self._deny("rename", "target_exists")
                except FileNotFoundError:
                    pass
                os.rename(old_name, new_name, src_dir_fd=self._root_fd, dst_dir_fd=self._root_fd)
            except OSError:
                return self._deny("rename", "filesystem")
            self._audit.record(self.account, "rename", "allow", "authorized")
            return SFTP_OK

    def posix_rename(self, oldpath: str, newpath: str) -> int:
        return self.rename(oldpath, newpath)

    def remove(self, path: str) -> int:
        return self._deny("remove", "unsupported_mutation")

    def mkdir(self, path: str, attr) -> int:
        return self._deny("mkdir", "unsupported_mutation")

    def rmdir(self, path: str) -> int:
        return self._deny("rmdir", "unsupported_mutation")

    def chattr(self, path: str, attr) -> int:
        return self._deny("chattr", "unsupported_mutation")

    def symlink(self, target_path: str, path: str) -> int:
        return self._deny("symlink", "unsupported_mutation")

    def readlink(self, path: str) -> int:
        return self._deny("readlink", "unsupported_mutation")


class _AuditedSFTPServer(paramiko.SFTPServer):
    """Record unknown handles before the pinned library rejects the packet."""

    def _process(self, message_type, request_number, message):
        if message_type in {CMD_CLOSE, CMD_READ, CMD_WRITE, CMD_FSTAT, CMD_FSETSTAT}:
            position = message.packet.tell()
            try:
                handle = message.get_binary()
            finally:
                message.packet.seek(position)
            if handle not in self.file_table and handle not in self.folder_table:
                action = {
                    CMD_CLOSE: "handle_close",
                    CMD_READ: "handle_read",
                    CMD_WRITE: "handle_write",
                    CMD_FSTAT: "handle_stat",
                    CMD_FSETSTAT: "handle_chattr",
                }[message_type]
                self.server._audit.record(self.server.account, action, "deny", "invalid_handle")
        return super()._process(message_type, request_number, message)


class GateServer:
    """Own a local listener; test clients pin ``host_key`` explicitly."""

    def __init__(
        self,
        root: Path,
        credentials: dict[str, str],
        policy: PermissionState,
        audit: AuditLog,
    ):
        self.root = Path(root)
        self.credentials = dict(credentials)
        self.policy = policy
        self.audit = audit
        self.host_key = paramiko.RSAKey.generate(2048)
        self._listener: socket.socket | None = None
        self._stop = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._transports: list[paramiko.Transport] = []
        self._connections: list[threading.Thread] = []
        self._lock = threading.Lock()

    @property
    def address(self) -> tuple[str, int]:
        if self._listener is None:
            raise RuntimeError("listener is not running")
        return self._listener.getsockname()

    def start(self) -> "GateServer":
        if self._listener is not None:
            raise RuntimeError("listener already running")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        listener.settimeout(0.2)
        self._listener = listener
        self._accept_thread = threading.Thread(target=self._accept, name="sftp-accept", daemon=True)
        self._accept_thread.start()
        return self

    def _accept(self) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self._serve, args=(connection,), daemon=True)
            with self._lock:
                self._connections.append(thread)
            thread.start()

    def _serve(self, connection: socket.socket) -> None:
        transport = paramiko.Transport(connection)
        with self._lock:
            self._transports.append(transport)
        transport.add_server_key(self.host_key)
        auth = _Authentication(self.credentials, self.audit)
        transport.set_subsystem_handler(
            "sftp", _AuditedSFTPServer, _SFTPInterface, self.root, self.policy, self.audit
        )
        try:
            transport.start_server(server=auth)
            while transport.is_active() and not self._stop.is_set():
                time.sleep(0.05)
        except (EOFError, OSError, paramiko.SSHException):
            pass
        finally:
            transport.close()

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        with self._lock:
            for transport in self._transports:
                transport.close()
            threads = list(self._connections)
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2)
        for thread in threads:
            thread.join(timeout=2)

    def __enter__(self) -> "GateServer":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
