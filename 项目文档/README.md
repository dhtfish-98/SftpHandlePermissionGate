# SftpHandlePermissionGate

An independently authored, loopback-only SFTP v3 authorization experiment. A reader may open and read `evidence.txt`; write opens, direct writes through a read handle, and renames are denied. Closing a handle, disconnecting, revoking read permission, or moving the file invalidates further operations on that handle. A separate editor account demonstrates authorized write and rename behavior. Every decision is recorded without credentials or raw handle values.

The runnable implementation uses `paramiko==5.0.0` as an external SSH/SFTP dependency. It binds only to `127.0.0.1`, uses an ephemeral host key, and requires the client to pin that key. Tests use synthetic data and credentials, and write only to a caller-selected `Build` directory. It is a bounded laboratory service, not a production SFTP server.

## Verify from the repository root

Use Python 3.11 or newer. The repository root must contain `项目文档/` alongside `src/` when packaging. Install `uv`, `build==1.3.0`, and `paramiko==5.0.0`, then run:

```sh
python scripts/run_validation.py --build-root Build/validation
```

The script builds both distribution formats, runs the 13 loopback tests against source, unpacked source archive, and isolated wheel, checks that the wheel contains no test-only weak fixture, and writes a machine-readable receipt under `Build/validation/`. CI runs the same entry point on Python 3.11 and 3.14.

## Scope and limits

- SFTP protocol version 3, Paramiko 5.0.0, and a two-file allowlist are fixed for the experiment.
- The service serializes its own policy updates and file operations. An external process that can modify the laboratory root is outside this test boundary.
- The baseline that writes through a declared read grant lives only in `tests/weak_baseline.py`; it is excluded from the installed wheel.
- A local baseline comparison and passing package tests do not demonstrate an upstream vulnerability, impact on a real target, or acceptance into any program. Evidence of an authorized real-world task and its actual safeguard effect remains open.

See `ORIGIN.md`, `THIRD_PARTY.md`, and `VERSION_STATUS.md` for provenance and release scope.
