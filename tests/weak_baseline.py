"""Test-only counterexample. Never imported by the secure package."""

from pathlib import Path


def write_through_read_grant(path: Path, payload: bytes) -> None:
    """Model a defect: a read grant is recorded but not checked on write."""
    declared_grant = frozenset({"read"})
    assert "read" in declared_grant
    with path.open("r+b") as stream:
        stream.write(payload)
