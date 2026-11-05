"""Helpers for authenticated installer startup status frames."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import BinaryIO, TypeVar

_NONCE_BYTES = 32
NONCE_LENGTH = _NONCE_BYTES * 2
_READ_BYTES = 128
_MAX_FRAME_BYTES = 128

_Status = TypeVar("_Status")


def new_nonce() -> str:
    """Create a cryptographically random nonce for one startup channel."""
    return secrets.token_hex(_NONCE_BYTES)


def valid_nonce(value: object) -> bool:
    """Check whether a value is a nonce produced by new_nonce."""
    if not isinstance(value, str) or len(value) != NONCE_LENGTH:
        return False
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        return False
    return len(decoded) == _NONCE_BYTES


def read_authenticated_status(
    stream: BinaryIO,
    *,
    marker: bytes,
    parse: Callable[[bytes], _Status | None],
    max_diagnostic_bytes: int | None = None,
) -> tuple[bytes, _Status] | None:
    """Find and parse one marker-prefixed status frame in startup output."""
    if not marker or len(marker) >= _MAX_FRAME_BYTES:
        raise ValueError("The authenticated status marker has an invalid length")

    buffered = bytearray()
    discarded = 0
    while chunk := stream.readline(_READ_BYTES):
        buffered.extend(chunk)
        while True:
            start = buffered.find(marker)
            if start < 0:
                keep = min(len(buffered), len(marker) - 1)
                drop = len(buffered) - keep
                if drop:
                    del buffered[:drop]
                    discarded += drop
                break
            if start:
                del buffered[:start]
                discarded += start

            newline = buffered.find(b"\\n", len(marker))
            if newline < 0:
                if len(buffered) <= _MAX_FRAME_BYTES:
                    break
                del buffered[0]
                discarded += 1
                continue

            candidate = bytes(buffered[: newline + 1])
            status = parse(candidate)
            if status is not None:
                return candidate, status
            del buffered[0]
            discarded += 1

        if max_diagnostic_bytes is not None and discarded > max_diagnostic_bytes:
            return None
    return None
