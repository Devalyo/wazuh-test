"""Authenticated length-prefixed frames for Mini Wazuh cluster traffic."""

import asyncio
import struct

from cryptography.fernet import Fernet, InvalidToken


DEFAULT_MAX_FRAME_SIZE = 1024 * 1024
_FRAME_LENGTH = struct.Struct("!I")


class ProtocolError(Exception):
    """Raised when a cluster frame is malformed or cannot be authenticated."""


def _validate_frame_length(length: int, max_frame_size: int) -> None:
    if not 1 <= length <= max_frame_size:
        raise ProtocolError("invalid frame length")


def encode_frame(
    plaintext: bytes,
    fernet: Fernet,
    max_frame_size: int = DEFAULT_MAX_FRAME_SIZE,
) -> bytes:
    """Encrypt plaintext and prefix the resulting token with its length."""
    token = fernet.encrypt(plaintext)
    _validate_frame_length(len(token), max_frame_size)
    return _FRAME_LENGTH.pack(len(token)) + token


async def read_frame(
    reader: asyncio.StreamReader,
    fernet: Fernet,
    max_frame_size: int = DEFAULT_MAX_FRAME_SIZE,
) -> bytes:
    """Read, authenticate, and decrypt one complete cluster frame."""
    try:
        length_data = await reader.readexactly(_FRAME_LENGTH.size)
        (length,) = _FRAME_LENGTH.unpack(length_data)
        _validate_frame_length(length, max_frame_size)
        token = await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        raise ProtocolError("truncated frame") from exc

    try:
        return fernet.decrypt(token)
    except InvalidToken as exc:
        raise ProtocolError("invalid frame token") from exc


async def write_frame(
    writer: asyncio.StreamWriter,
    plaintext: bytes,
    fernet: Fernet,
    max_frame_size: int = DEFAULT_MAX_FRAME_SIZE,
) -> None:
    """Write and flush one authenticated cluster frame."""
    writer.write(encode_frame(plaintext, fernet, max_frame_size))
    await writer.drain()
