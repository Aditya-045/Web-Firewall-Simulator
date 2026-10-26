"""
protocol.py -- Shared wire framing for SecureGateway persistent connections
=============================================================================
Moving from one-shot connections to persistent ones means a single
`recv()` can no longer be trusted to contain exactly one message, and a
naive newline-per-message scheme breaks the moment a response contains
embedded newlines (dossier JSON dumps, SQL result tables).

This module fixes both problems with an asymmetric, deliberately simple
scheme:

  REQUESTS  (client -> firewall): one newline-terminated line per
            message. Our own commands (LOGIN, CMD, ADMIN, ...) are
            always single-line, so this is enough, and it degrades
            gracefully for external/attacker traffic that never
            conforms to our protocol at all (see aegis_firewall.py's
            fallback-on-disconnect handling).

  RESPONSES (firewall -> client): 4-byte big-endian length prefix +
            UTF-8 payload. Responses can legitimately be multi-line
            (dossier dumps, SQL tables) so they cannot rely on a
            newline as a terminator.

Two variants of the response reader/writer are provided: async
(asyncio streams, used by aegis_firewall.py) and sync (blocking
`socket` objects, used by client.py / admin_console.py).
"""

import asyncio
import struct

HEADER_SIZE = 4
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB safety ceiling, keeps this lightweight


# ---------------------------------------------------------------------
# Async side (aegis_firewall.py)
# ---------------------------------------------------------------------
async def recv_line_async(reader) -> str | None:
    """Reads one newline-terminated request line. Returns None on clean EOF
    with no data pending (i.e. the peer disconnected without sending
    anything more)."""
    try:
        raw = await reader.readuntil(b'\n')
    except asyncio.IncompleteReadError as e:
        # Peer closed the connection mid-message (or without a trailing
        # newline at all, e.g. a raw external client). Use whatever was
        # sent so far -- this preserves compatibility with non-conforming
        # traffic instead of silently dropping it.
        raw = e.partial
    except (asyncio.LimitOverrunError, ConnectionResetError):
        return None

    if not raw:
        return None
    return raw.decode('utf-8', errors='ignore').strip()


async def send_framed_async(writer, text: str):
    """Sends one length-prefixed response."""
    payload = text.encode('utf-8')
    writer.write(struct.pack('>I', len(payload)) + payload)
    await writer.drain()


# ---------------------------------------------------------------------
# Sync side (client.py, admin_console.py -- plain blocking sockets)
# ---------------------------------------------------------------------
def send_line_sync(sock, text: str):
    """Sends one newline-terminated request line. Embedded newlines in the
    payload are flattened to spaces so they can never be mistaken for the
    line terminator."""
    safe_text = text.replace('\n', ' ').replace('\r', ' ')
    sock.sendall(safe_text.encode('utf-8') + b'\n')


def recv_framed_sync(sock) -> str | None:
    """Reads one length-prefixed response. Returns None if the peer closed
    the connection before a full message arrived."""
    header = _recv_exact_sync(sock, HEADER_SIZE)
    if header is None:
        return None
    (length,) = struct.unpack('>I', header)
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Response too large ({length} bytes) -- refusing to read.")
    payload = _recv_exact_sync(sock, length)
    if payload is None:
        return None
    return payload.decode('utf-8', errors='ignore')


def _recv_exact_sync(sock, n: int) -> bytes | None:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
