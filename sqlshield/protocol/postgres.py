from __future__ import annotations

import asyncio
import logging
import struct
import time
from typing import Optional

from .. import audit as _audit
from .. import pipeline
from ..types import Action, SessionInfo

logger = logging.getLogger(__name__)

_PROTO_V3     = 196608
_PROTO_SSL    = 80877103
_PROTO_CANCEL = 80877102

_T_QUERY     = ord('Q')
_T_PARSE     = ord('P')
_T_BIND      = ord('B')
_T_DESCRIBE  = ord('D')
_T_EXECUTE   = ord('E')
_T_SYNC      = ord('S')
_T_FLUSH     = ord('H')
_T_CLOSE     = ord('C')
_T_TERMINATE = ord('X')
_T_READY     = ord('Z')
_T_ERROR     = ord('E')

_SQLSTATE_BLOCKED = b"42501"

_AUTH_NEEDS_RESPONSE = frozenset({3, 5, 10, 11})


def _error_response(message: str) -> bytes:
    body = (
        b"S" + b"ERROR\x00"
        + b"V" + b"ERROR\x00"
        + b"C" + _SQLSTATE_BLOCKED + b"\x00"
        + b"M" + message.encode() + b"\x00"
        + b"\x00"
    )
    return bytes([_T_ERROR]) + struct.pack("!I", 4 + len(body)) + body


def _ready_for_query(status: bytes = b"I") -> bytes:
    return bytes([_T_READY]) + struct.pack("!I", 5) + status


class _Connection:
    __slots__ = ("cr", "cw", "br", "bw", "session", "stats")

    def __init__(
        self,
        cr: asyncio.StreamReader, cw: asyncio.StreamWriter,
        br: asyncio.StreamReader, bw: asyncio.StreamWriter,
        stats: dict,
    ) -> None:
        self.cr, self.cw = cr, cw
        self.br, self.bw = br, bw
        self.stats = stats
        self.session = SessionInfo()

    async def run(self) -> None:
        peer = self.cw.get_extra_info("peername", ("?", 0))
        self.session.source_ip = str(peer[0])
        if await self._startup():
            await self._query_loop()

    async def _startup(self) -> bool:
        raw = await self._read_startup()
        if raw is None:
            return False
        length_bytes, rest = raw
        proto = struct.unpack("!I", rest[:4])[0]

        if proto == _PROTO_SSL:
            self.cw.write(b"N")
            await self.cw.drain()
            raw = await self._read_startup()
            if raw is None:
                return False
            length_bytes, rest = raw
            proto = struct.unpack("!I", rest[:4])[0]

        if proto == _PROTO_CANCEL:
            self.bw.write(length_bytes + rest)
            await self.bw.drain()
            return False

        if proto == _PROTO_V3:
            parts = rest[4:].rstrip(b"\x00").split(b"\x00")
            params: dict[str, str] = {}
            for i in range(0, len(parts) - 1, 2):
                k = parts[i].decode("utf-8", errors="replace")
                v = parts[i + 1].decode("utf-8", errors="replace")
                params[k] = v
            self.session.user     = params.get("user", "unknown")
            self.session.database = params.get("database", params.get("user", ""))
            self.session.app_name = params.get("application_name", "")
            self.session.params   = params

        self.bw.write(length_bytes + rest)
        await self.bw.drain()
        return await self._relay_auth()

    async def _read_startup(self) -> Optional[tuple[bytes, bytes]]:
        try:
            lb = await self.cr.readexactly(4)
            total = struct.unpack("!I", lb)[0]
            rest = await self.cr.readexactly(total - 4)
            return lb, rest
        except asyncio.IncompleteReadError:
            return None

    async def _relay_auth(self) -> bool:
        while True:
            try:
                tb = await self.br.readexactly(1)
                lb = await self.br.readexactly(4)
                payload = await self.br.readexactly(struct.unpack("!I", lb)[0] - 4)
            except asyncio.IncompleteReadError:
                return False

            self.cw.write(tb + lb + payload)
            await self.cw.drain()

            t = tb[0]
            if t == _T_READY:
                return True
            if t == ord('R'):
                auth_type = struct.unpack("!I", payload[:4])[0]
                if auth_type in _AUTH_NEEDS_RESPONSE:
                    msg = await self._read_client_msg()
                    if msg:
                        self.bw.write(msg)
                        await self.bw.drain()

    async def _query_loop(self) -> None:
        while True:
            batch: list[bytes] = []
            sql: Optional[str] = None

            while True:
                msg = await self._read_client_msg()
                if msg is None:
                    return
                batch.append(msg)
                t = msg[0]

                if t == _T_TERMINATE:
                    self.bw.write(b"".join(batch))
                    await self.bw.drain()
                    return

                if t == _T_QUERY:
                    sql = msg[5:].rstrip(b"\x00").decode("utf-8", errors="replace")
                    break

                if t == _T_PARSE and sql is None:
                    payload = msg[5:]
                    try:
                        nul1 = payload.index(b"\x00")
                        rest = payload[nul1 + 1:]
                        nul2 = rest.index(b"\x00")
                        candidate = rest[:nul2].decode("utf-8", errors="replace")
                        if candidate.strip():
                            sql = candidate
                    except (ValueError, UnicodeDecodeError):
                        pass

                if t == _T_SYNC:
                    break

            if not batch:
                continue

            blocked = False
            if sql and sql.strip():
                blocked = await self._inspect(sql)

            if blocked:
                self.cw.write(_error_response("SQL Shield: query blocked"))
                self.cw.write(_ready_for_query(b"I"))
                await self.cw.drain()
            else:
                self.bw.write(b"".join(batch))
                await self.bw.drain()
                await self._relay_until_ready()

    async def _inspect(self, sql: str) -> bool:
        try:
            verdict, pq = pipeline.inspect(sql, self.session)
            blocked = verdict.action == Action.BLOCK
        except Exception as exc:
            logger.exception("pipeline error for sql %r: %s", sql[:80], exc)
            return False

        self.stats["total"] += 1
        if blocked:
            self.stats["blocked"] += 1
        else:
            self.stats["allowed"] += 1

        try:
            _audit.write(
                "proxy", sql, pq,
                blocked=blocked,
                shield_enabled=True,
                engine_verdicts=verdict.engine_verdicts,
                proxy_mode="enforce",
            )
        except Exception:
            pass

        return blocked

    async def _read_client_msg(self) -> Optional[bytes]:
        try:
            tb = await self.cr.readexactly(1)
            lb = await self.cr.readexactly(4)
            payload = await self.cr.readexactly(struct.unpack("!I", lb)[0] - 4)
            return tb + lb + payload
        except asyncio.IncompleteReadError:
            return None

    async def _relay_until_ready(self) -> None:
        while True:
            try:
                tb = await self.br.readexactly(1)
                lb = await self.br.readexactly(4)
                payload = await self.br.readexactly(struct.unpack("!I", lb)[0] - 4)
            except asyncio.IncompleteReadError:
                return
            self.cw.write(tb + lb + payload)
            await self.cw.drain()
            if tb[0] == _T_READY:
                return


class PostgresProxy:
    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 6432,
        backend_host: str = "localhost",
        backend_port: int = 5432,
    ) -> None:
        self.listen_host  = listen_host
        self.listen_port  = listen_port
        self.backend_host = backend_host
        self.backend_port = backend_port
        self._server: Optional[asyncio.AbstractServer] = None
        self.stats: dict[str, int] = {"total": 0, "blocked": 0, "allowed": 0}

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.listen_host,
            port=self.listen_port,
        )
        logger.info(
            "Proxy listening on %s:%d → backend %s:%d",
            self.listen_host, self.listen_port,
            self.backend_host, self.backend_port,
        )

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_client(
        self,
        cr: asyncio.StreamReader,
        cw: asyncio.StreamWriter,
    ) -> None:
        peer = cw.get_extra_info("peername", ("?", 0))
        logger.debug("new connection from %s:%d", *peer)
        try:
            br, bw = await asyncio.open_connection(self.backend_host, self.backend_port)
        except OSError as exc:
            logger.error("cannot connect to backend %s:%d — %s",
                         self.backend_host, self.backend_port, exc)
            cw.close()
            return

        conn = _Connection(cr, cw, br, bw, self.stats)
        try:
            await conn.run()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as exc:
            logger.exception("unhandled error in connection from %s: %s", peer, exc)
        finally:
            for w in (cw, bw):
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:
                    pass
