"""Loopback-only master for the Mini Wazuh cluster simulator."""

import argparse
import asyncio
import ipaddress
import json
import os
from collections.abc import Sequence
from typing import Any

from mini_wazuh.crypto import DEFAULT_CLUSTER_SECRET, build_fernet
from mini_wazuh.dapi import deserialize_request, run_local
from mini_wazuh.protocol import (
    DEFAULT_MAX_FRAME_SIZE,
    ProtocolError,
    read_frame,
    write_frame,
)


def validate_bind_host(host: str) -> str:
    """Return a literal loopback address or reject an externally reachable bind."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("host must be a literal loopback IP address") from exc
    if not address.is_loopback:
        raise ValueError("host must be a loopback IP address")
    return host


def validate_envelope(value: Any) -> dict[str, str]:
    """Validate the small outer envelope before DAPI deserialization."""
    required_keys = {"node", "command", "data"}
    if not isinstance(value, dict) or set(value) != required_keys:
        raise ValueError("envelope must contain only node, command, and data")
    if not all(isinstance(value[key], str) for key in required_keys):
        raise ValueError("envelope values must be strings")
    if value["command"] != "dapi":
        raise ValueError("unsupported envelope command")
    return value


class MiniWazuhMaster:
    """Serve exactly one authenticated DAPI envelope per loopback connection."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1516,
        cluster_secret: str = DEFAULT_CLUSTER_SECRET,
        max_frame_size: int = DEFAULT_MAX_FRAME_SIZE,
    ) -> None:
        self._host = validate_bind_host(host)
        self.port = port
        self.max_frame_size = max_frame_size
        self._fernet = build_fernet(cluster_secret)
        self._server: asyncio.AbstractServer | None = None
        self._closing = False
        self._client_writers: set[asyncio.StreamWriter] = set()
        self._client_tasks: set[asyncio.Task[None]] = set()

    @property
    def host(self) -> str:
        """Return the immutable loopback bind address."""
        return self._host

    @property
    def address(self) -> tuple[str, int]:
        """Return the host and port selected for the first bound socket."""
        if self._server is None or not self._server.sockets:
            raise RuntimeError("master server is not running")
        host, port, *_ = self._server.sockets[0].getsockname()
        return str(host), int(port)

    async def start(self) -> None:
        """Bind the master on its validated loopback address."""
        if self._server is not None:
            raise RuntimeError("master server is already running")
        self._closing = False
        host = validate_bind_host(self._host)
        self._server = await asyncio.start_server(
            self._client_connected, host, self.port
        )

    async def serve_forever(self) -> None:
        """Serve connections until the server is closed or cancelled."""
        if self._server is None:
            raise RuntimeError("master server is not running")
        await self._server.serve_forever()

    async def close(self) -> None:
        """Stop accepting connections and shut down active client handlers."""
        server = self._server
        if server is None:
            return

        self._closing = True
        server.close()
        for writer in tuple(self._client_writers):
            writer.close()

        current_task = asyncio.current_task()
        client_tasks = tuple(
            task for task in self._client_tasks if task is not current_task
        )
        for task in client_tasks:
            task.cancel()
        if client_tasks:
            await asyncio.gather(*client_tasks, return_exceptions=True)

        await server.wait_closed()
        self._server = None

    def _client_connected(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Own a client connection and its handler task until completion."""
        if self._closing:
            writer.close()
            return
        self._client_writers.add(writer)
        task = asyncio.create_task(self._handle_client(reader, writer))
        self._client_tasks.add(task)
        task.add_done_callback(
            lambda completed: self._client_task_done(completed, writer)
        )

    def _client_task_done(
        self, task: asyncio.Task[None], writer: asyncio.StreamWriter
    ) -> None:
        self._client_tasks.discard(task)
        self._client_writers.discard(writer)
        if not task.cancelled():
            task.exception()

    async def _send_response(
        self, writer: asyncio.StreamWriter, response: dict[str, Any]
    ) -> None:
        try:
            encoded = json.dumps(response).encode("utf-8")
        except (TypeError, ValueError) as exc:
            encoded = json.dumps(_failure(exc)).encode("utf-8")
        try:
            await write_frame(writer, encoded, self._fernet, self.max_frame_size)
        except ProtocolError:
            failure = json.dumps(
                {
                    "status": "failed",
                    "error": "response exceeds maximum frame size",
                },
                separators=(",", ":"),
            ).encode("utf-8")
            try:
                await write_frame(writer, failure, self._fernet, self.max_frame_size)
            except ProtocolError:
                pass

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            try:
                payload = await read_frame(reader, self._fernet, self.max_frame_size)
            except ProtocolError:
                return

            try:
                envelope = validate_envelope(json.loads(payload.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
                response = _failure(exc)
            else:
                try:
                    response = run_local(deserialize_request(envelope["data"]))
                except Exception as exc:
                    response = _failure(exc)
            await self._send_response(writer, response)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            finally:
                self._client_writers.discard(writer)


def _failure(exc: Exception) -> dict[str, str]:
    message = str(exc) or exc.__class__.__name__
    return {"status": "failed", "error": message}


async def _serve(master: MiniWazuhMaster) -> None:
    await master.start()
    host, port = master.address
    print(f"Listening on {host}:{port} (loopback only).")
    try:
        await master.serve_forever()
    finally:
        await master.close()


def main(argv: Sequence[str] | None = None) -> int:
    """Run the loopback-only master with an execution-scope warning."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=validate_bind_host, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1516)
    parser.add_argument(
        "--cluster-secret",
        default=os.environ.get("MINI_WAZUH_CLUSTER_SECRET", DEFAULT_CLUSTER_SECRET),
    )
    parser.add_argument("--max-frame-size", type=int, default=DEFAULT_MAX_FRAME_SIZE)
    args = parser.parse_args(argv)

    print(
        "WARNING: Local Mini Wazuh cluster simulator.\n"
        "This process executes worker-supplied shell commands with its own privileges.\n"
        "Bind only to loopback and use only in an authorized, isolated lab."
    )
    master = MiniWazuhMaster(
        host=args.host,
        port=args.port,
        cluster_secret=args.cluster_secret,
        max_frame_size=args.max_frame_size,
    )
    try:
        asyncio.run(_serve(master))
    except KeyboardInterrupt:
        return 0
    return 0
