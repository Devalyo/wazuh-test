"""Worker and command clients for the loopback-only Mini Wazuh simulator."""

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from mini_wazuh.crypto import DEFAULT_CLUSTER_SECRET, build_fernet
from mini_wazuh.protocol import (
    DEFAULT_MAX_FRAME_SIZE,
    ProtocolError,
    read_frame,
    write_frame,
)


class WorkerError(Exception):
    """Report a worker-side transport or response problem."""


def build_command_payload(command: str) -> dict[str, Any]:
    """Build the published callable payload without changing its command."""
    return {
        "f": {
            "__callable__": {
                "__name__": "getoutput",
                "__module__": "subprocess",
                "__qualname__": "getoutput",
            }
        },
        "f_kwargs": {"cmd": command},
        "request_type": "local_master",
    }


async def send_dapi(
    payload: Mapping[str, Any] | str,
    host: str = "127.0.0.1",
    port: int = 1516,
    cluster_secret: str = DEFAULT_CLUSTER_SECRET,
    node: str = "worker01",
    max_frame_size: int = DEFAULT_MAX_FRAME_SIZE,
) -> dict[str, Any]:
    """Send one authenticated DAPI request and return its object response."""
    writer: asyncio.StreamWriter | None = None
    try:
        inner_data = (
            payload
            if isinstance(payload, str)
            else json.dumps(dict(payload), separators=(",", ":"))
        )
        envelope = json.dumps(
            {"node": node, "command": "dapi", "data": inner_data},
            separators=(",", ":"),
        ).encode("utf-8")
        reader, writer = await asyncio.open_connection(host, port)
        fernet = build_fernet(cluster_secret)
        await write_frame(writer, envelope, fernet, max_frame_size)
        encoded_response = await read_frame(reader, fernet, max_frame_size)
        response = json.loads(encoded_response.decode("utf-8"))
        if not isinstance(response, dict):
            raise WorkerError("master response must be a top-level JSON object")
        return response
    except WorkerError:
        raise
    except (
        ConnectionError,
        OSError,
        ProtocolError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        message = str(exc) or exc.__class__.__name__
        raise WorkerError(message) from exc
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


def _add_connection_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1516)
    parser.add_argument("--node", default="worker01")
    parser.add_argument(
        "--cluster-secret",
        default=os.environ.get("MINI_WAZUH_CLUSTER_SECRET", DEFAULT_CLUSTER_SECRET),
    )
    parser.add_argument("--max-frame-size", type=int, default=DEFAULT_MAX_FRAME_SIZE)


def _send_from_args(payload: Mapping[str, Any] | str, args: Any) -> dict[str, Any]:
    return asyncio.run(
        send_dapi(
            payload,
            host=args.host,
            port=args.port,
            cluster_secret=args.cluster_secret,
            node=args.node,
            max_frame_size=args.max_frame_size,
        )
    )


def _print_worker_error(exc: Exception) -> None:
    message = str(exc) or exc.__class__.__name__
    print(json.dumps({"status": "failed", "error": message}, indent=2), file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    """Send a raw JSON string or file as a generic DAPI worker request."""
    parser = argparse.ArgumentParser(description=__doc__)
    payload_group = parser.add_mutually_exclusive_group(required=True)
    payload_group.add_argument("--payload")
    payload_group.add_argument("--payload-file", type=Path)
    _add_connection_options(parser)
    args = parser.parse_args(argv)

    try:
        payload = (
            args.payload
            if args.payload is not None
            else args.payload_file.read_text(encoding="utf-8")
        )
        response = _send_from_args(payload, args)
    except (WorkerError, OSError, UnicodeError) as exc:
        _print_worker_error(exc)
        return 1

    print(json.dumps(response, indent=2))
    return 0 if response.get("status") == "success" else 1


def command_main(argv: Sequence[str] | None = None) -> int:
    """Demonstrate authorized master-side command execution in the local lab."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command", required=True)
    _add_connection_options(parser)
    args = parser.parse_args(argv)

    print(
        "WARNING: authorized loopback lab only; this executes the supplied command "
        "on the Mini Wazuh master.",
        file=sys.stderr,
    )
    try:
        response = _send_from_args(build_command_payload(args.command), args)
    except WorkerError as exc:
        _print_worker_error(exc)
        return 1

    if response.get("status") == "success":
        print(response.get("result", ""))
        return 0

    print(json.dumps(response, indent=2), file=sys.stderr)
    return 1
