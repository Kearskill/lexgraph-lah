"""
Native JSON-RPC 2.0 MCP Server (Streamable HTTP `POST /mcp` & `--stdio` CLI).

Implements standard MCP JSON-RPC 2.0 methods (`initialize`, `notifications/initialized`,
`ping`, `tools/list`, `tools/call`) wrapping all 11 deterministic and agentic tools
in `mcp/tools.py`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any, TextIO

from pydantic import ValidationError

from lexgraph_lah.mcp.tools import MCP_TOOL_DEFINITIONS, dispatch_mcp_tool_async

MCP_PROTOCOL_VERSION = "2025-03-26"
SERVER_INFO: dict[str, str] = {
    "name": "lexgraph-lah",
    "version": "0.3.0",
}


def get_mcp_jsonrpc_tools() -> list[dict[str, Any]]:
    """Returns MCP tool definitions formatted with `name`, `description`, `inputSchema`."""
    return [
        {
            "name": tool["name"],
            "description": tool["description"],
            "inputSchema": tool["inputSchema"],
        }
        for tool in MCP_TOOL_DEFINITIONS
    ]


def _jsonrpc_error(
    req_id: Any, code: int, message: str, data: Any | None = None
) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _jsonrpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


async def handle_jsonrpc_message(payload: Any) -> dict[str, Any] | None:
    """
    Processes a single JSON-RPC 2.0 MCP request dict.
    Returns `None` for notifications (requests omitting `id`).
    """
    if not isinstance(payload, dict):
        return _jsonrpc_error(None, -32600, "Invalid Request: expected JSON object.")

    req_id = payload.get("id")
    if payload.get("jsonrpc") != "2.0":
        return _jsonrpc_error(
            req_id, -32600, "Invalid Request: 'jsonrpc' must equal '2.0'."
        )

    method = payload.get("method")
    if not isinstance(method, str) or not method.strip():
        return _jsonrpc_error(
            req_id, -32600, "Invalid Request: 'method' must be a non-empty string."
        )

    # Notifications omit "id" (e.g. notifications/initialized) and receive no JSON-RPC response payload.
    if "id" not in payload:
        return None

    params = payload.get("params")
    if params is not None and not isinstance(params, dict):
        return _jsonrpc_error(
            req_id, -32602, "Invalid params: 'params' must be an object when present."
        )
    params_dict: dict[str, Any] = params or {}

    if method == "initialize":
        return _jsonrpc_result(
            req_id,
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
            },
        )

    if method == "ping":
        return _jsonrpc_result(req_id, {})

    if method == "tools/list":
        return _jsonrpc_result(req_id, {"tools": get_mcp_jsonrpc_tools()})

    if method == "tools/call":
        tool_name = params_dict.get("name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            return _jsonrpc_error(
                req_id, -32602, "Invalid params: tools/call requires 'name' string."
            )
        arguments = params_dict.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return _jsonrpc_error(
                req_id, -32602, "Invalid params: 'arguments' must be an object."
            )

        try:
            tool_output = await dispatch_mcp_tool_async(tool_name, arguments)
        except (KeyError, ValueError, ValidationError) as exc:
            return _jsonrpc_error(req_id, -32602, str(exc))
        except (RuntimeError, TypeError) as exc:  # pragma: no cover
            return _jsonrpc_error(req_id, -32603, f"Internal error: {exc}")

        return _jsonrpc_result(
            req_id,
            {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(tool_output, ensure_ascii=False),
                    }
                ],
                "structuredContent": tool_output,
                "isError": False,
            },
        )

    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


async def _process_stdio_async(stdin: TextIO, stdout: TextIO) -> None:
    while True:
        line = stdin.readline()
        if not line:
            break
        stripped = line.strip()
        if not stripped:
            continue
        try:
            msg = json.loads(stripped)
        except json.JSONDecodeError as exc:
            err_resp = _jsonrpc_error(None, -32700, f"Parse error: {exc}")
            stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
            stdout.flush()
            continue

        resp = await handle_jsonrpc_message(msg)
        if resp is not None:
            stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            stdout.flush()


def run_stdio_server(
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Runs the newline-delimited JSON-RPC 2.0 MCP server over stdio."""
    in_stream = stdin or sys.stdin
    out_stream = stdout or sys.stdout
    asyncio.run(_process_stdio_async(in_stream, out_stream))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="lexgraph-lah JSON-RPC 2.0 MCP Server (stdio transport)"
    )
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Serve JSON-RPC 2.0 MCP messages over stdin/stdout.",
    )
    args = parser.parse_args(argv)
    if args.stdio or argv is None:
        run_stdio_server()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
