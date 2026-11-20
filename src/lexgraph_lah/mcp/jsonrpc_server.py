"""Backward-compatible re-export wrapper for `lexgraph_lah.mcp.jsonrpc`."""

from lexgraph_lah.mcp.jsonrpc import (
    MCP_PROTOCOL_VERSION,
    SERVER_INFO,
    get_mcp_jsonrpc_tools,
    handle_jsonrpc_message,
    main,
    run_stdio_server,
)

__all__ = [
    "MCP_PROTOCOL_VERSION",
    "SERVER_INFO",
    "get_mcp_jsonrpc_tools",
    "handle_jsonrpc_message",
    "main",
    "run_stdio_server",
]

if __name__ == "__main__":
    raise SystemExit(main())
