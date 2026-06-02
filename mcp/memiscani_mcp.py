#!/usr/bin/env python3
"""
memiscani MCP bridge.

Exposes the running memiscani GUI's memory-analysis tools to an MCP client
(e.g. Claude Code) by forwarding each tool call as a newline-delimited JSON
command to the GUI's loopback TCP server (mem_ipc, default 127.0.0.1:8377).

Requirements:
    pip install mcp
Run (normally launched by the MCP client via .mcp.json):
    python mcp/memiscani_mcp.py

The memiscani GUI must be running with its MCP server listening (shown as
"MCP :8377" in the status bar).
"""
import json
import os
import socket
import time
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

HOST = "127.0.0.1"
PORT = int(os.environ.get("MEMISCANI_MCP_PORT", "8377"))
TIMEOUT = float(os.environ.get("MEMISCANI_MCP_TIMEOUT", "10"))

mcp = FastMCP("memiscani")


class MemiscaniError(RuntimeError):
    pass


def _token_path() -> str:
    """Location of the per-user auth token file written by the GUI."""
    p = os.environ.get("MEMISCANI_MCP_TOKEN_FILE")
    if p:
        return p
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "memiscani", "mcp_token")


def _read_token() -> str:
    """Read the auth token (env override first, then the token file)."""
    t = os.environ.get("MEMISCANI_MCP_TOKEN")
    if t:
        return t.strip()
    try:
        with open(_token_path(), "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


_TOKEN = _read_token()


def _call(cmd: str, args: Optional[dict] = None, _retry: bool = True) -> dict:
    """Send one command to the GUI (with the auth token) and return its result."""
    global _TOKEN
    payload = json.dumps({"id": 1, "cmd": cmd, "args": args or {}, "token": _TOKEN}) + "\n"
    try:
        with socket.create_connection((HOST, PORT), timeout=TIMEOUT) as s:
            s.settimeout(TIMEOUT)
            s.sendall(payload.encode("utf-8"))
            buf = bytearray()
            while b"\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
    except (ConnectionRefusedError, OSError) as e:
        raise MemiscaniError(
            f"Could not reach memiscani on {HOST}:{PORT} ({e}). "
            "Is the GUI running with the MCP server on? (status bar shows 'MCP :8377')"
        )
    line = bytes(buf).split(b"\n", 1)[0].decode("utf-8", "replace")
    if not line:
        raise MemiscaniError("Empty response from memiscani")
    resp = json.loads(line)
    if not resp.get("ok"):
        err = resp.get("error", "unknown error")
        # Token may be stale (GUI restarted -> new token). Re-read once and retry.
        if _retry and "unauthorized" in err.lower():
            _TOKEN = _read_token()
            if _TOKEN:
                return _call(cmd, args, _retry=False)
            raise MemiscaniError(
                "unauthorized and no token found. Is the GUI running? "
                f"Expected token file at {_token_path()}"
            )
        raise MemiscaniError(err)
    return resp.get("result", {})


def _wait_for_scan(max_seconds: float = 120.0) -> dict:
    """Block until the current scan finishes (or times out); return scan_status."""
    deadline = time.time() + max_seconds
    while time.time() < deadline:
        st = _call("scan_status")
        if not st.get("running"):
            return st
        time.sleep(0.15)
    return _call("scan_status")


# ---------------------------------------------------------------------------
# Session / process
# ---------------------------------------------------------------------------
@mcp.tool()
def status() -> dict:
    """Get the live memiscani session state: attached pid, base address, scan
    running flag, current result count, live-monitor/lua status, and MCP stats."""
    return _call("status")


@mcp.tool()
def list_processes(name: str = "") -> dict:
    """List running processes, optionally filtered by a case-sensitive substring
    of the process name. Returns [{pid, name}]."""
    return _call("list_processes", {"name": name})


@mcp.tool()
def attach(pid: int = 0, name: str = "") -> dict:
    """Attach to a target process by pid or by name substring (first match).
    Returns {attached, pid, base}."""
    args: dict[str, Any] = {}
    if pid:
        args["pid"] = pid
    elif name:
        args["name"] = name
    return _call("attach", args)


@mcp.tool()
def detach() -> dict:
    """Detach from the current process (closes the handle, keeps scan results)."""
    return _call("detach")


@mcp.tool()
def list_modules() -> dict:
    """List loaded modules in the attached process: [{name, base, size, path}]."""
    return _call("list_modules")


# ---------------------------------------------------------------------------
# Read / write
# ---------------------------------------------------------------------------
@mcp.tool()
def read(addr: str, type: str = "int32", len: int = 64) -> dict:
    """Read a typed value at an address. addr is hex ("0x...") or decimal.
    type: int8/int16/int32/int64/float/double/string/aob. For string/aob, `len`
    is the number of bytes to read (max 1024). Returns {addr, type, value, hex}."""
    return _call("read", {"addr": addr, "type": type, "len": len})


@mcp.tool()
def read_bytes(addr: str, size: int = 64) -> dict:
    """Read raw bytes at an address (max 4096). Returns {addr, size, hex}."""
    return _call("read_bytes", {"addr": addr, "size": size})


@mcp.tool()
def write(addr: str, type: str, value: str, bypass: bool = True) -> dict:
    """Write a typed numeric value at an address. type: int8/16/32/64/float/double.
    value is a string ("1234", "0x1F", "3.5"). bypass=True flips page protection
    if needed. For strings/bytes use write_bytes."""
    return _call("write", {"addr": addr, "type": type, "value": value, "bypass": bypass})


@mcp.tool()
def write_bytes(addr: str, hex: str, bypass: bool = True) -> dict:
    """Write raw bytes at an address. `hex` is like "90 90 C3" or "0x90,0x90".
    bypass=True flips page protection if needed. Returns {addr, count}."""
    return _call("write_bytes", {"addr": addr, "hex": hex, "bypass": bypass})


@mcp.tool()
def disasm(addr: str, bytes: int = 64, count: int = 16) -> dict:
    """Disassemble up to `count` x86-64 instructions starting at addr, reading at
    most `bytes` bytes. Returns {lines:[{addr, bytes, text}]}."""
    return _call("disasm", {"addr": addr, "bytes": bytes, "count": count})


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
@mcp.tool()
def scan_first(
    type: str = "int32",
    match: str = "exact",
    value: str = "",
    writableOnly: bool = True,
    skipImage: bool = False,
    executableOnly: bool = False,
    workingSetOnly: bool = False,
    skipZero: bool = False,
    alignment: int = 0,
    maxResults: int = 100000,
    strEnc: int = 2,
    caseInsensitive: bool = False,
    addrMin: str = "",
    addrMax: str = "",
    wait: bool = True,
) -> dict:
    """Start a first scan and (by default) wait for it to finish.
    type: int8/16/32/64/float/double/string/aob.
    match: exact/changed/unchanged/increased/decreased/unknown.
    value: the value/string/AOB pattern to search for (empty for 'unknown').
    strEnc (string only): 0=ASCII, 1=UTF-16, 2=Both. caseInsensitive: string only.
    Returns scan_status {running,count} when wait=True, else {started,type}."""
    args: dict[str, Any] = {
        "type": type, "match": match, "value": value,
        "writableOnly": writableOnly, "skipImage": skipImage,
        "executableOnly": executableOnly, "workingSetOnly": workingSetOnly,
        "skipZero": skipZero, "alignment": alignment, "maxResults": maxResults,
        "strEnc": strEnc, "caseInsensitive": caseInsensitive,
    }
    if addrMin:
        args["addrMin"] = addrMin
    if addrMax:
        args["addrMax"] = addrMax
    started = _call("scan_first", args)
    if wait:
        return _wait_for_scan()
    return started


@mcp.tool()
def scan_next(match: str = "changed", value: str = "", wait: bool = True) -> dict:
    """Refine the current results with a next scan using the same data type.
    match: exact/changed/unchanged/increased/decreased/unknown.
    Returns scan_status {running,count} when wait=True."""
    started = _call("scan_next", {"match": match, "value": value})
    if wait:
        return _wait_for_scan()
    return started


@mcp.tool()
def scan_status() -> dict:
    """Return {running, count} for the current/last scan."""
    return _call("scan_status")


@mcp.tool()
def get_results(offset: int = 0, limit: int = 200) -> dict:
    """Fetch a window of scan results with live values:
    {results:[{index, addr, value}], total, type}. limit max 1000."""
    return _call("get_results", {"offset": offset, "limit": limit})


@mcp.tool()
def clear_scan() -> dict:
    """Clear all scan results, snapshot, and live-monitor data."""
    return _call("clear_scan")


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
@mcp.tool()
def guess_type(addr: str) -> dict:
    """Heuristically rank plausible data types at an address:
    {guesses:[{type, formatted, plausibility, reason}]}."""
    return _call("guess_type", {"addr": addr})


@mcp.tool()
def pointer_chain_resolve(moduleName: str = "", moduleOffset: str = "0",
                          offsets: Optional[list] = None) -> dict:
    """Resolve a pointer chain: base = module(moduleName)+moduleOffset (or a raw
    address if moduleName empty), then dereference through `offsets` (list of hex
    or int). Returns {addr}."""
    return _call("pointer_chain_resolve", {
        "moduleName": moduleName, "moduleOffset": moduleOffset,
        "offsets": offsets or [],
    })


@mcp.tool()
def aob_signature(addr: str, minLen: int = 12, maxLen: int = 64) -> dict:
    """Generate a unique AOB signature for the code at addr (marks relocatable
    bytes as wildcards). Returns {pattern, length, wildcards, hits, unique}."""
    return _call("aob_signature", {"addr": addr, "minLen": minLen, "maxLen": maxLen})


# ---------------------------------------------------------------------------
# Lua scripting (runs against the target via the memiscani Lua engine)
# ---------------------------------------------------------------------------
@mcp.tool()
def run_lua(source: str) -> dict:
    """Run a Lua script in the memiscani engine against the attached process.
    Available globals: mem.attach/detach/pid/base/find_module/read_typed/
    write_typed/read_bytes/write_bytes/alloc/free/disasm/aob_scan/sleep/protect,
    plus log()/print(). Use lua_log to read output. Returns {started}."""
    return _call("run_lua", {"source": source})


@mcp.tool()
def lua_status() -> dict:
    """Return {running} for the Lua engine."""
    return _call("lua_status")


@mcp.tool()
def lua_stop() -> dict:
    """Request the running Lua script to stop."""
    return _call("lua_stop")


@mcp.tool()
def lua_log(clear: bool = False) -> dict:
    """Fetch the Lua output log lines. Set clear=True to also clear it afterwards.
    Returns {lines:[...]}."""
    return _call("lua_log", {"clear": clear})


if __name__ == "__main__":
    mcp.run()
