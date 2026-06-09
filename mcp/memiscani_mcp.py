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
    p = os.environ.get("MEMISCANI_MCP_TOKEN_FILE")
    if p:
        return p
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "memiscani", "mcp_token")


def _read_token() -> str:
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
    deadline = time.time() + max_seconds
    while time.time() < deadline:
        st = _call("scan_status")
        if not st.get("running"):
            return st
        time.sleep(0.15)
    return _call("scan_status")


@mcp.tool()
def status() -> dict:
    return _call("status")


@mcp.tool()
def list_processes(name: str = "") -> dict:
    return _call("list_processes", {"name": name})


@mcp.tool()
def attach(pid: int = 0, name: str = "") -> dict:
    args: dict[str, Any] = {}
    if pid:
        args["pid"] = pid
    elif name:
        args["name"] = name
    return _call("attach", args)


@mcp.tool()
def detach() -> dict:
    return _call("detach")


@mcp.tool()
def list_modules() -> dict:
    return _call("list_modules")

@mcp.tool()
def read(addr: str, type: str = "int32", len: int = 64) -> dict:
    return _call("read", {"addr": addr, "type": type, "len": len})


@mcp.tool()
def read_bytes(addr: str, size: int = 64) -> dict:
    return _call("read_bytes", {"addr": addr, "size": size})


@mcp.tool()
def write(addr: str, type: str, value: str, bypass: bool = True) -> dict:
    return _call("write", {"addr": addr, "type": type, "value": value, "bypass": bypass})


@mcp.tool()
def write_bytes(addr: str, hex: str, bypass: bool = True) -> dict:
    return _call("write_bytes", {"addr": addr, "hex": hex, "bypass": bypass})


@mcp.tool()
def disasm(addr: str, bytes: int = 64, count: int = 16) -> dict:
    return _call("disasm", {"addr": addr, "bytes": bytes, "count": count})


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
    started = _call("scan_next", {"match": match, "value": value})
    if wait:
        return _wait_for_scan()
    return started


@mcp.tool()
def scan_status() -> dict:
    return _call("scan_status")


@mcp.tool()
def get_results(offset: int = 0, limit: int = 200) -> dict:
    return _call("get_results", {"offset": offset, "limit": limit})


@mcp.tool()
def clear_scan() -> dict:
    return _call("clear_scan")


@mcp.tool()
def guess_type(addr: str) -> dict:
    return _call("guess_type", {"addr": addr})


@mcp.tool()
def pointer_chain_resolve(moduleName: str = "", moduleOffset: str = "0",
                          offsets: Optional[list] = None) -> dict:
    return _call("pointer_chain_resolve", {
        "moduleName": moduleName, "moduleOffset": moduleOffset,
        "offsets": offsets or [],
    })


@mcp.tool()
def aob_signature(addr: str, minLen: int = 12, maxLen: int = 64) -> dict:
    return _call("aob_signature", {"addr": addr, "minLen": minLen, "maxLen": maxLen})


@mcp.tool()
def run_lua(source: str) -> dict:
    return _call("run_lua", {"source": source})


@mcp.tool()
def lua_status() -> dict:
    return _call("lua_status")


@mcp.tool()
def lua_stop() -> dict:
    return _call("lua_stop")


@mcp.tool()
def lua_log(clear: bool = False) -> dict:
    return _call("lua_log", {"clear": clear})


if __name__ == "__main__":
    mcp.run()
