# Proc Mem Analysis tool - Memiscani MCP — Full install

## Features - Memory Tools + Workflow Guides + MCP Connection
<img width="1900" height="1200" alt="memiscanigitrepo" src="https://github.com/user-attachments/assets/30495818-9caf-44c6-b48e-bf5849ce9a17" />
<img width="1900" height="1200" alt="memiscanigitrepoclaude" src="https://github.com/user-attachments/assets/cc3220cc-7d32-4544-9980-391ea719c646" />


## 1. Install MinGW-w64 (the C/C++ compiler)

The build needs `gcc`, `g++`, and `ar` (the archiver) in `PATH`.  Pick
**one** of the options below.


## 2. Create project folder

At minimum you need these files / directories in the project root:

```
memiscani_im.cpp
memcore.cpp / memcore.h
mem_lua.cpp / mem_lua.h
mem_ipc.cpp / mem_ipc.h      (optional MCP/IPC server - see section 6)
Zydis.c / Zydis.h
build.bat
```

For the optional MCP integration (section 6) you also need:

```
.mcp.json
mcp\memiscani_mcp.py
```

You do **not** need to get `imgui\`, `lua54\`, or `json.hpp` — `build.bat setup`
will clone/download them.

The tool uses Zydis disassembler to decode - so you must download the Zydis source and header file from https://github.com/zyantific/zydis/releases/tag/v4.1.0.

---

## 3. Setup

From the project root in `cmd`:

```cmd
build.bat setup
```

This does, in order:

1. Creates `build\`, `obj\`, and `obj\lua\`.
2. **Clones Dear ImGui v1.91.5** into `imgui\` (~10 MB git clone).
3. **Clones Lua 5.4.7** into `lua54\` (~3 MB git clone).
4. **Downloads nlohmann/json v3.11.3** single header `json.hpp` (used by the MCP/IPC server).
5. Compiles `Zydis.c` → `obj\Zydis.o`.
6. Compiles 32 Lua source files → `obj\lua\*.o`, then archives them
   into `obj\liblua54.a`.


## 4. Pre-compile ImGui 

```cmd
build.bat imgui
```

## 5. Build

```cmd
build.bat full
```

---

## 6. (Optional) MCP server — drive Memiscani from an AI agent (Claude)

Memiscani can expose its tools over an **MCP** connection

### Flow

```
Claude ──stdio MCP──▶  mcp\memiscani_mcp.py  ──loopback TCP JSON──▶  memiscani_im.exe
                              (Python bridge)        127.0.0.1:8377          (mem_ipc server,
                                                     token-authenticated)     runs on the UI thread)
                                                                              │
                                                                              ├─ memcore  (attach / scan / read / write / disasm / …)
                                                                              └─ mem_lua  (run scripts against the target)
```

The TCP command server (`mem_ipc`) is compiled into `memiscani_im.exe` and starts
automatically. When it is listening, the status bar shows **`MCP :8377`**.

### Requirements

- **Python with the MCP package:
  ```cmd
  pip install mcp
  ```
- These files in the repo: `mem_ipc.cpp` / `mem_ipc.h` (compiled into the exe),
  `mcp\memiscani_mcp.py`, and `.mcp.json`.

### Setup

1. Build and launch `memiscani_im.exe` (sections 1–5). Confirm the status bar
   shows **`MCP :8377`**.
2. Install the Python package: `pip install mcp`.
3. The included **`.mcp.json`** registers the server with Claude for this
   project. **Restart / reload Claude ** so it picks up the new server, then
   approve the `memiscani` server when prompted. Verify with `/mcp` (it should
   list `memiscani` and its tools).

### Security

- Loopback only bound to `127.0.0.1`
- Token authentication 
- Anti-CSRF / anti-probe
- Flood guards

### Available tools

| Group | Tools |
|-------|-------|
| Session | `status`, `list_processes`, `attach`, `detach`, `list_modules` |
| Read / write | `read`, `read_bytes`, `write`, `write_bytes`, `disasm` |
| Scanning | `scan_first`, `scan_next`, `scan_status`, `get_results`, `clear_scan` |
| Analysis | `guess_type`, `pointer_chain_resolve`, `aob_signature` |
| Lua scripting | `run_lua`, `lua_status`, `lua_stop`, `lua_log` |


### Quick test (without an MCP client)

PowerShell, with the memiscani GUI running:

```powershell
python -c "import socket,json,os; t=open(os.environ['LOCALAPPDATA']+r'\memiscani\mcp_token').read().strip(); s=socket.create_connection(('127.0.0.1',8377)); s.sendall((json.dumps({'cmd':'status','token':t})+'\n').encode()); print(s.recv(65536))"
```

A successful response looks like:

```json
{"id":1,"ok":true,"result":{"attached":false,"base":"0x0","scanRunning":false, ...}}
```

### DISCLAIMER
This code is for educational and research purposes only. Please use with caution.
