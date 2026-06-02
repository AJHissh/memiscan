#include <windows.h>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <thread>

extern "C" {
#include "lua54/lua.h"
#include "lua54/lauxlib.h"
#include "lua54/lualib.h"
}

#include "memcore.h"

namespace memlua {

// -- console output --------------------------------------------------------
static std::mutex             s_logMtx;
static std::vector<std::string> s_log;
static std::atomic<bool>      s_running{false};
static std::atomic<bool>      s_stopReq{false};
static std::thread            s_thread;
static lua_State*             s_L = nullptr;
static std::mutex             s_LMtx;

void log(const std::string& line) {
    std::lock_guard<std::mutex> lk(s_logMtx);
    if (s_log.size() > 5000) s_log.erase(s_log.begin(), s_log.begin() + 1000);
    s_log.push_back(line);
}
std::vector<std::string> snapshotLog() {
    std::lock_guard<std::mutex> lk(s_logMtx);
    return s_log;
}
void clearLog() {
    std::lock_guard<std::mutex> lk(s_logMtx);
    s_log.clear();
}
bool isRunning() { return s_running.load(); }
void requestStop() { s_stopReq = true; }

// -- helpers ---------------------------------------------------------------
static uintptr_t asAddr(lua_State* L, int idx) {
    if (lua_isinteger(L, idx)) return (uintptr_t)lua_tointeger(L, idx);
    if (lua_isnumber(L, idx))  return (uintptr_t)lua_tonumber(L, idx);
    if (lua_isstring(L, idx))  return (uintptr_t)mem::parseHexAwareInt(lua_tostring(L, idx));
    luaL_error(L, "expected address (integer or hex string)");
    return 0;
}

static int line_hook_check_stop(lua_State* L, lua_Debug* /*ar*/) {
    if (s_stopReq.load()) luaL_error(L, "script stopped by user");
    return 0;
}
static void install_stop_hook(lua_State* L) {
    lua_sethook(L, (lua_Hook)line_hook_check_stop, LUA_MASKCOUNT, 1000);
}

// -- bindings --------------------------------------------------------------
static int l_log(lua_State* L) {
    int n = lua_gettop(L);
    std::string out;
    for (int i = 1; i <= n; i++) {
        if (i > 1) out += "\t";
        size_t len = 0;
        const char* s = luaL_tolstring(L, i, &len); // converts everything to string
        out.append(s, len);
        lua_pop(L, 1);
    }
    log(out);
    return 0;
}

static int l_attach(lua_State* L) {
    DWORD pid = (DWORD)luaL_checkinteger(L, 1);
    lua_pushboolean(L, mem::attach(pid));
    return 1;
}
static int l_detach(lua_State* L) { (void)L; mem::detach(); return 0; }
static int l_pid(lua_State* L) {
    lua_pushinteger(L, mem::attachedPid());
    return 1;
}
static int l_base(lua_State* L) {
    lua_pushinteger(L, (lua_Integer)(uintptr_t)mem::baseAddress());
    return 1;
}

static int l_find_module(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    HMODULE m = mem::findRemoteModuleByName(name);
    if (!m) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, (lua_Integer)(uintptr_t)m);
    return 1;
}

template <typename T>
static int l_read_typed(lua_State* L) {
    uintptr_t a = asAddr(L, 1);
    if (!mem::isAttached()) { lua_pushnil(L); return 1; }
    T v{};
    SIZE_T r = 0;
    if (!ReadProcessMemory(mem::processHandle(), (LPVOID)a, &v, sizeof(v), &r) || r < sizeof(v)) { lua_pushnil(L); return 1; }
    if constexpr (std::is_floating_point_v<T>) lua_pushnumber(L, (lua_Number)v);
    else                                       lua_pushinteger(L, (lua_Integer)v);
    return 1;
}
template <typename T>
static int l_write_typed(lua_State* L) {
    uintptr_t a = asAddr(L, 1);
    T v;
    if constexpr (std::is_floating_point_v<T>) v = (T)luaL_checknumber(L, 2);
    else                                       v = (T)luaL_checkinteger(L, 2);
    if (!mem::isAttached()) { lua_pushboolean(L, 0); return 1; }
    DWORD oldProt = 0;
    VirtualProtectEx(mem::processHandle(), (LPVOID)a, sizeof(v), PAGE_EXECUTE_READWRITE, &oldProt);
    SIZE_T wr = 0;
    BOOL ok = WriteProcessMemory(mem::processHandle(), (LPVOID)a, &v, sizeof(v), &wr);
    DWORD tmp; VirtualProtectEx(mem::processHandle(), (LPVOID)a, sizeof(v), oldProt, &tmp);
    lua_pushboolean(L, ok && wr == sizeof(v));
    return 1;
}

static int l_read_bytes(lua_State* L) {
    uintptr_t a = asAddr(L, 1);
    size_t n = (size_t)luaL_checkinteger(L, 2);
    if (n == 0 || n > 1024*1024) { lua_pushnil(L); return 1; }
    std::vector<BYTE> buf(n);
    SIZE_T r = 0;
    if (!mem::isAttached() || !ReadProcessMemory(mem::processHandle(), (LPVOID)a, buf.data(), n, &r) || r == 0) { lua_pushnil(L); return 1; }
    lua_pushlstring(L, (const char*)buf.data(), r);
    return 1;
}
static int l_write_bytes(lua_State* L) {
    uintptr_t a = asAddr(L, 1);
    size_t n = 0;
    const char* s = luaL_checklstring(L, 2, &n);
    DWORD oldProt = 0;
    VirtualProtectEx(mem::processHandle(), (LPVOID)a, n, PAGE_EXECUTE_READWRITE, &oldProt);
    SIZE_T wr = 0;
    BOOL ok = WriteProcessMemory(mem::processHandle(), (LPVOID)a, s, n, &wr);
    DWORD tmp; VirtualProtectEx(mem::processHandle(), (LPVOID)a, n, oldProt, &tmp);
    lua_pushboolean(L, ok && wr == n);
    return 1;
}

static int l_alloc(lua_State* L) {
    size_t n = (size_t)luaL_checkinteger(L, 1);
    if (!mem::isAttached()) { lua_pushnil(L); return 1; }
    LPVOID p = VirtualAllocEx(mem::processHandle(), NULL, n, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!p) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, (lua_Integer)(uintptr_t)p);
    return 1;
}
static int l_free(lua_State* L) {
    uintptr_t a = asAddr(L, 1);
    if (!mem::isAttached()) { lua_pushboolean(L, 0); return 1; }
    lua_pushboolean(L, !!VirtualFreeEx(mem::processHandle(), (LPVOID)a, 0, MEM_RELEASE));
    return 1;
}

static int l_disasm(lua_State* L) {
    uintptr_t a = asAddr(L, 1);
    std::string s = mem::disasmOneAtRemote((LPVOID)a);
    lua_pushstring(L, s.c_str());
    return 1;
}
static int l_disasm_range(lua_State* L) {
    uintptr_t a = asAddr(L, 1);
    size_t n = (size_t)luaL_checkinteger(L, 2);
    auto v = mem::disasmRangeAtRemote((LPVOID)a, n, 1024);
    lua_newtable(L);
    int idx = 1;
    for (auto& l : v) {
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)l.addr); lua_setfield(L, -2, "addr");
        lua_pushlstring(L, (const char*)l.bytes.data(), l.bytes.size()); lua_setfield(L, -2, "bytes");
        lua_pushstring(L, l.text.c_str()); lua_setfield(L, -2, "text");
        lua_rawseti(L, -2, idx++);
    }
    return 1;
}

static int l_aob_scan(lua_State* L) {
    const char* pat = luaL_checkstring(L, 1);
    // Parse pattern "48 8B ?? ?? ?? ?? 90"
    std::vector<BYTE> bytes; std::vector<bool> mask;
    const char* p = pat;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!*p) break;
        if (p[0] == '?' && (p[1] == '?' || p[1] == 0)) {
            bytes.push_back(0); mask.push_back(true);
            p += 1; if (*p == '?') p++;
        } else {
            char h[3];
            h[0] = p[0];
            h[1] = p[1] ? p[1] : '\0';
            h[2] = '\0';
            BYTE b = (BYTE)strtoul(h, nullptr, 16);
            bytes.push_back(b); mask.push_back(false);
            p += 2; if (!*p) break;
        }
    }
    if (bytes.empty() || !mem::isAttached()) { lua_newtable(L); return 1; }

    lua_newtable(L);
    int idx = 1;
    SYSTEM_INFO si; GetSystemInfo(&si);
    LPVOID addr = si.lpMinimumApplicationAddress;
    int hits = 0;
    while (addr < si.lpMaximumApplicationAddress && hits < 5000 && !s_stopReq.load()) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(mem::processHandle(), addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            SIZE_T cap = mbi.RegionSize > (SIZE_T)(4*1024*1024) ? (SIZE_T)(4*1024*1024) : mbi.RegionSize;
            std::vector<BYTE> buf(cap);
            SIZE_T r = 0;
            if (ReadProcessMemory(mem::processHandle(), mbi.BaseAddress, buf.data(), cap, &r) && r > bytes.size()) {
                for (size_t i = 0; i + bytes.size() <= r && hits < 5000; i++) {
                    bool m = true;
                    for (size_t k = 0; k < bytes.size(); k++)
                        if (!mask[k] && buf[i+k] != bytes[k]) { m = false; break; }
                    if (m) {
                        uintptr_t found = (uintptr_t)mbi.BaseAddress + i;
                        lua_pushinteger(L, (lua_Integer)found);
                        lua_rawseti(L, -2, idx++);
                        hits++;
                    }
                }
            }
        }
        addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }
    return 1;
}

static int l_sleep(lua_State* L) {
    int ms = (int)luaL_checkinteger(L, 1);
    if (ms < 0) ms = 0;
    DWORD start = GetTickCount();
    while (!s_stopReq.load()) {
        DWORD el = GetTickCount() - start;
        if ((int)el >= ms) break;
        DWORD wait = (DWORD)ms - el;
        Sleep(wait > 50 ? 50 : wait);
    }
    return 0;
}

static int l_protect(lua_State* L) {
    uintptr_t a = asAddr(L, 1);
    size_t n = (size_t)luaL_checkinteger(L, 2);
    DWORD np = (DWORD)luaL_checkinteger(L, 3);
    if (!mem::isAttached()) { lua_pushnil(L); return 1; }
    DWORD oldProt = 0;
    if (!VirtualProtectEx(mem::processHandle(), (LPVOID)a, n, np, &oldProt)) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, oldProt);
    return 1;
}

// -- registration ----------------------------------------------------------
static const luaL_Reg memlib[] = {
    {"attach",      l_attach},
    {"detach",      l_detach},
    {"pid",         l_pid},
    {"base",        l_base},
    {"find_module", l_find_module},
    {"read_u8",     l_read_typed<uint8_t>},
    {"read_u16",    l_read_typed<uint16_t>},
    {"read_u32",    l_read_typed<uint32_t>},
    {"read_u64",    l_read_typed<uint64_t>},
    {"read_i8",     l_read_typed<int8_t>},
    {"read_i16",    l_read_typed<int16_t>},
    {"read_i32",    l_read_typed<int32_t>},
    {"read_i64",    l_read_typed<int64_t>},
    {"read_f32",    l_read_typed<float>},
    {"read_f64",    l_read_typed<double>},
    {"write_u8",    l_write_typed<uint8_t>},
    {"write_u16",   l_write_typed<uint16_t>},
    {"write_u32",   l_write_typed<uint32_t>},
    {"write_u64",   l_write_typed<uint64_t>},
    {"write_i8",    l_write_typed<int8_t>},
    {"write_i16",   l_write_typed<int16_t>},
    {"write_i32",   l_write_typed<int32_t>},
    {"write_i64",   l_write_typed<int64_t>},
    {"write_f32",   l_write_typed<float>},
    {"write_f64",   l_write_typed<double>},
    {"read_bytes",  l_read_bytes},
    {"write_bytes", l_write_bytes},
    {"alloc",       l_alloc},
    {"free",        l_free},
    {"disasm",      l_disasm},
    {"disasm_range",l_disasm_range},
    {"aob_scan",    l_aob_scan},
    {"sleep",       l_sleep},
    {"protect",     l_protect},
    {NULL, NULL}
};

// Custom Lua print() -> our log
static int lua_print_to_log(lua_State* L) {
    int n = lua_gettop(L);
    std::string out;
    for (int i = 1; i <= n; i++) {
        if (i > 1) out += "\t";
        size_t len = 0;
        const char* s = luaL_tolstring(L, i, &len);
        out.append(s, len);
        lua_pop(L, 1);
    }
    log(out);
    return 0;
}

// Public API
bool runScript(const std::string& source) {
    if (s_running.load()) return false;
    if (s_thread.joinable()) s_thread.join();
    s_stopReq = false;
    s_running = true;
    s_thread = std::thread([source]() {
        lua_State* L = luaL_newstate();
        { std::lock_guard<std::mutex> lk(s_LMtx); s_L = L; }
        luaL_openlibs(L);
        // Override print
        lua_pushcfunction(L, lua_print_to_log);
        lua_setglobal(L, "print");
        lua_pushcfunction(L, l_log);
        lua_setglobal(L, "log");
        // Register mem.* table
        luaL_newlib(L, memlib);
        lua_setglobal(L, "mem");
        // Constants for protection flags
        lua_newtable(L);
#define K(name, v) do { lua_pushinteger(L, v); lua_setfield(L, -2, name); } while(0)
        K("PAGE_NOACCESS",          PAGE_NOACCESS);
        K("PAGE_READONLY",          PAGE_READONLY);
        K("PAGE_READWRITE",         PAGE_READWRITE);
        K("PAGE_WRITECOPY",         PAGE_WRITECOPY);
        K("PAGE_EXECUTE",           PAGE_EXECUTE);
        K("PAGE_EXECUTE_READ",      PAGE_EXECUTE_READ);
        K("PAGE_EXECUTE_READWRITE", PAGE_EXECUTE_READWRITE);
        K("PAGE_EXECUTE_WRITECOPY", PAGE_EXECUTE_WRITECOPY);
        K("PAGE_GUARD",             PAGE_GUARD);
#undef K
        lua_setglobal(L, "prot");

        install_stop_hook(L);
        log("[lua] running...");
        int ok = luaL_dostring(L, source.c_str());
        if (ok != LUA_OK) {
            const char* err = lua_tostring(L, -1);
            log(std::string("[lua] error: ") + (err ? err : "unknown"));
        } else {
            log("[lua] finished.");
        }
        { std::lock_guard<std::mutex> lk(s_LMtx); s_L = nullptr; }
        lua_close(L);
        s_running = false;
    });
    return true;
}

void joinIfStopped() {
    if (!s_running.load() && s_thread.joinable()) s_thread.join();
}

void shutdown() {
    if (s_running.load()) { s_stopReq = true; }
    if (s_thread.joinable()) s_thread.join();
}

} 
