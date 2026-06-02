#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include "mem_ipc.h"
#include "memcore.h"
#include "mem_lua.h"
#include "json.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

static const size_t   kMaxLineBytes = 16 * 1024 * 1024;
static const int      kMaxConns     = 16;

using json = nlohmann::json;
using namespace mem;

namespace {

std::atomic<bool>          g_run{false};
std::atomic<bool>          g_wsaUp{false};
SOCKET                     g_listen = INVALID_SOCKET;
std::thread                g_acceptThread;
unsigned short             g_port = 0;
std::atomic<int>           g_conns{0};
std::atomic<unsigned long long> g_reqs{0};

std::string                g_token;
std::string                g_tokenPath;

std::string genToken() {
    unsigned char buf[32];
    if (BCryptGenRandom(NULL, buf, sizeof(buf), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        return std::string();
    static const char* hx = "0123456789abcdef";
    std::string s; s.reserve(64);
    for (unsigned char c : buf) { s += hx[c >> 4]; s += hx[c & 0xF]; }
    return s;
}

std::string tokenFilePath() {
    const char* la = getenv("LOCALAPPDATA");
    std::string dir = (la && *la) ? std::string(la) + "\\memiscani" : std::string("memiscani_mcp");
    CreateDirectoryA(dir.c_str(), NULL);
    return dir + "\\mcp_token";
}

bool writeTokenFile(const std::string& tok, std::string& outPath) {
    outPath = tokenFilePath();
    FILE* f = nullptr;
    if (fopen_s(&f, outPath.c_str(), "wb") != 0 || !f) return false;
    fwrite(tok.data(), 1, tok.size(), f);
    fclose(f);
    return true;
}

bool ctEq(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char r = 0;
    for (size_t i = 0; i < a.size(); i++) r |= (unsigned char)(a[i] ^ b[i]);
    return r == 0;
}

struct Pending {
    std::string req;
    std::string resp;
    bool        done = false;
};
std::mutex                              g_qmtx;
std::condition_variable                 g_qcv;
std::vector<std::shared_ptr<Pending>>   g_queue;

std::thread        g_scanThread;
int                g_lastDt = DT_INT32;

memipc::GuiHooks   g_gui;
void guiStatus(const std::string& m) { if (g_gui.status) g_gui.status(m); }

bool typedToBytes(DataType dt, const std::string& tv, std::vector<BYTE>& out) {
    out.clear();
    switch (dt) {
        case DT_FLOAT:  { float   v=(float)atof(tv.c_str());            out.assign((BYTE*)&v,(BYTE*)&v+4); return true; }
        case DT_DOUBLE: { double  v=atof(tv.c_str());                   out.assign((BYTE*)&v,(BYTE*)&v+8); return true; }
        case DT_INT8:   { int8_t  v=(int8_t)parseHexAwareInt(tv.c_str());out.assign((BYTE*)&v,(BYTE*)&v+1); return true; }
        case DT_INT16:  { int16_t v=(int16_t)parseHexAwareInt(tv.c_str());out.assign((BYTE*)&v,(BYTE*)&v+2);return true; }
        case DT_INT32:  { int32_t v=(int32_t)parseHexAwareInt(tv.c_str());out.assign((BYTE*)&v,(BYTE*)&v+4);return true; }
        case DT_INT64:  { int64_t v=parseHexAwareInt(tv.c_str());        out.assign((BYTE*)&v,(BYTE*)&v+8); return true; }
        default: return false;
    }
}

const char* dtName(DataType dt) {
    switch (dt) {
        case DT_INT8:  return "int8";
        case DT_INT16: return "int16";
        case DT_INT32: return "int32";
        case DT_INT64: return "int64";
        case DT_FLOAT: return "float";
        case DT_DOUBLE:return "double";
        case DT_STRING:return "string";
        case DT_AOB:   return "aob";
    }
    return "?";
}

bool parseDataType(const std::string& s, DataType& dt) {
    if      (s=="int8"  || s=="i8"  || s=="byte")  dt = DT_INT8;
    else if (s=="int16" || s=="i16" || s=="short") dt = DT_INT16;
    else if (s=="int32" || s=="i32" || s=="int")   dt = DT_INT32;
    else if (s=="int64" || s=="i64" || s=="long")  dt = DT_INT64;
    else if (s=="float" || s=="f32")               dt = DT_FLOAT;
    else if (s=="double"|| s=="f64")               dt = DT_DOUBLE;
    else if (s=="string"|| s=="str")               dt = DT_STRING;
    else if (s=="aob"   || s=="bytes")             dt = DT_AOB;
    else return false;
    return true;
}

bool parseScanCond(const std::string& s, ScanCondition& sc) {
    if      (s=="exact")     sc = SC_EXACT;
    else if (s=="changed")   sc = SC_CHANGED;
    else if (s=="unchanged") sc = SC_UNCHANGED;
    else if (s=="increased") sc = SC_INCREASED;
    else if (s=="decreased") sc = SC_DECREASED;
    else if (s=="unknown")   sc = SC_UNKNOWN;
    else return false;
    return true;
}

uintptr_t jaddr(const json& v) {
    if (v.is_string())            return (uintptr_t)parseHexAwareInt(v.get<std::string>().c_str());
    if (v.is_number_unsigned())   return (uintptr_t)v.get<uint64_t>();
    if (v.is_number_integer())    return (uintptr_t)v.get<int64_t>();
    if (v.is_number_float())      return (uintptr_t)v.get<double>();
    return 0;
}

std::string toHexAddr(uintptr_t a) {
    char b[32]; sprintf(b, "0x%llX", (unsigned long long)a);
    return b;
}

std::string bytesToHex(const std::vector<BYTE>& b) {
    std::string s; char t[4];
    for (size_t i = 0; i < b.size(); i++) { sprintf(t, "%02X", b[i]); if (i) s += ' '; s += t; }
    return s;
}

std::vector<BYTE> hexToBytes(const std::string& s) {
    std::vector<BYTE> out;
    auto hv = [](char c) -> int {
        if (c>='0'&&c<='9') return c-'0';
        if (c>='a'&&c<='f') return c-'a'+10;
        if (c>='A'&&c<='F') return c-'A'+10;
        return -1;
    };
    const char* p = s.c_str();
    while (*p) {
        while (*p==' '||*p==','||*p=='\t'||*p=='\n'||*p=='\r') p++;
        if (!*p) break;
        if (p[0]=='0' && (p[1]=='x'||p[1]=='X')) p += 2;
        int hi = hv(p[0]); if (hi < 0) { p++; continue; }
        int lo = hv(p[1]);
        if (lo < 0) { out.push_back((BYTE)hi); p += 1; }
        else        { out.push_back((BYTE)((hi<<4)|lo)); p += 2; }
    }
    return out;
}

void requireAttached() {
    if (!isAttached()) throw std::runtime_error("Not attached to a process");
}

json handle(const std::string& cmd, const json& args) {
    json r = json::object();

    if (cmd == "ping") {
        r["pong"] = true;
        return r;
    }

    if (cmd == "status") {
        r["attached"]      = isAttached();
        r["pid"]           = (uint64_t)attachedPid();
        r["base"]          = toHexAddr((uintptr_t)baseAddress());
        r["scanRunning"]   = (bool)g_scanRunning;
        r["resultCount"]   = (uint64_t)g_scan.results.size();
        r["liveMonActive"] = (bool)g_liveMonActive;
        r["luaRunning"]    = memlua::isRunning();
        r["connections"]   = g_conns.load();
        r["requests"]      = (uint64_t)g_reqs.load();
        r["lastScanType"]  = dtName((DataType)g_lastDt);
        return r;
    }

    if (cmd == "list_processes") {
        std::string needle = args.value("name", std::string());
        auto procs = findProcessesByName(needle);
        json arr = json::array();
        for (auto& pr : procs) arr.push_back({{"pid",(uint64_t)pr.first},{"name",pr.second}});
        r["processes"] = arr;
        r["count"] = (uint64_t)procs.size();
        return r;
    }

    if (cmd == "attach") {
        DWORD pid = 0;
        if (args.contains("pid")) {
            pid = (DWORD)args["pid"].get<uint64_t>();
        } else if (args.contains("name")) {
            auto procs = findProcessesByName(args["name"].get<std::string>());
            if (procs.empty()) throw std::runtime_error("No process matched name");
            pid = procs.front().first;
        } else {
            throw std::runtime_error("attach requires 'pid' or 'name'");
        }
        if (!attach(pid)) throw std::runtime_error("attach failed (insufficient rights or bad pid)");
        guiStatus("MCP attached to pid " + std::to_string((unsigned)pid));
        r["attached"] = true;
        r["pid"]  = (uint64_t)attachedPid();
        r["base"] = toHexAddr((uintptr_t)baseAddress());
        return r;
    }

    if (cmd == "detach") { detach(); guiStatus("MCP detached"); r["attached"] = false; return r; }

    if (cmd == "base") { requireAttached(); r["base"] = toHexAddr((uintptr_t)baseAddress()); return r; }

    if (cmd == "list_modules") {
        requireAttached();
        auto mods = listModules();
        json arr = json::array();
        for (auto& m : mods)
            arr.push_back({{"name",m.name},{"base",toHexAddr(m.base)},{"size",(uint64_t)m.size},{"path",m.path}});
        r["modules"] = arr;
        r["count"] = (uint64_t)mods.size();
        return r;
    }

    if (cmd == "read") {
        requireAttached();
        uintptr_t a = jaddr(args.at("addr"));
        DataType dt; if (!parseDataType(args.value("type","int32"), dt)) throw std::runtime_error("bad type");
        if (dt == DT_STRING || dt == DT_AOB) {
            size_t n = (size_t)args.value("len", 64); if (n > 1024) n = 1024; if (!n) n = 1;
            std::vector<BYTE> buf; std::string err;
            if (!hexRead(a, n, buf, err)) throw std::runtime_error(err.empty()?"read failed":err);
            r["value"] = formatTypedValueN(buf.data(), buf.size(), dt);
            r["hex"]   = bytesToHex(buf);
        } else {
            BYTE b[16] = {};
            if (!readTypedValue((LPVOID)a, dt, b)) throw std::runtime_error("read failed");
            r["value"] = formatTypedValueN(b, dtSize(dt), dt);
            std::vector<BYTE> bb(b, b+dtSize(dt));
            r["hex"] = bytesToHex(bb);
        }
        r["addr"] = toHexAddr(a);
        r["type"] = dtName(dt);
        return r;
    }

    if (cmd == "read_bytes") {
        requireAttached();
        uintptr_t a = jaddr(args.at("addr"));
        size_t n = (size_t)args.value("size", 64); if (n > 4096) n = 4096; if (!n) n = 1;
        std::vector<BYTE> buf; std::string err;
        if (!hexRead(a, n, buf, err)) throw std::runtime_error(err.empty()?"read failed":err);
        r["addr"] = toHexAddr(a);
        r["size"] = (uint64_t)buf.size();
        r["hex"]  = bytesToHex(buf);
        return r;
    }

    if (cmd == "write") {
        requireAttached();
        uintptr_t a = jaddr(args.at("addr"));
        DataType dt; if (!parseDataType(args.value("type","int32"), dt)) throw std::runtime_error("bad type");
        std::string val = args.at("value").is_string() ? args["value"].get<std::string>()
                                                        : args["value"].dump();
        std::vector<BYTE> bytes;
        if (!typedToBytes(dt, val, bytes))
            throw std::runtime_error("type not writable here (use write_bytes for string/aob)");

        std::string err;
        if (!patcherWrite(a, bytes, std::string("MCP ")+dtName(dt)+"="+val, err))
            throw std::runtime_error(err.empty()?"write failed":err);
        if (g_gui.selectAddr) g_gui.selectAddr((unsigned long long)a);
        guiStatus("MCP write: " + std::string(dtName(dt)) + " = " + val + " @ " + toHexAddr(a));
        r["addr"] = toHexAddr(a);
        r["wrote"] = val;
        return r;
    }

    if (cmd == "write_bytes") {
        requireAttached();
        uintptr_t a = jaddr(args.at("addr"));
        auto bytes = hexToBytes(args.at("hex").get<std::string>());
        if (bytes.empty()) throw std::runtime_error("no bytes parsed from 'hex'");
        std::string err;
        if (!patcherWrite(a, bytes, "MCP write_bytes", err))
            throw std::runtime_error(err.empty()?"write failed":err);
        if (g_gui.selectAddr) g_gui.selectAddr((unsigned long long)a);
        guiStatus("MCP write_bytes: " + std::to_string(bytes.size()) + " bytes @ " + toHexAddr(a));
        r["addr"]  = toHexAddr(a);
        r["count"] = (uint64_t)bytes.size();
        return r;
    }

    if (cmd == "disasm") {
        requireAttached();
        uintptr_t a = jaddr(args.at("addr"));
        size_t nbytes = (size_t)args.value("bytes", 64); if (nbytes > 4096) nbytes = 4096;
        size_t lines  = (size_t)args.value("count", 16);  if (lines > 256) lines = 256;
        auto ls = disasmRangeAtRemote((LPVOID)a, nbytes, lines);
        json arr = json::array();
        for (auto& l : ls)
            arr.push_back({{"addr",toHexAddr(l.addr)},{"bytes",bytesToHex(l.bytes)},{"text",l.text}});
        r["lines"] = arr;
        return r;
    }

    if (cmd == "scan_first" || cmd == "scan_next") {
        requireAttached();
        if (g_scanRunning) throw std::runtime_error("a scan is already running");
        ScanParams p;
        DataType dt = DT_INT32; ScanCondition sc = SC_EXACT;
        if (cmd == "scan_first") {
            if (!parseDataType(args.value("type","int32"), dt)) throw std::runtime_error("bad type");
        } else {
            if (g_scan.results.empty()) throw std::runtime_error("no previous scan for scan_next");
            dt = (DataType)g_lastDt;
        }
        if (!parseScanCond(args.value("match","exact"), sc)) throw std::runtime_error("bad match");
        p.dt = dt; p.sc = sc;
        p.value             = args.value("value", std::string());
        p.modFilter         = args.value("modFilter", std::string());
        p.writableOnly      = args.value("writableOnly", true);
        p.skipImage         = args.value("skipImage", false);
        p.executableOnly    = args.value("executableOnly", false);
        p.workingSetOnly    = args.value("workingSetOnly", false);
        p.copyOnWriteOnly   = args.value("copyOnWriteOnly", false);
        p.skipZero          = args.value("skipZero", false);
        p.alignment         = args.value("alignment", 0);
        p.maxResults        = args.value("maxResults", 100000);
        p.strEnc            = args.value("strEnc", 2);
        p.strCaseInsensitive= args.value("caseInsensitive", false);
        if (args.contains("addrMin")) p.addrMin = jaddr(args["addrMin"]);
        if (args.contains("addrMax")) p.addrMax = jaddr(args["addrMax"]);
        g_lastDt = dt;

        bool first = (cmd == "scan_first");

        if (g_gui.syncScan) g_gui.syncScan(p);
        guiStatus("MCP " + std::string(first ? "first" : "next") + " scan: " +
                  dtName(dt) + " / " + args.value("match","exact") +
                  (p.value.empty() ? "" : (" = " + p.value)));
        if (g_scanThread.joinable()) g_scanThread.join();
        g_scanThread = std::thread([p, first]() {
            std::string e;
            if (first) doFirstScan(p, e);
            else       doNextScan(p, e);
        });
        r["started"] = true;
        r["type"]    = dtName(dt);
        return r;
    }

    if (cmd == "scan_status") {
        r["running"] = (bool)g_scanRunning;
        r["count"]   = (uint64_t)g_scan.results.size();
        return r;
    }

    if (cmd == "get_results") {
        size_t total = g_scan.results.size();
        size_t off = (size_t)args.value("offset", 0);
        size_t lim = (size_t)args.value("limit", 200); if (lim > 1000) lim = 1000;
        DataType dt = (DataType)g_lastDt;
        json arr = json::array();
        bool attached = isAttached();
        for (size_t i = off; i < total && arr.size() < lim; i++) {
            LPVOID a = g_scan.results[i];
            json row = {{"index",(uint64_t)i},{"addr",toHexAddr((uintptr_t)a)}};
            if (attached) {
                size_t len = (dt==DT_STRING||dt==DT_AOB)
                           ? ((i < g_scan.prevVals.size() && !g_scan.prevVals[i].empty()) ? g_scan.prevVals[i].size() : 16)
                           : dtSize(dt);
                if (len > 1024) len = 1024;
                std::vector<BYTE> buf; std::string err;
                if (hexRead((uintptr_t)a, len, buf, err) && !buf.empty())
                    row["value"] = formatTypedValueN(buf.data(), buf.size(), dt);
                else
                    row["value"] = nullptr;
            }
            arr.push_back(row);
        }
        r["results"] = arr;
        r["total"]   = (uint64_t)total;
        r["type"]    = dtName(dt);
        return r;
    }

    if (cmd == "clear_scan") { clearScan(); guiStatus("MCP cleared scan results"); r["cleared"] = true; return r; }

    if (cmd == "guess_type") {
        requireAttached();
        uintptr_t a = jaddr(args.at("addr"));
        auto gs = guessTypeAt((LPVOID)a);
        json arr = json::array();
        for (auto& g : gs)
            arr.push_back({{"type",dtName(g.dt)},{"formatted",g.formatted},
                           {"plausibility",g.plausibility},{"reason",g.reason}});
        r["addr"] = toHexAddr(a);
        r["guesses"] = arr;
        return r;
    }

    if (cmd == "pointer_chain_resolve") {
        requireAttached();
        PointerChain c;
        c.moduleName   = args.value("moduleName", std::string());
        c.moduleOffset = jaddr(args.value("moduleOffset", json(0)));
        if (args.contains("offsets"))
            for (auto& o : args["offsets"]) c.offsets.push_back((intptr_t)jaddr(o));
        std::string err;
        uintptr_t a = resolveChain(c, err);
        if (!a) throw std::runtime_error(err.empty()?"chain did not resolve":err);
        r["addr"] = toHexAddr(a);
        return r;
    }

    if (cmd == "aob_signature") {
        requireAttached();
        uintptr_t a = jaddr(args.at("addr"));
        size_t mn = (size_t)args.value("minLen", 12);
        size_t mx = (size_t)args.value("maxLen", 64);
        auto sig = generateAobSignature((LPVOID)a, mn, mx);
        r["pattern"]   = sig.pattern;
        r["length"]    = (uint64_t)sig.length;
        r["wildcards"] = (uint64_t)sig.wildcards;
        r["hits"]      = (uint64_t)sig.hits;
        r["unique"]    = sig.unique;
        return r;
    }

    if (cmd == "run_lua") {
        std::string src = args.at("source").get<std::string>();
        if (memlua::isRunning()) throw std::runtime_error("a lua script is already running");
        memlua::clearLog();
        if (!memlua::runScript(src)) throw std::runtime_error("failed to start lua script");
        guiStatus("MCP started a Lua script (" + std::to_string(src.size()) + " bytes)");
        r["started"] = true;
        return r;
    }

    if (cmd == "lua_status") { r["running"] = memlua::isRunning(); return r; }

    if (cmd == "lua_stop")   { memlua::requestStop(); r["stopRequested"] = true; return r; }

    if (cmd == "lua_log") {
        auto lines = memlua::snapshotLog();
        r["lines"] = lines;
        if (args.value("clear", false)) memlua::clearLog();
        return r;
    }

    throw std::runtime_error("unknown command: " + cmd);
}

std::string handleLine(const std::string& line) {
    json id = nullptr;
    json out;
    try {
        json req = json::parse(line);
        if (req.contains("id")) id = req["id"];
        std::string tok = req.value("token", std::string());
        if (g_token.empty() || !ctEq(tok, g_token))
            throw std::runtime_error("unauthorized: missing or invalid token");
        std::string cmd = req.at("cmd").get<std::string>();
        json args = req.contains("args") && req["args"].is_object() ? req["args"] : json::object();
        json result = handle(cmd, args);
        out = {{"id", id}, {"ok", true}, {"result", result}};
    } catch (const std::exception& e) {
        out = {{"id", id}, {"ok", false}, {"error", e.what()}};
    }
    return out.dump();
}

std::string dispatchViaUiThread(const std::string& line) {
    auto p = std::make_shared<Pending>();
    p->req = line;
    {
        std::lock_guard<std::mutex> lk(g_qmtx);
        g_queue.push_back(p);
    }
    std::unique_lock<std::mutex> lk(g_qmtx);
    g_qcv.wait(lk, [&]{ return p->done || !g_run.load(); });
    return p->done ? p->resp
                   : std::string("{\"ok\":false,\"error\":\"server stopping\"}");
}

void clientLoop(SOCKET s) {
    g_conns++;
    std::string buf;
    char tmp[4096];
    bool framingChecked = false;
    while (g_run.load()) {
        int n = recv(s, tmp, sizeof(tmp), 0);
        if (n <= 0) break;
        buf.append(tmp, n);

        if (!framingChecked) {
            size_t i = 0;
            while (i < buf.size() && (buf[i]==' '||buf[i]=='\r'||buf[i]=='\n'||buf[i]=='\t')) i++;
            if (i < buf.size()) {
                if (buf[i] != '{') break;
                framingChecked = true;
            }
        }

        if (buf.size() > kMaxLineBytes) break;

        size_t pos;
        while ((pos = buf.find('\n')) != std::string::npos) {
            std::string line = buf.substr(0, pos);
            buf.erase(0, pos + 1);
            while (!line.empty() && (line.back()=='\r')) line.pop_back();
            if (line.empty()) continue;
            g_reqs++;
            std::string resp = dispatchViaUiThread(line);
            resp.push_back('\n');
            int off = 0, len = (int)resp.size();
            while (off < len) {
                int w = send(s, resp.data()+off, len-off, 0);
                if (w <= 0) { off = len; break; }
                off += w;
            }
        }
    }
    closesocket(s);
    g_conns--;
}

void acceptLoop() {
    while (g_run.load()) {
        sockaddr_in cli; int clen = sizeof(cli);
        SOCKET c = accept(g_listen, (sockaddr*)&cli, &clen);
        if (c == INVALID_SOCKET) {
            if (!g_run.load()) break;
            continue;
        }
        if (g_conns.load() >= kMaxConns) { closesocket(c); continue; }
        std::thread(clientLoop, c).detach();
    }
}

}

namespace memipc {

bool start(unsigned short port, std::string& err) {
    if (g_run.load()) return true;

    WSADATA wsa;
    if (!g_wsaUp.load()) {
        if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { err = "WSAStartup failed"; return false; }
        g_wsaUp = true;
    }

    g_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listen == INVALID_SOCKET) { err = "socket() failed"; return false; }

    BOOL yes = TRUE;
    setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    InetPtonA(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (bind(g_listen, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        err = "bind() failed (port " + std::to_string(port) + " in use?)";
        closesocket(g_listen); g_listen = INVALID_SOCKET; return false;
    }
    if (listen(g_listen, 8) == SOCKET_ERROR) {
        err = "listen() failed";
        closesocket(g_listen); g_listen = INVALID_SOCKET; return false;
    }

    g_token = genToken();
    if (g_token.empty()) {
        err = "failed to generate auth token (BCryptGenRandom)";
        closesocket(g_listen); g_listen = INVALID_SOCKET; return false;
    }
    if (!writeTokenFile(g_token, g_tokenPath)) {
        err = "failed to write token file";
        g_token.clear();
        closesocket(g_listen); g_listen = INVALID_SOCKET; return false;
    }

    g_port = port;
    g_run = true;
    g_acceptThread = std::thread(acceptLoop);
    return true;
}

void stop() {
    if (!g_run.load()) return;
    g_run = false;
    if (g_listen != INVALID_SOCKET) { closesocket(g_listen); g_listen = INVALID_SOCKET; }
    g_qcv.notify_all();
    if (g_acceptThread.joinable()) g_acceptThread.join();
    if (g_scanThread.joinable())   g_scanThread.join();
    g_conns = 0;
    if (!g_tokenPath.empty()) DeleteFileA(g_tokenPath.c_str());
    g_token.clear();
}

void setGuiHooks(const GuiHooks& hooks) { g_gui = hooks; }

bool               running()          { return g_run.load(); }
unsigned short     port()             { return g_port; }
int                connectionCount()  { return g_conns.load(); }
unsigned long long requestCount()     { return g_reqs.load(); }
std::string        tokenPath()        { return g_tokenPath; }

void poll() {
    std::vector<std::shared_ptr<Pending>> batch;
    {
        std::lock_guard<std::mutex> lk(g_qmtx);
        if (g_queue.empty()) return;
        batch.swap(g_queue);
    }
    for (auto& p : batch) p->resp = handleLine(p->req);
    {
        std::lock_guard<std::mutex> lk(g_qmtx);
        for (auto& p : batch) p->done = true;
    }
    g_qcv.notify_all();
}

}
