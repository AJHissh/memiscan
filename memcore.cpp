#include <winsock2.h>    
#include "memcore.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <map>
#include <functional>
#include <cmath>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#include "Zydis.h"

namespace mem {

static HANDLE s_hProc = NULL;
static DWORD  s_pid   = 0;
static LPVOID s_base  = nullptr;

volatile bool g_scanRunning       = false;
volatile bool g_scanStopRequested = false;
ScanState     g_scan;

std::vector<std::vector<BYTE>> g_snapshot;
int                            g_snapshotDt = -1;

ScanParams                     g_lastScanParams;

std::vector<LiveStat>          g_liveStats;
volatile bool                  g_liveMonActive = false;
int                            g_liveMonDt = -1;

HANDLE processHandle() { return s_hProc; }
DWORD  attachedPid()   { return s_pid; }
bool   isAttached()    { return s_hProc != NULL; }
LPVOID baseAddress()   { return s_base; }

bool attach(DWORD pid) {
    detach();
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                           PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                           PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME,
                           FALSE, pid);
    if (!h) return false;
    s_hProc = h; s_pid = pid;
    HMODULE m = NULL; DWORD cb = 0;
    if (EnumProcessModulesEx(h, &m, sizeof(m), &cb, LIST_MODULES_ALL))
        s_base = (LPVOID)m;
    return true;
}

void detach() {
    if (s_hProc) CloseHandle(s_hProc);
    s_hProc = NULL; s_pid = 0; s_base = nullptr;
    g_scan.results.clear(); g_scan.prevVals.clear();
}

std::vector<std::pair<DWORD,std::string>> findProcessesByName(const std::string& needle) {
    std::vector<std::pair<DWORD,std::string>> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe{ sizeof(pe) };
    std::string nLow = needle;
    for (auto& c : nLow) c = (char)std::tolower((unsigned char)c);
    auto wToUtf8 = [](const wchar_t* w) -> std::string {
        int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
        if (n <= 1) return std::string();
        std::string s(n - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
        return s;
    };
    if (Process32FirstW(snap, &pe)) {
        do {
            std::string name = wToUtf8(pe.szExeFile);
            std::string lo = name;
            for (auto& c : lo) c = (char)std::tolower((unsigned char)c);
            if (nLow.empty() || lo.find(nLow) != std::string::npos)
                out.emplace_back(pe.th32ProcessID, name);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    std::sort(out.begin(), out.end(),
              [](const auto& a, const auto& b){ return a.second < b.second; });
    return out;
}

size_t dtSize(DataType dt) {
    switch (dt) {
        case DT_INT8:  return 1;
        case DT_INT16: return 2;
        case DT_INT32: return 4;
        case DT_INT64: return 8;
        case DT_FLOAT: return 4;
        case DT_DOUBLE:return 8;
        case DT_STRING:return 1;
        case DT_AOB:   return 1;
    }
    return 4;
}

int64_t parseHexAwareInt(const char* s) {
    if (!s || !*s) return 0;
    while (*s == ' ' || *s == '\t') s++;
    bool neg = false;
    if (*s == '-') { neg = true; s++; }
    else if (*s == '+') s++;
    int64_t v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        v = (int64_t)_strtoui64(s + 2, nullptr, 16);
    else
        v = _strtoi64(s, nullptr, 10);
    return neg ? -v : v;
}

static bool matchesNumericCondition(const BYTE* cur, const BYTE* prev,
                                    const BYTE* target, DataType dt,
                                    ScanCondition sc, size_t sz) {
    if (sc == SC_UNKNOWN) return true;
    auto cmpInt = [&](int64_t a, int64_t b)->int { return (a > b) - (a < b); };
    auto cmpDbl = [&](double a, double b)->int { return (a > b) - (a < b); };

    int64_t aI = 0, bI = 0, tI = 0;
    double  aF = 0, bF = 0, tF = 0;
    bool isFloat = (dt == DT_FLOAT || dt == DT_DOUBLE);
    if (isFloat) {
        if (dt == DT_FLOAT) {
            aF = *(const float*)cur;
            if (prev) bF = *(const float*)prev;
            if (target) tF = *(const float*)target;
        } else {
            aF = *(const double*)cur;
            if (prev) bF = *(const double*)prev;
            if (target) tF = *(const double*)target;
        }
    } else {
        switch (dt) {
            case DT_INT8:  aI = *(const int8_t*)cur;  if(prev) bI=*(const int8_t*)prev;  if(target) tI=*(const int8_t*)target;  break;
            case DT_INT16: aI = *(const int16_t*)cur; if(prev) bI=*(const int16_t*)prev; if(target) tI=*(const int16_t*)target; break;
            case DT_INT32: aI = *(const int32_t*)cur; if(prev) bI=*(const int32_t*)prev; if(target) tI=*(const int32_t*)target; break;
            case DT_INT64: aI = *(const int64_t*)cur; if(prev) bI=*(const int64_t*)prev; if(target) tI=*(const int64_t*)target; break;
            default: break;
        }
    }
    int cmp = isFloat ? cmpDbl(aF, prev?bF:0) : cmpInt(aI, prev?bI:0);
    switch (sc) {
        case SC_EXACT:
            return isFloat ? (aF == tF) : (memcmp(cur, target, sz) == 0);
        case SC_CHANGED:   return prev && memcmp(cur, prev, sz) != 0;
        case SC_UNCHANGED: return prev && memcmp(cur, prev, sz) == 0;
        case SC_INCREASED: return prev && cmp > 0;
        case SC_DECREASED: return prev && cmp < 0;
        case SC_UNKNOWN:   return true;
    }
    return false;
}

static std::vector<uint8_t> buildWorkingSetBitmap(uintptr_t addrMax, bool& ok) {
    // Returns a bitmap indexed by (page_addr >> 12).  bit set = page in WS.
    // Sized to cover all of user-mode address space we may scan.
    ok = false;
    std::vector<uint8_t> bm;
    if (!s_hProc) return bm;
    // Allocate based on upper limit (cap at user-mode 128 TiB just in case)
    uintptr_t maxPages = (addrMax ? addrMax : 0x7FFFFFFFFFFFULL) >> 12;
    if (maxPages > (1ULL << 31)) maxPages = (1ULL << 31); // 256 MB bitmap cap
    bm.assign((size_t)((maxPages + 7) / 8), 0);
    std::vector<BYTE> buf(64 * 1024);
    while (true) {
        if (QueryWorkingSet(s_hProc, buf.data(), (DWORD)buf.size())) break;
        DWORD e = GetLastError();
        if (e == ERROR_BAD_LENGTH && buf.size() < (size_t)128 * 1024 * 1024) {
            buf.resize(buf.size() * 2);
            continue;
        }
        return bm;  // failure -> empty bitmap
    }
    PSAPI_WORKING_SET_INFORMATION* wsi = (PSAPI_WORKING_SET_INFORMATION*)buf.data();
    for (ULONG_PTR i = 0; i < wsi->NumberOfEntries; i++) {
        uintptr_t page = (uintptr_t)wsi->WorkingSetInfo[i].VirtualPage;
        if (page < maxPages) bm[(size_t)(page >> 3)] |= (uint8_t)(1u << (page & 7));
    }
    ok = true;
    return bm;
}

static bool addrInBitmap(const std::vector<uint8_t>& bm, uintptr_t addr) {
    uintptr_t page = addr >> 12;
    size_t off = (size_t)(page >> 3);
    if (off >= bm.size()) return false;
    return (bm[off] >> (page & 7)) & 1u;
}

bool doFirstScan(const ScanParams& p, std::string& err) {
    if (!s_hProc) { err = "Not attached"; return false; }
    g_scan.results.clear();
    g_scan.prevVals.clear();
    g_scanStopRequested = false;
    g_scanRunning = true;
    g_lastScanParams = p;

    BYTE targetBuf[8] = {};
    size_t valSz = dtSize(p.dt);
    if (p.sc == SC_EXACT && p.dt != DT_STRING && p.dt != DT_AOB) {
        if (p.dt == DT_FLOAT)      { float v=(float)atof(p.value.c_str()); memcpy(targetBuf,&v,4); }
        else if (p.dt == DT_DOUBLE){ double v=atof(p.value.c_str()); memcpy(targetBuf,&v,8); }
        else if (p.dt == DT_INT64) { int64_t v=parseHexAwareInt(p.value.c_str()); memcpy(targetBuf,&v,8); }
        else {
            int64_t vv = parseHexAwareInt(p.value.c_str()); int32_t v = (int32_t)vv;
            if (p.dt == DT_INT8)       { int8_t  b=(int8_t)v;  memcpy(targetBuf,&b,1); }
            else if (p.dt == DT_INT16) { int16_t b=(int16_t)v; memcpy(targetBuf,&b,2); }
            else                        memcpy(targetBuf, &v, 4);
        }
    }

    SYSTEM_INFO si; GetSystemInfo(&si);
    LPVOID addr = si.lpMinimumApplicationAddress;
    if (p.addrMin) addr = (LPVOID)p.addrMin;
    LPVOID stopAt = si.lpMaximumApplicationAddress;
    if (p.addrMax && (uintptr_t)stopAt > p.addrMax) stopAt = (LPVOID)p.addrMax;

    int found = 0;
    DWORD protMask;
    if (p.executableOnly) {
        protMask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    } else if (p.copyOnWriteOnly) {
        protMask = PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
    } else if (p.writableOnly) {
        protMask = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    } else {
        protMask = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY |
                   PAGE_READONLY | PAGE_EXECUTE_READ;
    }

    // Working-set page bitmap (only build if requested)
    std::vector<uint8_t> wsBitmap;
    bool wsBitmapValid = false;
    if (p.workingSetOnly) wsBitmap = buildWorkingSetBitmap(p.addrMax, wsBitmapValid);

    // Address-suffix skip parsing
    uintptr_t suffixMask = 0, suffixPat = 0;
    bool wantSuffixSkip = false;
    if (!p.skipAddrSuffixHex.empty()) {
        std::string s = p.skipAddrSuffixHex;
        // Trim leading "0x" if present
        if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
        if (!s.empty() && s.size() <= 16) {
            char* ep = nullptr;
            suffixPat = (uintptr_t)_strtoui64(s.c_str(), &ep, 16);
            if (ep != s.c_str()) {
                int hexDigits = (int)s.size();
                suffixMask = (hexDigits >= 16) ? (uintptr_t)~0ULL : (((uintptr_t)1 << (hexDigits * 4)) - 1);
                wantSuffixSkip = true;
            }
        }
    }

    size_t baseStep = (p.dt == DT_AOB || p.dt == DT_STRING) ? 1 : valSz;
    size_t step = (p.alignment > 0) ? (size_t)p.alignment : baseStep;
    if (step == 0) step = 1;

    while (addr < stopAt && found < p.maxResults) {
        if (g_scanStopRequested) break;
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(s_hProc, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        if (p.skipImage && mbi.Type == MEM_IMAGE) { addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize); continue; }
        if (mbi.State == MEM_COMMIT && (mbi.Protect & protMask) && !(mbi.Protect & PAGE_GUARD)) {
            SIZE_T chunkSz = mbi.RegionSize > (SIZE_T)(4 * 1024 * 1024) ? (SIZE_T)(4 * 1024 * 1024) : mbi.RegionSize;
            std::vector<BYTE> chunk(chunkSz);
            SIZE_T r = 0;
            if (ReadProcessMemory(s_hProc, mbi.BaseAddress, chunk.data(), chunkSz, &r) && r > 0) {
                for (SIZE_T i = 0; i + valSz <= r && found < p.maxResults && !g_scanStopRequested; i += step) {
                    uintptr_t fa = (uintptr_t)mbi.BaseAddress + i;
                    if (p.addrMin && fa < p.addrMin) continue;
                    if (p.addrMax && fa > p.addrMax) break;
                    if (p.workingSetOnly && wsBitmapValid && !addrInBitmap(wsBitmap, fa)) continue;
                    if (wantSuffixSkip && (fa & suffixMask) == suffixPat) continue;

                    const BYTE* cur = &chunk[i];

                    if (p.skipZero) {
                        bool isZero = true;
                        for (size_t k = 0; k < valSz; k++) if (cur[k] != 0) { isZero = false; break; }
                        if (isZero) continue;
                    }

                    bool hit = true;
                    if (p.sc == SC_EXACT && p.dt != DT_AOB && p.dt != DT_STRING)
                        hit = matchesNumericCondition(cur, nullptr, targetBuf, p.dt, p.sc, valSz);
                    if (hit && (p.hasMin || p.hasMax)) {
                        if (p.dt == DT_FLOAT || p.dt == DT_DOUBLE) {
                            double v = (p.dt == DT_FLOAT) ? (double)*(float*)cur : *(double*)cur;
                            if (p.hasMin && v < p.rminF) hit = false;
                            if (p.hasMax && v > p.rmaxF) hit = false;
                        } else {
                            int64_t v = 0;
                            switch (p.dt) {
                                case DT_INT8:  v = *(int8_t*)cur;  break;
                                case DT_INT16: v = *(int16_t*)cur; break;
                                case DT_INT32: v = *(int32_t*)cur; break;
                                case DT_INT64: v = *(int64_t*)cur; break;
                                default: break;
                            }
                            if (p.hasMin && v < p.rmin) hit = false;
                            if (p.hasMax && v > p.rmax) hit = false;
                        }
                    }
                    if (hit) {
                        g_scan.results.push_back((LPVOID)fa);
                        g_scan.prevVals.emplace_back(cur, cur + valSz);
                        found++;
                    }
                }
            }
        }
        addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }

    g_scanRunning = false;
    return true;
}

void clearScan() {
    g_scan.results.clear();
    g_scan.prevVals.clear();
    g_snapshot.clear();
    g_snapshotDt = -1;
    g_liveStats.clear();
    g_liveMonActive = false;
    g_liveMonDt = -1;
}

std::string formatTypedValue(const BYTE* data, DataType dt) {
    char buf[64];
    switch (dt) {
        case DT_INT8:  sprintf(buf, "%d", *(int8_t*)data); break;
        case DT_INT16: sprintf(buf, "%d", *(int16_t*)data); break;
        case DT_INT32: sprintf(buf, "%d", *(int32_t*)data); break;
        case DT_INT64: sprintf(buf, "%lld", (long long)*(int64_t*)data); break;
        case DT_FLOAT: sprintf(buf, "%.6g", *(float*)data); break;
        case DT_DOUBLE:sprintf(buf, "%.6g", *(double*)data); break;
        default:       sprintf(buf, "(non-numeric)"); break;
    }
    return buf;
}

double valueAsDouble(const BYTE* data, DataType dt) {
    switch (dt) {
        case DT_INT8:  return *(int8_t*)data;
        case DT_INT16: return *(int16_t*)data;
        case DT_INT32: return *(int32_t*)data;
        case DT_INT64: return (double)*(int64_t*)data;
        case DT_FLOAT: return *(float*)data;
        case DT_DOUBLE:return *(double*)data;
        default:       return 0;
    }
}

bool readTypedValue(LPVOID addr, DataType dt, BYTE out[16]) {
    if (!s_hProc || !addr) return false;
    SIZE_T r = 0;
    memset(out, 0, 16);
    return ReadProcessMemory(s_hProc, addr, out, dtSize(dt), &r) && r >= dtSize(dt);
}

bool writeTypedValue(LPVOID addr, DataType dt, const std::string& tv, bool bypass, std::string& err) {
    if (!s_hProc || !addr) { err = "Not attached or null address"; return false; }
    BYTE buf[16] = {};
    size_t sz = dtSize(dt);
    switch (dt) {
        case DT_FLOAT:  { float v = (float)atof(tv.c_str()); memcpy(buf, &v, 4); break; }
        case DT_DOUBLE: { double v = atof(tv.c_str());        memcpy(buf, &v, 8); break; }
        case DT_INT64:  { int64_t v = parseHexAwareInt(tv.c_str()); memcpy(buf, &v, 8); break; }
        case DT_INT8:   { int8_t  v = (int8_t)parseHexAwareInt(tv.c_str()); memcpy(buf, &v, 1); break; }
        case DT_INT16:  { int16_t v = (int16_t)parseHexAwareInt(tv.c_str()); memcpy(buf, &v, 2); break; }
        case DT_INT32:  { int32_t v = (int32_t)parseHexAwareInt(tv.c_str()); memcpy(buf, &v, 4); break; }
        default: err = "Type not supported for write"; return false;
    }
    DWORD oldProt = 0;
    if (bypass) VirtualProtectEx(s_hProc, addr, sz, PAGE_EXECUTE_READWRITE, &oldProt);
    SIZE_T wr = 0;
    BOOL ok = WriteProcessMemory(s_hProc, addr, buf, sz, &wr);
    if (bypass) { DWORD tmp; VirtualProtectEx(s_hProc, addr, sz, oldProt, &tmp); }
    if (!ok || wr != sz) { err = "WriteProcessMemory failed"; return false; }
    return true;
}

size_t exportResultsToCsv(const std::string& path, DataType dt) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "wb") != 0 || !f) return 0;
    fprintf(f, "index,address,value\r\n");
    size_t sz = dtSize(dt);
    BYTE buf[16];
    for (size_t i = 0; i < g_scan.results.size(); i++) {
        LPVOID a = g_scan.results[i];
        SIZE_T r = 0;
        std::string v = "?";
        if (s_hProc && ReadProcessMemory(s_hProc, a, buf, sz, &r) && r >= sz)
            v = formatTypedValue(buf, dt);
        fprintf(f, "%zu,0x%llX,%s\r\n", i + 1, (unsigned long long)(uintptr_t)a, v.c_str());
    }
    fclose(f);
    return g_scan.results.size();
}

// -- Snapshot / diff -----------------------------------------------------

void takeSnapshot(DataType dt) {
    if (!s_hProc || g_scan.results.empty()) return;
    g_snapshotDt = dt;
    size_t sz = dtSize(dt);
    g_snapshot.clear();
    g_snapshot.reserve(g_scan.results.size());
    for (LPVOID a : g_scan.results) {
        BYTE b[16] = {}; SIZE_T r = 0;
        ReadProcessMemory(s_hProc, a, b, sz, &r);
        g_snapshot.emplace_back(b, b + sz);
    }
}

bool filterByDiff(DataType dt, int mode, std::string& err) {
    if (!s_hProc) { err = "Not attached"; return false; }
    if (g_snapshot.empty() || g_snapshot.size() != g_scan.results.size()) {
        err = "Take a snapshot first (snapshot must match current result set size)";
        return false;
    }
    size_t sz = dtSize(dt);
    std::vector<LPVOID> next;
    std::vector<std::vector<BYTE>> nextPrev;
    std::vector<std::vector<BYTE>> nextSnap;
    for (size_t i = 0; i < g_scan.results.size(); i++) {
        if (g_scanStopRequested) break;
        LPVOID a = g_scan.results[i];
        BYTE cur[16] = {}; SIZE_T r = 0;
        if (!ReadProcessMemory(s_hProc, a, cur, sz, &r) || r < sz) continue;
        const BYTE* snap = g_snapshot[i].data();
        bool keep = false;
        if (mode == 0)      keep = (memcmp(cur, snap, sz) != 0);
        else if (mode == 1) keep = (memcmp(cur, snap, sz) == 0);
        else {
            double cd = valueAsDouble(cur, dt);
            double sd = valueAsDouble(snap, dt);
            if (mode == 2) keep = (cd > sd);
            else if (mode == 3) keep = (cd < sd);
        }
        if (keep) {
            next.push_back(a);
            nextPrev.emplace_back(cur, cur + sz);
            nextSnap.push_back(g_snapshot[i]);
        }
    }
    g_scan.results = std::move(next);
    g_scan.prevVals = std::move(nextPrev);
    g_snapshot = std::move(nextSnap);
    return true;
}

// -- Live monitor -------------------------------------------------------

void liveMonStart(DataType dt) {
    if (!s_hProc || g_scan.results.empty()) return;
    g_liveMonDt = dt;
    g_liveStats.assign(g_scan.results.size(), LiveStat{});
    size_t sz = dtSize(dt);
    for (size_t i = 0; i < g_scan.results.size(); i++) {
        SIZE_T r = 0;
        ReadProcessMemory(s_hProc, g_scan.results[i], g_liveStats[i].baseline, sz, &r);
        memcpy(g_liveStats[i].last, g_liveStats[i].baseline, sz);
        memcpy(g_liveStats[i].minV, g_liveStats[i].baseline, sz);
        memcpy(g_liveStats[i].maxV, g_liveStats[i].baseline, sz);
        g_liveStats[i].minMaxInit = true;
    }
    g_liveMonActive = true;
}

void liveMonStop() { g_liveMonActive = false; }

void liveMonTick() {
    if (!g_liveMonActive || !s_hProc) return;
    if (g_liveStats.size() != g_scan.results.size()) { g_liveMonActive = false; return; }
    int dt = g_liveMonDt;
    if (dt < 0) return;
    size_t sz = dtSize((DataType)dt);
    size_t hsz = sz > 8 ? 8 : sz;
    DWORD now = GetTickCount();
    for (size_t i = 0; i < g_scan.results.size(); i++) {
        BYTE cur[16] = {}; SIZE_T r = 0;
        if (!ReadProcessMemory(s_hProc, g_scan.results[i], cur, sz, &r) || r < sz) continue;
        LiveStat& s = g_liveStats[i];
        s.sampleCount++;
        // min/max
        switch ((DataType)dt) {
            case DT_INT8:  { int8_t  v=*(int8_t*)cur;  if(v<*(int8_t*)s.minV)*(int8_t*)s.minV=v;   if(v>*(int8_t*)s.maxV)*(int8_t*)s.maxV=v;} break;
            case DT_INT16: { int16_t v=*(int16_t*)cur; if(v<*(int16_t*)s.minV)*(int16_t*)s.minV=v; if(v>*(int16_t*)s.maxV)*(int16_t*)s.maxV=v;} break;
            case DT_INT32: { int32_t v=*(int32_t*)cur; if(v<*(int32_t*)s.minV)*(int32_t*)s.minV=v; if(v>*(int32_t*)s.maxV)*(int32_t*)s.maxV=v;} break;
            case DT_INT64: { int64_t v=*(int64_t*)cur; if(v<*(int64_t*)s.minV)*(int64_t*)s.minV=v; if(v>*(int64_t*)s.maxV)*(int64_t*)s.maxV=v;} break;
            case DT_FLOAT: { float   v=*(float*)cur;   if(v<*(float*)s.minV)*(float*)s.minV=v;     if(v>*(float*)s.maxV)*(float*)s.maxV=v;} break;
            case DT_DOUBLE:{ double  v=*(double*)cur;  if(v<*(double*)s.minV)*(double*)s.minV=v;   if(v>*(double*)s.maxV)*(double*)s.maxV=v;} break;
            default: break;
        }
        if (memcmp(cur, s.last, sz) != 0) {
            s.changed = true;
            s.changeCount++;
            double a = valueAsDouble(cur,    (DataType)dt);
            double b = valueAsDouble(s.last, (DataType)dt);
            if (a > b) s.increased = true;
            if (a < b) s.decreased = true;
            memset(s.history[s.historyHead], 0, 8);
            memcpy(s.history[s.historyHead], cur, hsz);
            s.historyTime[s.historyHead] = now;
            s.historyHead = (uint8_t)((s.historyHead + 1) % 16);
            if (s.historyCount < 16) s.historyCount++;
            memcpy(s.last, cur, sz);
        }
    }
}

static double liveRange(const LiveStat& s, DataType dt) {
    if (!s.minMaxInit) return 0;
    return valueAsDouble(s.maxV, dt) - valueAsDouble(s.minV, dt);
}

void computeLiveScores(DataType dt) {
    if (g_liveStats.empty()) return;
    for (size_t i = 0; i < g_liveStats.size(); i++) {
        LiveStat& s = g_liveStats[i];
        float score = 0;
        float rate = s.sampleCount > 0 ? (float)s.changeCount / (float)s.sampleCount : 0;
        if (rate > 0.005f && rate < 0.5f)       score += 25.0f;
        else if (rate >= 0.5f && rate < 0.95f)  score += 12.0f;
        else if (rate > 0)                       score += 5.0f;
        if (s.increased && s.decreased)         score += 25.0f;
        else if (s.increased || s.decreased)    score += 8.0f;
        double range = liveRange(s, dt);
        if (s.changed) {
            if (range > 0 && range <= 100)       score += 18.0f;
            else if (range > 0 && range <= 1000) score += 12.0f;
            else if (range > 0 && range <= 1e5)  score += 4.0f;
        }
        double baseV = valueAsDouble(s.baseline, dt);
        if (baseV >= 1 && baseV < 1e7) {
            int64_t b = (int64_t)baseV;
            if (b % 100 == 0)      score += 10.0f;
            else if (b % 10 == 0)  score += 5.0f;
            else if (b % 5 == 0)   score += 2.0f;
        }
        uintptr_t addrU = (uintptr_t)g_scan.results[i];
        if ((addrU & 0x3) == 0) score += 5.0f;
        if ((addrU & 0x7) == 0) score += 5.0f;
        if (s.historyCount > 0) score += (float)(s.historyCount < 7 ? s.historyCount : 7);
        s.score = score;
    }
}

bool filterByLiveChanged(DataType dt, std::string& err) {
    if (g_liveStats.empty() || g_liveStats.size() != g_scan.results.size()) {
        err = "No live-monitor data";
        return false;
    }
    size_t sz = dtSize(dt);
    std::vector<LPVOID> next;
    std::vector<std::vector<BYTE>> nextPrev;
    std::vector<LiveStat> nextStats;
    for (size_t i = 0; i < g_scan.results.size(); i++) {
        if (!g_liveStats[i].changed) continue;
        next.push_back(g_scan.results[i]);
        nextPrev.emplace_back(g_liveStats[i].last, g_liveStats[i].last + sz);
        nextStats.push_back(g_liveStats[i]);
    }
    g_scan.results = std::move(next);
    g_scan.prevVals = std::move(nextPrev);
    g_liveStats = std::move(nextStats);
    return true;
}

bool filterTopByScore(size_t topN, DataType dt, std::string& err) {
    if (g_liveStats.empty() || g_liveStats.size() != g_scan.results.size()) { err = "No live data"; return false; }
    computeLiveScores(dt);
    std::vector<size_t> idx(g_liveStats.size());
    for (size_t i = 0; i < idx.size(); i++) idx[i] = i;
    std::sort(idx.begin(), idx.end(), [](size_t a, size_t b){ return g_liveStats[a].score > g_liveStats[b].score; });
    if (topN > idx.size()) topN = idx.size();
    size_t sz = dtSize(dt);
    std::vector<LPVOID> next;
    std::vector<std::vector<BYTE>> nextPrev;
    std::vector<LiveStat> nextStats;
    for (size_t k = 0; k < topN; k++) {
        size_t i = idx[k];
        if (g_liveStats[i].score <= 0) break;
        next.push_back(g_scan.results[i]);
        nextPrev.emplace_back(g_liveStats[i].last, g_liveStats[i].last + sz);
        nextStats.push_back(g_liveStats[i]);
    }
    g_scan.results = std::move(next);
    g_scan.prevVals = std::move(nextPrev);
    g_liveStats = std::move(nextStats);
    return true;
}

bool filterByBoundedRange(double maxRange, DataType dt, std::string& err) {
    if (g_liveStats.empty() || g_liveStats.size() != g_scan.results.size()) { err = "No live data"; return false; }
    size_t sz = dtSize(dt);
    std::vector<LPVOID> next;
    std::vector<std::vector<BYTE>> nextPrev;
    std::vector<LiveStat> nextStats;
    for (size_t i = 0; i < g_scan.results.size(); i++) {
        const LiveStat& s = g_liveStats[i];
        if (!s.minMaxInit || !s.changed) continue;
        double range = liveRange(s, dt);
        if (range > maxRange) continue;
        next.push_back(g_scan.results[i]);
        nextPrev.emplace_back(s.last, s.last + sz);
        nextStats.push_back(s);
    }
    g_scan.results = std::move(next);
    g_scan.prevVals = std::move(nextPrev);
    g_liveStats = std::move(nextStats);
    return true;
}

bool doNextScan(const ScanParams& p, std::string& err) {
    if (!s_hProc) { err = "Not attached"; return false; }
    if (g_scan.results.empty()) { err = "No previous scan"; return false; }
    g_scanStopRequested = false;
    g_scanRunning = true;

    BYTE targetBuf[8] = {};
    size_t valSz = dtSize(p.dt);
    if (p.sc == SC_EXACT && p.dt != DT_STRING && p.dt != DT_AOB) {
        if (p.dt == DT_FLOAT)      { float v=(float)atof(p.value.c_str()); memcpy(targetBuf,&v,4); }
        else if (p.dt == DT_DOUBLE){ double v=atof(p.value.c_str()); memcpy(targetBuf,&v,8); }
        else if (p.dt == DT_INT64) { int64_t v=parseHexAwareInt(p.value.c_str()); memcpy(targetBuf,&v,8); }
        else {
            int64_t vv = parseHexAwareInt(p.value.c_str()); int32_t v = (int32_t)vv;
            if (p.dt == DT_INT8)       { int8_t  b=(int8_t)v;  memcpy(targetBuf,&b,1); }
            else if (p.dt == DT_INT16) { int16_t b=(int16_t)v; memcpy(targetBuf,&b,2); }
            else                        memcpy(targetBuf, &v, 4);
        }
    }

    std::vector<LPVOID> next;
    std::vector<std::vector<BYTE>> nextPrev;
    for (size_t i = 0; i < g_scan.results.size(); i++) {
        if (g_scanStopRequested) break;
        LPVOID a = g_scan.results[i];
        BYTE cur[16] = {}; SIZE_T r = 0;
        if (!ReadProcessMemory(s_hProc, a, cur, valSz, &r) || r < valSz) continue;
        const BYTE* prev = (i < g_scan.prevVals.size() && !g_scan.prevVals[i].empty())
                         ? g_scan.prevVals[i].data() : nullptr;
        if (matchesNumericCondition(cur, prev, targetBuf, p.dt, p.sc, valSz)) {
            next.push_back(a);
            nextPrev.emplace_back(cur, cur + valSz);
        }
    }
    g_scan.results = std::move(next);
    g_scan.prevVals = std::move(nextPrev);
    g_scanRunning = false;
    return true;
}

// ========================================================================
// Zydis disasm
// ========================================================================

static ZydisDecoder& zydisDecoder() {
    static ZydisDecoder d;
    static bool init = false;
    if (!init) { ZydisDecoderInit(&d, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64); init = true; }
    return d;
}
static ZydisFormatter& zydisFormatter() {
    static ZydisFormatter f;
    static bool init = false;
    if (!init) { ZydisFormatterInit(&f, ZYDIS_FORMATTER_STYLE_INTEL); init = true; }
    return f;
}

std::string disasmOneAtRemote(LPVOID remoteAddr) {
    if (!s_hProc || !remoteAddr) return "(not attached)";
    BYTE buf[16] = {}; SIZE_T r = 0;
    if (!ReadProcessMemory(s_hProc, remoteAddr, buf, sizeof(buf), &r) || r < 1) return "(unreadable)";
    ZydisDecodedInstruction ins; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&zydisDecoder(), buf, r, &ins, ops))) return "(decode fail)";
    char text[256];
    ZydisFormatterFormatInstruction(&zydisFormatter(), &ins, ops, ins.operand_count_visible,
                                     text, sizeof(text), (ZyanU64)(uintptr_t)remoteAddr, NULL);
    return text;
}

std::vector<DisasmLine> disasmRangeAtRemote(LPVOID remoteAddr, size_t nBytes, size_t maxLines) {
    std::vector<DisasmLine> out;
    if (!s_hProc || !remoteAddr || nBytes == 0) return out;
    if (nBytes > 4096) nBytes = 4096;
    std::vector<BYTE> buf(nBytes);
    SIZE_T r = 0;
    if (!ReadProcessMemory(s_hProc, remoteAddr, buf.data(), nBytes, &r) || r < 1) return out;
    size_t pos = 0;
    while (pos < r && out.size() < maxLines) {
        ZydisDecodedInstruction ins; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&zydisDecoder(), buf.data() + pos, r - pos, &ins, ops))) break;
        DisasmLine dl;
        dl.addr = (uintptr_t)remoteAddr + pos;
        dl.bytes.assign(buf.begin() + pos, buf.begin() + pos + ins.length);
        char text[256];
        ZydisFormatterFormatInstruction(&zydisFormatter(), &ins, ops, ins.operand_count_visible,
                                         text, sizeof(text), dl.addr, NULL);
        dl.text = text;
        out.push_back(std::move(dl));
        pos += ins.length;
    }
    return out;
}

// ========================================================================
// Modules
// ========================================================================

std::vector<ModuleEntry> listModules() {
    std::vector<ModuleEntry> out;
    if (!s_hProc) return out;
    HMODULE mods[1024]; DWORD cb = 0;
    if (!EnumProcessModulesEx(s_hProc, mods, sizeof(mods), &cb, LIST_MODULES_ALL)) return out;
    int n = (int)(cb / sizeof(HMODULE));
    for (int i = 0; i < n; i++) {
        ModuleEntry e;
        char nm[MAX_PATH] = {}, pt[MAX_PATH] = {};
        GetModuleBaseNameA(s_hProc, mods[i], nm, MAX_PATH);
        GetModuleFileNameExA(s_hProc, mods[i], pt, MAX_PATH);
        MODULEINFO mi{};
        GetModuleInformation(s_hProc, mods[i], &mi, sizeof(mi));
        e.name = nm; e.path = pt;
        e.base = (uintptr_t)mi.lpBaseOfDll;
        e.size = mi.SizeOfImage;
        out.push_back(std::move(e));
    }
    std::sort(out.begin(), out.end(),
              [](const ModuleEntry& a, const ModuleEntry& b){ return a.name < b.name; });
    return out;
}

HMODULE findRemoteModuleByName(const std::string& sub) {
    if (!s_hProc) return NULL;
    std::string lo = sub;
    for (auto& c : lo) c = (char)std::tolower((unsigned char)c);
    HMODULE mods[1024]; DWORD cb = 0;
    if (!EnumProcessModulesEx(s_hProc, mods, sizeof(mods), &cb, LIST_MODULES_ALL)) return NULL;
    int n = (int)(cb / sizeof(HMODULE));
    for (int i = 0; i < n; i++) {
        char nm[MAX_PATH] = {};
        GetModuleBaseNameA(s_hProc, mods[i], nm, MAX_PATH);
        std::string l = nm;
        for (auto& c : l) c = (char)std::tolower((unsigned char)c);
        if (l.find(lo) != std::string::npos) return mods[i];
    }
    return NULL;
}

bool injectDLL(const std::string& dllPath, std::string& err) {
    if (!s_hProc) { err = "Not attached"; return false; }
    if (dllPath.empty()) { err = "Empty DLL path"; return false; }
    size_t pathLen = dllPath.size() + 1;
    LPVOID remote = VirtualAllocEx(s_hProc, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { err = "VirtualAllocEx failed"; return false; }
    SIZE_T wr = 0;
    if (!WriteProcessMemory(s_hProc, remote, dllPath.c_str(), pathLen, &wr) || wr != pathLen) {
        err = "WriteProcessMemory failed"; VirtualFreeEx(s_hProc, remote, 0, MEM_RELEASE); return false;
    }
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE proc = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryA");
    if (!proc) { err = "LoadLibraryA address resolve failed"; VirtualFreeEx(s_hProc, remote, 0, MEM_RELEASE); return false; }
    HANDLE th = CreateRemoteThread(s_hProc, NULL, 0, proc, remote, 0, NULL);
    if (!th) { err = "CreateRemoteThread failed"; VirtualFreeEx(s_hProc, remote, 0, MEM_RELEASE); return false; }
    WaitForSingleObject(th, 8000);
    CloseHandle(th);
    VirtualFreeEx(s_hProc, remote, 0, MEM_RELEASE);
    return true;
}

bool ejectDLL(const std::string& sub, std::string& err) {
    if (!s_hProc) { err = "Not attached"; return false; }
    HMODULE m = findRemoteModuleByName(sub);
    if (!m) { err = "Module not found in target"; return false; }
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE proc = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "FreeLibrary");
    if (!proc) { err = "FreeLibrary address resolve failed"; return false; }
    HANDLE th = CreateRemoteThread(s_hProc, NULL, 0, proc, (LPVOID)m, 0, NULL);
    if (!th) { err = "CreateRemoteThread failed"; return false; }
    WaitForSingleObject(th, 8000);
    CloseHandle(th);
    return true;
}

// ========================================================================
// Binary patcher
// ========================================================================

std::vector<AppliedPatch> g_patches;

static bool writeWithProtect(uintptr_t addr, const BYTE* data, size_t n, std::string& err) {
    DWORD oldProt = 0;
    if (!VirtualProtectEx(s_hProc, (LPVOID)addr, n, PAGE_EXECUTE_READWRITE, &oldProt)) {
        err = "VirtualProtectEx failed"; return false;
    }
    SIZE_T wr = 0;
    BOOL ok = WriteProcessMemory(s_hProc, (LPVOID)addr, data, n, &wr);
    DWORD tmp; VirtualProtectEx(s_hProc, (LPVOID)addr, n, oldProt, &tmp);
    if (!ok || wr != n) { err = "WriteProcessMemory failed"; return false; }
    return true;
}

bool patcherRead(uintptr_t addr, size_t n, std::vector<BYTE>& out, std::string& err) {
    if (!s_hProc) { err = "Not attached"; return false; }
    if (n > 4096) n = 4096;
    out.assign(n, 0);
    SIZE_T r = 0;
    if (!ReadProcessMemory(s_hProc, (LPVOID)addr, out.data(), n, &r) || r < 1) { err = "Read failed"; return false; }
    out.resize(r);
    return true;
}

bool patcherWrite(uintptr_t addr, const std::vector<BYTE>& bytes, const std::string& label, std::string& err) {
    if (!s_hProc) { err = "Not attached"; return false; }
    if (bytes.empty()) { err = "No bytes to write"; return false; }
    std::vector<BYTE> orig;
    if (!patcherRead(addr, bytes.size(), orig, err)) return false;
    if (!writeWithProtect(addr, bytes.data(), bytes.size(), err)) return false;
    AppliedPatch p; p.addr = addr; p.original = orig; p.applied = bytes;
    p.label = label.empty() ? "bytes" : label;
    g_patches.push_back(std::move(p));
    return true;
}

bool patcherNop(uintptr_t addr, size_t n, const std::string& label, std::string& err) {
    if (n == 0 || n > 4096) { err = "Invalid NOP length"; return false; }
    std::vector<BYTE> nops(n, 0x90);
    return patcherWrite(addr, nops, label.empty() ? "nop" : label, err);
}

bool patcherNearJmp(uintptr_t addr, uintptr_t target, const std::string& label, std::string& err) {
    int64_t rel = (int64_t)target - (int64_t)addr - 5;
    if (rel > INT32_MAX || rel < INT32_MIN) { err = "Target too far for near jmp"; return false; }
    std::vector<BYTE> b(5);
    b[0] = 0xE9;
    int32_t r32 = (int32_t)rel;
    memcpy(b.data() + 1, &r32, 4);
    return patcherWrite(addr, b, label.empty() ? "near jmp" : label, err);
}

bool patcherRestore(size_t idx, std::string& err) {
    if (idx >= g_patches.size()) { err = "Patch index out of range"; return false; }
    AppliedPatch& p = g_patches[idx];
    if (!writeWithProtect(p.addr, p.original.data(), p.original.size(), err)) return false;
    g_patches.erase(g_patches.begin() + idx);
    return true;
}

// ========================================================================
// Pointer chains
// ========================================================================

std::vector<PointerChain> g_chains;

uintptr_t resolveChain(const PointerChain& c, std::string& err) {
    if (!s_hProc) { err = "Not attached"; return 0; }
    uintptr_t base = 0;
    if (!c.moduleName.empty()) {
        HMODULE m = findRemoteModuleByName(c.moduleName);
        if (!m) { err = "Module not found: " + c.moduleName; return 0; }
        base = (uintptr_t)m + c.moduleOffset;
    } else {
        base = c.moduleOffset;
    }
    uintptr_t addr = base;
    for (size_t i = 0; i < c.offsets.size(); i++) {
        uintptr_t deref = 0;
        SIZE_T r = 0;
        if (!ReadProcessMemory(s_hProc, (LPVOID)addr, &deref, sizeof(deref), &r) || r < sizeof(deref)) {
            err = "Dereference failed at level " + std::to_string(i);
            return 0;
        }
        addr = deref + c.offsets[i];
    }
    return addr;
}

bool saveChains(const std::string& path) {
    FILE* f = nullptr; if (fopen_s(&f, path.c_str(), "wb") != 0 || !f) return false;
    fprintf(f, "# memiscani pointer chains v1\n");
    for (const auto& c : g_chains) {
        fprintf(f, "CHAIN\nname=%s\nmodule=%s\nbase=%llX\noffs=", c.name.c_str(), c.moduleName.c_str(), (unsigned long long)c.moduleOffset);
        for (size_t i = 0; i < c.offsets.size(); i++) fprintf(f, "%s%llX", i?",":"", (unsigned long long)c.offsets[i]);
        fprintf(f, "\nENDCHAIN\n");
    }
    fclose(f); return true;
}

bool loadChains(const std::string& path) {
    FILE* f = nullptr; if (fopen_s(&f, path.c_str(), "rb") != 0 || !f) return false;
    g_chains.clear();
    char line[1024];
    PointerChain cur;
    bool inChain = false;
    while (fgets(line, sizeof(line), f)) {
        size_t L = strlen(line);
        while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = 0;
        if (!strcmp(line, "CHAIN")) { inChain = true; cur = PointerChain{}; }
        else if (!strcmp(line, "ENDCHAIN")) { g_chains.push_back(cur); inChain = false; }
        else if (inChain) {
            if (!strncmp(line, "name=", 5)) cur.name = line + 5;
            else if (!strncmp(line, "module=", 7)) cur.moduleName = line + 7;
            else if (!strncmp(line, "base=", 5)) cur.moduleOffset = (uintptr_t)_strtoui64(line + 5, nullptr, 16);
            else if (!strncmp(line, "offs=", 5)) {
                const char* p = line + 5;
                while (*p) {
                    char* e = nullptr; intptr_t v = (intptr_t)_strtoi64(p, &e, 16);
                    if (e == p) break;
                    cur.offsets.push_back(v);
                    p = e; while (*p == ',' || *p == ' ') p++;
                }
            }
        }
    }
    fclose(f); return true;
}

// ========================================================================
// Cheat scripts
// ========================================================================

std::vector<CheatEntry> g_cheats;

static std::string cheatTrim(std::string s) {
    while (!s.empty() && (unsigned char)s.front() <= ' ') s.erase(s.begin());
    while (!s.empty() && (unsigned char)s.back()  <= ' ') s.pop_back();
    return s;
}

uintptr_t cheatResolveAddr(const std::string& exprIn) {
    std::string expr = cheatTrim(exprIn);
    if (expr.empty()) return 0;
    size_t plus = expr.find('+');
    if (plus == std::string::npos) {
        const char* p = expr.c_str();
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        return (uintptr_t)_strtoui64(p, nullptr, 16);
    }
    std::string mod = cheatTrim(expr.substr(0, plus));
    std::string off = cheatTrim(expr.substr(plus + 1));
    while (!mod.empty() && (mod.front() == '"' || mod.front() == '\'')) mod.erase(mod.begin());
    while (!mod.empty() && (mod.back()  == '"' || mod.back()  == '\'')) mod.pop_back();
    const char* op = off.c_str();
    if (op[0] == '0' && (op[1] == 'x' || op[1] == 'X')) op += 2;
    uintptr_t offVal = (uintptr_t)_strtoui64(op, nullptr, 16);
    HMODULE m = findRemoteModuleByName(mod);
    if (!m) return 0;
    return (uintptr_t)m + offVal;
}

bool cheatExecute(CheatEntry& c, bool enableSection, std::string& err) {
    if (!s_hProc) { err = "Not attached"; return false; }
    const char* tag    = enableSection ? "[ENABLE]"  : "[DISABLE]";
    const char* endTag = enableSection ? "[DISABLE]" : "[ENABLE]";
    size_t start = c.script.find(tag);
    if (start == std::string::npos) { err = std::string("Missing ") + tag; return false; }
    start += strlen(tag);
    size_t endP = c.script.find(endTag, start);
    if (endP == std::string::npos) endP = c.script.size();
    std::string body = c.script.substr(start, endP - start);

    uintptr_t curAddr = 0;
    std::istringstream is(body);
    std::string line;
    int lineNum = 0;
    while (std::getline(is, line)) {
        lineNum++;
        size_t c1 = line.find("//"); if (c1 != std::string::npos) line.erase(c1);
        size_t c2 = line.find(';');  if (c2 != std::string::npos) line.erase(c2);
        line = cheatTrim(line);
        if (line.empty()) continue;
        if (line.back() == ':') {
            std::string addrStr = cheatTrim(line.substr(0, line.size() - 1));
            uintptr_t a = cheatResolveAddr(addrStr);
            if (!a) { char b[160]; sprintf(b, "Line %d: cannot resolve '%s'", lineNum, addrStr.c_str()); err = b; return false; }
            curAddr = a; continue;
        }
        std::string lo = line;
        for (char& c2 : lo) c2 = (char)std::tolower((unsigned char)c2);
        auto parseHex = [&](const char* startP, size_t unit, std::vector<BYTE>& out)->bool {
            const char* p = startP;
            while (*p) {
                while (*p == ' ' || *p == '\t' || *p == ',') p++;
                if (!*p) break;
                if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
                char* e = nullptr;
                unsigned long long v = _strtoui64(p, &e, 16);
                if (e == p) break;
                for (size_t k = 0; k < unit; k++) out.push_back((BYTE)((v >> (k * 8)) & 0xFF));
                p = e;
            }
            return !out.empty();
        };
        bool isDb = (lo.compare(0,3,"db ")==0 || lo.compare(0,3,"db\t")==0);
        bool isDw = (lo.compare(0,3,"dw ")==0 || lo.compare(0,3,"dw\t")==0);
        bool isDd = (lo.compare(0,3,"dd ")==0 || lo.compare(0,3,"dd\t")==0);
        bool isDq = (lo.compare(0,3,"dq ")==0 || lo.compare(0,3,"dq\t")==0);
        if (isDb || isDw || isDd || isDq) {
            size_t unit = isDb ? 1 : (isDw ? 2 : (isDd ? 4 : 8));
            std::vector<BYTE> bytes;
            if (!parseHex(line.c_str() + 3, unit, bytes)) { char b[120]; sprintf(b, "Line %d: no hex values", lineNum); err = b; return false; }
            if (!curAddr) { char b[80]; sprintf(b, "Line %d: no address set", lineNum); err = b; return false; }
            if (!writeWithProtect(curAddr, bytes.data(), bytes.size(), err)) { char b[200]; sprintf(b, "Line %d: %s", lineNum, err.c_str()); err = b; return false; }
            curAddr += bytes.size();
            continue;
        }
        if (lo == "nop" || lo.compare(0,4,"nop ")==0 || lo.compare(0,4,"nop\t")==0) {
            int count = 1;
            if (lo.size() > 3) { const char* p = line.c_str() + 3; while (*p == ' ' || *p == '\t') p++; if (*p) count = atoi(p); }
            if (count < 1) count = 1;
            std::vector<BYTE> nops(count, 0x90);
            if (!curAddr) { char b[80]; sprintf(b, "Line %d: no address set", lineNum); err = b; return false; }
            if (!writeWithProtect(curAddr, nops.data(), nops.size(), err)) { char b[200]; sprintf(b, "Line %d: %s", lineNum, err.c_str()); err = b; return false; }
            curAddr += nops.size();
            continue;
        }
        char b[200]; sprintf(b, "Line %d: unknown directive '%s'", lineNum, line.c_str()); err = b; return false;
    }
    return true;
}

bool cheatToggle(size_t idx, std::string& err) {
    if (idx >= g_cheats.size()) { err = "Index out of range"; return false; }
    bool toEnable = !g_cheats[idx].enabled;
    if (!cheatExecute(g_cheats[idx], toEnable, err)) return false;
    g_cheats[idx].enabled = toEnable;
    return true;
}

bool saveCheats(const std::string& path) {
    FILE* f = nullptr; if (fopen_s(&f, path.c_str(), "wb") != 0 || !f) return false;
    fprintf(f, "# memiscani cheat table v1\r\n");
    for (const auto& c : g_cheats) {
        fprintf(f, "---CHEAT---\r\nName: %s\r\nHotkey: %s\r\nEnabled: %d\r\nScript:\r\n",
                c.name.c_str(),
                (c.hotkeyVK >= VK_F1 && c.hotkeyVK <= VK_F5) ?
                    (std::string("F") + std::to_string(c.hotkeyVK - VK_F1 + 1)).c_str() : "",
                c.enabled ? 1 : 0);
        fwrite(c.script.data(), 1, c.script.size(), f);
        if (!c.script.empty() && c.script.back() != '\n') fprintf(f, "\r\n");
        fprintf(f, "---ENDSCRIPT---\r\n");
    }
    fclose(f); return true;
}

bool loadCheats(const std::string& path) {
    FILE* f = nullptr; if (fopen_s(&f, path.c_str(), "rb") != 0 || !f) return false;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    std::string blob(sz, 0);
    if (sz > 0) fread(&blob[0], 1, sz, f);
    fclose(f);
    g_cheats.clear();
    size_t p = 0;
    while (p < blob.size()) {
        size_t hdr = blob.find("---CHEAT---", p);
        if (hdr == std::string::npos) break;
        size_t next = blob.find("---CHEAT---", hdr + 11);
        std::string block = blob.substr(hdr + 11, (next == std::string::npos ? blob.size() : next) - (hdr + 11));
        p = (next == std::string::npos) ? blob.size() : next;
        CheatEntry c;
        size_t scriptStart = block.find("Script:");
        std::string header = (scriptStart == std::string::npos) ? block : block.substr(0, scriptStart);
        std::istringstream hs(header);
        std::string line;
        while (std::getline(hs, line)) {
            size_t cR = line.find('\r'); if (cR != std::string::npos) line.erase(cR);
            line = cheatTrim(line);
            if (line.compare(0, 5, "Name:") == 0) c.name = cheatTrim(line.substr(5));
            else if (line.compare(0, 7, "Hotkey:") == 0) {
                std::string h = cheatTrim(line.substr(7));
                for (auto& ch : h) ch = (char)std::toupper((unsigned char)ch);
                if (h == "F1") c.hotkeyVK = VK_F1;
                else if (h == "F2") c.hotkeyVK = VK_F2;
                else if (h == "F3") c.hotkeyVK = VK_F3;
                else if (h == "F4") c.hotkeyVK = VK_F4;
                else if (h == "F5") c.hotkeyVK = VK_F5;
            }
            else if (line.compare(0, 8, "Enabled:") == 0) c.enabled = false;
        }
        if (scriptStart != std::string::npos) {
            size_t sBeg = scriptStart + 7;
            while (sBeg < block.size() && (block[sBeg] == '\r' || block[sBeg] == '\n')) sBeg++;
            size_t sEnd = block.find("---ENDSCRIPT---", sBeg);
            if (sEnd == std::string::npos) sEnd = block.size();
            c.script = block.substr(sBeg, sEnd - sBeg);
            while (!c.script.empty() && (c.script.back() == '\r' || c.script.back() == '\n')) c.script.pop_back();
        }
        g_cheats.push_back(c);
    }
    return true;
}

// ========================================================================
// Code injection / caves / remote threads
// ========================================================================

LPVOID injectShellcode(const std::vector<BYTE>& sc, std::string& err) {
    if (!s_hProc) { err = "Not attached"; return NULL; }
    if (sc.empty()) { err = "Empty shellcode"; return NULL; }
    LPVOID remote = VirtualAllocEx(s_hProc, NULL, sc.size(), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) { err = "VirtualAllocEx failed"; return NULL; }
    SIZE_T wr = 0;
    if (!WriteProcessMemory(s_hProc, remote, sc.data(), sc.size(), &wr) || wr != sc.size()) {
        err = "WriteProcessMemory failed"; VirtualFreeEx(s_hProc, remote, 0, MEM_RELEASE); return NULL;
    }
    return remote;
}

bool injectAndExecute(const std::vector<BYTE>& sc, std::string& err, DWORD* outTid) {
    LPVOID remote = injectShellcode(sc, err);
    if (!remote) return false;
    DWORD tid = 0;
    HANDLE th = CreateRemoteThread(s_hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, &tid);
    if (!th) { err = "CreateRemoteThread failed"; VirtualFreeEx(s_hProc, remote, 0, MEM_RELEASE); return false; }
    if (outTid) *outTid = tid;
    CloseHandle(th);
    return true;
}

std::vector<CodeCave> scanCodeCaves(size_t minSize) {
    std::vector<CodeCave> out;
    if (!s_hProc) return out;
    SYSTEM_INFO si; GetSystemInfo(&si);
    LPVOID addr = si.lpMinimumApplicationAddress;
    while (addr < si.lpMaximumApplicationAddress && out.size() < 5000) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(s_hProc, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_READ|PAGE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            SIZE_T chunkSz = mbi.RegionSize > (SIZE_T)(1*1024*1024) ? (SIZE_T)(1*1024*1024) : mbi.RegionSize;
            std::vector<BYTE> chunk(chunkSz);
            SIZE_T r = 0;
            if (ReadProcessMemory(s_hProc, mbi.BaseAddress, chunk.data(), chunkSz, &r) && r > 0) {
                int runStart = -1, runLen = 0;
                for (int i = 0; i <= (int)r; i++) {
                    bool nullByte = (i < (int)r) && (chunk[i] == 0x00 || chunk[i] == 0x90 || chunk[i] == 0xCC);
                    if (nullByte) { if (runStart < 0) { runStart = i; runLen = 0; } runLen++; }
                    else {
                        if (runLen >= (int)minSize) {
                            CodeCave c;
                            c.addr = (LPVOID)((uintptr_t)mbi.BaseAddress + runStart);
                            c.size = runLen; c.protect = mbi.Protect;
                            out.push_back(c);
                            if (out.size() >= 5000) break;
                        }
                        runStart = -1; runLen = 0;
                    }
                }
            }
        }
        addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }
    return out;
}

std::vector<RemoteThreadEntry> listRemoteThreads() {
    std::vector<RemoteThreadEntry> out;
    if (!s_hProc || !s_pid) return out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == s_pid) {
                RemoteThreadEntry e;
                e.tid = te.th32ThreadID;
                e.startAddr = nullptr;
                e.priority = te.tpBasePri;
                HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (th) {
                    typedef NTSTATUS (NTAPI* PFN_NtQIT)(HANDLE,ULONG,PVOID,ULONG,PULONG);
                    HMODULE nt = GetModuleHandleA("ntdll.dll");
                    PFN_NtQIT pNtQIT = nt ? (PFN_NtQIT)GetProcAddress(nt, "NtQueryInformationThread") : nullptr;
                    if (pNtQIT) {
                        ULONG_PTR start = 0;
                        if (pNtQIT(th, 9 /*ThreadQuerySetWin32StartAddress*/, &start, sizeof(start), NULL) == 0)
                            e.startAddr = (LPVOID)start;
                    }
                    CloseHandle(th);
                }
                // Resolve start address to module
                e.startOffset = 0;
                if (e.startAddr) {
                    HMODULE mods[1024]; DWORD cb = 0;
                    if (EnumProcessModulesEx(s_hProc, mods, sizeof(mods), &cb, LIST_MODULES_ALL)) {
                        int n = (int)(cb / sizeof(HMODULE));
                        for (int i = 0; i < n; i++) {
                            MODULEINFO mi{}; GetModuleInformation(s_hProc, mods[i], &mi, sizeof(mi));
                            uintptr_t a = (uintptr_t)mi.lpBaseOfDll;
                            if ((uintptr_t)e.startAddr >= a && (uintptr_t)e.startAddr < a + mi.SizeOfImage) {
                                char nm[MAX_PATH]={}; GetModuleBaseNameA(s_hProc, mods[i], nm, MAX_PATH);
                                e.startModule = nm;
                                e.startOffset = (uintptr_t)e.startAddr - a;
                                break;
                            }
                        }
                    }
                }
                out.push_back(e);
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return out;
}

bool suspendThread(DWORD tid, std::string& err) {
    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!th) { err = "OpenThread failed"; return false; }
    bool ok = (SuspendThread(th) != (DWORD)-1);
    CloseHandle(th);
    if (!ok) err = "SuspendThread failed";
    return ok;
}
bool resumeThread(DWORD tid, std::string& err) {
    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!th) { err = "OpenThread failed"; return false; }
    bool ok = (ResumeThread(th) != (DWORD)-1);
    CloseHandle(th);
    if (!ok) err = "ResumeThread failed";
    return ok;
}
bool killThread(DWORD tid, std::string& err) {
    HANDLE th = OpenThread(THREAD_TERMINATE, FALSE, tid);
    if (!th) { err = "OpenThread failed"; return false; }
    bool ok = !!TerminateThread(th, 0);
    CloseHandle(th);
    if (!ok) err = "TerminateThread failed";
    return ok;
}

// ========================================================================
// Target windows
// ========================================================================
struct WndEnumCtx { DWORD pid; std::vector<TargetWindow>* out; };
static BOOL CALLBACK WndEnumProc(HWND hWnd, LPARAM lp) {
    WndEnumCtx* c = (WndEnumCtx*)lp;
    DWORD wpid = 0; GetWindowThreadProcessId(hWnd, &wpid);
    if (wpid != c->pid) return TRUE;
    char title[256] = {}, cls[128] = {};
    GetWindowTextA(hWnd, title, sizeof(title));
    GetClassNameA(hWnd, cls, sizeof(cls));
    TargetWindow w;
    w.hwnd = hWnd; w.title = title; w.className = cls; w.visible = !!IsWindowVisible(hWnd);
    c->out->push_back(w);
    return TRUE;
}
std::vector<TargetWindow> listTargetWindows() {
    std::vector<TargetWindow> out;
    if (!s_pid) return out;
    WndEnumCtx ctx{ s_pid, &out };
    EnumWindows(WndEnumProc, (LPARAM)&ctx);
    std::sort(out.begin(), out.end(),
              [](const TargetWindow& a, const TargetWindow& b){ return a.title < b.title; });
    return out;
}
bool sendWindowText(HWND hWnd, const std::string& text) {
    return !!SendMessageA(hWnd, WM_SETTEXT, 0, (LPARAM)text.c_str());
}
bool postWindowMessage(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    return !!PostMessageA(hWnd, msg, wp, lp);
}
bool windowShow(HWND hWnd, int nCmd) { return !!ShowWindow(hWnd, nCmd); }

// ========================================================================
// Detection scan
// ========================================================================
std::vector<DetectFinding> runDetectionScan(bool wantRwx, bool wantPrivExec, bool wantThreadAnom) {
    std::vector<DetectFinding> out;
    if (!s_hProc) return out;
    SYSTEM_INFO si; GetSystemInfo(&si);
    LPVOID addr = si.lpMinimumApplicationAddress;
    while (addr < si.lpMaximumApplicationAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(s_hProc, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD)) {
            bool isExec = !!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
            bool isRwx  = !!(mbi.Protect & PAGE_EXECUTE_READWRITE);
            if (wantRwx && isRwx) {
                DetectFinding f; f.category = "RWX";
                char b[128]; sprintf(b, "RWX %zu KB  type=%s",
                    mbi.RegionSize / 1024,
                    mbi.Type == MEM_IMAGE ? "image" : mbi.Type == MEM_MAPPED ? "mapped" : "private");
                f.detail = b; f.addr = mbi.BaseAddress; f.size = mbi.RegionSize;
                out.push_back(f);
            }
            if (wantPrivExec && isExec && mbi.Type == MEM_PRIVATE) {
                DetectFinding f; f.category = "PRIV+EXEC";
                char b[128]; sprintf(b, "executable PRIVATE %zu KB - manual map suspect", mbi.RegionSize / 1024);
                f.detail = b; f.addr = mbi.BaseAddress; f.size = mbi.RegionSize;
                out.push_back(f);
            }
        }
        addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        if (out.size() > 1000) break;
    }
    if (wantThreadAnom) {
        for (const auto& t : listRemoteThreads()) {
            if (t.startModule.empty()) {
                DetectFinding f; f.category = "THREAD";
                char b[160];
                sprintf(b, "TID %lu start 0x%llX is NOT in any loaded module - injected thread suspect",
                        t.tid, (unsigned long long)(uintptr_t)t.startAddr);
                f.detail = b; f.addr = t.startAddr; f.size = 0;
                out.push_back(f);
            }
        }
    }
    return out;
}

// ========================================================================
// Trigger
// ========================================================================
bool triggerCreateRemoteThread(LPVOID startAddr, LPVOID param, DWORD* outTid, std::string& err) {
    if (!s_hProc) { err = "Not attached"; return false; }
    DWORD tid = 0;
    HANDLE th = CreateRemoteThread(s_hProc, NULL, 0, (LPTHREAD_START_ROUTINE)startAddr, param, 0, &tid);
    if (!th) { err = "CreateRemoteThread failed"; return false; }
    if (outTid) *outTid = tid;
    CloseHandle(th);
    return true;
}
bool triggerQueueUserAPC(DWORD tid, LPVOID startAddr, LPVOID param, std::string& err) {
    HANDLE th = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
    if (!th) { err = "OpenThread failed"; return false; }
    DWORD r = QueueUserAPC((PAPCFUNC)startAddr, th, (ULONG_PTR)param);
    CloseHandle(th);
    if (!r) { err = "QueueUserAPC failed"; return false; }
    return true;
}

// ========================================================================
// Module exports
// ========================================================================
static std::vector<ExportRow> dumpExports(HMODULE mod, const std::string& modName) {
    std::vector<ExportRow> out;
    if (!s_hProc || !mod) return out;
    IMAGE_DOS_HEADER dos{};
    SIZE_T r = 0;
    if (!ReadProcessMemory(s_hProc, mod, &dos, sizeof(dos), &r) || dos.e_magic != IMAGE_DOS_SIGNATURE) return out;
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadProcessMemory(s_hProc, (LPCVOID)((BYTE*)mod + dos.e_lfanew), &nt, sizeof(nt), &r) || nt.Signature != IMAGE_NT_SIGNATURE) return out;
    DWORD expRva  = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD expSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!expRva || !expSize) return out;
    IMAGE_EXPORT_DIRECTORY ed{};
    if (!ReadProcessMemory(s_hProc, (LPCVOID)((BYTE*)mod + expRva), &ed, sizeof(ed), &r)) return out;
    if (!ed.NumberOfNames) return out;
    std::vector<DWORD> nameRVAs(ed.NumberOfNames);
    if (!ReadProcessMemory(s_hProc, (LPCVOID)((BYTE*)mod + ed.AddressOfNames), nameRVAs.data(), 4 * ed.NumberOfNames, &r)) return out;
    std::vector<WORD> ordinals(ed.NumberOfNames);
    if (!ReadProcessMemory(s_hProc, (LPCVOID)((BYTE*)mod + ed.AddressOfNameOrdinals), ordinals.data(), 2 * ed.NumberOfNames, &r)) return out;
    std::vector<DWORD> funcRVAs(ed.NumberOfFunctions);
    if (!ReadProcessMemory(s_hProc, (LPCVOID)((BYTE*)mod + ed.AddressOfFunctions), funcRVAs.data(), 4 * ed.NumberOfFunctions, &r)) return out;
    for (DWORD i = 0; i < ed.NumberOfNames; i++) {
        char name[256] = {};
        ReadProcessMemory(s_hProc, (LPCVOID)((BYTE*)mod + nameRVAs[i]), name, sizeof(name) - 1, &r);
        WORD ord = ordinals[i];
        if (ord >= ed.NumberOfFunctions) continue;
        ExportRow rw;
        rw.module = modName; rw.name = name; rw.ordinal = ord + ed.Base;
        rw.address = (LPVOID)((BYTE*)mod + funcRVAs[ord]);
        out.push_back(std::move(rw));
    }
    return out;
}
std::vector<ExportRow> enumerateAllExports() {
    std::vector<ExportRow> out;
    if (!s_hProc) return out;
    HMODULE mods[1024]; DWORD cb = 0;
    if (!EnumProcessModulesEx(s_hProc, mods, sizeof(mods), &cb, LIST_MODULES_ALL)) return out;
    int n = (int)(cb / sizeof(HMODULE));
    for (int i = 0; i < n; i++) {
        char nm[MAX_PATH] = {};
        GetModuleBaseNameA(s_hProc, mods[i], nm, MAX_PATH);
        auto ex = dumpExports(mods[i], nm);
        out.insert(out.end(), ex.begin(), ex.end());
        if (out.size() > 50000) break;
    }
    std::sort(out.begin(), out.end(),
              [](const ExportRow& a, const ExportRow& b){
                  if (a.module != b.module) return a.module < b.module;
                  return a.name < b.name;
              });
    return out;
}

// ========================================================================
// Auto pointer scanner (depth-N, capped candidates)
// ========================================================================
std::vector<AutoPtrChain> autoPointerScan(uintptr_t target, int maxDepth, intptr_t maxOff, size_t maxCandidates) {
    std::vector<AutoPtrChain> out;
    if (!s_hProc) return out;
    if (maxDepth < 1) maxDepth = 1; if (maxDepth > 5) maxDepth = 5;
    if (maxOff < 0x10) maxOff = 0x10; if (maxOff > 0x10000) maxOff = 0x10000;

    // Module ranges (image regions, used to detect "static" roots)
    struct ModRng { uintptr_t base, end; std::string name; };
    std::vector<ModRng> modRanges;
    {
        HMODULE mods[1024]; DWORD cb = 0;
        if (EnumProcessModulesEx(s_hProc, mods, sizeof(mods), &cb, LIST_MODULES_ALL)) {
            int n = (int)(cb / sizeof(HMODULE));
            for (int i = 0; i < n; i++) {
                MODULEINFO mi{}; GetModuleInformation(s_hProc, mods[i], &mi, sizeof(mi));
                char nm[MAX_PATH]={}; GetModuleBaseNameA(s_hProc, mods[i], nm, MAX_PATH);
                ModRng r{(uintptr_t)mi.lpBaseOfDll, (uintptr_t)mi.lpBaseOfDll + mi.SizeOfImage, nm};
                modRanges.push_back(r);
            }
        }
    }
    auto modOf = [&](uintptr_t a, ModRng** out)->bool {
        for (auto& r : modRanges) if (a >= r.base && a < r.end) { *out = &r; return true; }
        return false;
    };

    // Snapshot all readable memory
    struct Page { uintptr_t base; std::vector<BYTE> data; };
    std::vector<Page> pages;
    size_t totalRead = 0;
    {
        SYSTEM_INFO si; GetSystemInfo(&si);
        LPVOID addr = si.lpMinimumApplicationAddress;
        while (addr < si.lpMaximumApplicationAddress && totalRead < (size_t)256 * 1024 * 1024) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(s_hProc, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_READWRITE|PAGE_READONLY|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY)) &&
                !(mbi.Protect & PAGE_GUARD)) {
                SIZE_T chunkSz = mbi.RegionSize > (SIZE_T)(4*1024*1024) ? (SIZE_T)(4*1024*1024) : mbi.RegionSize;
                Page p; p.base = (uintptr_t)mbi.BaseAddress; p.data.resize(chunkSz);
                SIZE_T r = 0;
                if (ReadProcessMemory(s_hProc, mbi.BaseAddress, p.data.data(), chunkSz, &r) && r > 0) {
                    p.data.resize(r); totalRead += r; pages.push_back(std::move(p));
                }
            }
            addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        }
    }

    struct Candidate { uintptr_t pos; uintptr_t target; std::vector<intptr_t> offsetsSoFar; };
    std::vector<Candidate> level;
    level.push_back({0, target, {}});

    for (int d = 0; d < maxDepth; d++) {
        std::vector<Candidate> next;
        for (const auto& cand : level) {
            // For each page, scan qwords (aligned)
            for (const auto& pg : pages) {
                size_t n = pg.data.size();
                if (n < 8) continue;
                const uintptr_t* arr = (const uintptr_t*)pg.data.data();
                size_t cnt = n / 8;
                for (size_t i = 0; i < cnt; i++) {
                    uintptr_t v = arr[i];
                    if (v <= cand.target && cand.target - v <= (uintptr_t)maxOff) {
                        uintptr_t pos = pg.base + i * 8;
                        intptr_t offs = (intptr_t)(cand.target - v);
                        ModRng* mr = nullptr;
                        if (modOf(pos, &mr)) {
                            AutoPtrChain c;
                            c.moduleName = mr->name;
                            c.moduleOffset = pos - mr->base;
                            c.offsets = cand.offsetsSoFar;
                            c.offsets.push_back(offs);
                            out.push_back(std::move(c));
                            if (out.size() >= maxCandidates) return out;
                        } else if (d + 1 < maxDepth) {
                            Candidate nc;
                            nc.pos = pos; nc.target = pos;
                            nc.offsetsSoFar = cand.offsetsSoFar;
                            nc.offsetsSoFar.push_back(offs);
                            next.push_back(std::move(nc));
                            if (next.size() > maxCandidates) break;
                        }
                    }
                }
                if (next.size() > maxCandidates) break;
            }
        }
        if (next.empty()) break;
        if (next.size() > maxCandidates) next.resize(maxCandidates);
        level = std::move(next);
    }
    return out;
}

// ========================================================================
// Verify snapshot / diff
// ========================================================================
VerifySnapshot g_verify;

void takeVerifySnapshot() {
    g_verify.modules = listModules();
    g_verify.threads = listRemoteThreads();
}

// ========================================================================
// Inline assembler (ported from legacy)
// ========================================================================
namespace asmx {
    static std::string trim(const std::string& s){
        size_t st=s.find_first_not_of(" \t\r\n");
        if(st==std::string::npos)return"";
        std::string t=s.substr(st,s.find_last_not_of(" \t\r\n")-st+1);
        size_t c=t.find(';');if(c!=std::string::npos)t=t.substr(0,c);
        while(!t.empty()&&(t.back()==' '||t.back()=='\t'))t.pop_back();return t;
    }
    static std::string low(std::string s){ std::transform(s.begin(),s.end(),s.begin(),::tolower); return s; }
    static const struct{const char* name;int num;bool w64;}kReg[]={
        {"rax",0,1},{"rcx",1,1},{"rdx",2,1},{"rbx",3,1},{"rsp",4,1},{"rbp",5,1},{"rsi",6,1},{"rdi",7,1},
        {"r8",8,1},{"r9",9,1},{"r10",10,1},{"r11",11,1},{"r12",12,1},{"r13",13,1},{"r14",14,1},{"r15",15,1},
        {"eax",0,0},{"ecx",1,0},{"edx",2,0},{"ebx",3,0},{"esp",4,0},{"ebp",5,0},{"esi",6,0},{"edi",7,0},{nullptr,0,0}};
    static bool findReg(const std::string& nm,int& n,bool& w64){
        std::string l=low(nm);
        for(int i=0;kReg[i].name;i++) if(l==kReg[i].name){n=kReg[i].num;w64=kReg[i].w64;return true;}
        return false;
    }
    static bool parseMem(const std::string& expr,int& bn,bool& bw,int32_t& disp){
        std::string t=low(expr);
        size_t lb=t.find('['),rb=t.find(']');
        if(lb==std::string::npos||rb==std::string::npos)return false;
        std::string inner=trim(t.substr(lb+1,rb-lb-1));disp=0;
        size_t opPos=std::string::npos;int sign=0;
        for(size_t i=1;i<inner.size();i++){if(inner[i]=='+'){sign=1;opPos=i;break;}if(inner[i]=='-'){sign=-1;opPos=i;break;}}
        std::string regPart=opPos!=std::string::npos?trim(inner.substr(0,opPos)):inner;
        if(!findReg(regPart,bn,bw))return false;
        if(opPos!=std::string::npos){std::string dp=trim(inner.substr(opPos+1));disp=(int32_t)strtol(dp.c_str(),nullptr,0)*sign;}
        return true;
    }
    static void modrm(std::vector<BYTE>& out,int regF,int baseNum,int32_t disp){
        int rm=baseNum&7;
        int mod=(disp==0&&rm!=5)?0:(disp>=-128&&disp<=127)?1:2;
        out.push_back((BYTE)((mod<<6)|((regF&7)<<3)|rm));
        if(rm==4)out.push_back(0x24);
        if(mod==1)out.push_back((BYTE)(int8_t)disp);
        else if(mod==2){out.push_back(disp&0xFF);out.push_back((disp>>8)&0xFF);out.push_back((disp>>16)&0xFF);out.push_back((disp>>24)&0xFF);}
    }
    static void le32(std::vector<BYTE>& o,int32_t v){o.push_back(v&0xFF);o.push_back((v>>8)&0xFF);o.push_back((v>>16)&0xFF);o.push_back((v>>24)&0xFF);}
    static void le64(std::vector<BYTE>& o,uint64_t v){for(int i=0;i<8;i++)o.push_back((v>>(i*8))&0xFF);}
    static std::string stripSize(std::string s,int& sz){
        std::string sl=low(s);
        if(sl.find("qword")!=std::string::npos)sz=8;
        else if(sl.find("dword")!=std::string::npos)sz=4;
        else if(sl.find("word")!=std::string::npos&&sl.find("dword")==std::string::npos)sz=2;
        else if(sl.find("byte")!=std::string::npos)sz=1;
        for(const char* p:{"qword ptr","dword ptr","word ptr","byte ptr","qword","dword","word","byte"}){
            size_t pos=sl.find(p);if(pos!=std::string::npos){s=trim(s.substr(pos+strlen(p)));break;}
        }
        return s;
    }
    static std::string asmLine(const std::string& rawLine,std::vector<BYTE>& out){
        std::string line=trim(rawLine);if(line.empty())return"";
        std::string lo=low(line);
        if(lo=="nop"){out.push_back(0x90);return"";}
        if(lo=="ret"||lo=="retn"){out.push_back(0xC3);return"";}
        if(lo=="int3"||lo=="int 3"){out.push_back(0xCC);return"";}
        if(lo=="cdq"){out.push_back(0x99);return"";}
        if(lo=="pushfq"){out.push_back(0x9C);return"";}
        if(lo=="popfq"){out.push_back(0x9D);return"";}
        size_t sp=lo.find(' ');
        std::string mn=sp!=std::string::npos?lo.substr(0,sp):lo;
        std::string ops=sp!=std::string::npos?trim(line.substr(sp+1)):"";
        if(mn=="push"||mn=="pop"){
            int n;bool w;
            if(findReg(low(ops),n,w)&&w){
                BYTE base=(mn=="pop")?0x58:0x50;
                if(n>=8){out.push_back(0x41);out.push_back(base+(n-8));}else out.push_back(base+n);
                return"";
            }
            return mn+": unsupported register '"+ops+"'";
        }
        if(mn=="mov"||mn=="lea"){
            size_t comma=ops.find(',');if(comma==std::string::npos)return mn+": missing comma";
            std::string dst=trim(ops.substr(0,comma)),src=trim(ops.substr(comma+1));
            int sz=4;dst=stripSize(dst,sz);src=stripSize(src,sz);
            int dn,sn;bool dw,sw;
            bool dReg=findReg(low(dst),dn,dw),sReg=findReg(low(src),sn,sw);
            bool dMem=dst.find('[')!=std::string::npos,sMem=src.find('[')!=std::string::npos;
            if(mn=="lea"){if(!dReg||!sMem)return"lea: need reg, [mem]";int bn;bool bw;int32_t disp;if(!parseMem(src,bn,bw,disp))return"lea: bad mem ref";BYTE rex=dw?0x48:0x00;if(dn>=8)rex|=0x04;if(bn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(0x8D);modrm(out,dn&7,bn,disp);return"";}
            if(dReg&&dw&&!sMem&&!sReg){uint64_t imm=strtoull(src.c_str(),nullptr,0);out.push_back(0x48|(dn>=8?1:0));out.push_back(0xB8+(dn&7));le64(out,imm);return"";}
            if(dReg&&!dw&&!sMem&&!sReg){int32_t imm=(int32_t)strtoul(src.c_str(),nullptr,0);if(dn>=8)out.push_back(0x41);out.push_back(0xB8+(dn&7));le32(out,imm);return"";}
            if(dReg&&sReg&&dw==sw){BYTE rex=dw?0x48:0x00;if(sn>=8)rex|=0x04;if(dn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(0x89);out.push_back(0xC0|((sn&7)<<3)|(dn&7));return"";}
            if(dReg&&sMem){int bn;bool bw;int32_t disp;if(!parseMem(src,bn,bw,disp))return"mov: bad mem ref '"+src+"'";BYTE rex=dw?0x48:0x00;if(dn>=8)rex|=0x04;if(bn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(0x8B);modrm(out,dn&7,bn,disp);return"";}
            if(dMem&&sReg){int bn;bool bw;int32_t disp;if(!parseMem(dst,bn,bw,disp))return"mov: bad mem ref '"+dst+"'";BYTE rex=sw?0x48:0x00;if(sn>=8)rex|=0x04;if(bn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(0x89);modrm(out,sn&7,bn,disp);return"";}
            if(dMem&&!sReg){int bn;bool bw;int32_t disp;if(!parseMem(dst,bn,bw,disp))return"mov: bad mem ref '"+dst+"'";int64_t imm=strtoll(src.c_str(),nullptr,0);BYTE rex=0;if(bn>=8)rex|=0x01;if(sz==1){if(rex)out.push_back(0x40|rex);out.push_back(0xC6);modrm(out,0,bn,disp);out.push_back((BYTE)(uint8_t)imm);}else if(sz==2){out.push_back(0x66);if(rex)out.push_back(0x40|rex);out.push_back(0xC7);modrm(out,0,bn,disp);out.push_back(imm&0xFF);out.push_back((imm>>8)&0xFF);}else{if(rex)out.push_back(0x40|rex);out.push_back(0xC7);modrm(out,0,bn,disp);le32(out,(int32_t)imm);}return"";}
            return"mov: unsupported form '"+line+"'";
        }
        static const struct{const char* mn;int rf;BYTE rm2r;BYTE r2rm;}kArith[]={
            {"add",0,0x01,0x03},{"or",1,0x09,0x0B},{"adc",2,0x11,0x13},{"sbb",3,0x19,0x1B},
            {"and",4,0x21,0x23},{"sub",5,0x29,0x2B},{"xor",6,0x31,0x33},{"cmp",7,0x39,0x3B},{nullptr,0,0,0}};
        for(int ai=0;kArith[ai].mn;ai++){
            if(mn!=kArith[ai].mn)continue;
            size_t comma=ops.find(',');if(comma==std::string::npos)return mn+": missing comma";
            std::string dst=trim(ops.substr(0,comma)),src=trim(ops.substr(comma+1));
            int sz=4;dst=stripSize(dst,sz);bool dMem=dst.find('[')!=std::string::npos;
            int dn,sn;bool dw,sw;
            bool dReg=findReg(low(dst),dn,dw),sReg=findReg(low(src),sn,sw);
            bool sMem=src.find('[')!=std::string::npos;
            if(dReg&&sReg){BYTE rex=0;if(dw||sw)rex|=0x48;if(sn>=8)rex|=0x04;if(dn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(kArith[ai].r2rm);out.push_back(0xC0|((dn&7)<<3)|(sn&7));return"";}
            if(dReg&&!sReg&&!sMem){int64_t imm=strtoll(src.c_str(),nullptr,0);BYTE rex=0;if(dw)rex|=0x48;if(dn>=8)rex|=0x01;if(rex)out.push_back(rex);if(imm>=-128&&imm<=127){out.push_back(0x83);out.push_back(0xC0|(kArith[ai].rf<<3)|(dn&7));out.push_back((BYTE)(int8_t)imm);}else{out.push_back(0x81);out.push_back(0xC0|(kArith[ai].rf<<3)|(dn&7));le32(out,(int32_t)imm);}return"";}
            return mn+": unsupported form";
        }
        if(mn=="call"||mn=="jmp"){
            int rf=(mn=="jmp")?4:2;std::string op2=ops;int sz=8;op2=stripSize(op2,sz);int n;bool w;
            if(findReg(low(op2),n,w)){BYTE rex=0;if(n>=8)rex|=0x01;if(rex)out.push_back(0x40|rex);out.push_back(0xFF);out.push_back(0xC0|(rf<<3)|(n&7));return"";}
            return mn+": only register targets supported here (use jmp <label> in source)";
        }
        return"Unknown or unsupported instruction: "+mn;
    }
} // namespace asmx

bool assembleSource(const std::string& src, std::vector<BYTE>& out, std::string& err) {
    out.clear();
    std::map<std::string, size_t> labels;
    struct Fixup { size_t patchOff; std::string label; bool isLong; size_t insEnd; };
    std::vector<Fixup> fixups;
    auto isLabel = [](const std::string& s)->bool {
        if (s.empty()) return false;
        if (isdigit((unsigned char)s[0])) return false;
        if (s[0]=='-'||s[0]=='+') return false;
        if (s.size()>=2 && s[0]=='0' && (s[1]=='x'||s[1]=='X')) return false;
        int n; bool w; if (asmx::findReg(asmx::low(s), n, w)) return false;
        if (s.find('[')!=std::string::npos) return false;
        for (char c : s) if (!(isalnum((unsigned char)c)||c=='_'||c=='.')) return false;
        return true;
    };
    static const struct { const char* mn; BYTE opLong; } kJcc[] = {
        {"jo",0x80},{"jno",0x81},{"jb",0x82},{"jnb",0x83},{"jz",0x84},{"je",0x84},
        {"jnz",0x85},{"jne",0x85},{"jbe",0x86},{"ja",0x87},{"js",0x88},{"jns",0x89},
        {"jl",0x8C},{"jge",0x8D},{"jle",0x8E},{"jg",0x8F},{nullptr,0}
    };
    std::istringstream ss(src); std::string line; int ln = 0;
    while (std::getline(ss, line)) {
        ln++;
        std::string t = asmx::trim(line);
        if (t.empty()) continue;
        if (t.back() == ':') {
            std::string name = t.substr(0, t.size()-1);
            while (!name.empty() && (name.back()==' '||name.back()=='\t')) name.pop_back();
            if (!isLabel(name)) { err = "Line " + std::to_string(ln) + ": invalid label '" + name + "'"; return false; }
            if (labels.count(name)) { err = "Line " + std::to_string(ln) + ": duplicate label '" + name + "'"; return false; }
            labels[name] = out.size();
            continue;
        }
        std::string lo = asmx::low(t);
        size_t sp = lo.find_first_of(" \t");
        std::string mn = sp!=std::string::npos ? lo.substr(0,sp) : lo;
        std::string opsRaw = sp!=std::string::npos ? asmx::trim(t.substr(sp+1)) : "";
        if ((mn == "db" || mn == "dw" || mn == "dd" || mn == "dq") && !opsRaw.empty()) {
            int unit = (mn=="db")?1:(mn=="dw")?2:(mn=="dd")?4:8;
            const std::string& s = opsRaw;
            size_t p = 0;
            while (p < s.size()) {
                while (p < s.size() && (s[p]==' '||s[p]=='\t'||s[p]==',')) p++;
                if (p >= s.size()) break;
                size_t e2 = p; while (e2 < s.size() && s[e2]!=','&&s[e2]!=' '&&s[e2]!='\t') e2++;
                std::string tok = s.substr(p, e2 - p);
                uint64_t v = strtoull(tok.c_str(), nullptr, 0);
                for (int b = 0; b < unit; b++) out.push_back((BYTE)((v >> (b*8)) & 0xFF));
                p = e2;
            }
            continue;
        }
        bool handled = false;
        for (int i = 0; kJcc[i].mn; i++) {
            if (mn != kJcc[i].mn) continue;
            if (!isLabel(opsRaw)) break;
            out.push_back(0x0F); out.push_back(kJcc[i].opLong);
            Fixup fx; fx.patchOff = out.size(); fx.label = opsRaw; fx.isLong = true;
            for (int b = 0; b < 4; b++) out.push_back(0);
            fx.insEnd = out.size();
            fixups.push_back(fx);
            handled = true; break;
        }
        if (handled) continue;
        if ((mn == "jmp" || mn == "call") && isLabel(opsRaw)) {
            out.push_back(mn=="jmp" ? 0xE9 : 0xE8);
            Fixup fx; fx.patchOff = out.size(); fx.label = opsRaw; fx.isLong = true;
            for (int b = 0; b < 4; b++) out.push_back(0);
            fx.insEnd = out.size();
            fixups.push_back(fx); continue;
        }
        std::string e2 = asmx::asmLine(t, out);
        if (!e2.empty()) { err = "Line " + std::to_string(ln) + ": " + e2; return false; }
    }
    for (auto& fx : fixups) {
        auto it = labels.find(fx.label);
        if (it == labels.end()) { err = "Unresolved label '" + fx.label + "'"; return false; }
        int64_t rel = (int64_t)it->second - (int64_t)fx.insEnd;
        if (rel < INT32_MIN || rel > INT32_MAX) { err = "rel32 out of range for '" + fx.label + "'"; return false; }
        int32_t r32 = (int32_t)rel;
        for (int b = 0; b < 4; b++) out[fx.patchOff + b] = (BYTE)((r32 >> (b*8)) & 0xFF);
    }
    return !out.empty();
}

// ========================================================================
// AOB signature generator
// ========================================================================
static bool aobScanForFirstMatch(const std::vector<BYTE>& pat, const std::vector<bool>& mask,
                                 size_t& outHits, size_t maxScan = 256 * 1024 * 1024) {
    if (!s_hProc) return false;
    outHits = 0;
    SYSTEM_INFO si; GetSystemInfo(&si);
    LPVOID addr = si.lpMinimumApplicationAddress;
    size_t scanned = 0;
    while (addr < si.lpMaximumApplicationAddress && scanned < maxScan && outHits < 3) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(s_hProc, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD) && mbi.Type == MEM_IMAGE) {
            SIZE_T cap = mbi.RegionSize > (SIZE_T)(4*1024*1024) ? (SIZE_T)(4*1024*1024) : mbi.RegionSize;
            std::vector<BYTE> buf(cap);
            SIZE_T r = 0;
            if (ReadProcessMemory(s_hProc, mbi.BaseAddress, buf.data(), cap, &r) && r > pat.size()) {
                scanned += r;
                for (size_t i = 0; i + pat.size() <= r; i++) {
                    bool m = true;
                    for (size_t k = 0; k < pat.size(); k++)
                        if (!mask[k] && buf[i+k] != pat[k]) { m = false; break; }
                    if (m) { outHits++; if (outHits >= 3) break; }
                }
            }
        }
        addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }
    return true;
}

AobSignature generateAobSignature(LPVOID address, size_t minLen, size_t maxLen) {
    AobSignature sig{};
    sig.pattern = "(failed)";
    if (!s_hProc || !address) return sig;
    if (minLen < 4) minLen = 4;
    if (maxLen > 96) maxLen = 96;

    // Read enough bytes for decoding
    std::vector<BYTE> buf(maxLen + 32);
    SIZE_T r = 0;
    if (!ReadProcessMemory(s_hProc, address, buf.data(), buf.size(), &r) || r < minLen)
        return sig;
    buf.resize(r);

    // Walk instructions, mark bytes as wildcards where they could be relocatable
    std::vector<bool> wildcard(buf.size(), false);
    size_t pos = 0;
    while (pos < buf.size() && pos < maxLen) {
        ZydisDecodedInstruction ins; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&zydisDecoder(), buf.data() + pos, buf.size() - pos, &ins, ops))) break;
        // Mark RIP-relative displacement bytes as wildcards
        if (ins.raw.disp.offset && ins.raw.disp.size) {
            for (int b = 0; b < ops[0].element_count; b++) {} // noop
            // Check if any operand is RIP-relative memory
            for (int i = 0; i < ins.operand_count; i++) {
                if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    ops[i].mem.base == ZYDIS_REGISTER_RIP) {
                    size_t dispOff = pos + ins.raw.disp.offset;
                    size_t dispSz  = ins.raw.disp.size / 8;
                    for (size_t k = 0; k < dispSz && (dispOff + k) < wildcard.size(); k++)
                        wildcard[dispOff + k] = true;
                    break;
                }
            }
        }
        // Mark relative immediates (call/jmp) as wildcards
        if (ins.raw.imm[0].offset && ins.raw.imm[0].is_relative) {
            size_t immOff = pos + ins.raw.imm[0].offset;
            size_t immSz  = ins.raw.imm[0].size / 8;
            for (size_t k = 0; k < immSz && (immOff + k) < wildcard.size(); k++)
                wildcard[immOff + k] = true;
        }
        pos += ins.length;
    }
    if (pos < minLen) pos = std::min(buf.size(), maxLen);

    // Try lengths from minLen up, expand until unique (single hit)
    AobSignature best{};
    best.pattern = "(no unique pattern found)";
    for (size_t L = minLen; L <= pos; L++) {
        std::vector<BYTE> pat(buf.begin(), buf.begin() + L);
        std::vector<bool> mask(wildcard.begin(), wildcard.begin() + L);
        size_t hits = 0;
        aobScanForFirstMatch(pat, mask, hits);
        if (hits <= 1) {
            // Build pattern string
            std::string s;
            size_t wc = 0;
            char tmp[8];
            for (size_t i = 0; i < L; i++) {
                if (mask[i]) { s += "?? "; wc++; }
                else { sprintf(tmp, "%02X ", pat[i]); s += tmp; }
            }
            if (!s.empty()) s.pop_back();
            best.pattern = s;
            best.length = L;
            best.wildcards = wc;
            best.hits = hits;
            best.unique = (hits == 1);
            return best;
        }
    }
    return best;
}

// ========================================================================
// Live watch list
// ========================================================================
std::vector<WatchItem> g_watch;

void watchAdd(const std::string& name, LPVOID addr, DataType dt) {
    WatchItem w{};
    w.name = name.empty() ? "(unnamed)" : name;
    w.addr = addr; w.dt = dt;
    w.valid = false; w.flashChanged = false; w.flashUntil = 0;
    g_watch.push_back(w);
}
void watchRemove(size_t idx) { if (idx < g_watch.size()) g_watch.erase(g_watch.begin() + idx); }
void watchUpdateAll() {
    if (!s_hProc) return;
    DWORD now = GetTickCount();
    for (auto& w : g_watch) {
        BYTE cur[16] = {}; SIZE_T r = 0;
        size_t sz = dtSize(w.dt);
        w.valid = ReadProcessMemory(s_hProc, w.addr, cur, sz, &r) && r >= sz;
        if (w.valid) {
            if (memcmp(cur, w.lastVal, sz) != 0) {
                memcpy(w.prevVal, w.lastVal, sz);
                memcpy(w.lastVal, cur, sz);
                w.flashChanged = true;
                w.flashUntil = now + 600;
            } else if (now > w.flashUntil) {
                w.flashChanged = false;
            }
        }
    }
}
bool watchSave(const std::string& path) {
    FILE* f = nullptr; if (fopen_s(&f, path.c_str(), "wb") != 0 || !f) return false;
    fprintf(f, "# memiscani watch list v1\n");
    for (const auto& w : g_watch)
        fprintf(f, "%d|0x%llX|%s\n", (int)w.dt, (unsigned long long)(uintptr_t)w.addr, w.name.c_str());
    fclose(f); return true;
}
bool watchLoad(const std::string& path) {
    FILE* f = nullptr; if (fopen_s(&f, path.c_str(), "rb") != 0 || !f) return false;
    g_watch.clear();
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        size_t L = strlen(line); while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = 0;
        char* p1 = strchr(line, '|'); if (!p1) continue;
        char* p2 = strchr(p1+1, '|'); if (!p2) continue;
        int dt = atoi(line);
        const char* aStr = p1+1; if (aStr[0]=='0' && (aStr[1]=='x'||aStr[1]=='X')) aStr += 2;
        uintptr_t a = (uintptr_t)_strtoui64(aStr, nullptr, 16);
        watchAdd(p2+1, (LPVOID)a, (DataType)dt);
    }
    fclose(f); return true;
}

// ========================================================================
// Trampoline hooks (ported from legacy)
// ========================================================================
std::vector<TrampHook> g_thooks;

static bool relocateInsts(const BYTE* orig, size_t origLen,
                          uintptr_t origRip, uintptr_t newRip,
                          std::vector<BYTE>& out, std::string& err) {
    out.clear();
    size_t pos = 0;
    while (pos < origLen) {
        ZydisDecodedInstruction ins; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&zydisDecoder(), orig + pos, origLen - pos, &ins, ops))) { err = "decode failed during relocation"; return false; }
        uintptr_t insOrigRip = origRip + pos;
        uintptr_t insNewRip = newRip + out.size();
        uintptr_t origNext = insOrigRip + ins.length;
        bool ripMem = false, relImm = false;
        int64_t targetAbs = 0;
        ZyanU8 dispOff = 0, dispSz = 0;
        for (int i = 0; i < ins.operand_count; i++) {
            if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[i].mem.base == ZYDIS_REGISTER_RIP) {
                ripMem = true; targetAbs = (int64_t)origNext + ops[i].mem.disp.value;
                dispOff = ins.raw.disp.offset; dispSz = ins.raw.disp.size; break;
            }
            if (ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[i].imm.is_relative) {
                relImm = true; targetAbs = (int64_t)origNext + ops[i].imm.value.s; break;
            }
        }
        if (!ripMem && !relImm) { for (size_t k = 0; k < ins.length; k++) out.push_back(orig[pos+k]); pos += ins.length; continue; }
        if (ripMem) {
            int64_t nd = targetAbs - (int64_t)(insNewRip + ins.length);
            if (nd < INT32_MIN || nd > INT32_MAX || dispSz != 32) { err = "rip-rel disp out of range"; return false; }
            size_t outBase = out.size();
            for (size_t k = 0; k < ins.length; k++) out.push_back(orig[pos+k]);
            int32_t r32 = (int32_t)nd;
            for (int b = 0; b < 4; b++) out[outBase + dispOff + b] = (BYTE)((r32 >> (b*8)) & 0xFF);
        } else {
            BYTE first = orig[pos], second = ins.length>1 ? orig[pos+1] : 0;
            if ((first == 0xE8 || first == 0xE9) && ins.length == 5) {
                int64_t nd = targetAbs - (int64_t)(insNewRip + 5);
                if (nd >= INT32_MIN && nd <= INT32_MAX) {
                    out.push_back(first);
                    int32_t r32 = (int32_t)nd; for (int b = 0; b < 4; b++) out.push_back((BYTE)((r32>>(b*8))&0xFF));
                } else if (first == 0xE9) {
                    out.push_back(0xFF); out.push_back(0x25);
                    for (int b = 0; b < 4; b++) out.push_back(0);
                    uintptr_t t = (uintptr_t)targetAbs;
                    for (int b = 0; b < 8; b++) out.push_back((BYTE)((t>>(b*8))&0xFF));
                } else { err = "rel call too far"; return false; }
            } else if (first == 0x0F && (second >= 0x80 && second <= 0x8F) && ins.length == 6) {
                int64_t nd = targetAbs - (int64_t)(insNewRip + 6);
                if (nd < INT32_MIN || nd > INT32_MAX) { err = "long jcc out of range"; return false; }
                out.push_back(0x0F); out.push_back(second);
                int32_t r32 = (int32_t)nd; for (int b = 0; b < 4; b++) out.push_back((BYTE)((r32>>(b*8))&0xFF));
            } else if ((first >= 0x70 && first <= 0x7F) && ins.length == 2) {
                int64_t sd = targetAbs - (int64_t)(insNewRip + 2);
                if (sd >= -128 && sd <= 127) { out.push_back(first); out.push_back((BYTE)(int8_t)sd); }
                else {
                    int64_t ld = targetAbs - (int64_t)(insNewRip + 6);
                    if (ld < INT32_MIN || ld > INT32_MAX) { err = "jcc rel8 cannot widen"; return false; }
                    out.push_back(0x0F); out.push_back(first + 0x10);
                    int32_t r32 = (int32_t)ld; for (int b = 0; b < 4; b++) out.push_back((BYTE)((r32>>(b*8))&0xFF));
                }
            } else if (first == 0xEB && ins.length == 2) {
                int64_t sd = targetAbs - (int64_t)(insNewRip + 2);
                if (sd >= -128 && sd <= 127) { out.push_back(0xEB); out.push_back((BYTE)(int8_t)sd); }
                else {
                    int64_t ld = targetAbs - (int64_t)(insNewRip + 5);
                    if (ld < INT32_MIN || ld > INT32_MAX) { err = "jmp rel cannot widen"; return false; }
                    out.push_back(0xE9);
                    int32_t r32 = (int32_t)ld; for (int b = 0; b < 4; b++) out.push_back((BYTE)((r32>>(b*8))&0xFF));
                }
            } else { err = "unhandled relative branch"; return false; }
        }
        pos += ins.length;
    }
    return true;
}

static size_t spliceBoundary(const BYTE* buf, size_t bufLen, size_t minBytes, std::string& err) {
    size_t pos = 0;
    while (pos < minBytes && pos < bufLen) {
        ZydisDecodedInstruction ins; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&zydisDecoder(), buf + pos, bufLen - pos, &ins, ops))) { err = "decode failed at splice boundary"; return 0; }
        pos += ins.length;
    }
    return pos;
}

bool installTrampoline(LPVOID target, const std::vector<BYTE>& userPayload, size_t minStolen, const std::string& label, std::string& err) {
    if (!s_hProc || !target) { err = "Not attached"; return false; }
    if (minStolen < 14) minStolen = 14;
    BYTE prefetch[64] = {};
    SIZE_T r = 0;
    if (!ReadProcessMemory(s_hProc, target, prefetch, sizeof(prefetch), &r) || r < minStolen) { err = "Cannot read target"; return false; }
    size_t boundary = spliceBoundary(prefetch, r, minStolen, err);
    if (!boundary) return false;
    LPVOID cave = VirtualAllocEx(s_hProc, NULL, userPayload.size() + 32 + boundary, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!cave) { err = "VirtualAllocEx for cave failed"; return false; }
    std::vector<BYTE> caveBytes;
    caveBytes.insert(caveBytes.end(), userPayload.begin(), userPayload.end());
    std::vector<BYTE> relocated;
    if (!relocateInsts(prefetch, boundary, (uintptr_t)target,
                       (uintptr_t)cave + caveBytes.size(), relocated, err)) {
        VirtualFreeEx(s_hProc, cave, 0, MEM_RELEASE); return false;
    }
    caveBytes.insert(caveBytes.end(), relocated.begin(), relocated.end());
    // append abs JMP back to target+boundary
    caveBytes.push_back(0xFF); caveBytes.push_back(0x25);
    for (int b = 0; b < 4; b++) caveBytes.push_back(0);
    uintptr_t ret = (uintptr_t)target + boundary;
    for (int b = 0; b < 8; b++) caveBytes.push_back((BYTE)((ret >> (b*8)) & 0xFF));
    SIZE_T wr = 0;
    if (!WriteProcessMemory(s_hProc, cave, caveBytes.data(), caveBytes.size(), &wr) || wr != caveBytes.size()) {
        err = "Write cave failed"; VirtualFreeEx(s_hProc, cave, 0, MEM_RELEASE); return false;
    }
    // Splice at target: abs JMP to cave + NOP padding
    std::vector<BYTE> splice(boundary, 0x90);
    splice[0] = 0xFF; splice[1] = 0x25;
    for (int b = 0; b < 4; b++) splice[2+b] = 0;
    uintptr_t caveAddr = (uintptr_t)cave;
    for (int b = 0; b < 8; b++) splice[6+b] = (BYTE)((caveAddr >> (b*8)) & 0xFF);
    std::vector<BYTE> original(prefetch, prefetch + boundary);
    if (!writeWithProtect((uintptr_t)target, splice.data(), splice.size(), err)) {
        VirtualFreeEx(s_hProc, cave, 0, MEM_RELEASE); return false;
    }
    TrampHook h; h.target = target; h.cave = cave; h.stolen = original; h.stolenLen = boundary;
    h.label = label.empty() ? "hook" : label;
    g_thooks.push_back(h);
    return true;
}

bool uninstallTrampoline(size_t idx, std::string& err) {
    if (idx >= g_thooks.size()) { err = "Index out of range"; return false; }
    auto& h = g_thooks[idx];
    if (!writeWithProtect((uintptr_t)h.target, h.stolen.data(), h.stolen.size(), err)) return false;
    if (h.cave) VirtualFreeEx(s_hProc, h.cave, 0, MEM_RELEASE);
    g_thooks.erase(g_thooks.begin() + idx);
    return true;
}

// ========================================================================
// Hardware breakpoint tracer  (DebugActiveProcess + DR0/DR7 manipulation)
// ========================================================================
volatile bool             g_hwbpActive = false;
std::vector<HwbpLogEntry> g_hwbpLog;
uintptr_t                 g_hwbpWatchAddr = 0;
static HANDLE             s_hwbpThread = NULL;
static volatile bool      s_hwbpStopReq = false;
static int                s_hwbpType = HWBP_WRITE;
static int                s_hwbpSize = 4;
static DWORD              s_hwbpPid  = 0;

void hwbpClearLog() { g_hwbpLog.clear(); }

static void applyDr(HANDLE thread, uintptr_t addr, bool enable, int type, int size) {
    if (!thread) return;
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx)) return;
    if (!enable) {
        ctx.Dr0 = 0;
        ctx.Dr7 &= ~((DWORD64)1);                // disable DR0 (L0)
        ctx.Dr7 &= ~((DWORD64)0xF << 16);        // clear type/length for DR0
    } else {
        ctx.Dr0 = (DWORD64)addr;
        DWORD64 dr7 = ctx.Dr7;
        dr7 |= 1;                                 // L0 (DR0 enabled, locally)
        dr7 &= ~((DWORD64)0xF << 16);             // clear DR0 type/length nibble
        DWORD typeBits = (DWORD)type;             // 0=exec, 1=write, 3=rw
        DWORD lenBits;
        switch (size) { case 1: lenBits=0; break; case 2: lenBits=1; break; case 4: lenBits=3; break; case 8: lenBits=2; break; default: lenBits=3; }
        dr7 |= ((DWORD64)(typeBits | (lenBits<<2))) << 16;
        ctx.Dr7 = dr7;
    }
    SetThreadContext(thread, &ctx);
}

static void applyDrAllThreads(DWORD pid, uintptr_t addr, bool enable, int type, int size) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE th = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (th) {
                    SuspendThread(th);
                    applyDr(th, addr, enable, type, size);
                    ResumeThread(th);
                    CloseHandle(th);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static DWORD WINAPI hwbpThreadProc(LPVOID) {
    if (!DebugActiveProcess(s_hwbpPid)) { g_hwbpActive = false; return 1; }
    DebugSetProcessKillOnExit(FALSE);
    applyDrAllThreads(s_hwbpPid, g_hwbpWatchAddr, true, s_hwbpType, s_hwbpSize);
    while (!s_hwbpStopReq) {
        DEBUG_EVENT ev{};
        if (!WaitForDebugEvent(&ev, 100)) continue;
        DWORD cont = DBG_CONTINUE;
        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
            if (code == EXCEPTION_SINGLE_STEP) {
                HANDLE th = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT, FALSE, ev.dwThreadId);
                if (th) {
                    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(th, &ctx)) {
                        if (ctx.Dr6 & 0x1) {        // DR0 hit
                            HwbpLogEntry e;
                            e.tid = ev.dwThreadId;
                            e.offenderRip = (uintptr_t)ctx.Rip;
                            e.disasm = disasmOneAtRemote((LPVOID)ctx.Rip);
                            e.timeMs = GetTickCount();
                            if (g_hwbpLog.size() < 2000) g_hwbpLog.push_back(e);
                            ctx.Dr6 = 0;
                            // Set RF in EFlags so the instruction completes without re-triggering
                            ctx.EFlags |= 0x10000;
                            SetThreadContext(th, &ctx);
                        }
                    }
                    CloseHandle(th);
                }
            } else if (code == EXCEPTION_BREAKPOINT) {
                // initial bp from DebugActiveProcess - just continue
            } else {
                cont = DBG_EXCEPTION_NOT_HANDLED;
            }
        } else if (ev.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
            // Apply DR0 to new thread
            HANDLE th = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME, FALSE, ev.dwThreadId);
            if (th) { SuspendThread(th); applyDr(th, g_hwbpWatchAddr, true, s_hwbpType, s_hwbpSize); ResumeThread(th); CloseHandle(th); }
        } else if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
            break;
        }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
    }
    applyDrAllThreads(s_hwbpPid, 0, false, 0, 0);
    DebugActiveProcessStop(s_hwbpPid);
    g_hwbpActive = false;
    return 0;
}

bool hwbpEnable(uintptr_t addr, HwbpType type, int size, std::string& err) {
    if (!s_hProc) { err = "Not attached"; return false; }
    if (g_hwbpActive) { err = "Hardware breakpoint already active - disable first"; return false; }
    g_hwbpLog.clear();
    g_hwbpWatchAddr = addr;
    s_hwbpType = (int)type;
    s_hwbpSize = size;
    s_hwbpPid  = s_pid;
    s_hwbpStopReq = false;
    g_hwbpActive = true;
    s_hwbpThread = CreateThread(NULL, 0, hwbpThreadProc, NULL, 0, NULL);
    if (!s_hwbpThread) { err = "CreateThread failed"; g_hwbpActive = false; return false; }
    return true;
}

void hwbpDisable() {
    if (!g_hwbpActive) return;
    s_hwbpStopReq = true;
    if (s_hwbpThread) { WaitForSingleObject(s_hwbpThread, 5000); CloseHandle(s_hwbpThread); s_hwbpThread = NULL; }
    g_hwbpActive = false;
}

// ========================================================================
// Memory hex viewer
// ========================================================================
bool hexRead(uintptr_t addr, size_t n, std::vector<BYTE>& out, std::string& err) {
    if (!s_hProc) { err = "Not attached"; return false; }
    if (n == 0 || n > 1024 * 1024) { err = "Bad size"; return false; }
    out.assign(n, 0);
    SIZE_T r = 0;
    if (!ReadProcessMemory(s_hProc, (LPVOID)addr, out.data(), n, &r) || r < 1) { err = "ReadProcessMemory failed"; out.clear(); return false; }
    out.resize(r);
    return true;
}
bool hexWrite(uintptr_t addr, const std::vector<BYTE>& bytes, bool bypassRO, std::string& err) {
    if (!s_hProc) { err = "Not attached"; return false; }
    if (bytes.empty()) { err = "No bytes"; return false; }
    DWORD oldProt = 0;
    if (bypassRO && !VirtualProtectEx(s_hProc, (LPVOID)addr, bytes.size(), PAGE_EXECUTE_READWRITE, &oldProt)) { err = "VirtualProtectEx failed"; return false; }
    SIZE_T wr = 0;
    BOOL ok = WriteProcessMemory(s_hProc, (LPVOID)addr, bytes.data(), bytes.size(), &wr);
    if (bypassRO) { DWORD t; VirtualProtectEx(s_hProc, (LPVOID)addr, bytes.size(), oldProt, &t); }
    if (!ok || wr != bytes.size()) { err = "WriteProcessMemory failed"; return false; }
    return true;
}

// ========================================================================
// Bookmarks
// ========================================================================
std::vector<Bookmark> g_bookmarks;
void bookmarkAdd(const std::string& name, LPVOID addr, DataType dt, const std::string& note) {
    Bookmark b; b.name = name.empty() ? "(unnamed)" : name;
    b.addr = addr; b.dt = dt; b.note = note;
    g_bookmarks.push_back(b);
}
void bookmarkRemove(size_t idx) { if (idx < g_bookmarks.size()) g_bookmarks.erase(g_bookmarks.begin() + idx); }
bool bookmarkSave(const std::string& path) {
    FILE* f = nullptr; if (fopen_s(&f, path.c_str(), "wb") != 0 || !f) return false;
    fprintf(f, "# memiscani bookmarks v1\n");
    for (const auto& b : g_bookmarks) {
        // Escape pipes in name/note
        std::string n = b.name, no = b.note;
        for (char& c : n)  if (c == '|') c = ' ';
        for (char& c : no) if (c == '|') c = ' ';
        fprintf(f, "%d|0x%llX|%s|%s\n", (int)b.dt, (unsigned long long)(uintptr_t)b.addr, n.c_str(), no.c_str());
    }
    fclose(f); return true;
}
bool bookmarkLoad(const std::string& path) {
    FILE* f = nullptr; if (fopen_s(&f, path.c_str(), "rb") != 0 || !f) return false;
    g_bookmarks.clear();
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        size_t L = strlen(line); while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = 0;
        char* p1 = strchr(line, '|'); if (!p1) continue;
        char* p2 = strchr(p1+1, '|'); if (!p2) continue;
        char* p3 = strchr(p2+1, '|'); if (!p3) continue;
        int dt = atoi(line);
        const char* aStr = p1+1; if (aStr[0]=='0' && (aStr[1]=='x'||aStr[1]=='X')) aStr += 2;
        uintptr_t a = (uintptr_t)_strtoui64(aStr, nullptr, 16);
        std::string name(p2+1, p3 - (p2+1));
        std::string note(p3+1);
        bookmarkAdd(name, (LPVOID)a, (DataType)dt, note);
    }
    fclose(f); return true;
}

// ========================================================================
// Auto type detection
// ========================================================================
static float plausibilityInt(int64_t v, size_t bits) {
    // Heuristic: small to moderate positive ints in normal game ranges are most plausible
    if (v == 0) return 0.35f;                       // common but generic
    int64_t magnitude = v < 0 ? -v : v;
    // Pattern fill markers - very unlikely real data
    uint64_t u = (uint64_t)v;
    if (bits == 32 && (u == 0xCCCCCCCC || u == 0xCDCDCDCD || u == 0xFEEEFEEE || u == 0xBAADF00D)) return 0.05f;
    if (bits == 32 && u == 0xFFFFFFFF) return 0.15f;
    if (magnitude < 100)                 return 0.85f;
    if (magnitude < 1000)                return 0.90f;
    if (magnitude < 100000)              return 0.85f;
    if (magnitude < 100000000)           return 0.70f;
    if (magnitude < 1000000000000LL)     return 0.40f;
    return 0.15f;
}
static float plausibilityFloat(double v) {
    if (v == 0) return 0.40f;
    if (!std::isfinite(v)) return 0.02f;
    double a = v < 0 ? -v : v;
    if (a >= 1e-30 && a < 1e-6)  return 0.15f; // tiny denormals - usually noise
    if (a < 1e10 && a > 1e-6)    return 0.85f;
    return 0.20f;
}

std::vector<TypeGuess> guessTypeAt(LPVOID addr) {
    std::vector<TypeGuess> out;
    if (!s_hProc) return out;
    BYTE buf[16] = {}; SIZE_T r = 0;
    if (!ReadProcessMemory(s_hProc, addr, buf, sizeof(buf), &r) || r < 4) return out;

    auto add = [&](DataType dt, std::string val, float p, std::string why){
        TypeGuess g; g.dt = dt; g.formatted = std::move(val); g.plausibility = p; g.reason = std::move(why);
        out.push_back(g);
    };
    add(DT_INT8 , formatTypedValue(buf, DT_INT8 ), plausibilityInt(*(int8_t*)buf , 8 ), "narrow signed byte");
    add(DT_INT16, formatTypedValue(buf, DT_INT16), plausibilityInt(*(int16_t*)buf, 16), "16-bit signed");
    add(DT_INT32, formatTypedValue(buf, DT_INT32), plausibilityInt(*(int32_t*)buf, 32), "32-bit signed");
    if (r >= 8) {
        add(DT_INT64 , formatTypedValue(buf, DT_INT64 ), plausibilityInt(*(int64_t*)buf, 64), "64-bit signed");
        add(DT_DOUBLE, formatTypedValue(buf, DT_DOUBLE), plausibilityFloat(*(double*)buf), "IEEE-754 double");
        // Pointer heuristic on 8 bytes
        uint64_t u = *(uint64_t*)buf;
        if (u >= 0x10000 && u < 0x7FFFFFFFFFFF) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(s_hProc, (LPCVOID)u, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.State == MEM_COMMIT) {
                char buf2[64]; sprintf(buf2, "0x%llX", (unsigned long long)u);
                add(DT_INT64, buf2, 0.80f, "pointer-shaped, dereferences to valid memory");
            }
        }
    }
    add(DT_FLOAT, formatTypedValue(buf, DT_FLOAT), plausibilityFloat(*(float*)buf), "IEEE-754 float");

    std::sort(out.begin(), out.end(), [](const TypeGuess& a, const TypeGuess& b){ return a.plausibility > b.plausibility; });
    return out;
}

// ========================================================================
// PE info viewer
// ========================================================================
PEInfo getPEInfo(HMODULE mod, const std::string& modName) {
    PEInfo info{};
    info.moduleName = modName;
    if (!s_hProc || !mod) return info;
    IMAGE_DOS_HEADER dos{};
    SIZE_T r = 0;
    if (!ReadProcessMemory(s_hProc, mod, &dos, sizeof(dos), &r) || dos.e_magic != IMAGE_DOS_SIGNATURE) return info;

    // Read NT headers
    IMAGE_NT_HEADERS64 nt64{};
    if (!ReadProcessMemory(s_hProc, (LPCVOID)((BYTE*)mod + dos.e_lfanew), &nt64, sizeof(nt64), &r) || nt64.Signature != IMAGE_NT_SIGNATURE) return info;
    info.is64 = (nt64.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    info.imageBase = (uintptr_t)mod;
    info.imageSize = nt64.OptionalHeader.SizeOfImage;
    info.timestamp = nt64.FileHeader.TimeDateStamp;
    info.checksum  = nt64.OptionalHeader.CheckSum;

    // Sections
    LPVOID secStart = (LPVOID)((BYTE*)mod + dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt64.FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < nt64.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sh{};
        if (!ReadProcessMemory(s_hProc, (LPVOID)((BYTE*)secStart + i * sizeof(IMAGE_SECTION_HEADER)), &sh, sizeof(sh), &r)) break;
        PESection ps;
        char nm[16] = {}; memcpy(nm, sh.Name, 8);
        ps.name = nm;
        ps.rva = sh.VirtualAddress;
        ps.vsize = sh.Misc.VirtualSize;
        ps.characteristics = sh.Characteristics;
        info.sections.push_back(std::move(ps));
    }

    // Imports
    DWORD impRva  = nt64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (impRva) {
        IMAGE_IMPORT_DESCRIPTOR idt{};
        size_t i = 0;
        while (i < 256) {
            if (!ReadProcessMemory(s_hProc, (LPVOID)((BYTE*)mod + impRva + i * sizeof(idt)), &idt, sizeof(idt), &r)) break;
            if (idt.Name == 0 && idt.FirstThunk == 0) break;
            char dllName[256] = {};
            ReadProcessMemory(s_hProc, (LPVOID)((BYTE*)mod + idt.Name), dllName, sizeof(dllName)-1, &r);
            // Walk OriginalFirstThunk
            DWORD oft = idt.OriginalFirstThunk ? idt.OriginalFirstThunk : idt.FirstThunk;
            size_t k = 0;
            while (k < 4096) {
                ULONGLONG thunk = 0;
                if (!ReadProcessMemory(s_hProc, (LPVOID)((BYTE*)mod + oft + k * sizeof(ULONGLONG)), &thunk, sizeof(thunk), &r)) break;
                if (!thunk) break;
                PEImport ipt;
                ipt.dll = dllName;
                ipt.iatPointer = (LPVOID)((BYTE*)mod + idt.FirstThunk + k * sizeof(ULONGLONG));
                if (thunk & 0x8000000000000000ULL) {
                    // Ordinal
                    char ord[32]; sprintf(ord, "#%llu", (unsigned long long)(thunk & 0xFFFF));
                    ipt.name = ord;
                } else {
                    IMAGE_IMPORT_BY_NAME ibn{};
                    char nameBuf[256] = {};
                    ReadProcessMemory(s_hProc, (LPVOID)((BYTE*)mod + thunk + 2), nameBuf, sizeof(nameBuf)-1, &r);
                    ipt.name = nameBuf;
                }
                info.imports.push_back(std::move(ipt));
                k++;
                if (info.imports.size() > 8000) break;
            }
            i++;
            if (info.imports.size() > 8000) break;
        }
    }

    // Exports (reuse dumpExports)
    info.exports = enumerateAllExports();
    // Filter to this module
    info.exports.erase(std::remove_if(info.exports.begin(), info.exports.end(),
        [&](const ExportRow& e){ return e.module != modName; }), info.exports.end());

    return info;
}

// ========================================================================
// Process suspend / resume all
// ========================================================================
volatile bool g_processSuspended = false;

size_t suspendAllThreads() {
    if (!s_pid) return 0;
    size_t n = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == s_pid) {
                HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (th) { SuspendThread(th); CloseHandle(th); n++; }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    g_processSuspended = true;
    return n;
}
size_t resumeAllThreads() {
    if (!s_pid) return 0;
    size_t n = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == s_pid) {
                HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (th) { ResumeThread(th); CloseHandle(th); n++; }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    g_processSuspended = false;
    return n;
}

// ========================================================================
// Stack walker (heuristic - reads qwords from RSP forward, treats those that
// look like return addresses in module code regions as frame anchors)
// ========================================================================
std::vector<StackFrame> walkStack(DWORD tid, size_t maxFrames) {
    std::vector<StackFrame> out;
    if (!s_hProc) return out;
    HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!th) return out;
    SuspendThread(th);
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(th, &ctx)) { ResumeThread(th); CloseHandle(th); return out; }
    ResumeThread(th); CloseHandle(th);

    // Build module ranges for code-section identification
    struct ModR { uintptr_t base, end; std::string name; };
    std::vector<ModR> modR;
    HMODULE mods[1024]; DWORD cb = 0;
    if (EnumProcessModulesEx(s_hProc, mods, sizeof(mods), &cb, LIST_MODULES_ALL)) {
        int n = (int)(cb / sizeof(HMODULE));
        for (int i = 0; i < n; i++) {
            MODULEINFO mi{}; GetModuleInformation(s_hProc, mods[i], &mi, sizeof(mi));
            char nm[MAX_PATH]={}; GetModuleBaseNameA(s_hProc, mods[i], nm, MAX_PATH);
            modR.push_back({(uintptr_t)mi.lpBaseOfDll, (uintptr_t)mi.lpBaseOfDll + mi.SizeOfImage, nm});
        }
    }
    auto findMod = [&](uintptr_t a, std::string& name, uintptr_t& off)->bool {
        for (auto& m : modR) if (a >= m.base && a < m.end) { name = m.name; off = a - m.base; return true; }
        return false;
    };

    // First frame from current RIP
    StackFrame f0;
    f0.rip = (uintptr_t)ctx.Rip;
    f0.rsp = (uintptr_t)ctx.Rsp;
    findMod(f0.rip, f0.moduleName, f0.moduleOffset);
    f0.disasm = disasmOneAtRemote((LPVOID)f0.rip);
    out.push_back(f0);

    // Heuristic walk: read 256 qwords from RSP up, keep ones that look like return addresses
    uintptr_t rsp = (uintptr_t)ctx.Rsp;
    BYTE buf[8 * 256];
    SIZE_T r = 0;
    if (ReadProcessMemory(s_hProc, (LPVOID)rsp, buf, sizeof(buf), &r)) {
        size_t cnt = r / 8;
        for (size_t i = 0; i < cnt && out.size() < maxFrames; i++) {
            uintptr_t cand = ((uintptr_t*)buf)[i];
            std::string name; uintptr_t off;
            if (findMod(cand, name, off)) {
                StackFrame f;
                f.rip = cand;
                f.rsp = rsp + i * 8;
                f.moduleName = name;
                f.moduleOffset = off;
                f.disasm = disasmOneAtRemote((LPVOID)(cand - 5));   // disassemble likely call site
                out.push_back(f);
            }
        }
    }
    return out;
}

// ========================================================================
// Process tree + Network endpoints
// ========================================================================
std::vector<ProcessNode> listProcessesTree(const std::string& filter) {
    std::vector<ProcessNode> all;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return all;
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessNode n;
            n.pid = pe.th32ProcessID;
            n.ppid = pe.th32ParentProcessID;
            int sz = WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nullptr, 0, nullptr, nullptr);
            if (sz > 1) {
                std::string s(sz - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, &s[0], sz, nullptr, nullptr);
                n.name = s;
            }
            n.depth = 0;
            all.push_back(n);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    // Build a quick child map: ppid -> indices
    std::map<DWORD, std::vector<size_t>> children;
    std::map<DWORD, size_t> byPid;
    for (size_t i = 0; i < all.size(); i++) byPid[all[i].pid] = i;
    for (size_t i = 0; i < all.size(); i++) {
        if (all[i].ppid != all[i].pid && byPid.count(all[i].ppid))
            children[all[i].ppid].push_back(i);
    }
    // Find roots (pids whose parent is missing OR self-parent)
    std::vector<size_t> roots;
    for (size_t i = 0; i < all.size(); i++)
        if (!byPid.count(all[i].ppid) || all[i].ppid == all[i].pid) roots.push_back(i);
    // Sort roots by name
    std::sort(roots.begin(), roots.end(), [&](size_t a, size_t b){ return all[a].name < all[b].name; });

    // DFS traversal, building depth
    std::vector<ProcessNode> ordered;
    std::function<void(size_t,int)> dfs = [&](size_t i, int d) {
        ProcessNode n = all[i]; n.depth = d;
        ordered.push_back(n);
        auto it = children.find(all[i].pid);
        if (it == children.end()) return;
        auto cc = it->second;
        std::sort(cc.begin(), cc.end(), [&](size_t a, size_t b){ return all[a].name < all[b].name; });
        for (size_t c : cc) dfs(c, d + 1);
    };
    for (size_t r : roots) dfs(r, 0);

    // Apply substring filter (case-insensitive) - but keep ancestor context for visible matches
    if (!filter.empty()) {
        std::string fl = filter;
        for (auto& c : fl) c = (char)std::tolower((unsigned char)c);
        // Build set of visible indices in `ordered`
        std::vector<bool> keep(ordered.size(), false);
        for (size_t i = 0; i < ordered.size(); i++) {
            std::string lo = ordered[i].name;
            for (auto& c : lo) c = (char)std::tolower((unsigned char)c);
            if (lo.find(fl) != std::string::npos) {
                keep[i] = true;
                // Mark all parents (lower depth, immediately preceding) up to depth 0
                int d = ordered[i].depth;
                for (int j = (int)i - 1; j >= 0 && d > 0; j--) {
                    if (ordered[j].depth < d) { keep[j] = true; d = ordered[j].depth; }
                }
            }
        }
        std::vector<ProcessNode> out;
        for (size_t i = 0; i < ordered.size(); i++) if (keep[i]) out.push_back(ordered[i]);
        return out;
    }
    return ordered;
}

std::vector<NetEndpoint> listProcessNetwork(DWORD pid) {
    std::vector<NetEndpoint> out;
    auto netaddr = [](DWORD ip) {
        char b[24];
        sprintf(b, "%lu.%lu.%lu.%lu",
            ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
        return std::string(b);
    };
    auto stateStr = [](DWORD s) {
        switch (s) {
            case MIB_TCP_STATE_CLOSED:     return "CLOSED";
            case MIB_TCP_STATE_LISTEN:     return "LISTEN";
            case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
            case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
            case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
            case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
            case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
            case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
            case MIB_TCP_STATE_CLOSING:    return "CLOSING";
            case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
            case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
            case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        }
        return "?";
    };
    DWORD sz = 0;
    GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (sz) {
        std::vector<BYTE> buf(sz);
        if (GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            MIB_TCPTABLE_OWNER_PID* t = (MIB_TCPTABLE_OWNER_PID*)buf.data();
            for (DWORD i = 0; i < t->dwNumEntries; i++) {
                const auto& e = t->table[i];
                if (pid && e.dwOwningPid != pid) continue;
                NetEndpoint ne;
                ne.protocol = "TCP";
                ne.localAddr  = netaddr(e.dwLocalAddr);
                ne.localPort  = (int)ntohs((u_short)e.dwLocalPort);
                ne.remoteAddr = netaddr(e.dwRemoteAddr);
                ne.remotePort = (int)ntohs((u_short)e.dwRemotePort);
                ne.state = stateStr(e.dwState);
                ne.pid = e.dwOwningPid;
                out.push_back(ne);
            }
        }
    }
    sz = 0;
    GetExtendedUdpTable(NULL, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (sz) {
        std::vector<BYTE> buf(sz);
        if (GetExtendedUdpTable(buf.data(), &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            MIB_UDPTABLE_OWNER_PID* u = (MIB_UDPTABLE_OWNER_PID*)buf.data();
            for (DWORD i = 0; i < u->dwNumEntries; i++) {
                const auto& e = u->table[i];
                if (pid && e.dwOwningPid != pid) continue;
                NetEndpoint ne;
                ne.protocol = "UDP";
                ne.localAddr = netaddr(e.dwLocalAddr);
                ne.localPort = (int)ntohs((u_short)e.dwLocalPort);
                ne.remoteAddr = "";
                ne.remotePort = 0;
                ne.state = "";
                ne.pid = e.dwOwningPid;
                out.push_back(ne);
            }
        }
    }
    std::sort(out.begin(), out.end(),
              [](const NetEndpoint& a, const NetEndpoint& b){
                  if (a.protocol != b.protocol) return a.protocol < b.protocol;
                  return a.localPort < b.localPort;
              });
    return out;
}

VerifyDiff verifyDiffNow() {
    VerifyDiff d;
    auto curM = listModules();
    auto curT = listRemoteThreads();
    auto inM  = [&](const std::vector<ModuleEntry>& v, const std::string& n){
        for (auto& m : v) if (m.name == n) return true; return false;
    };
    for (auto& m : curM)        if (!inM(g_verify.modules, m.name)) d.modulesAdded.push_back(m.name);
    for (auto& m : g_verify.modules) if (!inM(curM, m.name))       d.modulesRemoved.push_back(m.name);
    auto inT = [&](const std::vector<RemoteThreadEntry>& v, DWORD tid){
        for (auto& t : v) if (t.tid == tid) return true; return false;
    };
    for (auto& t : curT)        if (!inT(g_verify.threads, t.tid)) { char b[40]; sprintf(b,"TID %lu",t.tid); d.threadsAdded.push_back(b); }
    for (auto& t : g_verify.threads) if (!inT(curT, t.tid))        { char b[40]; sprintf(b,"TID %lu",t.tid); d.threadsRemoved.push_back(b); }
    return d;
}

// ========================================================================
// Session save / load
//
// Binary format (little-endian on x86-64):
//   magic "MSC1" (4)
//   u32   version (=1)
//   u32   attached_pid
//   --- ScanParams ---
//   u32   dt, sc
//   u32   writableOnly, skipImage, executableOnly, workingSetOnly, copyOnWriteOnly
//   u64   addrMin, addrMax
//   u32   alignment, skipZero
//   u32   hasMin, hasMax
//   i64   rmin, rmax
//   f64   rminF, rmaxF
//   u32   maxResults
//   str   value, modFilter, skipAddrSuffixHex
//   --- Scan results ---
//   u32   nResults
//   for each: u64 addr, u32 prevValLen, bytes prevVal
//   --- Snapshot ---
//   u32   snapshotDt, nSnapshot
//   for each: u32 len, bytes data
//   --- Live monitor ---
//   u32   liveMonDt, nLive
//   for each: LiveStat (POD blob - 8+8+16+16+16+16+1+1+1+1+4+4+16*8+16*4+1+1+4 = ~250 bytes; we write a fixed struct dump)
// ========================================================================

static void wU32(FILE* f, uint32_t v) { fwrite(&v, 4, 1, f); }
static void wU64(FILE* f, uint64_t v) { fwrite(&v, 8, 1, f); }
static void wI64(FILE* f, int64_t v)  { fwrite(&v, 8, 1, f); }
static void wF64(FILE* f, double v)   { fwrite(&v, 8, 1, f); }
static void wStr(FILE* f, const std::string& s) { uint32_t n = (uint32_t)s.size(); fwrite(&n, 4, 1, f); if (n) fwrite(s.data(), 1, n, f); }
static bool rU32(FILE* f, uint32_t& v) { return fread(&v, 4, 1, f) == 1; }
static bool rU64(FILE* f, uint64_t& v) { return fread(&v, 8, 1, f) == 1; }
static bool rI64(FILE* f, int64_t& v)  { return fread(&v, 8, 1, f) == 1; }
static bool rF64(FILE* f, double& v)   { return fread(&v, 8, 1, f) == 1; }
static bool rStr(FILE* f, std::string& s) {
    uint32_t n = 0;
    if (fread(&n, 4, 1, f) != 1) return false;
    if (n > (1u << 24)) return false;     // 16 MB cap per string
    s.assign(n, 0);
    if (n) { if (fread(&s[0], 1, n, f) != n) return false; }
    return true;
}

bool saveSession(const std::string& path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "wb") != 0 || !f) return false;
    fwrite("MSC1", 1, 4, f);
    wU32(f, 1);                                // version
    wU32(f, s_pid);                            // last attached PID
    // ScanParams
    const ScanParams& p = g_lastScanParams;
    wU32(f, (uint32_t)p.dt);
    wU32(f, (uint32_t)p.sc);
    wU32(f, p.writableOnly ? 1 : 0);
    wU32(f, p.skipImage ? 1 : 0);
    wU32(f, p.executableOnly ? 1 : 0);
    wU32(f, p.workingSetOnly ? 1 : 0);
    wU32(f, p.copyOnWriteOnly ? 1 : 0);
    wU64(f, (uint64_t)p.addrMin);
    wU64(f, (uint64_t)p.addrMax);
    wU32(f, (uint32_t)p.alignment);
    wU32(f, p.skipZero ? 1 : 0);
    wU32(f, p.hasMin ? 1 : 0);
    wU32(f, p.hasMax ? 1 : 0);
    wI64(f, p.rmin);
    wI64(f, p.rmax);
    wF64(f, p.rminF);
    wF64(f, p.rmaxF);
    wU32(f, (uint32_t)p.maxResults);
    wStr(f, p.value);
    wStr(f, p.modFilter);
    wStr(f, p.skipAddrSuffixHex);
    // Results
    wU32(f, (uint32_t)g_scan.results.size());
    for (size_t i = 0; i < g_scan.results.size(); i++) {
        wU64(f, (uint64_t)(uintptr_t)g_scan.results[i]);
        const auto& pv = (i < g_scan.prevVals.size()) ? g_scan.prevVals[i] : std::vector<BYTE>{};
        wU32(f, (uint32_t)pv.size());
        if (!pv.empty()) fwrite(pv.data(), 1, pv.size(), f);
    }
    // Snapshot
    wU32(f, (uint32_t)g_snapshotDt);
    wU32(f, (uint32_t)g_snapshot.size());
    for (const auto& s : g_snapshot) {
        wU32(f, (uint32_t)s.size());
        if (!s.empty()) fwrite(s.data(), 1, s.size(), f);
    }
    // Live monitor
    wU32(f, (uint32_t)g_liveMonDt);
    wU32(f, (uint32_t)g_liveStats.size());
    for (const auto& s : g_liveStats) {
        fwrite(&s, sizeof(LiveStat), 1, f);   // POD blob
    }
    fclose(f);
    return true;
}

bool loadSession(const std::string& path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") != 0 || !f) return false;
    char magic[4] = {};
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, "MSC1", 4) != 0) { fclose(f); return false; }
    uint32_t version = 0; if (!rU32(f, version) || version != 1) { fclose(f); return false; }
    uint32_t pid = 0; rU32(f, pid);
    // ScanParams
    ScanParams p;
    uint32_t u;
    rU32(f, u); p.dt = (DataType)u;
    rU32(f, u); p.sc = (ScanCondition)u;
    rU32(f, u); p.writableOnly  = !!u;
    rU32(f, u); p.skipImage     = !!u;
    rU32(f, u); p.executableOnly  = !!u;
    rU32(f, u); p.workingSetOnly  = !!u;
    rU32(f, u); p.copyOnWriteOnly = !!u;
    uint64_t u64;
    rU64(f, u64); p.addrMin = (uintptr_t)u64;
    rU64(f, u64); p.addrMax = (uintptr_t)u64;
    rU32(f, u); p.alignment = (int)u;
    rU32(f, u); p.skipZero  = !!u;
    rU32(f, u); p.hasMin    = !!u;
    rU32(f, u); p.hasMax    = !!u;
    rI64(f, p.rmin);
    rI64(f, p.rmax);
    rF64(f, p.rminF);
    rF64(f, p.rmaxF);
    rU32(f, u); p.maxResults = (int)u;
    rStr(f, p.value);
    rStr(f, p.modFilter);
    rStr(f, p.skipAddrSuffixHex);
    g_lastScanParams = p;
    // Results
    uint32_t nRes = 0;
    if (!rU32(f, nRes)) { fclose(f); return false; }
    if (nRes > 2000000) { fclose(f); return false; }
    g_scan.results.clear();
    g_scan.prevVals.clear();
    g_scan.results.reserve(nRes);
    g_scan.prevVals.reserve(nRes);
    for (uint32_t i = 0; i < nRes; i++) {
        uint64_t a; uint32_t pvLen;
        if (!rU64(f, a) || !rU32(f, pvLen) || pvLen > 256) { fclose(f); return false; }
        std::vector<BYTE> pv(pvLen);
        if (pvLen) { if (fread(pv.data(), 1, pvLen, f) != pvLen) { fclose(f); return false; } }
        g_scan.results.push_back((LPVOID)(uintptr_t)a);
        g_scan.prevVals.push_back(std::move(pv));
    }
    // Snapshot
    rU32(f, u); g_snapshotDt = (int)u;
    uint32_t nSnap = 0;
    if (!rU32(f, nSnap)) { fclose(f); return false; }
    if (nSnap > 2000000) { fclose(f); return false; }
    g_snapshot.clear();
    g_snapshot.reserve(nSnap);
    for (uint32_t i = 0; i < nSnap; i++) {
        uint32_t len;
        if (!rU32(f, len) || len > 256) { fclose(f); return false; }
        std::vector<BYTE> v(len);
        if (len) { if (fread(v.data(), 1, len, f) != len) { fclose(f); return false; } }
        g_snapshot.push_back(std::move(v));
    }
    // Live monitor
    rU32(f, u); g_liveMonDt = (int)u;
    uint32_t nLive = 0;
    if (!rU32(f, nLive)) { fclose(f); return false; }
    if (nLive > 2000000) { fclose(f); return false; }
    g_liveStats.clear();
    g_liveStats.resize(nLive);
    for (uint32_t i = 0; i < nLive; i++) {
        if (fread(&g_liveStats[i], sizeof(LiveStat), 1, f) != 1) { fclose(f); return false; }
    }
    fclose(f);

    // Try to re-attach to the saved PID if still alive
    if (pid && !s_hProc) {
        if (!attach(pid)) {
            // PID not alive anymore; leave detached but keep results
        }
    }
    return true;
}

} 
