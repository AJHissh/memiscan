#pragma once

#include <windows.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace mem {

enum DataType {
    DT_INT8 = 0, DT_INT16, DT_INT32, DT_INT64,
    DT_FLOAT, DT_DOUBLE, DT_STRING, DT_AOB,
};

enum ScanCondition {
    SC_EXACT = 0, SC_CHANGED, SC_UNCHANGED, SC_INCREASED, SC_DECREASED, SC_UNKNOWN,
};

struct ScanParams {
    DataType  dt        = DT_INT32;
    ScanCondition sc    = SC_EXACT;
    std::string  value;         // textual value (parsed per dt)
    std::string  modFilter;
    bool         writableOnly  = true;
    bool         skipImage     = false;
    bool         executableOnly = false;     // only PAGE_EXECUTE_* regions
    bool         workingSetOnly = false;     // only pages currently in working set
    bool         copyOnWriteOnly = false;    // only PAGE_WRITECOPY / PAGE_EXECUTE_WRITECOPY
    uintptr_t    addrMin = 0;                // 0 = no lower limit
    uintptr_t    addrMax = 0;                // 0 = no upper limit
    int          alignment = 0;              // 0 = auto (use valSz)
    bool         skipZero = false;           // skip values that are all-zero
    std::string  skipAddrSuffixHex;          // skip addresses whose low N hex digits match this
    bool         hasMin = false; int64_t rmin = 0; double rminF = 0;
    bool         hasMax = false; int64_t rmax = 0; double rmaxF = 0;
    int          maxResults = 100000;
};

struct ScanState {
    std::vector<LPVOID>             results;
    std::vector<std::vector<BYTE>>  prevVals;
};

struct LiveStat {
    BYTE baseline[16]   = {};
    BYTE last[16]       = {};
    BYTE minV[16]       = {};
    BYTE maxV[16]       = {};
    bool changed        = false;
    bool increased      = false;
    bool decreased      = false;
    bool minMaxInit     = false;
    uint32_t changeCount = 0;
    uint32_t sampleCount = 0;
    BYTE     history[16][8] = {};
    DWORD    historyTime[16] = {};
    uint8_t  historyHead  = 0;
    uint8_t  historyCount = 0;
    float    score       = 0;
};

bool   attach(DWORD pid);
void   detach();
bool   isAttached();
DWORD  attachedPid();
LPVOID baseAddress();
HANDLE processHandle();
std::vector<std::pair<DWORD,std::string>> findProcessesByName(const std::string& needle);

size_t  dtSize(DataType dt);
int64_t parseHexAwareInt(const char* s);

// Public state (will move into a class once the migration solidifies)
extern volatile bool g_scanRunning;
extern volatile bool g_scanStopRequested;
extern ScanState     g_scan;

extern std::vector<std::vector<BYTE>> g_snapshot;
extern int                            g_snapshotDt;

extern std::vector<LiveStat>          g_liveStats;
extern volatile bool                  g_liveMonActive;
extern int                            g_liveMonDt;

bool doFirstScan(const ScanParams& p, std::string& errOut);
bool doNextScan (const ScanParams& p, std::string& errOut);
void clearScan();
size_t exportResultsToCsv(const std::string& path, DataType dt);

// Snapshot + diff workflow ------------------------------------------------
void takeSnapshot(DataType dt);
bool filterByDiff(DataType dt, int mode, std::string& errOut);   // 0=changed 1=unchanged 2=inc 3=dec

// Live monitor ------------------------------------------------------------
void liveMonStart(DataType dt);
void liveMonStop();
void liveMonTick();                       // call ~50 ms while active
void computeLiveScores(DataType dt);
bool filterByLiveChanged(DataType dt, std::string& err);
bool filterTopByScore(size_t topN, DataType dt, std::string& err);
bool filterByBoundedRange(double maxRange, DataType dt, std::string& err);

// Value formatting / read / write -----------------------------------------
std::string formatTypedValue(const BYTE* data, DataType dt);
double      valueAsDouble  (const BYTE* data, DataType dt);
bool        readTypedValue (LPVOID addr, DataType dt, BYTE out[16]);
bool        writeTypedValue(LPVOID addr, DataType dt, const std::string& textValue, bool bypassReadOnly, std::string& err);

// Zydis ------------------------------------------------------------------
struct DisasmLine {
    uintptr_t addr;
    std::vector<BYTE> bytes;
    std::string text;       // mnemonic + ops
};
std::string disasmOneAtRemote(LPVOID remoteAddr);                // single instruction at remote address
std::vector<DisasmLine> disasmRangeAtRemote(LPVOID remoteAddr, size_t bytes, size_t maxLines = 256);

// Modules ----------------------------------------------------------------
struct ModuleEntry {
    std::string name;
    std::string path;
    uintptr_t   base;
    size_t      size;
};
std::vector<ModuleEntry> listModules();
bool injectDLL(const std::string& dllPath, std::string& err);
bool ejectDLL (const std::string& dllNameSubstr, std::string& err);

// Binary patcher ---------------------------------------------------------
struct AppliedPatch {
    uintptr_t        addr;
    std::vector<BYTE> original;
    std::vector<BYTE> applied;
    std::string      label;
};
extern std::vector<AppliedPatch> g_patches;
bool patcherRead   (uintptr_t addr, size_t n, std::vector<BYTE>& out, std::string& err);
bool patcherWrite  (uintptr_t addr, const std::vector<BYTE>& bytes, const std::string& label, std::string& err);
bool patcherNop    (uintptr_t addr, size_t n,  const std::string& label, std::string& err);
bool patcherNearJmp(uintptr_t addr, uintptr_t target, const std::string& label, std::string& err);
bool patcherRestore(size_t idx, std::string& err);

// Pointer chains ---------------------------------------------------------
struct PointerChain {
    std::string name;
    std::string moduleName;       // e.g. "game.exe" or "" for raw
    uintptr_t   moduleOffset;     // offset within module
    std::vector<intptr_t> offsets;
};
extern std::vector<PointerChain> g_chains;
uintptr_t  resolveChain(const PointerChain& c, std::string& err);
bool       saveChains  (const std::string& path);
bool       loadChains  (const std::string& path);

// Cheat table (CE-style scripts) -----------------------------------------
struct CheatEntry {
    std::string name;
    std::string script;
    bool        enabled  = false;
    int         hotkeyVK = 0;
};
extern std::vector<CheatEntry> g_cheats;
bool      cheatExecute    (CheatEntry& c, bool enableSection, std::string& err);
bool      cheatToggle     (size_t idx, std::string& err);   // runs enable or disable based on current state, flips state on success
uintptr_t cheatResolveAddr(const std::string& expr);
bool      saveCheats      (const std::string& path);
bool      loadCheats      (const std::string& path);

// DLL helpers ------------------------------------------------------------
HMODULE   findRemoteModuleByName(const std::string& nameSubstr);

// Code injection / caves / remote threads --------------------------------
struct CodeCave { LPVOID addr; size_t size; DWORD protect; };
struct RemoteThreadEntry { DWORD tid; LPVOID startAddr; DWORD priority; std::string startModule; uintptr_t startOffset; };
LPVOID injectShellcode    (const std::vector<BYTE>& sc, std::string& err);   // returns remote address (don't execute)
bool   injectAndExecute   (const std::vector<BYTE>& sc, std::string& err, DWORD* outTid = nullptr);
std::vector<CodeCave>          scanCodeCaves   (size_t minSize);
std::vector<RemoteThreadEntry> listRemoteThreads();
bool   suspendThread(DWORD tid, std::string& err);
bool   resumeThread (DWORD tid, std::string& err);
bool   killThread   (DWORD tid, std::string& err);

// Target windows ---------------------------------------------------------
struct TargetWindow { HWND hwnd; std::string title; std::string className; bool visible; };
std::vector<TargetWindow> listTargetWindows();
bool sendWindowText   (HWND, const std::string& text);
bool postWindowMessage(HWND, UINT msg, WPARAM wp, LPARAM lp);
bool windowShow(HWND, int nCmdShow);

// Detection scan ---------------------------------------------------------
struct DetectFinding {
    std::string category;
    std::string detail;
    LPVOID      addr;
    size_t      size;
};
std::vector<DetectFinding> runDetectionScan(bool rwx, bool privExec, bool threadAnom);

// Trigger ---------------------------------------------------------------
bool triggerCreateRemoteThread(LPVOID startAddr, LPVOID param, DWORD* outTid, std::string& err);
bool triggerQueueUserAPC      (DWORD tid, LPVOID startAddr, LPVOID param, std::string& err);

// Module exports --------------------------------------------------------
struct ExportRow { std::string module; std::string name; LPVOID address; DWORD ordinal; };
std::vector<ExportRow> enumerateAllExports();

// Auto pointer scan -----------------------------------------------------
struct AutoPtrChain {
    std::string moduleName;
    uintptr_t   moduleOffset;
    std::vector<intptr_t> offsets;
};
std::vector<AutoPtrChain> autoPointerScan(uintptr_t targetAddr, int maxDepth, intptr_t maxOffset, size_t maxCandidates = 5000);

// --- ADVANCED ---------------------------------------------------------

// Inline assembler (port of legacy AssembleSource - x86-64 subset) -------
bool assembleSource(const std::string& src, std::vector<BYTE>& out, std::string& err);

// AOB signature generator ------------------------------------------------
struct AobSignature {
    std::string pattern;     // "48 8B 05 ?? ?? ?? ?? 48 85 C0"
    size_t      length;
    size_t      wildcards;
    size_t      hits;
    bool        unique;
};
AobSignature generateAobSignature(LPVOID address, size_t minLen = 12, size_t maxLen = 64);

// Live multi-address watch list ------------------------------------------
struct WatchItem {
    std::string name;
    LPVOID      addr;
    DataType    dt;
    BYTE        lastVal[16];
    BYTE        prevVal[16];
    bool        valid;
    bool        flashChanged;
    DWORD       flashUntil;
};
extern std::vector<WatchItem> g_watch;
void  watchAdd       (const std::string& name, LPVOID addr, DataType dt);
void  watchRemove    (size_t idx);
void  watchUpdateAll ();
bool  watchSave      (const std::string& path);
bool  watchLoad      (const std::string& path);

// Trampoline hooks -------------------------------------------------------
struct TrampHook {
    LPVOID            target;       // patched site
    LPVOID            cave;         // VirtualAllocEx region (payload + stolen + return)
    std::vector<BYTE> stolen;       // original bytes (for restore)
    size_t            stolenLen;
    std::string       label;
};
extern std::vector<TrampHook> g_thooks;
bool installTrampoline(LPVOID target, const std::vector<BYTE>& userPayload,
                       size_t minStolen, const std::string& label, std::string& err);
bool uninstallTrampoline(size_t idx, std::string& err);

// Memory hex viewer / editor ---------------------------------------------
bool hexRead (uintptr_t addr, size_t n, std::vector<BYTE>& out, std::string& err);
bool hexWrite(uintptr_t addr, const std::vector<BYTE>& bytes, bool bypassRO, std::string& err);

// Bookmarks --------------------------------------------------------------
struct Bookmark {
    std::string name;
    LPVOID      addr;
    DataType    dt;
    std::string note;
};
extern std::vector<Bookmark> g_bookmarks;
void bookmarkAdd   (const std::string& name, LPVOID addr, DataType dt, const std::string& note);
void bookmarkRemove(size_t idx);
bool bookmarkSave  (const std::string& path);
bool bookmarkLoad  (const std::string& path);

// Auto data-type detection ------------------------------------------------
struct TypeGuess {
    DataType    dt;
    std::string formatted;
    float       plausibility;     // 0..1
    std::string reason;
};
std::vector<TypeGuess> guessTypeAt(LPVOID addr);

// PE info viewer ---------------------------------------------------------
struct PESection {
    std::string name;
    uintptr_t   rva;
    size_t      vsize;
    DWORD       characteristics;
};
struct PEImport {
    std::string dll;
    std::string name;
    LPVOID      iatPointer;
};
struct PEInfo {
    std::string moduleName;
    uintptr_t   imageBase;
    size_t      imageSize;
    DWORD       timestamp;
    DWORD       checksum;
    bool        is64;
    std::vector<PESection> sections;
    std::vector<PEImport>  imports;
    std::vector<ExportRow> exports;
};
PEInfo getPEInfo(HMODULE module, const std::string& moduleName);

// Process control --------------------------------------------------------
extern volatile bool g_processSuspended;
size_t suspendAllThreads();
size_t resumeAllThreads();

// Process tree -----------------------------------------------------------
struct ProcessNode {
    DWORD       pid;
    DWORD       ppid;
    std::string name;
    int         depth;          // 0 = root, used for indent
};
std::vector<ProcessNode> listProcessesTree(const std::string& filterSubstr = "");

// Network endpoints ------------------------------------------------------
struct NetEndpoint {
    std::string protocol;       // "TCP" / "UDP"
    std::string localAddr;
    int         localPort;
    std::string remoteAddr;
    int         remotePort;
    std::string state;          // TCP states or "" for UDP
    DWORD       pid;
};
std::vector<NetEndpoint> listProcessNetwork(DWORD pid);

// Stack walker -----------------------------------------------------------
struct StackFrame {
    uintptr_t rip;
    uintptr_t rsp;
    std::string moduleName;
    uintptr_t   moduleOffset;
    std::string disasm;
};
std::vector<StackFrame> walkStack(DWORD tid, size_t maxFrames = 32);

// Hardware breakpoint tracer --------------------------------------------
enum HwbpType { HWBP_EXECUTE = 0, HWBP_WRITE = 1, HWBP_READWRITE = 3 };
struct HwbpLogEntry {
    DWORD       tid;
    uintptr_t   offenderRip;
    std::string disasm;
    DWORD       timeMs;
};
extern volatile bool                   g_hwbpActive;
extern std::vector<HwbpLogEntry>       g_hwbpLog;
extern uintptr_t                       g_hwbpWatchAddr;
bool   hwbpEnable (uintptr_t addr, HwbpType type, int size, std::string& err);
void   hwbpDisable();
void   hwbpClearLog();

// Verify ---------------------------------------------------------------
struct VerifySnapshot {
    std::vector<ModuleEntry>             modules;
    std::vector<RemoteThreadEntry>       threads;
};
extern VerifySnapshot g_verify;
void   takeVerifySnapshot();
struct VerifyDiff {
    std::vector<std::string> modulesAdded, modulesRemoved;
    std::vector<std::string> threadsAdded, threadsRemoved;
};
VerifyDiff verifyDiffNow();

// Persistent session ----------------------------------------------------
extern ScanParams g_lastScanParams;          
bool saveSession(const std::string& path);
bool loadSession(const std::string& path);

} 
