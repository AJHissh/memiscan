#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <commctrl.h>
#include <commdlg.h>
#include <vector>
#include <string>
#include <map>
#include <sstream>
#include <algorithm>
#include <stdio.h>
#include <stdint.h>
#include <math.h>

#define ID_BTN_BROWSE        1
#define ID_BTN_ATTACH        2
#define ID_BTN_FIRST_SCAN    4
#define ID_BTN_NEXT_SCAN     5
#define ID_LST_RESULTS       6
#define ID_BTN_REFRESH_HEX   7
#define ID_BTN_REFRESH_MAP   8
#define ID_LST_MEMMAP        9
#define ID_LST_HEX          10
#define ID_BTN_WRITE        11
#define ID_BTN_UNDO         12
#define ID_BTN_SET_OFFSET   13
#define ID_BTN_GOTO_OFFSET  14
#define ID_EDIT_OFFSET      15
#define ID_BTN_SEARCH_NAME  20
#define ID_EDIT_SEARCH      21
#define ID_LST_PROCS        22
#define ID_BTN_SELECT_PROC  23
#define ID_CMB_DATA_TYPE    30
#define ID_CMB_SCAN_TYPE    31
#define ID_BTN_ADD_WATCH    32
#define ID_BTN_CLEAR_WATCH  33
#define ID_BTN_FREEZE       34
#define ID_BTN_EXPORT       35
#define ID_BTN_PTR_SCAN     36
#define ID_BTN_READ_VAL     37
#define ID_LST_WATCH        39
#define ID_LST_MODULES      40
#define ID_BTN_REM_WATCH    41
#define ID_BTN_REFRESH_MODS 42
#define ID_BTN_CLEAR_SCAN   43
#define ID_BTN_INJECT_DLL   50
#define ID_BTN_EJECT_DLL    51
#define ID_BTN_BROWSE_DLL   52
#define ID_EDIT_DLL_PATH    53
#define ID_BTN_INJECT_CODE  54
#define ID_EDIT_SHELLCODE   55
#define ID_BTN_SCAN_CAVES   56
#define ID_LST_CAVES        57
#define ID_BTN_LIST_THREADS 58
#define ID_LST_THREADS      59
#define ID_EDIT_CAVE_SIZE   60
#define ID_CMB_MEM_PROT     61
#define ID_BTN_LOAD_SC_FILE 62
#define ID_CMB_ARCH         70
#define ID_CMB_SC_OP        71
#define ID_EDIT_SC_ADDR     72
#define ID_EDIT_SC_VAL      73
#define ID_BTN_BUILD_SC     74
#define ID_EDIT_SC_RESULT   75
#define ID_BTN_COPY_SC      76
#define ID_BTN_SEND_TO_BUILDER 77
#define ID_BTN_ASSEMBLER    80
#define ID_EDIT_ASM_SRC     81
#define ID_BTN_ASSEMBLE     82
#define ID_EDIT_ASM_OUT     83
#define ID_BTN_ASM_TO_SC    84
#define TIMER_FREEZE        100
#define TIMER_WATCH         101

#define DT_INT32  0
#define DT_INT16  1
#define DT_INT8   2
#define DT_INT64  3
#define DT_FLOAT  4
#define DT_DOUBLE 5
#define DT_STRING 6
#define DT_AOB    7

#define SC_EXACT    0
#define SC_CHANGED  1
#define SC_UNCHANGED 2
#define SC_INCREASED 3
#define SC_DECREASED 4
#define SC_UNKNOWN  5

#define CLR_BG_WINDOW  RGB(22,  22,  32)
#define CLR_BG_EDIT    RGB(35,  35,  50)
#define CLR_BG_LIST    RGB(18,  18,  26)
#define CLR_BG_STATUS  RGB(12,  12,  18)
#define CLR_TEXT_NORM  RGB(210, 210, 225)
#define CLR_TEXT_EDIT  RGB(180, 240, 180)
#define CLR_TEXT_LIST  RGB(160, 235, 160)
#define CLR_TEXT_HDR   RGB(90,  200, 255)
#define CLR_TEXT_STAT  RGB(180, 210, 180)
#define CLR_TEXT_INFO  RGB(255, 220, 100)

HINSTANCE hInst;
HWND hMainWnd;
HWND hScanResultsWnd, hMemoryMapWnd, hHexViewWnd;
HWND hEditPID, hEditScanValue, hEditNewValue, hEditHexAddress;
HWND hEditSearchName, hEditTrackedOffset;
HWND hBtnFirstScan, hBtnNextScan, hBtnWrite, hBtnUndo, hBtnRefreshHex;
HWND hBtnSetOffset, hBtnGotoOffset, hBtnFreeze, hBtnExport;
HWND hStaticProcessInfo, hStaticModuleInfo, hStaticAddressInfo, hStatusWnd;
HWND hStaticOffsetInfo, hStaticScanCount;
HWND hHdrScan, hHdrMap, hHdrHex, hHdrWrite, hHdrMods, hHdrWatch;
HWND hCmbDataType, hCmbScanType;
HWND hLstWatchList, hLstModules;
HWND hHdrInject, hHdrDllInject, hHdrShellcode, hHdrBuilder, hHdrCaves, hHdrThreads;
HWND hEditDllPath, hBtnBrowseDll, hBtnInjectDll, hBtnEjectDll;
HWND hEditShellcode, hBtnInjectCode, hBtnLoadScFile, hCmbMemProt;
HWND hEditCaveSize, hBtnScanCaves, hLstCaves;
HWND hBtnListThreads, hLstThreads;
HWND hCmbArch, hCmbScOp, hEditScAddr, hEditScVal, hBtnBuildSc;
HWND hEditScResult, hBtnCopySc, hBtnSendToBuilder, hBtnAssembler;
HWND hWndAssembler = NULL;
HFONT hFontTitle, hFontSection, hFontNormal, hFontMono, hFontSmall;
HBRUSH hBrushWindow, hBrushEdit, hBrushList, hBrushStatus;

HANDLE hProcess = NULL;
DWORD  currentPID = 0;
LPVOID selectedAddress = NULL;

std::vector<LPVOID>             scanResults;
std::vector<std::vector<BYTE>>  scanPrevVals; 

struct Backup4 { BYTE data[4]; };
std::map<LPVOID, Backup4> backups;

std::vector<LPVOID> watchList;

LONGLONG trackedOffset  = 0;
bool     hasTrackedOffset = false;
bool     freezeActive   = false;
int      freezeValue    = 0;

void LogToStatus(const char* msg, bool error = false);
std::vector<std::pair<DWORD, std::string>> SearchProcessesByName(const std::string& name);
bool AttachToProcess(DWORD pid);
void UpdateProcessInfo();
void ShowMemoryMap();
void ShowHexAtAddress(LPVOID address, LPVOID highlightAddr = nullptr);
void UpdateOffsetInfo();
void UpdateScanCount();
void PopulateModuleList();
void RefreshWatchList();
void ExportScanResults();
void BuildShellcode();
void ShowAssemblerWindow();
void InjectDLL();
void EjectDLL();
void InjectShellcode();
void ScanCodeCaves();
void ListRemoteThreads();
void DoFirstScan();
void DoNextScan();
void ScanForPointers(LPVOID targetAddr);
std::string FormatMemorySize(SIZE_T bytes);
LPVOID GetBaseAddress();
int    ReadValueFromAddress(LPVOID address);
void   WriteValueToAddress(LPVOID address, int value);

static void EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    TOKEN_PRIVILEGES tp = {};
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(hToken);
}

static bool IsElevated() {
    BOOL elevated = FALSE;
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION te; DWORD sz = sizeof(te);
        if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &sz))
            elevated = te.TokenIsElevated;
        CloseHandle(hToken);
    }
    return elevated != FALSE;
}

static void RelaunchAsAdmin() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    ShellExecuteA(NULL, "runas", path, NULL, NULL, SW_SHOW);
    ExitProcess(0);
}

void LogToStatus(const char* msg, bool error) {
    char buf[512];
    SYSTEMTIME st; GetLocalTime(&st);
    sprintf_s(buf, "[%02d:%02d:%02d]  %s", st.wHour, st.wMinute, st.wSecond, msg);
    SetWindowTextA(hStatusWnd, buf);
    if (error) MessageBeep(MB_ICONERROR);
}

std::string FormatMemorySize(SIZE_T bytes) {
    std::stringstream ss;
    if      (bytes < 1024)           ss << bytes                           << " B";
    else if (bytes < 1024*1024)      ss << bytes/1024                      << " KB";
    else if (bytes < 1024*1024*1024) ss << bytes/(1024*1024)               << " MB";
    else                             ss << bytes/(1024ULL*1024ULL*1024ULL) << " GB";
    return ss.str();
}

LPVOID GetBaseAddress() {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, currentPID);
    if (!h) return nullptr;
    HMODULE mods[1024]; DWORD needed;
    LPVOID base = nullptr;
    if (EnumProcessModules(h, mods, sizeof(mods), &needed))
        base = mods[0];
    CloseHandle(h);
    return base;
}

std::vector<std::pair<DWORD, std::string>> SearchProcessesByName(const std::string& search) {
    std::vector<std::pair<DWORD, std::string>> results;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return results;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            std::string name(pe.szExeFile);
            std::string sl = search, nl = name;
            std::transform(sl.begin(), sl.end(), sl.begin(), ::tolower);
            std::transform(nl.begin(), nl.end(), nl.begin(), ::tolower);
            if (search.empty() || nl.find(sl) != std::string::npos)
                results.push_back({pe.th32ProcessID, name});
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return results;
}

size_t GetDataTypeSize(int dt) {
    switch (dt) {
        case DT_INT32:  return 4;
        case DT_INT16:  return 2;
        case DT_INT8:   return 1;
        case DT_INT64:  return 8;
        case DT_FLOAT:  return 4;
        case DT_DOUBLE: return 8;
        default:        return 4;
    }
}

std::string FormatTypedValue(const BYTE* data, int dt) {
    char buf[128] = {};
    switch (dt) {
        case DT_INT32:  sprintf_s(buf, "%d",    *(int32_t*)data);  break;
        case DT_INT16:  sprintf_s(buf, "%d",    (int)*(int16_t*)data); break;
        case DT_INT8:   sprintf_s(buf, "%d",    (int)*(int8_t*)data);  break;
        case DT_INT64:  sprintf_s(buf, "%lld",  *(int64_t*)data);  break;
        case DT_FLOAT:  sprintf_s(buf, "%.4f",  *(float*)data);    break;
        case DT_DOUBLE: sprintf_s(buf, "%.6f",  *(double*)data);   break;
        case DT_STRING: {
            char tmp[32] = {}; memcpy(tmp, data, 31);
            sprintf_s(buf, "\"%s\"", tmp); break;
        }
        case DT_AOB: {
            sprintf_s(buf, "%02X %02X %02X %02X", data[0], data[1], data[2], data[3]); break;
        }
    }
    return buf;
}

bool MatchesCondition(const BYTE* cur, const BYTE* prev,
                      const BYTE* target, int dt, int sc, size_t sz) {
    switch (sc) {
        case SC_EXACT:
            if (dt == DT_FLOAT)  return fabsf(*(float*)cur  - *(float*)target)  < 0.001f;
            if (dt == DT_DOUBLE) return fabs (*(double*)cur - *(double*)target) < 0.00001;
            return memcmp(cur, target, sz) == 0;
        case SC_CHANGED:
            return prev && memcmp(cur, prev, sz) != 0;
        case SC_UNCHANGED:
            return prev && memcmp(cur, prev, sz) == 0;
        case SC_INCREASED:
            if (!prev) return false;
            if (dt == DT_INT8)   return *(int8_t*)cur   > *(int8_t*)prev;
            if (dt == DT_INT16)  return *(int16_t*)cur  > *(int16_t*)prev;
            if (dt == DT_INT64)  return *(int64_t*)cur  > *(int64_t*)prev;
            if (dt == DT_FLOAT)  return *(float*)cur    > *(float*)prev;
            if (dt == DT_DOUBLE) return *(double*)cur   > *(double*)prev;
            return *(int32_t*)cur > *(int32_t*)prev;
        case SC_DECREASED:
            if (!prev) return false;
            if (dt == DT_INT8)   return *(int8_t*)cur   < *(int8_t*)prev;
            if (dt == DT_INT16)  return *(int16_t*)cur  < *(int16_t*)prev;
            if (dt == DT_INT64)  return *(int64_t*)cur  < *(int64_t*)prev;
            if (dt == DT_FLOAT)  return *(float*)cur    < *(float*)prev;
            if (dt == DT_DOUBLE) return *(double*)cur   < *(double*)prev;
            return *(int32_t*)cur < *(int32_t*)prev;
        case SC_UNKNOWN:
            return true;
    }
    return false;
}

bool ParseAOB(const char* pattern, std::vector<BYTE>& outBytes, std::vector<bool>& outMask) {
    outBytes.clear(); outMask.clear();
    const char* p = pattern;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (p[0] == '?' ) {
            outBytes.push_back(0); outMask.push_back(true);
            p++; if (*p == '?') p++;
        } else if (isxdigit((unsigned char)p[0]) && isxdigit((unsigned char)p[1])) {
            char h[3] = {p[0], p[1], 0};
            outBytes.push_back((BYTE)strtoul(h, nullptr, 16));
            outMask.push_back(false);
            p += 2;
        } else { p++; }
    }
    return !outBytes.empty();
}

void UpdateScanCount() {
    char buf[64]; sprintf_s(buf, "Found: %zu", scanResults.size());
    SetWindowTextA(hStaticScanCount, buf);
}

void UpdateOffsetInfo() {
    if (!hasTrackedOffset) {
        SetWindowTextA(hStaticOffsetInfo,
            "No offset tracked.  Select a scan result then click Set Offset.");
        return;
    }
    LPVOID base = GetBaseAddress();
    if (!base || !hProcess) {
        char buf[256];
        sprintf_s(buf, "Tracked offset: +0x%llX  (attach to process to resolve)", trackedOffset);
        SetWindowTextA(hStaticOffsetInfo, buf);
        return;
    }
    LPVOID resolved = (LPVOID)((uintptr_t)base + (uintptr_t)trackedOffset);
    int val = ReadValueFromAddress(resolved);
    char buf[512];
    sprintf_s(buf, "Tracked offset: +0x%llX  ->  0x%p  |  Current int32: %d",
              trackedOffset, resolved, val);
    SetWindowTextA(hStaticOffsetInfo, buf);
}

void PopulateProcessList(HWND hList, const std::string& filter) {
    SendMessage(hList, LB_RESETCONTENT, 0, 0);
    for (auto& p : SearchProcessesByName(filter)) {
        char entry[256];
        sprintf_s(entry, "PID: %-8d | %s", p.first, p.second.c_str());
        SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)entry);
    }
}

struct ProcDlgData { HWND hList; HWND hSearch; };

LRESULT CALLBACK ProcDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    static ProcDlgData* d = nullptr;
    switch (msg) {
        case WM_CREATE: {
            d = (ProcDlgData*)((CREATESTRUCT*)lParam)->lpCreateParams;
            CreateWindowA("STATIC","Search:", WS_CHILD|WS_VISIBLE, 10,10,55,22, hDlg,NULL,hInst,NULL);
            d->hSearch = CreateWindowA("EDIT","", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                                       70,8,300,24, hDlg,(HMENU)ID_EDIT_SEARCH,hInst,NULL);
            CreateWindowA("BUTTON","Search", WS_CHILD|WS_VISIBLE,
                          378,8,90,24, hDlg,(HMENU)ID_BTN_SEARCH_NAME,hInst,NULL);
            d->hList = CreateWindowA("LISTBOX","",
                                     WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|LBS_NOTIFY,
                                     10,40,460,360, hDlg,(HMENU)ID_LST_PROCS,hInst,NULL);
            CreateWindowA("BUTTON","Select Process", WS_CHILD|WS_VISIBLE,
                          340,410,130,28, hDlg,(HMENU)ID_BTN_SELECT_PROC,hInst,NULL);
            SendMessage(d->hList,   WM_SETFONT, (WPARAM)hFontMono,   TRUE);
            SendMessage(d->hSearch, WM_SETFONT, (WPARAM)hFontNormal, TRUE);
            PopulateProcessList(d->hList, "");
            return 0;
        }
        case WM_COMMAND: {
            WORD id = LOWORD(wParam);
            if (id == ID_BTN_SEARCH_NAME || (id == ID_EDIT_SEARCH && HIWORD(wParam) == EN_CHANGE)) {
                char buf[256]; GetWindowTextA(d->hSearch, buf, 256);
                PopulateProcessList(d->hList, buf);
            }
            bool sel = (id == ID_BTN_SELECT_PROC) ||
                       (id == ID_LST_PROCS && HIWORD(wParam) == LBN_DBLCLK);
            if (sel) {
                int idx = (int)SendMessage(d->hList, LB_GETCURSEL, 0, 0);
                if (idx != LB_ERR) {
                    char entry[256];
                    SendMessageA(d->hList, LB_GETTEXT, idx, (LPARAM)entry);
                    const char* p = entry + 5; while (*p == ' ') p++;
                    SetWindowTextA(hEditPID, std::to_string((DWORD)atoi(p)).c_str());
                    DestroyWindow(hDlg);
                }
            }
            return 0;
        }
        case WM_DESTROY: d = nullptr; return 0;
    }
    return DefWindowProc(hDlg, msg, wParam, lParam);
}

void ShowProcessListDialog() {
    static bool registered = false;
    if (!registered) {
        WNDCLASSA wc = {};
        wc.lpfnWndProc   = ProcDlgProc;
        wc.hInstance     = hInst;
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
        wc.lpszClassName = "ProcDlgClass";
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        RegisterClassA(&wc);
        registered = true;
    }
    ProcDlgData data = {};
    HWND hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "ProcDlgClass", "Select Process",
                                WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_VISIBLE,
                                150,120, 490,470, hMainWnd, NULL, hInst, &data);
    if (!hDlg) return;
    MSG msg;
    while (IsWindow(hDlg) && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg); DispatchMessage(&msg);
    }
}

bool AttachToProcess(DWORD pid) {
    if (hProcess) { CloseHandle(hProcess); hProcess = NULL; }
    hProcess = OpenProcess(PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION|
                           PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess) {
        currentPID = pid;
        UpdateProcessInfo();
        char buf[128]; sprintf_s(buf, "Attached to PID: %d", pid);
        LogToStatus(buf);
        ShowMemoryMap();
        PopulateModuleList();
        UpdateOffsetInfo();
        SetTimer(hMainWnd, TIMER_WATCH, 1000, NULL);
        return true;
    }
    LogToStatus("Failed to attach - Run as Administrator!", true);
    return false;
}

void UpdateProcessInfo() {
    if (!currentPID) return;
    LPVOID base = GetBaseAddress();
    std::string name = "Unknown";
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                if (pe.th32ProcessID == currentPID) { name = pe.szExeFile; break; }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    const char* arch = "?";
    if (hProcess) {
        BOOL isWow64 = FALSE;
        IsWow64Process(hProcess, &isWow64);
#ifdef _WIN64
        arch = isWow64 ? "x86 (32-bit)" : "x64 (64-bit)";
#else
        arch = "x86 (32-bit)";
#endif
    }
    char info[512];
    sprintf_s(info, "Process: %s  |  PID: %d  |  Arch: %s  |  Base: 0x%p",
              name.c_str(), currentPID, arch, base);
    SetWindowTextA(hStaticProcessInfo, info);
    if (hProcess) {
        HMODULE mods[1024]; DWORD needed;
        if (EnumProcessModules(hProcess, mods, sizeof(mods), &needed)) {
            MODULEINFO mi;
            if (GetModuleInformation(hProcess, mods[0], &mi, sizeof(mi))) {
                sprintf_s(info, "Module: %s  |  Size: %s  |  Entry: 0x%p",
                          name.c_str(), FormatMemorySize(mi.SizeOfImage).c_str(), mi.EntryPoint);
                SetWindowTextA(hStaticModuleInfo, info);
            }
        }
    }
}

void ShowMemoryMap() {
    if (!hProcess) { LogToStatus("No process attached!", true); return; }
    SendMessage(hMemoryMapWnd, LB_RESETCONTENT, 0, 0);

    std::vector<uintptr_t> foundPtrs;
    for (LPVOID a : scanResults) foundPtrs.push_back((uintptr_t)a);

    SYSTEM_INFO si; GetSystemInfo(&si);
    LPVOID addr = si.lpMinimumApplicationAddress;
    SendMessageA(hMemoryMapWnd, LB_ADDSTRING, 0,
        (LPARAM)"Base Address         | Size        | Type    | Protection    | Notes");
    SendMessageA(hMemoryMapWnd, LB_ADDSTRING, 0,
        (LPARAM)"---------------------+-------------+---------+---------------+------------------------");

    int n = 0, firstFound = -1;
    while (addr < si.lpMaximumApplicationAddress && n < 1000) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        if (mbi.State == MEM_COMMIT) {
            const char* prot = "OTHER";
            if      (mbi.Protect & PAGE_EXECUTE_READWRITE) prot = "EXEC+RW";
            else if (mbi.Protect & PAGE_EXECUTE_READ)      prot = "EXEC+R";
            else if (mbi.Protect & PAGE_READWRITE)         prot = "READ/WRITE";
            else if (mbi.Protect & PAGE_READONLY)          prot = "READ ONLY";
            else if (mbi.Protect & PAGE_EXECUTE)           prot = "EXECUTE";
            else if (mbi.Protect & PAGE_WRITECOPY)         prot = "WRITECOPY";

            const char* mtype = "PRIV";
            if      (mbi.Type == MEM_IMAGE)  mtype = "IMAGE";
            else if (mbi.Type == MEM_MAPPED) mtype = "MAPPED";

            uintptr_t rs = (uintptr_t)mbi.BaseAddress;
            uintptr_t re = rs + mbi.RegionSize;
            int hits = 0;
            for (uintptr_t fa : foundPtrs) if (fa >= rs && fa < re) hits++;

            char line[512];
            if (hits > 0) {
                sprintf_s(line, "0x%016llX | %11s | %-7s | %-13s | >>> %d RESULT(S) FOUND <<<",
                    (unsigned long long)rs, FormatMemorySize(mbi.RegionSize).c_str(), mtype, prot, hits);
                if (firstFound < 0) firstFound = n + 2;
            } else {
                sprintf_s(line, "0x%016llX | %11s | %-7s | %s",
                    (unsigned long long)rs, FormatMemorySize(mbi.RegionSize).c_str(), mtype, prot);
            }
            SendMessageA(hMemoryMapWnd, LB_ADDSTRING, 0, (LPARAM)line);
            n++;
        }
        addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }
    if (firstFound >= 0)
        SendMessage(hMemoryMapWnd, LB_SETTOPINDEX, (WPARAM)std::max(0, firstFound-2), 0);
    char buf[128]; sprintf_s(buf, "Memory map: %d committed regions", n);
    LogToStatus(buf);
}

int ReadValueFromAddress(LPVOID address) {
    if (!hProcess) return 0;
    int v = 0; SIZE_T r;
    ReadProcessMemory(hProcess, address, &v, 4, &r);
    return v;
}

void WriteValueToAddress(LPVOID address, int value) {
    if (!hProcess) { LogToStatus("No process attached!", true); return; }
    BYTE orig[4]; SIZE_T r;
    if (ReadProcessMemory(hProcess, address, orig, 4, &r)) {
        Backup4 bk; memcpy(bk.data, orig, 4);
        backups[address] = bk;
    }
    BYTE nb[4]; *(int*)nb = value; SIZE_T w;
    if (WriteProcessMemory(hProcess, address, nb, 4, &w)) {
        char buf[128]; sprintf_s(buf, "Wrote %d to 0x%p", value, address);
        LogToStatus(buf);
        ShowHexAtAddress(address, address);
    } else {
        LogToStatus("Write failed - Run as Administrator!", true);
    }
}

void DoFirstScan() {
    if (!hProcess) { LogToStatus("No process attached!", true); return; }
    int dt = (int)SendMessage(hCmbDataType, CB_GETCURSEL, 0, 0);
    int sc = (int)SendMessage(hCmbScanType, CB_GETCURSEL, 0, 0);
    if (dt < 0) dt = DT_INT32;
    if (sc < 0) sc = SC_EXACT;

    char valueStr[128]; GetWindowTextA(hEditScanValue, valueStr, 128);

    char logBuf[256]; sprintf_s(logBuf, "First scan: type=%d cond=%d value='%s' ...", dt, sc, valueStr);
    LogToStatus(logBuf);
    SendMessage(hScanResultsWnd, LB_RESETCONTENT, 0, 0);
    scanResults.clear(); scanPrevVals.clear();

    LPVOID base = GetBaseAddress();
    SYSTEM_INFO si; GetSystemInfo(&si);
    LPVOID addr = si.lpMinimumApplicationAddress;
    int found = 0;
    const int MAX_RESULTS = 100000;

    std::vector<BYTE> aobBytes; std::vector<bool> aobMask;
    if (dt == DT_AOB && !ParseAOB(valueStr, aobBytes, aobMask)) {
        LogToStatus("Invalid AOB pattern. Use: 48 8B 05 ?? ?? ??", true); return;
    }

    BYTE targetBuf[8] = {};
    size_t valSz = GetDataTypeSize(dt);

    if (sc == SC_EXACT && dt != DT_STRING && dt != DT_AOB) {
        if (dt == DT_FLOAT)  { float  v = (float)atof(valueStr);  memcpy(targetBuf, &v, 4); }
        else if (dt == DT_DOUBLE) { double v = atof(valueStr);    memcpy(targetBuf, &v, 8); }
        else if (dt == DT_INT64) {
            int64_t v = (int64_t)_atoi64(valueStr); memcpy(targetBuf, &v, 8);
        } else {
            int32_t v = atoi(valueStr);
            if      (dt == DT_INT8)  { int8_t  b = (int8_t)v;  memcpy(targetBuf, &b, 1); }
            else if (dt == DT_INT16) { int16_t b = (int16_t)v; memcpy(targetBuf, &b, 2); }
            else                     { memcpy(targetBuf, &v, 4); }
        }
    }

    while (addr < si.lpMaximumApplicationAddress && found < MAX_RESULTS) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READWRITE|PAGE_READONLY|PAGE_EXECUTE_READ)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            SIZE_T chunkSz = std::min(mbi.RegionSize, (SIZE_T)(4*1024*1024));
            std::vector<BYTE> chunk(chunkSz); SIZE_T r;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, chunk.data(), chunkSz, &r) && r > 0) {

                if (dt == DT_STRING) {
                    size_t slen = strlen(valueStr);
                    if (slen == 0) goto nextRegion;
                    for (SIZE_T i = 0; i + slen <= r && found < MAX_RESULTS; i++) {
                        if (memcmp(&chunk[i], valueStr, slen) == 0) {
                            LPVOID fa = (LPVOID)((uintptr_t)mbi.BaseAddress + i);
                            scanResults.push_back(fa);
                            std::vector<BYTE> pv(chunk.begin()+i, chunk.begin()+i+slen);
                            scanPrevVals.push_back(pv);
                            LONGLONG off = base ? ((LONGLONG)(uintptr_t)fa-(LONGLONG)(uintptr_t)base) : 0;
                            char entry[512]; sprintf_s(entry, "0x%p  |  Offset: +0x%llX  |  String: \"%s\"", fa, off, valueStr);
                            SendMessageA(hScanResultsWnd, LB_ADDSTRING, 0, (LPARAM)entry);
                            found++;
                        }
                    }
                } else if (dt == DT_AOB) {
                    size_t plen = aobBytes.size();
                    for (SIZE_T i = 0; i + plen <= r && found < MAX_RESULTS; i++) {
                        bool match = true;
                        for (size_t k = 0; k < plen; k++) {
                            if (!aobMask[k] && chunk[i+k] != aobBytes[k]) { match = false; break; }
                        }
                        if (match) {
                            LPVOID fa = (LPVOID)((uintptr_t)mbi.BaseAddress + i);
                            scanResults.push_back(fa);
                            std::vector<BYTE> pv(chunk.begin()+i, chunk.begin()+i+plen);
                            scanPrevVals.push_back(pv);
                            LONGLONG off = base ? ((LONGLONG)(uintptr_t)fa-(LONGLONG)(uintptr_t)base) : 0;
                            char entry[512]; sprintf_s(entry, "0x%p  |  Offset: +0x%llX  |  AOB match (%zu bytes)", fa, off, plen);
                            SendMessageA(hScanResultsWnd, LB_ADDSTRING, 0, (LPARAM)entry);
                            found++;
                        }
                    }
                } else {
                    for (SIZE_T i = 0; i + valSz <= r && found < MAX_RESULTS; i += valSz) {
                        const BYTE* cur = &chunk[i];
                        bool hit = false;
                        if (sc == SC_EXACT)   hit = MatchesCondition(cur, nullptr, targetBuf, dt, sc, valSz);
                        else                  hit = true; 
                        if (hit) {
                            LPVOID fa = (LPVOID)((uintptr_t)mbi.BaseAddress + i);
                            scanResults.push_back(fa);
                            std::vector<BYTE> pv(cur, cur + valSz);
                            scanPrevVals.push_back(pv);
                            if (sc == SC_EXACT) {
                                LONGLONG off = base ? ((LONGLONG)(uintptr_t)fa-(LONGLONG)(uintptr_t)base) : 0;
                                char entry[512]; sprintf_s(entry, "0x%p  |  Offset: +0x%llX  |  Value: %s",
                                    fa, off, FormatTypedValue(cur, dt).c_str());
                                SendMessageA(hScanResultsWnd, LB_ADDSTRING, 0, (LPARAM)entry);
                                found++;
                            } else {
                                found++;
                            }
                        }
                    }
                }
            }
        }
        nextRegion:
        addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }

    if (sc != SC_EXACT && dt != DT_STRING && dt != DT_AOB) {
        char buf[256]; sprintf_s(buf, "Baseline captured: %d address(es). Change value then click Next Scan.", found);
        LogToStatus(buf);
        SendMessageA(hScanResultsWnd, LB_ADDSTRING, 0, (LPARAM)"[Baseline captured - change value in target and click Next Scan]");
        SendMessageA(hScanResultsWnd, LB_ADDSTRING, 0, (LPARAM)"[Results will appear after the next scan filters the baseline]");
    } else {
        char buf[256]; sprintf_s(buf, "Found %d match(es)", found);
        LogToStatus(buf);
    }
    ShowMemoryMap();
    UpdateScanCount();
}

void DoNextScan() {
    if (scanResults.empty()) { LogToStatus("No previous scan - use First Scan first", true); return; }
    int dt = (int)SendMessage(hCmbDataType, CB_GETCURSEL, 0, 0);
    int sc = (int)SendMessage(hCmbScanType, CB_GETCURSEL, 0, 0);
    if (dt < 0) dt = DT_INT32;
    if (sc < 0) sc = SC_EXACT;

    char valueStr[128]; GetWindowTextA(hEditScanValue, valueStr, 128);
    size_t valSz = GetDataTypeSize(dt);

    BYTE targetBuf[8] = {};
    if (sc == SC_EXACT && dt != DT_STRING && dt != DT_AOB) {
        if (dt == DT_FLOAT)  { float  v = (float)atof(valueStr);  memcpy(targetBuf, &v, 4); }
        else if (dt == DT_DOUBLE) { double v = atof(valueStr);    memcpy(targetBuf, &v, 8); }
        else if (dt == DT_INT64) {
            int64_t v = (int64_t)_atoi64(valueStr); memcpy(targetBuf, &v, 8);
        } else {
            int32_t v = atoi(valueStr);
            if      (dt == DT_INT8)  { int8_t  b = (int8_t)v;  memcpy(targetBuf, &b, 1); }
            else if (dt == DT_INT16) { int16_t b = (int16_t)v; memcpy(targetBuf, &b, 2); }
            else                     { memcpy(targetBuf, &v, 4); }
        }
    }

    std::vector<BYTE> aobBytes; std::vector<bool> aobMask;
    if (dt == DT_AOB) ParseAOB(valueStr, aobBytes, aobMask);

    LPVOID base = GetBaseAddress();
    std::vector<LPVOID>            nextResults;
    std::vector<std::vector<BYTE>> nextPrev;

    SendMessage(hScanResultsWnd, LB_RESETCONTENT, 0, 0);
    char logBuf[256]; sprintf_s(logBuf, "Refining scan (cond=%d)...", sc);
    LogToStatus(logBuf);

    for (size_t i = 0; i < scanResults.size(); i++) {
        LPVOID a = scanResults[i];
        BYTE cur[16] = {};
        SIZE_T r;

        size_t readSz = (dt == DT_AOB && !aobBytes.empty()) ? aobBytes.size() : valSz;
        if (dt == DT_STRING) readSz = strlen(valueStr);
        if (!ReadProcessMemory(hProcess, a, cur, readSz, &r) || r < readSz) continue;

        const BYTE* prev = (!scanPrevVals.empty() && i < scanPrevVals.size() && !scanPrevVals[i].empty())
                           ? scanPrevVals[i].data() : nullptr;

        bool hit = false;
        if (dt == DT_STRING) {
            hit = (memcmp(cur, valueStr, readSz) == 0);
        } else if (dt == DT_AOB) {
            hit = true;
            for (size_t k = 0; k < aobBytes.size() && hit; k++)
                if (!aobMask[k] && cur[k] != aobBytes[k]) hit = false;
        } else {
            hit = MatchesCondition(cur, prev, targetBuf, dt, sc, valSz);
        }

        if (hit) {
            nextResults.push_back(a);
            nextPrev.push_back(std::vector<BYTE>(cur, cur + readSz));
            LONGLONG off = base ? ((LONGLONG)(uintptr_t)a-(LONGLONG)(uintptr_t)base) : 0;
            char entry[512];
            sprintf_s(entry, "0x%p  |  Offset: +0x%llX  |  Value: %s",
                      a, off, FormatTypedValue(cur, dt).c_str());
            SendMessageA(hScanResultsWnd, LB_ADDSTRING, 0, (LPARAM)entry);
        }
    }
    scanResults  = nextResults;
    scanPrevVals = nextPrev;
    char buf[128]; sprintf_s(buf, "Refined to %zu match(es)", scanResults.size());
    LogToStatus(buf);
    ShowMemoryMap();
    UpdateScanCount();
}

void ScanForPointers(LPVOID targetAddr) {
    if (!hProcess) { LogToStatus("No process attached!", true); return; }
    char buf[256]; sprintf_s(buf, "Pointer scan for addresses pointing to 0x%p ...", targetAddr);
    LogToStatus(buf);
    SendMessage(hScanResultsWnd, LB_RESETCONTENT, 0, 0);
    scanResults.clear(); scanPrevVals.clear();

    LPVOID base = GetBaseAddress();
    SYSTEM_INFO si; GetSystemInfo(&si);
    LPVOID addr = si.lpMinimumApplicationAddress;
    int found = 0;
    uintptr_t target = (uintptr_t)targetAddr;
    size_t ptrSz = sizeof(uintptr_t);

    while (addr < si.lpMaximumApplicationAddress && found < 50000) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE|PAGE_READONLY|PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            SIZE_T chunkSz = std::min(mbi.RegionSize, (SIZE_T)(2*1024*1024));
            std::vector<BYTE> chunk(chunkSz); SIZE_T r;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, chunk.data(), chunkSz, &r)) {
                for (SIZE_T i = 0; i + ptrSz <= r && found < 50000; i += ptrSz) {
                    uintptr_t val;
                    memcpy(&val, &chunk[i], ptrSz);
                    if (val >= target && val <= target + 4096) {
                        LPVOID fa = (LPVOID)((uintptr_t)mbi.BaseAddress + i);
                        scanResults.push_back(fa);
                        LONGLONG ptrVal = (LONGLONG)val;
                        LONGLONG off = base ? ((LONGLONG)(uintptr_t)fa-(LONGLONG)(uintptr_t)base) : 0;
                        char entry[512];
                        sprintf_s(entry, "0x%p  |  Offset: +0x%llX  |  Points to: 0x%llX  (+0x%llX)",
                                  fa, off, ptrVal, (LONGLONG)(val - target));
                        SendMessageA(hScanResultsWnd, LB_ADDSTRING, 0, (LPARAM)entry);
                        found++;
                    }
                }
            }
        }
        addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }
    sprintf_s(buf, "Pointer scan: %d pointer(s) found to 0x%p (range +4096)", found, targetAddr);
    LogToStatus(buf);
    ShowMemoryMap();
    UpdateScanCount();
}

void ShowHexAtAddress(LPVOID address, LPVOID highlightAddr) {
    if (!hProcess) { LogToStatus("No process attached!", true); return; }
    SendMessage(hHexViewWnd, LB_RESETCONTENT, 0, 0);
    BYTE data[512]; SIZE_T r;
    if (!ReadProcessMemory(hProcess, address, data, sizeof(data), &r)) {
        LogToStatus("Failed to read memory at address", true); return;
    }
    char hdr[256]; sprintf_s(hdr, "Hex dump @ 0x%p  (%zu bytes)", address, r);
    SendMessageA(hHexViewWnd, LB_ADDSTRING, 0, (LPARAM)hdr);
    SendMessageA(hHexViewWnd, LB_ADDSTRING, 0,
        (LPARAM)"Offset   | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII");
    SendMessageA(hHexViewWnd, LB_ADDSTRING, 0,
        (LPARAM)"---------+-------------------------------------------------+-----------------");

    int highlightRow = -1;
    for (int i = 0; i < (int)r; i += 16) {
        char line[256] = {}; char asc[20] = {};
        sprintf_s(line, "%08X | ", (DWORD)((uintptr_t)address + i));
        for (int j = 0; j < 16; j++) {
            if (i+j < (int)r) {
                char h[4]; sprintf_s(h, "%02X ", data[i+j]); strcat_s(line, h);
                asc[j] = (data[i+j] >= 32 && data[i+j] < 127) ? (char)data[i+j] : '.';
            } else { strcat_s(line, "   "); asc[j] = ' '; }
        }
        asc[16] = 0;
        strcat_s(line, "| "); strcat_s(line, asc);
        if (highlightAddr) {
            uintptr_t rs = (uintptr_t)address + i;
            uintptr_t ha = (uintptr_t)highlightAddr;
            if (ha >= rs && ha < rs + 16) {
                int byteOff = (int)(ha - rs);
                int hval = 0;
                if (byteOff + 4 <= (int)r - i) hval = *(int*)(&data[i + byteOff]);
                char marker[80];
                sprintf_s(marker, "  <<<< byte+0x%02X  int32=%d  >>>>", byteOff, hval);
                strcat_s(line, marker);
                highlightRow = (i / 16) + 3;
            }
        }
        SendMessageA(hHexViewWnd, LB_ADDSTRING, 0, (LPARAM)line);
    }
    SendMessageA(hHexViewWnd, LB_ADDSTRING, 0, (LPARAM)"");
    int32_t vi = *(int32_t*)data; int16_t vs = *(int16_t*)data;
    float vf = *(float*)data; double vd = *(double*)data;
    char interp[256];
    sprintf_s(interp, "int32=%d  |  int16=%d  |  float=%.4f  |  double=%.6f  (@ base addr)",
              vi, vs, vf, vd);
    SendMessageA(hHexViewWnd, LB_ADDSTRING, 0, (LPARAM)interp);
    if (highlightRow >= 0) {
        SendMessage(hHexViewWnd, LB_SETTOPINDEX, (WPARAM)std::max(0, highlightRow-2), 0);
        SendMessage(hHexViewWnd, LB_SETCURSEL,   (WPARAM)highlightRow, 0);
    }
    char hexAddr[32]; sprintf_s(hexAddr, "0x%p", address);
    SetWindowTextA(hEditHexAddress, hexAddr);
    LogToStatus("Hex view updated");
}

void PopulateModuleList() {
    SendMessage(hLstModules, LB_RESETCONTENT, 0, 0);
    if (!hProcess) return;
    HMODULE mods[512]; DWORD needed;
    SendMessageA(hLstModules, LB_ADDSTRING, 0,
        (LPARAM)"Module Name              | Base Address        | Size       | Entry Point");
    SendMessageA(hLstModules, LB_ADDSTRING, 0,
        (LPARAM)"-------------------------+---------------------+------------+--------------------");
    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed)) return;
    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count && i < 512; i++) {
        char modPath[MAX_PATH] = {};
        GetModuleFileNameExA(hProcess, mods[i], modPath, MAX_PATH);
        const char* modName = strrchr(modPath, '\\');
        if (modName) modName++; else modName = modPath;
        MODULEINFO mi = {};
        GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi));
        char line[512];
        sprintf_s(line, "%-24s | 0x%016llX | %10s | 0x%p",
                  modName, (unsigned long long)(uintptr_t)mi.lpBaseOfDll,
                  FormatMemorySize(mi.SizeOfImage).c_str(), mi.EntryPoint);
        SendMessageA(hLstModules, LB_ADDSTRING, 0, (LPARAM)line);
    }
}

void RefreshWatchList() {
    if (!hProcess || watchList.empty()) return;
    SendMessage(hLstWatchList, LB_RESETCONTENT, 0, 0);
    LPVOID base = GetBaseAddress();
    for (int i = 0; i < (int)watchList.size(); i++) {
        LPVOID a = watchList[i];
        int v = ReadValueFromAddress(a);
        float vf = 0.0f; ReadProcessMemory(hProcess, a, &vf, 4, nullptr);
        LONGLONG off = base ? ((LONGLONG)(uintptr_t)a-(LONGLONG)(uintptr_t)base) : 0;
        char entry[512];
        sprintf_s(entry, "[%02d]  0x%p  +0x%llX  =  %d  (%.4f)", i, a, off, v, vf);
        SendMessageA(hLstWatchList, LB_ADDSTRING, 0, (LPARAM)entry);
    }
}

void ExportScanResults() {
    if (scanResults.empty()) { LogToStatus("No results to export", true); return; }
    char filename[MAX_PATH] = "scan_results.txt";
    OPENFILENAMEA ofn = {}; ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMainWnd; ofn.lpstrFile = filename; ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = "Text Files\0*.txt\0All Files\0*.*\0";
    ofn.lpstrDefExt = "txt"; ofn.Flags = OFN_OVERWRITEPROMPT;
    if (!GetSaveFileNameA(&ofn)) return;
    FILE* f = nullptr; fopen_s(&f, filename, "w");
    if (!f) { LogToStatus("Could not open file for export", true); return; }
    LPVOID base = GetBaseAddress();
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "MEMISCANI Scan Results Export\n");
    fprintf(f, "Date: %04d-%02d-%02d %02d:%02d:%02d\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    fprintf(f, "PID: %d  Base: 0x%p  Results: %zu\n\n",
            currentPID, base, scanResults.size());
    int dt = (int)SendMessage(hCmbDataType, CB_GETCURSEL, 0, 0);
    for (LPVOID a : scanResults) {
        BYTE buf[8] = {}; SIZE_T r;
        ReadProcessMemory(hProcess, a, buf, GetDataTypeSize(dt), &r);
        LONGLONG off = base ? ((LONGLONG)(uintptr_t)a-(LONGLONG)(uintptr_t)base) : 0;
        fprintf(f, "0x%p  Offset: +0x%llX  Value: %s\n",
                a, off, FormatTypedValue(buf, dt).c_str());
    }
    fclose(f);
    char msg[256]; sprintf_s(msg, "Exported %zu results to %s", scanResults.size(), filename);
    LogToStatus(msg);
}

static std::string AsmTrimLine(const std::string& s) {
    size_t st = s.find_first_not_of(" \t\r\n");
    if (st == std::string::npos) return "";
    std::string t = s.substr(st, s.find_last_not_of(" \t\r\n") - st + 1);
    size_t c = t.find(';'); if (c != std::string::npos) t = t.substr(0, c);
    while (!t.empty() && (t.back()==' '||t.back()=='\t')) t.pop_back();
    return t;
}
static std::string AsmToLow(std::string s) { std::transform(s.begin(),s.end(),s.begin(),::tolower); return s; }

static const struct { const char* name; int num; bool w64; } kRegTable[] = {
    {"rax",0,1},{"rcx",1,1},{"rdx",2,1},{"rbx",3,1},{"rsp",4,1},{"rbp",5,1},{"rsi",6,1},{"rdi",7,1},
    {"r8",8,1},{"r9",9,1},{"r10",10,1},{"r11",11,1},{"r12",12,1},{"r13",13,1},{"r14",14,1},{"r15",15,1},
    {"eax",0,0},{"ecx",1,0},{"edx",2,0},{"ebx",3,0},{"esp",4,0},{"ebp",5,0},{"esi",6,0},{"edi",7,0},
    {nullptr,0,0}
};
static bool AsmFindReg(const std::string& nm, int& n, bool& w64) {
    std::string l = AsmToLow(nm);
    for (int i=0; kRegTable[i].name; i++) if (l==kRegTable[i].name) { n=kRegTable[i].num; w64=kRegTable[i].w64; return true; }
    return false;
}
static bool AsmParseMemRef(const std::string& expr, int& bn, bool& bw, int32_t& disp) {
    std::string t = AsmToLow(expr);
    size_t lb=t.find('['), rb=t.find(']');
    if (lb==std::string::npos||rb==std::string::npos) return false;
    std::string inner = AsmTrimLine(t.substr(lb+1,rb-lb-1));
    disp=0;
    size_t opPos=std::string::npos; int sign=0;
    for (size_t i=1;i<inner.size();i++) { if(inner[i]=='+'){sign=1;opPos=i;break;} if(inner[i]=='-'){sign=-1;opPos=i;break;} }
    std::string regPart = opPos!=std::string::npos ? AsmTrimLine(inner.substr(0,opPos)) : inner;
    if (!AsmFindReg(regPart,bn,bw)) return false;
    if (opPos!=std::string::npos) { std::string dp=AsmTrimLine(inner.substr(opPos+1)); disp=(int32_t)strtol(dp.c_str(),nullptr,0)*sign; }
    return true;
}
static void AsmModRM(std::vector<BYTE>& out, int regF, int baseNum, int32_t disp) {
    int rm=baseNum&7;
    int mod = (disp==0&&rm!=5) ? 0 : (disp>=-128&&disp<=127) ? 1 : 2;
    out.push_back((BYTE)((mod<<6)|((regF&7)<<3)|rm));
    if (rm==4) out.push_back(0x24);
    if (mod==1) out.push_back((BYTE)(int8_t)disp);
    else if (mod==2) { out.push_back(disp&0xFF);out.push_back((disp>>8)&0xFF);out.push_back((disp>>16)&0xFF);out.push_back((disp>>24)&0xFF); }
}
static void AsmLE32(std::vector<BYTE>& o, int32_t v) { o.push_back(v&0xFF);o.push_back((v>>8)&0xFF);o.push_back((v>>16)&0xFF);o.push_back((v>>24)&0xFF); }
static void AsmLE64(std::vector<BYTE>& o, uint64_t v) { for(int i=0;i<8;i++) o.push_back((v>>(i*8))&0xFF); }
static std::string AsmStripSize(std::string s, int& sz) {
    std::string sl=AsmToLow(s);
    if(sl.find("qword")!=std::string::npos) sz=8;
    else if(sl.find("dword")!=std::string::npos) sz=4;
    else if(sl.find("word")!=std::string::npos&&sl.find("dword")==std::string::npos) sz=2;
    else if(sl.find("byte")!=std::string::npos) sz=1;
    for(const char* p:{"qword ptr","dword ptr","word ptr","byte ptr","qword","dword","word","byte"}) {
        size_t pos=sl.find(p); if(pos!=std::string::npos){s=AsmTrimLine(s.substr(pos+strlen(p)));break;}
    }
    return s;
}

static std::string AssembleLine(const std::string& rawLine, std::vector<BYTE>& out) {
    std::string line=AsmTrimLine(rawLine); if(line.empty()) return "";
    std::string low=AsmToLow(line);
    if(low=="nop")               {out.push_back(0x90);return "";}
    if(low=="ret"||low=="retn")  {out.push_back(0xC3);return "";}
    if(low=="int3"||low=="int 3"){out.push_back(0xCC);return "";}
    if(low=="cdq")               {out.push_back(0x99);return "";}
    if(low=="pushfq")            {out.push_back(0x9C);return "";}
    if(low=="popfq")             {out.push_back(0x9D);return "";}

    size_t sp=low.find(' ');
    std::string mn=sp!=std::string::npos?low.substr(0,sp):low;
    std::string ops=sp!=std::string::npos?AsmTrimLine(line.substr(sp+1)):"";

    if(mn=="push"||mn=="pop") {
        int n; bool w;
        if(AsmFindReg(AsmToLow(ops),n,w)&&w) {
            BYTE base=(mn=="pop")?0x58:0x50;
            if(n>=8){out.push_back(0x41);out.push_back(base+(n-8));}else out.push_back(base+n);
            return "";
        }
        return mn+": unsupported register '"+ops+"'";
    }

    if(mn=="mov"||mn=="lea") {
        size_t comma=ops.find(','); if(comma==std::string::npos) return mn+": missing comma";
        std::string dst=AsmTrimLine(ops.substr(0,comma)), src=AsmTrimLine(ops.substr(comma+1));
        int sz=4; dst=AsmStripSize(dst,sz); src=AsmStripSize(src,sz);
        int dn,sn; bool dw,sw;
        bool dReg=AsmFindReg(AsmToLow(dst),dn,dw), sReg=AsmFindReg(AsmToLow(src),sn,sw);
        bool dMem=dst.find('[')!=std::string::npos, sMem=src.find('[')!=std::string::npos;

        if(mn=="lea") {
            if(!dReg||!sMem) return "lea: need reg, [mem]";
            int bn; bool bw; int32_t disp;
            if(!AsmParseMemRef(src,bn,bw,disp)) return "lea: bad mem ref";
            BYTE rex=dw?0x48:0x00; if(dn>=8)rex|=0x04; if(bn>=8)rex|=0x01;
            if(rex)out.push_back(rex); out.push_back(0x8D); AsmModRM(out,dn&7,bn,disp); return "";
        }
        if(dReg&&dw&&!sMem&&!sReg) {
            uint64_t imm=strtoull(src.c_str(),nullptr,0);
            out.push_back(0x48|(dn>=8?1:0)); out.push_back(0xB8+(dn&7)); AsmLE64(out,imm); return "";
        }
        if(dReg&&!dw&&!sMem&&!sReg) {
            int32_t imm=(int32_t)strtoul(src.c_str(),nullptr,0);
            if(dn>=8)out.push_back(0x41); out.push_back(0xB8+(dn&7)); AsmLE32(out,imm); return "";
        }
        if(dReg&&sReg&&dw==sw) {
            BYTE rex=dw?0x48:0x00; if(sn>=8)rex|=0x04; if(dn>=8)rex|=0x01;
            if(rex)out.push_back(rex); out.push_back(0x89); out.push_back(0xC0|((sn&7)<<3)|(dn&7)); return "";
        }
        if(dReg&&sMem) {
            int bn; bool bw; int32_t disp;
            if(!AsmParseMemRef(src,bn,bw,disp)) return "mov: bad mem ref '"+src+"'";
            BYTE rex=dw?0x48:0x00; if(dn>=8)rex|=0x04; if(bn>=8)rex|=0x01;
            if(rex)out.push_back(rex); out.push_back(0x8B); AsmModRM(out,dn&7,bn,disp); return "";
        }

        if(dMem&&sReg) {
            int bn; bool bw; int32_t disp;
            if(!AsmParseMemRef(dst,bn,bw,disp)) return "mov: bad mem ref '"+dst+"'";
            BYTE rex=sw?0x48:0x00; if(sn>=8)rex|=0x04; if(bn>=8)rex|=0x01;
            if(rex)out.push_back(rex); out.push_back(0x89); AsmModRM(out,sn&7,bn,disp); return "";
        }


        if(dMem&&!sReg) {
            int bn; bool bw; int32_t disp;
            if(!AsmParseMemRef(dst,bn,bw,disp)) return "mov: bad mem ref '"+dst+"'";
            int64_t imm=strtoll(src.c_str(),nullptr,0);
            BYTE rex=0; if(bn>=8)rex|=0x01;
            if(sz==1){if(rex)out.push_back(0x40|rex);out.push_back(0xC6);AsmModRM(out,0,bn,disp);out.push_back((BYTE)(uint8_t)imm);}
            else if(sz==2){out.push_back(0x66);if(rex)out.push_back(0x40|rex);out.push_back(0xC7);AsmModRM(out,0,bn,disp);out.push_back(imm&0xFF);out.push_back((imm>>8)&0xFF);}
            else{if(rex)out.push_back(0x40|rex);out.push_back(0xC7);AsmModRM(out,0,bn,disp);AsmLE32(out,(int32_t)imm);}
            return "";
        }
        return "mov: unsupported form '"+line+"'";
    }

    static const struct { const char* mn; int rf; BYTE rm2r; BYTE r2rm; } kArith[]={
        {"add",0,0x01,0x03},{"or",1,0x09,0x0B},{"adc",2,0x11,0x13},{"sbb",3,0x19,0x1B},
        {"and",4,0x21,0x23},{"sub",5,0x29,0x2B},{"xor",6,0x31,0x33},{"cmp",7,0x39,0x3B},{nullptr,0,0,0}
    };
    for(int ai=0;kArith[ai].mn;ai++) {
        if(mn!=kArith[ai].mn) continue;
        size_t comma=ops.find(','); if(comma==std::string::npos) return mn+": missing comma";
        std::string dst=AsmTrimLine(ops.substr(0,comma)), src=AsmTrimLine(ops.substr(comma+1));
        int sz=4; dst=AsmStripSize(dst,sz);
        bool dMem=dst.find('[')!=std::string::npos;
        int dn,sn; bool dw,sw;
        bool dReg=AsmFindReg(AsmToLow(dst),dn,dw), sReg=AsmFindReg(AsmToLow(src),sn,sw);
        bool sMem=src.find('[')!=std::string::npos;

        if(dReg&&sReg) {
            BYTE rex=0; if(dw||sw)rex|=0x48; if(sn>=8)rex|=0x04; if(dn>=8)rex|=0x01;
            if(rex)out.push_back(rex); out.push_back(kArith[ai].r2rm); out.push_back(0xC0|((dn&7)<<3)|(sn&7)); return "";
        }
        if(dReg&&!sReg&&!sMem) {
            int64_t imm=strtoll(src.c_str(),nullptr,0);
            BYTE rex=0; if(dw)rex|=0x48; if(dn>=8)rex|=0x01; if(rex)out.push_back(rex);
            if(imm>=-128&&imm<=127){out.push_back(0x83);out.push_back(0xC0|(kArith[ai].rf<<3)|(dn&7));out.push_back((BYTE)(int8_t)imm);}
            else{out.push_back(0x81);out.push_back(0xC0|(kArith[ai].rf<<3)|(dn&7));AsmLE32(out,(int32_t)imm);}
            return "";
        }
        if(dReg&&sMem) {
            int bn; bool bw; int32_t disp; if(!AsmParseMemRef(src,bn,bw,disp)) return mn+": bad mem ref";
            BYTE rex=dw?0x48:0; if(dn>=8)rex|=0x04; if(bn>=8)rex|=0x01;
            if(rex)out.push_back(rex); out.push_back(kArith[ai].r2rm); AsmModRM(out,dn&7,bn,disp); return "";
        }
        if(dMem&&sReg) {
            int bn; bool bw; int32_t disp; if(!AsmParseMemRef(dst,bn,bw,disp)) return mn+": bad mem ref";
            BYTE rex=sw?0x48:0; if(sn>=8)rex|=0x04; if(bn>=8)rex|=0x01;
            if(rex)out.push_back(rex); out.push_back(kArith[ai].rm2r); AsmModRM(out,sn&7,bn,disp); return "";
        }
        if(dMem&&!sReg&&!sMem) {
            int bn; bool bw; int32_t disp; if(!AsmParseMemRef(dst,bn,bw,disp)) return mn+": bad mem ref";
            int64_t imm=strtoll(src.c_str(),nullptr,0);
            BYTE rex=0; if(bn>=8)rex|=0x01;
            if(sz==1){if(rex)out.push_back(0x40|rex);out.push_back(0x80);AsmModRM(out,kArith[ai].rf,bn,disp);out.push_back((BYTE)(int8_t)imm);}
            else if(imm>=-128&&imm<=127){if(rex)out.push_back(0x40|rex);out.push_back(0x83);AsmModRM(out,kArith[ai].rf,bn,disp);out.push_back((BYTE)(int8_t)imm);}
            else{if(rex)out.push_back(0x40|rex);out.push_back(0x81);AsmModRM(out,kArith[ai].rf,bn,disp);AsmLE32(out,(int32_t)imm);}
            return "";
        }
        return mn+": unsupported form";
    }

    static const struct { const char* mn; int rf; BYTE op; } kUnary[]={
        {"inc",0,0xFF},{"dec",1,0xFF},{"not",2,0xF7},{"neg",3,0xF7},{nullptr,0,0}
    };
    for(int ui=0;kUnary[ui].mn;ui++) {
        if(mn!=kUnary[ui].mn) continue;
        std::string op2=ops; int sz=4; op2=AsmStripSize(op2,sz);
        int n; bool w;
        if(AsmFindReg(AsmToLow(op2),n,w)) {
            BYTE rex=w?0x48:0; if(n>=8)rex|=0x01; if(rex)out.push_back(rex);
            out.push_back(kUnary[ui].op); out.push_back(0xC0|(kUnary[ui].rf<<3)|(n&7)); return "";
        }
        if(op2.find('[')!=std::string::npos) {
            int bn; bool bw; int32_t disp; if(!AsmParseMemRef(op2,bn,bw,disp)) return mn+": bad mem ref";
            BYTE rex=0; if(bn>=8)rex|=0x01; if(rex)out.push_back(0x40|rex);
            out.push_back(kUnary[ui].op); AsmModRM(out,kUnary[ui].rf,bn,disp); return "";
        }
        return mn+": unsupported operand '"+ops+"'";
    }

    static const struct { const char* mn; int rf; } kMul[]={{"mul",4},{"imul",5},{"div",6},{"idiv",7},{nullptr,0}};
    for(int mi=0;kMul[mi].mn;mi++) {
        if(mn!=kMul[mi].mn) continue;
        std::string op2=ops; int sz=4; op2=AsmStripSize(op2,sz);
        int n; bool w; if(!AsmFindReg(AsmToLow(op2),n,w)) return mn+": bad register";
        BYTE rex=w?0x48:0; if(n>=8)rex|=0x01; if(rex)out.push_back(rex);
        out.push_back(0xF7); out.push_back(0xC0|(kMul[mi].rf<<3)|(n&7)); return "";
    }

    static const struct { const char* mn; int rf; } kShift[]={
        {"rol",0},{"ror",1},{"shl",4},{"sal",4},{"shr",5},{"sar",7},{nullptr,0}
    };
    for(int si=0;kShift[si].mn;si++) {
        if(mn!=kShift[si].mn) continue;
        size_t comma=ops.find(','); if(comma==std::string::npos) return mn+": missing comma";
        std::string dst=AsmTrimLine(ops.substr(0,comma)), src=AsmTrimLine(ops.substr(comma+1));
        int sz=4; dst=AsmStripSize(dst,sz);
        int n; bool w; if(!AsmFindReg(AsmToLow(dst),n,w)) return mn+": bad register";
        int cnt=(int)strtol(src.c_str(),nullptr,0);
        BYTE rex=w?0x48:0; if(n>=8)rex|=0x01; if(rex)out.push_back(rex);
        if(cnt==1){out.push_back(0xD1);out.push_back(0xC0|(kShift[si].rf<<3)|(n&7));}
        else{out.push_back(0xC1);out.push_back(0xC0|(kShift[si].rf<<3)|(n&7));out.push_back((BYTE)cnt);}
        return "";
    }

    if(mn=="call"||mn=="jmp") {
        int rf=(mn=="jmp")?4:2;
        std::string op2=ops; int sz=8; op2=AsmStripSize(op2,sz);
        int n; bool w;
        if(AsmFindReg(AsmToLow(op2),n,w)) {
            BYTE rex=0; if(n>=8)rex|=0x01; if(rex)out.push_back(0x40|rex);
            out.push_back(0xFF); out.push_back(0xC0|(rf<<3)|(n&7)); return "";
        }
        if(op2.find('[')!=std::string::npos) {
            int bn; bool bw; int32_t disp; if(!AsmParseMemRef(op2,bn,bw,disp)) return mn+": bad mem ref";
            BYTE rex=0; if(bn>=8)rex|=0x01; if(rex)out.push_back(0x40|rex);
            out.push_back(0xFF); AsmModRM(out,rf,bn,disp); return "";
        }
        return mn+": only register/memory targets supported (no relative jumps)";
    }

    if(mn=="test") {
        size_t comma=ops.find(','); if(comma==std::string::npos) return "test: missing comma";
        std::string d=AsmTrimLine(ops.substr(0,comma)), s2=AsmTrimLine(ops.substr(comma+1));
        int dn,sn; bool dw,sw;
        bool dR=AsmFindReg(AsmToLow(d),dn,dw), sR=AsmFindReg(AsmToLow(s2),sn,sw);
        if(dR&&sR){BYTE rex=0;if(dw||sw)rex|=0x48;if(sn>=8)rex|=0x04;if(dn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(0x85);out.push_back(0xC0|((sn&7)<<3)|(dn&7));return "";}
        if(dR&&!sR){int32_t imm=(int32_t)strtoll(s2.c_str(),nullptr,0);BYTE rex=dw?0x48:0;if(dn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(0xF7);out.push_back(0xC0|(dn&7));AsmLE32(out,imm);return "";}
        return "test: unsupported form";
    }


    if(mn=="xchg") {
        size_t comma=ops.find(','); if(comma==std::string::npos) return "xchg: missing comma";
        std::string d=AsmTrimLine(ops.substr(0,comma)), s2=AsmTrimLine(ops.substr(comma+1));
        int dn,sn; bool dw,sw;
        if(!AsmFindReg(AsmToLow(d),dn,dw)||!AsmFindReg(AsmToLow(s2),sn,sw)) return "xchg: bad registers";
        BYTE rex=0; if(dw||sw)rex|=0x48; if(sn>=8)rex|=0x04; if(dn>=8)rex|=0x01;
        if(rex)out.push_back(rex); out.push_back(0x87); out.push_back(0xC0|((dn&7)<<3)|(sn&7)); return "";
    }

    return "Unknown or unsupported instruction: "+mn;
}

static std::string AssembleSource(const char* src) {
    std::vector<BYTE> bytes;
    std::istringstream ss(src);
    std::string line; int ln=0;
    while(std::getline(ss,line)) {
        ln++;
        std::string err=AssembleLine(line,bytes);
        if(!err.empty()) return "Line "+std::to_string(ln)+": "+err;
    }
    if(bytes.empty()) return "ERROR: nothing assembled";
    std::string result;
    for(size_t i=0;i<bytes.size();i++){char h[4];sprintf_s(h,"%02X ",bytes[i]);result+=h;}
    if(!result.empty()) result.pop_back();
    return result;
}

LRESULT CALLBACK AsmWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hSrc=NULL, hOut=NULL, hErr=NULL;
    switch(msg) {
    case WM_CREATE: {
        HFONT fMono = CreateFontA(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,FIXED_PITCH,"Consolas");
        HFONT fNorm = CreateFontA(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,"Segoe UI");
        HWND h;
        h=CreateWindowA("STATIC","Assembly source  (Intel x64 syntax — ; comments ok):",WS_CHILD|WS_VISIBLE,10,8,640,18,hWnd,NULL,hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)fNorm,TRUE);
        hSrc=CreateWindowA("EDIT","",WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_WANTRETURN,
            10,28,660,270,hWnd,(HMENU)ID_EDIT_ASM_SRC,hInst,NULL);
        SendMessage(hSrc,WM_SETFONT,(WPARAM)fMono,TRUE);
        SetWindowTextA(hSrc,
           
            "Example: set value at found address to 9999\r\n"
            "push rax\r\n"
            "mov rax, 0x00007FF1ABCD1234  ; replace with your found address\r\n"
            "mov dword [rax], 9999\r\n"
            "pop rax\r\n"
            "ret");
        HWND hBtn=CreateWindowA("BUTTON","Assemble",WS_CHILD|WS_VISIBLE,10,308,110,26,hWnd,(HMENU)ID_BTN_ASSEMBLE,hInst,NULL);
        SendMessage(hBtn,WM_SETFONT,(WPARAM)fNorm,TRUE);
        hErr=CreateWindowA("STATIC","",WS_CHILD|WS_VISIBLE,130,314,550,18,hWnd,NULL,hInst,NULL);
        SendMessage(hErr,WM_SETFONT,(WPARAM)fNorm,TRUE);
        h=CreateWindowA("STATIC","Output hex bytes:",WS_CHILD|WS_VISIBLE,10,344,180,18,hWnd,NULL,hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)fNorm,TRUE);
        hOut=CreateWindowA("EDIT","",WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|ES_READONLY,
            10,364,545,24,hWnd,(HMENU)ID_EDIT_ASM_OUT,hInst,NULL);
        SendMessage(hOut,WM_SETFONT,(WPARAM)fMono,TRUE);
        HWND hSend=CreateWindowA("BUTTON","Send to SC Field",WS_CHILD|WS_VISIBLE,562,362,118,26,hWnd,(HMENU)ID_BTN_ASM_TO_SC,hInst,NULL);
        SendMessage(hSend,WM_SETFONT,(WPARAM)fNorm,TRUE);
        return 0;
    }
    case WM_COMMAND: {
        if(LOWORD(wParam)==ID_BTN_ASSEMBLE) {
            char src[8192]={}; GetWindowTextA(hSrc,src,8192);
            std::string result=AssembleSource(src);
            bool ok=(result.find("Line ")==std::string::npos && result.find("ERROR")==std::string::npos);
            SetWindowTextA(hErr, ok ? ("OK - "+std::to_string((result.size()+1)/3)+" bytes").c_str() : result.c_str());
            SetWindowTextA(hOut, ok ? result.c_str() : "");
        }
        if(LOWORD(wParam)==ID_BTN_ASM_TO_SC) {
            char buf[4096]={}; GetWindowTextA(hOut,buf,4096);
            if(buf[0]){SetWindowTextA(hEditShellcode,buf);LogToStatus("Assembled shellcode sent to injection field");}
        }
        return 0;
    }
    case WM_DESTROY: hWndAssembler=NULL; return 0;
    }
    return DefWindowProc(hWnd,msg,wParam,lParam);
}

void ShowAssemblerWindow() {
    if(hWndAssembler && IsWindow(hWndAssembler)) { SetForegroundWindow(hWndAssembler); return; }
    static bool reg=false;
    if(!reg) {
        WNDCLASSA wc={};
        wc.lpfnWndProc=AsmWndProc; wc.hInstance=hInst;
        wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
        wc.lpszClassName="AsmWnd"; wc.hCursor=LoadCursor(NULL,IDC_ARROW);
        RegisterClassA(&wc); reg=true;
    }
    hWndAssembler=CreateWindowExA(0,"AsmWnd","Assembly -> Shellcode  (Intel x64 syntax)",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_VISIBLE,
        200,150,692,408,hMainWnd,NULL,hInst,NULL);
}


void BuildShellcode() {
    int arch = (int)SendMessage(hCmbArch,  CB_GETCURSEL, 0, 0); 
    int op   = (int)SendMessage(hCmbScOp,  CB_GETCURSEL, 0, 0); 
    char addrStr[64] = {}; GetWindowTextA(hEditScAddr, addrStr, 64);
    char valStr[32]  = {}; GetWindowTextA(hEditScVal,  valStr,  32);
    uintptr_t addr = (uintptr_t)strtoull(addrStr, nullptr, 0);
    int val = atoi(valStr);

    BYTE b[64]; int n = 0;
    std::string result;

    if (op == 4) { 
        int count = val > 0 ? val : 16;
        for (int i = 0; i < count; i++) { char h[4]; sprintf_s(h,"90 "); result+=h; }
        result += "C3";
        SetWindowTextA(hEditScResult, result.c_str());
        LogToStatus("NOP sled built - click Send to SC to copy");
        return;
    }

    if (arch == 0) { 
        b[n++]=0x48; b[n++]=0xB8;
        for (int i=0;i<8;i++) b[n++]=(BYTE)((addr>>(i*8))&0xFF);
    } else {        
        b[n++]=0xB8;
        for (int i=0;i<4;i++) b[n++]=(BYTE)((addr>>(i*8))&0xFF);
    }

    switch (op) {
        case 0: 
            b[n++]=0xC7; b[n++]=0x00;
            b[n++]=(BYTE)(val&0xFF); b[n++]=(BYTE)((val>>8)&0xFF);
            b[n++]=(BYTE)((val>>16)&0xFF); b[n++]=(BYTE)((val>>24)&0xFF);
            break;
        case 1: 
            b[n++]=0x81; b[n++]=0x00;
            b[n++]=(BYTE)(val&0xFF); b[n++]=(BYTE)((val>>8)&0xFF);
            b[n++]=(BYTE)((val>>16)&0xFF); b[n++]=(BYTE)((val>>24)&0xFF);
            break;
        case 2: 
            b[n++]=0x81; b[n++]=0x28;
            b[n++]=(BYTE)(val&0xFF); b[n++]=(BYTE)((val>>8)&0xFF);
            b[n++]=(BYTE)((val>>16)&0xFF); b[n++]=(BYTE)((val>>24)&0xFF);
            break;
        case 3: 
            b[n++]=0xC7; b[n++]=0x00;
            b[n++]=0x00; b[n++]=0x00; b[n++]=0x00; b[n++]=0x00;
            break;
    }
    b[n++]=0xC3; 

    for (int i=0;i<n;i++) { char h[4]; sprintf_s(h,"%02X ",b[i]); result+=h; }
    if (!result.empty()) result.pop_back();
    SetWindowTextA(hEditScResult, result.c_str());

    char msg[128];
    sprintf_s(msg, "Built %d bytes (%s %s) - click Send to SC",
              n, arch==0?"x64":"x86",
              op==0?"Set":op==1?"Add":op==2?"Sub":"Zero");
    LogToStatus(msg);
}


void InjectDLL() {
    if (!hProcess) { LogToStatus("No process attached!", true); return; }
    char dllPath[MAX_PATH] = {};
    GetWindowTextA(hEditDllPath, dllPath, MAX_PATH);
    if (!dllPath[0]) { LogToStatus("Enter a DLL path first", true); return; }
    char fullPath[MAX_PATH] = {};
    GetFullPathNameA(dllPath, MAX_PATH, fullPath, nullptr);
    if (GetFileAttributesA(fullPath) == INVALID_FILE_ATTRIBUTES) {
        char buf[512]; sprintf_s(buf, "DLL file not found: %s", fullPath);
        LogToStatus(buf, true); return;
    }
    SIZE_T pathLen = strlen(fullPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, pathLen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        char buf[128]; sprintf_s(buf, "VirtualAllocEx failed: %lu", GetLastError());
        LogToStatus(buf, true); return;
    }
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteMem, fullPath, pathLen, &written)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        LogToStatus("WriteProcessMemory failed for DLL path", true); return;
    }
    LPVOID loadLib = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        (LPTHREAD_START_ROUTINE)loadLib, remoteMem, 0, nullptr);
    if (!hThread) {
        char buf[128]; sprintf_s(buf, "CreateRemoteThread failed: %lu", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        LogToStatus(buf, true); return;
    }
    WaitForSingleObject(hThread, 5000);
    DWORD exitCode = 0; GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    if (exitCode == 0) {
        LogToStatus("DLL injection: LoadLibrary returned NULL (check path/arch match)", true);
    } else {
        char buf[512]; sprintf_s(buf, "DLL injected: %s  (handle=0x%lX)", fullPath, exitCode);
        LogToStatus(buf);
        PopulateModuleList();
    }
}

void EjectDLL() {
    if (!hProcess) { LogToStatus("No process attached!", true); return; }
    int idx = (int)SendMessage(hLstModules, LB_GETCURSEL, 0, 0);
    if (idx < 2) { LogToStatus("Select a module in the Modules list to eject", true); return; }
    char line[512] = {}; SendMessageA(hLstModules, LB_GETTEXT, idx, (LPARAM)line);
    const char* p = strstr(line, "0x");
    if (!p) { LogToStatus("Could not parse module base address from list", true); return; }
    uintptr_t base = (uintptr_t)strtoull(p + 2, nullptr, 16);
    if (!base) { LogToStatus("Invalid module address", true); return; }
    LPVOID freeLib = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        (LPTHREAD_START_ROUTINE)freeLib, (LPVOID)base, 0, nullptr);
    if (!hThread) {
        char buf[128]; sprintf_s(buf, "CreateRemoteThread (FreeLibrary) failed: %lu", GetLastError());
        LogToStatus(buf, true); return;
    }
    WaitForSingleObject(hThread, 5000);
    DWORD ec = 0; GetExitCodeThread(hThread, &ec);
    CloseHandle(hThread);
    char buf[256]; sprintf_s(buf, "FreeLibrary on 0x%llX returned %lu", (unsigned long long)base, ec);
    LogToStatus(buf);
    PopulateModuleList();
}

void InjectShellcode() {
    if (!hProcess) { LogToStatus("No process attached!", true); return; }
    char scText[4096] = {}; GetWindowTextA(hEditShellcode, scText, sizeof(scText));
    std::vector<BYTE> scBytes; std::vector<bool> scMask;
    if (!ParseAOB(scText, scBytes, scMask) || scBytes.empty()) {
        LogToStatus("Invalid shellcode - enter as hex bytes: 90 90 C3 ...", true); return;
    }
    int protIdx = (int)SendMessage(hCmbMemProt, CB_GETCURSEL, 0, 0);
    DWORD prot = (protIdx == 1) ? PAGE_EXECUTE_READ : PAGE_EXECUTE_READWRITE;
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, scBytes.size(), MEM_COMMIT|MEM_RESERVE, prot);
    if (!remoteMem) {
        char buf[128]; sprintf_s(buf, "VirtualAllocEx failed: %lu", GetLastError());
        LogToStatus(buf, true); return;
    }
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteMem, scBytes.data(), scBytes.size(), &written)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        LogToStatus("WriteProcessMemory failed for shellcode", true); return;
    }
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        (LPTHREAD_START_ROUTINE)remoteMem, nullptr, 0, nullptr);
    if (!hThread) {
        char buf[128]; sprintf_s(buf, "CreateRemoteThread (shellcode) failed: %lu", GetLastError());
        LogToStatus(buf, true); return;
    }
    char buf[256]; sprintf_s(buf, "Shellcode (%zu bytes) executing at 0x%p", scBytes.size(), remoteMem);
    LogToStatus(buf);
    CloseHandle(hThread);
    ShowHexAtAddress(remoteMem, remoteMem);
}

void ScanCodeCaves() {
    if (!hProcess) { LogToStatus("No process attached!", true); return; }
    char szBuf[16] = {}; GetWindowTextA(hEditCaveSize, szBuf, 16);
    int minSize = atoi(szBuf); if (minSize < 4) minSize = 32;
    SendMessage(hLstCaves, LB_RESETCONTENT, 0, 0);
    char hdr[128]; sprintf_s(hdr, "Code caves (min %d bytes of 0x00 or 0x90):", minSize);
    SendMessageA(hLstCaves, LB_ADDSTRING, 0, (LPARAM)hdr);
    SYSTEM_INFO si; GetSystemInfo(&si);
    LPVOID addr = si.lpMinimumApplicationAddress;
    int found = 0;
    while (addr < si.lpMaximumApplicationAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_READ|PAGE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            SIZE_T chunkSz = std::min(mbi.RegionSize, (SIZE_T)(1*1024*1024));
            std::vector<BYTE> chunk(chunkSz); SIZE_T r;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, chunk.data(), chunkSz, &r) && r > 0) {
                int runStart = -1, runLen = 0;
                for (int i = 0; i <= (int)r; i++) {
                    bool nullByte = (i < (int)r) && (chunk[i] == 0x00 || chunk[i] == 0x90);
                    if (nullByte) {
                        if (runStart < 0) { runStart = i; runLen = 0; }
                        runLen++;
                    } else {
                        if (runLen >= minSize) {
                            LPVOID ca = (LPVOID)((uintptr_t)mbi.BaseAddress + runStart);
                            const char* prot = (mbi.Protect & PAGE_EXECUTE_READWRITE) ? "RWX" :
                                               (mbi.Protect & PAGE_EXECUTE_READ)      ? "R-X" : "RW-";
                            const char* mtype = (mbi.Type == MEM_IMAGE) ? "IMAGE" : "PRIV";
                            char line[256];
                            sprintf_s(line, "0x%p  size=%-6d  %s  %s", ca, runLen, prot, mtype);
                            SendMessageA(hLstCaves, LB_ADDSTRING, 0, (LPARAM)line);
                            found++;
                        }
                        runStart = -1; runLen = 0;
                    }
                }
            }
        }
        addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }
    char msg[128]; sprintf_s(msg, "Code caves: %d found (min size %d)", found, minSize);
    LogToStatus(msg);
}


void ListRemoteThreads() {
    if (!currentPID) { LogToStatus("No process attached!", true); return; }
    SendMessage(hLstThreads, LB_RESETCONTENT, 0, 0);
    SendMessageA(hLstThreads, LB_ADDSTRING, 0,
        (LPARAM)"TID          | Base Pri | Delta Pri");
    SendMessageA(hLstThreads, LB_ADDSTRING, 0,
        (LPARAM)"-------------+----------+----------");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { LogToStatus("Thread snapshot failed", true); return; }
    THREADENTRY32 te; te.dwSize = sizeof(te);
    int count = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != currentPID) continue;
            char line[256];
            sprintf_s(line, "TID: %-10lu | BasePri: %2d | DeltaPri: %+3d",
                      te.th32ThreadID, te.tpBasePri, te.tpDeltaPri);
            SendMessageA(hLstThreads, LB_ADDSTRING, 0, (LPARAM)line);
            count++;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    char buf[128]; sprintf_s(buf, "Found %d thread(s) in PID %d", count, currentPID);
    LogToStatus(buf);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_CREATE: {
        hBrushWindow = CreateSolidBrush(CLR_BG_WINDOW);
        hBrushEdit   = CreateSolidBrush(CLR_BG_EDIT);
        hBrushList   = CreateSolidBrush(CLR_BG_LIST);
        hBrushStatus = CreateSolidBrush(CLR_BG_STATUS);

        hFontTitle   = CreateFontA(22,0,0,0,FW_BOLD,  0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,"Segoe UI");
        hFontSection = CreateFontA(15,0,0,0,FW_BOLD,  0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,"Segoe UI");
        hFontNormal  = CreateFontA(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,"Segoe UI");
        hFontMono    = CreateFontA(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,FIXED_PITCH, "Consolas");
        hFontSmall   = CreateFontA(12,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,"Segoe UI");

        auto SF = [&](HWND h, HFONT f){ SendMessage(h, WM_SETFONT, (WPARAM)f, TRUE); };

        HWND hTitle = CreateWindowA("STATIC","MEMISCANI :)",
            WS_CHILD|WS_VISIBLE, 10,8,900,30, hWnd,NULL,hInst,NULL);
        SF(hTitle, hFontTitle);

        CreateWindowA("STATIC","PID:", WS_CHILD|WS_VISIBLE, 10,46,30,24, hWnd,NULL,hInst,NULL);
        hEditPID = CreateWindowA("EDIT","", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER,
                                 44,44,85,24, hWnd,NULL,hInst,NULL);
        CreateWindowA("BUTTON","Attach", WS_CHILD|WS_VISIBLE,
                      136,44,75,24, hWnd,(HMENU)ID_BTN_ATTACH,hInst,NULL);
        CreateWindowA("BUTTON","Browse", WS_CHILD|WS_VISIBLE,
                      216,44,80,24, hWnd,(HMENU)ID_BTN_BROWSE,hInst,NULL);
        CreateWindowA("BUTTON","Refresh Map", WS_CHILD|WS_VISIBLE,
                      302,44,100,24, hWnd,(HMENU)ID_BTN_REFRESH_MAP,hInst,NULL);

        CreateWindowA("STATIC","Find process:", WS_CHILD|WS_VISIBLE,
                      10,76,95,24, hWnd,NULL,hInst,NULL);
        hEditSearchName = CreateWindowA("EDIT","", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                                        110,74,195,24, hWnd,(HMENU)ID_EDIT_SEARCH,hInst,NULL);
        CreateWindowA("BUTTON","Search", WS_CHILD|WS_VISIBLE,
                      312,74,75,24, hWnd,(HMENU)ID_BTN_SEARCH_NAME,hInst,NULL);

        hStaticProcessInfo = CreateWindowA("STATIC","Process: Not attached",
            WS_CHILD|WS_VISIBLE, 10,104,1200,20, hWnd,NULL,hInst,NULL);
        hStaticModuleInfo  = CreateWindowA("STATIC","Module: N/A",
            WS_CHILD|WS_VISIBLE, 10,126,1200,20, hWnd,NULL,hInst,NULL);


        hHdrScan = CreateWindowA("STATIC","MEMORY SCANNING",
            WS_CHILD|WS_VISIBLE, 10,151,240,22, hWnd,NULL,hInst,NULL);
        SF(hHdrScan, hFontSection);

        CreateWindowA("STATIC","Value:", WS_CHILD|WS_VISIBLE, 10,178,43,24, hWnd,NULL,hInst,NULL);
        hEditScanValue = CreateWindowA("EDIT","", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                                       56,176,80,24, hWnd,NULL,hInst,NULL);
        CreateWindowA("STATIC","Type:", WS_CHILD|WS_VISIBLE, 141,178,36,24, hWnd,NULL,hInst,NULL);
        hCmbDataType = CreateWindowA("COMBOBOX","",
            WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL,
            179,176,82,200, hWnd,(HMENU)ID_CMB_DATA_TYPE,hInst,NULL);
        const char* dtItems[] = {"int32","int16","int8","int64","float","double","String","AOB"};
        for (auto s : dtItems) SendMessageA(hCmbDataType, CB_ADDSTRING, 0, (LPARAM)s);
        SendMessage(hCmbDataType, CB_SETCURSEL, 0, 0);
        CreateWindowA("STATIC","Match:", WS_CHILD|WS_VISIBLE, 266,178,44,24, hWnd,NULL,hInst,NULL);
        hCmbScanType = CreateWindowA("COMBOBOX","",
            WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL,
            313,176,132,200, hWnd,(HMENU)ID_CMB_SCAN_TYPE,hInst,NULL);
        const char* scItems[] = {"Exact Value","Changed","Unchanged","Increased","Decreased","Unknown Initial"};
        for (auto s : scItems) SendMessageA(hCmbScanType, CB_ADDSTRING, 0, (LPARAM)s);
        SendMessage(hCmbScanType, CB_SETCURSEL, 0, 0);
        hBtnFirstScan = CreateWindowA("BUTTON","First Scan", WS_CHILD|WS_VISIBLE,
                                      450,176,92,24, hWnd,(HMENU)ID_BTN_FIRST_SCAN,hInst,NULL);
        hBtnNextScan  = CreateWindowA("BUTTON","Next Scan",  WS_CHILD|WS_VISIBLE,
                                      547,176,90,24, hWnd,(HMENU)ID_BTN_NEXT_SCAN,hInst,NULL);

        CreateWindowA("STATIC","Tracked Offset:", WS_CHILD|WS_VISIBLE,
                      10,208,112,24, hWnd,NULL,hInst,NULL);
        hEditTrackedOffset = CreateWindowA("EDIT","", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                                           127,206,168,24, hWnd,(HMENU)ID_EDIT_OFFSET,hInst,NULL);
        hBtnSetOffset  = CreateWindowA("BUTTON","Set Offset", WS_CHILD|WS_VISIBLE,
                                       302,206,90,24, hWnd,(HMENU)ID_BTN_SET_OFFSET,hInst,NULL);
        hBtnGotoOffset = CreateWindowA("BUTTON","Jump to Offset", WS_CHILD|WS_VISIBLE,
                                       398,206,120,24, hWnd,(HMENU)ID_BTN_GOTO_OFFSET,hInst,NULL);

        hStaticOffsetInfo = CreateWindowA("STATIC",
            "No offset tracked.  Select a scan result then click Set Offset.",
            WS_CHILD|WS_VISIBLE, 10,235,635,20, hWnd,NULL,hInst,NULL);

        CreateWindowA("STATIC","Found Addresses:", WS_CHILD|WS_VISIBLE,
                      10,260,148,20, hWnd,NULL,hInst,NULL);
        hStaticScanCount = CreateWindowA("STATIC","Found: 0",
            WS_CHILD|WS_VISIBLE, 162,260,80,20, hWnd,NULL,hInst,NULL);
        CreateWindowA("BUTTON","Export", WS_CHILD|WS_VISIBLE,
                      248,257,65,22, hWnd,(HMENU)ID_BTN_EXPORT,hInst,NULL);
        CreateWindowA("BUTTON","Clear",  WS_CHILD|WS_VISIBLE,
                      317,257,55,22, hWnd,(HMENU)ID_BTN_CLEAR_SCAN,hInst,NULL);
        CreateWindowA("BUTTON","Ptr Scan", WS_CHILD|WS_VISIBLE,
                      377,257,75,22, hWnd,(HMENU)ID_BTN_PTR_SCAN,hInst,NULL);
        hBtnSendToBuilder = CreateWindowA("BUTTON","-> SC Builder", WS_CHILD|WS_VISIBLE,
                      457,257,110,22, hWnd,(HMENU)ID_BTN_SEND_TO_BUILDER,hInst,NULL);

        hScanResultsWnd = CreateWindowA("LISTBOX","",
            WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|WS_HSCROLL|LBS_NOTIFY,
            10,283,635,570, hWnd,(HMENU)ID_LST_RESULTS,hInst,NULL);
        SendMessage(hScanResultsWnd, WM_SETFONT, (WPARAM)hFontMono, TRUE);
        SendMessage(hScanResultsWnd, LB_SETHORIZONTALEXTENT, 950, 0);

        hStaticAddressInfo = CreateWindowA("STATIC","Selected: None",
            WS_CHILD|WS_VISIBLE, 10,858,635,20, hWnd,NULL,hInst,NULL);

        hHdrMap = CreateWindowA("STATIC","MEMORY MAP",
            WS_CHILD|WS_VISIBLE, 655,151,250,22, hWnd,NULL,hInst,NULL);
        SF(hHdrMap, hFontSection);

        hMemoryMapWnd = CreateWindowA("LISTBOX","",
            WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|WS_HSCROLL|LBS_NOTIFY,
            655,176,490,390, hWnd,(HMENU)ID_LST_MEMMAP,hInst,NULL);
        SendMessage(hMemoryMapWnd, WM_SETFONT, (WPARAM)hFontMono, TRUE);
        SendMessage(hMemoryMapWnd, LB_SETHORIZONTALEXTENT, 950, 0);

        hHdrHex = CreateWindowA("STATIC","HEX VIEWER",
            WS_CHILD|WS_VISIBLE, 655,574,250,22, hWnd,NULL,hInst,NULL);
        SF(hHdrHex, hFontSection);

        CreateWindowA("STATIC","Address:", WS_CHILD|WS_VISIBLE,
                      655,600,62,24, hWnd,NULL,hInst,NULL);
        hEditHexAddress = CreateWindowA("EDIT","0x0", WS_CHILD|WS_VISIBLE|WS_BORDER,
                                        720,598,200,24, hWnd,NULL,hInst,NULL);
        hBtnRefreshHex  = CreateWindowA("BUTTON","Go", WS_CHILD|WS_VISIBLE,
                                        924,598,60,24, hWnd,(HMENU)ID_BTN_REFRESH_HEX,hInst,NULL);

        hHexViewWnd = CreateWindowA("LISTBOX","",
            WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|WS_HSCROLL,
            655,628,490,248, hWnd,(HMENU)ID_LST_HEX,hInst,NULL);
        SendMessage(hHexViewWnd, WM_SETFONT, (WPARAM)hFontMono, TRUE);
        SendMessage(hHexViewWnd, LB_SETHORIZONTALEXTENT, 850, 0);

        hHdrMods = CreateWindowA("STATIC","LOADED MODULES",
            WS_CHILD|WS_VISIBLE, 1155,151,220,22, hWnd,NULL,hInst,NULL);
        SF(hHdrMods, hFontSection);
        CreateWindowA("BUTTON","Refresh", WS_CHILD|WS_VISIBLE,
                      1450,149,75,22, hWnd,(HMENU)ID_BTN_REFRESH_MODS,hInst,NULL);

        hLstModules = CreateWindowA("LISTBOX","",
            WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|WS_HSCROLL,
            1155,176,370,178, hWnd,(HMENU)ID_LST_MODULES,hInst,NULL);
        SendMessage(hLstModules, WM_SETFONT, (WPARAM)hFontMono, TRUE);
        SendMessage(hLstModules, LB_SETHORIZONTALEXTENT, 800, 0);

        hHdrWatch = CreateWindowA("STATIC","WATCH LIST (live, 1s refresh)",
            WS_CHILD|WS_VISIBLE, 1155,362,210,22, hWnd,NULL,hInst,NULL);
        SF(hHdrWatch, hFontSection);
        CreateWindowA("BUTTON","Add",    WS_CHILD|WS_VISIBLE,
                      1340,360,50,22, hWnd,(HMENU)ID_BTN_ADD_WATCH,hInst,NULL);
        CreateWindowA("BUTTON","Remove", WS_CHILD|WS_VISIBLE,
                      1394,360,58,22, hWnd,(HMENU)ID_BTN_REM_WATCH,hInst,NULL);
        CreateWindowA("BUTTON","Clear",  WS_CHILD|WS_VISIBLE,
                      1456,360,50,22, hWnd,(HMENU)ID_BTN_CLEAR_WATCH,hInst,NULL);

        hLstWatchList = CreateWindowA("LISTBOX","",
            WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|WS_HSCROLL|LBS_NOTIFY,
            1155,387,370,490, hWnd,(HMENU)ID_LST_WATCH,hInst,NULL);
        SendMessage(hLstWatchList, WM_SETFONT, (WPARAM)hFontMono, TRUE);
        SendMessage(hLstWatchList, LB_SETHORIZONTALEXTENT, 650, 0);

        hHdrInject = CreateWindowA("STATIC","CODE INJECTION",
            WS_CHILD|WS_VISIBLE, 1535,151,260,22, hWnd,NULL,hInst,NULL);
        SF(hHdrInject, hFontSection);

        hHdrDllInject = CreateWindowA("STATIC","DLL Injection",
            WS_CHILD|WS_VISIBLE, 1535,176,200,20, hWnd,NULL,hInst,NULL);
        hEditDllPath = CreateWindowA("EDIT","", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                                     1535,200,265,24, hWnd,(HMENU)ID_EDIT_DLL_PATH,hInst,NULL);
        hBtnBrowseDll = CreateWindowA("BUTTON","Browse", WS_CHILD|WS_VISIBLE,
                                      1805,200,65,24, hWnd,(HMENU)ID_BTN_BROWSE_DLL,hInst,NULL);
        hBtnInjectDll = CreateWindowA("BUTTON","Inject DLL", WS_CHILD|WS_VISIBLE,
                                      1535,229,115,24, hWnd,(HMENU)ID_BTN_INJECT_DLL,hInst,NULL);
        hBtnEjectDll  = CreateWindowA("BUTTON","Eject Module", WS_CHILD|WS_VISIBLE,
                                      1655,229,120,24, hWnd,(HMENU)ID_BTN_EJECT_DLL,hInst,NULL);
        CreateWindowA("STATIC","(select in modules list)",
            WS_CHILD|WS_VISIBLE, 1782,232,160,18, hWnd,NULL,hInst,NULL);

        hHdrShellcode = CreateWindowA("STATIC","Shellcode Injection",
            WS_CHILD|WS_VISIBLE, 1535,262,220,20, hWnd,NULL,hInst,NULL);
        CreateWindowA("STATIC","Hex bytes (e.g. 90 90 C3):",
            WS_CHILD|WS_VISIBLE, 1535,285,195,18, hWnd,NULL,hInst,NULL);
        hEditShellcode = CreateWindowA("EDIT","", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                                       1535,306,375,24, hWnd,(HMENU)ID_EDIT_SHELLCODE,hInst,NULL);
        CreateWindowA("STATIC","Prot:", WS_CHILD|WS_VISIBLE,
                      1535,336,35,22, hWnd,NULL,hInst,NULL);
        hCmbMemProt = CreateWindowA("COMBOBOX","",
            WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL,
            1573,334,100,120, hWnd,(HMENU)ID_CMB_MEM_PROT,hInst,NULL);
        SendMessageA(hCmbMemProt, CB_ADDSTRING, 0, (LPARAM)"RWX (exec+write)");
        SendMessageA(hCmbMemProt, CB_ADDSTRING, 0, (LPARAM)"RX  (exec only)");
        SendMessage(hCmbMemProt, CB_SETCURSEL, 0, 0);
        hBtnLoadScFile = CreateWindowA("BUTTON","Load File", WS_CHILD|WS_VISIBLE,
                                       1678,334,80,24, hWnd,(HMENU)ID_BTN_LOAD_SC_FILE,hInst,NULL);
        hBtnInjectCode = CreateWindowA("BUTTON","Alloc + Execute", WS_CHILD|WS_VISIBLE,
                                       1762,334,148,24, hWnd,(HMENU)ID_BTN_INJECT_CODE,hInst,NULL);

        hHdrBuilder = CreateWindowA("STATIC","Shellcode Builder",
            WS_CHILD|WS_VISIBLE, 1535,368,220,20, hWnd,NULL,hInst,NULL);
        SF(hHdrBuilder, hFontNormal);
        hBtnAssembler = CreateWindowA("BUTTON","Assembler...", WS_CHILD|WS_VISIBLE,
            1762,366,148,22, hWnd,(HMENU)ID_BTN_ASSEMBLER,hInst,NULL);
        SF(hBtnAssembler, hFontNormal);

        CreateWindowA("STATIC","Arch:", WS_CHILD|WS_VISIBLE,
                      1535,392,38,22, hWnd,NULL,hInst,NULL);
        hCmbArch = CreateWindowA("COMBOBOX","",
            WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL,
            1576,390,58,80, hWnd,(HMENU)ID_CMB_ARCH,hInst,NULL);
        SendMessageA(hCmbArch, CB_ADDSTRING, 0, (LPARAM)"x64");
        SendMessageA(hCmbArch, CB_ADDSTRING, 0, (LPARAM)"x86");
        SendMessage(hCmbArch, CB_SETCURSEL, 0, 0);
        CreateWindowA("STATIC","Op:", WS_CHILD|WS_VISIBLE,
                      1640,392,28,22, hWnd,NULL,hInst,NULL);
        hCmbScOp = CreateWindowA("COMBOBOX","",
            WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL,
            1671,390,115,150, hWnd,(HMENU)ID_CMB_SC_OP,hInst,NULL);
        { const char* ops[]={"Set value","Add value","Subtract","Zero out","NOP sled"};
          for (auto s:ops) SendMessageA(hCmbScOp,CB_ADDSTRING,0,(LPARAM)s);
          SendMessage(hCmbScOp,CB_SETCURSEL,0,0); }

        CreateWindowA("STATIC","Addr:", WS_CHILD|WS_VISIBLE,
                      1535,420,38,22, hWnd,NULL,hInst,NULL);
        hEditScAddr = CreateWindowA("EDIT","0x0", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                                    1576,418,180,24, hWnd,(HMENU)ID_EDIT_SC_ADDR,hInst,NULL);
        CreateWindowA("STATIC","Val:", WS_CHILD|WS_VISIBLE,
                      1762,420,30,22, hWnd,NULL,hInst,NULL);
        hEditScVal = CreateWindowA("EDIT","0", WS_CHILD|WS_VISIBLE|WS_BORDER,
                                   1795,418,65,24, hWnd,(HMENU)ID_EDIT_SC_VAL,hInst,NULL);

        hBtnBuildSc = CreateWindowA("BUTTON","Build", WS_CHILD|WS_VISIBLE,
                                    1535,448,60,24, hWnd,(HMENU)ID_BTN_BUILD_SC,hInst,NULL);
        hEditScResult = CreateWindowA("EDIT","", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|ES_READONLY,
                                      1600,448,210,24, hWnd,(HMENU)ID_EDIT_SC_RESULT,hInst,NULL);
        hBtnCopySc = CreateWindowA("BUTTON","Send to SC", WS_CHILD|WS_VISIBLE,
                                   1815,448,95,24, hWnd,(HMENU)ID_BTN_COPY_SC,hInst,NULL);

        hHdrCaves = CreateWindowA("STATIC","Code Cave Scanner",
            WS_CHILD|WS_VISIBLE, 1535,482,220,20, hWnd,NULL,hInst,NULL);
        CreateWindowA("STATIC","Min bytes:", WS_CHILD|WS_VISIBLE,
                      1535,505,72,22, hWnd,NULL,hInst,NULL);
        hEditCaveSize = CreateWindowA("EDIT","32", WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER,
                                      1611,503,50,24, hWnd,(HMENU)ID_EDIT_CAVE_SIZE,hInst,NULL);
        hBtnScanCaves = CreateWindowA("BUTTON","Scan Caves", WS_CHILD|WS_VISIBLE,
                                      1666,503,110,24, hWnd,(HMENU)ID_BTN_SCAN_CAVES,hInst,NULL);
        hLstCaves = CreateWindowA("LISTBOX","",
            WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|WS_HSCROLL|LBS_NOTIFY,
            1535,532,375,168, hWnd,(HMENU)ID_LST_CAVES,hInst,NULL);
        SendMessage(hLstCaves, WM_SETFONT, (WPARAM)hFontMono, TRUE);
        SendMessage(hLstCaves, LB_SETHORIZONTALEXTENT, 700, 0);

        hHdrThreads = CreateWindowA("STATIC","Remote Threads",
            WS_CHILD|WS_VISIBLE, 1535,708,220,20, hWnd,NULL,hInst,NULL);
        hBtnListThreads = CreateWindowA("BUTTON","List Threads", WS_CHILD|WS_VISIBLE,
                                        1755,706,110,24, hWnd,(HMENU)ID_BTN_LIST_THREADS,hInst,NULL);
        hLstThreads = CreateWindowA("LISTBOX","",
            WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|WS_HSCROLL,
            1535,733,375,230, hWnd,(HMENU)ID_LST_THREADS,hInst,NULL);
        SendMessage(hLstThreads, WM_SETFONT, (WPARAM)hFontMono, TRUE);
        SendMessage(hLstThreads, LB_SETHORIZONTALEXTENT, 600, 0);

        SF(hHdrInject,    hFontSection);
        SF(hHdrDllInject, hFontNormal);
        SF(hHdrShellcode, hFontNormal);
        SF(hHdrBuilder,   hFontNormal);
        SF(hHdrCaves,     hFontNormal);
        SF(hHdrThreads,   hFontNormal);
        SF(hEditDllPath,  hFontMono);
        SF(hEditShellcode,hFontMono);
        SF(hEditScAddr,   hFontMono);
        SF(hEditScResult, hFontMono);
        SF(hCmbMemProt,   hFontNormal);
        SF(hCmbArch,      hFontNormal);
        SF(hCmbScOp,      hFontNormal);
        SF(hEditCaveSize, hFontNormal);
        SF(hEditScVal,    hFontNormal);


        hHdrWrite = CreateWindowA("STATIC","VALUE MODIFICATION",
            WS_CHILD|WS_VISIBLE, 10,883,220,22, hWnd,NULL,hInst,NULL);
        SF(hHdrWrite, hFontSection);

        CreateWindowA("STATIC","New value:", WS_CHILD|WS_VISIBLE,
                      10,908,72,24, hWnd,NULL,hInst,NULL);
        hEditNewValue = CreateWindowA("EDIT","", WS_CHILD|WS_VISIBLE|WS_BORDER,
                                      86,906,100,24, hWnd,NULL,hInst,NULL);
        CreateWindowA("BUTTON","Read",  WS_CHILD|WS_VISIBLE,
                      191,906,50,24, hWnd,(HMENU)ID_BTN_READ_VAL,hInst,NULL);
        hBtnWrite = CreateWindowA("BUTTON","Write", WS_CHILD|WS_VISIBLE,
                                  246,906,68,24, hWnd,(HMENU)ID_BTN_WRITE,hInst,NULL);
        hBtnUndo  = CreateWindowA("BUTTON","Undo",  WS_CHILD|WS_VISIBLE,
                                  319,906,68,24, hWnd,(HMENU)ID_BTN_UNDO,hInst,NULL);
        hBtnFreeze = CreateWindowA("BUTTON","Freeze", WS_CHILD|WS_VISIBLE,
                                   393,906,75,24, hWnd,(HMENU)ID_BTN_FREEZE,hInst,NULL);

        hStatusWnd = CreateWindowA("STATIC",
            "Ready - browse or type a PID and click Attach.  Run as Administrator for full access.",
            WS_CHILD|WS_VISIBLE|SS_SUNKEN,
            0,942,1920,24, hWnd,NULL,hInst,NULL);
        SendMessage(hStatusWnd, WM_SETFONT, (WPARAM)hFontSmall, TRUE);

        SF(hStaticProcessInfo, hFontNormal);
        SF(hStaticModuleInfo,  hFontNormal);
        SF(hStaticAddressInfo, hFontSmall);
        SF(hStaticOffsetInfo,  hFontSmall);
        SF(hStaticScanCount,   hFontSmall);
        SF(hEditPID,           hFontNormal);
        SF(hEditScanValue,     hFontNormal);
        SF(hEditSearchName,    hFontNormal);
        SF(hEditHexAddress,    hFontMono);
        SF(hEditTrackedOffset, hFontMono);
        SF(hEditNewValue,      hFontNormal);
        SF(hCmbDataType,       hFontNormal);
        SF(hCmbScanType,       hFontNormal);

        EnableWindow(hBtnFirstScan,  FALSE);
        EnableWindow(hBtnNextScan,   FALSE);
        EnableWindow(hBtnWrite,      FALSE);
        EnableWindow(hBtnUndo,       FALSE);
        EnableWindow(hBtnRefreshHex, FALSE);
        EnableWindow(hBtnGotoOffset, FALSE);
        EnableWindow(hBtnFreeze,     FALSE);
        EnableWindow(hBtnExport,     FALSE);
        break;
    }

    case WM_TIMER:
        if (wParam == TIMER_FREEZE && selectedAddress && freezeActive && hProcess) {
            BYTE fb[4]; *(int*)fb = freezeValue;
            WriteProcessMemory(hProcess, selectedAddress, fb, 4, NULL);
        } else if (wParam == TIMER_WATCH) {
            RefreshWatchList();
        }
        break;

    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wParam; RECT rc; GetClientRect(hWnd, &rc);
        FillRect(hdc, &rc, hBrushWindow);
        return 1;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam; HWND hCtrl = (HWND)lParam;
        if (hCtrl == hStatusWnd) {
            SetBkColor(hdc, CLR_BG_STATUS); SetTextColor(hdc, CLR_TEXT_STAT);
            return (LRESULT)hBrushStatus;
        }
        SetBkMode(hdc, TRANSPARENT);
        if (hCtrl==hHdrScan||hCtrl==hHdrMap||hCtrl==hHdrHex||
            hCtrl==hHdrWrite||hCtrl==hHdrMods||hCtrl==hHdrWatch||hCtrl==hHdrInject)
            SetTextColor(hdc, CLR_TEXT_HDR);
        else if (hCtrl == hStaticOffsetInfo)
            SetTextColor(hdc, CLR_TEXT_INFO);
        else if (hCtrl == hStaticScanCount)
            SetTextColor(hdc, CLR_TEXT_INFO);
        else
            SetTextColor(hdc, CLR_TEXT_NORM);
        return (LRESULT)hBrushWindow;
    }

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, CLR_BG_EDIT); SetTextColor(hdc, CLR_TEXT_EDIT);
        return (LRESULT)hBrushEdit;
    }

    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, CLR_BG_LIST); SetTextColor(hdc, CLR_TEXT_LIST);
        return (LRESULT)hBrushList;
    }

    case WM_SIZE: {
        int w = LOWORD(lParam), h = HIWORD(lParam);
        SetWindowPos(hStatusWnd, NULL, 0, h-24, w, 24, SWP_NOZORDER);
        break;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {

        case ID_BTN_BROWSE: ShowProcessListDialog(); break;

        case ID_BTN_SEARCH_NAME: {
            char buf[256]; GetWindowTextA(hEditSearchName, buf, 256);
            SendMessage(hScanResultsWnd, LB_RESETCONTENT, 0, 0);
            scanResults.clear(); scanPrevVals.clear();
            for (auto& p : SearchProcessesByName(buf)) {
                char entry[256]; sprintf_s(entry, "PID: %-8d | %s", p.first, p.second.c_str());
                SendMessageA(hScanResultsWnd, LB_ADDSTRING, 0, (LPARAM)entry);
            }
            int cnt = (int)SendMessage(hScanResultsWnd, LB_GETCOUNT, 0, 0);
            if (cnt > 0) {
                char first[256]; SendMessageA(hScanResultsWnd, LB_GETTEXT, 0, (LPARAM)first);
                const char* p = first + 5; while (*p == ' ') p++;
                SetWindowTextA(hEditPID, std::to_string((DWORD)atoi(p)).c_str());
            }
            LogToStatus("Name search complete - select a row or type PID and click Attach");
            break;
        }

        case ID_BTN_ATTACH: {
            char buf[32]; GetWindowTextA(hEditPID, buf, 32);
            DWORD pid = (DWORD)atoi(buf);
            if (pid == 0) { LogToStatus("Enter a valid PID", true); break; }
            if (AttachToProcess(pid)) {
                EnableWindow(hBtnFirstScan,  TRUE);
                EnableWindow(hBtnNextScan,   TRUE);
                EnableWindow(hBtnRefreshHex, TRUE);
                EnableWindow(hBtnGotoOffset, TRUE);
                EnableWindow(hBtnFreeze,     TRUE);
                EnableWindow(hBtnExport,     TRUE);
            }
            break;
        }

        case ID_BTN_FIRST_SCAN: DoFirstScan(); break;
        case ID_BTN_NEXT_SCAN:  DoNextScan();  break;

        case ID_BTN_CLEAR_SCAN:
            SendMessage(hScanResultsWnd, LB_RESETCONTENT, 0, 0);
            scanResults.clear(); scanPrevVals.clear();
            UpdateScanCount();
            SetWindowTextA(hStaticAddressInfo, "Selected: None");
            selectedAddress = NULL;
            LogToStatus("Scan results cleared");
            break;

        case ID_BTN_EXPORT: ExportScanResults(); break;

        case ID_BTN_PTR_SCAN:
            if (selectedAddress) ScanForPointers(selectedAddress);
            else LogToStatus("Select an address first, then click Ptr Scan", true);
            break;

        case ID_BTN_SET_OFFSET: {
            char buf[64]; GetWindowTextA(hEditTrackedOffset, buf, 64);
            if (buf[0] != '\0') {
                trackedOffset = (LONGLONG)strtoull(buf, NULL, 0);
                hasTrackedOffset = true;
                UpdateOffsetInfo();
                LogToStatus("Offset tracked - use Jump to Offset to read value");
            } else if (selectedAddress && hProcess) {
                LPVOID base = GetBaseAddress();
                if (base) {
                    trackedOffset = (LONGLONG)(uintptr_t)selectedAddress - (LONGLONG)(uintptr_t)base;
                    hasTrackedOffset = true;
                    char s[32]; sprintf_s(s, "0x%llX", trackedOffset);
                    SetWindowTextA(hEditTrackedOffset, s);
                    UpdateOffsetInfo();
                    LogToStatus("Offset locked from selected address");
                }
            } else { LogToStatus("Select an address or type an offset value first", true); }
            break;
        }

        case ID_BTN_GOTO_OFFSET: {
            if (!hasTrackedOffset) { LogToStatus("No offset tracked yet", true); break; }
            LPVOID base = GetBaseAddress();
            if (!base) { LogToStatus("Cannot resolve base address", true); break; }
            LPVOID resolved = (LPVOID)((uintptr_t)base + (uintptr_t)trackedOffset);
            ShowHexAtAddress(resolved, resolved);
            UpdateOffsetInfo();
            break;
        }

        case ID_LST_RESULTS: {
            if (HIWORD(wParam) != LBN_SELCHANGE && HIWORD(wParam) != LBN_DBLCLK) break;
            int idx = (int)SendMessage(hScanResultsWnd, LB_GETCURSEL, 0, 0);
            if (idx == LB_ERR || idx >= (int)scanResults.size()) break;
            selectedAddress = scanResults[idx];
            int curVal = ReadValueFromAddress(selectedAddress);
            SetWindowTextA(hEditNewValue, std::to_string(curVal).c_str());
            LPVOID base = GetBaseAddress();
            LONGLONG off = base ? ((LONGLONG)(uintptr_t)selectedAddress-(LONGLONG)(uintptr_t)base) : 0;
            char info[512];
            sprintf_s(info, "Selected: 0x%p  |  Offset: +0x%llX  |  int32 value: %d",
                      selectedAddress, off, curVal);
            SetWindowTextA(hStaticAddressInfo, info);
            char offStr[32]; sprintf_s(offStr, "0x%llX", off);
            SetWindowTextA(hEditTrackedOffset, offStr);
            char addrHex[32]; sprintf_s(addrHex, "0x%llX", (uintptr_t)selectedAddress);
            SetWindowTextA(hEditScAddr, addrHex);
            EnableWindow(hBtnWrite, TRUE); EnableWindow(hBtnUndo, TRUE);
            ShowHexAtAddress(selectedAddress, selectedAddress);
            break;
        }

        case ID_LST_MEMMAP: {
            if (HIWORD(wParam) != LBN_SELCHANGE && HIWORD(wParam) != LBN_DBLCLK) break;
            int idx = (int)SendMessage(hMemoryMapWnd, LB_GETCURSEL, 0, 0);
            if (idx < 2) break;
            char line[512]; line[0] = 0;
            SendMessageA(hMemoryMapWnd, LB_GETTEXT, idx, (LPARAM)line);
            if (line[0] != '0' || line[1] != 'x') break;
            uintptr_t regionAddr = (uintptr_t)strtoull(line+2, NULL, 16);
            if (!regionAddr) break;
            LPVOID highlight = nullptr;
            for (LPVOID a : scanResults) {
                uintptr_t fa = (uintptr_t)a;
                if (fa >= regionAddr && fa < regionAddr + 512) { highlight = a; break; }
            }
            ShowHexAtAddress((LPVOID)regionAddr, highlight);
            break;
        }

        case ID_LST_WATCH: {
            if (HIWORD(wParam) != LBN_DBLCLK) break;
            int idx = (int)SendMessage(hLstWatchList, LB_GETCURSEL, 0, 0);
            if (idx != LB_ERR && idx < (int)watchList.size())
                ShowHexAtAddress(watchList[idx], watchList[idx]);
            break;
        }

        case ID_BTN_ADD_WATCH:
            if (selectedAddress) {
                for (LPVOID a : watchList) if (a == selectedAddress) goto alreadyInWatch;
                watchList.push_back(selectedAddress);
                RefreshWatchList();
                LogToStatus("Address added to watch list");
                alreadyInWatch:;
            } else { LogToStatus("Select an address first", true); }
            break;

        case ID_BTN_REM_WATCH: {
            int idx = (int)SendMessage(hLstWatchList, LB_GETCURSEL, 0, 0);
            if (idx != LB_ERR && idx < (int)watchList.size()) {
                watchList.erase(watchList.begin() + idx);
                RefreshWatchList();
            }
            break;
        }

        case ID_BTN_CLEAR_WATCH:
            watchList.clear();
            SendMessage(hLstWatchList, LB_RESETCONTENT, 0, 0);
            LogToStatus("Watch list cleared");
            break;

        case ID_BTN_REFRESH_MODS:
            PopulateModuleList();
            LogToStatus("Module list refreshed");
            break;

        case ID_BTN_READ_VAL:
            if (selectedAddress) {
                int v = ReadValueFromAddress(selectedAddress);
                SetWindowTextA(hEditNewValue, std::to_string(v).c_str());
                char buf[128]; sprintf_s(buf, "Read 0x%p = %d", selectedAddress, v);
                LogToStatus(buf);
            } else { LogToStatus("Select an address first", true); }
            break;

        case ID_BTN_REFRESH_HEX: {
            char buf[64]; GetWindowTextA(hEditHexAddress, buf, 64);
            LPVOID addr = (LPVOID)(uintptr_t)strtoull(buf, NULL, 0);
            ShowHexAtAddress(addr, selectedAddress);
            break;
        }

        case ID_BTN_REFRESH_MAP: ShowMemoryMap(); break;

        case ID_BTN_WRITE:
            if (selectedAddress) {
                char buf[32]; GetWindowTextA(hEditNewValue, buf, 32);
                int v = atoi(buf);
                if (freezeActive) freezeValue = v;
                WriteValueToAddress(selectedAddress, v);
                EnableWindow(hBtnUndo, TRUE);
            }
            break;

        case ID_BTN_UNDO:
            if (selectedAddress && backups.count(selectedAddress)) {
                WriteProcessMemory(hProcess, selectedAddress, backups[selectedAddress].data, 4, NULL);
                int v = ReadValueFromAddress(selectedAddress);
                SetWindowTextA(hEditNewValue, std::to_string(v).c_str());
                LogToStatus("Undo successful");
                ShowHexAtAddress(selectedAddress, selectedAddress);
            } else { LogToStatus("No backup available for undo", true); }
            break;

        case ID_BTN_INJECT_DLL:  InjectDLL();  break;
        case ID_BTN_EJECT_DLL:   EjectDLL();   break;
        case ID_BTN_INJECT_CODE: InjectShellcode(); break;
        case ID_BTN_SCAN_CAVES:  ScanCodeCaves(); break;
        case ID_BTN_LIST_THREADS: ListRemoteThreads(); break;

        case ID_BTN_BROWSE_DLL: {
            char path[MAX_PATH] = {};
            OPENFILENAMEA ofn = {}; ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner    = hMainWnd;
            ofn.lpstrFile    = path; ofn.nMaxFile = MAX_PATH;
            ofn.lpstrFilter  = "DLL Files\0*.dll\0All Files\0*.*\0";
            ofn.lpstrDefExt  = "dll";
            ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileNameA(&ofn))
                SetWindowTextA(hEditDllPath, path);
            break;
        }

        case ID_BTN_LOAD_SC_FILE: {
            char path[MAX_PATH] = {};
            OPENFILENAMEA ofn = {}; ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner    = hMainWnd;
            ofn.lpstrFile    = path; ofn.nMaxFile = MAX_PATH;
            ofn.lpstrFilter  = "Binary Files\0*.bin;*.sc;*.raw\0All Files\0*.*\0";
            ofn.Flags        = OFN_FILEMUSTEXIST;
            if (!GetOpenFileNameA(&ofn)) break;
            FILE* f = nullptr; fopen_s(&f, path, "rb");
            if (!f) { LogToStatus("Could not open shellcode file", true); break; }
            fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
            if (sz <= 0 || sz > 4096) { fclose(f); LogToStatus("File too large or empty (max 4096 bytes)", true); break; }
            std::vector<BYTE> raw((size_t)sz);
            fread(raw.data(), 1, sz, f); fclose(f);
            std::string hex;
            for (size_t i = 0; i < raw.size(); i++) {
                char h[4]; sprintf_s(h, "%02X ", raw[i]); hex += h;
            }
            SetWindowTextA(hEditShellcode, hex.c_str());
            char msg[128]; sprintf_s(msg, "Loaded %ld bytes from %s", sz, path);
            LogToStatus(msg);
            break;
        }

        case ID_LST_CAVES: {
            if (HIWORD(wParam) != LBN_SELCHANGE && HIWORD(wParam) != LBN_DBLCLK) break;
            int idx = (int)SendMessage(hLstCaves, LB_GETCURSEL, 0, 0);
            if (idx < 1) break;
            char line[256] = {}; SendMessageA(hLstCaves, LB_GETTEXT, idx, (LPARAM)line);
            if (line[0] != '0' || line[1] != 'x') break;
            uintptr_t ca = (uintptr_t)strtoull(line + 2, nullptr, 16);
            if (ca) ShowHexAtAddress((LPVOID)ca, nullptr);
            break;
        }

        case ID_BTN_ASSEMBLER: ShowAssemblerWindow(); break;

        case ID_BTN_SEND_TO_BUILDER:
            if (selectedAddress) {
                char buf[32]; sprintf_s(buf, "0x%llX", (uintptr_t)selectedAddress);
                SetWindowTextA(hEditScAddr, buf);
                LogToStatus("Address sent to Shellcode Builder - set Op/Val then click Build");
            } else { LogToStatus("Select a scan result first", true); }
            break;

        case ID_BTN_BUILD_SC: BuildShellcode(); break;

        case ID_BTN_COPY_SC: {
            char buf[512] = {};
            GetWindowTextA(hEditScResult, buf, 512);
            SetWindowTextA(hEditShellcode, buf);
            LogToStatus("Shellcode copied to injection field");
            break;
        }

        case ID_BTN_FREEZE:
            if (!selectedAddress) { LogToStatus("Select an address first", true); break; }
            freezeActive = !freezeActive;
            if (freezeActive) {
                char buf[32]; GetWindowTextA(hEditNewValue, buf, 32);
                freezeValue = atoi(buf);
                SetTimer(hWnd, TIMER_FREEZE, 50, NULL);
                SetWindowTextA(hBtnFreeze, "Unfreeze");
                char msg[128]; sprintf_s(msg, "Freezing 0x%p at value %d (50ms interval)", selectedAddress, freezeValue);
                LogToStatus(msg);
            } else {
                KillTimer(hWnd, TIMER_FREEZE);
                SetWindowTextA(hBtnFreeze, "Freeze");
                LogToStatus("Freeze disabled");
            }
            break;
        }
        break;

    case WM_DESTROY:
        KillTimer(hWnd, TIMER_FREEZE);
        KillTimer(hWnd, TIMER_WATCH);
        if (hProcess) CloseHandle(hProcess);
        DeleteObject(hFontTitle); DeleteObject(hFontSection);
        DeleteObject(hFontNormal); DeleteObject(hFontMono); DeleteObject(hFontSmall);
        DeleteObject(hBrushWindow); DeleteObject(hBrushEdit);
        DeleteObject(hBrushList); DeleteObject(hBrushStatus);
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    hInst = hInstance;

    if (!IsElevated()) {
        int r = MessageBoxA(NULL,
            "Administrator privileges are required to attach to most processes.\n\n"
            "Relaunch as Administrator now?",
            "Elevation Required", MB_YESNO | MB_ICONWARNING | MB_TOPMOST);
        if (r == IDYES) RelaunchAsAdmin();
    }
    EnableDebugPrivilege();

    INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icex);

    WNDCLASSA wc    = {};
    wc.lpfnWndProc  = WndProc;
    wc.hInstance    = hInstance;
    wc.hbrBackground= NULL;
    wc.lpszClassName= "MemiscaniMain";
    wc.hCursor      = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);

    hMainWnd = CreateWindowA("MemiscaniMain",
        "Memiscani :)",
        WS_OVERLAPPEDWINDOW,
        30,30, 1920,1080,
        NULL,NULL,hInstance,NULL);
    if (!hMainWnd) return 1;

    ShowWindow(hMainWnd, nCmdShow);
    UpdateWindow(hMainWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg); DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
