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

#define ID_LST_WINDOWS        110
#define ID_BTN_REFRESH_WNDS   111
#define ID_EDIT_WND_TEXT      112
#define ID_BTN_SEND_SETTEXT   113
#define ID_BTN_SEND_GETTEXT   114

#define ID_TAB_CTRL          200
#define ID_BTN_WRITE_ALL     201
#define ID_CHK_PROTECT_WR    230
#define ID_BTN_SUSPEND_THR   231
#define ID_BTN_RESUME_THR    232
#define ID_BTN_KILL_THREAD   233
#define ID_BTN_CAVE_INJECT   234

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

#define TIMER_FREEZE        100
#define TIMER_WATCH         101
#define TIMER_HEALTH        102

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
HWND hEditSearchName, hEditTrackedOffset;
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

HWND hTabCtrl, hPageScan, hPageMods, hPageInject, hPageWnd;

HWND hChkProtect;

HWND hWndAssembler = NULL;
HFONT hFontTitle, hFontSection, hFontNormal, hFontMono, hFontSmall;
HBRUSH hBrushWindow, hBrushEdit, hBrushList, hBrushStatus;
static WNDPROC g_origScanEditProc = NULL;
static WNDPROC g_origWndListProc  = NULL;
static HMODULE g_hRichEdit = NULL;
static HWND    g_targetWnd = NULL;  
static BYTE    freezeBytes[16] = {};
static size_t  freezeByteLen   = 0;

HANDLE hProcess   = NULL;
DWORD  currentPID = 0;
LPVOID selectedAddress = NULL;

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
void ScanForPointers(LPVOID targetAddr);
std::string FormatMemorySize(SIZE_T bytes);
LPVOID GetBaseAddress();
int    ReadValueFromAddress(LPVOID address);
void   WriteValueToAddress(LPVOID address, int value);

void CopyEditToClipboard(HWND hEdit);
void AppendEditText(HWND hEdit, const char* line);
void SetEditText(HWND hEdit, const char* text);
void ReadStringAtAddress(LPVOID address);
void WriteStringToAddress(LPVOID address, bool utf16);
void DoAobPatchReplace();
void EnumerateProcessWindows();
bool WriteTypedValue(LPVOID address, const char* str, int dt, bool protect);
void WriteAllScanResults();
void SuspendResumeProcess(bool suspend);
void InjectIntoCodeCave();
void KillSelectedThread();
void UpdateSelectedWindowInfo(HWND target);

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


void WriteStringToAddress(LPVOID address,bool utf16){
    if(!hProcess||!address){LogToStatus("Select an address first",true);return;}
    char txt[512]={};
    GetWindowTextA(hEditStrWrite,txt,512);
    if(!txt[0]){LogToStatus("Enter string text first",true);return;}

    if(!utf16){
       
        SIZE_T len=strlen(txt)+1;
        SIZE_T w;
        if(WriteProcessMemory(hProcess,address,txt,len,&w)){
            char buf[256];sprintf_s(buf,"Wrote UTF-8 string (%zu bytes) to 0x%p",len,address);
            LogToStatus(buf);ShowHexAtAddress(address,address);
        }else LogToStatus("Write failed",true);
    }else{
        
        int needed=MultiByteToWideChar(CP_UTF8,0,txt,-1,NULL,0);
        if(needed<=0){LogToStatus("Conversion failed",true);return;}
        std::vector<wchar_t> wide(needed);
        MultiByteToWideChar(CP_UTF8,0,txt,-1,wide.data(),needed);
        SIZE_T byteLen=(SIZE_T)needed*2;
        SIZE_T w;
        if(WriteProcessMemory(hProcess,address,wide.data(),byteLen,&w)){
            char buf[256];sprintf_s(buf,"Wrote UTF-16LE string (%d wchars, %zu bytes) to 0x%p",needed,(size_t)w,address);
            LogToStatus(buf);ShowHexAtAddress(address,address);
        }else LogToStatus("Write failed",true);
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
        else if(dt==DT_INT64){int64_t v=(int64_t)_atoi64(valueStr);memcpy(targetBuf,&v,8);}
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
        else if(dt==DT_INT64){int64_t v=(int64_t)_atoi64(valueStr);memcpy(targetBuf,&v,8);}
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
    if(!hThread){char buf[128];sprintf_s(buf,"CreateRemoteThread (shellcode) failed: %lu",GetLastError());
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
    std::vector<BYTE> bytes;std::istringstream ss(src);std::string line;int ln=0;
    while(std::getline(ss,line)){ln++;std::string err=AssembleLine(line,bytes);if(!err.empty())return"Line "+std::to_string(ln)+": "+err;}
    if(bytes.empty())return"ERROR: nothing assembled";
    std::string result;
    for(size_t i=0;i<bytes.size();i++){char h[4];sprintf_s(h,"%02X ",bytes[i]);result+=h;}
    if(!result.empty())result.pop_back();return result;
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
            "Example: write UTF-16 filename string to address\r\n"
            "; Use String Writer panel in main window instead for most string tasks\r\n"
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
            selectedAddress=scanResults[i];
            int curVal=ReadValueFromAddress(selectedAddress);
            SetWindowTextA(hEditNewValue,std::to_string(curVal).c_str());
            LPVOID base=GetBaseAddress();
            LONGLONG off=base?((LONGLONG)(uintptr_t)selectedAddress-(LONGLONG)(uintptr_t)base):0;
            char info[512];
            sprintf_s(info,"Selected: 0x%p  |  Offset: +0x%llX  |  int32: %d",selectedAddress,off,curVal);
            SetWindowTextA(hStaticAddressInfo,info);
            char offStr[32];sprintf_s(offStr,"0x%llX",off);
            SetWindowTextA(hEditTrackedOffset,offStr);
            char addrHex[32];sprintf_s(addrHex,"0x%llX",(uintptr_t)selectedAddress);
            SetWindowTextA(hEditScAddr,addrHex);
            EnableWindow(hBtnWrite,TRUE);EnableWindow(hBtnUndo,TRUE);
            ShowHexAtAddress(selectedAddress,selectedAddress);
            return;
        }
    }
    selectedAddress=(LPVOID)fa;
    char info[256];sprintf_s(info,"Selected (manual): 0x%llX",(unsigned long long)fa);
    SetWindowTextA(hStaticAddressInfo,info);
    char addrHex[32];sprintf_s(addrHex,"0x%llX",fa);
    SetWindowTextA(hEditScAddr,addrHex);
    ShowHexAtAddress((LPVOID)fa,(LPVOID)fa);
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

bool WriteTypedValue(LPVOID address, const char* str, int dt, bool protect) {
    if (!hProcess || !address) return false;
    BYTE buf[16] = {};
    size_t sz = 4;
    bool isVar = false;
    std::vector<BYTE> varBytes;
    switch (dt) {
        case DT_INT8:  { int8_t  v=(int8_t)atoi(str);   memcpy(buf,&v,1); sz=1; break; }
        case DT_INT16: { int16_t v=(int16_t)atoi(str);  memcpy(buf,&v,2); sz=2; break; }
        case DT_INT64: { int64_t v=(int64_t)_atoi64(str);memcpy(buf,&v,8);sz=8; break; }
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
    if (protect) VirtualProtectEx(hProcess,address,sz,PAGE_EXECUTE_READWRITE,&oldProt);
    SIZE_T w; bool ok = WriteProcessMemory(hProcess,address,data,sz,&w) && w==sz;
    if (protect && oldProt) VirtualProtectEx(hProcess,address,sz,oldProt,&oldProt);
    return ok;
}

void WriteAllScanResults() {
    if (!hProcess||scanResults.empty()){LogToStatus("No scan results to write to",true);return;}
    int dt=(int)SendMessage(hCmbDataType,CB_GETCURSEL,0,0);
    char valStr[512]={};GetWindowTextA(hEditNewValue,valStr,512);
    bool prot=(SendMessage(hChkProtect,BM_GETCHECK,0,0)==BST_CHECKED);
    int ok=0,fail=0;
    for (LPVOID addr:scanResults){if(WriteTypedValue(addr,valStr,dt,prot))ok++;else fail++;}
    char msg[128];sprintf_s(msg,"Bulk write: %d OK, %d failed (of %zu)",ok,fail,scanResults.size());
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
         ti.pszText=(LPSTR)"Cde Inj"; TabCtrl_InsertItem(hTabCtrl,2,&ti);
         ti.pszText=(LPSTR)"Window Writer";  TabCtrl_InsertItem(hTabCtrl,3,&ti);}
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

        hHdrScan=B(hPageScan,"STATIC","MEMORY SCANNING",0,5,5,220,18,0,hFontSection);

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
        B(hPageScan,"STATIC","Value:",0,1242,348,44,22,0);
        hEditNewValue=B(hPageScan,"EDIT","",WS_BORDER,1289,346,200,24,0,hFontMono);
        B(hPageScan,"BUTTON","Read",    0,1494,346,50,24,ID_BTN_READ_VAL);
        hBtnWrite =B(hPageScan,"BUTTON","Write",   0,1548,346,58,24,ID_BTN_WRITE);
        B(hPageScan,"BUTTON","Write All",0,1610,346,70,24,ID_BTN_WRITE_ALL);
        hBtnUndo  =B(hPageScan,"BUTTON","Undo",   0,1684,346,50,24,ID_BTN_UNDO);
        hBtnFreeze=B(hPageScan,"BUTTON","Freeze", 0,1738,346,64,24,ID_BTN_FREEZE);
        B(hPageScan,"STATIC","(Write All: write to every scan result at once)",0,1242,374,560,16,0,hFontSmall);

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
        
        hHdrDllInject=B(hPageMods,"STATIC","DLL INJ",0,5,656,200,18,0,hFontSection);
        B(hPageMods,"STATIC","DLL path:",0,5,682,65,22,0);
        hEditDllPath=B(hPageMods,"EDIT","",WS_BORDER|ES_AUTOHSCROLL,73,680,700,24,ID_EDIT_DLL_PATH,hFontMono);
        hBtnBrowseDll=B(hPageMods,"BUTTON","Browse...",0,778,680,80,24,ID_BTN_BROWSE_DLL);
        hBtnInjectDll=B(hPageMods,"BUTTON","Inject DLL (LoadLibraryA)",0,865,680,190,24,ID_BTN_INJECT_DLL);
        hBtnEjectDll =B(hPageMods,"BUTTON","Eject (FreeLibrary)",0,1060,680,160,24,ID_BTN_EJECT_DLL);
        B(hPageMods,"STATIC","  <- click module line first to eject",0,1225,682,380,20,0,hFontSmall);

        
        hHdrInject=B(hPageInject,"STATIC","SHCODE INJ",0,5,5,300,18,0,hFontSection);
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
        hLstThreads=MakeDE(hPageInject,740,446,1155,430,ID_LST_THREADS);

        
        hHdrWndWriter=B(hPageWnd,"STATIC","WINDOW / CONTROL WRITER",0,5,5,330,18,0,hFontSection);
        B(hPageWnd,"BUTTON","Refresh Windows",0,1680,3,160,22,ID_BTN_REFRESH_WNDS);
        
        hStaticSelWnd=B(hPageWnd,"STATIC","Selected: None  (click a line in the list below)",0,5,28,1880,18,0,hFontSmall);
        
        hLstWindows=MakeDE(hPageWnd,5,50,1205,560,ID_LST_WINDOWS);
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
        if(wParam==TIMER_FREEZE&&selectedAddress&&freezeActive&&hProcess&&freezeByteLen>0){
            WriteProcessMemory(hProcess,selectedAddress,freezeBytes,freezeByteLen,NULL);
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
           hCtrl==hHdrCaves||hCtrl==hHdrThreads)
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
           hCtrl==hLstWindows){
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
            selectedAddress=NULL;
            LogToStatus("Scan results cleared");
            break;

        case ID_BTN_EXPORT: ExportScanResults(); break;

        case ID_BTN_PTR_SCAN:
            if(selectedAddress)ScanForPointers(selectedAddress);
            else LogToStatus("Select an address first",true);
            break;

        case ID_BTN_COPY_RESULTS: CopyEditToClipboard(hScanResultsWnd); break;
        case ID_BTN_COPY_HEX:     CopyEditToClipboard(hHexViewWnd); break;

        case ID_BTN_COPY_ADDR_CLIP:
            if(selectedAddress){
                char buf[32];sprintf_s(buf,"0x%llX",(uintptr_t)selectedAddress);
                if(OpenClipboard(hMainWnd)){EmptyClipboard();
                    HGLOBAL hm=GlobalAlloc(GMEM_MOVEABLE,strlen(buf)+1);
                    if(hm){memcpy(GlobalLock(hm),buf,strlen(buf)+1);GlobalUnlock(hm);SetClipboardData(CF_TEXT,hm);}
                    CloseClipboard();LogToStatus("Address copied to clipboard");}
            }else LogToStatus("No address selected",true);
            break;

        case ID_LST_RESULTS:{
            if(HIWORD(wParam)!=EN_CHANGE)break;
            break;
        }

        case ID_BTN_SET_OFFSET:{
            char buf[64];GetWindowTextA(hEditTrackedOffset,buf,64);
            if(buf[0]!='\0'){
                trackedOffset=(LONGLONG)strtoull(buf,NULL,0);hasTrackedOffset=true;
                UpdateOffsetInfo();LogToStatus("Offset tracked");
            }else if(selectedAddress&&hProcess){
                LPVOID base=GetBaseAddress();
                if(base){
                    trackedOffset=(LONGLONG)(uintptr_t)selectedAddress-(LONGLONG)(uintptr_t)base;
                    hasTrackedOffset=true;
                    char s[32];sprintf_s(s,"0x%llX",trackedOffset);
                    SetWindowTextA(hEditTrackedOffset,s);
                    UpdateOffsetInfo();LogToStatus("Offset locked from selected address");
                }
            }else LogToStatus("Select an address or type an offset value first",true);
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

        case ID_BTN_ADD_WATCH:
            if(selectedAddress){
                for(LPVOID a:watchList)if(a==selectedAddress)goto alreadyInWatch;
                watchList.push_back(selectedAddress);RefreshWatchList();
                LogToStatus("Address added to watch list");
                alreadyInWatch:;
            }else LogToStatus("Select an address first",true);
            break;

        case ID_BTN_REM_WATCH:{
            for(int i=0;i<(int)watchList.size();i++){
                if(watchList[i]==selectedAddress){
                    watchList.erase(watchList.begin()+i);RefreshWatchList();break;
                }
            }
            break;
        }

        case ID_BTN_CLEAR_WATCH:
            watchList.clear();ClearEditText(hLstWatchList);LogToStatus("Watch list cleared");break;

        case ID_BTN_REFRESH_MODS: PopulateModuleList();LogToStatus("Module list refreshed");break;

        case ID_BTN_READ_VAL:
            if(selectedAddress){
                int dt=(int)SendMessage(hCmbDataType,CB_GETCURSEL,0,0);
                if(dt==DT_STRING){
                    BYTE raw[256]={};SIZE_T r;
                    ReadProcessMemory(hProcess,selectedAddress,raw,255,&r);raw[255]=0;
                    int slen=0;
                    while(slen<(int)r&&raw[slen]>=32&&(unsigned char)raw[slen]<127)slen++;
                    std::string s((char*)raw,slen);
                    SetWindowTextA(hEditNewValue,s.c_str());
                    char buf[300];sprintf_s(buf,"Read string @ 0x%p: \"%s\"",selectedAddress,s.c_str());
                    LogToStatus(buf);
                }else{
                    int v=ReadValueFromAddress(selectedAddress);
                    SetWindowTextA(hEditNewValue,std::to_string(v).c_str());
                    char buf[128];sprintf_s(buf,"Read 0x%p = %d",selectedAddress,v);LogToStatus(buf);
                }
            }else LogToStatus("Select an address first",true);
            break;

        case ID_BTN_REFRESH_HEX:{
            char buf[64];GetWindowTextA(hEditHexAddress,buf,64);
            LPVOID addr=(LPVOID)(uintptr_t)strtoull(buf,NULL,0);
            ShowHexAtAddress(addr,selectedAddress);break;
        }

        case ID_BTN_REFRESH_MAP: ShowMemoryMap(); break;

        case ID_BTN_WRITE:
            if(!selectedAddress){LogToStatus("Select an address first",true);break;}
            if(!hProcess){LogToStatus("Not attached to a process",true);break;}
            {
                int dt=(int)SendMessage(hCmbDataType,CB_GETCURSEL,0,0);
                char buf[512]={};GetWindowTextA(hEditNewValue,buf,512);
                bool prot=(SendMessage(hChkProtect,BM_GETCHECK,0,0)==BST_CHECKED);
                if(dt==DT_INT32||dt==DT_FLOAT){
                    Backup4 bk={};ReadProcessMemory(hProcess,selectedAddress,bk.data,4,NULL);
                    backups[selectedAddress]=bk;
                }
                if(WriteTypedValue(selectedAddress,buf,dt,prot)){
                    char msg[256];sprintf_s(msg,"Wrote %s to 0x%p%s",buf,(void*)selectedAddress,prot?" (bypass)":"");
                    LogToStatus(msg);ShowHexAtAddress(selectedAddress,selectedAddress);
                    EnableWindow(hBtnUndo,TRUE);
                } else LogToStatus("Write failed — try Bypass checkbox or run as Admin",true);
            }
            break;

        case ID_BTN_UNDO:
            if(selectedAddress&&backups.count(selectedAddress)){
                WriteProcessMemory(hProcess,selectedAddress,backups[selectedAddress].data,4,NULL);
                int v=ReadValueFromAddress(selectedAddress);
                SetWindowTextA(hEditNewValue,std::to_string(v).c_str());
                LogToStatus("Undo successful");ShowHexAtAddress(selectedAddress,selectedAddress);
            }else LogToStatus("No backup available",true);
            break;

        case ID_BTN_INJECT_DLL:  InjectDLL();  break;
        case ID_BTN_EJECT_DLL:   EjectDLL();   break;
        case ID_BTN_INJECT_CODE: InjectShellcode(); break;
        case ID_BTN_SCAN_CAVES:  ScanCodeCaves(); break;
        case ID_BTN_LIST_THREADS:ListRemoteThreads(); break;

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

        case ID_BTN_SEND_TO_BUILDER:
            if(selectedAddress){
                char buf[32];sprintf_s(buf,"0x%llX",(uintptr_t)selectedAddress);
                SetWindowTextA(hEditScAddr,buf);
                LogToStatus("Address sent to Shellcode Builder");
            }else LogToStatus("Select a scan result first",true);
            break;

        case ID_BTN_BUILD_SC: BuildShellcode(); break;

        case ID_BTN_COPY_SC:{
            char buf[512]={};GetWindowTextA(hEditScResult,buf,512);
            SetWindowTextA(hEditShellcode,buf);LogToStatus("Shellcode copied to inj field");
            break;
        }

        case ID_BTN_FREEZE:
            if(!selectedAddress){LogToStatus("Select an address first",true);break;}
            freezeActive=!freezeActive;
            if(freezeActive){
                int dt=(int)SendMessage(hCmbDataType,CB_GETCURSEL,0,0);
                char buf[512]={};GetWindowTextA(hEditNewValue,buf,512);
                memset(freezeBytes,0,sizeof(freezeBytes));freezeByteLen=4;
                switch(dt){
                    case DT_INT8:  {int8_t  v=(int8_t)atoi(buf);  memcpy(freezeBytes,&v,1);freezeByteLen=1;break;}
                    case DT_INT16: {int16_t v=(int16_t)atoi(buf); memcpy(freezeBytes,&v,2);freezeByteLen=2;break;}
                    case DT_INT64: {int64_t v=(int64_t)_atoi64(buf);memcpy(freezeBytes,&v,8);freezeByteLen=8;break;}
                    case DT_FLOAT: {float   v=(float)atof(buf);   memcpy(freezeBytes,&v,4);freezeByteLen=4;break;}
                    case DT_DOUBLE:{double  v=atof(buf);           memcpy(freezeBytes,&v,8);freezeByteLen=8;break;}
                    default:       {int32_t v=atoi(buf);           memcpy(freezeBytes,&v,4);freezeByteLen=4;break;}
                }
                SetTimer(hWnd,TIMER_FREEZE,50,NULL);
                SetWindowTextA(hBtnFreeze,"Unfreeze");
                char msg[128];sprintf_s(msg,"Freezing 0x%p  (%zu bytes)",selectedAddress,freezeByteLen);LogToStatus(msg);
            }else{
                KillTimer(hWnd,TIMER_FREEZE);SetWindowTextA(hBtnFreeze,"Freeze");LogToStatus("Freeze disabled");
            }
            break;

        case ID_BTN_WRITE_UTF8:  WriteStringToAddress(selectedAddress,false); break;
        case ID_BTN_WRITE_UTF16: WriteStringToAddress(selectedAddress,true);  break;
        case ID_BTN_READ_STRING: ReadStringAtAddress(selectedAddress);         break;

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

        }
        break;

    case WM_LBUTTONUP: break;

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
