#include <windows.h>
#include <tchar.h>
#include <d3d11.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <algorithm>

#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"

#include "memcore.h"
#include "mem_lua.h"
#include "mem_ipc.h"

static const unsigned short kMcpPort = 8377;

static ID3D11Device*           g_pd3dDevice = NULL;
static ID3D11DeviceContext*    g_pd3dDeviceContext = NULL;
static IDXGISwapChain*         g_pSwapChain = NULL;
static UINT                    g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = NULL;

bool CreateDeviceD3D(HWND hWnd); void CleanupDeviceD3D();
void CreateRenderTarget();        void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND, UINT, WPARAM, LPARAM);
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);
static void DrawStackSection();

struct ScannerCfg {
    int   dtIdx = mem::DT_INT32;
    int   scIdx = mem::SC_EXACT;
    char  valueBuf[128] = "";
    char  modFilter[128] = "";
    bool  writableOnly = true;
    bool  skipImage = false;
    bool  executableOnly = false;
    bool  workingSetOnly = false;
    bool  copyOnWriteOnly = false;
    char  addrMinBuf[24] = "";
    char  addrMaxBuf[24] = "";
    int   alignmentIdx = 0;
    bool  skipZero = false;
    char  skipSuffix[16] = "";
    char  rangeMin[32] = "";
    char  rangeMax[32] = "";
    char  topNBuf[16]  = "100";
    char  maxDBuf[16]  = "100";
    char  rowFilter[64] = "";
    bool  fullscreen = false;
    bool  showAsText = false;
    int   strEncIdx = 2;
    bool  strCaseInsensitive = false;
};

struct ModulesUI {
    std::vector<mem::ModuleEntry> list;
    char filter[64] = "";
    int  selected = -1;
    char dllPath[MAX_PATH] = "";
    char ejectName[128] = "";
};

struct PatcherUI {
    char addrBuf[40]  = "0x0";
    char sizeBuf[16]  = "16";
    char bytesBuf[256] = "";
    char nopLen[16] = "5";
    char jmpTarget[40] = "0x0";
    std::vector<BYTE> readOut;
    std::string lastReadAddr;
};

struct PointersUI {
    char name[128] = "";
    char modName[64] = "";
    char baseHex[40] = "";
    char offsHex[256] = "0x10, 0x50, 0x0";
    int  selected = -1;
};

struct CheatsUI {
    int   selected = -1;
    char  nameBuf[128] = "";
    char  hotkeyBuf[16] = "";
    std::string scriptEdit;
};

struct DisasmUI {
    char  targetBuf[40] = "0x0";
    char  sizeBuf[16]   = "256";
    std::vector<mem::DisasmLine> lines;
};

struct CodeInjUI {
    char    scBuf[1024]  = "";
    char    caveMin[16]  = "32";
    std::vector<mem::CodeCave> caves;
    std::vector<mem::RemoteThreadEntry> threads;
};
struct WindowsUI {
    std::vector<mem::TargetWindow> wnds;
    int  selected = -1;
    char filter[64] = "";
    char setText[256] = "";
    char msgId[16] = "0x111";
    char wpBuf[16] = "0";
    char lpBuf[16] = "0";
};
struct DetectUI {
    bool rwx = true, privExec = true, threadAnom = true;
    std::vector<mem::DetectFinding> findings;
    char filter[64] = "";
};
struct ShellcodeUI {
    char path[MAX_PATH] = "";
    std::vector<BYTE> bytes;
    bool autoExec = false;
};
struct TriggerUI {
    char addrBuf[40] = "0x0";
    char paramBuf[40] = "0x0";
    char tidBuf[16] = "0";
    DWORD lastTid = 0;
};
struct ExportsUI {
    std::vector<mem::ExportRow> rows;
    char filter[128] = "";
};
struct AutoPtrUI {
    char target[40] = "0x0";
    char depthBuf[8] = "3";
    char maxOffBuf[16] = "0x800";
    std::vector<mem::AutoPtrChain> results;
};
struct VerifyUI {
    bool haveSnapshot = false;
    mem::VerifyDiff lastDiff;
};

struct AsmUI {
    std::string src;
    std::vector<BYTE> bytes;
    std::string err;
};

struct SigUI {
    mem::AobSignature lastSig;
    bool haveSig = false;
};

struct WatchUI {
    char nameBuf[64] = "";
    char addrBuf[40] = "0x0";
    int  dtIdx = mem::DT_INT32;
    char editBuf[64] = "";
    int  selected = -1;
    DWORD lastTick = 0;
};

struct HookUI {
    char  targetBuf[40]   = "0x0";
    char  stolenBuf[16]   = "14";
    std::string payloadSrc;
};

struct HwbpUI {
    int  type = mem::HWBP_WRITE;
    int  size = 4;
    char filter[64] = "";
};

struct HexUI {
    char addrBuf[40] = "0x0";
    char sizeBuf[16] = "256";
    std::vector<BYTE> data;
    uintptr_t base = 0;
    int  editIdx = -1;
    char editVal[8] = "";
};
struct BookmarksUI {
    char nameBuf[64] = "";
    char addrBuf[40] = "0x0";
    int  dtIdx = mem::DT_INT32;
    char noteBuf[256] = "";
    int  selected = -1;
};
struct PEUI {
    int                selectedModule = -1;
    mem::PEInfo        info;
    char               filter[64] = "";
    int                viewMode = 0;
};
struct StackUI {
    char tidBuf[16] = "0";
    std::vector<mem::StackFrame> frames;
};
struct AutoTypeUI {
    bool showModal = false;
    std::vector<mem::TypeGuess> guesses;
};

struct ProcTreeUI {
    std::vector<mem::ProcessNode> tree;
    char filter[64] = "";
    DWORD lastRefresh = 0;
};
struct NetUI {
    std::vector<mem::NetEndpoint> entries;
    bool   onlyAttached = true;
    char   filter[64] = "";
};

struct LuaUI {
    std::string source;
    char       savePath[MAX_PATH] = "script.lua";
    int        logScrollTo = -1;
};

struct AppState {
    char pidBuf[32] = "";
    char findBuf[64] = "";
    std::vector<std::pair<DWORD,std::string>> procList;
    bool showProcModal = false;

    LPVOID         selAddr = nullptr;
    char           newValueBuf[64] = "";
    bool           bypassReadOnly = false;
    bool           forceScannerTab = false;

    bool           showHistory = false;
    LPVOID         historyAddr = nullptr;
    bool           showGuide = false;
    char           guideFilter[64] = "";

    std::thread       scanThread;
    std::atomic<bool> scanBusy{false};
    DWORD             lastLiveTick = 0;

    ScannerCfg sc;
    ModulesUI  mods;
    PatcherUI  patch;
    PointersUI ptrs;
    CheatsUI   cheats;
    DisasmUI   dis;
    CodeInjUI  ci;
    WindowsUI  wnd;
    DetectUI   det;
    ShellcodeUI shel;
    TriggerUI  trg;
    ExportsUI  exp;
    AutoPtrUI  aps;
    VerifyUI   ver;
    AsmUI      asmui;
    SigUI      sig;
    WatchUI    watch;
    HookUI     hook;
    HwbpUI     hwbp;
    HexUI       hex;
    BookmarksUI bm;
    PEUI        pe;
    StackUI     stk;
    AutoTypeUI  at;
    ProcTreeUI  pt;
    NetUI       net;
    LuaUI       lua;

    std::string statusLine = "Ready. Enter a PID + Attach, or search by name.";
    std::string statusKind = "info";
    HHOOK       kbHook = NULL;
    HWND        hwnd = NULL;

    void setStatus(const std::string& s, const char* kind = "info") { statusLine = s; statusKind = kind; }
};
static AppState gApp;

namespace clr {
    constexpr ImVec4 bg        = ImVec4(0.055f, 0.062f, 0.084f, 1.00f);
    constexpr ImVec4 panel     = ImVec4(0.085f, 0.094f, 0.130f, 1.00f);
    constexpr ImVec4 panelAlt  = ImVec4(0.105f, 0.118f, 0.160f, 1.00f);
    constexpr ImVec4 border    = ImVec4(0.180f, 0.205f, 0.270f, 1.00f);
    constexpr ImVec4 frame     = ImVec4(0.135f, 0.155f, 0.210f, 1.00f);
    constexpr ImVec4 frameH    = ImVec4(0.180f, 0.215f, 0.290f, 1.00f);
    constexpr ImVec4 frameA    = ImVec4(0.220f, 0.260f, 0.340f, 1.00f);
    constexpr ImVec4 accent    = ImVec4(0.330f, 0.665f, 1.000f, 1.00f);
    constexpr ImVec4 accentH   = ImVec4(0.430f, 0.745f, 1.000f, 1.00f);
    constexpr ImVec4 ok        = ImVec4(0.420f, 0.880f, 0.520f, 1.00f);
    constexpr ImVec4 warn      = ImVec4(1.000f, 0.690f, 0.300f, 1.00f);
    constexpr ImVec4 err       = ImVec4(1.000f, 0.380f, 0.380f, 1.00f);
    constexpr ImVec4 text      = ImVec4(0.880f, 0.910f, 0.960f, 1.00f);
    constexpr ImVec4 textDim   = ImVec4(0.520f, 0.560f, 0.660f, 1.00f);
    constexpr ImVec4 sectHdr   = ImVec4(0.500f, 0.800f, 1.000f, 1.00f);
}

static void StyleDark() {
    ImGuiStyle& s = ImGui::GetStyle();
    ImGui::StyleColorsDark();
    s.WindowRounding=6; s.ChildRounding=6; s.FrameRounding=5; s.PopupRounding=6;
    s.GrabRounding=5;   s.TabRounding=6;   s.ScrollbarRounding=8;
    s.WindowPadding=ImVec2(12,10); s.FramePadding=ImVec2(9,5); s.ItemSpacing=ImVec2(8,7);
    s.ItemInnerSpacing=ImVec2(6,5); s.IndentSpacing=18; s.ScrollbarSize=14; s.GrabMinSize=14;
    s.WindowBorderSize=0; s.ChildBorderSize=1; s.FrameBorderSize=0; s.PopupBorderSize=1; s.TabBorderSize=0;
    s.SeparatorTextBorderSize=2; s.SeparatorTextAlign=ImVec2(0,0.5f); s.SeparatorTextPadding=ImVec2(20,4);
    ImVec4* c = s.Colors;
    c[ImGuiCol_Text]=clr::text; c[ImGuiCol_TextDisabled]=clr::textDim;
    c[ImGuiCol_WindowBg]=clr::bg; c[ImGuiCol_ChildBg]=clr::panel; c[ImGuiCol_PopupBg]=clr::panelAlt;
    c[ImGuiCol_Border]=clr::border;
    c[ImGuiCol_FrameBg]=clr::frame; c[ImGuiCol_FrameBgHovered]=clr::frameH; c[ImGuiCol_FrameBgActive]=clr::frameA;
    c[ImGuiCol_TitleBg]=clr::panel; c[ImGuiCol_TitleBgActive]=clr::panelAlt; c[ImGuiCol_TitleBgCollapsed]=clr::panel;
    c[ImGuiCol_MenuBarBg]=clr::panel; c[ImGuiCol_ScrollbarBg]=clr::panel;
    c[ImGuiCol_ScrollbarGrab]=clr::frame; c[ImGuiCol_ScrollbarGrabHovered]=clr::frameH; c[ImGuiCol_ScrollbarGrabActive]=clr::frameA;
    c[ImGuiCol_CheckMark]=clr::accent; c[ImGuiCol_SliderGrab]=clr::accent; c[ImGuiCol_SliderGrabActive]=clr::accentH;
    c[ImGuiCol_Button]=ImVec4(0.155f,0.205f,0.310f,1); c[ImGuiCol_ButtonHovered]=ImVec4(0.215f,0.310f,0.470f,1); c[ImGuiCol_ButtonActive]=ImVec4(0.290f,0.430f,0.640f,1);
    c[ImGuiCol_Header]=ImVec4(0.180f,0.260f,0.380f,0.60f); c[ImGuiCol_HeaderHovered]=ImVec4(0.260f,0.380f,0.560f,0.85f); c[ImGuiCol_HeaderActive]=ImVec4(0.310f,0.460f,0.660f,1);
    c[ImGuiCol_Separator]=clr::border; c[ImGuiCol_SeparatorHovered]=clr::accent; c[ImGuiCol_SeparatorActive]=clr::accentH;
    c[ImGuiCol_ResizeGrip]=ImVec4(0.180f,0.260f,0.380f,0.40f); c[ImGuiCol_ResizeGripHovered]=clr::accent; c[ImGuiCol_ResizeGripActive]=clr::accentH;
    c[ImGuiCol_Tab]=ImVec4(0.105f,0.130f,0.180f,1); c[ImGuiCol_TabHovered]=ImVec4(0.230f,0.330f,0.490f,1);
    c[ImGuiCol_TabActive]=ImVec4(0.310f,0.460f,0.660f,1);
    c[ImGuiCol_TabUnfocused]=ImVec4(0.075f,0.090f,0.130f,1); c[ImGuiCol_TabUnfocusedActive]=ImVec4(0.180f,0.260f,0.380f,1);
    c[ImGuiCol_TableHeaderBg]=ImVec4(0.140f,0.170f,0.230f,1);
    c[ImGuiCol_TableBorderStrong]=clr::border; c[ImGuiCol_TableBorderLight]=ImVec4(0.130f,0.150f,0.200f,1);
    c[ImGuiCol_TableRowBg]=ImVec4(0,0,0,0); c[ImGuiCol_TableRowBgAlt]=ImVec4(1,1,1,0.025f);
    c[ImGuiCol_TextSelectedBg]=ImVec4(0.310f,0.460f,0.660f,0.45f);
    c[ImGuiCol_NavHighlight]=clr::accent; c[ImGuiCol_DragDropTarget]=clr::accentH;
}

static void SectionLabel(const char* txt) {
    ImGui::PushStyleColor(ImGuiCol_Text, clr::sectHdr);
    ImGui::SeparatorText(txt);
    ImGui::PopStyleColor();
}
static void HintText(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    char buf[512]; vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    ImGui::PushStyleColor(ImGuiCol_Text, clr::textDim);
    ImGui::TextWrapped("%s", buf);
    ImGui::PopStyleColor();
}
static void Tip(const char* text) {
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32);
        ImGui::TextUnformatted(text);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}
static bool ColorButton(const char* label, ImVec4 a, const ImVec2& sz = ImVec2(0,0)) {
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(a.x*0.45f, a.y*0.45f, a.z*0.45f, 1));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(a.x*0.65f, a.y*0.65f, a.z*0.65f, 1));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  a);
    bool r = ImGui::Button(label, sz);
    ImGui::PopStyleColor(3);
    return r;
}

static void DrawTopBar() {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, clr::panel);
    ImGui::BeginChild("##topbar", ImVec2(0, 64), true);
    ImGui::AlignTextToFramePadding();
    ImGui::PushStyleColor(ImGuiCol_Text, clr::accent);
    ImGui::Text(" MEMISCANI ");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::TextDisabled(" |  process / memory toolkit ");

    ImGui::SameLine(0, 30);
    ImGui::SetNextItemWidth(90);
    ImGui::InputText("##pid", gApp.pidBuf, sizeof(gApp.pidBuf), ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    if (ColorButton(mem::isAttached() ? "Re-Attach" : "Attach", clr::accent, ImVec2(96, 0))) {
        DWORD pid = (DWORD)atoi(gApp.pidBuf);
        if (pid && mem::attach(pid)) { char b[80]; sprintf(b, "Attached to PID %lu", pid); gApp.setStatus(b, "ok"); }
        else                          gApp.setStatus("Attach failed (need admin?)", "err");
    }
    Tip("Open a handle to the process whose PID is in the box.  Most game scans need admin - run this exe elevated if Attach keeps failing.");
    ImGui::SameLine();
    if (mem::isAttached() && ImGui::Button("Detach", ImVec2(72, 0))) {
        mem::detach(); mem::clearScan(); gApp.setStatus("Detached.", "info");
    }
    Tip("Close the process handle and clear scan results.");
    ImGui::SameLine(0, 20);
    ImGui::SetNextItemWidth(160);
    ImGui::InputTextWithHint("##find", "process name...", gApp.findBuf, sizeof(gApp.findBuf));
    ImGui::SameLine();
    if (ImGui::Button("Find", ImVec2(60, 0))) {
        gApp.procList = mem::findProcessesByName(gApp.findBuf);
        gApp.showProcModal = !gApp.procList.empty();
        char b[80]; sprintf(b, "Found %zu process(es)", gApp.procList.size());
        gApp.setStatus(b, gApp.procList.empty() ? "warn" : "info");
    }
    Tip("Search running processes by name substring.  Opens a picker with parent/child tree.");
    ImGui::SameLine(0, 20);
    ImGui::BeginDisabled(!mem::isAttached());
    if (mem::g_processSuspended) {
        if (ColorButton("Resume Process", clr::ok, ImVec2(150, 0))) {
            size_t n = mem::resumeAllThreads();
            char b[80]; sprintf(b, "Resumed %zu thread(s).", n); gApp.setStatus(b, "ok");
        }
        Tip("Resume all threads of the attached process.");
    } else {
        if (ColorButton("Suspend Process", clr::warn, ImVec2(150, 0))) {
            size_t n = mem::suspendAllThreads();
            char b[80]; sprintf(b, "Suspended %zu thread(s) - safe to inspect now.", n); gApp.setStatus(b, "ok");
        }
        Tip("Freeze every thread of the target so memory stops changing while you inspect.  Click again (label becomes 'Resume Process') to unpause.");
    }
    ImGui::EndDisabled();
    ImGui::SameLine(0, 12);
    if (ColorButton("Guide / Workflows", clr::accentH, ImVec2(170, 0))) gApp.showGuide = true;
    Tip("Open the workflow guide modal with 50+ step-by-step recipes (filterable).");
    ImGui::SameLine(0, 12);
    if (ImGui::Button("Save Session", ImVec2(120, 0))) {
        if (mem::saveSession("memiscani_session.dat")) gApp.setStatus("Session saved.", "ok");
        else gApp.setStatus("Session save failed.", "err");
    }
    Tip("Persist current scan results, snapshot, live stats, scan params (and on-exit also bookmarks/watch/chains/cheats/lua) so you can resume after closing the app.  Auto-saved on exit.");
    ImGui::SameLine();
    if (ImGui::Button("Load Session", ImVec2(120, 0))) {
        if (mem::loadSession("memiscani_session.dat")) gApp.setStatus("Session loaded.", "ok");
        else gApp.setStatus("Session load failed (file missing or version mismatch).", "warn");
    }
    Tip("Restore the last saved session (auto-loaded at startup if memiscani_session.dat exists).");
    ImGui::EndChild();
    ImGui::PopStyleColor();

    if (gApp.showProcModal) ImGui::OpenPopup("Pick process (tree)");
    ImGui::SetNextWindowSize(ImVec2(720, 600), ImGuiCond_FirstUseEver);
    if (ImGui::BeginPopupModal("Pick process (tree)", &gApp.showProcModal)) {
        ImGui::TextDisabled("Parent/child relationships are preserved.  Filter on the right hides non-matching rows but keeps ancestors visible for context.");
        ImGui::SetNextItemWidth(280);
        if (ImGui::InputTextWithHint("##ptf", "filter substring", gApp.pt.filter, sizeof(gApp.pt.filter)) || gApp.pt.tree.empty()) {
            gApp.pt.tree = mem::listProcessesTree(gApp.pt.filter);
        }
        ImGui::SameLine();
        if (ImGui::Button("Refresh##pt", ImVec2(100, 0))) gApp.pt.tree = mem::listProcessesTree(gApp.pt.filter);
        if (ImGui::BeginTable("proctree", 2, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0, 480))) {
            ImGui::TableSetupColumn("PID",  ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableSetupColumn("Process");
            ImGui::TableHeadersRow();
            for (const auto& n : gApp.pt.tree) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::Text("%lu", n.pid);
                ImGui::TableSetColumnIndex(1);
                std::string indent(n.depth * 4, ' ');
                char lbl[400]; sprintf(lbl, "%s%s%s##pt%lu", indent.c_str(), n.depth ? "+- " : "", n.name.c_str(), n.pid);
                if (ImGui::Selectable(lbl, false, ImGuiSelectableFlags_SpanAllColumns)) {
                    sprintf(gApp.pidBuf, "%lu", n.pid);
                    gApp.procList.clear(); gApp.showProcModal = false;
                    ImGui::CloseCurrentPopup();
                }
            }
            ImGui::EndTable();
        }
        if (ImGui::Button("Close")) { gApp.procList.clear(); gApp.showProcModal = false; ImGui::CloseCurrentPopup(); }
        ImGui::EndPopup();
    }
}

static void StatusBar() {
    ImVec4 col = clr::text;
    if      (gApp.statusKind == "ok")   col = clr::ok;
    else if (gApp.statusKind == "warn") col = clr::warn;
    else if (gApp.statusKind == "err")  col = clr::err;
    ImGui::PushStyleColor(ImGuiCol_ChildBg, clr::panelAlt);
    ImGui::BeginChild("##status", ImVec2(0, 30), true);
    ImGui::AlignTextToFramePadding();
    if (mem::isAttached()) {
        ImGui::TextColored(clr::ok, " ATTACHED  pid %lu", mem::attachedPid());
        ImGui::SameLine();
        ImGui::TextDisabled("  base 0x%llX", (unsigned long long)(uintptr_t)mem::baseAddress());
    } else ImGui::TextColored(clr::warn, " NOT ATTACHED");
    ImGui::SameLine();
    ImGui::TextDisabled("  |  results %zu", mem::g_scan.results.size());
    if (mem::g_liveMonActive) { ImGui::SameLine(); ImGui::TextColored(clr::ok, "  |  LIVE %zu", mem::g_liveStats.size()); }
    if (!mem::g_snapshot.empty()) { ImGui::SameLine(); ImGui::TextColored(clr::accentH, "  |  snapshot %zu", mem::g_snapshot.size()); }
    if (memipc::running()) {
        ImGui::SameLine();
        ImGui::TextColored(clr::ok, "  |  MCP :%u (%d conn, %llu req)",
                           (unsigned)memipc::port(), memipc::connectionCount(),
                           (unsigned long long)memipc::requestCount());
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("MCP/IPC command server: 127.0.0.1 (loopback only), token-authenticated.\nToken file: %s\nDrive this session from Claude via the memiscani MCP bridge.",
                              memipc::tokenPath().c_str());
    } else {
        ImGui::SameLine(); ImGui::TextColored(clr::warn, "  |  MCP off");
    }
    ImGui::SameLine(0, 18);
    ImGui::TextColored(col, "%s", gApp.statusLine.c_str());
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

static void DrawSelectedStrip() {
    using namespace mem;
    ImGui::PushStyleColor(ImGuiCol_ChildBg, clr::panel);
    ImGui::BeginChild("##selstrip", ImVec2(0, 96), true);
    if (!gApp.selAddr) {
        ImGui::TextDisabled("  Selected:  (click a row in the results table)");
        ImGui::EndChild(); ImGui::PopStyleColor(); return;
    }
    DataType dt = (DataType)gApp.sc.dtIdx;
    LPVOID a = gApp.selAddr;
    char addrStr[40]; sprintf(addrStr, "0x%llX", (unsigned long long)(uintptr_t)a);
    LPVOID base = baseAddress();
    BYTE buf[16] = {};
    bool ok = readTypedValue(a, dt, buf);
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(clr::accent, "  Selected:");
    ImGui::SameLine(); ImGui::Text("%s", addrStr);
    if (base) { ImGui::SameLine(); ImGui::TextDisabled("(+0x%llX)", (unsigned long long)((uintptr_t)a - (uintptr_t)base)); }
    ImGui::SameLine();
    ImGui::TextDisabled("  |  current value");
    ImGui::SameLine();
    if (ok) ImGui::TextColored(clr::ok, "%s", formatTypedValue(buf, dt).c_str());
    else    ImGui::TextDisabled("?");
    ImGui::SameLine();
    ImGui::TextDisabled("  |  asm: %s", disasmOneAtRemote(a).c_str());

    ImGui::Spacing();
    ImGui::SetNextItemWidth(220);
    ImGui::InputTextWithHint("##newv", "new value (0x ok)", gApp.newValueBuf, sizeof(gApp.newValueBuf));
    ImGui::SameLine();
    if (ColorButton("Write", clr::accent, ImVec2(80, 0))) {
        std::string err;
        if (!writeTypedValue(a, dt, gApp.newValueBuf, gApp.bypassReadOnly, err)) gApp.setStatus("Write failed: " + err, "err");
        else gApp.setStatus("Wrote value.", "ok");
    }
    Tip("Write the value in the box above to the selected address.  Type is inferred from the Scanner's Type combo.  Enable 'Bypass read-only' to write to .text / code pages.");
    ImGui::SameLine();
    if (ImGui::Button("Read", ImVec2(60, 0))) {
        BYTE b[16]; if (readTypedValue(a, dt, b)) sprintf(gApp.newValueBuf, "%s", formatTypedValue(b, dt).c_str());
    }
    Tip("Read the current value at the selected address into the input box.");
    ImGui::SameLine();
    if (ImGui::Button("Copy Addr", ImVec2(95, 0))) { ImGui::SetClipboardText(addrStr); gApp.setStatus("Address copied.", "ok"); }
    Tip("Copy the selected address (hex with 0x prefix) to the clipboard.");
    ImGui::SameLine();
    ImGui::Checkbox("Bypass read-only", &gApp.bypassReadOnly);
    Tip("Flip page protection to RWX before writing, then restore.  Needed for patches into code (.text) pages.");
    ImGui::SameLine(0, 24);
    if (ImGui::Button("-> Patcher")) {
        sprintf(gApp.patch.addrBuf, "0x%llX", (unsigned long long)(uintptr_t)a);
        gApp.setStatus("Address sent to Patcher tab.", "info");
    }
    Tip("Send the selected address to the Patcher tab's Address field.");
    ImGui::SameLine();
    if (ImGui::Button("-> Hex View")) {
        sprintf(gApp.hex.addrBuf, "0x%llX", (unsigned long long)(uintptr_t)a);
        gApp.setStatus("Address sent to Hex Viewer.", "info");
    }
    Tip("Open this address in the Hex View tab.");
    ImGui::SameLine();
    if (ImGui::Button("Bookmark")) {
        mem::bookmarkAdd("@scanner", a, dt, "from selected");
        gApp.setStatus("Address bookmarked.", "ok");
    }
    Tip("Save this address as a bookmark (default name '@scanner').  Edit name + notes on the Bookmarks tab.");
    ImGui::SameLine();
    if (ColorButton("Auto-detect type", clr::accentH, ImVec2(150, 0))) {
        gApp.at.guesses = mem::guessTypeAt(a);
        gApp.at.showModal = true;
    }
    Tip("Heuristically guess what data type is most plausible at this address: int8/16/32/64, float, double, or pointer.  Opens a modal with ranked candidates.");
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

static void DoScanAsync(bool first) {
    using namespace mem;
    ScanParams p;
    p.dt = (DataType)gApp.sc.dtIdx; p.sc = (ScanCondition)gApp.sc.scIdx;
    p.value = gApp.sc.valueBuf; p.modFilter = gApp.sc.modFilter;
    p.strEnc = gApp.sc.strEncIdx; p.strCaseInsensitive = gApp.sc.strCaseInsensitive;
    p.writableOnly = gApp.sc.writableOnly;
    p.skipImage = gApp.sc.skipImage;
    p.executableOnly = gApp.sc.executableOnly;
    p.workingSetOnly = gApp.sc.workingSetOnly;
    p.copyOnWriteOnly = gApp.sc.copyOnWriteOnly;
    if (gApp.sc.addrMinBuf[0]) p.addrMin = (uintptr_t)parseHexAwareInt(gApp.sc.addrMinBuf);
    if (gApp.sc.addrMaxBuf[0]) p.addrMax = (uintptr_t)parseHexAwareInt(gApp.sc.addrMaxBuf);
    int alignMap[5] = {0, 1, 2, 4, 8};
    p.alignment = alignMap[(gApp.sc.alignmentIdx >= 0 && gApp.sc.alignmentIdx < 5) ? gApp.sc.alignmentIdx : 0];
    p.skipZero = gApp.sc.skipZero;
    p.skipAddrSuffixHex = gApp.sc.skipSuffix;
    if (gApp.sc.rangeMin[0]) { p.hasMin = true; p.rmin = parseHexAwareInt(gApp.sc.rangeMin); p.rminF = atof(gApp.sc.rangeMin); }
    if (gApp.sc.rangeMax[0]) { p.hasMax = true; p.rmax = parseHexAwareInt(gApp.sc.rangeMax); p.rmaxF = atof(gApp.sc.rangeMax); }
    if (gApp.scanThread.joinable()) gApp.scanThread.join();
    gApp.scanBusy = true;
    gApp.scanThread = std::thread([p, first]() {
        std::string err;
        if (first) doFirstScan(p, err);
        else       doNextScan(p, err);
        gApp.scanBusy = false;
    });
}

static std::string resultBytesAsText(const BYTE* b, size_t n) {
    std::string s;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = b[i];
        if (c == 0) break;
        s += (c >= 0x20 && c < 0x7F) ? (char)c : '.';
    }
    return s.empty() ? std::string("(empty)") : s;
}

static void DrawResultsTable(bool fullscreen) {
    using namespace mem;
    DataType dt = (DataType)gApp.sc.dtIdx;
    bool haveLive = !g_liveStats.empty() && g_liveStats.size() == g_scan.results.size();
    int cols = haveLive ? 8 : 5;
    ImGuiTableFlags tflags = ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY|
                             ImGuiTableFlags_Resizable|ImGuiTableFlags_Reorderable|ImGuiTableFlags_Hideable;
    if (ImGui::BeginTable("results", cols, tflags, ImVec2(0, fullscreen ? -2 : 0))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#",       ImGuiTableColumnFlags_WidthFixed, 64);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 200);
        ImGui::TableSetupColumn("Offset",  ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Value");
        ImGui::TableSetupColumn("Disasm",  ImGuiTableColumnFlags_WidthFixed, 320);
        if (haveLive) {
            ImGui::TableSetupColumn("Range", ImGuiTableColumnFlags_WidthFixed, 160);
            ImGui::TableSetupColumn("Hits",  ImGuiTableColumnFlags_WidthFixed, 110);
            ImGui::TableSetupColumn("Score", ImGuiTableColumnFlags_WidthFixed, 80);
        }
        ImGui::TableHeadersRow();

        size_t total = g_scan.results.size();
        size_t cap = std::min((size_t)5000, total);
        size_t sz = dtSize(dt);
        LPVOID base = mem::baseAddress();

        static std::vector<size_t> visibleIdx;
        visibleIdx.clear();
        visibleIdx.reserve(cap);
        if (gApp.sc.rowFilter[0]) {
            for (size_t i = 0; i < cap; i++) {
                char addrStr[40]; sprintf(addrStr, "0x%llX", (unsigned long long)(uintptr_t)g_scan.results[i]);
                if (strstr(addrStr, gApp.sc.rowFilter)) visibleIdx.push_back(i);
            }
        } else {
            for (size_t i = 0; i < cap; i++) visibleIdx.push_back(i);
        }

        bool patType = (dt == DT_STRING || dt == DT_AOB);
        bool asText = gApp.sc.showAsText && !patType;
        ImGuiListClipper clipper;
        clipper.Begin((int)visibleIdx.size());
        BYTE cur[16];
        BYTE wide[256];
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++) {
                size_t i = visibleIdx[row];
                LPVOID a = g_scan.results[i];
                char addrStr[40]; sprintf(addrStr, "0x%llX", (unsigned long long)(uintptr_t)a);
                SIZE_T r = 0;
                bool ok = isAttached() && ReadProcessMemory(processHandle(), a, cur, sz, &r) && r >= sz;

                size_t wantW = 0;
                if (patType) {
                    wantW = (i < g_scan.prevVals.size() && !g_scan.prevVals[i].empty())
                          ? g_scan.prevVals[i].size() : 16;
                } else if (asText) {
                    wantW = sizeof(wide) - 1;
                }
                if (wantW > sizeof(wide)) wantW = sizeof(wide);
                SIZE_T wr = 0;
                bool okW = wantW && isAttached() &&
                           ReadProcessMemory(processHandle(), a, wide, wantW, &wr) && wr > 0;

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                char idLbl[48]; sprintf(idLbl, "%zu##row%zu", i + 1, i);
                bool isSel = (gApp.selAddr == a);
                if (ImGui::Selectable(idLbl, isSel, ImGuiSelectableFlags_SpanAllColumns)) gApp.selAddr = a;
                ImGui::TableSetColumnIndex(1); ImGui::Text("%s", addrStr);
                ImGui::TableSetColumnIndex(2);
                if (base) ImGui::Text("+0x%llX", (unsigned long long)((uintptr_t)a - (uintptr_t)base));
                else      ImGui::TextDisabled("-");
                ImGui::TableSetColumnIndex(3);
                if (patType) {
                    if (okW) ImGui::TextColored(clr::ok, "%s", formatTypedValueN(wide, wr, dt).c_str());
                    else     ImGui::TextDisabled("?");
                } else if (asText) {
                    if (okW) ImGui::TextColored(clr::ok, "\"%s\"", resultBytesAsText(wide, wr).c_str());
                    else     ImGui::TextDisabled("?");
                } else {
                    if (ok) ImGui::TextColored(clr::ok, "%s", formatTypedValue(cur, dt).c_str());
                    else    ImGui::TextDisabled("?");
                }
                ImGui::TableSetColumnIndex(4);
                std::string ds = isAttached() ? disasmOneAtRemote(a) : std::string("(not attached)");
                ImGui::TextColored(isSel ? clr::accentH : clr::textDim, "%s", ds.c_str());
                if (haveLive) {
                    const LiveStat& s = g_liveStats[i];
                    ImGui::TableSetColumnIndex(5);
                    if (s.minMaxInit) ImGui::Text("%s .. %s", formatTypedValue(s.minV, dt).c_str(), formatTypedValue(s.maxV, dt).c_str());
                    else ImGui::TextDisabled("-");
                    ImGui::TableSetColumnIndex(6);
                    const char* dir = (s.increased && s.decreased) ? "u/d" : s.increased ? "up" : s.decreased ? "dn" : "-";
                    ImGui::Text("%u/%u %s", s.changeCount, s.sampleCount, dir);
                    ImGui::TableSetColumnIndex(7);
                    if (s.score > 0) ImGui::TextColored(clr::accentH, "%.0f", s.score); else ImGui::TextDisabled("-");
                }
            }
        }
        clipper.End();
        ImGui::EndTable();
    }
}

static void DrawScannerTab() {
    using namespace mem;
    DataType dt = (DataType)gApp.sc.dtIdx;

    if (gApp.sc.fullscreen) {
        ImGui::AlignTextToFramePadding();
        ImGui::TextColored(clr::accent, "Fullscreen results");
        ImGui::SameLine(); ImGui::TextDisabled("(%zu rows)", g_scan.results.size());
        ImGui::SameLine();
        ImGui::SetNextItemWidth(280);
        ImGui::InputTextWithHint("##rowf", "filter (substring on address)", gApp.sc.rowFilter, sizeof(gApp.sc.rowFilter));
        ImGui::SameLine();
        ImGui::Checkbox("As Text", &gApp.sc.showAsText);
        Tip("Show the Value column as printable ASCII text (bytes at each address) instead of the typed/numeric value.");
        ImGui::SameLine();
        if (ImGui::Button("Exit Fullscreen", ImVec2(140, 0))) gApp.sc.fullscreen = false;
        ImGui::Separator();
        DrawResultsTable(true);
        return;
    }

    SectionLabel("1.  Configure");
    HintText("Pick the data type + match condition.  'Unknown Initial' captures every address as a baseline.  Writable + Skip-image + initial-value Range cut scan size dramatically.");
    const char* dtItems[] = { "int8","int16","int32","int64","float","double","String","AOB" };
    int dtMap[] = { DT_INT8, DT_INT16, DT_INT32, DT_INT64, DT_FLOAT, DT_DOUBLE, DT_STRING, DT_AOB };
    int dtSel = 2; for (int i = 0; i < 8; i++) if (dtMap[i] == gApp.sc.dtIdx) { dtSel = i; break; }
    ImGui::SetNextItemWidth(120);
    if (ImGui::Combo("Type##dt", &dtSel, dtItems, IM_ARRAYSIZE(dtItems))) gApp.sc.dtIdx = dtMap[dtSel];
    ImGui::SameLine();
    const char* scItems[] = { "Exact","Changed","Unchanged","Increased","Decreased","Unknown Initial" };
    int scMap[] = { SC_EXACT, SC_CHANGED, SC_UNCHANGED, SC_INCREASED, SC_DECREASED, SC_UNKNOWN };
    int scSel = 0; for (int i = 0; i < 6; i++) if (scMap[i] == gApp.sc.scIdx) { scSel = i; break; }
    ImGui::SetNextItemWidth(150);
    if (ImGui::Combo("Match##sc", &scSel, scItems, IM_ARRAYSIZE(scItems))) gApp.sc.scIdx = scMap[scSel];
    ImGui::SameLine(); ImGui::SetNextItemWidth(220);
    ImGui::InputTextWithHint("##val", "value (0x prefix = hex)", gApp.sc.valueBuf, sizeof(gApp.sc.valueBuf));
    ImGui::SameLine(); ImGui::TextDisabled("Value");

    if (dt == DT_STRING) {
        const char* encItems[] = { "ASCII/UTF-8", "UTF-16", "Both" };
        ImGui::SetNextItemWidth(130);
        ImGui::Combo("Encoding##strenc", &gApp.sc.strEncIdx, encItems, IM_ARRAYSIZE(encItems));
        Tip("Text encoding to search for.  Many Windows apps (e.g. Notepad) store text as UTF-16.  'Both' searches ASCII and UTF-16 at once - the safe default.");
        ImGui::SameLine();
        ImGui::Checkbox("Ignore case", &gApp.sc.strCaseInsensitive);
        Tip("Match letters regardless of upper/lower case (ASCII letters only).");
    }

    ImGui::Checkbox("Writable", &gApp.sc.writableOnly);
    Tip("Limit scan to writable pages (RW / WC / X+RW).  Default ON.  Drops scan time 5-10x by skipping read-only DLL pages.");
    ImGui::SameLine(); ImGui::Checkbox("Skip image", &gApp.sc.skipImage);
    Tip("Skip MEM_IMAGE regions (loaded DLLs/EXE static memory).  Use for pure heap/stack data.");
    ImGui::SameLine(); ImGui::Checkbox("Exec only", &gApp.sc.executableOnly);
    Tip("Override the protect mask to ONLY executable pages (PAGE_EXECUTE_*).  Use to find code, hook sites, vtables.  Overrides 'Writable' and 'CoW'.");
    ImGui::SameLine(); ImGui::Checkbox("CoW only", &gApp.sc.copyOnWriteOnly);
    Tip("Only copy-on-write pages (PAGE_WRITECOPY / PAGE_EXECUTE_WRITECOPY).  Useful for inspecting shared+modified data.  Overrides 'Writable'.");
    ImGui::SameLine(); ImGui::Checkbox("Active mem", &gApp.sc.workingSetOnly);
    Tip("Only scan pages currently in the target's working set (resident in RAM).  Much faster on bloated processes; skips paged-out memory.");

    ImGui::SetNextItemWidth(140);
    ImGui::InputTextWithHint("##mf", "substring", gApp.sc.modFilter, sizeof(gApp.sc.modFilter));
    ImGui::SameLine(); ImGui::TextDisabled("Mod filter");
    ImGui::SameLine(); ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##amin", "addr start (0x...)", gApp.sc.addrMinBuf, sizeof(gApp.sc.addrMinBuf));
    Tip("Restrict scan to addresses >= this value.  Hex with 0x prefix.  Leave empty for no lower limit.");
    ImGui::SameLine(); ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##amax", "addr stop (0x...)", gApp.sc.addrMaxBuf, sizeof(gApp.sc.addrMaxBuf));
    Tip("Restrict scan to addresses <= this value.  Example:  0x7FFFFFFFFFFF caps to user-mode space.");

    ImGui::SetNextItemWidth(100); ImGui::InputTextWithHint("##rmin", "val min", gApp.sc.rangeMin, sizeof(gApp.sc.rangeMin));
    ImGui::SameLine(); ImGui::SetNextItemWidth(100); ImGui::InputTextWithHint("##rmax", "val max", gApp.sc.rangeMax, sizeof(gApp.sc.rangeMax));
    ImGui::SameLine(); ImGui::TextDisabled("Initial-value range (numeric only)");

    const char* alignItems[] = { "Auto", "1 byte", "2 byte", "4 byte", "8 byte" };
    ImGui::SetNextItemWidth(110);
    ImGui::Combo("Align##fal", &gApp.sc.alignmentIdx, alignItems, IM_ARRAYSIZE(alignItems));
    Tip("Skip unaligned addresses.  Auto = use the data-type size (4 for int32, 8 for int64).  Smaller alignment = slower but catches more.");
    ImGui::SameLine(); ImGui::Checkbox("Skip zero", &gApp.sc.skipZero);
    Tip("Skip addresses whose value is all-zero.  Massive speedup for processes with huge zero-init regions.");
    ImGui::SameLine(); ImGui::SetNextItemWidth(100);
    ImGui::InputTextWithHint("##suf", "skip suffix", gApp.sc.skipSuffix, sizeof(gApp.sc.skipSuffix));
    Tip("Skip addresses whose lower hex digits match.  E.g. '00' skips every page-aligned bottom, 'FFF' skips end-of-page positions.  Empty = off.");

    SectionLabel("2.  Scan");
    bool busy = gApp.scanBusy.load();
    ImGui::BeginDisabled(!isAttached() || busy);
    if (ColorButton("First Scan", clr::accent, ImVec2(120, 0))) DoScanAsync(true);
    Tip("Start a fresh scan over all readable memory.  Captures every address whose value matches the current Type / Match / Value / Range / filters.  Hotkey: F6.");
    ImGui::SameLine();
    if (ImGui::Button("Next Scan", ImVec2(120, 0))) DoScanAsync(false);
    Tip("Refine the current result set by re-reading each address and keeping only those that still match.  Use after changing Value or Match.  Hotkey: F7.");
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!busy);
    if (ColorButton("Stop", clr::err, ImVec2(80, 0))) g_scanStopRequested = true;
    Tip("Cancel the in-progress scan immediately, keeping whatever partial results were already captured.  Hotkey: F8.");
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Clear", ImVec2(70, 0))) { mem::clearScan(); gApp.selAddr = nullptr; gApp.setStatus("Cleared.", "info"); }
    Tip("Wipe results, snapshot, and live-monitor data.  Doesn't detach.");
    ImGui::SameLine();
    if (ImGui::Button("Export CSV", ImVec2(100, 0))) {
        size_t n = mem::exportResultsToCsv("memiscani_results.csv", dt);
        char b[120]; sprintf(b, "Exported %zu rows -> memiscani_results.csv", n); gApp.setStatus(b, "ok");
    }
    if (busy) { ImGui::SameLine(); ImGui::TextColored(clr::warn, "  scanning... %zu so far", g_scan.results.size()); }

    SectionLabel("3.  Refine - Snapshot / Diff");
    HintText("Capture current values with 'Snapshot'.  Trigger an event in the target.  Then keep only addresses that Changed / Stayed / Increased / Decreased.");
    ImGui::BeginDisabled(!isAttached() || g_scan.results.empty());
    if (ColorButton("Take Snapshot", clr::accentH, ImVec2(140, 0))) { takeSnapshot(dt); gApp.setStatus("Snapshot captured.", "ok"); }
    Tip("Capture the current value at every result address.  Trigger your in-game event next, then use Find Changed / Inc / Dec to filter.  Hotkey: F9.");
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!isAttached() || g_snapshot.empty());
    if (ImGui::Button("Find Changed",   ImVec2(120, 0))) { std::string e; if (!filterByDiff(dt, 0, e)) gApp.setStatus(e, "err"); else gApp.setStatus("Filtered.", "ok"); }
    Tip("Keep only addresses whose value DIFFERS from the snapshot.  Hotkey: F10.");
    ImGui::SameLine();
    if (ImGui::Button("Find Unchanged", ImVec2(120, 0))) { std::string e; if (!filterByDiff(dt, 1, e)) gApp.setStatus(e, "err"); else gApp.setStatus("Filtered.", "ok"); }
    Tip("Keep only addresses that haven't moved since the snapshot - good for stable settings.");
    ImGui::SameLine();
    if (ImGui::Button("Inc Since",      ImVec2(100, 0))) { std::string e; if (!filterByDiff(dt, 2, e)) gApp.setStatus(e, "err"); else gApp.setStatus("Filtered.", "ok"); }
    Tip("Keep addresses whose value went UP since the snapshot (HP regen, XP gain).");
    ImGui::SameLine();
    if (ImGui::Button("Dec Since",      ImVec2(100, 0))) { std::string e; if (!filterByDiff(dt, 3, e)) gApp.setStatus(e, "err"); else gApp.setStatus("Filtered.", "ok"); }
    Tip("Keep addresses whose value went DOWN since the snapshot (damage, spend).");
    ImGui::EndDisabled();

    SectionLabel("4.  Refine - Live Monitor + Score");
    HintText("Live samples every result at 50 ms.  Trigger events repeatedly, then Keep-Chg filters anything that moved, Score Now ranks by likelihood of being a real game variable, Keep Bounded keeps tightly-ranged values (HP-like).");
    ImGui::BeginDisabled(!isAttached() || g_scan.results.empty());
    if (mem::g_liveMonActive) {
        if (ColorButton("Stop Live", clr::warn, ImVec2(100,0))) { liveMonStop(); gApp.setStatus("Live off.", "info"); }
        Tip("Stop the 50ms background sampler.  Hotkey: F11.");
    } else {
        if (ColorButton("Start Live", clr::ok,   ImVec2(100,0))) { liveMonStart(dt); gApp.setStatus("Live on (50 ms).", "ok"); }
        Tip("Start sampling every result address every 50 ms.  Captures flickering values that a normal scan would miss.  Hotkey: F11.");
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(g_liveStats.empty());
    if (ImGui::Button("Keep Chg", ImVec2(90, 0))) { liveMonStop(); std::string e; if (!filterByLiveChanged(dt, e)) gApp.setStatus(e, "err"); else gApp.setStatus("Kept changed.", "ok"); }
    Tip("Filter to addresses that changed at least once while Live was on.  Hotkey: F12.");
    ImGui::SameLine();
    if (ImGui::Button("Score Now", ImVec2(100, 0))) { computeLiveScores(dt); gApp.setStatus("Scores recomputed.", "ok"); }
    Tip("Compute a 0-100 likelihood score per address based on rate of change, bounded range, alignment, and round baseline.  Shows in the Score column.");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(60); ImGui::InputText("Top##topn", gApp.sc.topNBuf, sizeof(gApp.sc.topNBuf), ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    if (ImGui::Button("Keep Top", ImVec2(90, 0))) { liveMonStop(); std::string e; int n = atoi(gApp.sc.topNBuf); if (n<1) n=100; if (!filterTopByScore(n, dt, e)) gApp.setStatus(e, "err"); else gApp.setStatus("Kept top.", "ok"); }
    Tip("Keep the highest-scored N rows (drops live-monitor noise).  Typical real game variables rank top 5-50.");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(70); ImGui::InputText("MaxD##bnd", gApp.sc.maxDBuf, sizeof(gApp.sc.maxDBuf));
    ImGui::SameLine();
    if (ImGui::Button("Keep Bounded", ImVec2(120, 0))) { liveMonStop(); std::string e; double m=atof(gApp.sc.maxDBuf); if (m<=0) m=100; if (!filterByBoundedRange(m, dt, e)) gApp.setStatus(e, "err"); else gApp.setStatus("Kept bounded.", "ok"); }
    Tip("Keep rows whose total swing (max - min) is below MaxD.  Excellent for finding HP-style bounded values, drops counters and pointers.");
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!gApp.selAddr || g_liveStats.empty());
    if (ImGui::Button("History", ImVec2(80, 0))) { gApp.historyAddr = gApp.selAddr; gApp.showHistory = true; }
    Tip("Open the change history for the selected address - every recorded value with its age in ms.");
    ImGui::EndDisabled();

    SectionLabel("5.  Results");
    ImGui::SetNextItemWidth(240);
    ImGui::InputTextWithHint("##filter", "filter (substring on address)", gApp.sc.rowFilter, sizeof(gApp.sc.rowFilter));
    ImGui::SameLine();
    if (ColorButton("Fullscreen", clr::accent, ImVec2(110, 0))) gApp.sc.fullscreen = true;
    ImGui::SameLine();
    ImGui::Checkbox("As Text", &gApp.sc.showAsText);
    Tip("Show the Value column as printable ASCII text (bytes at each address) instead of the typed/numeric value.");
    ImGui::SameLine();
    ImGui::TextDisabled("shown %zu of %zu  (cap 5000 in UI)", std::min((size_t)5000, g_scan.results.size()), g_scan.results.size());

    DrawResultsTable(false);
}

static void DrawHistoryModal() {
    using namespace mem;
    if (!gApp.showHistory) return;
    ImGui::OpenPopup("Value History");
    if (ImGui::BeginPopupModal("Value History", &gApp.showHistory, ImGuiWindowFlags_AlwaysAutoResize)) {
        size_t idx = (size_t)-1;
        for (size_t i = 0; i < g_scan.results.size(); i++) if (g_scan.results[i] == gApp.historyAddr) { idx = i; break; }
        if (idx == (size_t)-1 || idx >= g_liveStats.size()) ImGui::Text("No live data for this address.");
        else {
            const LiveStat& s = g_liveStats[idx];
            DataType dt = (DataType)g_liveMonDt;
            char buf[80]; sprintf(buf, "0x%llX", (unsigned long long)(uintptr_t)gApp.historyAddr);
            ImGui::TextColored(clr::accent, "Address:  %s", buf);
            ImGui::Text("Baseline: %s", formatTypedValue(s.baseline, dt).c_str());
            ImGui::Text("Current:  %s", formatTypedValue(s.last, dt).c_str());
            if (s.minMaxInit) ImGui::Text("Min: %s    Max: %s", formatTypedValue(s.minV, dt).c_str(), formatTypedValue(s.maxV, dt).c_str());
            ImGui::Text("Samples: %u    Changes: %u    Score: %.0f", s.sampleCount, s.changeCount, s.score);
            ImGui::Separator();
            ImGui::TextDisabled("Recent changes (newest first):");
            if (ImGui::BeginTable("hist", 2, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg, ImVec2(420, 280))) {
                ImGui::TableSetupColumn("Age", ImGuiTableColumnFlags_WidthFixed, 100);
                ImGui::TableSetupColumn("Value"); ImGui::TableHeadersRow();
                DWORD now = GetTickCount();
                uint8_t start = (uint8_t)((s.historyHead + 16 - s.historyCount) % 16);
                for (int k = s.historyCount - 1; k >= 0; k--) {
                    uint8_t pos = (uint8_t)((start + k) % 16);
                    BYTE padded[16] = {}; memcpy(padded, s.history[pos], 8);
                    DWORD age = now - s.historyTime[pos];
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::Text("%lu ms", age);
                    ImGui::TableSetColumnIndex(1); ImGui::Text("%s", formatTypedValue(padded, dt).c_str());
                }
                ImGui::EndTable();
            }
        }
        if (ImGui::Button("Close")) { gApp.showHistory = false; ImGui::CloseCurrentPopup(); }
        ImGui::EndPopup();
    }
}

static void DrawModulesTab() {
    SectionLabel("Loaded modules");
    HintText("Click Refresh to enumerate loaded modules.  Use the filter to narrow.  Select a row + Inject / Eject below.");
    if (ImGui::Button("Refresh", ImVec2(100, 0))) { gApp.mods.list = mem::listModules(); gApp.setStatus("Module list refreshed.", "ok"); }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220);
    ImGui::InputTextWithHint("##modfilter", "filter substring", gApp.mods.filter, sizeof(gApp.mods.filter));

    if (ImGui::BeginTable("mods", 4, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable|ImGuiTableFlags_Sortable, ImVec2(0, 360))) {
        ImGui::TableSetupScrollFreeze(0,1);
        ImGui::TableSetupColumn("Name",  ImGuiTableColumnFlags_WidthFixed, 280);
        ImGui::TableSetupColumn("Base",  ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableSetupColumn("Size",  ImGuiTableColumnFlags_WidthFixed, 100);
        ImGui::TableSetupColumn("Path");
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < gApp.mods.list.size(); i++) {
            const auto& m = gApp.mods.list[i];
            if (gApp.mods.filter[0]) {
                std::string lo = m.name; for (auto& c : lo) c = (char)std::tolower((unsigned char)c);
                std::string fl = gApp.mods.filter; for (auto& c : fl) c = (char)std::tolower((unsigned char)c);
                if (lo.find(fl) == std::string::npos) continue;
            }
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            char idLbl[300]; sprintf(idLbl, "%s##m%zu", m.name.c_str(), i);
            if (ImGui::Selectable(idLbl, gApp.mods.selected == (int)i, ImGuiSelectableFlags_SpanAllColumns)) {
                gApp.mods.selected = (int)i;
                strncpy(gApp.mods.ejectName, m.name.c_str(), sizeof(gApp.mods.ejectName)-1);
            }
            ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", (unsigned long long)m.base);
            ImGui::TableSetColumnIndex(2); ImGui::Text("%zu KB", m.size/1024);
            ImGui::TableSetColumnIndex(3); ImGui::TextDisabled("%s", m.path.c_str());
        }
        ImGui::EndTable();
    }

    SectionLabel("DLL Inject");
    HintText("Inject a DLL by absolute path.  This calls LoadLibraryA in the target via CreateRemoteThread.");
    ImGui::SetNextItemWidth(620);
    ImGui::InputTextWithHint("##dllp", "C:\\path\\to\\my.dll", gApp.mods.dllPath, sizeof(gApp.mods.dllPath));
    ImGui::SameLine();
    ImGui::BeginDisabled(!mem::isAttached() || !gApp.mods.dllPath[0]);
    if (ColorButton("Inject DLL", clr::accent, ImVec2(140, 0))) {
        std::string err;
        if (mem::injectDLL(gApp.mods.dllPath, err)) gApp.setStatus("Injected DLL.", "ok");
        else                                         gApp.setStatus("Inject failed: " + err, "err");
    }
    ImGui::EndDisabled();

    SectionLabel("DLL Eject");
    HintText("Find a loaded module by name substring and call FreeLibrary in the target.");
    ImGui::SetNextItemWidth(300);
    ImGui::InputTextWithHint("##ejname", "name substring", gApp.mods.ejectName, sizeof(gApp.mods.ejectName));
    ImGui::SameLine();
    ImGui::BeginDisabled(!mem::isAttached() || !gApp.mods.ejectName[0]);
    if (ColorButton("Eject DLL", clr::warn, ImVec2(140, 0))) {
        std::string err;
        if (mem::ejectDLL(gApp.mods.ejectName, err)) gApp.setStatus("Ejected module.", "ok");
        else                                          gApp.setStatus("Eject failed: " + err, "err");
    }
    ImGui::EndDisabled();
}

static std::vector<BYTE> parseHexBytes(const char* s) {
    std::vector<BYTE> out;
    while (*s) {
        while (*s == ' ' || *s == '\t' || *s == ',') s++;
        if (!*s) break;
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
        char* e = nullptr; unsigned long v = strtoul(s, &e, 16);
        if (e == s) break;
        out.push_back((BYTE)(v & 0xFF));
        s = e;
    }
    return out;
}

static void DrawPatcherTab() {
    SectionLabel("Read bytes");
    HintText("Read N bytes at an address.  Address accepts 0x prefix.");
    ImGui::SetNextItemWidth(220); ImGui::InputTextWithHint("##paddr", "address (0x...)", gApp.patch.addrBuf, sizeof(gApp.patch.addrBuf));
    ImGui::SameLine(); ImGui::SetNextItemWidth(80); ImGui::InputText("Size##psz", gApp.patch.sizeBuf, sizeof(gApp.patch.sizeBuf), ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    ImGui::BeginDisabled(!mem::isAttached());
    if (ImGui::Button("Read", ImVec2(80, 0))) {
        uintptr_t a = (uintptr_t)mem::parseHexAwareInt(gApp.patch.addrBuf);
        size_t n = (size_t)atoi(gApp.patch.sizeBuf); if (n < 1) n = 16;
        std::string err;
        if (!mem::patcherRead(a, n, gApp.patch.readOut, err)) gApp.setStatus("Read failed: " + err, "err");
        else { char b[80]; sprintf(b, "Read %zu bytes", gApp.patch.readOut.size()); gApp.setStatus(b, "ok"); gApp.patch.lastReadAddr = gApp.patch.addrBuf; }
    }
    ImGui::EndDisabled();
    if (!gApp.patch.readOut.empty()) {
        ImGui::TextDisabled("hex bytes (%s):", gApp.patch.lastReadAddr.c_str());
        std::string hex; char tmp[6];
        for (BYTE b : gApp.patch.readOut) { sprintf(tmp, "%02X ", b); hex += tmp; }
        ImGui::TextWrapped("%s", hex.c_str());
        ImGui::TextDisabled("disasm:");
        uintptr_t a = (uintptr_t)mem::parseHexAwareInt(gApp.patch.addrBuf);
        auto lines = mem::disasmRangeAtRemote((LPVOID)a, gApp.patch.readOut.size(), 32);
        for (auto& l : lines) ImGui::TextColored(clr::accentH, "  0x%llX  %s", (unsigned long long)l.addr, l.text.c_str());
    }

    SectionLabel("Patch bytes");
    HintText("Write arbitrary bytes (hex) at the address above.  Original bytes are kept so you can Restore.");
    ImGui::SetNextItemWidth(620);
    ImGui::InputTextWithHint("##pbytes", "90 90 90  or  E9 12 34 56 78", gApp.patch.bytesBuf, sizeof(gApp.patch.bytesBuf));
    ImGui::BeginDisabled(!mem::isAttached());
    if (ColorButton("Write Bytes", clr::accent, ImVec2(130, 0))) {
        uintptr_t a = (uintptr_t)mem::parseHexAwareInt(gApp.patch.addrBuf);
        auto bytes = parseHexBytes(gApp.patch.bytesBuf);
        std::string err;
        if (!mem::patcherWrite(a, bytes, "bytes", err)) gApp.setStatus("Patch failed: " + err, "err");
        else gApp.setStatus("Patched.", "ok");
    }
    Tip("Write the hex bytes above at Addr.  Saves original bytes so you can Restore from the Applied patches list.");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(70); ImGui::InputText("NOP##nl", gApp.patch.nopLen, sizeof(gApp.patch.nopLen), ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    if (ImGui::Button("NOP N bytes", ImVec2(130, 0))) {
        uintptr_t a = (uintptr_t)mem::parseHexAwareInt(gApp.patch.addrBuf);
        int n = atoi(gApp.patch.nopLen); if (n < 1) n = 1;
        std::string err;
        if (!mem::patcherNop(a, n, "nop", err)) gApp.setStatus("NOP failed: " + err, "err");
        else gApp.setStatus("NOPed.", "ok");
    }
    Tip("Overwrite N bytes at Addr with 0x90 (NOP).  Use the length of the instruction you want to disable (typically 3-7 bytes).");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180); ImGui::InputTextWithHint("##jt", "jmp target 0x...", gApp.patch.jmpTarget, sizeof(gApp.patch.jmpTarget));
    ImGui::SameLine();
    if (ImGui::Button("Near JMP", ImVec2(120, 0))) {
        uintptr_t a = (uintptr_t)mem::parseHexAwareInt(gApp.patch.addrBuf);
        uintptr_t t = (uintptr_t)mem::parseHexAwareInt(gApp.patch.jmpTarget);
        std::string err;
        if (!mem::patcherNearJmp(a, t, "jmp", err)) gApp.setStatus("JMP failed: " + err, "err");
        else gApp.setStatus("Installed near jmp.", "ok");
    }
    Tip("Install a 5-byte 0xE9 (near JMP) at Addr targeting the destination above.  Reversible via Applied patches list.");
    ImGui::EndDisabled();

    SectionLabel("Inline assembler  (x86-64)");
    HintText("Type assembly source - one instruction per line.  Supports labels, db/dw/dd/dq, jmp/call to labels, jcc to labels.  Output goes to the bytes field above so you can Write at the current Address.");
    if (gApp.asmui.src.size() < 4096) gApp.asmui.src.resize(4096);
    ImGui::InputTextMultiline("##asmsrc", gApp.asmui.src.data(), gApp.asmui.src.size(),
                              ImVec2(-1, 120), ImGuiInputTextFlags_AllowTabInput);
    gApp.asmui.src.resize(strlen(gApp.asmui.src.c_str()));
    if (ColorButton("Assemble", clr::accentH, ImVec2(120, 0))) {
        gApp.asmui.bytes.clear();
        gApp.asmui.err.clear();
        if (mem::assembleSource(gApp.asmui.src, gApp.asmui.bytes, gApp.asmui.err)) {
            std::string hex; char tmp[6];
            for (BYTE b : gApp.asmui.bytes) { sprintf(tmp, "%02X ", b); hex += tmp; }
            if (!hex.empty()) hex.pop_back();
            strncpy(gApp.patch.bytesBuf, hex.c_str(), sizeof(gApp.patch.bytesBuf)-1);
            gApp.patch.bytesBuf[sizeof(gApp.patch.bytesBuf)-1] = 0;
            char b[80]; sprintf(b, "Assembled %zu byte(s) into bytes field.", gApp.asmui.bytes.size());
            gApp.setStatus(b, "ok");
        } else gApp.setStatus("Assemble failed: " + gApp.asmui.err, "err");
    }
    Tip("Assemble the x86-64 source above to hex bytes.  Supports mov/lea/push/pop/add/or/and/sub/xor/cmp/test/call/jmp + labels and jcc to labels.  Bytes go into the Write Bytes field for one-click patching.");
    ImGui::SameLine();
    if (!gApp.asmui.bytes.empty()) {
        std::string hex; char tmp[6];
        for (BYTE b : gApp.asmui.bytes) { sprintf(tmp, "%02X ", b); hex += tmp; }
        ImGui::TextColored(clr::ok, "%s", hex.c_str());
    } else if (!gApp.asmui.err.empty()) {
        ImGui::TextColored(clr::err, "%s", gApp.asmui.err.c_str());
    }

    SectionLabel("AOB signature generator");
    HintText("Build a unique byte pattern at the current Address with smart wildcards on RIP-relative / call+jmp displacements.  The pattern survives game updates that relocate addresses.");
    ImGui::BeginDisabled(!mem::isAttached());
    if (ColorButton("Generate signature", clr::accent, ImVec2(190, 0))) {
        uintptr_t a = (uintptr_t)mem::parseHexAwareInt(gApp.patch.addrBuf);
        gApp.sig.lastSig = mem::generateAobSignature((LPVOID)a, 12, 64);
        gApp.sig.haveSig = true;
        gApp.setStatus(gApp.sig.lastSig.unique ? "Unique signature found." : "Signature is NOT unique - increase length manually.",
                       gApp.sig.lastSig.unique ? "ok" : "warn");
    }
    Tip("Decode instructions at the current Addr with Zydis, mark RIP-relative + call/jmp displacement bytes as wildcards (?\?), expand length until pattern matches only one location in module memory.  Result survives game updates.");
    ImGui::EndDisabled();
    if (gApp.sig.haveSig) {
        ImGui::TextDisabled("length %zu  wildcards %zu  matches %zu  %s",
            gApp.sig.lastSig.length, gApp.sig.lastSig.wildcards, gApp.sig.lastSig.hits,
            gApp.sig.lastSig.unique ? "(unique)" : "(NOT unique)");
        ImGui::PushStyleColor(ImGuiCol_Text, gApp.sig.lastSig.unique ? clr::ok : clr::warn);
        ImGui::TextWrapped("%s", gApp.sig.lastSig.pattern.c_str());
        ImGui::PopStyleColor();
        if (ImGui::Button("Copy pattern to clipboard")) {
            ImGui::SetClipboardText(gApp.sig.lastSig.pattern.c_str());
            gApp.setStatus("Pattern copied.", "ok");
        }
    }

    SectionLabel("Trampoline hook  (CE-style code cave + JMP)");
    HintText("Splice a JMP at Target to a cave that runs your payload, replays the original (relocated) bytes, and JMPs back.  Payload is assembly source - use the inline assembler.");
    ImGui::SetNextItemWidth(220); ImGui::InputTextWithHint("##htg", "target 0x...", gApp.hook.targetBuf, sizeof(gApp.hook.targetBuf));
    ImGui::SameLine(); ImGui::SetNextItemWidth(80); ImGui::InputText("Stolen##hs", gApp.hook.stolenBuf, sizeof(gApp.hook.stolenBuf), ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    if (ImGui::Button("From Patcher Addr", ImVec2(160, 0))) strncpy(gApp.hook.targetBuf, gApp.patch.addrBuf, sizeof(gApp.hook.targetBuf)-1);
    if (gApp.hook.payloadSrc.size() < 1024) gApp.hook.payloadSrc.resize(1024);
    ImGui::TextDisabled("Payload asm:");
    ImGui::InputTextMultiline("##hp", gApp.hook.payloadSrc.data(), gApp.hook.payloadSrc.size(),
                              ImVec2(-1, 100), ImGuiInputTextFlags_AllowTabInput);
    gApp.hook.payloadSrc.resize(strlen(gApp.hook.payloadSrc.c_str()));
    ImGui::BeginDisabled(!mem::isAttached());
    if (ColorButton("Install hook", clr::accent, ImVec2(140, 0))) {
        uintptr_t t = (uintptr_t)mem::parseHexAwareInt(gApp.hook.targetBuf);
        size_t st = (size_t)atoi(gApp.hook.stolenBuf); if (st < 14) st = 14;
        std::vector<BYTE> payload; std::string aerr;
        if (gApp.hook.payloadSrc.empty() || !mem::assembleSource(gApp.hook.payloadSrc, payload, aerr)) {
            gApp.setStatus("Hook payload didn't assemble: " + aerr, "err");
        } else {
            std::string err;
            if (mem::installTrampoline((LPVOID)t, payload, st, "user", err)) gApp.setStatus("Hook installed.", "ok");
            else gApp.setStatus("Hook failed: " + err, "err");
        }
    }
    Tip("Splice an absolute JMP at Target to a fresh code cave that runs your payload, replays the (relocated) stolen bytes, then JMPs back.  Reversible via the row's Uninstall button.");
    ImGui::EndDisabled();

    if (!mem::g_thooks.empty()) {
        if (ImGui::BeginTable("hooks", 4, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0, 180))) {
            ImGui::TableSetupColumn("Target", ImGuiTableColumnFlags_WidthFixed, 180);
            ImGui::TableSetupColumn("Cave",   ImGuiTableColumnFlags_WidthFixed, 180);
            ImGui::TableSetupColumn("Stolen", ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 120);
            ImGui::TableHeadersRow();
            for (size_t i = 0; i < mem::g_thooks.size(); i++) {
                const auto& h = mem::g_thooks[i];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::Text("0x%llX", (unsigned long long)(uintptr_t)h.target);
                ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", (unsigned long long)(uintptr_t)h.cave);
                ImGui::TableSetColumnIndex(2); ImGui::Text("%zu", h.stolenLen);
                ImGui::TableSetColumnIndex(3);
                char b[40]; sprintf(b, "Uninstall##uh%zu", i);
                if (ImGui::Button(b)) { std::string err; mem::uninstallTrampoline(i, err); break; }
            }
            ImGui::EndTable();
        }
    }

    SectionLabel("Applied patches");
    HintText("Each patch is reversible.  Select a row and click Restore to put the original bytes back.");
    if (ImGui::BeginTable("patches", 4, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0, 220))) {
        ImGui::TableSetupColumn("Addr",  ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthFixed, 120);
        ImGui::TableSetupColumn("Bytes");
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 100);
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < mem::g_patches.size(); i++) {
            const auto& p = mem::g_patches[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::Text("0x%llX", (unsigned long long)p.addr);
            ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%s", p.label.c_str());
            ImGui::TableSetColumnIndex(2);
            std::string hex; char tmp[6];
            for (size_t k = 0; k < p.applied.size() && k < 16; k++) { sprintf(tmp, "%02X ", p.applied[k]); hex += tmp; }
            if (p.applied.size() > 16) hex += "...";
            ImGui::Text("%s", hex.c_str());
            ImGui::TableSetColumnIndex(3);
            char btn[32]; sprintf(btn, "Restore##rp%zu", i);
            if (ImGui::Button(btn, ImVec2(80, 0))) {
                std::string err;
                if (mem::patcherRestore(i, err)) { gApp.setStatus("Restored.", "ok"); break; }
                else gApp.setStatus("Restore failed: " + err, "err");
            }
        }
        ImGui::EndTable();
    }
}

static std::vector<intptr_t> parseOffsetList(const char* s) {
    std::vector<intptr_t> out;
    while (*s) {
        while (*s == ' ' || *s == '\t' || *s == ',') s++;
        if (!*s) break;
        bool neg = false;
        if (*s == '-') { neg = true; s++; }
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
        char* e = nullptr; long long v = _strtoi64(s, &e, 16);
        if (e == s) break;
        out.push_back(neg ? -(intptr_t)v : (intptr_t)v);
        s = e;
    }
    return out;
}

static void DrawPointersTab() {
    SectionLabel("Pointer chains");
    HintText("Each chain = module + base offset + a list of dereferences.  Final address = resolveChain(...).  Save / Load persists the table to disk.");
    ImGui::SetNextItemWidth(160); ImGui::InputTextWithHint("##cn", "name", gApp.ptrs.name, sizeof(gApp.ptrs.name));
    ImGui::SameLine(); ImGui::SetNextItemWidth(140); ImGui::InputTextWithHint("##cm", "module (e.g. game.exe)", gApp.ptrs.modName, sizeof(gApp.ptrs.modName));
    ImGui::SameLine(); ImGui::SetNextItemWidth(140); ImGui::InputTextWithHint("##cb", "base off (hex)", gApp.ptrs.baseHex, sizeof(gApp.ptrs.baseHex));
    ImGui::SetNextItemWidth(440); ImGui::InputTextWithHint("##co", "offsets, comma-sep hex (e.g. 0x10, 0x50, 0x0)", gApp.ptrs.offsHex, sizeof(gApp.ptrs.offsHex));
    ImGui::SameLine();
    if (ImGui::Button("Add chain", ImVec2(120, 0))) {
        mem::PointerChain c;
        c.name = gApp.ptrs.name; c.moduleName = gApp.ptrs.modName;
        c.moduleOffset = (uintptr_t)mem::parseHexAwareInt(gApp.ptrs.baseHex);
        c.offsets = parseOffsetList(gApp.ptrs.offsHex);
        mem::g_chains.push_back(c);
        gApp.setStatus("Chain added.", "ok");
    }
    ImGui::SameLine();
    if (ImGui::Button("Save", ImVec2(60, 0))) { mem::saveChains("memiscani_chains.txt"); gApp.setStatus("Saved chains.", "ok"); }
    ImGui::SameLine();
    if (ImGui::Button("Load", ImVec2(60, 0))) { mem::loadChains("memiscani_chains.txt"); gApp.setStatus("Loaded chains.", "ok"); }

    if (ImGui::BeginTable("chains", 6, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0, 320))) {
        ImGui::TableSetupColumn("#",       ImGuiTableColumnFlags_WidthFixed, 40);
        ImGui::TableSetupColumn("Name",    ImGuiTableColumnFlags_WidthFixed, 160);
        ImGui::TableSetupColumn("Module",  ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Base off",ImGuiTableColumnFlags_WidthFixed, 110);
        ImGui::TableSetupColumn("Offsets");
        ImGui::TableSetupColumn("Resolve", ImGuiTableColumnFlags_WidthFixed, 220);
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < mem::g_chains.size(); i++) {
            const auto& c = mem::g_chains[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            char idLbl[40]; sprintf(idLbl, "%zu##chx%zu", i+1, i);
            if (ImGui::Selectable(idLbl, gApp.ptrs.selected == (int)i, ImGuiSelectableFlags_SpanAllColumns)) gApp.ptrs.selected = (int)i;
            ImGui::TableSetColumnIndex(1); ImGui::Text("%s", c.name.c_str());
            ImGui::TableSetColumnIndex(2); ImGui::TextDisabled("%s", c.moduleName.c_str());
            ImGui::TableSetColumnIndex(3); ImGui::Text("0x%llX", (unsigned long long)c.moduleOffset);
            ImGui::TableSetColumnIndex(4);
            std::string offs; char tmp[32];
            for (size_t k = 0; k < c.offsets.size(); k++) { sprintf(tmp, "%s0x%llX", k?",":"", (unsigned long long)c.offsets[k]); offs += tmp; }
            ImGui::Text("%s", offs.c_str());
            ImGui::TableSetColumnIndex(5);
            char btn[40]; sprintf(btn, "Resolve##r%zu", i);
            if (ImGui::Button(btn, ImVec2(90, 0))) {
                std::string err; uintptr_t a = mem::resolveChain(c, err);
                if (a) { gApp.selAddr = (LPVOID)a; char b[80]; sprintf(b, "Resolved to 0x%llX", (unsigned long long)a); gApp.setStatus(b, "ok"); }
                else   gApp.setStatus("Resolve failed: " + err, "err");
            }
            ImGui::SameLine();
            char btnD[40]; sprintf(btnD, "Del##d%zu", i);
            if (ImGui::Button(btnD, ImVec2(50, 0))) { mem::g_chains.erase(mem::g_chains.begin() + i); break; }
        }
        ImGui::EndTable();
    }
}

static void LoadSelectedCheatIntoEditor() {
    if (gApp.cheats.selected < 0 || gApp.cheats.selected >= (int)mem::g_cheats.size()) {
        gApp.cheats.nameBuf[0] = 0; gApp.cheats.hotkeyBuf[0] = 0; gApp.cheats.scriptEdit.clear();
        return;
    }
    const auto& c = mem::g_cheats[gApp.cheats.selected];
    strncpy(gApp.cheats.nameBuf, c.name.c_str(), sizeof(gApp.cheats.nameBuf)-1); gApp.cheats.nameBuf[sizeof(gApp.cheats.nameBuf)-1]=0;
    const char* h = "";
    switch (c.hotkeyVK) { case VK_F1: h="F1"; break; case VK_F2: h="F2"; break; case VK_F3: h="F3"; break; case VK_F4: h="F4"; break; case VK_F5: h="F5"; break; }
    strncpy(gApp.cheats.hotkeyBuf, h, sizeof(gApp.cheats.hotkeyBuf)-1); gApp.cheats.hotkeyBuf[sizeof(gApp.cheats.hotkeyBuf)-1]=0;
    gApp.cheats.scriptEdit = c.script;
}

static void ApplyCheatEditor() {
    if (gApp.cheats.selected < 0 || gApp.cheats.selected >= (int)mem::g_cheats.size()) return;
    auto& c = mem::g_cheats[gApp.cheats.selected];
    c.name = gApp.cheats.nameBuf; c.script = gApp.cheats.scriptEdit;
    std::string hk = gApp.cheats.hotkeyBuf;
    for (auto& ch : hk) ch = (char)std::toupper((unsigned char)ch);
    c.hotkeyVK = (hk == "F1") ? VK_F1 : (hk == "F2") ? VK_F2 : (hk == "F3") ? VK_F3 : (hk == "F4") ? VK_F4 : (hk == "F5") ? VK_F5 : 0;
}

static void DrawCheatsTab() {
    SectionLabel("Cheat table");
    HintText("CE-style scripts.  Each entry has [ENABLE] and [DISABLE] sections.  Address form:  game.exe+1234:  or  7FF6...:  followed by  db / dw / dd / dq / nop.");
    if (ImGui::Button("New", ImVec2(70, 0))) {
        mem::CheatEntry c;
        c.name = "New cheat";
        c.script = "[ENABLE]\r\n// game.exe+12345:\r\n//   db 90 90 90 90 90\r\n\r\n[DISABLE]\r\n// game.exe+12345:\r\n//   db F2 49 0F 11\r\n";
        mem::g_cheats.push_back(c);
        gApp.cheats.selected = (int)mem::g_cheats.size() - 1;
        LoadSelectedCheatIntoEditor();
        gApp.setStatus("Cheat added.", "ok");
    }
    ImGui::SameLine();
    if (ImGui::Button("Delete", ImVec2(80, 0))) {
        if (gApp.cheats.selected >= 0 && gApp.cheats.selected < (int)mem::g_cheats.size()) {
            mem::g_cheats.erase(mem::g_cheats.begin() + gApp.cheats.selected);
            if (gApp.cheats.selected >= (int)mem::g_cheats.size()) gApp.cheats.selected = (int)mem::g_cheats.size() - 1;
            LoadSelectedCheatIntoEditor();
            gApp.setStatus("Cheat deleted.", "info");
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Save table", ImVec2(110, 0))) { mem::saveCheats("memiscani_cheats.ct.txt"); gApp.setStatus("Saved cheats.", "ok"); }
    ImGui::SameLine();
    if (ImGui::Button("Load table", ImVec2(110, 0))) { mem::loadCheats("memiscani_cheats.ct.txt"); gApp.cheats.selected = -1; LoadSelectedCheatIntoEditor(); gApp.setStatus("Loaded cheats.", "ok"); }

    ImGui::Columns(2, "##cheatscol", true);
    ImGui::SetColumnWidth(0, 500);

    if (ImGui::BeginTable("cheats", 4, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0, 520))) {
        ImGui::TableSetupColumn("#",      ImGuiTableColumnFlags_WidthFixed, 40);
        ImGui::TableSetupColumn("State",  ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("Hotkey", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("Name");
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < mem::g_cheats.size(); i++) {
            const auto& c = mem::g_cheats[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            char idLbl[40]; sprintf(idLbl, "%zu##c%zu", i+1, i);
            if (ImGui::Selectable(idLbl, gApp.cheats.selected == (int)i, ImGuiSelectableFlags_SpanAllColumns)) {
                gApp.cheats.selected = (int)i; LoadSelectedCheatIntoEditor();
            }
            ImGui::TableSetColumnIndex(1);
            if (c.enabled) ImGui::TextColored(clr::ok, "ON"); else ImGui::TextDisabled("OFF");
            ImGui::TableSetColumnIndex(2);
            const char* h = "";
            switch (c.hotkeyVK) { case VK_F1: h="F1"; break; case VK_F2: h="F2"; break; case VK_F3: h="F3"; break; case VK_F4: h="F4"; break; case VK_F5: h="F5"; break; }
            ImGui::TextDisabled("%s", h);
            ImGui::TableSetColumnIndex(3); ImGui::Text("%s", c.name.c_str());
        }
        ImGui::EndTable();
    }

    ImGui::NextColumn();

    ImGui::TextColored(clr::accent, "Selected cheat");
    if (gApp.cheats.selected < 0) {
        ImGui::TextDisabled("(click a row to edit)");
    } else {
        ImGui::SetNextItemWidth(280); ImGui::InputText("Name", gApp.cheats.nameBuf, sizeof(gApp.cheats.nameBuf));
        ImGui::SameLine(); ImGui::SetNextItemWidth(60); ImGui::InputTextWithHint("Hotkey##hk", "F1-F5", gApp.cheats.hotkeyBuf, sizeof(gApp.cheats.hotkeyBuf));

        ImGui::TextDisabled("Script:");
        char* sb = (char*)gApp.cheats.scriptEdit.data();
        gApp.cheats.scriptEdit.resize(std::max<size_t>(gApp.cheats.scriptEdit.size(), 4096));
        ImGui::InputTextMultiline("##script", gApp.cheats.scriptEdit.data(), gApp.cheats.scriptEdit.size(),
                                  ImVec2(-1, 380), ImGuiInputTextFlags_AllowTabInput);

        gApp.cheats.scriptEdit.resize(strlen(gApp.cheats.scriptEdit.c_str()));

        if (ColorButton("Apply edits", clr::accent, ImVec2(110, 0))) { ApplyCheatEditor(); gApp.setStatus("Edits applied.", "ok"); }
        ImGui::SameLine();
        if (ImGui::Button("Toggle ON/OFF", ImVec2(140, 0))) {
            ApplyCheatEditor();
            std::string err;
            if (mem::cheatToggle((size_t)gApp.cheats.selected, err)) {
                gApp.setStatus(mem::g_cheats[gApp.cheats.selected].enabled ? "Enabled." : "Disabled.", "ok");
            } else gApp.setStatus("Toggle failed: " + err, "err");
        }
        ImGui::SameLine();
        if (ImGui::Button("Test ENABLE", ImVec2(120, 0))) {
            ApplyCheatEditor();
            std::string err;
            if (mem::cheatExecute(mem::g_cheats[gApp.cheats.selected], true, err)) gApp.setStatus("Test ENABLE ok.", "ok");
            else gApp.setStatus("Test ENABLE failed: " + err, "err");
        }
        ImGui::SameLine();
        if (ImGui::Button("Test DISABLE", ImVec2(130, 0))) {
            ApplyCheatEditor();
            std::string err;
            if (mem::cheatExecute(mem::g_cheats[gApp.cheats.selected], false, err)) gApp.setStatus("Test DISABLE ok.", "ok");
            else gApp.setStatus("Test DISABLE failed: " + err, "err");
        }
    }
    ImGui::Columns(1);
}

static void DrawDisasmTab() {
    SectionLabel("Disasm walker (Zydis x86-64)");
    HintText("Disassemble N bytes at any address.  Use 'From selected' to import the Scanner-selected address.");
    ImGui::SetNextItemWidth(220); ImGui::InputTextWithHint("##dat", "target 0x...", gApp.dis.targetBuf, sizeof(gApp.dis.targetBuf));
    ImGui::SameLine(); ImGui::SetNextItemWidth(80); ImGui::InputText("Bytes##dsz", gApp.dis.sizeBuf, sizeof(gApp.dis.sizeBuf), ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    if (ImGui::Button("From selected", ImVec2(140, 0)) && gApp.selAddr) {
        sprintf(gApp.dis.targetBuf, "0x%llX", (unsigned long long)(uintptr_t)gApp.selAddr);
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(!mem::isAttached());
    if (ColorButton("Disassemble", clr::accent, ImVec2(140, 0))) {
        uintptr_t a = (uintptr_t)mem::parseHexAwareInt(gApp.dis.targetBuf);
        size_t n = (size_t)atoi(gApp.dis.sizeBuf); if (n < 1) n = 64;
        gApp.dis.lines = mem::disasmRangeAtRemote((LPVOID)a, n, 256);
        char b[80]; sprintf(b, "Decoded %zu instruction(s)", gApp.dis.lines.size());
        gApp.setStatus(b, "ok");
    }
    ImGui::EndDisabled();

    if (ImGui::BeginTable("disasm", 3, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0, 560))) {
        ImGui::TableSetupColumn("Address",   ImGuiTableColumnFlags_WidthFixed, 200);
        ImGui::TableSetupColumn("Bytes",     ImGuiTableColumnFlags_WidthFixed, 240);
        ImGui::TableSetupColumn("Instruction");
        ImGui::TableHeadersRow();
        for (const auto& l : gApp.dis.lines) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::Text("0x%llX", (unsigned long long)l.addr);
            ImGui::TableSetColumnIndex(1);
            std::string hex; char tmp[6];
            for (BYTE b : l.bytes) { sprintf(tmp, "%02X ", b); hex += tmp; }
            ImGui::TextDisabled("%s", hex.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextColored(clr::accentH, "%s", l.text.c_str());
        }
        ImGui::EndTable();
    }
}

static void DrawCodeInjTab() {
    SectionLabel("Inject shellcode");
    HintText("Paste hex bytes (e.g. 90 90 C3 or 90,90,C3 or 0x90 0x90 0xC3).  Inject allocates RWX in target, writes the bytes, optionally starts a new thread at the entry.");
    ImGui::InputTextMultiline("##scbytes", gApp.ci.scBuf, sizeof(gApp.ci.scBuf), ImVec2(-1, 120));
    ImGui::BeginDisabled(!mem::isAttached());
    if (ColorButton("Inject (no exec)", clr::accentH, ImVec2(170, 0))) {
        auto bytes = parseHexBytes(gApp.ci.scBuf);
        std::string err; LPVOID a = mem::injectShellcode(bytes, err);
        if (!a) gApp.setStatus("Inject failed: " + err, "err");
        else { char b[80]; sprintf(b, "Injected at 0x%llX", (unsigned long long)(uintptr_t)a); gApp.setStatus(b, "ok"); sprintf(gApp.trg.addrBuf, "0x%llX", (unsigned long long)(uintptr_t)a); }
    }
    ImGui::SameLine();
    if (ColorButton("Inject + Execute", clr::ok, ImVec2(170, 0))) {
        auto bytes = parseHexBytes(gApp.ci.scBuf);
        std::string err; DWORD tid = 0;
        if (mem::injectAndExecute(bytes, err, &tid)) { char b[80]; sprintf(b, "Executing as TID %lu", tid); gApp.setStatus(b, "ok"); gApp.trg.lastTid = tid; }
        else gApp.setStatus("Inject+Exec failed: " + err, "err");
    }
    ImGui::EndDisabled();

    SectionLabel("Code caves");
    HintText("Scan target memory for contiguous runs of 0x00 / 0x90 / 0xCC bytes of at least Min size.  These are good spots to drop small patches.");
    ImGui::SetNextItemWidth(80); ImGui::InputText("Min size##cc", gApp.ci.caveMin, sizeof(gApp.ci.caveMin), ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    ImGui::BeginDisabled(!mem::isAttached());
    if (ColorButton("Scan caves", clr::accent, ImVec2(140, 0))) {
        size_t n = (size_t)atoi(gApp.ci.caveMin); if (n < 4) n = 32;
        gApp.ci.caves = mem::scanCodeCaves(n);
        char b[80]; sprintf(b, "Found %zu cave(s)", gApp.ci.caves.size()); gApp.setStatus(b, "ok");
    }
    ImGui::EndDisabled();
    if (ImGui::BeginTable("caves", 3, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0, 200))) {
        ImGui::TableSetupColumn("Addr",   ImGuiTableColumnFlags_WidthFixed, 200);
        ImGui::TableSetupColumn("Size",   ImGuiTableColumnFlags_WidthFixed, 100);
        ImGui::TableSetupColumn("Protect");
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < gApp.ci.caves.size(); i++) {
            const auto& c = gApp.ci.caves[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); char idl[60]; sprintf(idl, "0x%llX##c%zu", (unsigned long long)(uintptr_t)c.addr, i);
            if (ImGui::Selectable(idl, false, ImGuiSelectableFlags_SpanAllColumns)) { sprintf(gApp.patch.addrBuf, "0x%llX", (unsigned long long)(uintptr_t)c.addr); gApp.setStatus("Cave address sent to Patcher.", "info"); }
            ImGui::TableSetColumnIndex(1); ImGui::Text("%zu", c.size);
            ImGui::TableSetColumnIndex(2);
            ImGui::TextDisabled("%s",
                (c.protect & PAGE_EXECUTE_READWRITE) ? "RWX" :
                (c.protect & PAGE_EXECUTE_READ)      ? "RX"  :
                (c.protect & PAGE_READWRITE)         ? "RW"  : "?");
        }
        ImGui::EndTable();
    }

    SectionLabel("Remote threads");
    if (ImGui::Button("Refresh threads", ImVec2(150, 0))) { gApp.ci.threads = mem::listRemoteThreads(); gApp.setStatus("Threads refreshed.", "ok"); }
    if (ImGui::BeginTable("threads", 5, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0, 240))) {
        ImGui::TableSetupColumn("TID",     ImGuiTableColumnFlags_WidthFixed, 90);
        ImGui::TableSetupColumn("Start",   ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableSetupColumn("Module+offset");
        ImGui::TableSetupColumn("Priority",ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("Action",  ImGuiTableColumnFlags_WidthFixed, 240);
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < gApp.ci.threads.size(); i++) {
            const auto& t = gApp.ci.threads[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::Text("%lu", t.tid);
            ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", (unsigned long long)(uintptr_t)t.startAddr);
            ImGui::TableSetColumnIndex(2);
            if (!t.startModule.empty()) ImGui::Text("%s+0x%llX", t.startModule.c_str(), (unsigned long long)t.startOffset);
            else ImGui::TextColored(clr::warn, "(not in any module)");
            ImGui::TableSetColumnIndex(3); ImGui::Text("%lu", t.priority);
            ImGui::TableSetColumnIndex(4);
            char b1[24], b2[24], b3[24];
            sprintf(b1,"Susp##s%zu",i); sprintf(b2,"Res##r%zu",i); sprintf(b3,"Kill##k%zu",i);
            std::string err;
            if (ImGui::SmallButton(b1)) { mem::suspendThread(t.tid, err); }
            ImGui::SameLine(); if (ImGui::SmallButton(b2)) { mem::resumeThread(t.tid, err); }
            ImGui::SameLine(); if (ImGui::SmallButton(b3)) { mem::killThread(t.tid, err); gApp.ci.threads = mem::listRemoteThreads(); }
        }
        ImGui::EndTable();
    }
    DrawStackSection();
}

static void DrawWindowsTab() {
    SectionLabel("Target windows");
    HintText("Enumerate top-level HWNDs of the attached process.  Click a row to select.  Then send text or messages, or control window state.");
    if (ImGui::Button("Refresh", ImVec2(100, 0))) { gApp.wnd.wnds = mem::listTargetWindows(); gApp.setStatus("Windows enumerated.", "ok"); }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220);
    ImGui::InputTextWithHint("##wf", "filter substring (title/class)", gApp.wnd.filter, sizeof(gApp.wnd.filter));

    if (ImGui::BeginTable("wnds", 4, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0, 280))) {
        ImGui::TableSetupColumn("HWND",  ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Title", ImGuiTableColumnFlags_WidthFixed, 280);
        ImGui::TableSetupColumn("Class");
        ImGui::TableSetupColumn("Visible", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < gApp.wnd.wnds.size(); i++) {
            const auto& w = gApp.wnd.wnds[i];
            if (gApp.wnd.filter[0]) {
                std::string sum = w.title + " " + w.className;
                std::string lo = sum; for (auto& c : lo) c = (char)std::tolower((unsigned char)c);
                std::string fl = gApp.wnd.filter; for (auto& c : fl) c = (char)std::tolower((unsigned char)c);
                if (lo.find(fl) == std::string::npos) continue;
            }
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            char idl[40]; sprintf(idl, "0x%p##w%zu", (void*)w.hwnd, i);
            if (ImGui::Selectable(idl, gApp.wnd.selected == (int)i, ImGuiSelectableFlags_SpanAllColumns)) gApp.wnd.selected = (int)i;
            ImGui::TableSetColumnIndex(1); ImGui::Text("%s", w.title.c_str());
            ImGui::TableSetColumnIndex(2); ImGui::TextDisabled("%s", w.className.c_str());
            ImGui::TableSetColumnIndex(3);
            if (w.visible) ImGui::TextColored(clr::ok, "yes"); else ImGui::TextDisabled("no");
        }
        ImGui::EndTable();
    }

    SectionLabel("Send / Post");
    bool haveSel = gApp.wnd.selected >= 0 && gApp.wnd.selected < (int)gApp.wnd.wnds.size();
    ImGui::BeginDisabled(!haveSel);
    HWND target = haveSel ? gApp.wnd.wnds[gApp.wnd.selected].hwnd : NULL;

    ImGui::SetNextItemWidth(360); ImGui::InputTextWithHint("##stext", "WM_SETTEXT payload", gApp.wnd.setText, sizeof(gApp.wnd.setText));
    ImGui::SameLine();
    if (ColorButton("Set Text", clr::accent, ImVec2(100, 0))) { mem::sendWindowText(target, gApp.wnd.setText); gApp.setStatus("WM_SETTEXT sent.", "ok"); }

    ImGui::SetNextItemWidth(100); ImGui::InputTextWithHint("Msg##wm", "0x...", gApp.wnd.msgId, sizeof(gApp.wnd.msgId));
    ImGui::SameLine(); ImGui::SetNextItemWidth(80); ImGui::InputText("wParam", gApp.wnd.wpBuf, sizeof(gApp.wnd.wpBuf));
    ImGui::SameLine(); ImGui::SetNextItemWidth(80); ImGui::InputText("lParam", gApp.wnd.lpBuf, sizeof(gApp.wnd.lpBuf));
    ImGui::SameLine();
    if (ColorButton("PostMessage", clr::accent, ImVec2(120, 0))) {
        UINT m = (UINT)mem::parseHexAwareInt(gApp.wnd.msgId);
        WPARAM w = (WPARAM)mem::parseHexAwareInt(gApp.wnd.wpBuf);
        LPARAM l = (LPARAM)mem::parseHexAwareInt(gApp.wnd.lpBuf);
        if (mem::postWindowMessage(target, m, w, l)) gApp.setStatus("PostMessage sent.", "ok");
        else gApp.setStatus("PostMessage failed.", "err");
    }

    ImGui::Text("State:");
    ImGui::SameLine(); if (ImGui::Button("Show",    ImVec2(80,0))) mem::windowShow(target, SW_SHOW);
    ImGui::SameLine(); if (ImGui::Button("Hide",    ImVec2(80,0))) mem::windowShow(target, SW_HIDE);
    ImGui::SameLine(); if (ImGui::Button("Minimize",ImVec2(95,0))) mem::windowShow(target, SW_MINIMIZE);
    ImGui::SameLine(); if (ImGui::Button("Maximize",ImVec2(95,0))) mem::windowShow(target, SW_MAXIMIZE);
    ImGui::SameLine(); if (ImGui::Button("Restore", ImVec2(85,0))) mem::windowShow(target, SW_RESTORE);
    ImGui::SameLine(); if (ColorButton("Close", clr::warn, ImVec2(80,0))) mem::postWindowMessage(target, WM_CLOSE, 0, 0);
    ImGui::EndDisabled();
}

static void DrawDetectTab() {
    SectionLabel("Injection detection");
    HintText("Defensive scan for suspicious memory regions and thread anomalies.  Enable the checks you want, then Run.");
    ImGui::Checkbox("RWX pages",                       &gApp.det.rwx); ImGui::SameLine();
    ImGui::Checkbox("Private executable (manmap suspect)", &gApp.det.privExec); ImGui::SameLine();
    ImGui::Checkbox("Thread start not in any module",  &gApp.det.threadAnom);
    ImGui::BeginDisabled(!mem::isAttached());
    if (ColorButton("Run detection scan", clr::accent, ImVec2(200, 0))) {
        gApp.det.findings = mem::runDetectionScan(gApp.det.rwx, gApp.det.privExec, gApp.det.threadAnom);
        char b[120]; sprintf(b, "%zu finding(s)", gApp.det.findings.size());
        gApp.setStatus(b, gApp.det.findings.empty() ? "ok" : "warn");
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220);
    ImGui::InputTextWithHint("##df", "filter substring", gApp.det.filter, sizeof(gApp.det.filter));

    if (ImGui::BeginTable("det", 4, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable, ImVec2(0, 560))) {
        ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, 120);
        ImGui::TableSetupColumn("Addr",     ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableSetupColumn("Size",     ImGuiTableColumnFlags_WidthFixed, 90);
        ImGui::TableSetupColumn("Detail");
        ImGui::TableHeadersRow();
        for (const auto& f : gApp.det.findings) {
            if (gApp.det.filter[0]) {
                std::string sum = f.category + " " + f.detail;
                std::string lo = sum; for (auto& c : lo) c = (char)std::tolower((unsigned char)c);
                std::string fl = gApp.det.filter; for (auto& c : fl) c = (char)std::tolower((unsigned char)c);
                if (lo.find(fl) == std::string::npos) continue;
            }
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImVec4 col = (f.category == "RWX") ? clr::warn :
                         (f.category == "PRIV+EXEC") ? clr::err :
                         (f.category == "THREAD") ? clr::warn : clr::text;
            ImGui::TextColored(col, "%s", f.category.c_str());
            ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", (unsigned long long)(uintptr_t)f.addr);
            ImGui::TableSetColumnIndex(2); ImGui::Text("%zu", f.size);
            ImGui::TableSetColumnIndex(3); ImGui::Text("%s", f.detail.c_str());
        }
        ImGui::EndTable();
    }
}

static void DrawShellcodeTab() {
    SectionLabel("Shellcode loader");
    HintText("Load a shellcode .bin file, optionally auto-execute via CreateRemoteThread after upload.");
    ImGui::SetNextItemWidth(620);
    ImGui::InputTextWithHint("##spath", "C:\\path\\to\\sc.bin", gApp.shel.path, sizeof(gApp.shel.path));
    if (ImGui::Button("Load file", ImVec2(120, 0))) {
        FILE* f = nullptr;
        if (fopen_s(&f, gApp.shel.path, "rb") == 0 && f) {
            fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
            gApp.shel.bytes.resize(sz);
            if (sz > 0) fread(gApp.shel.bytes.data(), 1, sz, f);
            fclose(f);
            char b[120]; sprintf(b, "Loaded %zu bytes", gApp.shel.bytes.size()); gApp.setStatus(b, "ok");
        } else gApp.setStatus("Load failed.", "err");
    }
    ImGui::SameLine();
    ImGui::Checkbox("Auto-execute after upload", &gApp.shel.autoExec);
    ImGui::SameLine();
    ImGui::BeginDisabled(!mem::isAttached() || gApp.shel.bytes.empty());
    if (ColorButton("Inject", clr::accent, ImVec2(100, 0))) {
        std::string err;
        if (gApp.shel.autoExec) {
            DWORD tid = 0;
            if (mem::injectAndExecute(gApp.shel.bytes, err, &tid)) { char b[80]; sprintf(b, "Executing as TID %lu", tid); gApp.setStatus(b, "ok"); gApp.trg.lastTid = tid; }
            else gApp.setStatus("Inject+Exec failed: " + err, "err");
        } else {
            LPVOID a = mem::injectShellcode(gApp.shel.bytes, err);
            if (a) { char b[80]; sprintf(b, "Injected at 0x%llX", (unsigned long long)(uintptr_t)a); gApp.setStatus(b, "ok"); sprintf(gApp.trg.addrBuf, "0x%llX", (unsigned long long)(uintptr_t)a); }
            else gApp.setStatus("Inject failed: " + err, "err");
        }
    }
    ImGui::EndDisabled();

    if (!gApp.shel.bytes.empty()) {
        SectionLabel("Preview (first 256 bytes)");
        std::string hex; char tmp[6];
        size_t cap = gApp.shel.bytes.size(); if (cap > 256) cap = 256;
        for (size_t i = 0; i < cap; i++) { sprintf(tmp, "%02X ", gApp.shel.bytes[i]); hex += tmp; if ((i & 15) == 15) hex += "\n"; }
        ImGui::TextWrapped("%s", hex.c_str());
        SectionLabel("Disasm (first 256 bytes)");
        auto lines = mem::disasmRangeAtRemote(NULL, 0, 0);
        (void)lines;
        ImGui::TextDisabled("(disasm preview shown after the shellcode is injected - re-open Disasm tab and 'From selected' on the injected address)");
    }
}

static void DrawVerifyTab() {
    SectionLabel("Verification snapshot");
    HintText("Take a snapshot of currently loaded modules + threads.  Then run 'Diff' later to see what's been added or removed.");
    if (ColorButton("Take snapshot", clr::accent, ImVec2(150, 0))) {
        mem::takeVerifySnapshot();
        gApp.ver.haveSnapshot = true;
        gApp.setStatus("Snapshot taken.", "ok");
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(!gApp.ver.haveSnapshot);
    if (ColorButton("Diff now", clr::accentH, ImVec2(120, 0))) {
        gApp.ver.lastDiff = mem::verifyDiffNow();
        gApp.setStatus("Diff computed.", "ok");
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextDisabled(gApp.ver.haveSnapshot
        ? "snapshot: %zu modules, %zu threads"
        : "no snapshot yet",
        gApp.ver.haveSnapshot ? mem::g_verify.modules.size() : 0,
        gApp.ver.haveSnapshot ? mem::g_verify.threads.size() : 0);

    SectionLabel("Diff result");
    ImGui::Columns(2);
    ImGui::TextColored(clr::ok, "Added");
    for (auto& s : gApp.ver.lastDiff.modulesAdded) ImGui::Text("MOD  %s", s.c_str());
    for (auto& s : gApp.ver.lastDiff.threadsAdded) ImGui::Text("THR  %s", s.c_str());
    ImGui::NextColumn();
    ImGui::TextColored(clr::warn, "Removed");
    for (auto& s : gApp.ver.lastDiff.modulesRemoved) ImGui::Text("MOD  %s", s.c_str());
    for (auto& s : gApp.ver.lastDiff.threadsRemoved) ImGui::Text("THR  %s", s.c_str());
    ImGui::Columns(1);
}

static void DrawTriggerTab() {
    SectionLabel("Trigger remote execution");
    HintText("Run code already present in the target process.  CreateRemoteThread starts a new thread at the address.  QueueUserAPC piggybacks on an existing alertable thread by TID.");
    ImGui::SetNextItemWidth(220); ImGui::InputTextWithHint("##tat", "address 0x...", gApp.trg.addrBuf, sizeof(gApp.trg.addrBuf));
    ImGui::SameLine(); ImGui::SetNextItemWidth(220); ImGui::InputTextWithHint("##tpr", "param 0x...", gApp.trg.paramBuf, sizeof(gApp.trg.paramBuf));
    ImGui::BeginDisabled(!mem::isAttached());
    if (ColorButton("CreateRemoteThread", clr::accent, ImVec2(200, 0))) {
        uintptr_t a = (uintptr_t)mem::parseHexAwareInt(gApp.trg.addrBuf);
        uintptr_t p = (uintptr_t)mem::parseHexAwareInt(gApp.trg.paramBuf);
        std::string err; DWORD tid = 0;
        if (mem::triggerCreateRemoteThread((LPVOID)a, (LPVOID)p, &tid, err)) { char b[80]; sprintf(b, "Spawned TID %lu", tid); gApp.setStatus(b, "ok"); gApp.trg.lastTid = tid; sprintf(gApp.trg.tidBuf, "%lu", tid); }
        else gApp.setStatus("CRT failed: " + err, "err");
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(90); ImGui::InputText("TID##tid", gApp.trg.tidBuf, sizeof(gApp.trg.tidBuf), ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    if (ColorButton("QueueUserAPC", clr::accentH, ImVec2(150, 0))) {
        uintptr_t a = (uintptr_t)mem::parseHexAwareInt(gApp.trg.addrBuf);
        uintptr_t p = (uintptr_t)mem::parseHexAwareInt(gApp.trg.paramBuf);
        DWORD tid = (DWORD)atoi(gApp.trg.tidBuf);
        std::string err;
        if (mem::triggerQueueUserAPC(tid, (LPVOID)a, (LPVOID)p, err)) gApp.setStatus("APC queued.", "ok");
        else gApp.setStatus("APC failed: " + err, "err");
    }
    ImGui::SameLine();
    if (ImGui::Button("Use last TID", ImVec2(120, 0))) sprintf(gApp.trg.tidBuf, "%lu", gApp.trg.lastTid);
    ImGui::EndDisabled();
}

static void DrawExportsTab() {
    SectionLabel("Module exports");
    HintText("Parses the PE export directory of every loaded module of the attached process.  Click a row to send the address to the Scanner selected slot.");
    ImGui::BeginDisabled(!mem::isAttached());
    if (ColorButton("Enumerate exports", clr::accent, ImVec2(180, 0))) {
        gApp.exp.rows = mem::enumerateAllExports();
        char b[80]; sprintf(b, "Enumerated %zu exports", gApp.exp.rows.size()); gApp.setStatus(b, "ok");
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(300);
    ImGui::InputTextWithHint("##ef", "filter (module or function name)", gApp.exp.filter, sizeof(gApp.exp.filter));

    if (ImGui::BeginTable("exps", 4, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable, ImVec2(0, 600))) {
        ImGui::TableSetupColumn("Module",  ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableSetupColumn("Ord",     ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < gApp.exp.rows.size(); i++) {
            const auto& r = gApp.exp.rows[i];
            if (gApp.exp.filter[0]) {
                std::string sum = r.module + " " + r.name;
                std::string lo = sum; for (auto& c : lo) c = (char)std::tolower((unsigned char)c);
                std::string fl = gApp.exp.filter; for (auto& c : fl) c = (char)std::tolower((unsigned char)c);
                if (lo.find(fl) == std::string::npos) continue;
            }
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            char idl[80]; sprintf(idl, "%s##e%zu", r.module.c_str(), i);
            if (ImGui::Selectable(idl, false, ImGuiSelectableFlags_SpanAllColumns)) {
                gApp.selAddr = r.address;
                gApp.setStatus("Selected export address.", "ok");
            }
            ImGui::TableSetColumnIndex(1); ImGui::Text("%s", r.name.c_str());
            ImGui::TableSetColumnIndex(2); ImGui::Text("0x%llX", (unsigned long long)(uintptr_t)r.address);
            ImGui::TableSetColumnIndex(3); ImGui::TextDisabled("%lu", r.ordinal);
        }
        ImGui::EndTable();
    }
}

static void DrawAutoPtrTab() {
    SectionLabel("Auto pointer scanner");
    HintText("Snapshot all readable memory, then walk backwards N levels to find pointer chains rooted in static module memory that resolve to the target.  Depth 3 + maxOff 0x800 is a good default for game cheats.");
    ImGui::SetNextItemWidth(220); ImGui::InputTextWithHint("##aps_t", "target 0x...", gApp.aps.target, sizeof(gApp.aps.target));
    ImGui::SameLine();
    if (ImGui::Button("From selected", ImVec2(140, 0)) && gApp.selAddr) sprintf(gApp.aps.target, "0x%llX", (unsigned long long)(uintptr_t)gApp.selAddr);
    ImGui::SetNextItemWidth(80);  ImGui::InputText("Max depth##apsd", gApp.aps.depthBuf, sizeof(gApp.aps.depthBuf), ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine(); ImGui::SetNextItemWidth(120); ImGui::InputText("Max offset (hex)##apsm", gApp.aps.maxOffBuf, sizeof(gApp.aps.maxOffBuf));
    ImGui::SameLine();
    ImGui::BeginDisabled(!mem::isAttached());
    if (ColorButton("Scan chains", clr::accent, ImVec2(140, 0))) {
        uintptr_t t = (uintptr_t)mem::parseHexAwareInt(gApp.aps.target);
        int d = atoi(gApp.aps.depthBuf); if (d < 1) d = 3;
        intptr_t mo = (intptr_t)mem::parseHexAwareInt(gApp.aps.maxOffBuf);
        gApp.aps.results = mem::autoPointerScan(t, d, mo);
        char b[120]; sprintf(b, "Found %zu chain(s)", gApp.aps.results.size()); gApp.setStatus(b, gApp.aps.results.empty() ? "warn" : "ok");
    }
    ImGui::EndDisabled();

    if (ImGui::BeginTable("aps", 4, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable, ImVec2(0, 560))) {
        ImGui::TableSetupColumn("#",      ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthFixed, 160);
        ImGui::TableSetupColumn("Base off",ImGuiTableColumnFlags_WidthFixed, 130);
        ImGui::TableSetupColumn("Offsets");
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < gApp.aps.results.size() && i < 4000; i++) {
            const auto& c = gApp.aps.results[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            char idl[40]; sprintf(idl, "%zu##aps%zu", i+1, i);
            if (ImGui::Selectable(idl, false, ImGuiSelectableFlags_SpanAllColumns)) {
                mem::PointerChain pc; pc.name = "auto"; pc.moduleName = c.moduleName; pc.moduleOffset = c.moduleOffset; pc.offsets = c.offsets;
                mem::g_chains.push_back(pc);
                gApp.setStatus("Chain added to Pointers tab.", "ok");
            }
            ImGui::TableSetColumnIndex(1); ImGui::Text("%s", c.moduleName.c_str());
            ImGui::TableSetColumnIndex(2); ImGui::Text("0x%llX", (unsigned long long)c.moduleOffset);
            ImGui::TableSetColumnIndex(3);
            std::string s; char tmp[32];
            for (size_t k = 0; k < c.offsets.size(); k++) { sprintf(tmp, "%s0x%llX", k?",":"", (unsigned long long)c.offsets[k]); s += tmp; }
            ImGui::Text("%s", s.c_str());
        }
        ImGui::EndTable();
    }
}

static const char* kLuaStarter =
    "-- Memiscani Lua scripting.\n"
    "-- Globals exposed: mem.*, log(), print(), prot.PAGE_*\n"
    "-- Examples:\n"
    "--   local b = mem.find_module('kernel32.dll'); log(string.format('kernel32 base = 0x%X', b))\n"
    "--   local hp = mem.read_i32(0x7FF6C0FE1234); log('hp=', hp)\n"
    "--   mem.write_i32(0x7FF6C0FE1234, 9999)\n"
    "--   local hits = mem.aob_scan('48 8B 05 ?? ?? ?? ?? 48 85 C0')\n"
    "--   for i,a in ipairs(hits) do log(string.format('hit %d = 0x%X', i, a)) end\n"
    "--   for _,line in ipairs(mem.disasm_range(0x7FF6C0FE1234, 64)) do log(line.text) end\n"
    "--\n"
    "-- For long loops use mem.sleep(ms) so Stop button can cancel.\n"
    "\n";

static const struct LuaExample {
    const char* label;
    const char* tip;
    const char* code;
} kLuaExamples[] = {
    {
        "Hello",
        "Print to the output console.",
        "print('hello from lua')\n"
        "log(string.format('attached pid = %d', mem.pid()))\n"
    },
    {
        "Read i32",
        "Read a single int32 from a known address.",
        "local addr = 0x7FF6C0FE1234   -- replace with your address\n"
        "local v = mem.read_i32(addr)\n"
        "log(string.format('value at 0x%X = %d', addr, v or -1))\n"
    },
    {
        "Write i32",
        "Write a single int32.  Auto-flips read-only pages.",
        "local addr  = 0x7FF6C0FE1234\n"
        "local value = 9999\n"
        "mem.write_i32(addr, value)\n"
        "log(string.format('wrote %d -> 0x%X', value, addr))\n"
    },
    {
        "Freeze loop",
        "Lock a value until Stop is pressed.",
        "local addr  = 0x7FF6C0FE1234\n"
        "local value = 9999\n"
        "log(string.format('Locking 0x%X to %d.  Press Stop to release.', addr, value))\n"
        "while true do\n"
        "  mem.write_i32(addr, value)\n"
        "  mem.sleep(100)   -- cancellable wait\n"
        "end\n"
    },
    {
        "Find module",
        "Look up a remote module base address by name.",
        "local b = mem.find_module('kernel32.dll')\n"
        "if not b then log('not loaded'); return end\n"
        "log(string.format('kernel32.dll @ 0x%X', b))\n"
    },
    {
        "AOB scan",
        "Find a byte pattern with wildcards.",
        "local pat = '48 8B 05 ?? ?? ?? ?? 48 85 C0'\n"
        "local hits = mem.aob_scan(pat)\n"
        "log(string.format('%d match(es)', #hits))\n"
        "for i = 1, math.min(#hits, 5) do log(string.format('  hit %d = 0x%X', i, hits[i])) end\n"
    },
    {
        "AOB + patch",
        "Find by pattern then NOP the first match.  Uncomment write line when ready.",
        "local pat = '48 8B 05 ?? ?? ?? ?? 48 85 C0'\n"
        "local hits = mem.aob_scan(pat)\n"
        "if #hits == 0 then log('no match'); return end\n"
        "local addr = hits[1]\n"
        "log('would NOP at 0x' .. string.format('%X', addr))\n"
        "log('current instr: ' .. mem.disasm(addr))\n"
        "-- mem.write_bytes(addr, '\\x90\\x90\\x90\\x90\\x90')\n"
    },
    {
        "Disasm range",
        "Dump the first N instructions starting at an address.",
        "local addr = 0x7FF6C0FE1234\n"
        "for _, l in ipairs(mem.disasm_range(addr, 128)) do\n"
        "  log(string.format('0x%X  %s', l.addr, l.text))\n"
        "end\n"
    },
    {
        "Struct walk",
        "Read 32 4-byte slots starting at BASE - useful to discover adjacent struct fields.",
        "local BASE = 0x7FF6C0FE1234\n"
        "log('offset | int32                | float')\n"
        "log('-------+----------------------+--------')\n"
        "for off = 0, 0x80, 4 do\n"
        "  local i = mem.read_i32(BASE + off) or 0\n"
        "  local f = mem.read_f32(BASE + off) or 0\n"
        "  log(string.format('+0x%02X  | %-20d | %g', off, i, f))\n"
        "end\n"
    },
    {
        "Alloc + run shellcode",
        "Allocate RWX, write bytes, get the address.  Then trigger from the Trigger tab.",
        "-- mov eax, 42 ; ret\n"
        "local sc = '\\xB8\\x2A\\x00\\x00\\x00\\xC3'\n"
        "local p = mem.alloc(#sc)\n"
        "if not p then log('alloc failed'); return end\n"
        "mem.write_bytes(p, sc)\n"
        "log(string.format('shellcode at 0x%X - now CreateRemoteThread it from Trigger tab', p))\n"
    },
    {
        "Module + offset read",
        "Combine find_module with an offset.  Mirrors the CE 'game.exe+OFFSET' syntax.",
        "local b = mem.find_module('memiscani_im.exe')   -- replace with your target\n"
        "if not b then log('module not found'); return end\n"
        "local v = mem.read_i32(b + 0x1234)\n"
        "log(string.format('at +0x1234 = %s', tostring(v)))\n"
    },
};

static const char* kLuaPromptMd =
    "HOW TO USE THIS TAB\n"
    "===================\n"
    "1. Attach to a target process via the top bar.\n"
    "2. Edit the script in the LEFT pane (or click an Insert button below to paste an example).\n"
    "3. Click Run.  Output appears in the RIGHT pane.\n"
    "4. Click Stop at any time - the cancel signal hits at every ~1000 instructions or mem.sleep() boundary.\n"
    "5. Save the script to a .lua file (path on the toolbar) to keep it across sessions.\n"
    "   The script you have open at exit is also auto-saved to memiscani_lua_state.lua.\n"
    "\n"
    "CHEATSHEET\n"
    "==========\n"
    "  mem.attach(pid)           mem.detach()       mem.pid()         mem.base()\n"
    "  mem.find_module(name)     -> address or nil\n"
    "  mem.read_u8/u16/u32/u64/i8/i16/i32/i64/f32/f64(addr) -> number\n"
    "  mem.write_u8/...write_f64(addr, value)  -> bool\n"
    "  mem.read_bytes(addr, n)   mem.write_bytes(addr, str)\n"
    "  mem.alloc(n)              mem.free(addr)     mem.protect(addr, n, flags)\n"
    "  mem.disasm(addr)          mem.disasm_range(addr, n)  -> array of {addr, bytes, text}\n"
    "  mem.aob_scan('48 8B 05 ?? ?? ?? ?? 48 85 C0')  -> array of addresses\n"
    "  mem.sleep(ms)             prot.PAGE_EXECUTE_READWRITE etc.\n"
    "  print(...)                log(...)\n"
    "Address args accept:  integer, hex string ('0x7FF6...'), or number.\n";

static void DrawLuaTab() {
    SectionLabel("Lua scripting");
    HintText("Embedded Lua 5.4 with a `mem` table.  Scripts run on a worker thread so the UI stays live.  Click any 'Insert' button below to paste a ready-to-run example into the editor.");

    if (gApp.lua.source.empty()) gApp.lua.source = kLuaStarter;

    bool busy = memlua::isRunning();
    ImGui::BeginDisabled(busy);
    if (ColorButton("Run", clr::ok, ImVec2(80, 0))) {
        memlua::clearLog();
        memlua::runScript(gApp.lua.source);
    }
    Tip("Execute the script on a worker thread.  print() / log() output appears below.  Use Stop to interrupt at any time.");
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!busy);
    if (ColorButton("Stop", clr::err, ImVec2(80, 0))) memlua::requestStop();
    Tip("Set a stop flag.  Long-running scripts are checked every ~1000 Lua instructions and at every mem.sleep() boundary.");
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Clear output", ImVec2(110, 0))) memlua::clearLog();
    Tip("Wipe the output console.");
    ImGui::SameLine(0, 24);
    ImGui::SetNextItemWidth(260);
    ImGui::InputTextWithHint("##luapath", "script.lua", gApp.lua.savePath, sizeof(gApp.lua.savePath));
    ImGui::SameLine();
    if (ImGui::Button("Save", ImVec2(70, 0))) {
        FILE* f = nullptr;
        if (fopen_s(&f, gApp.lua.savePath, "wb") == 0 && f) {
            fwrite(gApp.lua.source.data(), 1, gApp.lua.source.size(), f);
            fclose(f);
            gApp.setStatus("Saved.", "ok");
        } else gApp.setStatus("Save failed.", "err");
    }
    Tip("Save the editor contents to the .lua file at the path on the left.");
    ImGui::SameLine();
    if (ImGui::Button("Load", ImVec2(70, 0))) {
        FILE* f = nullptr;
        if (fopen_s(&f, gApp.lua.savePath, "rb") == 0 && f) {
            fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
            std::string s(sz, 0);
            if (sz > 0) fread(&s[0], 1, sz, f);
            fclose(f);
            gApp.lua.source = s;
            gApp.setStatus("Loaded.", "ok");
        } else gApp.setStatus("Load failed.", "err");
    }
    Tip("Load a .lua file from disk into the editor.");
    ImGui::SameLine();
    if (busy) ImGui::TextColored(clr::ok, "  RUNNING");
    else      ImGui::TextDisabled("  idle");

    ImGui::Separator();
    ImGui::TextColored(clr::accent, "Insert example:");
    ImGui::SameLine();
    for (const auto& ex : kLuaExamples) {
        if (ImGui::SmallButton(ex.label)) {

            if (gApp.lua.source == kLuaStarter || gApp.lua.source.empty()) {
                gApp.lua.source = std::string("-- ") + ex.label + "\n" + ex.code;
            } else {
                if (!gApp.lua.source.empty() && gApp.lua.source.back() != '\n') gApp.lua.source.push_back('\n');
                gApp.lua.source += std::string("\n-- ") + ex.label + "\n" + ex.code;
            }
            gApp.setStatus(std::string("Inserted '") + ex.label + "'.", "ok");
        }
        Tip(ex.tip);
        ImGui::SameLine();
    }
    ImGui::NewLine();

    if (ImGui::CollapsingHeader("How to use this tab + Lua API cheatsheet", ImGuiTreeNodeFlags_None)) {
        ImGui::TextUnformatted(kLuaPromptMd);
    }

    ImVec2 region = ImGui::GetContentRegionAvail();
    float editorW = region.x * 0.55f;
    if (editorW < 380) editorW = 380;

    ImGui::BeginChild("##luaedit", ImVec2(editorW, -2), true);
    ImGui::TextColored(clr::accent, "script");
    if (gApp.lua.source.capacity() < gApp.lua.source.size() + 64) gApp.lua.source.reserve(gApp.lua.source.size() + 64);
    gApp.lua.source.resize(std::max<size_t>(gApp.lua.source.size(), 4096));
    ImGui::InputTextMultiline("##luasrc",
                              gApp.lua.source.data(),
                              gApp.lua.source.size(),
                              ImVec2(-1, -1),
                              ImGuiInputTextFlags_AllowTabInput);
    gApp.lua.source.resize(strlen(gApp.lua.source.c_str()));
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##luaout", ImVec2(0, -2), true);
    ImGui::TextColored(clr::accent, "output");
    ImGui::Separator();
    auto lines = memlua::snapshotLog();
    for (auto& l : lines) {
        ImVec4 col = clr::text;
        if (l.rfind("[lua] error", 0) == 0) col = clr::err;
        else if (l.rfind("[lua]", 0) == 0)  col = clr::accentH;
        ImGui::PushStyleColor(ImGuiCol_Text, col);
        ImGui::TextUnformatted(l.c_str());
        ImGui::PopStyleColor();
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 2) ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
}

static void DrawNetworkTab() {
    SectionLabel("Network endpoints");
    HintText("TCP/UDP sockets owned by processes on this machine (via GetExtendedTcp/UdpTable).  Filter to the attached process for game-network analysis, or look across the whole system for what's listening.");
    ImGui::Checkbox("Only attached process", &gApp.net.onlyAttached);
    Tip("If on, show only sockets owned by the currently-attached PID.  Otherwise list every TCP/UDP endpoint on the system.");
    ImGui::SameLine();
    if (ImGui::Button("Refresh", ImVec2(110, 0))) {
        DWORD pid = gApp.net.onlyAttached ? mem::attachedPid() : 0;
        gApp.net.entries = mem::listProcessNetwork(pid);
        char b[80]; sprintf(b, "%zu endpoint(s)", gApp.net.entries.size()); gApp.setStatus(b, "ok");
    }
    Tip("Re-enumerate sockets.");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(280);
    ImGui::InputTextWithHint("##nf", "filter (addr / port / state)", gApp.net.filter, sizeof(gApp.net.filter));

    if (ImGui::BeginTable("net", 7, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable, ImVec2(0, 0))) {
        ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("Local",  ImGuiTableColumnFlags_WidthFixed, 160);
        ImGui::TableSetupColumn("LPort",  ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("Remote", ImGuiTableColumnFlags_WidthFixed, 160);
        ImGui::TableSetupColumn("RPort",  ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("State",  ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("PID",    ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableHeadersRow();
        for (const auto& e : gApp.net.entries) {
            if (gApp.net.filter[0]) {
                char buf[160]; sprintf(buf, "%s %s %d %s %d %s %lu",
                    e.protocol.c_str(), e.localAddr.c_str(), e.localPort,
                    e.remoteAddr.c_str(), e.remotePort, e.state.c_str(), e.pid);
                std::string lo = buf; for (auto& c : lo) c = (char)std::tolower((unsigned char)c);
                std::string fl = gApp.net.filter; for (auto& c : fl) c = (char)std::tolower((unsigned char)c);
                if (lo.find(fl) == std::string::npos) continue;
            }
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (e.protocol == "TCP") ImGui::TextColored(clr::accent, "%s", e.protocol.c_str());
            else                      ImGui::TextColored(clr::accentH, "%s", e.protocol.c_str());
            ImGui::TableSetColumnIndex(1); ImGui::Text("%s", e.localAddr.c_str());
            ImGui::TableSetColumnIndex(2); ImGui::Text("%d", e.localPort);
            ImGui::TableSetColumnIndex(3); ImGui::Text("%s", e.remoteAddr.c_str());
            ImGui::TableSetColumnIndex(4); ImGui::Text("%d", e.remotePort);
            ImGui::TableSetColumnIndex(5);
            ImVec4 stCol = (e.state == "ESTABLISHED") ? clr::ok :
                           (e.state == "LISTEN")      ? clr::accentH :
                           (e.state == "TIME_WAIT" || e.state == "CLOSE_WAIT") ? clr::warn :
                           clr::textDim;
            ImGui::TextColored(stCol, "%s", e.state.c_str());
            ImGui::TableSetColumnIndex(6); ImGui::Text("%lu", e.pid);
        }
        ImGui::EndTable();
    }
}

static const char* kDtItemsX[] = { "int8","int16","int32","int64","float","double","String","AOB" };

static void DrawHexTab() {
    SectionLabel("Memory hex viewer / editor");
    HintText("Read and edit raw bytes at any address.  Click a hex cell to edit its byte.  Use 'From selected' to pull the Scanner-selected address.");
    ImGui::SetNextItemWidth(220); ImGui::InputTextWithHint("##hva", "address 0x...", gApp.hex.addrBuf, sizeof(gApp.hex.addrBuf));
    ImGui::SameLine(); ImGui::SetNextItemWidth(100); ImGui::InputText("Bytes##hvb", gApp.hex.sizeBuf, sizeof(gApp.hex.sizeBuf), ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    if (ImGui::Button("From selected", ImVec2(140, 0)) && gApp.selAddr) sprintf(gApp.hex.addrBuf, "0x%llX", (unsigned long long)(uintptr_t)gApp.selAddr);
    ImGui::SameLine();
    ImGui::BeginDisabled(!mem::isAttached());
    if (ColorButton("Read", clr::accent, ImVec2(80, 0))) {
        uintptr_t a = (uintptr_t)mem::parseHexAwareInt(gApp.hex.addrBuf);
        size_t n = (size_t)atoi(gApp.hex.sizeBuf); if (n < 16) n = 16; if (n > 4096) n = 4096;
        std::string err;
        if (mem::hexRead(a, n, gApp.hex.data, err)) { gApp.hex.base = a; gApp.setStatus("Hex read OK.", "ok"); gApp.hex.editIdx = -1; }
        else gApp.setStatus("Read failed: " + err, "err");
    }
    ImGui::SameLine();
    if (ImGui::Button("Jump -64", ImVec2(80, 0))) { uintptr_t a = (uintptr_t)mem::parseHexAwareInt(gApp.hex.addrBuf); sprintf(gApp.hex.addrBuf, "0x%llX", (unsigned long long)(a - 64)); }
    ImGui::SameLine();
    if (ImGui::Button("Jump +64", ImVec2(80, 0))) { uintptr_t a = (uintptr_t)mem::parseHexAwareInt(gApp.hex.addrBuf); sprintf(gApp.hex.addrBuf, "0x%llX", (unsigned long long)(a + 64)); }
    ImGui::EndDisabled();

    if (gApp.hex.data.empty()) { ImGui::TextDisabled("(no data - click Read)"); return; }

    ImGui::BeginChild("##hexscroll", ImVec2(0, 0), true);
    char hdr[80]; sprintf(hdr, "       offset    +0 +1 +2 +3 +4 +5 +6 +7 +8 +9 +A +B +C +D +E +F   ascii");
    ImGui::TextDisabled("%s", hdr);
    for (size_t row = 0; row < gApp.hex.data.size(); row += 16) {
        uintptr_t a = gApp.hex.base + row;
        ImGui::PushStyleColor(ImGuiCol_Text, clr::sectHdr);
        ImGui::Text("0x%016llX  ", (unsigned long long)a);
        ImGui::PopStyleColor();
        ImGui::SameLine();

        std::string asciiPart;
        for (size_t col = 0; col < 16; col++) {
            size_t i = row + col;
            if (i >= gApp.hex.data.size()) { ImGui::TextDisabled(".. "); ImGui::SameLine(); asciiPart += " "; continue; }
            char cell[6]; sprintf(cell, "%02X", gApp.hex.data[i]);
            char id[24];  sprintf(id, "%02X##c%zu", gApp.hex.data[i], i);
            ImGui::PushID((int)i);
            ImGui::PushStyleColor(ImGuiCol_Text, gApp.hex.editIdx == (int)i ? clr::warn : clr::text);
            if (ImGui::Selectable(cell, gApp.hex.editIdx == (int)i, 0, ImVec2(22, 0))) {
                gApp.hex.editIdx = (int)i;
                sprintf(gApp.hex.editVal, "%02X", gApp.hex.data[i]);
            }
            ImGui::PopStyleColor();
            ImGui::PopID();
            ImGui::SameLine();
            BYTE b = gApp.hex.data[i];
            asciiPart += (b >= 32 && b < 127) ? (char)b : '.';
        }
        ImGui::TextDisabled(" %s", asciiPart.c_str());
    }
    ImGui::EndChild();

    if (gApp.hex.editIdx >= 0 && gApp.hex.editIdx < (int)gApp.hex.data.size()) {
        ImGui::OpenPopup("Edit byte");
    }
    if (ImGui::BeginPopupModal("Edit byte", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Editing byte at 0x%016llX (offset +%d)", (unsigned long long)(gApp.hex.base + gApp.hex.editIdx), gApp.hex.editIdx);
        ImGui::SetNextItemWidth(80);
        ImGui::InputText("Hex value##ev", gApp.hex.editVal, sizeof(gApp.hex.editVal));
        if (ColorButton("Write", clr::accent, ImVec2(80, 0))) {
            BYTE nv = (BYTE)strtoul(gApp.hex.editVal, nullptr, 16);
            std::vector<BYTE> wr{ nv };
            std::string err;
            uintptr_t a = gApp.hex.base + gApp.hex.editIdx;
            if (mem::hexWrite(a, wr, true, err)) { gApp.hex.data[gApp.hex.editIdx] = nv; gApp.setStatus("Wrote.", "ok"); }
            else gApp.setStatus("Write failed: " + err, "err");
            gApp.hex.editIdx = -1;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(80, 0))) { gApp.hex.editIdx = -1; ImGui::CloseCurrentPopup(); }
        ImGui::EndPopup();
    }
}

static void DrawBookmarksTab() {
    SectionLabel("Bookmarks");
    HintText("Save named addresses with optional notes.  Persists across sessions via memiscani_bookmarks.txt.  Click a row to send the address to the Scanner-selected slot.");
    ImGui::SetNextItemWidth(180); ImGui::InputTextWithHint("##bn", "name", gApp.bm.nameBuf, sizeof(gApp.bm.nameBuf));
    ImGui::SameLine(); ImGui::SetNextItemWidth(180); ImGui::InputTextWithHint("##ba", "address 0x...", gApp.bm.addrBuf, sizeof(gApp.bm.addrBuf));
    ImGui::SameLine(); ImGui::SetNextItemWidth(110); ImGui::Combo("Type##bdt", &gApp.bm.dtIdx, kDtItemsX, IM_ARRAYSIZE(kDtItemsX));
    ImGui::SetNextItemWidth(540); ImGui::InputTextWithHint("Note##bnote", "free-form notes", gApp.bm.noteBuf, sizeof(gApp.bm.noteBuf));
    ImGui::SameLine();
    if (ColorButton("Add", clr::accent, ImVec2(80, 0))) {
        uintptr_t a = (uintptr_t)mem::parseHexAwareInt(gApp.bm.addrBuf);
        if (a) { mem::bookmarkAdd(gApp.bm.nameBuf, (LPVOID)a, (mem::DataType)gApp.bm.dtIdx, gApp.bm.noteBuf); gApp.setStatus("Bookmark added.", "ok"); }
        else gApp.setStatus("Bad address.", "err");
    }
    ImGui::SameLine();
    if (ImGui::Button("From Scanner", ImVec2(130, 0)) && gApp.selAddr) {
        mem::bookmarkAdd(gApp.bm.nameBuf[0] ? gApp.bm.nameBuf : "(unnamed)", gApp.selAddr, (mem::DataType)gApp.sc.dtIdx, gApp.bm.noteBuf);
        gApp.setStatus("Bookmark added from selection.", "ok");
    }
    ImGui::SameLine();
    if (ImGui::Button("Save", ImVec2(60, 0))) { mem::bookmarkSave("memiscani_bookmarks.txt"); gApp.setStatus("Saved.", "ok"); }
    ImGui::SameLine();
    if (ImGui::Button("Load", ImVec2(60, 0))) { mem::bookmarkLoad("memiscani_bookmarks.txt"); gApp.setStatus("Loaded.", "ok"); }

    if (ImGui::BeginTable("bm", 6, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable, ImVec2(0, 0))) {
        ImGui::TableSetupColumn("#",       ImGuiTableColumnFlags_WidthFixed, 40);
        ImGui::TableSetupColumn("Name",    ImGuiTableColumnFlags_WidthFixed, 200);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableSetupColumn("Type",    ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("Note");
        ImGui::TableSetupColumn("Action",  ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < mem::g_bookmarks.size(); i++) {
            const auto& b = mem::g_bookmarks[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            char idl[40]; sprintf(idl, "%zu##bsel%zu", i+1, i);
            if (ImGui::Selectable(idl, gApp.bm.selected == (int)i, ImGuiSelectableFlags_SpanAllColumns)) {
                gApp.bm.selected = (int)i; gApp.selAddr = b.addr; gApp.sc.dtIdx = b.dt;
                gApp.setStatus("Bookmark address selected.", "ok");
            }
            ImGui::TableSetColumnIndex(1); ImGui::Text("%s", b.name.c_str());
            ImGui::TableSetColumnIndex(2); ImGui::Text("0x%llX", (unsigned long long)(uintptr_t)b.addr);
            ImGui::TableSetColumnIndex(3); ImGui::TextDisabled("%s", kDtItemsX[b.dt]);
            ImGui::TableSetColumnIndex(4); ImGui::Text("%s", b.note.c_str());
            ImGui::TableSetColumnIndex(5);
            char r1[40], r2[40];
            sprintf(r1, "Goto##bg%zu", i); sprintf(r2, "Del##bd%zu", i);
            if (ImGui::SmallButton(r1)) { gApp.selAddr = b.addr; gApp.sc.dtIdx = b.dt; }
            ImGui::SameLine();
            if (ImGui::SmallButton(r2)) { mem::bookmarkRemove(i); break; }
        }
        ImGui::EndTable();
    }
}

static void DrawPETab() {
    SectionLabel("PE info");
    HintText("Parse the PE header of any loaded module - sections, imports, exports - directly from target memory.");
    if (ImGui::Button("Refresh modules", ImVec2(150, 0))) { gApp.mods.list = mem::listModules(); gApp.setStatus("Modules refreshed.", "ok"); }
    ImGui::SameLine();
    std::vector<const char*> names;
    for (auto& m : gApp.mods.list) names.push_back(m.name.c_str());
    ImGui::SetNextItemWidth(280);
    if (ImGui::Combo("Module##pemod", &gApp.pe.selectedModule, names.data(), (int)names.size())) {
        if (gApp.pe.selectedModule >= 0 && gApp.pe.selectedModule < (int)gApp.mods.list.size()) {
            const auto& m = gApp.mods.list[gApp.pe.selectedModule];
            gApp.pe.info = mem::getPEInfo((HMODULE)m.base, m.name);
            gApp.setStatus("PE info parsed.", "ok");
        }
    }
    if (gApp.pe.info.imageBase) {
        ImGui::TextDisabled("Image base: 0x%llX  |  size %zu KB  |  bits %d  |  TS 0x%08X  |  checksum 0x%08X",
            (unsigned long long)gApp.pe.info.imageBase, gApp.pe.info.imageSize/1024,
            gApp.pe.info.is64 ? 64 : 32, gApp.pe.info.timestamp, gApp.pe.info.checksum);
    }

    if (ImGui::RadioButton("Sections", gApp.pe.viewMode == 0)) gApp.pe.viewMode = 0;
    ImGui::SameLine(); if (ImGui::RadioButton("Imports", gApp.pe.viewMode == 1)) gApp.pe.viewMode = 1;
    ImGui::SameLine(); if (ImGui::RadioButton("Exports", gApp.pe.viewMode == 2)) gApp.pe.viewMode = 2;
    ImGui::SameLine(); ImGui::SetNextItemWidth(240); ImGui::InputTextWithHint("##pef", "filter substring", gApp.pe.filter, sizeof(gApp.pe.filter));

    if (gApp.pe.viewMode == 0) {
        if (ImGui::BeginTable("pesec", 4, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0, 0))) {
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableSetupColumn("Addr (RVA + base)", ImGuiTableColumnFlags_WidthFixed, 220);
            ImGui::TableSetupColumn("Size",   ImGuiTableColumnFlags_WidthFixed, 100);
            ImGui::TableSetupColumn("Characteristics");
            ImGui::TableHeadersRow();
            for (const auto& s : gApp.pe.info.sections) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::Text("%s", s.name.c_str());
                ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", (unsigned long long)(gApp.pe.info.imageBase + s.rva));
                ImGui::TableSetColumnIndex(2); ImGui::Text("%zu KB", s.vsize/1024);
                ImGui::TableSetColumnIndex(3);
                ImGui::TextDisabled("%s%s%s%s",
                    (s.characteristics & IMAGE_SCN_MEM_EXECUTE) ? "X " : "",
                    (s.characteristics & IMAGE_SCN_MEM_READ)    ? "R " : "",
                    (s.characteristics & IMAGE_SCN_MEM_WRITE)   ? "W " : "",
                    (s.characteristics & IMAGE_SCN_CNT_CODE)    ? "(code) " : "");
            }
            ImGui::EndTable();
        }
    } else if (gApp.pe.viewMode == 1) {
        if (ImGui::BeginTable("peimp", 3, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0, 0))) {
            ImGui::TableSetupColumn("DLL",  ImGuiTableColumnFlags_WidthFixed, 200);
            ImGui::TableSetupColumn("Name");
            ImGui::TableSetupColumn("IAT entry", ImGuiTableColumnFlags_WidthFixed, 200);
            ImGui::TableHeadersRow();
            for (const auto& im : gApp.pe.info.imports) {
                if (gApp.pe.filter[0]) {
                    std::string sum = im.dll + " " + im.name;
                    std::string lo = sum; for (auto& c : lo) c = (char)std::tolower((unsigned char)c);
                    std::string fl = gApp.pe.filter; for (auto& c : fl) c = (char)std::tolower((unsigned char)c);
                    if (lo.find(fl) == std::string::npos) continue;
                }
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::TextDisabled("%s", im.dll.c_str());
                ImGui::TableSetColumnIndex(1); ImGui::Text("%s", im.name.c_str());
                ImGui::TableSetColumnIndex(2); ImGui::Text("0x%llX", (unsigned long long)(uintptr_t)im.iatPointer);
            }
            ImGui::EndTable();
        }
    } else {
        if (ImGui::BeginTable("peexp", 3, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0, 0))) {
            ImGui::TableSetupColumn("Name");
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 200);
            ImGui::TableSetupColumn("Ord",     ImGuiTableColumnFlags_WidthFixed, 60);
            ImGui::TableHeadersRow();
            for (const auto& e : gApp.pe.info.exports) {
                if (gApp.pe.filter[0]) {
                    std::string lo = e.name; for (auto& c : lo) c = (char)std::tolower((unsigned char)c);
                    std::string fl = gApp.pe.filter; for (auto& c : fl) c = (char)std::tolower((unsigned char)c);
                    if (lo.find(fl) == std::string::npos) continue;
                }
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                char idl[256]; sprintf(idl, "%s##peel", e.name.c_str());
                if (ImGui::Selectable(idl, false, ImGuiSelectableFlags_SpanAllColumns)) {
                    gApp.selAddr = e.address; gApp.setStatus("Export address selected.", "ok");
                }
                ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", (unsigned long long)(uintptr_t)e.address);
                ImGui::TableSetColumnIndex(2); ImGui::TextDisabled("%lu", e.ordinal);
            }
            ImGui::EndTable();
        }
    }
}

static void DrawAutoTypeModal() {
    if (!gApp.at.showModal) return;
    ImGui::OpenPopup("Auto-detect data type");
    ImGui::SetNextWindowSize(ImVec2(560, 380), ImGuiCond_FirstUseEver);
    if (ImGui::BeginPopupModal("Auto-detect data type", &gApp.at.showModal)) {
        ImGui::TextDisabled("Heuristic ranking of interpretations at the selected address.  Click a row to apply that type to the Scanner.");
        if (ImGui::BeginTable("at", 4, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY)) {
            ImGui::TableSetupColumn("Type",         ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableSetupColumn("Value");
            ImGui::TableSetupColumn("Plausibility", ImGuiTableColumnFlags_WidthFixed, 120);
            ImGui::TableSetupColumn("Reason");
            ImGui::TableHeadersRow();
            for (size_t i = 0; i < gApp.at.guesses.size(); i++) {
                const auto& g = gApp.at.guesses[i];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                char idl[40]; sprintf(idl, "%s##atg%zu", kDtItemsX[g.dt], i);
                if (ImGui::Selectable(idl, false, ImGuiSelectableFlags_SpanAllColumns)) {
                    gApp.sc.dtIdx = g.dt;
                    gApp.setStatus("Scanner type set to " + std::string(kDtItemsX[g.dt]), "ok");
                    gApp.at.showModal = false; ImGui::CloseCurrentPopup();
                }
                ImGui::TableSetColumnIndex(1); ImGui::TextColored(clr::ok, "%s", g.formatted.c_str());
                ImGui::TableSetColumnIndex(2);
                ImVec4 col = g.plausibility >= 0.7f ? clr::ok : g.plausibility >= 0.4f ? clr::warn : clr::textDim;
                ImGui::TextColored(col, "%.0f%%", g.plausibility * 100.0f);
                ImGui::TableSetColumnIndex(3); ImGui::TextDisabled("%s", g.reason.c_str());
            }
            ImGui::EndTable();
        }
        if (ImGui::Button("Close")) { gApp.at.showModal = false; ImGui::CloseCurrentPopup(); }
        ImGui::EndPopup();
    }
}

static void DrawStackSection() {
    SectionLabel("Stack walker (selected thread)");
    HintText("Suspends a thread, reads RSP-area qwords, and shows those that look like return addresses inside a module's code.  Heuristic walker - good enough to see who called what.");
    ImGui::SetNextItemWidth(100); ImGui::InputText("TID##swt", gApp.stk.tidBuf, sizeof(gApp.stk.tidBuf), ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    if (ColorButton("Walk stack", clr::accent, ImVec2(140, 0))) {
        DWORD tid = (DWORD)atoi(gApp.stk.tidBuf);
        gApp.stk.frames = mem::walkStack(tid, 32);
        char b[80]; sprintf(b, "Walked %zu frame(s)", gApp.stk.frames.size()); gApp.setStatus(b, "ok");
    }
    if (!gApp.stk.frames.empty()) {
        if (ImGui::BeginTable("sw", 4, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0, 220))) {
            ImGui::TableSetupColumn("RIP",     ImGuiTableColumnFlags_WidthFixed, 180);
            ImGui::TableSetupColumn("RSP",     ImGuiTableColumnFlags_WidthFixed, 180);
            ImGui::TableSetupColumn("Module+off", ImGuiTableColumnFlags_WidthFixed, 280);
            ImGui::TableSetupColumn("Asm @ call site");
            ImGui::TableHeadersRow();
            for (const auto& f : gApp.stk.frames) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                char idl[40]; sprintf(idl, "0x%llX##sf", (unsigned long long)f.rip);
                if (ImGui::Selectable(idl, false, ImGuiSelectableFlags_SpanAllColumns)) {
                    gApp.selAddr = (LPVOID)f.rip;
                }
                ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", (unsigned long long)f.rsp);
                ImGui::TableSetColumnIndex(2);
                if (!f.moduleName.empty()) ImGui::Text("%s+0x%llX", f.moduleName.c_str(), (unsigned long long)f.moduleOffset);
                else                       ImGui::TextDisabled("(unknown)");
                ImGui::TableSetColumnIndex(3); ImGui::TextColored(clr::accentH, "%s", f.disasm.c_str());
            }
            ImGui::EndTable();
        }
    }
}

static void DrawWatchTab() {
    SectionLabel("Live watch list");
    HintText("Add addresses by hand and watch their values update.  Independent of the scanner.  Save / Load persists to memiscani_watch.txt.");
    ImGui::SetNextItemWidth(180); ImGui::InputTextWithHint("##wnm", "name", gApp.watch.nameBuf, sizeof(gApp.watch.nameBuf));
    ImGui::SameLine(); ImGui::SetNextItemWidth(180); ImGui::InputTextWithHint("##wad", "address 0x...", gApp.watch.addrBuf, sizeof(gApp.watch.addrBuf));
    ImGui::SameLine();
    const char* items[] = { "int8","int16","int32","int64","float","double","String","AOB" };
    ImGui::SetNextItemWidth(110);
    ImGui::Combo("Type##wdt", &gApp.watch.dtIdx, items, IM_ARRAYSIZE(items));
    ImGui::SameLine();
    if (ColorButton("Add", clr::accent, ImVec2(70, 0))) {
        uintptr_t a = (uintptr_t)mem::parseHexAwareInt(gApp.watch.addrBuf);
        if (a) {
            mem::watchAdd(gApp.watch.nameBuf, (LPVOID)a, (mem::DataType)gApp.watch.dtIdx);
            gApp.setStatus("Watch added.", "ok");
        } else gApp.setStatus("Bad address.", "err");
    }
    ImGui::SameLine();
    if (ImGui::Button("From Scanner selection", ImVec2(190, 0)) && gApp.selAddr) {
        mem::watchAdd(gApp.watch.nameBuf[0] ? gApp.watch.nameBuf : "(unnamed)", gApp.selAddr, (mem::DataType)gApp.sc.dtIdx);
        gApp.setStatus("Watch added from selection.", "ok");
    }
    ImGui::SameLine();
    if (ImGui::Button("Save",  ImVec2(60, 0))) { mem::watchSave("memiscani_watch.txt"); gApp.setStatus("Saved.", "ok"); }
    ImGui::SameLine();
    if (ImGui::Button("Load",  ImVec2(60, 0))) { mem::watchLoad("memiscani_watch.txt"); gApp.setStatus("Loaded.", "ok"); }
    ImGui::SameLine();
    if (ColorButton("Clear all", clr::warn, ImVec2(90, 0))) { mem::g_watch.clear(); gApp.setStatus("Cleared.", "info"); }

    DWORD now = GetTickCount();
    if (now - gApp.watch.lastTick > 200) {
        mem::watchUpdateAll();
        gApp.watch.lastTick = now;
    }

    if (ImGui::BeginTable("watch", 6, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable, ImVec2(0, 0))) {
        ImGui::TableSetupColumn("#",       ImGuiTableColumnFlags_WidthFixed, 40);
        ImGui::TableSetupColumn("Name",    ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableSetupColumn("Type",    ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("Value");
        ImGui::TableSetupColumn("Action",  ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < mem::g_watch.size(); i++) {
            auto& w = mem::g_watch[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::Text("%zu", i+1);
            ImGui::TableSetColumnIndex(1); ImGui::Text("%s", w.name.c_str());
            ImGui::TableSetColumnIndex(2); ImGui::Text("0x%llX", (unsigned long long)(uintptr_t)w.addr);
            ImGui::TableSetColumnIndex(3); ImGui::TextDisabled("%s", items[w.dt]);
            ImGui::TableSetColumnIndex(4);
            ImVec4 col = w.flashChanged ? clr::warn : (w.valid ? clr::ok : clr::textDim);
            ImGui::PushStyleColor(ImGuiCol_Text, col);
            ImGui::Text("%s", w.valid ? mem::formatTypedValue(w.lastVal, w.dt).c_str() : "?");
            ImGui::PopStyleColor();
            ImGui::TableSetColumnIndex(5);
            char b1[40], b2[40];
            sprintf(b1, "Select##ws%zu", i); sprintf(b2, "Remove##wr%zu", i);
            if (ImGui::SmallButton(b1)) { gApp.selAddr = w.addr; gApp.sc.dtIdx = w.dt; }
            ImGui::SameLine();
            if (ImGui::SmallButton(b2)) { mem::watchRemove(i); break; }
        }
        ImGui::EndTable();
    }
}

static void DrawHwbpTab() {
    SectionLabel("Hardware breakpoint  (find what reads / writes)");
    HintText("Sets DR0 on every thread of the target via DebugActiveProcess + SetThreadContext.  When the watched address is read / written, the offending RIP and disassembly are logged below.  Disable when done.");
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Watch address: ");
    ImGui::SameLine();
    if (gApp.selAddr) ImGui::TextColored(clr::accent, "0x%llX  (Scanner-selected)", (unsigned long long)(uintptr_t)gApp.selAddr);
    else              ImGui::TextColored(clr::warn,   "(click a row in Scanner results first)");

    const char* tItems[] = { "Execute", "Write", "Read+Write" };
    int tMap[] = { mem::HWBP_EXECUTE, mem::HWBP_WRITE, mem::HWBP_READWRITE };
    int tSel = 1; for (int i = 0; i < 3; i++) if (tMap[i] == gApp.hwbp.type) { tSel = i; break; }
    ImGui::SetNextItemWidth(120); if (ImGui::Combo("On##hbt", &tSel, tItems, 3)) gApp.hwbp.type = tMap[tSel];
    ImGui::SameLine();
    const char* sItems[] = { "1 byte","2 byte","4 byte","8 byte" };
    int sMap[] = { 1,2,4,8 };
    int sSel = 2; for (int i = 0; i < 4; i++) if (sMap[i] == gApp.hwbp.size) { sSel = i; break; }
    ImGui::SetNextItemWidth(100); if (ImGui::Combo("Length##hbs", &sSel, sItems, 4)) gApp.hwbp.size = sMap[sSel];

    ImGui::SameLine();
    ImGui::BeginDisabled(!gApp.selAddr || !mem::isAttached() || mem::g_hwbpActive);
    if (ColorButton("Enable trace", clr::ok, ImVec2(150, 0))) {
        std::string err;
        if (mem::hwbpEnable((uintptr_t)gApp.selAddr, (mem::HwbpType)gApp.hwbp.type, gApp.hwbp.size, err)) gApp.setStatus("HW breakpoint armed - perform the access now.", "ok");
        else gApp.setStatus("Enable failed: " + err, "err");
    }
    Tip("Attach as debugger, set DR0+DR7 on every thread of the target.  When the watched address is accessed, the offending RIP is logged below.  Requires admin and SeDebugPrivilege.");
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!mem::g_hwbpActive);
    if (ColorButton("Disable trace", clr::warn, ImVec2(150, 0))) { mem::hwbpDisable(); gApp.setStatus("HW breakpoint cleared.", "info"); }
    Tip("Clear DR0 on all threads and detach the debugger.  Always disable when done - leaving a debugger attached can confuse the target.");
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Clear log", ImVec2(100, 0))) { mem::hwbpClearLog(); }
    Tip("Empty the offender log.");
    ImGui::SameLine();
    if (mem::g_hwbpActive) ImGui::TextColored(clr::ok, "  TRACING  -  watch 0x%llX", (unsigned long long)mem::g_hwbpWatchAddr);
    else                    ImGui::TextDisabled("  inactive");

    ImGui::SetNextItemWidth(280);
    ImGui::InputTextWithHint("##hbf", "filter substring", gApp.hwbp.filter, sizeof(gApp.hwbp.filter));
    ImGui::SameLine();
    ImGui::TextDisabled("%zu hit(s)", mem::g_hwbpLog.size());

    if (ImGui::BeginTable("hbl", 4, ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0, 0))) {
        ImGui::TableSetupColumn("TID",     ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("Offender RIP", ImGuiTableColumnFlags_WidthFixed, 200);
        ImGui::TableSetupColumn("Instruction");
        ImGui::TableSetupColumn("t+ms",    ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableHeadersRow();
        DWORD t0 = mem::g_hwbpLog.empty() ? GetTickCount() : mem::g_hwbpLog.front().timeMs;
        for (size_t i = 0; i < mem::g_hwbpLog.size(); i++) {
            const auto& e = mem::g_hwbpLog[i];
            if (gApp.hwbp.filter[0]) {
                std::string lo = e.disasm; for (auto& c : lo) c = (char)std::tolower((unsigned char)c);
                std::string fl = gApp.hwbp.filter; for (auto& c : fl) c = (char)std::tolower((unsigned char)c);
                if (lo.find(fl) == std::string::npos) continue;
            }
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::Text("%lu", e.tid);
            ImGui::TableSetColumnIndex(1);
            char idl[60]; sprintf(idl, "0x%llX##hb%zu", (unsigned long long)e.offenderRip, i);
            if (ImGui::Selectable(idl, false, ImGuiSelectableFlags_SpanAllColumns)) {
                gApp.selAddr = (LPVOID)e.offenderRip;
                gApp.setStatus("Offender RIP selected.", "ok");
            }
            ImGui::TableSetColumnIndex(2); ImGui::TextColored(clr::accentH, "%s", e.disasm.c_str());
            ImGui::TableSetColumnIndex(3); ImGui::TextDisabled("+%lu", e.timeMs - t0);
        }
        ImGui::EndTable();
    }
}

struct WF {
    const char* title;
    const char* purpose;
    std::vector<const char*> steps;
};

static bool wfMatchesFilter(const WF& w) {
    if (!gApp.guideFilter[0]) return true;
    std::string fl = gApp.guideFilter;
    for (auto& c : fl) c = (char)std::tolower((unsigned char)c);
    auto contains = [&](const char* s) {
        std::string lo = s;
        for (auto& c : lo) c = (char)std::tolower((unsigned char)c);
        return lo.find(fl) != std::string::npos;
    };
    if (contains(w.title)) return true;
    if (contains(w.purpose)) return true;
    for (auto* s : w.steps) if (contains(s)) return true;
    return false;
}

static void DrawWorkflow(const WF& w) {
    if (!wfMatchesFilter(w)) return;
    ImGui::PushStyleColor(ImGuiCol_Text, clr::accent);
    ImGui::TextWrapped("%s", w.title);
    ImGui::PopStyleColor();
    ImGui::PushStyleColor(ImGuiCol_Text, clr::textDim);
    ImGui::TextWrapped("%s", w.purpose);
    ImGui::PopStyleColor();
    ImGui::Spacing();
    ImGui::Indent(12);
    for (size_t i = 0; i < w.steps.size(); i++) {
        ImGui::Bullet();
        ImGui::SameLine();
        ImGui::TextWrapped("%s", w.steps[i]);
    }
    ImGui::Unindent(12);
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
}

static void DrawCategory(const char* name, std::vector<WF> wfs, bool defaultOpen = false) {
    bool anyMatch = false;
    for (auto& w : wfs) if (wfMatchesFilter(w)) { anyMatch = true; break; }
    if (!anyMatch && gApp.guideFilter[0]) return;
    ImGuiTreeNodeFlags flg = defaultOpen ? ImGuiTreeNodeFlags_DefaultOpen : 0;
    if (gApp.guideFilter[0]) flg |= ImGuiTreeNodeFlags_DefaultOpen;
    ImGui::PushStyleColor(ImGuiCol_Header,        ImVec4(0.18f, 0.32f, 0.52f, 0.7f));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0.24f, 0.42f, 0.66f, 0.85f));
    ImGui::PushStyleColor(ImGuiCol_HeaderActive,  ImVec4(0.30f, 0.50f, 0.78f, 1.00f));
    bool open = ImGui::CollapsingHeader(name, flg);
    ImGui::PopStyleColor(3);
    if (open) {
        ImGui::Spacing();
        for (auto& w : wfs) DrawWorkflow(w);
    }
}

static void DrawGuideModal() {
    if (!gApp.showGuide) return;
    ImGui::SetNextWindowSize(ImVec2(960, 760), ImGuiCond_FirstUseEver);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, clr::panel);
    if (ImGui::Begin("Workflow Guide", &gApp.showGuide,
                     ImGuiWindowFlags_NoCollapse)) {
        ImGui::PushStyleColor(ImGuiCol_Text, clr::sectHdr);
        ImGui::Text("Memiscani  -  workflow recipes");
        ImGui::PopStyleColor();
        ImGui::SameLine(0, 16);
        ImGui::SetNextItemWidth(280);
        ImGui::InputTextWithHint("##gf", "filter workflows...", gApp.guideFilter, sizeof(gApp.guideFilter));
        ImGui::TextDisabled("Each workflow lists the tabs and buttons to use, in order.  Hotkeys: F6/F7 First/Next scan, F8 Stop, F9 Snapshot, F10 Diff, F11/F12 Live/Keep, F1-F5 cheats.");
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::BeginChild("##gscroll", ImVec2(0, -2), false);

        DrawCategory("A.  Finding values in memory", {
            {
                "1.  HP / health  (small bounded int, typical 0-1000)",
                "Most games store HP as int32 in [0..1000] or float [0..100].  Try int32 first.  Example: Skyrim HP is float around 100, GTA V health is int32 ~200, Souls games int32 ~3000.",
                {
                    "Scanner: Type=int32, Match=Exact, Value=your-on-screen-HP, Range Min=1 Max=10000.",
                    "First Scan.  Status bar shows e.g. 'Baseline 12,847 results' - too many but normal.",
                    "Take some damage in-game (drop e.g. 100 -> 73).",
                    "Update Value=73, Next Scan.  Result count typically drops to 5-200.",
                    "Heal back to 100 (or another value).  Next Scan with new value.",
                    "After 3-5 cycles you should have 1-10 results - usually one is the real HP.",
                    "Click a row, in Selected strip use 'Auto-detect type' to confirm it's int32 (will show >70% plausibility).",
                    "Bookmark it (button on Selected strip) - 'Goto' brings you back instantly.",
                    "Write a new value (try a small change like +50 to verify, then go big for godmode).",
                    "If HP doesn't visibly change: it's probably max-HP, not current.  Try the inverse (find current HP first)."
                }
            },
            {
                "2.  Gold / money / score  (mid-range int32 or int64)",
                "Values typically 10..1e9 for int32, up to 1e15 for int64.  Round numbers (multiples of 100) are common - leverage 'Score Now' bonus.",
                {
                    "Scanner: Type=int32, Match=Exact, Value=current money, Range Min=1 Max=1000000000.",
                    "First Scan.  Expected count: 500-50,000 rows.",
                    "Spend or earn a noticeable amount in-game (e.g. 5000 -> 4750).",
                    "Update Value, Next Scan.  Count drops to typically 5-50.",
                    "If you see >50 still, run 'Start Live' on the Scanner, change money a few times, 'Keep Chg' then 'Score Now'.",
                    "Top-scored row should be it - 'Score' column shows ~70-90 for real bounded values.",
                    "Watch it: open Watch tab, 'From Scanner selection', leave it pinned.  You'll see the value flash orange whenever it changes."
                }
            },
            {
                "3.  Percentage / multiplier  (float 0.0-1.0 or 0-100)",
                "Stamina bars, damage multipliers, speed values.  Float type is critical here - integer scans will miss them entirely.",
                {
                    "Scanner: Type=float, Match=Exact, Value=current% (e.g. 1.0 for 100%, or 0.5 for 50%).",
                    "Range: 0.0 to 100.0 (or 0.0 to 1.0 - whichever your game uses).",
                    "First Scan.  Count typically 1,000-30,000 rows.",
                    "Use the stamina bar a bit so it drops to e.g. 0.73.",
                    "Update Value to 0.73, Next Scan.  Float matches are sometimes inexact - if you get 0 results, change Match to 'Decreased' (since value went down) and Next Scan.",
                    "If Match=Decreased gives too many, refill stamina then Match=Increased to filter further.",
                    "After 2-3 cycles: handful of candidates.  Auto-detect type to confirm float plausibility >70%.",
                    "Write 100.0 (or 1.0) to test - if stamina bar fills to full instantly, you found it."
                }
            },
            {
                "4.  Position / coordinate  (float, world units)",
                "Player X/Y/Z position.  Usually three consecutive 4-byte floats in same struct.  Find one and the others are at +4 and +8.",
                {
                    "Stand still in-game.  Move 1 step right (just slightly).  Note your X position changed by a tiny amount.",
                    "Scanner: Type=float, Match=Unknown Initial, Writable ON.  First Scan.  Expected: 100,000+ rows.",
                    "Start Live.  Move slightly forward/back several times in-game.  Stop Live.",
                    "Keep Chg.  Now Score Now and Keep Top with N=200.",
                    "Wait near the top will be X, Y, Z float values.  Z is usually largest (height).",
                    "Click one row, look at 'Range' column - position values typically have range 1-100 over a few moves.",
                    "Once you find one coordinate: write a teleport value, then check +4 and +8 in Hex View tab to find Y and Z."
                }
            },
            {
                "5.  Counter / level / ammo count  (int8 or int16, small range)",
                "Bullets in magazine (0-100), inventory slot count (0-100), level (0-50). Try int8 first since it's tightest, fewer false positives.",
                {
                    "Scanner: Type=int8, Match=Exact, Value=current count, Range Min=0 Max=100.",
                    "First Scan.  Count: 5,000-100,000 (int8 is everywhere).",
                    "Fire one shot.  Update Value=N-1.  Next Scan.",
                    "Reload (count goes back up).  Update Value=N.  Next Scan.",
                    "After 3-4 cycles: usually <20 candidates.  Final test: write a wild value (200), check in-game.",
                    "If display didn't change: try int16 or int32 in a fresh scan."
                }
            },
            {
                "6.  Flag / boolean  (int8 holding 0/1, or int32)",
                "Settings booleans, ability unlocks, quest flags.  Use Range 0..1 to massively cut baseline.",
                {
                    "Scanner: Type=int8, Match=Unknown Initial, Range 0..1.",
                    "First Scan.  Expected: a few thousand candidates.",
                    "Toggle the flag in-game (e.g. enter/exit menu).",
                    "Match=Changed, Next Scan.  Count drops sharply (usually 5-100).",
                    "Toggle a few more times with Changed + Unchanged alternating.",
                    "Final write: 0 to disable, 1 to enable.  Some flags need server validation - test in single-player first."
                }
            },
            {
                "7.  String  (player name, dialog, settings)",
                "Player name, server address, file paths.  Usually UTF-8 / ANSI; some engines use UTF-16.",
                {
                    "Scanner: Type=String, Value=the exact text you see.",
                    "First Scan.  Count: 5-200 hits typically.",
                    "If no results: the string is UTF-16.  Workaround: enter every other character with spaces (e.g. 'P l a y e r').",
                    "Click any hit, the Selected strip shows surrounding bytes.  Patcher tab -> Read to see context.",
                    "To edit: Patcher tab, paste new bytes (use db 'H','i', 0  pattern for ASCII strings)."
                }
            },
            {
                "8.  AOB pattern  (signature scan for a function entry)",
                "Locate a function by its byte pattern when the address changes between game versions.",
                {
                    "Scanner: Type=AOB, Value=the pattern (e.g. 48 8B 05 ?? ?? ?? ?? 48 85 C0).",
                    "First Scan.  Expected hits: usually 1-5.",
                    "Click each hit -> check Disasm in Selected strip to confirm it's the function you wanted (mnemonic should look right, e.g. 'mov rax, [rip+...]').",
                    "Once confirmed: Patcher tab and generate a signature from THIS address with the AOB generator - now your patch will resolve correctly across game updates."
                }
            },
        }, true);

        DrawCategory("B.  Tracking values over time", {
            {
                "9.  Snapshot + Diff workflow  (event-driven refinement)",
                "Take baseline snapshot, trigger event, filter changed.  Best when event is repeatable but causes many addresses to change at once.",
                {
                    "Scanner with non-empty results.",
                    "Click Take Snapshot.  Status: 'Snapshot captured.'",
                    "Trigger event in target (level up / take damage / open menu / etc).",
                    "Click Find Changed (or Inc/Dec for direction).  Result count drops typically 10-100x.",
                    "Hotkeys: F9 snapshot, F10 find changed - work even when target is focused.",
                    "Expected outcome after 2-3 snapshot-diff cycles: under 20 candidates."
                }
            },
            {
                "10.  Live Monitor + Heuristic Score  (catch flickering / sub-second changes)",
                "Use when value flickers fast (damage flash, animation tick) and a normal scan misses it.",
                {
                    "Scanner with results (Unknown Initial First Scan is fine).",
                    "Click Start Live (or F11).  Sampling every 50 ms.",
                    "In target: trigger the event 5-15 times over ~10 seconds.",
                    "Click Stop Live, then Keep Chg.  Results: only addresses that moved.",
                    "Click Score Now.  Top-scored rows show 'up/down' direction, sparkline of recent changes, and a score 0-100.",
                    "Keep Top with N=50.  Game-state values typically rank 60-90.",
                    "Keep Bounded MaxD=100 keeps only addresses with tight range - perfect for HP/MP/ammo."
                }
            },
            {
                "11.  Watch list  (multi-address live monitor)",
                "Pin specific addresses (HP, MP, gold) to monitor simultaneously without rerunning scans.",
                {
                    "Watch tab.",
                    "Type a name + paste an address + pick type.  Click Add.",
                    "Or with an address selected in Scanner: click 'From Scanner selection' on Watch tab.",
                    "Tick is automatic (200 ms).  Changed values flash orange for ~600 ms.",
                    "Save / Load persists to memiscani_watch.txt - bring your watchlist between sessions.",
                    "Click a Watch row's 'Select' to send it back to the Scanner."
                }
            },
            {
                "12.  Tampering / state verify",
                "Detect changes to modules / threads after running suspect operations (e.g. testing if a DLL was injected).",
                {
                    "Verify tab.  Click Take snapshot.",
                    "Run the operation under test (inject DLL, launch tool, etc).",
                    "Click Diff now.",
                    "modulesAdded shows newly-loaded DLLs; threadsAdded shows new TIDs.",
                    "Common findings: injected DLL appears, new thread spawned at strange RIP."
                }
            },
        });

        DrawCategory("C.  Stable / pointer-resolved addresses", {
            {
                "13.  Manual pointer chain",
                "When you have a known module+offset+[derefs] chain from a writeup or your own reversing.",
                {
                    "Pointers tab.  Fill: name, module (e.g. 'game.exe'), base offset hex, comma-sep offset list.",
                    "Click Add chain.  Then Resolve - the resolved address goes to Scanner selected.",
                    "Click Save to persist to memiscani_chains.txt.  Survives restarts."
                }
            },
            {
                "14.  Auto pointer scan  (find chains rooted in static memory)",
                "Convert one-shot scan hit into a stable cross-launch address.  Critical for cheats that must survive game restarts.",
                {
                    "Find an address by any method.  Click it in results to select.",
                    "Auto Ptr tab -> 'From selected'.  Max depth=3, Max offset=0x800 are the standard defaults.",
                    "Click Scan chains.  Wait - reads a lot of memory.  Expected: 5-500 chains.",
                    "Each row: module + base offset + offsets list.  Click any -> auto-saved as chain on Pointers tab.",
                    "Save chains to file.  After restart: Load chains, Resolve, the new (potentially-different) address pops up correctly."
                }
            },
            {
                "15.  Bookmarks (named addresses with notes)",
                "Quick-access library of important addresses you discovered, with context notes.",
                {
                    "Bookmarks tab.  Type name + address + type + free-form note.  Add.",
                    "Or with selected address: 'From Scanner'.",
                    "Save persists to memiscani_bookmarks.txt.",
                    "Click any row -> 'Goto' to make that address the Scanner selected."
                }
            },
        });

        DrawCategory("D.  Patching code / values", {
            {
                "16.  NOP an instruction  (disable a code path)",
                "Disable cooldown subtraction, fall damage, ammo decrement.  Find the writer first via HW BP.",
                {
                    "Disasm tab -> 'From selected' on the offending instruction.",
                    "Patcher tab.  Set Addr to the instruction RIP, Size to the instruction byte count (read it first).",
                    "Click NOP N bytes (where N = instruction length, usually 3-7).",
                    "Test in-game - the relevant value should stop changing.  Restore on the row to undo."
                }
            },
            {
                "17.  Inline assembler  (write code by mnemonics)",
                "Type 'mov rax, 1; ret' instead of computing E9 bytes by hand.",
                {
                    "Patcher tab -> Inline assembler section.",
                    "Type asm source (one inst per line).  Supports mov/lea/push/pop/arithmetic/jcc/jmp/call/db/dw/dd/dq/labels.",
                    "Click Assemble.  Bytes appear in the bytes field above.",
                    "Set the Address, click Write Bytes."
                }
            },
            {
                "18.  CE-style cheat script  (multi-patch unit, toggleable)",
                "Bundle multiple byte writes that should turn on/off together; hotkey for quick toggle.",
                {
                    "Cheats tab -> New.  Set Name + Hotkey (F1-F5).",
                    "Script with [ENABLE] / [DISABLE].  Inside each: addr labels + db/dw/dd/dq/nop directives.",
                    "Example  [ENABLE]:   game.exe+12345:    db 90 90 90 90 90",
                    "Apply edits -> Test ENABLE in single-player -> Toggle ON/OFF.",
                    "Press F-key in target to flip - works in fullscreen.",
                    "Save table to a .ct.txt file to keep across sessions."
                }
            },
            {
                "19.  Trampoline hook  (intercept a function with custom logic)",
                "True code hook: splice a JMP at target, run your code in a cave, restore original bytes, JMP back.",
                {
                    "Patcher tab -> Trampoline hook section.",
                    "Target = the function entry (e.g. damage handler).  Stolen = 14 (default for 14-byte abs JMP).",
                    "Payload (asm source): write whatever you want to run before the original code, e.g. 'mov dword ptr [rcx+0x20], 0'.",
                    "Click Install hook.  A code cave is allocated, your payload + relocated stolen bytes + JMP back are written, then JMP installed at target.",
                    "When the function executes, your code runs first.  Uninstall any time to restore."
                }
            },
            {
                "20.  AOB-portable patch  (survives game updates)",
                "Build a unique byte signature for a patch site so the cheat keeps working when the game version changes the absolute address.",
                {
                    "Find the patch site (Scanner or HW BP).",
                    "Patcher tab -> AOB signature generator -> Generate.",
                    "Copy pattern to clipboard - it has ?? wildcards for relocatable bytes (RIP-rel, call/jmp displacements).",
                    "In your cheat script:  before the [ENABLE] section, do an AOB scan in code (or paste it as documentation), then patch the discovered address."
                }
            },
            {
                "21.  Freeze a value  (lock to a constant via hotkey or write-back)",
                "Effective for HP/score/ammo locks.",
                {
                    "Find the address.  Open Cheats tab -> New.",
                    "[ENABLE]:  0xADDRESS:    dd 999999    (or dq for 8-byte)",
                    "Bind a hotkey F1-F5.  Press to re-apply if the game overwrites it.",
                    "Or use a trampoline hook on the WRITER instruction (find with HW BP) to make the value never decrement."
                }
            },
        });

        DrawCategory("E.  Find what reads / writes  (Hardware Breakpoints)", {
            {
                "22.  Find what WRITES an address  (find the function that modifies HP)",
                "Single most powerful workflow.  Sets DR0 + DR7 via SetThreadContext, traps the writer with single-step.",
                {
                    "Scanner: find the target value (e.g. HP).  Click row to select it.",
                    "HW BP tab.  Type=Write, Length=4 byte (for int32).",
                    "Click 'Enable trace'.  Status shows 'TRACING - watch 0x...'.",
                    "Trigger the event (take damage, level up, etc).",
                    "Hits appear in the table: TID, offender RIP, disassembled instruction, ms timestamp.",
                    "Click Disable trace when done.  Expected: 1-5 distinct offenders per write event.",
                    "Click an offender RIP -> that address becomes the Scanner-selected.  Now Disasm tab to see context, or Patcher tab to NOP it."
                }
            },
            {
                "23.  Find what READS an address  (find code that consumes a value)",
                "Useful for finding aimbot input variables, render-time data, AI decision routines.",
                {
                    "Same as workflow 22 but Type=Read+Write (DR can't do 'read only' alone).",
                    "Filter the offender table - reads from a value tend to far outnumber writes.  Use the substring filter on the disasm column."
                }
            },
            {
                "24.  Execute breakpoint  (catch when control reaches a code address)",
                "Cheap alternative to traditional debugger breakpoint - lets you confirm a function entry is being hit.",
                {
                    "Scanner: bookmarked function entry RIP (or any code address).  Select it.",
                    "HW BP tab: Type=Execute, Length=1.  Enable trace.",
                    "Trigger the function call.  Single hit logged with caller's RIP."
                }
            },
            {
                "25.  Stack walker on a thread (who called who)",
                "After HW BP catches a writer, run the stack walker to see the call chain.",
                {
                    "Note the TID from a HW BP hit.",
                    "Code Inj tab -> Stack walker section.  Enter TID + Walk stack.",
                    "Result: list of RIPs that look like return addresses inside loaded modules.  Each shows module+offset + Zydis disasm of the suspected call site."
                }
            },
        });

        DrawCategory("F.  Code injection & remote execution", {
            {
                "26.  Inject a DLL",
                "Load a helper / proxy / cheat-loading DLL into the target.",
                {
                    "Modules tab.  Paste absolute path.  Inject DLL.",
                    "Refresh - confirm the DLL is in the list.",
                    "To unload: Eject with name substring."
                }
            },
            {
                "27.  Inject + execute custom shellcode",
                "Drop raw bytes into target and run.",
                {
                    "Code Inj tab.  Paste hex bytes (or Inline Assembler -> assemble first).",
                    "Inject + Execute.  Status shows new TID.  Address auto-pushed to Trigger tab.",
                    "If you just want to upload (no run): Inject (no exec)."
                }
            },
            {
                "28.  Trigger code at an arbitrary address",
                "Run code that already exists in target memory (your injection, or an existing function).",
                {
                    "Trigger tab.  Address + optional parameter (hex).",
                    "CreateRemoteThread: spawns new thread starting at address.  Captures TID.",
                    "QueueUserAPC: piggybacks on existing alertable thread by TID."
                }
            },
            {
                "29.  Eject a DLL when done",
                "Clean teardown.",
                {
                    "Modules tab -> Eject section.  Name substring (e.g. 'mycheat').  Eject.",
                    "Uses CreateRemoteThread(FreeLibrary)."
                }
            },
        });

        DrawCategory("G.  Inspection / analysis", {
            {
                "30.  Disassemble around an address",
                "See what code lives at a given address.",
                {
                    "Disasm tab.  Target + Bytes (256 = ~50 instructions).  Disassemble.",
                    "Or quick-look: any Scanner row, when selected, shows live Zydis disasm in the Selected strip."
                }
            },
            {
                "31.  Auto-detect data type",
                "Don't know if an address holds int32, float, or pointer?  Let the heuristic guess.",
                {
                    "Click any row in Scanner results.",
                    "Selected strip -> 'Auto-detect type'.",
                    "Modal opens with ranked guesses: int32 87% / float 73% / pointer 0% etc.  Click a row to apply that type to the Scanner."
                }
            },
            {
                "32.  Memory hex viewer / editor",
                "Inspect raw bytes around an address.  Click cells to edit single bytes.",
                {
                    "Hex View tab.  Address + bytes count.  Read.",
                    "16 bytes per row, hex + ASCII pane.  Click any hex cell -> modal to edit that byte.",
                    "Jump -64 / +64 to scroll through memory."
                }
            },
            {
                "33.  PE info  (sections + imports + exports of a module)",
                "Inspect a DLL's structure - useful for finding hooks, suspicious imports, IAT pointers.",
                {
                    "PE Info tab.  Refresh modules.  Pick a module from the combo.",
                    "Three views: Sections (.text/.data/.rdata with R/W/X), Imports (resolved IAT entries), Exports (function name -> address)."
                }
            },
            {
                "34.  Detect injection",
                "Defensive scan for suspicious memory regions / threads in a target.",
                {
                    "Detect Inj tab.  Enable RWX + Private+Exec + Thread anomaly.",
                    "Run scan.  Categories: RWX (warn), PRIV+EXEC (err), THREAD (warn).",
                    "Click a THREAD finding -> open Code Inj tab to inspect/suspend/kill."
                }
            },
            {
                "35.  Module exports browser",
                "Find target's WinAPI / engine function addresses.",
                {
                    "Exports tab -> Enumerate exports.  Filter by module or function name.",
                    "Click any row -> address becomes Scanner-selected.  Trigger that address from the Trigger tab if desired."
                }
            },
            {
                "36.  Suspend whole process for safe inspection",
                "Stop the target so values don't change while you investigate.",
                {
                    "Top bar -> Suspend Process.  All threads suspended.",
                    "Hex View / Disasm / Scanner now stable.",
                    "Click Resume Process when done."
                }
            },
        });

        DrawCategory("H.  Window / process control", {
            {
                "37.  Send keystrokes / messages to target HWND",
                "Drive a UI or close a popup programmatically.",
                {
                    "Windows tab.  Refresh.  Click target HWND row.",
                    "Set Text + Set Text button (WM_SETTEXT).",
                    "Or PostMessage with custom Msg + wParam + lParam.",
                    "State buttons: Show / Hide / Min / Max / Restore / Close."
                }
            },
        });

        DrawCategory("I.  End-to-end combined workflows", {
            {
                "38.  Infinite HP with cross-restart stability",
                "Scanner -> Live Monitor -> Auto Ptr -> Bookmark -> Cheat script with hotkey.",
                {
                    "Scanner: find HP via workflow 1.",
                    "Confirm via workflow 10 (Live Monitor + Score).",
                    "Auto Ptr scan on the address (workflow 14).  Click best chain - saved on Pointers tab.",
                    "Bookmark the chain root.",
                    "Cheat script: [ENABLE] block writes 999999 at the resolved address.  Hotkey=F1.",
                    "After game restart: Load chain, Resolve, the cheat works at the new dynamic address."
                }
            },
            {
                "39.  Find what writes HP, NOP the writer, victory",
                "Best workflow for godmode without value-freeze.",
                {
                    "Find HP (workflow 1).  Select it.",
                    "HW BP tab: Write, 4 byte, Enable trace.",
                    "Take damage.  Offender RIP logged - probably the damage handler.",
                    "Click the offender row -> Disasm tab -> 'From selected' to see context.",
                    "Patcher tab: NOP N bytes where N is the offending instruction's length (read it via Patcher Read first).",
                    "Test: take damage -> HP shouldn't drop.  Restore the patch via Applied patches list if you break the game."
                }
            },
            {
                "40.  Make the patch portable with AOB sig",
                "After workflow 39, the patch address will change on next game update.  AOB-sig it.",
                {
                    "Stay on the offender RIP.",
                    "Patcher tab -> AOB signature generator -> Generate.",
                    "Copy pattern.  Now your cheat script (or a notes file) records:  pattern + offset-into-pattern-where-to-NOP.",
                    "Next game version: AOB scan with the pattern (Scanner Type=AOB), find the new address, NOP at the same instruction offset."
                }
            },
            {
                "41.  Drop a helper DLL then call one of its exports",
                "Combines DLL injection + Exports tab + Trigger tab.",
                {
                    "Modules tab -> Inject DLL with your helper.",
                    "Exports tab -> Enumerate.  Filter to your DLL's name.  Click the function you want -> Scanner-selected.",
                    "Trigger tab -> CreateRemoteThread with that address + an optional parameter."
                }
            },
            {
                "42.  Find structure layout from one field",
                "Once you have HP, find max-HP / stamina / armor adjacent in the same struct.",
                {
                    "Got HP at address A.  Hex View tab: Read 128 bytes at A-32 to see struct context.",
                    "Look for floats / ints near A that change at the same time.  Common layout: [hp, maxHp, stamina, maxStamina, ...] all 4-byte aligned.",
                    "Bookmark each field with note like 'HP', 'maxHP', etc.",
                    "Trampoline-hook the struct's update function to set max=maxHP every frame -> never lose stats."
                }
            },
            {
                "43.  Trampoline hook a damage calculator (real godmode)",
                "Instead of NOPing the writer (which can break other code), intercept the function and zero the damage parameter.",
                {
                    "HW BP -> find damage WRITER (workflow 22).",
                    "Stack walker on the writer's TID -> find the CALLER (the damage function).",
                    "Disasm at the caller to find the parameter holding damage amount (often rdx or [rsp+xx]).",
                    "Patcher tab -> Trampoline hook on the function entry.  Payload: 'mov rdx, 0; jmp original' (the trampoline appends original bytes + JMP-back for you).",
                    "Test - damage events fire but with 0 damage."
                }
            },
            {
                "44.  Audit a process for malicious injection",
                "Detect Inj + Stack walker + Verify snapshot.",
                {
                    "Verify tab: Snapshot when process starts clean.",
                    "Detect Inj tab: RWX + Private+Exec + Thread anomaly.  Run.",
                    "Any THREAD finding -> Code Inj tab, Stack walker that TID.",
                    "PE Info tab: pick the suspicious module, check Imports for LoadLibrary / GetProcAddress (classic injector pattern)."
                }
            },
        });

        DrawCategory("J.  Lua scripting", {
            {
                "45.  Read / write values with a Lua one-liner",
                "Fastest way to inspect or set a value when you already know the address.  Open the Lua tab.",
                {
                    "Open the Lua tab.",
                    "Replace the starter script with: log(string.format('hp=%d', mem.read_i32(0x7FF6C0FE1234)))",
                    "Click Run.  Output shows the current value.",
                    "Set: mem.write_i32(0x7FF6C0FE1234, 9999)",
                    "Combine: local hp = mem.read_i32(addr); mem.write_i32(addr, math.max(hp, 9999))"
                }
            },
            {
                "46.  AOB scan in Lua then patch",
                "Game-version-portable patches without manual address tracking.",
                {
                    "Lua tab.  Script:",
                    "  local hits = mem.aob_scan('48 8B 05 ?? ?? ?? ?? 48 85 C0')",
                    "  if #hits == 0 then log('no match'); return end",
                    "  if #hits > 1 then log('warning: '..#hits..' matches, picking first') end",
                    "  local addr = hits[1]",
                    "  log(string.format('found 0x%X', addr))",
                    "  mem.write_bytes(addr, '\\x90\\x90\\x90\\x90\\x90')",
                    "Run.  If pattern is unique you've just NOPed it."
                }
            },
            {
                "47.  Long-running freeze loop with Stop button",
                "Continuously re-write a value (HP / score lock) until you click Stop.",
                {
                    "Lua tab.  Script:",
                    "  local addr = 0x7FF6C0FE1234",
                    "  while true do",
                    "    mem.write_i32(addr, 9999)",
                    "    mem.sleep(100)            -- check Stop request every 100 ms",
                    "  end",
                    "Run.  Click Stop to break out cleanly."
                }
            },
            {
                "48.  Walk a struct by reading consecutive offsets",
                "Build your own analyzer when the layout has many adjacent fields.",
                {
                    "  local base = 0x7FF6...",
                    "  for off = 0, 0x80, 4 do",
                    "    local v = mem.read_i32(base + off)",
                    "    local f = mem.read_f32(base + off)",
                    "    log(string.format('+0x%02X  i32=%d  f32=%.4f', off, v or 0, f or 0))",
                    "  end"
                }
            },
            {
                "49.  Disassemble around an address",
                "Quick code preview without leaving the tab.",
                {
                    "  for _,l in ipairs(mem.disasm_range(0x7FF6..., 128)) do",
                    "    log(string.format('0x%X  %s', l.addr, l.text))",
                    "  end"
                }
            },
            {
                "50.  Allocate + write + execute (manual shellcode runner)",
                "Same as Code Inj tab but scripted - useful when you want to template the bytes.",
                {
                    "  local sc = '\\xB8\\x2A\\x00\\x00\\x00\\xC3'   -- mov eax,42; ret",
                    "  local p = mem.alloc(#sc); mem.write_bytes(p, sc)",
                    "  log(string.format('shellcode at 0x%X', p))",
                    "  -- now trigger it via the Trigger tab with this address"
                }
            },
            {
                "51.  How to actually run a Lua script (zero-to-first-run)",
                "If you've never touched the Lua tab before, follow this once.",
                {
                    "Top bar: Attach to a target process.",
                    "Click the Lua tab.",
                    "In the toolbar row, click any 'Insert example' button (Hello / Read i32 / etc.).  The example is pasted into the script editor.",
                    "Replace any placeholder addresses (default 0x7FF6C0FE1234) with the address you care about.",
                    "Click 'Run'.  Output appears on the right.",
                    "If it loops forever (e.g. Freeze loop): click 'Stop' - the stop signal fires at the next mem.sleep() or after ~1000 instructions.",
                    "Click 'Save' (toolbar) to save the script to a .lua file for next time.  Memiscani also auto-saves whatever script you have open at exit to memiscani_lua_state.lua and reopens it next launch."
                }
            },
            {
                "52.  Module + offset addressing in Lua (CE-style 'game.exe+OFFSET')",
                "Lua equivalent of the 'game.exe+1234' notation from the Cheats tab.",
                {
                    "  local b = mem.find_module('game.exe')      -- nil if not loaded",
                    "  if not b then return end",
                    "  local addr = b + 0x12345",
                    "  log(string.format('addr = 0x%X', addr))",
                    "  log('value: ' .. tostring(mem.read_i32(addr)))",
                    "  log('disasm: ' .. mem.disasm(addr))"
                }
            },
            {
                "53.  Lua + AOB-scan + write_bytes (portable patch in one script)",
                "Combine workflow 46 with portability of workflow 20.  The result is a single .lua file you can run after a game update without remembering an address.",
                {
                    "  local pat = '48 8B 05 ?? ?? ?? ?? 48 85 C0'   -- get from Patcher AOB sig gen",
                    "  local hits = mem.aob_scan(pat)",
                    "  if #hits ~= 1 then log('expected exactly 1 hit, got '..#hits); return end",
                    "  mem.write_bytes(hits[1], '\\x90\\x90\\x90\\x90\\x90')  -- NOP 5 bytes",
                    "  log('patched.')"
                }
            },
            {
                "54.  Lua callback-style polling (no infinite while-loop)",
                "Sometimes you want a 'check every N ms' workflow without a busy while-true.  This still uses sleep but is the canonical pattern.",
                {
                    "  local addr  = 0x7FF6C0FE1234",
                    "  local last  = nil",
                    "  while true do",
                    "    local v = mem.read_i32(addr)",
                    "    if v ~= last then log(string.format('changed: %s -> %s', tostring(last), tostring(v))); last = v end",
                    "    mem.sleep(200)",
                    "  end"
                }
            },
        });

        DrawCategory("K.  Session save / load + scan filters", {
            {
                "55.  Save and restore your scan session across restarts",
                "Don't lose 30 minutes of scan work because you closed the app.",
                {
                    "Top bar: 'Save Session' writes memiscani_session.dat next to the exe.  Captures: scan params, all results + their previous values, snapshot, live-monitor stats.",
                    "Top bar: 'Load Session' restores everything.  If the target's PID is still alive it auto-re-attaches.",
                    "On clean exit, the session is auto-saved.  On startup, if memiscani_session.dat exists it is auto-loaded.",
                    "The Lua editor's current contents are also auto-saved to memiscani_lua_state.lua and restored next launch.",
                    "Watch / Bookmarks / Pointer chains / Cheats have their own separate persistence (Save/Load buttons inside each tab) - those already survive restarts."
                }
            },
            {
                "56.  Scan inside a specific address range",
                "Use to skip kernel space, focus on a heap region you know about, etc.",
                {
                    "Scanner tab.  Set 'addr start (0x...)' to your lower bound (e.g. 0x10000000).",
                    "Set 'addr stop (0x...)' to your upper bound (e.g. 0x7FFFFFFFFFFF to cap to user mode).",
                    "First Scan.  Pages outside [start..stop] are skipped entirely.  Often 5-10x faster on bloated processes.",
                    "Tip: discover a useful range from the Memory Map / Detect Inj tabs first.",
                    "Tip: combine with 'Mod filter' to scan only inside a specific DLL's allocation."
                }
            },
            {
                "57.  Scan only executable memory  (or only copy-on-write)",
                "Filter to specific protection classes for code-vs-data investigations.",
                {
                    "Scanner tab.  Check 'Exec only' to scan only PAGE_EXECUTE_* pages.  Use this to find code, vtables, JIT-compiled functions.",
                    "Or check 'CoW only' to scan only PAGE_WRITECOPY pages (loaded module .data sections that the process has modified - hot configuration).",
                    "Or check 'Active mem' to scan only the working-set pages (pages currently resident in RAM, skipping paged-out memory).  Massive speedup on processes with multi-GB committed but mostly idle.",
                    "These three checkboxes are mutually overriding - exec-only overrides writable / CoW etc."
                }
            },
            {
                "58.  Fast scan: alignment + skip zero + skip suffix",
                "Cuts scan time without changing data type.",
                {
                    "Scanner tab.  'Align' dropdown - set to a fixed alignment (e.g. 4 for int32) so the scanner steps in 4-byte increments instead of byte-by-byte.  'Auto' uses the data-type size which is almost always what you want.",
                    "'Skip zero' checkbox - skips addresses whose value is all zeros.  Huge speedup for fresh allocations / .bss sections.",
                    "'Skip suffix' field - skip addresses whose lower hex digits match.  E.g. '00' skips every address ending in 0x..00 (cuts 1/256 of work cheaply).  '0000' skips page-aligned bottoms.",
                    "All of these are compatible with Snapshot/Diff and Live Monitor - the reduced result set carries through unchanged."
                }
            },
        });

        DrawCategory("K.  Quick-reference value/type cheatsheet", {
            {
                "Common in-game values - type defaults that almost always work",
                "Use these as your first guess.  If a 'Find Changed' returns 0 results after an obvious change, your type or range is wrong.",
                {
                    "HP / health bar  -  int32 in [1..10000] or float in [0..100]",
                    "Gold / money / score  -  int32 in [0..1e9] or int64 if you see commas/dots",
                    "Ammo / counter  -  int8 in [0..255] (try this FIRST, smallest false-positive rate)",
                    "Level / XP  -  int16 in [0..32767] (XP) or int8 in [0..100] (level)",
                    "Percentage  -  float in [0..1] OR [0..100]; try both",
                    "Position X/Y/Z  -  three consecutive 4-byte floats",
                    "Cooldown  -  float in [0..tens of seconds]; may be ticks (int32)",
                    "Quest / settings flag  -  int8 holding 0 or 1; sometimes int32",
                    "Player name  -  String (ANSI or UTF-16) at game's player struct",
                    "Pointer  -  64-bit qword in [0x10000..0x7FFFFFFFFFFF]; use Auto-detect type to confirm"
                }
            },
            {
                "How many results to expect at each stage",
                "If you see WAY more or WAY less than these, something is off.",
                {
                    "First Scan, Unknown Initial + Writable + Range:           1,000 - 50,000",
                    "First Scan, Exact value (int32 small number):             500 - 200,000",
                    "After 1 Next Scan with new value:                          5 - 5,000",
                    "After 2-3 Next Scans:                                      1 - 100",
                    "After Live Monitor + Keep Chg:                             10 - 2,000",
                    "After Score Now + Keep Top 50:                             1 - 50  (real target usually top 5)",
                    "Auto Pointer Scan with depth=3 maxOff=0x800:               5 - 500 chains",
                    "HW BP write trace on a single event:                       1 - 5 distinct offenders"
                }
            },
        });
        ImGui::EndChild();
        ImGui::End();
    }
    ImGui::PopStyleColor();
}

static void DrawComingSoon(const char* name, const char* what) {
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, clr::sectHdr);
    ImGui::Text("%s  -  MVP coming next session", name);
    ImGui::PopStyleColor();
    ImGui::Spacing();
    HintText("%s", what);
    ImGui::Spacing();
    ImGui::TextDisabled("Use legacy memiscani.exe for this tab in the meantime - all logic exists there and will be ported to memcore/ImGui in the next pass.");
}

static LRESULT CALLBACK LowLevelKbProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* k = (KBDLLHOOKSTRUCT*)lParam;
        if (k->vkCode >= VK_F1 && k->vkCode <= VK_F5) {
            int vk = (int)k->vkCode;
            for (size_t i = 0; i < mem::g_cheats.size(); i++) {
                if (mem::g_cheats[i].hotkeyVK == vk) {
                    std::string err;
                    mem::cheatToggle(i, err);
                    return 1;
                }
            }
        }
    }
    return CallNextHookEx(gApp.kbHook, nCode, wParam, lParam);
}

static void DrawMainUI() {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("##main", NULL,
        ImGuiWindowFlags_NoTitleBar|ImGuiWindowFlags_NoResize|ImGuiWindowFlags_NoMove|
        ImGuiWindowFlags_NoCollapse|ImGuiWindowFlags_NoBringToFrontOnFocus|ImGuiWindowFlags_NoNavFocus);
    ImGui::PopStyleVar();

    DrawTopBar();
    StatusBar();
    DrawSelectedStrip();

    ImGui::PushStyleColor(ImGuiCol_ChildBg, clr::panel);
    ImGui::BeginChild("##tabsHost", ImVec2(0, -2), true);
    if (ImGui::BeginTabBar("tabs", ImGuiTabBarFlags_Reorderable|ImGuiTabBarFlags_FittingPolicyResizeDown)) {
        ImGuiTabItemFlags scTabFlags = gApp.forceScannerTab ? ImGuiTabItemFlags_SetSelected : 0;
        gApp.forceScannerTab = false;
        if (ImGui::BeginTabItem("Scanner", nullptr, scTabFlags)) { DrawScannerTab(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Watch"))      { DrawWatchTab();   ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Bookmarks"))  { DrawBookmarksTab(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Hex View"))   { DrawHexTab();     ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("HW BP"))      { DrawHwbpTab();    ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Modules"))    { DrawModulesTab(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("PE Info"))    { DrawPETab();      ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Patcher"))    { DrawPatcherTab(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Pointers"))   { DrawPointersTab(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Cheats"))     { DrawCheatsTab(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Lua"))        { DrawLuaTab();    ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Disasm"))     { DrawDisasmTab(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Code Inj"))   { DrawCodeInjTab();   ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Windows"))    { DrawWindowsTab();   ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Detect Inj")) { DrawDetectTab();    ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Shellcode"))  { DrawShellcodeTab(); ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Verify"))     { DrawVerifyTab();    ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Trigger"))    { DrawTriggerTab();   ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Exports"))    { DrawExportsTab();   ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Auto Ptr"))   { DrawAutoPtrTab();   ImGui::EndTabItem(); }
        if (ImGui::BeginTabItem("Network"))    { DrawNetworkTab();   ImGui::EndTabItem(); }
        ImGui::EndTabBar();
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    DrawHistoryModal();
    DrawAutoTypeModal();
    DrawGuideModal();

    ImGui::End();
    ImGui::PopStyleVar(2);
}

static void PumpLiveMonitor() {
    if (!mem::g_liveMonActive) return;
    DWORD now = GetTickCount();
    if (now - gApp.lastLiveTick >= 50) { mem::liveMonTick(); gApp.lastLiveTick = now; }
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0, 0, hInstance, NULL, NULL, NULL, NULL, L"MemiscaniIm", NULL };
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"Memiscani (ImGui)",
                              WS_OVERLAPPEDWINDOW, 80, 60, 1600, 980, NULL, NULL, wc.hInstance, NULL);
    gApp.hwnd = hwnd;
    if (!CreateDeviceD3D(hwnd)) { CleanupDeviceD3D(); UnregisterClassW(wc.lpszClassName, wc.hInstance); return 1; }

    ShowWindow(hwnd, SW_MAXIMIZE);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = "memiscani_im.ini";
    io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 16.0f);
    io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\consola.ttf", 14.0f);

    StyleDark();

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    gApp.kbHook = SetWindowsHookExA(WH_KEYBOARD_LL, LowLevelKbProc, GetModuleHandleA(NULL), 0);

    if (mem::loadSession("memiscani_session.dat")) {
        gApp.setStatus("Previous session restored.", "ok");
    }
    {
        FILE* fl = nullptr;
        if (fopen_s(&fl, "memiscani_lua_state.lua", "rb") == 0 && fl) {
            fseek(fl, 0, SEEK_END); long sz = ftell(fl); fseek(fl, 0, SEEK_SET);
            if (sz > 0 && sz < 10*1024*1024) { gApp.lua.source.resize(sz); fread(&gApp.lua.source[0], 1, sz, fl); }
            fclose(fl);
        }
    }

    {
        std::string ipcErr;
        if (memipc::start(kMcpPort, ipcErr)) {
            char b[96]; sprintf(b, "MCP server listening on 127.0.0.1:%u", (unsigned)kMcpPort);
            gApp.setStatus(b, "ok");
        } else {
            gApp.setStatus(("MCP server off: " + ipcErr).c_str(), "warn");
        }
    }
    {
        memipc::GuiHooks h;
        h.syncScan = [](const mem::ScanParams& p) {
            gApp.sc.dtIdx = (int)p.dt;
            gApp.sc.scIdx = (int)p.sc;
            strncpy(gApp.sc.valueBuf, p.value.c_str(), sizeof(gApp.sc.valueBuf) - 1);
            gApp.sc.valueBuf[sizeof(gApp.sc.valueBuf) - 1] = 0;
            gApp.sc.strEncIdx = p.strEnc;
            gApp.sc.strCaseInsensitive = p.strCaseInsensitive;
            gApp.sc.writableOnly   = p.writableOnly;
            gApp.sc.skipImage      = p.skipImage;
            gApp.sc.executableOnly = p.executableOnly;
            gApp.sc.workingSetOnly = p.workingSetOnly;
            gApp.sc.skipZero       = p.skipZero;
            gApp.forceScannerTab = true;
        };
        h.selectAddr = [](unsigned long long a) { gApp.selAddr = (LPVOID)(uintptr_t)a; };
        h.status     = [](const std::string& m) { gApp.setStatus(m.c_str(), "info"); };
        memipc::setGuiHooks(h);
    }

    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        memipc::poll();

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        PumpLiveMonitor();

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        DrawMainUI();
        ImGui::Render();
        const float bg[4] = { clr::bg.x, clr::bg.y, clr::bg.z, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, bg);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    if (gApp.kbHook) UnhookWindowsHookEx(gApp.kbHook);
    memipc::stop();
    if (gApp.scanThread.joinable()) gApp.scanThread.join();
    memlua::shutdown();
    mem::liveMonStop();

    mem::saveSession("memiscani_session.dat");
    {
        FILE* fl = nullptr;
        if (fopen_s(&fl, "memiscani_lua_state.lua", "wb") == 0 && fl) {
            if (!gApp.lua.source.empty()) fwrite(gApp.lua.source.data(), 1, gApp.lua.source.size(), fl);
            fclose(fl);
        }
    }

    mem::detach();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}

bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2; sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60; sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd; sd.SampleDesc.Count = 1; sd.Windowed = TRUE; sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    UINT createFlags = 0;
    D3D_FEATURE_LEVEL fl;
    const D3D_FEATURE_LEVEL flArr[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    HRESULT res = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createFlags,
        flArr, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &fl, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED) {
        res = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_WARP, NULL, createFlags,
            flArr, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &fl, &g_pd3dDeviceContext);
    }
    if (res != S_OK) return false;
    CreateRenderTarget();
    return true;
}
void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = NULL; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = NULL; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
}
void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer = NULL;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer) { g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView); pBackBuffer->Release(); }
}
void CleanupRenderTarget() { if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = NULL; } }

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    switch (msg) {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED) return 0;
        g_ResizeWidth  = (UINT)LOWORD(lParam);
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
        break;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}
