@echo off
REM ============================================================================
REM Memiscani build script.
REM
REM Final layout:
REM   build\                  <- THIS is your runnable folder. Self-contained.
REM     memiscani_im.exe
REM     README.txt            <- usage, hotkeys, file list
REM     samples\              <- sample Lua scripts + cheat table starter
REM       example_freeze_hp.lua
REM       example_aob_patch.lua
REM       example_struct_walk.lua
REM       example_godmode.ct.txt
REM   obj\                    <- intermediate compile cache.  Ignore.
REM     Zydis.o, liblua54.a, imgui*.o, etc.
REM     lua\                  <- Lua .o files used to assemble liblua54.a
REM
REM Usage from cmd:
REM   build.bat setup    - one-time: clone imgui+lua, build Zydis+lua libs
REM   build.bat imgui    - one-time: precompile imgui .o files
REM   build.bat full     - full rebuild (~30-60 sec).  Rebuilds imgui from src.
REM   build.bat fast     - incremental rebuild (~3-5 sec).  Uses imgui cache.
REM   build.bat run      - 'fast' build, then launch build\memiscani_im.exe
REM   build.bat clean    - delete build\ and obj\ entirely
REM
REM Requires:  MinGW g++/gcc/ar in PATH, git.
REM Close build\memiscani_im.exe before building or the link step will fail.
REM ============================================================================

setlocal enabledelayedexpansion
cd /d "%~dp0"

if "%1"=="setup" goto :setup
if "%1"=="imgui" goto :imgui
if "%1"=="full"  goto :full
if "%1"=="fast"  goto :fast
if "%1"=="run"   goto :run
if "%1"=="clean" goto :clean

echo Usage:  build.bat ^[setup ^| imgui ^| full ^| fast ^| run ^| clean^]
echo.
echo Typical first-time workflow:
echo     build.bat setup
echo     build.bat imgui
echo     build.bat full
echo Typical daily workflow:
echo     build.bat fast      ^(or^)      build.bat run
exit /b 1

REM ---------------------------------------------------------------------------
:setup
if not exist build      mkdir build
if not exist obj        mkdir obj
if not exist obj\lua    mkdir obj\lua

if not exist imgui (
    echo == Cloning imgui v1.91.5 ==
    git clone --depth 1 --branch v1.91.5 https://github.com/ocornut/imgui.git imgui || exit /b 1
)
if not exist lua54 (
    echo == Cloning lua v5.4.7 ==
    git clone --depth 1 --branch v5.4.7 https://github.com/lua/lua.git lua54 || exit /b 1
)
if not exist obj\Zydis.o (
    echo == Compiling Zydis ==
    gcc -I. -O2 -c Zydis.c -o obj\Zydis.o || exit /b 1
)
if not exist obj\liblua54.a (
    echo == Building Lua static lib ==
    for %%f in (lua54\*.c) do (
        if /i not "%%~nxf"=="lua.c" if /i not "%%~nxf"=="onelua.c" if /i not "%%~nxf"=="ltests.c" if /i not "%%~nxf"=="luac.c" (
            gcc -O2 -Ilua54 -c "%%f" -o "obj\lua\%%~nf.o" || exit /b 1
        )
    )
    ar rcs obj\liblua54.a obj\lua\*.o || exit /b 1
)
echo == Setup complete ==
goto :end

REM ---------------------------------------------------------------------------
:imgui
if not exist obj mkdir obj
echo == Precompiling ImGui *.o ==
for %%f in (imgui\imgui.cpp imgui\imgui_draw.cpp imgui\imgui_tables.cpp imgui\imgui_widgets.cpp imgui\imgui_demo.cpp imgui\backends\imgui_impl_win32.cpp imgui\backends\imgui_impl_dx11.cpp) do (
    echo   cc %%f
    g++ -std=c++17 -O2 -I. -Iimgui -Iimgui\backends -c "%%f" -o "obj\%%~nf.o" || exit /b 1
)
echo == ImGui objects built ==
goto :end

REM ---------------------------------------------------------------------------
:full
if not exist build mkdir build
if not exist obj mkdir obj
if not exist obj\Zydis.o (
    echo Zydis.o missing - run 'build.bat setup' first.
    exit /b 1
)
if not exist obj\liblua54.a (
    echo obj\liblua54.a missing - run 'build.bat setup' first.
    exit /b 1
)
echo == Full build ==
g++ -std=c++17 -O2 -I. -Iimgui -Iimgui\backends -Ilua54 -o build\memiscani_im.exe memiscani_im.cpp memcore.cpp mem_lua.cpp obj\Zydis.o imgui\imgui.cpp imgui\imgui_draw.cpp imgui\imgui_tables.cpp imgui\imgui_widgets.cpp imgui\imgui_demo.cpp imgui\backends\imgui_impl_win32.cpp imgui\backends\imgui_impl_dx11.cpp obj\liblua54.a -lpsapi -lgdi32 -lcomctl32 -lcomdlg32 -lshell32 -ld3d11 -ld3dcompiler -ldwmapi -liphlpapi -lws2_32 -mwindows || exit /b 1
call :resources
echo == Built build\memiscani_im.exe ==
goto :end

REM ---------------------------------------------------------------------------
:fast
if not exist build mkdir build
if not exist obj\imgui.o (
    echo ImGui .o files missing.  Run 'build.bat imgui' once first.
    exit /b 1
)
if not exist obj\Zydis.o (
    echo Zydis.o missing - run 'build.bat setup' first.
    exit /b 1
)
if not exist obj\liblua54.a (
    echo obj\liblua54.a missing - run 'build.bat setup' first.
    exit /b 1
)
echo == Incremental build ==
g++ -std=c++17 -O2 -I. -Iimgui -Iimgui\backends -Ilua54 -o build\memiscani_im.exe memiscani_im.cpp memcore.cpp mem_lua.cpp obj\Zydis.o obj\imgui.o obj\imgui_draw.o obj\imgui_tables.o obj\imgui_widgets.o obj\imgui_demo.o obj\imgui_impl_win32.o obj\imgui_impl_dx11.o obj\liblua54.a -lpsapi -lgdi32 -lcomctl32 -lcomdlg32 -lshell32 -ld3d11 -ld3dcompiler -ldwmapi -liphlpapi -lws2_32 -mwindows || exit /b 1
call :resources
echo == Built build\memiscani_im.exe ==
goto :end

REM ---------------------------------------------------------------------------
:run
call :fast || exit /b 1
echo == Launching build\memiscani_im.exe ==
start "" "build\memiscani_im.exe"
goto :end

REM ---------------------------------------------------------------------------
:clean
echo == Cleaning build\ and obj\ ==
if exist build rmdir /s /q build
if exist obj rmdir /s /q obj
del /q *.o 2>nul
del /q memiscani_im.exe 2>nul
del /q memiscani_im_check.exe 2>nul
del /q memiscani_im_new.exe 2>nul
echo == Done.  Run 'build.bat setup' to rebuild dependencies. ==
goto :end

REM ---------------------------------------------------------------------------
:resources
REM Copy README + samples next to the exe so build\ is self-contained.
if exist resources\README.txt copy /Y resources\README.txt build\README.txt >nul
if not exist build\samples mkdir build\samples
if exist resources\samples (
    xcopy /Y /Q resources\samples\* build\samples\ >nul
)
exit /b 0

REM ---------------------------------------------------------------------------
:end
endlocal
